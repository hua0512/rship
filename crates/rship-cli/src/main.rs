mod allocator;
mod cli;
mod errors;
mod ops;
mod prompt;
mod providers;
mod tui;
mod ui;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use rship_core::state::JobMode;
use std::io;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command, ConfigAction, MoveArgs};
use crate::ops::bisync::execute_bisync;
use crate::ops::check::{execute_check, execute_size, execute_tree};
use crate::ops::config_ops::{
    execute_config_edit, execute_config_interactive, execute_config_list, execute_config_new,
    execute_config_profiles, execute_config_rm, execute_config_test,
};
use crate::ops::fs::{
    execute_cat, execute_delete, execute_ls, execute_mkdir, execute_purge, execute_rcat,
};
use crate::ops::inspect::{execute_about, execute_dedupe, execute_hashsum};
use crate::ops::jobs::{execute_gc, execute_resume, execute_status};
use crate::ops::transfer::{ResumeOverrides, execute_transfer};
use crate::ops::{CliRuntime, TransportOverrides};
use crate::providers::{AuthContext, handle_auth, import_rclone_all};
use rship::config::{AppPaths, load_config};

fn main() -> ExitCode {
    allocator::ensure_mimalloc_defaults();
    ui::init_terminal();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if !err.use_stderr() {
                let _ = err.print();
                return ExitCode::SUCCESS;
            }
            let raw_args: Vec<String> = std::env::args_os()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let wants_json = raw_args.iter().any(|a| a == "--json");
            let wants_json_progress = raw_args.iter().any(|a| a == "--json-progress");
            if wants_json || wants_json_progress {
                let msg = err.render().to_string().trim().to_string();
                let wrapped = anyhow::Error::new(rship_core::Error::config(msg));
                return emit_fatal_cli_error("cli", wants_json, wants_json_progress, &wrapped);
            }
            err.exit();
        }
    };
    if let Command::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "rship", &mut io::stdout());
        return ExitCode::SUCCESS;
    }
    let wants_json = cli.command.wants_json();
    let wants_json_progress = cli.command.wants_json_progress();
    let command_name = cli.command.command_name();
    let dump_mode = match cli.dump.as_deref() {
        Some(raw) => match rship_transport::HttpDumpMode::parse(raw) {
            Some(m) => m,
            None => {
                let err = anyhow::Error::new(rship_core::Error::config(format!(
                    "invalid --dump mode `{raw}` (supported: headers, off)"
                )));
                return emit_fatal_cli_error(command_name, wants_json, wants_json_progress, &err);
            }
        },
        None => rship_transport::HttpDumpMode::None,
    };
    if dump_mode != rship_transport::HttpDumpMode::None
        && wants_json_progress
        && cli.log_file.is_none()
    {
        let err = anyhow::Error::new(rship_core::Error::config(
            "--dump headers cannot be combined with --json-progress without --log-file <PATH> (would corrupt JSONL on stderr)",
        ));
        return emit_fatal_cli_error(command_name, wants_json, wants_json_progress, &err);
    }
    if let Err(e) = init_tracing(
        cli.verbose,
        wants_json_progress,
        cli.log_file.as_deref(),
        dump_mode,
    ) {
        return emit_fatal_cli_error(command_name, wants_json, wants_json_progress, &e);
    }

    // Direct SQLite external-sort temp files onto disk-backed `<state_dir>/runs/sqlite-tmp`
    // BEFORE spawning the multi-threaded Tokio runtime (so `set_var` is single-threaded
    // and large 40M-row sorts never exhaust small Linux `/tmp` `tmpfs` mounts).
    // The directory itself is created lazily only if a transfer actually spills to SQLite.
    if std::env::var_os("SQLITE_TMPDIR").is_none() {
        let early_paths = AppPaths::resolve(cli.config.clone(), cli.state_dir.clone());
        let sqlite_tmp = early_paths.sqlite_tmp_dir();
        // SAFETY: Called once in `main()` before any worker threads are spawned.
        unsafe {
            std::env::set_var("SQLITE_TMPDIR", &sqlite_tmp);
        }
    }

    // Cap async worker threads (`2..=8`) and blocking thread pool so high-core hosts
    // don't spin up dozens of idle allocator thread heaps (`theaps`) for an I/O-bound
    // engine, and expire idle blocking threads promptly to reclaim RSS.
    let worker_threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 8);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .max_blocking_threads(32)
        .thread_keep_alive(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match rt.block_on(Box::pin(run_cli(cli, dump_mode))) {
        Ok(code) => code,
        Err(e) => emit_fatal_cli_error(command_name, wants_json, wants_json_progress, &e),
    }
}

fn emit_fatal_cli_error(
    command_name: &str,
    wants_json: bool,
    wants_json_progress: bool,
    e: &anyhow::Error,
) -> ExitCode {
    let classified = errors::classify_anyhow_error(e);
    if wants_json_progress {
        let line = errors::format_error_jsonl(
            command_name,
            None,
            None,
            classified.kind,
            classified.category,
            classified.retry_class,
            classified.retry_after_ms,
            &classified.message,
            true,
        );
        errors::write_jsonl_stderr(&line);
    }
    if wants_json {
        let payload = errors::format_fatal_error_json(command_name, &classified);
        if let Ok(encoded) = serde_json::to_string_pretty(&payload) {
            println!("{encoded}");
        }
    } else if !wants_json_progress {
        ui::print_error(e);
    }
    ExitCode::from(classified.exit_code)
}

fn init_tracing(
    verbosity: u8,
    json_progress: bool,
    log_file: Option<&std::path::Path>,
    dump_mode: rship_transport::HttpDumpMode,
) -> Result<()> {
    let default_level = if log_file.is_some() {
        match verbosity {
            0 | 1 => "info",
            2 => "debug",
            _ => "trace",
        }
    } else {
        match verbosity {
            0 if json_progress => "off",
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    // Under `--json-progress` without `--log-file`, silence ALL stderr tracing unconditionally
    // (regardless of `RUST_LOG`, `RSHIP_LOG`, or `-v`) so plain-text tracing lines can never
    // corrupt JSONL `stderr` output; pass `--log-file <PATH>` to capture logs alongside JSONL.
    let mut filter = if json_progress && log_file.is_none() {
        EnvFilter::new("off")
    } else if let Ok(v) = std::env::var("RSHIP_LOG")
        && !v.trim().is_empty()
    {
        EnvFilter::try_new(v).unwrap_or_else(|_| EnvFilter::new(default_level))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level))
    };
    if dump_mode != rship_transport::HttpDumpMode::None
        && !(json_progress && log_file.is_none())
        && let Ok(dir) = "rship::http_dump=info".parse()
    {
        filter = filter.add_directive(dir);
    }

    if let Some(path) = log_file {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                rship_core::Error::io(
                    format!(
                        "create parent directory for --log-file `{}`",
                        path.display()
                    ),
                    e,
                )
            })?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(path).map_err(|e| {
            rship_core::Error::io(format!("open --log-file `{}`", path.display()), e)
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = file.metadata()
                && meta.is_file()
            {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
        }
        let _ = tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(std::io::LineWriter::new(file)))
            .with_ansi(false)
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    }
    Ok(())
}

async fn run_cli(cli: Cli, dump_mode: rship_transport::HttpDumpMode) -> Result<ExitCode> {
    let paths = AppPaths::resolve(cli.config.clone(), cli.state_dir.clone());
    let mut app_cfg = load_config(&paths.config_file)?;
    let active_profile = app_cfg.resolve_profile(cli.profile.as_deref())?;
    let runtime_options = rship::RuntimeOptions::new()
        .with_gdrive_stop_on_upload_limit(cli.drive_stop_on_upload_limit)
        .with_gdrive_low_level_retries(cli.low_level_retries.or(active_profile.low_level_retries));
    let t_opts = TransportOverrides::from_cli_and_profile(&cli, &active_profile, dump_mode)?;
    ops::validate_transport_overrides(&t_opts)?;
    let allow_changes_feed = !cli.no_changes_feed;
    let interactive = prompt::is_interactive(cli.non_interactive);

    match cli.command {
        Command::Config { action } => match action {
            None => execute_config_interactive(&paths, &mut app_cfg, &t_opts, interactive).await,
            Some(ConfigAction::List { json }) => execute_config_list(json, &app_cfg),
            Some(ConfigAction::Profiles { json }) => execute_config_profiles(json, &app_cfg),
            Some(ConfigAction::New { provider, remote }) => {
                execute_config_new(
                    provider.as_deref(),
                    remote.as_deref(),
                    &paths,
                    &mut app_cfg,
                    &t_opts,
                    interactive,
                )
                .await
            }
            Some(ConfigAction::Edit { remote }) => {
                execute_config_edit(
                    remote.as_deref(),
                    &paths,
                    &mut app_cfg,
                    &t_opts,
                    interactive,
                )
                .await
            }
            Some(ConfigAction::Path) => {
                let st = ui::Style::stdout();
                println!("{} {}", st.dim("config_file:"), paths.config_file.display());
                println!("{}   {}", st.dim("state_dir:"), paths.state_dir.display());
                Ok(ExitCode::SUCCESS)
            }
            Some(ConfigAction::Show { show_secrets }) => {
                let display_cfg = if show_secrets {
                    app_cfg.clone()
                } else {
                    app_cfg.redacted()
                };
                let s = toml::to_string_pretty(&display_cfg)?;
                print!("{s}");
                Ok(ExitCode::SUCCESS)
            }
            Some(ConfigAction::ImportRclone {
                path,
                overwrite,
                dry_run,
            }) => import_rclone_all(path, overwrite, dry_run, &paths, &mut app_cfg),
            Some(ConfigAction::Test { remote, json }) => {
                let mut rt = CliRuntime::new(
                    &paths,
                    &app_cfg,
                    active_profile,
                    &t_opts,
                    false,
                    runtime_options,
                )?;
                let code = execute_config_test(&remote, json, &mut rt).await?;
                rt.shutdown().await?;
                Ok(code)
            }
            Some(ConfigAction::Rm { remote }) => execute_config_rm(&remote, &paths, &mut app_cfg),
        },

        Command::Auth { action } => match action {
            None => {
                if !interactive {
                    let enabled: Vec<&str> = providers::registered_providers()
                        .into_iter()
                        .map(|p| p.kind())
                        .collect();
                    return Err(rship_core::Error::config(format!(
                        "missing auth provider subcommand (available: {}; run interactively in a terminal or see `rship auth --help`)",
                        enabled.join(", ")
                    ))
                    .into());
                }
                execute_config_new(None, None, &paths, &mut app_cfg, &t_opts, true).await
            }
            Some(action) => {
                let mut ctx = AuthContext::new(&paths, &mut app_cfg, &t_opts, interactive)
                    .with_runtime_options(runtime_options);
                handle_auth(action, &mut ctx).await
            }
        },

        cmd => {
            let mut rt = CliRuntime::new(
                &paths,
                &app_cfg,
                active_profile,
                &t_opts,
                allow_changes_feed,
                runtime_options,
            )?;
            let res = run_runtime_command(cmd, &mut rt).await;
            let shutdown_res = rt.shutdown().await;
            let code = res?;
            shutdown_res?;
            Ok(code)
        }
    }
}

async fn run_runtime_command(cmd: Command, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    match cmd {
        Command::Ls {
            target,
            recursive,
            json,
        } => Box::pin(execute_ls(&target, recursive, json, rt)).await,
        Command::Tree(args) => Box::pin(execute_tree(args, rt)).await,
        Command::Size(args) => Box::pin(execute_size(args, rt)).await,
        Command::About { target, json } => Box::pin(execute_about(&target, json, rt)).await,
        Command::Check(args) => Box::pin(execute_check(args, rt)).await,
        Command::Hashsum(args) => Box::pin(execute_hashsum(args, rt)).await,
        Command::Dedupe(args) => Box::pin(execute_dedupe(args, rt)).await,

        Command::Copy(args) => {
            Box::pin(execute_transfer(JobMode::Copy, args, false, false, rt)).await
        }
        Command::Copyto(args) => {
            Box::pin(execute_transfer(JobMode::Copy, args, false, true, rt)).await
        }
        Command::Sync(args) => {
            Box::pin(execute_transfer(JobMode::Sync, args, false, false, rt)).await
        }
        Command::Move(MoveArgs {
            transfer,
            delete_empty_src_dirs,
        }) => {
            Box::pin(execute_transfer(
                JobMode::Move,
                transfer,
                delete_empty_src_dirs,
                false,
                rt,
            ))
            .await
        }
        Command::Moveto(args) => {
            Box::pin(execute_transfer(JobMode::Move, args, false, true, rt)).await
        }
        Command::Bisync(args) => Box::pin(execute_bisync(args, rt)).await,
        Command::Delete(args) => Box::pin(execute_delete(args, rt)).await,
        Command::Purge(args) => Box::pin(execute_purge(args, rt)).await,
        Command::Mkdir { target } => Box::pin(execute_mkdir(&target, rt)).await,
        Command::Cat(args) => Box::pin(execute_cat(args, rt)).await,
        Command::Rcat(args) => Box::pin(execute_rcat(args, rt)).await,
        Command::Completions { .. } => unreachable!("handled prior to Tokio runtime startup"),

        Command::Resume {
            job_id,
            transfers,
            max_buffer_mem,
            bwlimit,
            json_progress,
            stats,
            tui,
            json,
        } => {
            let overrides = ResumeOverrides {
                transfers,
                max_buffer_mem,
                bwlimit,
                json_progress,
                stats,
                tui,
                json,
            };
            Box::pin(execute_resume(job_id, overrides, rt)).await
        }
        Command::Status { limit, json } => Box::pin(execute_status(limit, json, rt)).await,
        Command::Gc {
            all,
            remote_multipart,
            older_than,
            dry_run,
            json,
        } => {
            Box::pin(execute_gc(
                all,
                remote_multipart,
                older_than,
                dry_run,
                json,
                rt,
            ))
            .await
        }
        Command::Config { .. } | Command::Auth { .. } => unreachable!(),
    }
}
