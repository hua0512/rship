//! Shared interactive and flag-merging wizard primitives for provider `handle_auth` adapters.

#![cfg_attr(not(feature = "all-backends"), allow(dead_code, unused_imports))]

use anyhow::Result;

use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::RemoteConfig;

use super::{AuthContext, AuthOutcome, apply_secret_outcome, persist_remote, resolve_remote_name};

/// Coordinates remote-name resolution, section banners, flag-vs-prompt field resolution,
/// secret prompting, and config persistence across all provider `handle_auth` handlers.
pub(super) struct PromptWizard<'a, 'ctx> {
    pub remote: String,
    pub did_prompt: bool,
    pub full_wizard: bool,
    pub ctx: &'a mut AuthContext<'ctx>,
}

impl<'a, 'ctx> PromptWizard<'a, 'ctx> {
    pub fn begin(
        remote_arg: Option<String>,
        default_name: &str,
        kind: &str,
        any_flag: bool,
        ctx: &'a mut AuthContext<'ctx>,
    ) -> Result<Self> {
        let (remote, did_prompt) = resolve_remote_name(remote_arg, default_name, ctx, kind)?;
        let full_wizard = ctx.force_wizard || (ctx.interactive && !any_flag);
        Ok(Self {
            remote,
            did_prompt,
            full_wizard,
            ctx,
        })
    }

    pub fn section(&mut self, title: &str, has_existing: bool, edit_sub: &str, new_sub: &str) {
        if self.full_wizard {
            let sub = if has_existing { edit_sub } else { new_sub };
            prompt::section(title, Some(sub));
            self.did_prompt = true;
        }
    }

    pub fn required_text(
        &mut self,
        label: &str,
        flag: Option<String>,
        existing: Option<&str>,
        hint: Option<&str>,
        missing_err: &str,
    ) -> Result<String> {
        if let Some(v) = flag {
            Ok(v)
        } else if self.full_wizard || (self.ctx.interactive && existing.is_none()) {
            self.did_prompt = true;
            prompt::text_required(label, existing, hint)
        } else if let Some(prev) = existing {
            Ok(prev.to_string())
        } else {
            Err(config_err(missing_err))
        }
    }

    pub fn required_text_validated<F>(
        &mut self,
        label: &str,
        flag: Option<String>,
        existing: Option<&str>,
        hint: Option<&str>,
        missing_err: &str,
        validate: F,
    ) -> Result<String>
    where
        F: FnMut(&str) -> std::result::Result<(), String>,
    {
        if let Some(v) = flag {
            Ok(v)
        } else if self.full_wizard || (self.ctx.interactive && existing.is_none()) {
            self.did_prompt = true;
            prompt::text_validated_required(label, existing, hint, validate)
        } else if let Some(prev) = existing {
            Ok(prev.to_string())
        } else {
            Err(config_err(missing_err))
        }
    }

    pub fn optional_text(
        &mut self,
        label: &str,
        flag: Option<String>,
        existing: Option<String>,
        hint: Option<&str>,
    ) -> Result<Option<String>> {
        let cur = flag.as_ref().cloned().or(existing);
        if self.full_wizard && flag.is_none() {
            self.did_prompt = true;
            prompt::text(label, cur.as_deref(), hint, false)
        } else {
            Ok(cur)
        }
    }

    pub fn prompt_secret(
        &mut self,
        label: &str,
        existing: Option<&str>,
        required: bool,
        hint: Option<&str>,
    ) -> Result<Option<String>> {
        self.did_prompt = true;
        let has_existing = existing.is_some_and(|s| !s.is_empty());
        let out = prompt::password(label, has_existing, required, hint)?;
        apply_secret_outcome(out, existing)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn select_flag_or_menu<T: Copy + Eq>(
        &mut self,
        prompt_label: &str,
        flag: Option<&str>,
        parse: fn(&str) -> Option<T>,
        parse_err: impl FnOnce(&str) -> anyhow::Error,
        items: &[(T, &str, &str)],
        default_val: T,
        fallback_val: T,
    ) -> Result<T> {
        if let Some(raw) = flag {
            parse(raw).ok_or_else(|| parse_err(raw))
        } else if self.full_wizard {
            let default_idx = items
                .iter()
                .position(|(v, _, _)| *v == default_val)
                .unwrap_or(0);
            let select_items: Vec<SelectItem> = items
                .iter()
                .map(|(_, label, desc)| {
                    if desc.is_empty() {
                        SelectItem::new(*label)
                    } else {
                        SelectItem::new(*label).with_desc(*desc)
                    }
                })
                .collect();
            let chosen = prompt::select(prompt_label, &select_items, default_idx)?;
            self.did_prompt = true;
            Ok(items[chosen].0)
        } else {
            Ok(fallback_val)
        }
    }

    pub fn finish(self, cfg: RemoteConfig, summary_msg: &str) -> Result<AuthOutcome> {
        persist_remote(&self.remote, cfg, self.did_prompt, self.ctx)?;
        println!("{summary_msg}");
        Ok(AuthOutcome {
            remote: self.remote,
            did_prompt: self.did_prompt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::{AppConfig, LocalRemoteConfig};
    use tempfile::TempDir;

    #[test]
    fn prompt_wizard_non_interactive_required_text_resolves_or_fails_fast() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        let mut wiz =
            PromptWizard::begin(Some("my-rem".to_string()), "def", "webdav", true, &mut ctx)
                .unwrap();
        assert!(!wiz.full_wizard);

        assert_eq!(
            wiz.required_text("URL", Some("https://a".into()), None, None, "missing url")
                .unwrap(),
            "https://a"
        );
        assert_eq!(
            wiz.required_text("URL", None, Some("https://prev"), None, "missing url")
                .unwrap(),
            "https://prev"
        );
        let err = wiz
            .required_text("URL", None, None, None, "missing url")
            .unwrap_err();
        assert!(err.to_string().contains("missing url"));
    }

    #[test]
    fn prompt_wizard_optional_text_and_select_preserve_or_override() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        let mut wiz = PromptWizard::begin(
            Some("my-loc".to_string()),
            "local",
            "local",
            false,
            &mut ctx,
        )
        .unwrap();

        assert_eq!(
            wiz.optional_text("Prefix", None, Some("old/".into()), None)
                .unwrap(),
            Some("old/".into())
        );
        assert_eq!(
            wiz.optional_text("Prefix", Some("new/".into()), Some("old/".into()), None)
                .unwrap(),
            Some("new/".into())
        );

        let choice = wiz
            .select_flag_or_menu(
                "Pick",
                Some("b"),
                |s| match s {
                    "a" => Some(1u8),
                    "b" => Some(2u8),
                    _ => None,
                },
                |s| anyhow::anyhow!("bad {s}"),
                &[(1, "A", ""), (2, "B", "")],
                1,
                1,
            )
            .unwrap();
        assert_eq!(choice, 2);

        let out = wiz
            .finish(
                RemoteConfig::Local(Box::new(LocalRemoteConfig::new(tmp.path()))),
                "configured",
            )
            .unwrap();
        assert_eq!(out.remote, "my-loc");
        assert!(!out.did_prompt);
        assert!(cfg.remotes.contains_key("my-loc"));
    }
}
