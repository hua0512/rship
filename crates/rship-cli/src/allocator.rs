//! Global `mimalloc` allocator registration and pre-`main` low-RSS option tuning.
//!
//! Isolated in its own module so all FFI and linker-section `unsafe` code for
//! process startup allocator configuration stays tightly contained and auditable.

#[cfg(any(feature = "mimalloc", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Mimalloc v3 `mi_option_e` ordinals configured before `main()` runs.
#[cfg(any(feature = "mimalloc", target_env = "musl"))]
mod mimalloc_init {
    use std::ffi::{c_int, c_long};
    use std::sync::atomic::{AtomicBool, Ordering};

    pub(super) const MI_OPTION_ARENA_EAGER_COMMIT: c_int = 4;
    pub(super) const MI_OPTION_PURGE_DECOMMITS: c_int = 5;
    pub(super) const MI_OPTION_PURGE_DELAY: c_int = 15;
    pub(super) const MI_OPTION_ARENA_PURGE_MULT: c_int = 24;
    pub(super) const MI_OPTION_PAGE_RECLAIM_ON_FREE: c_int = 35;
    pub(super) const MI_OPTION_ALLOW_THP: c_int = 43;

    pub(super) static EARLY_INIT_RAN: AtomicBool = AtomicBool::new(false);

    // SAFETY: `mimalloc` is linked as `#[global_allocator]` for this binary.
    // All option ordinals are verified against mimalloc v3 (`MI_MALLOC_VERSION` 3.x)
    // and guarded at runtime via `mi_version() / 10_000 == 3`.
    unsafe extern "C" {
        pub(super) fn mi_version() -> c_int;
        fn mi_option_set_default(option: c_int, value: c_long);
    }

    /// Tune `mimalloc` v3 default options for low-RSS streaming transfers.
    ///
    /// Uses `mi_option_set_default` exclusively (pure static table write: zero
    /// allocations, zero CRT/TLS/env calls), so it is safe to execute inside a
    /// pre-`main` OS initializer before `std::rt::lang_start` allocates the
    /// first arena, while still letting explicit `MIMALLOC_*` env vars win.
    pub(super) fn apply_low_rss_defaults() {
        // SAFETY: Pure read-only version query, safe before CRT/runtime init.
        let ver = unsafe { mi_version() };
        if ver / 10_000 != 3 {
            return;
        }

        // SAFETY: Called single-threaded during process startup before worker
        // threads or arena reservations exist; each ordinal is a valid mimalloc
        // v3 `mi_option_e` value, and `mi_option_set_default` never overwrites
        // an option already initialized from a `MIMALLOC_*` environment variable.
        unsafe {
            // Avoid committing full arenas eagerly on startup/bursts.
            mi_option_set_default(MI_OPTION_ARENA_EAGER_COMMIT, 0);
            // Decommit purged pages back to OS rather than only soft-resetting.
            mi_option_set_default(MI_OPTION_PURGE_DECOMMITS, 1);
            // Keep a gentle 10 ms purge delay (avoids 0 ms churn page faults) while
            // tightening arena purge delay from 10× (100 ms) to 2× (20 ms).
            mi_option_set_default(MI_OPTION_PURGE_DELAY, 10);
            mi_option_set_default(MI_OPTION_ARENA_PURGE_MULT, 2);
            // Immediately reclaim cross-thread freed pages (Tokio worker -> blocking writer handoffs).
            mi_option_set_default(MI_OPTION_PAGE_RECLAIM_ON_FREE, 1);
            // Disable 2 MiB transparent huge pages so Linux purges at 64 KiB granularity.
            mi_option_set_default(MI_OPTION_ALLOW_THP, 0);
        }
    }

    #[cfg(any(unix, windows))]
    extern "C" fn init_mimalloc_early() {
        apply_low_rss_defaults();
        EARLY_INIT_RAN.store(true, Ordering::Release);
    }

    // Place `init_mimalloc_early` in the platform's pre-`main` initializer section
    // so defaults take effect before `std::rt::lang_start` allocates its first arena
    // (and on Linux/ELF before GCC's `.init_array` mimalloc process init).
    #[cfg(any(unix, windows))]
    #[used]
    #[cfg_attr(
        all(unix, not(target_vendor = "apple")),
        unsafe(link_section = ".init_array.00101")
    )]
    #[cfg_attr(
        target_vendor = "apple",
        unsafe(link_section = "__DATA,__mod_init_func")
    )]
    #[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
    static INIT_MIMALLOC: extern "C" fn() = init_mimalloc_early;

    pub(super) fn ensure_defaults() {
        if !EARLY_INIT_RAN.load(Ordering::Acquire) {
            apply_low_rss_defaults();
        }
    }
}

#[cfg(any(feature = "mimalloc", target_env = "musl"))]
pub(crate) fn ensure_mimalloc_defaults() {
    mimalloc_init::ensure_defaults();
}

#[cfg(not(any(feature = "mimalloc", target_env = "musl")))]
pub(crate) fn ensure_mimalloc_defaults() {}

#[cfg(all(test, any(feature = "mimalloc", target_env = "musl")))]
mod mimalloc_tests {
    use super::mimalloc_init::{
        EARLY_INIT_RAN, MI_OPTION_ALLOW_THP, MI_OPTION_ARENA_EAGER_COMMIT,
        MI_OPTION_ARENA_PURGE_MULT, MI_OPTION_PAGE_RECLAIM_ON_FREE, MI_OPTION_PURGE_DECOMMITS,
        MI_OPTION_PURGE_DELAY, mi_version,
    };
    use std::ffi::{c_int, c_long};
    use std::sync::atomic::Ordering;

    unsafe extern "C" {
        fn mi_option_get(option: c_int) -> c_long;
    }

    #[test]
    fn pre_main_constructor_applies_low_rss_v3_defaults_before_main() {
        #[cfg(any(unix, windows))]
        assert!(
            EARLY_INIT_RAN.load(Ordering::Acquire),
            "pre-main mimalloc initializer did not run before the test harness"
        );

        // SAFETY: Read-only mimalloc version query.
        let ver = unsafe { mi_version() };
        assert_eq!(ver / 10_000, 3, "expected mimalloc v3, got {ver}");

        // Verify defaults took effect automatically without calling `main()` or
        // invoking any manual configuration helper inside the test.
        let check = |env_name: &str, opt: c_int, expected: c_long, label: &str| {
            if std::env::var_os(env_name).is_none() {
                // SAFETY: `opt` is a valid mimalloc v3 `mi_option_e` ordinal.
                let actual = unsafe { mi_option_get(opt) };
                assert_eq!(actual, expected, "mimalloc option `{label}`");
            }
        };
        check(
            "MIMALLOC_ARENA_EAGER_COMMIT",
            MI_OPTION_ARENA_EAGER_COMMIT,
            0,
            "arena_eager_commit",
        );
        check(
            "MIMALLOC_PURGE_DECOMMITS",
            MI_OPTION_PURGE_DECOMMITS,
            1,
            "purge_decommits",
        );
        check(
            "MIMALLOC_PURGE_DELAY",
            MI_OPTION_PURGE_DELAY,
            10,
            "purge_delay",
        );
        check(
            "MIMALLOC_ARENA_PURGE_MULT",
            MI_OPTION_ARENA_PURGE_MULT,
            2,
            "arena_purge_mult",
        );
        check(
            "MIMALLOC_PAGE_RECLAIM_ON_FREE",
            MI_OPTION_PAGE_RECLAIM_ON_FREE,
            1,
            "page_reclaim_on_free",
        );
        check("MIMALLOC_ALLOW_THP", MI_OPTION_ALLOW_THP, 0, "allow_thp");
    }

    #[test]
    fn mimalloc_env_override_wins_over_pre_main_defaults() {
        const CHILD_ENV: &str = "RSHIP_MIMALLOC_OVERRIDE_CHILD";
        const MARKER: &str = "RSHIP_MIMALLOC_OVERRIDE_OK";

        if std::env::var_os(CHILD_ENV).is_some() {
            #[cfg(any(unix, windows))]
            assert!(
                EARLY_INIT_RAN.load(Ordering::Acquire),
                "pre-main mimalloc initializer did not run in child subprocess"
            );
            // SAFETY: Valid mimalloc v3 `mi_option_e` ordinals.
            unsafe {
                assert_eq!(
                    mi_option_get(MI_OPTION_PURGE_DELAY),
                    50,
                    "MIMALLOC_PURGE_DELAY=50 env var must override pre-main default"
                );
                assert_eq!(
                    mi_option_get(MI_OPTION_ARENA_EAGER_COMMIT),
                    0,
                    "arena_eager_commit default must still apply"
                );
                assert_eq!(
                    mi_option_get(MI_OPTION_PURGE_DECOMMITS),
                    1,
                    "purge_decommits default must still apply"
                );
                assert_eq!(
                    mi_option_get(MI_OPTION_ARENA_PURGE_MULT),
                    2,
                    "arena_purge_mult default must still apply"
                );
                assert_eq!(
                    mi_option_get(MI_OPTION_PAGE_RECLAIM_ON_FREE),
                    1,
                    "page_reclaim_on_free default must still apply"
                );
                assert_eq!(
                    mi_option_get(MI_OPTION_ALLOW_THP),
                    0,
                    "allow_thp default must still apply"
                );
            }
            eprintln!("{MARKER}");
            return;
        }

        let exe = std::env::current_exe().expect("locate current test executable");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "allocator::mimalloc_tests::mimalloc_env_override_wins_over_pre_main_defaults",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .env_remove("MIMALLOC_ARENA_EAGER_COMMIT")
            .env_remove("MIMALLOC_PURGE_DECOMMITS")
            .env_remove("MIMALLOC_ARENA_PURGE_MULT")
            .env_remove("MIMALLOC_PAGE_RECLAIM_ON_FREE")
            .env_remove("MIMALLOC_ALLOW_THP")
            .env("MIMALLOC_PURGE_DELAY", "50")
            .output()
            .expect("spawn mimalloc override verification child");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "child failed (status={:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            out.status.code()
        );
        assert!(
            stderr.contains(MARKER) || stdout.contains(MARKER),
            "child did not execute override assertions!\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        );
    }
}
