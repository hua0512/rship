use super::*;

fn mk_file(path: &str, size: u64, mtime_ns: i64) -> Entry {
    let rel = RelPath::parse(path).unwrap();
    Entry {
        node_id: None,
        parent_id: None,
        raw_path: crate::types::raw_path_override(&rel, path),
        nfc_path: rel,
        kind: EntryKind::File,
        size,
        mtime_ns,
        ctime_ns: None,
        etag: None,
        checksum: None,
    }
}

#[test]
fn prunes_dirs_and_matches_files() {
    let f = FilterSet::new(
        &["*.rs".to_string(), "Cargo.toml".to_string()],
        &[
            ".git/".to_string(),
            "target/".to_string(),
            "*.tmp".to_string(),
        ],
    )
    .unwrap();

    assert!(f.should_prune_dir(&RelPath::parse(".git").unwrap()));
    assert!(f.should_prune_dir(&RelPath::parse("sub/target").unwrap()));
    assert!(!f.should_prune_dir(&RelPath::parse("src").unwrap()));

    assert!(f.matches_file(&RelPath::parse("src/main.rs").unwrap()));
    assert!(f.matches_file(&RelPath::parse("Cargo.toml").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("target/debug/a.rs").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("notes.txt").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("foo.tmp").unwrap()));
}

#[test]
fn ordered_filter_rules_first_match_wins_and_dir_pruning() {
    let rules = parse_filter_rules(
        "
        # ignore build dirs first
        - build/
        + keep/*.log
        - *.log
        + **/*.rs
        - *
        ",
    )
    .unwrap();
    let f = FilterSet::from_options(&FilterOptions {
        rules,
        ..Default::default()
    })
    .unwrap();

    assert!(f.should_prune_dir(&RelPath::parse("build").unwrap()));
    assert!(!f.should_prune_dir(&RelPath::parse("keep").unwrap()));
    assert!(f.matches_file(&RelPath::parse("keep/app.log").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("other/app.log").unwrap()));
    assert!(f.matches_file(&RelPath::parse("src/lib.rs").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("README.md").unwrap()));
}

#[test]
fn files_from_prunes_unrelated_dirs_and_allows_only_listed() {
    let list = parse_files_from("# comment\n/a/b/one.txt\nc/two.bin\n");
    let f = FilterSet::from_options(&FilterOptions {
        files_from: Some(list),
        ..Default::default()
    })
    .unwrap();

    assert!(!f.should_prune_dir(&RelPath::parse("a").unwrap()));
    assert!(!f.should_prune_dir(&RelPath::parse("a/b").unwrap()));
    assert!(!f.should_prune_dir(&RelPath::parse("c").unwrap()));
    assert!(f.should_prune_dir(&RelPath::parse("unrelated").unwrap()));

    assert!(f.matches_file(&RelPath::parse("a/b/one.txt").unwrap()));
    assert!(f.matches_file(&RelPath::parse("c/two.bin").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("a/b/other.txt").unwrap()));
}

#[test]
fn size_and_age_filters_evaluate_on_entries() {
    let now_ns = 1_700_000_000i64 * 1_000_000_000;
    let one_hour = parse_duration_nanos("1h").unwrap();
    let one_day = parse_duration_nanos("1d").unwrap();
    assert_eq!(parse_duration_nanos("1h30m").unwrap(), 5400 * 1_000_000_000);

    let f = FilterSet::from_options(&FilterOptions {
        min_size: Some(100),
        max_size: Some(1000),
        min_age_ns: Some(one_hour),
        max_age_ns: Some(one_day),
        ..Default::default()
    })
    .unwrap();

    let ok = mk_file("ok.bin", 500, now_ns - 2 * one_hour);
    let too_small = mk_file("small.bin", 50, now_ns - 2 * one_hour);
    let too_large = mk_file("big.bin", 5000, now_ns - 2 * one_hour);
    let too_new = mk_file("new.bin", 500, now_ns - 10 * 1_000_000_000);
    let too_old = mk_file("old.bin", 500, now_ns - 3 * one_day);

    assert!(f.matches_entry(&ok, now_ns));
    assert!(!f.matches_entry(&too_small, now_ns));
    assert!(!f.matches_entry(&too_large, now_ns));
    assert!(!f.matches_entry(&too_new, now_ns));
    assert!(!f.matches_entry(&too_old, now_ns));
}

#[test]
fn files_from_deduplicates_and_tracks_sorted_membership_and_ancestors() {
    let mut big_list: Vec<String> = (0..2_000)
        .map(|i| format!("dir_{:02}/file_{:04}.dat", i % 10, i))
        .collect();
    // Inject duplicates and leading slashes.
    big_list.push("/dir_00/file_0000.dat".to_string());
    big_list.push("dir_01/file_0001.dat".to_string());

    let opts = FilterOptions {
        files_from: Some(big_list),
        files_from_path: Some("/var/tmp/manifest.txt".to_string()),
        ..Default::default()
    };

    let fs = FilterSet::from_options(&opts).unwrap();
    assert_eq!(fs.files_from_paths().unwrap().len(), 2_000);
    assert!(fs.matches_file(&RelPath::parse("dir_00/file_0000.dat").unwrap()));
    assert!(!fs.matches_file(&RelPath::parse("dir_00/missing.dat").unwrap()));
    assert!(!fs.should_prune_dir(&RelPath::parse("dir_05").unwrap()));
    assert!(fs.should_prune_dir(&RelPath::parse("dir_99").unwrap()));
}

#[test]
fn rclone_filter_root_anchoring_double_star_and_non_dir_exclude_no_false_prune() {
    // 1. Non-directory `--exclude "*foo*"` MUST NOT prune directory `food/` containing `keep.txt`.
    let f = FilterSet::new(&[], &["*foo*".to_string()]).unwrap();
    assert!(!f.has_dir_pruning());
    assert!(!f.should_prune_dir(&RelPath::parse("food").unwrap()));
    assert!(!f.matches_file(&RelPath::parse("dir/myfoo.txt").unwrap()));
    assert!(f.matches_file(&RelPath::parse("food/keep.txt").unwrap()));

    // 2. Leading `/` anchors pattern strictly to sync root (both files and dirs).
    let f_anchor = FilterSet::from_options(&FilterOptions {
        includes: vec!["/README.md".into(), "a/**/b.txt".into()],
        excludes: vec!["/build/".into()],
        ..Default::default()
    })
    .unwrap();
    assert!(f_anchor.should_prune_dir(&RelPath::parse("build").unwrap()));
    assert!(f_anchor.should_prune_dir(&RelPath::parse("build/sub").unwrap()));
    assert!(!f_anchor.should_prune_dir(&RelPath::parse("pkg/build").unwrap()));
    let f_unanchored = FilterSet::new(&[], &["build/".into()]).unwrap();
    assert!(f_unanchored.should_prune_dir(&RelPath::parse("build/sub").unwrap()));
    assert!(f_unanchored.should_prune_dir(&RelPath::parse("pkg/build/sub").unwrap()));
    assert!(f_anchor.matches_file(&RelPath::parse("README.md").unwrap()));
    assert!(!f_anchor.matches_file(&RelPath::parse("sub/README.md").unwrap()));
    // `a/**/b.txt` matches BOTH 0 intermediate dirs (`a/b.txt`) and nested (`a/x/y/b.txt`).
    assert!(f_anchor.matches_file(&RelPath::parse("a/b.txt").unwrap()));
    assert!(f_anchor.matches_file(&RelPath::parse("a/x/y/b.txt").unwrap()));

    // 3. Ordered rules: `+ deep/keep.txt` before `- *` must NOT prune `deep/`.
    let rules = parse_filter_rules("+ deep/keep.txt\n- *").unwrap();
    let f_ord = FilterSet::from_options(&FilterOptions {
        rules,
        ..Default::default()
    })
    .unwrap();
    assert!(!f_ord.should_prune_dir(&RelPath::parse("deep").unwrap()));
    assert!(f_ord.matches_file(&RelPath::parse("deep/keep.txt").unwrap()));
    assert!(!f_ord.matches_file(&RelPath::parse("deep/drop.txt").unwrap()));

    // 4. Regex-special characters in paths (`(1)`, `$a`, `+`) work without mis-matching.
    let f_lit = FilterSet::new(&["*.txt".into()], &[]).unwrap();
    assert!(f_lit.matches_file(&RelPath::parse("report (1)+$a.txt").unwrap()));
}

mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn seg_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "a", "b", "build", "src", "target", "tmp", "keep", "logs", "sub", "x.rs", "y.tmp",
            "z.log", "app.txt",
        ])
        .prop_map(str::to_string)
    }

    fn dir_path_strategy() -> impl Strategy<Value = RelPath> {
        prop::collection::vec(seg_strategy(), 1..=3)
            .prop_map(|segs| RelPath::parse(&segs.join("/")).unwrap())
    }

    fn file_path_strategy() -> impl Strategy<Value = RelPath> {
        prop::collection::vec(seg_strategy(), 1..=4)
            .prop_map(|segs| RelPath::parse(&segs.join("/")).unwrap())
    }

    fn glob_pattern_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "*.rs",
            "*.tmp",
            "*.log",
            "*.txt",
            "/a/*",
            "build/",
            "/build/",
            "target/",
            "sub/tmp/",
            "**/keep/**",
            "keep/*.log",
            "*tmp*",
            "src/**",
            "*",
        ])
        .prop_map(str::to_string)
    }

    fn filter_rule_strategy() -> impl Strategy<Value = FilterRule> {
        (prop::bool::ANY, glob_pattern_strategy())
            .prop_map(|(include, pattern)| FilterRule { include, pattern })
    }

    proptest! {
        #[test]
        fn prop_dir_pruning_is_strictly_sound_for_all_descendant_files(
            includes in prop::collection::vec(glob_pattern_strategy(), 0..=3),
            excludes in prop::collection::vec(glob_pattern_strategy(), 0..=4),
            rules in prop::collection::vec(filter_rule_strategy(), 0..=5),
            files_from in prop::option::of(prop::collection::vec(file_path_strategy(), 1..=4)),
            dir in dir_path_strategy(),
            desc_segs in prop::collection::vec(seg_strategy(), 1..=3),
        ) {
            let opts = FilterOptions {
                includes,
                excludes,
                rules,
                files_from: files_from
                    .map(|v| v.into_iter().map(|p| p.as_str().to_string()).collect()),
                ..Default::default()
            };
            let filter = FilterSet::from_options(&opts).unwrap();
            let mut descendant = dir.clone();
            for s in &desc_segs {
                descendant = descendant.join(s).unwrap();
            }

            if !filter.has_dir_pruning() {
                prop_assert!(!filter.should_prune_dir(&dir));
            }
            // Core soundness invariant: if `should_prune_dir(dir)` returns true,
            // NO descendant file inside `dir` may match `FilterSet`!
            if filter.should_prune_dir(&dir) {
                prop_assert!(
                    !filter.matches_file(&descendant),
                    "UNSOUND PRUNE: dir=`{}` pruned but descendant=`{}` matched! opts={:?}",
                    dir,
                    descendant,
                    opts
                );
                let entry = mk_file(descendant.as_str(), 128, 1_700_000_000_000_000_000);
                prop_assert!(!filter.matches_entry(&entry, 1_700_000_100_000_000_000));
            }
        }

        #[test]
        fn prop_include_exclude_and_ordered_rule_precedence(
            includes in prop::collection::vec(glob_pattern_strategy(), 0..=3),
            rules in prop::collection::vec(filter_rule_strategy(), 0..=4),
            path in file_path_strategy(),
        ) {
            let p_str = path.as_str().to_string();

            // 1. Explicit exclude on exact path ALWAYS wins over includes and rules.
            let ex_filter = FilterSet::from_options(&FilterOptions {
                includes: includes.clone(),
                excludes: vec![format!("/{p_str}")],
                rules: rules.clone(),
                ..Default::default()
            })
            .unwrap();
            prop_assert!(!ex_filter.matches_file(&path));

            // 2. First-match-wins ordered rules: prepending `+ /<path>` includes `path`
            //    and prepending `- /<path>` excludes `path` regardless of later rules/includes.
            let mut inc_first = vec![FilterRule {
                include: true,
                pattern: format!("/{p_str}"),
            }];
            inc_first.extend(rules.clone());
            let f_inc_first = FilterSet::from_options(&FilterOptions {
                includes: includes.clone(),
                rules: inc_first,
                ..Default::default()
            })
            .unwrap();
            prop_assert!(f_inc_first.matches_file(&path));

            let mut exc_first = vec![FilterRule {
                include: false,
                pattern: format!("/{p_str}"),
            }];
            exc_first.extend(rules);
            let f_exc_first = FilterSet::from_options(&FilterOptions {
                includes,
                rules: exc_first,
                ..Default::default()
            })
            .unwrap();
            prop_assert!(!f_exc_first.matches_file(&path));
        }

        #[test]
        fn prop_min_max_size_and_age_bounds_exact_semantics(
            size in 0u64..=10_000_000,
            min_size in prop::option::of(0u64..=10_000_000),
            max_size in prop::option::of(0u64..=10_000_000),
            now_secs in 1_000_000i64..=2_000_000_000i64,
            mtime_delta_secs in -100_000i64..=100_000i64,
            min_age_secs in prop::option::of(0i64..=100_000i64),
            max_age_secs in prop::option::of(0i64..=100_000i64),
        ) {
            let now_ns = now_secs * 1_000_000_000;
            let mtime_ns = (now_secs - mtime_delta_secs) * 1_000_000_000;
            let min_age_ns = min_age_secs.map(|s| s * 1_000_000_000);
            let max_age_ns = max_age_secs.map(|s| s * 1_000_000_000);

            let filter = FilterSet::from_options(&FilterOptions {
                min_size,
                max_size,
                min_age_ns,
                max_age_ns,
                ..Default::default()
            })
            .unwrap();
            let entry = mk_file("sample/file.bin", size, mtime_ns);
            let age_ns = now_ns.saturating_sub(mtime_ns);
            let expected = min_size.is_none_or(|lo| size >= lo)
                && max_size.is_none_or(|hi| size <= hi)
                && min_age_ns.is_none_or(|lo| age_ns >= lo)
                && max_age_ns.is_none_or(|hi| age_ns <= hi);
            prop_assert_eq!(filter.matches_entry(&entry, now_ns), expected);
        }
    }
}
