use super::caller::validate_existing;
use super::*;

#[test]
fn legacy_approval_rejects_changed_conditions_permissions_and_inputs() {
    let audited: serde_yaml::Value =
        serde_yaml::from_str(include_str!("legacy-approve.yml")).unwrap();
    assert!(
        validate_existing(
            ".github/workflows/approve-request.yml",
            serde_yaml::to_string(&audited).unwrap().as_bytes(),
            "main"
        )
        .is_ok()
    );
    for field in ["if", "env", "runs-on", "permissions", "timeout-minutes"] {
        let mut changed = audited.clone();
        changed["jobs"]["approve"][field] = serde_yaml::Value::String("custom restriction".into());
        assert!(
            validate_existing(
                ".github/workflows/approve-request.yml",
                serde_yaml::to_string(&changed).unwrap().as_bytes(),
                "main"
            )
            .is_err(),
            "accepted customized {field}"
        );
    }
    let mut changed = audited;
    changed["jobs"]["approve"]["steps"][1]["with"]["extra"] =
        serde_yaml::Value::String("custom input".into());
    assert!(
        validate_existing(
            ".github/workflows/approve-request.yml",
            serde_yaml::to_string(&changed).unwrap().as_bytes(),
            "main"
        )
        .is_err()
    );
}

#[test]
fn publisher_gate_accepts_only_successful_owner_run_for_current_published_sha() {
    use crate::fixtures::{Fixture, Route};
    let sha = "a".repeat(40);
    let publisher = json!({"id":17,"repository":{"full_name":SERVER,"id":1},"head_repository":{"full_name":SERVER,"id":1},"path":".github/workflows/publish-runtime.yml@refs/heads/main","event":"workflow_dispatch","head_branch":"main","head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":PUBLISHER_ACTOR},"triggering_actor":{"id":PUBLISHER_ACTOR}});
    let release = json!({"id":31,"tag_name":format!("securefix-runtime-{sha}"),"target_commitish":sha,"draft":false,"prerelease":true,"assets":[{"name":RUNTIME_ASSET,"state":"uploaded","size":9,"digest":"sha256:abcd"}]});
    let policy = Policy::load("policy.json").unwrap();
    let fixture = Fixture::new(vec![
        Route::get(
            format!("/repos/{SERVER}/actions/runs/17"),
            publisher.clone(),
        ),
        Route::get(
            format!("/repos/{SERVER}"),
            json!({"full_name":SERVER,"owner":{"id":policy.owner_id}}),
        ),
        Route::get(format!("/repos/{SERVER}/commits/main"), json!({"sha":sha})),
        Route::get(
            format!("/repos/{SERVER}/releases/tags/securefix-runtime-{sha}"),
            release,
        ),
    ]);
    assert_eq!(
        validate_promotion(&fixture.api, &policy, 17)
            .unwrap()
            .source_sha,
        sha
    );
    fixture.finish();

    let mut failed = publisher;
    failed["conclusion"] = json!("failure");
    let fixture = Fixture::new(vec![Route::get(
        format!("/repos/{SERVER}/actions/runs/17"),
        failed,
    )]);
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();

    for (field, value) in [
        ("actor", json!({"id": 99})),
        ("triggering_actor", json!({"id": 99})),
        ("path", json!(".github/workflows/other.yml@refs/heads/main")),
        ("head_sha", json!("b".repeat(40))),
    ] {
        let mut invalid = json!({"id":17,"repository":{"full_name":SERVER,"id":1},"head_repository":{"full_name":SERVER,"id":1},"path":".github/workflows/publish-runtime.yml@refs/heads/main","event":"workflow_dispatch","head_branch":"main","head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":PUBLISHER_ACTOR},"triggering_actor":{"id":PUBLISHER_ACTOR}});
        invalid[field] = value;
        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/{SERVER}/actions/runs/17"),
            invalid,
        )]);
        assert!(
            validate_promotion(&fixture.api, &policy, 17).is_err(),
            "publisher accepted invalid {field}"
        );
        fixture.finish();
    }
}

#[test]
fn reconcile_reuses_one_scoped_open_pr_and_does_not_duplicate_it() {
    use crate::fixtures::{Fixture, Route};
    let policy = Policy::load("policy.json").unwrap();
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        publisher_run_id: 17,
        source_run_id: 18,
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(
            ".github/workflows/approve-request.yml".into(),
            b"approved".to_vec(),
        )]),
        default_current: false,
        already_current: true,
    };
    let pr = json!({"state":"open","user":{"id":policy.server_bot_id},"number":4,"head":{"repo":{"full_name":"civitaspo/nagi"},"ref":UPDATE_BRANCH},"base":{"repo":{"full_name":"civitaspo/nagi"},"ref":"main"}});
    let fixture = Fixture::new(vec![
        Route::get(
            "/repos/civitaspo/nagi/pulls?state=open&head=civitaspo:automation/securefix-runtime&per_page=100&page=1",
            json!([pr.clone()]),
        ),
        Route::get(
            "/repos/civitaspo/nagi/pulls/4/files?per_page=100&per_page=100&page=1",
            json!([{"filename":".github/workflows/approve-request.yml","status":"modified"}]),
        ),
        Route::get(
            "/repos/civitaspo/nagi/pulls?state=open&head=civitaspo:automation/securefix-runtime&per_page=100&page=1",
            json!([pr]),
        ),
        Route::get(
            "/repos/civitaspo/nagi/pulls/4/files?per_page=100&per_page=100&page=1",
            json!([{"filename":".github/workflows/approve-request.yml","status":"modified"}]),
        ),
    ]);
    assert_eq!(
        reconcile_pull_request(&fixture.api, &policy, &migration).unwrap(),
        4
    );
    assert_eq!(
        reconcile_pull_request(&fixture.api, &policy, &migration).unwrap(),
        4
    );
    fixture.finish();
}

#[test]
fn caller_pr_with_wrong_base_fails_before_reading_or_writing_files() {
    use crate::fixtures::{Fixture, Route};
    let policy = Policy::load("policy.json").unwrap();
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        publisher_run_id: 17,
        source_run_id: 18,
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(
            ".github/workflows/approve-request.yml".into(),
            b"approved".to_vec(),
        )]),
        default_current: false,
        already_current: true,
    };
    let pr = json!({"user":{"id":policy.server_bot_id},"number":4,"head":{"repo":{"full_name":"civitaspo/nagi"},"ref":UPDATE_BRANCH},"base":{"repo":{"full_name":"civitaspo/nagi"},"ref":"attacker-branch"}});
    let fixture = Fixture::new(vec![Route::get(
        "/repos/civitaspo/nagi/pulls?state=open&head=civitaspo:automation/securefix-runtime&per_page=100&page=1",
        json!([pr]),
    )]);
    assert!(validate_existing_pull_request(&fixture.api, &policy, &migration).is_err());
    fixture.finish();
}

#[test]
fn canonical_bot_branch_accepts_current_or_prior_runtime_and_rejects_bad_commits_and_tree_modes() {
    use crate::fixtures::{Fixture, Route};

    let policy = Policy::load("policy.json").unwrap();
    let source_sha = "b".repeat(40);
    let desired = rendered_files(&source_sha, "main", false).unwrap();
    let prior = rendered_files(&"a".repeat(40), "main", false).unwrap();

    let routes = |branch_files: &BTreeMap<String, Vec<u8>>,
                  author_id: u64,
                  verified: bool,
                  mode: &str,
                  status: &str| {
        let keys: Vec<_> = branch_files.keys().cloned().collect();
        let diff = keys
            .iter()
            .map(|path| json!({"filename":path,"status":"modified"}))
            .collect::<Vec<_>>();
        let tree = keys
            .iter()
            .map(|path| json!({"path":path,"type":"blob","mode":mode,"sha":"d".repeat(40)}))
            .collect::<Vec<_>>();
        let mut routes = vec![
            Route::get(
                "/repos/civitaspo/nagi/git/ref/heads/automation/securefix-runtime",
                json!({"object":{"sha":"c".repeat(40)}}),
            ),
            Route::get(
                "/repos/civitaspo/nagi/commits/main",
                json!({"sha":"e".repeat(40)}),
            ),
            Route::get(
                format!(
                    "/repos/civitaspo/nagi/compare/{}...{}",
                    "e".repeat(40),
                    "c".repeat(40)
                ),
                json!({"status":status,"files":if status == "behind" {vec![]} else {diff},"total_commits":if status == "behind" {0} else {1},"commits":if status == "behind" {vec![]} else {vec![json!({"sha":"c".repeat(40)})]}}),
            ),
            Route::get(
                "/repos/civitaspo/nagi/commits/cccccccccccccccccccccccccccccccccccccccc",
                json!({"author":{"id":author_id},"commit":{"verification":{"verified":verified}}}),
            ),
            Route::get(
                "/repos/civitaspo/nagi/git/commits/cccccccccccccccccccccccccccccccccccccccc",
                json!({"tree":{"sha":"9".repeat(40)}}),
            ),
            Route::get(
                "/repos/civitaspo/nagi/git/trees/9999999999999999999999999999999999999999?recursive=1",
                json!({"truncated":false,"tree":tree}),
            ),
        ];
        for (path, bytes) in branch_files {
            use base64::Engine;
            routes.push(Route::get(
                    format!("/repos/civitaspo/nagi/contents/{path}?ref={}", "c".repeat(40)),
                    json!({"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(bytes)}),
                ));
        }
        routes
    };
    let migration = |files| CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        publisher_run_id: 17,
        source_run_id: 18,
        source_sha: source_sha.clone(),
        files,
        default_current: false,
        already_current: false,
    };

    let fixture = Fixture::new(routes(
        &desired,
        policy.server_bot_id,
        true,
        "100644",
        "ahead",
    ));
    let result = validate_automation_branch(&fixture.api, &policy, &migration(desired.clone()));
    assert!(result.is_ok(), "branch gate failed: {result:?}");
    assert!(result.unwrap());
    fixture.finish();
    let fixture = Fixture::new(routes(
        &prior,
        policy.server_bot_id,
        true,
        "100644",
        "ahead",
    ));
    let result = validate_automation_branch(&fixture.api, &policy, &migration(desired.clone()));
    assert!(!result.unwrap());
    fixture.finish();

    let fixture = Fixture::new(routes(
        &prior,
        policy.server_bot_id,
        true,
        "100644",
        "behind",
    ));
    assert!(
        !validate_automation_branch(&fixture.api, &policy, &migration(desired.clone())).unwrap()
    );
    fixture.finish();

    let fixture = Fixture::new(
        routes(&desired, policy.server_bot_id, false, "100644", "ahead")
            .into_iter()
            .take(4)
            .collect(),
    );
    assert!(
        validate_automation_branch(&fixture.api, &policy, &migration(desired.clone())).is_err()
    );
    fixture.finish();

    let fixture = Fixture::new(
        routes(&desired, 99, true, "100644", "ahead")
            .into_iter()
            .take(4)
            .collect(),
    );
    assert!(
        validate_automation_branch(&fixture.api, &policy, &migration(desired.clone())).is_err()
    );
    fixture.finish();

    let fixture = Fixture::new(
        routes(&desired, policy.server_bot_id, true, "120000", "ahead")
            .into_iter()
            .take(6)
            .collect(),
    );
    assert!(validate_automation_branch(&fixture.api, &policy, &migration(desired)).is_err());
    fixture.finish();
}

#[test]
fn already_migrated_default_branch_is_a_noop_without_pull_request_api_calls() {
    let policy = Policy::load("policy.json").unwrap();
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        publisher_run_id: 17,
        source_run_id: 18,
        source_sha: "a".repeat(40),
        files: BTreeMap::new(),
        default_current: true,
        already_current: true,
    };
    let fixture = crate::fixtures::Fixture::new(vec![]);
    assert_eq!(
        reconcile_pull_request(&fixture.api, &policy, &migration).unwrap(),
        0
    );
    fixture.finish();
}

#[test]
fn registry_is_exactly_the_nine_non_server_securefix_callers() {
    let policy = Policy::load("policy.json").unwrap();
    assert!(
        caller_names(&policy)
            .unwrap()
            .contains(&"civitaspo/nagi".to_owned())
    );
    let mut changed = policy;
    changed
        .repositories
        .retain(|entry| entry.repository != "civitaspo/nagi");
    assert!(
        !caller_names(&changed)
            .unwrap()
            .contains(&"civitaspo/nagi".to_owned())
    );
}

#[test]
fn actual_nine_caller_inventory_contains_only_supported_managed_workflow_shapes() {
    let callers: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/distribution-callers.json"
    ))
    .unwrap();
    let callers = callers.as_array().unwrap();
    assert_eq!(callers.len(), 9);
    for caller in callers {
        let repository = caller["repository"].as_str().unwrap();
        let files = caller["files"].as_object().unwrap();
        assert!(
            files.contains_key(".github/workflows/approve-request.yml"),
            "{repository}"
        );
        assert!(
            files.contains_key(".github/workflows/merge-request.yml"),
            "{repository}"
        );
        for (path, contents) in files {
            validate_existing(
                path,
                contents.as_str().unwrap().as_bytes(),
                caller["default_branch"].as_str().unwrap(),
            )
            .unwrap_or_else(|e| panic!("{repository}/{path}: {e:#}"));
        }
    }
}

#[test]
fn templates_render_exact_sha_default_branch_and_capability_specific_files() {
    let sha = "a".repeat(40);
    let files = rendered_files(&sha, "trunk", false).unwrap();
    assert_eq!(files.len(), 3);
    let policy = String::from_utf8(files[".github/workflows/policy-check.yml"].clone()).unwrap();
    assert!(policy.contains(&format!("reusable-policy-check.yml@{sha}")));
    assert!(policy.contains("branches:\n      - \"trunk\""));
    assert!(!policy.contains("@SECUREFIX_RUNTIME_SHA@"));
    let releases = rendered_files(&sha, "main", true).unwrap();
    assert_eq!(releases.len(), 6);
    let tag = String::from_utf8(releases[".github/workflows/release-tag.yml"].clone()).unwrap();
    assert!(tag.contains("release_pr_number"));
    assert!(!tag.contains("merge_sha"));
}

#[test]
fn migration_renderer_rejects_custom_jobs_and_unknown_legacy_approval_steps() {
    let canonical = rendered_files(&"a".repeat(40), "main", false).unwrap();
    let mut custom: serde_yaml::Value =
        serde_yaml::from_slice(&canonical[".github/workflows/merge-request.yml"]).unwrap();
    custom["jobs"]["custom"] =
        serde_yaml::from_str("runs-on: ubuntu-latest\nsteps:\n  - run: curl attacker").unwrap();
    let custom = serde_yaml::to_string(&custom).unwrap();
    assert!(
        validate_existing(
            ".github/workflows/merge-request.yml",
            custom.as_bytes(),
            "main"
        )
        .is_err()
    );
    let legacy = b"name: Approve Request\non: pull_request_target\npermissions: {}\njobs:\n  approve:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo custom\n      - uses: attacker/action@main\n";
    assert!(validate_existing(".github/workflows/approve-request.yml", legacy, "main").is_err());
}
