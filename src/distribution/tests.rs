use super::caller::validate_existing;
use super::*;

#[test]
fn legacy_approval_rejects_changed_conditions_permissions_and_inputs() {
    let templates = caller::legacy_approval_templates().unwrap();
    for source in [
        include_str!("legacy-approve.yml"),
        include_str!("legacy-approve-infobox.yml"),
    ] {
        assert!(!source.contains("civitaspo"));
        assert!(!source.contains("cursoragent"));
        assert!(!source.contains("3872492"));
        assert!(!source.contains("securefix-server"));
    }
    for template in &templates {
        assert!(
            validate_existing(
                ".github/workflows/approve-request.yml",
                template.as_bytes(),
                "main"
            )
            .is_ok()
        );
    }
    let audited: serde_yaml::Value = serde_yaml::from_str(&templates[0]).unwrap();
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
fn prepared_caller_migration_requires_exact_regular_managed_files() {
    let files = BTreeMap::from([(
        ".github/workflows/approve-request.yml".to_owned(),
        b"reviewed workflow".to_vec(),
    )]);
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files,
        default_current: false,
    };
    let directory = tempfile::tempdir().unwrap();
    caller::write_migration(directory.path(), &migration).unwrap();
    assert!(caller::validate_migration_files(directory.path(), &migration).is_ok());

    std::fs::write(
        directory
            .path()
            .join(".github/workflows/approve-request.yml"),
        b"changed workflow",
    )
    .unwrap();
    assert!(caller::validate_migration_files(directory.path(), &migration).is_err());

    std::fs::remove_file(
        directory
            .path()
            .join(".github/workflows/approve-request.yml"),
    )
    .unwrap();
    std::fs::write(directory.path().join("expected.yml"), b"reviewed workflow").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        directory.path().join("expected.yml"),
        directory
            .path()
            .join(".github/workflows/approve-request.yml"),
    )
    .unwrap();
    #[cfg(unix)]
    assert!(caller::validate_migration_files(directory.path(), &migration).is_err());
}

#[test]
fn runtime_update_auto_merge_requires_the_fresh_server_owned_pr_and_managed_files() {
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(".github/workflows/ci.yml".into(), b"canonical".to_vec())]),
        default_current: false,
    };
    let head = "b".repeat(40);
    let pull = json!({
        "number": 19,
        "state": "open",
        "draft": false,
        "user": {"id": policy.server_bot_id, "type": "Bot"},
        "head": {"repo": {"full_name": "civitaspo/nagi"}, "ref": "automation/securefix-runtime", "sha": head},
        "base": {"repo": {"full_name": "civitaspo/nagi"}, "ref": "main"}
    });
    assert!(validate_runtime_update_pull_request(&policy, &migration, 19, &pull, &head).is_ok());
    let mut bad = pull.clone();
    bad["draft"] = json!(true);
    assert!(validate_runtime_update_pull_request(&policy, &migration, 19, &bad, &head).is_err());
    let mut bad = pull.clone();
    bad["head"]["sha"] = json!("c".repeat(40));
    assert!(validate_runtime_update_pull_request(&policy, &migration, 19, &bad, &head).is_err());
    let mut bad = pull;
    bad["user"]["type"] = json!("User");
    assert!(validate_runtime_update_pull_request(&policy, &migration, 19, &bad, &head).is_err());

    assert!(
        validate_runtime_update_changed_files(
            &migration,
            &[json!({"filename":".github/workflows/ci.yml","status":"modified"})]
        )
        .is_ok()
    );
    for changed in [
        vec![json!({"filename":".github/workflows/extra.yml","status":"added"})],
        vec![json!({"filename":".github/workflows/ci.yml","status":"removed"})],
        vec![],
    ] {
        assert!(validate_runtime_update_changed_files(&migration, &changed).is_err());
    }
}

#[test]
fn runtime_update_auto_merge_sha_pins_the_merge_and_verifies_default_branch_contents() {
    use crate::fixtures::{Fixture, Route};
    use base64::Engine;

    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let repository = crate::config::trusted()
        .unwrap()
        .deployment
        .integration
        .repository
        .clone();
    let branch = crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch
        .clone();
    let source_sha = "a".repeat(40);
    let migration = CallerMigration {
        repository: repository.clone(),
        default_branch: "main".into(),
        source_sha: source_sha.clone(),
        files: rendered_files(&source_sha, "v0.2.3", "main", false).unwrap(),
        default_current: false,
    };
    let head = "c".repeat(40);
    let base = "d".repeat(40);
    let merge_sha = "f".repeat(40);
    let pull = json!({
        "number": 19,
        "state": "open",
        "draft": false,
        "user": {"id": policy.server_bot_id, "type": "Bot"},
        "head": {"repo": {"full_name": repository}, "ref": branch, "sha": head},
        "base": {"repo": {"full_name": repository}, "ref": "main"}
    });
    let diff = migration
        .files
        .keys()
        .map(|path| json!({"filename":path,"status":"modified"}))
        .collect::<Vec<_>>();
    let entries = migration
        .files
        .keys()
        .map(|path| json!({"path":path,"type":"blob","mode":"100644","sha":"e".repeat(40)}))
        .collect::<Vec<_>>();
    let content = |bytes: &[u8]| json!({"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(bytes)});
    let mut routes = vec![
        Route::get(format!("/repos/{repository}/pulls/19"), pull.clone()),
        Route::get(
            format!("/repos/{repository}/git/ref/heads/{branch}"),
            json!({"object":{"sha":head}}),
        ),
        Route::get(
            format!("/repos/{repository}/git/ref/heads/{branch}"),
            json!({"object":{"sha":head}}),
        ),
        Route::get(
            format!("/repos/{repository}/commits/main"),
            json!({"sha":base}),
        ),
        Route::get(
            format!("/repos/{repository}/compare/{base}...{head}"),
            json!({"status":"ahead","files":diff,"total_commits":1,"commits":[{"sha":head}]}),
        ),
        Route::get(
            format!("/repos/{repository}/commits/{head}"),
            json!({"author":{"id":policy.server_bot_id},"commit":{"verification":{"verified":true}}}),
        ),
        Route::get(
            format!("/repos/{repository}/git/commits/{head}"),
            json!({"tree":{"sha":"e".repeat(40)}}),
        ),
        Route::get(
            format!(
                "/repos/{repository}/git/trees/{}?recursive=1",
                "e".repeat(40)
            ),
            json!({"truncated":false,"tree":entries}),
        ),
    ];
    for (path, bytes) in &migration.files {
        routes.push(Route::get(
            format!("/repos/{repository}/contents/{path}?ref={head}"),
            content(bytes),
        ));
    }
    routes.extend([
        Route::get(
            format!("/repos/{repository}/pulls/19/files?per_page=100&page=1"),
            json!(
                migration
                    .files
                    .keys()
                    .map(|path| json!({"filename":path,"status":"modified"}))
                    .collect::<Vec<_>>()
            ),
        ),
        Route::get(format!("/repos/{repository}/pulls/19"), pull),
        Route::get(
            format!("/repos/{repository}/git/ref/heads/{branch}"),
            json!({"object":{"sha":head}}),
        ),
        Route::get(
            format!(
                "/repos/{}/commits/main",
                crate::config::trusted()
                    .unwrap()
                    .deployment
                    .server
                    .repository
            ),
            json!({"sha":source_sha}),
        ),
        Route::request(
            "PUT",
            format!("/repos/{repository}/pulls/19/merge"),
            200,
            json!({"merged":true,"sha":merge_sha}),
        )
        .with_request_body(json!({"sha":head,"merge_method":"squash"})),
        Route::get(
            format!("/repos/{repository}/commits/main"),
            json!({"sha":merge_sha}),
        ),
    ]);
    for (path, bytes) in &migration.files {
        routes.push(Route::get(
            format!("/repos/{repository}/contents/{path}?ref={merge_sha}"),
            content(bytes),
        ));
    }
    let fixture = Fixture::new(routes);
    assert_eq!(
        merge_runtime_update(&fixture.api, &policy, &migration, 19, &head).unwrap(),
        merge_sha
    );
    fixture.finish();
}

#[test]
fn runtime_update_auto_merge_aborts_when_the_branch_head_moves_before_validation() {
    use crate::fixtures::{Fixture, Route};
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let migration = CallerMigration {
        repository: crate::config::trusted()
            .unwrap()
            .deployment
            .integration
            .repository
            .clone(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(".github/workflows/ci.yml".into(), b"canonical".to_vec())]),
        default_current: false,
    };
    let branch = crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch
        .clone();
    let head = "b".repeat(40);
    let moved_head = "c".repeat(40);
    let pull = json!({
        "number": 19,
        "state": "open",
        "draft": false,
        "user": {"id": policy.server_bot_id, "type": "Bot"},
        "head": {"repo": {"full_name": migration.repository}, "ref": branch, "sha": head},
        "base": {"repo": {"full_name": migration.repository}, "ref": "main"}
    });
    let fixture = Fixture::new(vec![
        Route::get(format!("/repos/{}/pulls/19", migration.repository), pull),
        Route::get(
            format!("/repos/{}/git/ref/heads/{branch}", migration.repository),
            json!({"object":{"sha":moved_head}}),
        ),
    ]);
    assert!(merge_runtime_update(&fixture.api, &policy, &migration, 19, &head).is_err());
    fixture.finish();
}

#[test]
fn runtime_update_auto_merge_waits_for_only_the_same_valid_pr_head_to_catch_up() {
    use crate::fixtures::{Fixture, Route};
    use std::time::Duration;

    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let repository = crate::config::trusted()
        .unwrap()
        .deployment
        .integration
        .repository
        .clone();
    let branch = crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch
        .clone();
    let migration = CallerMigration {
        repository: repository.clone(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::new(),
        default_current: false,
    };
    let old_head = "b".repeat(40);
    let expected_head = "c".repeat(40);
    let pr = |head: &str| {
        json!({
            "number": 19,
            "state": "open",
            "draft": false,
            "user": {"id": policy.server_bot_id, "type": "Bot"},
            "head": {"repo": {"full_name": repository}, "ref": branch, "sha": head},
            "base": {"repo": {"full_name": repository}, "ref": "main"}
        })
    };
    let fixture = Fixture::new(vec![
        Route::get(format!("/repos/{repository}/pulls/19"), pr(&old_head)),
        Route::get(
            format!("/repos/{repository}/git/ref/heads/{branch}"),
            json!({"object":{"sha":expected_head}}),
        ),
        Route::get(format!("/repos/{repository}/pulls/19"), pr(&expected_head)),
    ]);
    let pull = wait_for_runtime_update_pull_request_with_interval(
        &fixture.api,
        &policy,
        &migration,
        19,
        &expected_head,
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(pull["head"]["sha"], expected_head);
    fixture.finish();
}

#[test]
fn caller_migration_requires_repository_owner_identity_not_human_owner_identity() {
    use crate::fixtures::{Fixture, Route};

    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let trusted = crate::config::trusted().unwrap();
    assert_ne!(trusted.owner_id, trusted.deployment.repository_owner.id);
    let repository = policy
        .repositories
        .iter()
        .find(|entry| entry.repository != trusted.deployment.server.repository)
        .unwrap()
        .repository
        .as_str();
    let fixture = Fixture::new(vec![Route::get(
        format!("/repos/{repository}"),
        json!({
            "full_name":repository,
            "owner":{"id":trusted.owner_id},
            "default_branch":trusted.deployment.server.default_branch
        }),
    )]);

    assert!(caller::prepare_caller(&fixture.api, &policy, repository, &"a".repeat(40)).is_err());
    fixture.finish();
}

#[test]
fn publisher_gate_accepts_only_successful_owner_run_for_current_published_sha() {
    use crate::fixtures::{Fixture, Route};
    let trusted = crate::config::trusted().unwrap();
    let server = &trusted.deployment.server.repository;
    let branch = &trusted.deployment.server.default_branch;
    let owner_id = trusted.owner_id;
    let sha = "a".repeat(40);
    let publisher = json!({"id":17,"repository":{"full_name":server,"id":trusted.deployment.server.id},"head_repository":{"full_name":server,"id":trusted.deployment.server.id},"path":format!(".github/workflows/publish-runtime.yml@refs/heads/{branch}"),"event":"workflow_dispatch","head_branch":branch,"head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":owner_id},"triggering_actor":{"id":owner_id}});
    let release = json!({"id":31,"tag_name":"v0.2.0-pre.1","name":"v0.2.0-pre.1","target_commitish":sha,"draft":false,"prerelease":true,"assets":[{"name":RUNTIME_ASSET,"state":"uploaded","size":9,"digest":format!("sha256:{}", "a".repeat(64))}]});
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let fixture = Fixture::new(vec![
        Route::get(
            format!("/repos/{server}/actions/runs/17"),
            publisher.clone(),
        ),
        Route::get(
            format!("/repos/{server}"),
            json!({
                "full_name":server,
                "id":trusted.deployment.server.id,
                "owner":{"id":trusted.deployment.repository_owner.id}
            }),
        ),
        Route::get(
            format!("/repos/{server}/commits/{branch}"),
            json!({"sha":sha}),
        ),
        Route::get(
            format!("/repos/{server}/contents/Cargo.toml?ref={sha}"),
            json!({"type":"file","path":"Cargo.toml","size":34,"encoding":"base64","content":"W3BhY2thZ2VdCnZlcnNpb24gPSAiMC4yLjAtcHJlLjEiCg=="}),
        ),
        Route::get(
            format!("/repos/{server}/releases/tags/v0.2.0-pre.1"),
            release,
        ),
        Route::get(
            format!("/repos/{server}/git/ref/tags/{}", "v0.2.0-pre.1"),
            json!({"ref":"refs/tags/v0.2.0-pre.1","object":{"type":"commit","sha":sha}}),
        ),
    ]);
    assert_eq!(
        validate_promotion(&fixture.api, &policy, 17)
            .unwrap()
            .source_sha,
        sha
    );
    fixture.finish();

    let fixture = Fixture::new(vec![
        Route::get(
            format!("/repos/{server}/actions/runs/17"),
            json!({
                "id":17,
                "repository":{"full_name":server,"id":trusted.deployment.server.id},
                "head_repository":{"full_name":server,"id":trusted.deployment.server.id},
                "path":format!(".github/workflows/publish-runtime.yml@refs/heads/{branch}"),
                "event":"workflow_dispatch",
                "head_branch":branch,
                "head_sha":sha,
                "run_attempt":2,
                "status":"completed",
                "conclusion":"success",
                "actor":{"id":owner_id},
                "triggering_actor":{"id":owner_id}
            }),
        ),
        Route::get(
            format!("/repos/{server}"),
            json!({
                "full_name":server,
                "id":trusted.deployment.server.id,
                "owner":{"id":owner_id}
            }),
        ),
    ]);
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();

    let mut failed = publisher;
    failed["conclusion"] = json!("failure");
    let fixture = Fixture::new(vec![Route::get(
        format!("/repos/{server}/actions/runs/17"),
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
        let mut invalid = json!({"id":17,"repository":{"full_name":server,"id":trusted.deployment.server.id},"head_repository":{"full_name":server,"id":trusted.deployment.server.id},"path":format!(".github/workflows/publish-runtime.yml@refs/heads/{branch}"),"event":"workflow_dispatch","head_branch":branch,"head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":owner_id},"triggering_actor":{"id":owner_id}});
        invalid[field] = value;
        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/{server}/actions/runs/17"),
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
fn promotion_gate_binds_manifest_version_release_identity_and_direct_ref() {
    use crate::fixtures::{Fixture, Route};
    use base64::Engine;

    let trusted = crate::config::trusted().unwrap();
    let server = &trusted.deployment.server.repository;
    let branch = &trusted.deployment.server.default_branch;
    let owner_id = trusted.owner_id;
    let sha = "a".repeat(40);
    let publisher = json!({"id":17,"repository":{"full_name":server,"id":trusted.deployment.server.id},"head_repository":{"full_name":server,"id":trusted.deployment.server.id},"path":format!(".github/workflows/publish-runtime.yml@refs/heads/{branch}"),"event":"workflow_dispatch","head_branch":branch,"head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":owner_id},"triggering_actor":{"id":owner_id}});
    let make_routes = |source_version: &str,
                       release_tag: &str,
                       release_target: &str,
                       release_prerelease: bool,
                       ref_type: &str,
                       ref_sha: &str,
                       include_ref: bool| {
        let manifest = format!("[package]\nversion = \"{source_version}\"\n");
        let canonical_tag = format!("v{source_version}");
        let mut routes = vec![
            Route::get(
                format!("/repos/{server}/actions/runs/17"),
                publisher.clone(),
            ),
            Route::get(
                format!("/repos/{server}"),
                json!({"full_name":server,"id":trusted.deployment.server.id,"owner":{"id":trusted.deployment.repository_owner.id}}),
            ),
            Route::get(
                format!("/repos/{server}/commits/{branch}"),
                json!({"sha":sha}),
            ),
            Route::get(
                format!("/repos/{server}/contents/Cargo.toml?ref={sha}"),
                json!({
                    "type":"file",
                    "path":"Cargo.toml",
                    "size":manifest.len(),
                    "encoding":"base64",
                    "content":base64::engine::general_purpose::STANDARD.encode(manifest)
                }),
            ),
            Route::get(
                format!("/repos/{server}/releases/tags/{canonical_tag}"),
                json!({
                    "id":31,
                    "tag_name":release_tag,
                    "name":release_tag,
                    "target_commitish":release_target,
                    "draft":false,
                    "prerelease":release_prerelease,
                    "assets":[{"name":RUNTIME_ASSET,"state":"uploaded","size":9,"digest":format!("sha256:{}", "a".repeat(64))}]
                }),
            ),
        ];
        if include_ref {
            routes.push(Route::get(
                format!("/repos/{server}/git/ref/tags/{canonical_tag}"),
                json!({"ref":format!("refs/tags/{canonical_tag}"),"object":{"type":ref_type,"sha":ref_sha}}),
            ));
        }
        routes
    };
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();

    let fixture = Fixture::new(make_routes(
        "0.2.0-pre.2",
        "v0.2.0-pre.1",
        &sha,
        true,
        "commit",
        &sha,
        false,
    ));
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();

    let fixture = Fixture::new(make_routes(
        "0.2.0-pre.1",
        "v0.2.0-pre.1",
        &"b".repeat(40),
        true,
        "commit",
        &sha,
        false,
    ));
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();

    let fixture = Fixture::new(make_routes(
        "0.2.0-pre.1",
        "v0.2.0-pre.1",
        &sha,
        true,
        "commit",
        &"b".repeat(40),
        true,
    ));
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();

    let fixture = Fixture::new(make_routes(
        "0.2.0-pre.1",
        "v0.2.0-pre.1",
        &sha,
        true,
        "tag",
        &sha,
        true,
    ));
    assert!(validate_promotion(&fixture.api, &policy, 17).is_err());
    fixture.finish();
}

#[test]
fn promotion_gate_stops_on_stale_main_before_manifest_or_release_lookup() {
    use crate::fixtures::{Fixture, Route};

    let trusted = crate::config::trusted().unwrap();
    let server = &trusted.deployment.server.repository;
    let branch = &trusted.deployment.server.default_branch;
    let owner_id = trusted.owner_id;
    let sha = "a".repeat(40);
    let publisher = json!({"id":17,"repository":{"full_name":server,"id":trusted.deployment.server.id},"head_repository":{"full_name":server,"id":trusted.deployment.server.id},"path":format!(".github/workflows/publish-runtime.yml@refs/heads/{branch}"),"event":"workflow_dispatch","head_branch":branch,"head_sha":sha,"run_attempt":2,"status":"completed","conclusion":"success","actor":{"id":owner_id},"triggering_actor":{"id":owner_id}});
    let fixture = Fixture::new(vec![
        Route::get(format!("/repos/{server}/actions/runs/17"), publisher),
        Route::get(
            format!("/repos/{server}"),
            json!({"full_name":server,"id":trusted.deployment.server.id,"owner":{"id":trusted.deployment.repository_owner.id}}),
        ),
        Route::get(
            format!("/repos/{server}/commits/{branch}"),
            json!({"sha":"b".repeat(40)}),
        ),
    ]);
    let error = validate_promotion(
        &fixture.api,
        &Policy::load("tests/fixtures/policy.json").unwrap(),
        17,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publisher is not the current server main revision"),
        "stale publisher should stop at the main SHA guard: {error:#}"
    );
    fixture.finish();
}

#[test]
fn runtime_renderer_accepts_only_source_bound_canonical_or_legacy_annotations() {
    let sha = "a".repeat(40);
    for tag in ["v0.2.0-pre.1".to_owned(), format!("v0.1.0+{sha}")] {
        assert!(caller::validate_runtime_annotation(&tag, &sha).is_ok());
        let files = caller::rendered_files(&sha, &tag, "main", true).unwrap();
        assert_eq!(files.len(), 6);
        for (path, bytes) in files {
            let workflow = String::from_utf8(bytes).unwrap();
            assert!(
                workflow.contains(&format!("@{sha} # {tag}")),
                "{path} did not preserve the validated annotation"
            );
        }
        let client_files = caller::rendered_client_fixture_files(&sha, &tag).unwrap();
        assert!(
            String::from_utf8(client_files[".github/workflows/wc-autofix.yml"].clone())
                .unwrap()
                .contains(&format!("# {tag}"))
        );
    }

    for invalid in [
        format!("v0.1.0+{}", "b".repeat(40)),
        "v0.1.0+local".to_owned(),
        "v0.2.0-pre.1+local".to_owned(),
        "v0.2.0-pre.01".to_owned(),
    ] {
        assert!(caller::validate_runtime_annotation(&invalid, &sha).is_err());
        assert!(caller::rendered_files(&sha, &invalid, "main", false).is_err());
        assert!(caller::rendered_client_fixture_files(&sha, &invalid).is_err());
    }
}

#[test]
fn prior_generation_ignores_only_runtime_comment_changes() {
    let sha = "a".repeat(40);
    let mut files = caller::rendered_files(&sha, "v0.2.0-pre.1", "main", false).unwrap();
    assert!(validate_previous_generation(&files, false).is_ok());

    let approve_path = ".github/workflows/approve-request.yml";
    let approve = String::from_utf8(files[approve_path].clone()).unwrap();
    assert!(approve.contains("# v0.2.0-pre.1"));
    files.insert(
        approve_path.to_owned(),
        approve.replace("# v0.2.0-pre.1", "# v9.8.7").into_bytes(),
    );
    assert!(validate_previous_generation(&files, false).is_ok());

    let approve: serde_yaml::Value = serde_yaml::from_slice(&files[approve_path]).unwrap();
    let mut changed = approve;
    changed["jobs"]["approve"]["permissions"]["contents"] =
        serde_yaml::Value::String("write".into());
    files.insert(
        approve_path.to_owned(),
        serde_yaml::to_string(&changed).unwrap().into_bytes(),
    );
    assert!(validate_previous_generation(&files, false).is_err());
}

#[test]
fn prior_generation_accepts_only_the_legacy_read_permission_on_request_workflows() {
    let sha = "a".repeat(40);
    let mut files = caller::rendered_files(&sha, "v0.2.0-pre.1", "main", false).unwrap();
    for (path, job, approval) in [
        (".github/workflows/approve-request.yml", "approve", true),
        (".github/workflows/merge-request.yml", "request", false),
    ] {
        for issues in ["write", "read"] {
            let mut workflow: serde_yaml::Value = serde_yaml::from_slice(&files[path]).unwrap();
            workflow["jobs"][job]["permissions"]["issues"] =
                serde_yaml::Value::String(issues.into());
            workflow["jobs"][job]["permissions"]["pull-requests"] =
                serde_yaml::Value::String("read".into());
            if approval {
                workflow["concurrency"]["group"] = serde_yaml::Value::String(
                    "approve-request-${{ github.event.pull_request.number || github.event.issue.number || github.ref }}".into(),
                );
            }
            files.insert(
                path.to_owned(),
                serde_yaml::to_string(&workflow).unwrap().into_bytes(),
            );
            assert!(validate_previous_generation(&files, false).is_ok());
        }
    }
    assert!(validate_previous_generation(&files, false).is_ok());

    let path = ".github/workflows/approve-request.yml";
    let mut workflow: serde_yaml::Value = serde_yaml::from_slice(&files[path]).unwrap();
    workflow["concurrency"]["group"] =
        serde_yaml::Value::String("approve-request-${{ github.event.issue.number }}".into());
    files.insert(
        path.to_owned(),
        serde_yaml::to_string(&workflow).unwrap().into_bytes(),
    );
    assert!(validate_previous_generation(&files, false).is_err());

    let path = ".github/workflows/policy-check.yml";
    let mut workflow: serde_yaml::Value = serde_yaml::from_slice(&files[path]).unwrap();
    workflow["jobs"]["check"]["permissions"]["pull-requests"] =
        serde_yaml::Value::String("write".into());
    files.insert(
        path.to_owned(),
        serde_yaml::to_string(&workflow).unwrap().into_bytes(),
    );
    assert!(validate_previous_generation(&files, false).is_err());

    // Reset to the exact legacy generation before checking an unrelated broadening
    // on the request workflow itself.
    let path = ".github/workflows/policy-check.yml";
    let canonical = caller::rendered_files(&sha, "v0.2.0-pre.1", "main", false).unwrap();
    files.insert(path.to_owned(), canonical[path].clone());
    let path = ".github/workflows/approve-request.yml";
    let mut workflow: serde_yaml::Value = serde_yaml::from_slice(&files[path]).unwrap();
    workflow["jobs"]["approve"]["permissions"]["contents"] =
        serde_yaml::Value::String("write".into());
    files.insert(
        path.to_owned(),
        serde_yaml::to_string(&workflow).unwrap().into_bytes(),
    );
    assert!(validate_previous_generation(&files, false).is_err());
}

#[test]
fn caller_validator_accepts_only_the_exact_legacy_approve_concurrency_group() {
    let sha = "a".repeat(40);
    let files = caller::rendered_files(&sha, "v0.2.0-pre.1", "main", false).unwrap();
    let path = ".github/workflows/approve-request.yml";
    let mut workflow: serde_yaml::Value = serde_yaml::from_slice(&files[path]).unwrap();
    workflow["concurrency"]["group"] = serde_yaml::Value::String(
        "approve-request-${{ github.event.pull_request.number || github.event.issue.number || github.ref }}".into(),
    );
    workflow["jobs"]["approve"]["permissions"]["issues"] =
        serde_yaml::Value::String("write".into());
    workflow["jobs"]["approve"]["permissions"]["pull-requests"] =
        serde_yaml::Value::String("read".into());
    let legacy = serde_yaml::to_string(&workflow).unwrap();
    assert!(caller::validate_existing(path, legacy.as_bytes(), "main").is_ok());

    workflow["concurrency"]["group"] =
        serde_yaml::Value::String("approve-request-${{ github.event.issue.number }}".into());
    let unknown = serde_yaml::to_string(&workflow).unwrap();
    assert!(caller::validate_existing(path, unknown.as_bytes(), "main").is_err());
}

#[test]
fn release_tag_validator_accepts_exact_previous_empty_event_input_fallback() {
    let sha = "a".repeat(40);
    let mut files = caller::rendered_files(&sha, "v0.2.2", "main", true).unwrap();
    let path = ".github/workflows/release-tag.yml";
    let canonical = String::from_utf8(files[path].clone()).unwrap();
    let new_value = "${{ fromJSON(format('{0}', inputs.release_pr_number || github.event.pull_request.number || 0)) }}";
    assert!(canonical.contains(new_value));
    let previous = canonical.replace(new_value, "${{ inputs.release_pr_number }}");
    files.insert(path.to_owned(), previous.as_bytes().to_vec());

    assert!(validate_previous_generation(&files, true).is_ok());
    assert!(caller::validate_existing(path, previous.as_bytes(), "main").is_ok());

    let unsupported = previous.replace(
        "${{ inputs.release_pr_number }}",
        "${{ inputs.release_pr_number || 0 }}",
    );
    files.insert(path.to_owned(), unsupported.as_bytes().to_vec());
    assert!(validate_previous_generation(&files, true).is_err());
    assert!(caller::validate_existing(path, unsupported.as_bytes(), "main").is_err());
}

#[test]
fn reconcile_reuses_one_scoped_open_pr_and_does_not_duplicate_it() {
    use crate::fixtures::{Fixture, Route};
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let runtime_branch = &crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch;
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(
            ".github/workflows/approve-request.yml".into(),
            b"approved".to_vec(),
        )]),
        default_current: false,
    };
    let pr = json!({"state":"open","user":{"id":policy.server_bot_id},"number":4,"head":{"repo":{"full_name":"civitaspo/nagi"},"ref":runtime_branch},"base":{"repo":{"full_name":"civitaspo/nagi"},"ref":"main"}});
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
fn apply_caller_creates_only_the_reviewed_signed_branch_change_before_opening_a_pr() {
    use crate::fixtures::{Fixture, Route};
    use base64::Engine;

    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let server = crate::config::trusted()
        .unwrap()
        .deployment
        .server
        .repository
        .clone();
    let runtime_branch = crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch
        .clone();
    let repository = "civitaspo/nagi";
    let branch = format!("refs/heads/{runtime_branch}");
    let base_sha = "b".repeat(40);
    let source_sha = "a".repeat(40);
    let path = ".github/workflows/approve-request.yml";
    let contents = b"reviewed workflow".to_vec();
    let migration = CallerMigration {
        repository: repository.into(),
        default_branch: "main".into(),
        source_sha: source_sha.clone(),
        files: BTreeMap::from([(path.into(), contents.clone())]),
        default_current: false,
    };
    let pr = json!({"user":{"id":policy.server_bot_id},"number":4,"head":{"repo":{"full_name":repository},"ref":runtime_branch},"base":{"repo":{"full_name":repository},"ref":"main"}});
    let pull_path = "/repos/civitaspo/nagi/pulls?state=open&head=civitaspo:automation/securefix-runtime&per_page=100&page=1";
    let commit_query = "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid parents(first:2){nodes{oid}} signature{isValid state}}}}";
    let fixture = Fixture::new(vec![
        Route::request(
            "GET",
            format!("/repos/{repository}/git/ref/heads/{runtime_branch}"),
            404,
            json!({}),
        ),
        Route::get(pull_path, json!([])),
        Route::get(format!("/repos/{repository}/commits/main"), json!({"sha":base_sha})),
        Route::get(format!("/repos/{server}/commits/main"), json!({"sha":source_sha})),
        Route::request(
            "POST",
            format!("/repos/{repository}/git/refs"),
            201,
            json!({"ref":branch,"object":{"sha":base_sha}}),
        )
        .with_request_body(json!({"ref":branch,"sha":base_sha})),
        Route::get(format!("/repos/{server}/commits/main"), json!({"sha":source_sha})),
        Route::request(
            "POST",
            "/graphql",
            200,
            json!({"data":{"createCommitOnBranch":{"commit":{"oid":"c".repeat(40),"parents":{"nodes":[{"oid":base_sha}]},"signature":{"isValid":true,"state":"VALID"}}}}}),
        )
        .with_request_body(json!({
            "query":commit_query,
            "variables":{"input":{
                "branch":{"repositoryNameWithOwner":repository,"branchName":runtime_branch},
                "expectedHeadOid":base_sha,
                "message":{"headline":format!("chore: update Securefix workflows to {source_sha}"),"body":""},
                "fileChanges":{"additions":[{"path":path,"contents":base64::engine::general_purpose::STANDARD.encode(&contents)}],"deletions":[]}
            }}
        })),
        Route::get(pull_path, json!([])),
        Route::get(format!("/repos/{server}/commits/main"), json!({"sha":source_sha})),
        Route::request(
            "POST",
            format!("/repos/{repository}/pulls"),
            201,
            pr.clone(),
        ),
        Route::get(pull_path, json!([pr])),
        Route::get(
            format!("/repos/{repository}/pulls/4/files?per_page=100&per_page=100&page=1"),
            json!([{"filename":path,"status":"modified"}]),
        ),
    ]);

    assert_eq!(
        apply_caller_migration(&fixture.api, &policy, &migration, false).unwrap(),
        4
    );
    fixture.finish();
}

#[test]
fn caller_pr_with_wrong_base_fails_before_reading_or_writing_files() {
    use crate::fixtures::{Fixture, Route};
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let runtime_branch = &crate::config::trusted()
        .unwrap()
        .deployment
        .runtime_update_branch;
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::from([(
            ".github/workflows/approve-request.yml".into(),
            b"approved".to_vec(),
        )]),
        default_current: false,
    };
    let pr = json!({"user":{"id":policy.server_bot_id},"number":4,"head":{"repo":{"full_name":"civitaspo/nagi"},"ref":runtime_branch},"base":{"repo":{"full_name":"civitaspo/nagi"},"ref":"attacker-branch"}});
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

    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let source_sha = "b".repeat(40);
    let desired = rendered_files(&source_sha, "v0.2.0-pre.1", "main", false).unwrap();
    let prior = rendered_files(&"a".repeat(40), "v0.2.0-pre.1", "main", false).unwrap();

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
        source_sha: source_sha.clone(),
        files,
        default_current: false,
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
    assert_eq!(result.unwrap(), (true, Some("c".repeat(40))));
    fixture.finish();
    let fixture = Fixture::new(routes(
        &prior,
        policy.server_bot_id,
        true,
        "100644",
        "ahead",
    ));
    let result = validate_automation_branch(&fixture.api, &policy, &migration(desired.clone()));
    assert_eq!(result.unwrap(), (false, Some("c".repeat(40))));
    fixture.finish();

    let fixture = Fixture::new(routes(
        &prior,
        policy.server_bot_id,
        true,
        "100644",
        "behind",
    ));
    assert!(
        !validate_automation_branch(&fixture.api, &policy, &migration(desired.clone()))
            .unwrap()
            .0
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
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
    let migration = CallerMigration {
        repository: "civitaspo/nagi".into(),
        default_branch: "main".into(),
        source_sha: "a".repeat(40),
        files: BTreeMap::new(),
        default_current: true,
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
    let policy = Policy::load("tests/fixtures/policy.json").unwrap();
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
    let files = rendered_files(&sha, "v0.2.0-pre.1", "trunk", false).unwrap();
    assert_eq!(files.len(), 3);
    let policy = String::from_utf8(files[".github/workflows/policy-check.yml"].clone()).unwrap();
    assert!(policy.contains(&format!("reusable-policy-check.yml@{sha}")));
    assert!(policy.contains("branches:\n      - \"trunk\""));
    assert!(!policy.contains("@SECUREFIX_RUNTIME_SHA@"));
    let releases = rendered_files(&sha, "v0.2.0-pre.1", "main", true).unwrap();
    assert_eq!(releases.len(), 6);
    let tag = String::from_utf8(releases[".github/workflows/release-tag.yml"].clone()).unwrap();
    assert!(tag.contains("release_pr_number"));
    assert!(!tag.contains("merge_sha"));
}

#[test]
fn migration_renderer_rejects_custom_jobs_and_unknown_legacy_approval_steps() {
    let canonical = rendered_files(&"a".repeat(40), "v0.2.0-pre.1", "main", false).unwrap();
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

#[test]
fn migration_renderer_accepts_only_the_previous_exact_merge_body_prefilter() {
    let canonical = rendered_files(&"a".repeat(40), "v0.2.0-pre.1", "main", false).unwrap();
    let canonical = std::str::from_utf8(&canonical[".github/workflows/merge-request.yml"]).unwrap();
    assert!(
        validate_existing(
            ".github/workflows/merge-request.yml",
            canonical.as_bytes(),
            "main"
        )
        .is_ok()
    );
    let prior_condition = canonical.replace(
        "contains(github.event.comment.body, '/merge')",
        "github.event.comment.body == '/merge'",
    );
    assert_ne!(canonical, prior_condition);
    assert!(
        validate_existing(
            ".github/workflows/merge-request.yml",
            prior_condition.as_bytes(),
            "main"
        )
        .is_ok()
    );

    let relaxed_owner = prior_condition.replace(
        "github.event.comment.user.id == 4525500",
        "github.event.comment.user.id > 0",
    );
    assert!(
        validate_existing(
            ".github/workflows/merge-request.yml",
            relaxed_owner.as_bytes(),
            "main"
        )
        .is_err()
    );
    let relaxed_attempt =
        prior_condition.replace("github.run_attempt == 1", "github.run_attempt < 3");
    assert!(
        validate_existing(
            ".github/workflows/merge-request.yml",
            relaxed_attempt.as_bytes(),
            "main"
        )
        .is_err()
    );
}
