use super::*;
use crate::fixtures::{Fixture, Route};

fn host(fixture: &Fixture, auth: &Authorization) -> Host {
    let policy_bytes = include_bytes!("../policy.json").to_vec();
    let policy = Policy::parse(&policy_bytes).unwrap();
    let source = "a".repeat(40);
    Host {
        api: fixture.api.clone(),
        policy: policy.clone(),
        policy_bytes,
        context: Dispatch {
            repository: policy.deployment.server.repository.clone(),
            reference: format!("refs/heads/{}", auth.authority_branch),
            event_name: "workflow_dispatch".into(),
            workflow_ref: format!(
                "{}/{}@refs/heads/{}",
                policy.deployment.server.repository, auth.workflow, auth.authority_branch
            ),
            workflow_sha: source.clone(),
            compiled_sha: source.clone(),
            actor_id: policy.owner_id.to_string(),
            attempt: "1".into(),
            source_sha: source.clone(),
            run_id: 77,
            event: json!({"inputs":{"phase":"request-recovery-plan","authority_sha":source}}),
        },
    }
}

fn pull(auth: &Authorization, host: &Host) -> Value {
    let server = &host.policy.deployment.server;
    json!({"number":auth.pull_request,"state":"open","draft":false,"merged_at":null,
        "user":{"id":host.policy.owner_id,"login":host.policy.deployment.owner_login,"type":"User"},
        "head":{"sha":auth.expected_head_sha,"ref":auth.target_branch,"repo":{"id":server.id,"full_name":server.repository}},
        "base":{"sha":auth.expected_main_sha,"ref":server.default_branch,"repo":{"id":server.id,"full_name":server.repository}}})
}

#[test]
fn compiled_recovery_record_is_bounded_and_not_a_descriptor_change() {
    let auth = Authorization::load().unwrap();
    assert_eq!(auth.files.len(), 7);
    assert!(
        auth.files
            .iter()
            .all(|f| f.path != ACTIVE && f.path != "policy.json")
    );
    assert_eq!(
        auth.active.identity().unwrap(),
        "ab2b5b473767f6a3e58022dce677ae94a344c54fd1c12c8714a4deb6a74bd444"
    );
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../control/request-recovery.json")).unwrap();
    value["alternate_target"] = json!(123);
    assert!(serde_json::from_value::<Authorization>(value).is_err());
}

#[test]
fn recovery_dispatch_rejects_context_substitution_before_network() {
    let auth = Authorization::load().unwrap();
    let fixture = Fixture::new(vec![]);
    for field in [
        "repository",
        "reference",
        "event_name",
        "workflow_ref",
        "workflow_sha",
        "compiled_sha",
        "actor_id",
        "attempt",
        "source_sha",
        "phase",
        "authority_sha",
    ] {
        let mut host = host(&fixture, &auth);
        match field {
            "repository" => host.context.repository.push('x'),
            "reference" => host.context.reference.push('x'),
            "event_name" => host.context.event_name.push('x'),
            "workflow_ref" => host.context.workflow_ref.push('x'),
            "workflow_sha" => host.context.workflow_sha = "b".repeat(40),
            "compiled_sha" => host.context.compiled_sha = "b".repeat(40),
            "actor_id" => host.context.actor_id.push('9'),
            "attempt" => host.context.attempt = "2".into(),
            "source_sha" => host.context.source_sha = "b".repeat(40),
            "phase" => host.context.event["inputs"]["phase"] = json!("request-recovery-merge"),
            "authority_sha" => {
                host.context.event["inputs"]["authority_sha"] = json!("b".repeat(40))
            }
            _ => unreachable!(),
        }
        assert!(
            auth.dispatch(&host, "request-recovery-plan").is_err(),
            "{field}"
        );
    }
}

#[test]
fn recovery_pr_rejects_changed_head_base_author_repository_and_state() {
    let auth = Authorization::load().unwrap();
    let fixture = Fixture::new(vec![]);
    let host = host(&fixture, &auth);
    let valid = pull(&auth, &host);
    auth.pull_identity(&host, &valid).unwrap();
    for (pointer, invalid) in [
        ("/number", json!(999)),
        ("/state", json!("closed")),
        ("/draft", json!(true)),
        ("/merged_at", json!("2026-10-20T00:00:00Z")),
        ("/user/id", json!(999)),
        ("/user/type", json!("Bot")),
        ("/head/sha", json!("b".repeat(40))),
        ("/base/sha", json!("b".repeat(40))),
        ("/base/ref", json!("other")),
        ("/head/repo/id", json!(999)),
        ("/base/repo/full_name", json!("other/repo")),
    ] {
        let mut pull = valid.clone();
        *pull.pointer_mut(pointer).unwrap() = invalid;
        assert!(auth.pull_identity(&host, &pull).is_err(), "{pointer}");
    }
}

fn comparison(auth: &Authorization, host: &Host) -> Value {
    let mut parent = auth.expected_main_sha.clone();
    let commits: Vec<_> = auth.commits.iter().map(|sha| {
        let result = json!({"sha":sha,"commit":{"verification":{"verified":true}},
            "author":{"id":host.policy.owner_id},"committer":{"id":host.policy.owner_id},"parents":[{"sha":parent}]});
        parent = sha.clone(); result
    }).collect();
    json!({"base_commit":{"sha":auth.expected_main_sha},"merge_base_commit":{"sha":auth.expected_main_sha},"status":"ahead",
        "total_commits":commits.len(),"commits":commits,"files":auth.files.iter().map(|f|json!({"filename":f.path,"status":f.status})).collect::<Vec<_>>()})
}

#[test]
fn recovery_diff_requires_complete_fixed_files_and_signed_effective_committers() {
    let auth = Authorization::load().unwrap();
    let fixture = Fixture::new(vec![]);
    let host = host(&fixture, &auth);
    let valid = comparison(&auth, &host);
    auth.target_comparison(
        &host,
        &valid,
        signed_descendant_files(&valid, &auth.expected_main_sha).unwrap(),
    )
    .unwrap();
    for (pointer, value) in [
        ("/total_commits", json!(99)),
        ("/commits/0/commit/verification/verified", json!(false)),
        ("/commits/0/author/id", json!(999)),
        ("/commits/0/committer/id", json!(999)),
        ("/commits/0/parents/0/sha", json!("b".repeat(40))),
        ("/commits/0/sha", json!("b".repeat(40))),
        ("/files/0/filename", json!(ACTIVE)),
        ("/files/0/status", json!("renamed")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let result = signed_descendant_files(&changed, &auth.expected_main_sha)
            .and_then(|files| auth.target_comparison(&host, &changed, files));
        assert!(result.is_err(), "{pointer}");
    }
    let mut changed = valid.clone();
    changed["files"].as_array_mut().unwrap().pop();
    assert!(
        auth.target_comparison(&host, &changed, array(&changed["files"]).unwrap())
            .is_err()
    );
    let mut changed = valid.clone();
    changed["files"][0]["previous_filename"] = json!("policy.json");
    assert!(
        auth.target_comparison(&host, &changed, array(&changed["files"]).unwrap())
            .is_err()
    );
}

#[test]
fn owner_recovery_comment_binds_source_head_control_and_rejects_edits_and_replay() {
    let auth = Authorization::load().unwrap();
    let fixture = Fixture::new(vec![]);
    let host = host(&fixture, &auth);
    let now = chrono::Utc::now().to_rfc3339();
    let comment = json!({"id":12,"issue_url":format!("https://api.github.com/repos/{}/issues/{}",host.repository(),auth.pull_request),
        "user":{"id":host.policy.owner_id,"login":host.policy.deployment.owner_login,"type":"User"},
        "body":auth.owner_body(&host.context.compiled_sha).unwrap(),"created_at":now,"updated_at":now});
    auth.owner_comment(&host, &comment, 12).unwrap();
    for (pointer, value) in [
        ("/id", json!(13)),
        (
            "/issue_url",
            json!("https://api.github.com/repos/other/repo/issues/142"),
        ),
        ("/user/id", json!(999)),
        ("/user/type", json!("Bot")),
        ("/body", json!("/approve")),
        ("/updated_at", json!("2026-01-01T00:00:00Z")),
    ] {
        let mut changed = comment.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            auth.owner_comment(&host, &changed, 12).is_err(),
            "{pointer}"
        );
    }
    let mut changed = comment.clone();
    let old = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
    changed["created_at"] = json!(old);
    changed["updated_at"] = json!(old);
    assert!(auth.owner_comment(&host, &changed, 12).is_err());
    let mut host = host;
    host.context.compiled_sha = "b".repeat(40);
    assert!(auth.owner_comment(&host, &comment, 12).is_err());
}

#[test]
fn recovery_main_fence_stops_before_control_or_any_write_when_main_moves() {
    let auth = Authorization::load().unwrap();
    let path = format!(
        "/repos/{}/commits/main",
        Policy::parse(include_bytes!("../policy.json"))
            .unwrap()
            .deployment
            .server
            .repository
    );
    let fixture = Fixture::new(vec![Route::get(path, json!({"sha":"b".repeat(40)}))]);
    let host = host(&fixture, &auth);
    assert!(
        auth.fence(&host)
            .unwrap_err()
            .to_string()
            .contains("main moved")
    );
    fixture.finish();
}

#[test]
fn recovery_merge_core_writes_only_the_fixed_pr_and_expected_head() {
    let auth = Authorization::load().unwrap();
    let empty = Fixture::new(vec![]);
    let h = host(&empty, &auth);
    let root = format!("/repos/{}", h.repository());
    let bytes = include_bytes!("../control/active.json");
    let policy = include_bytes!("../policy.json");
    let content = |path: &str, bytes: &[u8]| json!({"type":"file","path":path,"encoding":"base64","size":bytes.len(),"content":STANDARD.encode(bytes)});
    let fixture = Fixture::new(vec![
        Route::get(
            format!("{root}/pulls/{}", auth.pull_request),
            pull(&auth, &h),
        ),
        Route::get(
            format!("{root}/commits/main"),
            json!({"sha":auth.expected_main_sha}),
        ),
        Route::get(
            format!("{root}/contents/{ACTIVE}?ref={}", auth.expected_main_sha),
            content(ACTIVE, bytes),
        ),
        Route::get(
            format!("{root}/contents/policy.json?ref={}", auth.expected_main_sha),
            content("policy.json", policy),
        ),
        Route::request(
            "PUT",
            format!("{root}/pulls/{}/merge", auth.pull_request),
            200,
            json!({"merged":true,"sha":"c".repeat(40)}),
        )
        .with_request_body(json!({"sha":auth.expected_head_sha,"merge_method":"squash"})),
    ]);
    let host = host(&fixture, &auth);
    let writer = Writer {
        host: &host,
        main: auth.expected_main_sha.clone(),
        token: "fixture-writer".into(),
        api_base: fixture.base.clone(),
        client: Client::new(),
    };
    auth.merge_fixed(&host, &writer).unwrap();
    fixture.finish();
}

fn rehearsal_authorization(state: &Value, case: &str) -> Result<Authorization> {
    let entry = &state[case];
    let mut auth = Authorization::load()?;
    auth.expected_main_sha = state["base_sha"]
        .as_str()
        .context("missing base sha")?
        .into();
    auth.pull_request = entry["number"].as_u64().context("missing fixture PR")?;
    auth.target_branch = entry["branch"]
        .as_str()
        .context("missing fixture branch")?
        .into();
    ensure!(
        auth.target_branch.starts_with("testing/recovery2-"),
        "invalid fixture branch"
    );
    auth.expected_head_sha = entry["head"]
        .as_str()
        .context("missing fixture head")?
        .into();
    auth.expected_tree_sha = entry["tree"]
        .as_str()
        .context("missing fixture tree")?
        .into();
    auth.commits = vec![auth.expected_head_sha.clone()];
    auth.files = vec![FixedFile {
        path: entry["path"]
            .as_str()
            .context("missing fixture path")?
            .into(),
        status: "added".into(),
        sha256: entry["sha256"]
            .as_str()
            .context("missing fixture digest")?
            .into(),
    }];
    Ok(auth)
}

#[test]
fn compiled_rehearsal_fixtures_pass_the_live_branch_guard() {
    let state: Value =
        serde_json::from_slice(include_bytes!("../control/request-recovery-rehearsal.json"))
            .unwrap();
    for case in ["positive", "stale"] {
        rehearsal_authorization(&state, case).unwrap();
        let mut invalid = state.clone();
        invalid[case]["branch"] = json!("main");
        assert!(rehearsal_authorization(&invalid, case).is_err());
        invalid[case]["branch"] = json!("testing/recovery-positive-20261020");
        assert!(rehearsal_authorization(&invalid, case).is_err());
    }
}

#[test]
#[ignore = "owner-dispatched scratch-only recovery rehearsal"]
fn live_request_recovery_core_rehearsal() -> Result<()> {
    let compiled = option_env!("SECUREFIX_BOOTSTRAP_SOURCE_SHA")
        .context("source-pinned test build required")?;
    let production = Authorization::load()?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")?
            == Policy::parse(include_bytes!("../policy.json"))?
                .deployment
                .server
                .repository
            && std::env::var("GITHUB_REF")?
                == format!("refs/heads/{}", production.authority_branch)
            && std::env::var("GITHUB_SHA")? == compiled
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1"
            && std::env::var("SECUREFIX_REQUEST_RECOVERY_SOURCE_SHA")? == compiled,
        "unapproved rehearsal source/context"
    );
    let state: Value =
        serde_json::from_slice(include_bytes!("../control/request-recovery-rehearsal.json"))?;
    let production_policy = Policy::parse(include_bytes!("../policy.json"))?;
    ensure!(
        std::env::var("GITHUB_ACTOR_ID")? == production_policy.owner_id.to_string(),
        "owner-only rehearsal"
    );
    let token = std::env::var("GH_TOKEN")?;
    let api = GitHub::scratch_from_env("GH_TOKEN", compiled)?;
    let mut policy = production_policy.clone();
    policy.deployment.server = production_policy.deployment.integration.clone();
    policy.deployment.server.default_branch = state["base_branch"]
        .as_str()
        .context("missing rehearsal base")?
        .into();
    ensure!(
        policy
            .deployment
            .server
            .default_branch
            .starts_with("testing/recovery2-base-"),
        "invalid rehearsal base"
    );
    let root = format!("/repos/{}", policy.deployment.server.repository);
    let main_path = format!(
        "{root}/git/ref/heads/{}",
        production_policy.deployment.integration.default_branch
    );
    let main: Value = api.get(&main_path)?;
    ensure!(
        main["object"]["sha"] == state["scratch_main_sha"],
        "scratch protected main moved"
    );
    let context = Dispatch {
        repository: std::env::var("GITHUB_REPOSITORY")?,
        reference: std::env::var("GITHUB_REF")?,
        event_name: "workflow_dispatch".into(),
        workflow_ref: String::new(),
        workflow_sha: compiled.into(),
        compiled_sha: compiled.into(),
        actor_id: policy.owner_id.to_string(),
        attempt: "1".into(),
        source_sha: compiled.into(),
        run_id: std::env::var("GITHUB_RUN_ID")?.parse()?,
        event: json!({}),
    };
    let host = Host {
        api,
        policy,
        policy_bytes: include_bytes!("../policy.json").to_vec(),
        context,
    };
    let stale = rehearsal_authorization(&state, "stale")?;
    let writer = Writer {
        host: &host,
        main: stale.expected_main_sha.clone(),
        token: token.clone(),
        api_base: "https://api.github.com".into(),
        client: Client::new(),
    };
    let before: Value = host
        .api
        .get(&format!("{root}/pulls/{}", stale.pull_request))?;
    ensure!(
        before["head"]["sha"] == state["stale"]["advanced_head"],
        "stale fixture head mismatch"
    );
    let mut accepted_identity = before.clone();
    accepted_identity["head"]["sha"] = json!(stale.expected_head_sha);
    stale.pull_identity(&host, &accepted_identity)?;
    stale.fence(&host)?;
    let error = stale
        .merge_fixed(&host, &writer)
        .expect_err("stale recovery head unexpectedly accepted");
    ensure!(
        error.to_string() == "fixed recovery PR identity, head, base or state changed",
        "unexpected stale rejection: {error}"
    );
    let stale_pull: Value = host
        .api
        .get(&format!("{root}/pulls/{}", stale.pull_request))?;
    ensure!(
        stale_pull["state"] == "open"
            && stale_pull["merged"] == false
            && stale_pull["head"]["sha"] == state["stale"]["advanced_head"],
        "stale fixture mutated"
    );
    let positive = rehearsal_authorization(&state, "positive")?;
    positive.fence(&host)?;
    positive.target(&host)?;
    let result = positive.merge_fixed(&host, &writer)?;
    let merged = result["sha"].as_str().context("merge SHA missing")?;
    let commit: Value = host.api.get(&format!("{root}/commits/{merged}"))?;
    ensure!(
        commit["commit"]["verification"]["verified"] == true
            && array(&commit["parents"])?.len() == 1
            && commit["parents"][0]["sha"] == positive.expected_main_sha
            && commit["commit"]["tree"]["sha"] == positive.expected_tree_sha,
        "rehearsal merge tree, parent or signature mismatch"
    );
    let main: Value = host.api.get(&main_path)?;
    ensure!(
        main["object"]["sha"] == state["scratch_main_sha"],
        "scratch main changed"
    );
    let _: Value = host.api.patch(
        &format!("{root}/pulls/{}", stale.pull_request),
        &json!({"state":"closed"}),
    )?;
    for (branch, sha) in [
        (
            positive.target_branch.as_str(),
            positive.expected_head_sha.as_str(),
        ),
        (
            stale.target_branch.as_str(),
            state["stale"]["advanced_head"].as_str().unwrap(),
        ),
        (
            host.policy.deployment.server.default_branch.as_str(),
            merged,
        ),
    ] {
        let reference: Value = host.api.get(&format!("{root}/git/ref/heads/{branch}"))?;
        ensure!(
            reference["object"]["sha"] == sha,
            "fixture branch changed before cleanup"
        );
        host.api
            .delete(&format!("{root}/git/refs/heads/{branch}"))?;
    }
    let evidence = json!({"recovery_source":compiled,"repository":host.policy.deployment.server.repository,"positive_pr":positive.pull_request,"merge_sha":merged,"stale_pr":stale.pull_request,"scratch_main_sha":state["scratch_main_sha"],"stale_head_rejected":true,"scratch_main_unchanged":true,"fixtures_cleaned":true,"production_merge_verified":false});
    std::fs::write(
        Path::new(&std::env::var("RUNNER_TEMP")?).join("request-recovery-rehearsal.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "{}",
        json!({"recovery_source":compiled,"repository":host.policy.deployment.server.repository,"positive_pr":positive.pull_request,"merge_sha":merged,"stale_pr":stale.pull_request,"stale_head_rejected":true,"scratch_main_unchanged":true,"fixtures_cleaned":true,"production_merge_verified":false})
    );
    Ok(())
}

#[test]
fn policy_exception_accepts_only_the_reported_missing_owner_authorization() {
    let check = json!({"conclusion":"failure","output":{"title":"Policy rejected","summary":"Owner authorization is required.\n\nDetails: owner authorization for this exact pull request head is missing"}});
    assert!(ordinary_policy_reports_missing_owner_authorization(&check));
    for (pointer, value) in [
        ("/conclusion", json!("success")),
        ("/output/title", json!("Policy approved")),
        ("/output/summary", json!("signature verification failed")),
    ] {
        let mut changed = check.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(!ordinary_policy_reports_missing_owner_authorization(
            &changed
        ));
    }
}

#[test]
fn owner_authorization_rejects_lifecycle_and_head_transitions_including_same_second() {
    let accepted = "2026-10-20T00:00:01Z";
    for event in [
        "head_ref_force_pushed",
        "head_ref_deleted",
        "head_ref_restored",
        "base_ref_force_pushed",
        "base_ref_deleted",
        "base_ref_changed",
        "merged",
        "closed",
        "reopened",
        "convert_to_draft",
        "ready_for_review",
    ] {
        for created in ["2026-10-20T00:00:01Z", "2026-10-20T00:00:02Z"] {
            assert!(
                validate_authorization_timeline(
                    &[json!({"event":event,"created_at":created})],
                    accepted
                )
                .is_err()
            );
        }
        assert!(
            validate_authorization_timeline(
                &[json!({"event":event,"created_at":"2026-10-20T00:00:00Z"})],
                accepted
            )
            .is_ok()
        );
        assert!(validate_authorization_timeline(&[json!({"event":event})], accepted).is_err());
    }
    assert!(validate_authorization_timeline(&[json!({"event":"commented"})], accepted).is_ok());
}

#[test]
fn ordinary_policy_check_must_exist_once_with_complete_results() {
    let auth = Authorization::load().unwrap();
    let fixture = Fixture::new(vec![]);
    let host = host(&fixture, &auth);
    let policy = json!({"name":"securefix-policy-check","app":{"id":host.policy.deployment.checks.policy_app_id},
        "external_id":format!("{}:{}",auth.expected_head_sha,auth.active.identity().unwrap()),"status":"completed","conclusion":"failure",
        "output":{"title":"Policy rejected","summary":"Details: owner authorization for this exact pull request head is missing"}});
    auth.check_results(
        &host,
        &json!({"total_count":1,"check_runs":[policy.clone()]}),
    )
    .unwrap();
    for result in [
        json!({"total_count":0,"check_runs":[]}),
        json!({"total_count":2,"check_runs":[policy.clone()]}),
        json!({"total_count":2,"check_runs":[policy.clone(),policy.clone()]}),
    ] {
        assert!(auth.check_results(&host, &result).is_err());
    }
    for (pointer, value) in [
        ("/app/id", json!(999)),
        ("/external_id", json!("stale")),
        ("/status", json!("in_progress")),
        ("/output/summary", json!("signature verification failed")),
    ] {
        let mut changed = policy.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            auth.check_results(&host, &json!({"total_count":1,"check_runs":[changed]}))
                .is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn workflow_permission_probe_requires_both_expanded_callers_without_execution() {
    let auth = Authorization::load().unwrap();
    let valid = json!({"total_count":2,"jobs":[
        {"name":"approve","status":"completed","conclusion":"skipped"},
        {"name":"merge","status":"completed","conclusion":"skipped"}
    ]});
    auth.workflow_probe_jobs(&valid).unwrap();
    for (pointer, value) in [
        ("/total_count", json!(3)),
        ("/jobs/0/name", json!("merge")),
        ("/jobs/0/status", json!("in_progress")),
        ("/jobs/1/conclusion", json!("failure")),
        ("/jobs/1/conclusion", json!("success")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(auth.workflow_probe_jobs(&changed).is_err(), "{pointer}");
    }
}
