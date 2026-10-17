use super::*;
use crate::{
    bootstrap::tests::*,
    fixtures::{Fixture, Route},
};

fn auth() -> Authorization {
    let active = Fixture::control_revision();
    let mut successor = active.clone();
    successor.generation = 2;
    successor.previous = active.identity().unwrap();
    successor.source_sha = head_sha();
    Authorization {
        version: 1,
        authority_branch: "codex/recover-successor-test".into(),
        expected_main_sha: head_sha(),
        expected_head_sha: "c".repeat(40),
        pull_request: 12,
        active,
        successor,
    }
}

fn recovery_host(fixture: &Fixture, phase: &str) -> Host {
    let mut host = host(fixture, phase);
    let auth = auth();
    host.context.reference = format!("refs/heads/{}", auth.authority_branch);
    host.context.workflow_ref = format!(
        "{}/{WORKFLOW}@{}",
        host.repository(),
        host.context.reference
    );
    host.context.workflow_sha = "d".repeat(40);
    host.context.compiled_sha = "d".repeat(40);
    host.context.source_sha = "d".repeat(40);
    host.context.event["inputs"]["authority_sha"] = json!(host.context.compiled_sha);
    host.context.event["inputs"]["source_sha"] = json!(auth.successor.source_sha);
    host.context.event["inputs"]["publisher_run_id"] =
        json!(auth.successor.publisher_run_id.to_string());
    host.context.event["inputs"]["verification_run_id"] =
        json!(auth.successor.verification_run_id.to_string());
    host.context.event["inputs"]["expected_control_id"] = json!(auth.active.identity().unwrap());
    host
}

fn proposal() -> Value {
    let auth = auth();
    let mut pull = pull(&auth.expected_head_sha);
    pull["base"]["sha"] = json!(auth.expected_main_sha);
    pull["head"]["ref"] = json!(format!(
        "automation/securefix-runtime/control-2-{}",
        &auth.successor.source_sha[..12]
    ));
    pull["user"]["login"] = json!(policy().deployment.server_bot_login);
    pull["user"]["type"] = json!("Bot");
    pull["head"]["user"] =
        json!({"id":policy().owner_id,"login":policy().deployment.owner_login,"type":"User"});
    pull["draft"] = json!(false);
    pull
}

fn fence_routes() -> Vec<Route> {
    vec![
        Route::get(
            path("commits/main"),
            json!({"sha":auth().expected_main_sha}),
        ),
        content_route(
            ACTIVE,
            &auth().expected_main_sha,
            &serde_json::to_vec(&auth().active).unwrap(),
        ),
    ]
}

#[test]
fn recovery_record_requires_the_fixed_first_normal_successor() {
    let fixed = Authorization::load().unwrap();
    assert!(
        include_str!("../.github/workflows/control-activation.yml")
            .contains(&format!("refs/heads/{}", fixed.authority_branch))
    );
    auth().validate().unwrap();
    for field in [
        "version",
        "number",
        "generation",
        "predecessor",
        "source",
        "head",
        "branch",
    ] {
        let mut changed = auth();
        match field {
            "version" => changed.version = 2,
            "number" => changed.pull_request = 0,
            "generation" => changed.successor.generation = 3,
            "predecessor" => changed.successor.previous = "f".repeat(64),
            "source" => changed.successor.source_sha = "f".repeat(40),
            "head" => changed.expected_head_sha = "main".into(),
            "branch" => changed.authority_branch = "main".into(),
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err(), "{field}");
    }
    let mut record = json!({"version":1});
    record["unreviewed"] = json!(true);
    assert!(serde_json::from_value::<Authorization>(record).is_err());
}

#[test]
fn recovery_dispatch_binds_every_source_owner_workflow_and_attempt_field() {
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
        "run_id",
        "phase",
        "authority_sha",
    ] {
        let mut host = recovery_host(&fixture, "successor-qualify");
        auth().dispatch(&host, "successor-qualify").unwrap();
        match field {
            "repository" => host.context.repository = "other/repo".into(),
            "reference" => host.context.reference = "refs/heads/main".into(),
            "event_name" => host.context.event_name = "push".into(),
            "workflow_ref" => host.context.workflow_ref = "unreviewed".into(),
            "workflow_sha" => host.context.workflow_sha = main_sha(),
            "compiled_sha" => host.context.compiled_sha = main_sha(),
            "actor_id" => host.context.actor_id = "1".into(),
            "attempt" => host.context.attempt = "2".into(),
            "source_sha" => host.context.source_sha = main_sha(),
            "run_id" => host.context.run_id = 0,
            "phase" | "authority_sha" => host.context.event["inputs"][field] = json!("unreviewed"),
            _ => unreachable!(),
        }
        assert!(
            auth().dispatch(&host, "successor-qualify").is_err(),
            "{field}"
        );
    }
    for (field, number) in [
        ("publisher_run_id", auth().successor.publisher_run_id),
        ("verification_run_id", auth().successor.verification_run_id),
    ] {
        let mut changed = recovery_host(&fixture, "successor-qualify");
        changed.context.event["inputs"][field] = json!(number);
        assert!(auth().dispatch(&changed, "successor-qualify").is_err());
    }
    fixture.finish();
}

#[test]
fn recovery_requires_exact_out_of_band_source_approval_and_fixed_inputs() {
    let fixture = Fixture::new(vec![]);
    let host = recovery_host(&fixture, "successor-merge");
    require_source_approval(&host, &host.context.compiled_sha).unwrap();
    for wrong in ["", "main", &main_sha()] {
        assert!(require_source_approval(&host, wrong).is_err());
    }
    for field in [
        "source_sha",
        "publisher_run_id",
        "verification_run_id",
        "expected_control_id",
    ] {
        let mut changed = recovery_host(&fixture, "successor-qualify");
        changed.context.event["inputs"][field] = json!("unreviewed");
        assert!(
            auth().dispatch(&changed, "successor-qualify").is_err(),
            "{field}"
        );
    }
    fixture.finish();
}

#[test]
fn recovery_rejects_substituted_workflow_run_provenance() {
    let fixture = Fixture::new(vec![]);
    let host = recovery_host(&fixture, "successor-qualify");
    let mut run = run_fixture(WORKFLOW, false);
    run["head_branch"] = json!(auth().authority_branch);
    run["head_sha"] = json!(host.context.compiled_sha);
    validate_authority_run(&run, &host, &auth()).unwrap();
    for (path, value) in [
        ("/id", json!(78)),
        ("/repository/id", json!(1)),
        ("/head_repository/id", json!(1)),
        ("/path", json!(BOOTSTRAP_WORKFLOW)),
        ("/event", json!("push")),
        ("/head_branch", json!("main")),
        ("/head_sha", json!(main_sha())),
        ("/run_attempt", json!(2)),
        ("/actor/id", json!(1)),
        ("/triggering_actor/id", json!(1)),
        ("/status", json!("completed")),
    ] {
        let mut changed = run.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            validate_authority_run(&changed, &host, &auth()).is_err(),
            "{path}"
        );
    }
    fixture.finish();
}

#[test]
fn recovery_requires_owner_and_bot_control_reviews_exact_policy_and_review_decision() {
    let auth = auth();
    let policy = policy();
    let marker = format!(
        "<!-- securefix:control-review:{} -->",
        auth.active.identity().unwrap()
    );
    let reviewer = policy.deployment.approval_reviewer;
    for change in [
        "none",
        "owner_marker",
        "owner_changes",
        "bot_head",
        "policy_control",
        "duplicate_policy",
        "decision",
    ] {
        let mut reviews = json!([
            {"id":1,"user":{"id":policy.owner_id,"login":policy.deployment.owner_login,"type":"User"},"submitted_at":"2026-10-17T14:00:00Z","state":"APPROVED","commit_id":auth.expected_head_sha,"body":marker},
            {"id":2,"user":{"id":reviewer.id,"login":reviewer.login,"type":"User"},"submitted_at":"2026-10-17T14:01:00Z","state":"APPROVED","commit_id":auth.expected_head_sha,"body":marker}
        ]);
        let check = json!({"name":"securefix-policy-check","app":{"id":policy.deployment.checks.policy_app_id},"status":"completed","conclusion":"success","external_id":format!("{}:{}",auth.expected_head_sha,auth.active.identity().unwrap())});
        let mut checks = json!({"check_runs":[check]});
        match change {
            "owner_marker" => reviews[0]["body"] = json!("unbound approval"),
            "owner_changes" => reviews.as_array_mut().unwrap().push(json!({"id":3,"user":{"id":policy.owner_id},"submitted_at":"2026-10-17T14:02:00Z","state":"CHANGES_REQUESTED","commit_id":auth.expected_head_sha})),
            "bot_head" => reviews[1]["commit_id"] = json!(main_sha()),
            "policy_control" => checks["check_runs"][0]["external_id"] = json!(format!("{}:{}",auth.expected_head_sha,"f".repeat(64))),
            "duplicate_policy" => checks["check_runs"].as_array_mut().unwrap().push(check),
            _ => (),
        }
        let mut routes = vec![Route::get(
            path("pulls/12/reviews?per_page=100&page=1"),
            reviews,
        )];
        if !matches!(change, "owner_marker" | "owner_changes" | "bot_head") {
            routes.push(Route::get(
                path(&format!(
                    "commits/{}/check-runs?per_page=100&page=1&filter=latest",
                    auth.expected_head_sha
                )),
                checks,
            ));
            if !matches!(change, "policy_control" | "duplicate_policy") {
                routes.push(Route::request("POST", "/graphql", 200,
                    json!({"data":{"repository":{"pullRequest":{"reviewDecision":if change == "none" {"APPROVED"} else {"REVIEW_REQUIRED"}}}}})));
            }
        }
        let fixture = Fixture::new(routes);
        let host = recovery_host(&fixture, "successor-qualify");
        assert_eq!(
            auth.reviews_and_policy(&host).is_ok(),
            change == "none",
            "{change}"
        );
        fixture.finish();
    }
}

#[test]
fn recovery_qualification_rejects_changed_main_or_control_before_publication_access() {
    for change in ["main", "control"] {
        let mut routes = fence_routes();
        if change == "main" {
            routes = vec![Route::get(path("commits/main"), json!({"sha":main_sha()}))];
        } else {
            let mut active = auth().active;
            active.asset_id += 1;
            routes[1] = content_route(
                ACTIVE,
                &auth().expected_main_sha,
                &serde_json::to_vec(&active).unwrap(),
            );
        }
        let fixture = Fixture::new(routes);
        assert!(
            auth()
                .qualify(
                    &recovery_host(&fixture, "successor-qualify"),
                    "successor-qualify"
                )
                .is_err()
        );
        fixture.finish();
    }
}

#[test]
fn recovery_accepts_the_real_pr_author_shape_and_rejects_substituted_identity() {
    let fixture = Fixture::new(vec![]);
    let host = recovery_host(&fixture, "successor-qualify");
    let pull = proposal();
    auth().pull_identity(&host, &pull).unwrap();
    for (path, value) in [
        ("/number", json!(13)),
        ("/state", json!("closed")),
        ("/draft", json!(true)),
        ("/merged_at", json!("2026-10-17T00:00:00Z")),
        ("/user/id", json!(policy().owner_id)),
        ("/user/type", json!("User")),
        ("/user/login", json!("impostor")),
        ("/head/sha", json!(main_sha())),
        ("/head/ref", json!("other")),
        ("/head/repo/id", json!(1)),
        ("/base/repo/id", json!(1)),
        ("/base/sha", json!(main_sha())),
        ("/base/ref", json!("other")),
    ] {
        let mut changed = pull.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(auth().pull_identity(&host, &changed).is_err(), "{path}");
    }
    fixture.finish();
}

#[test]
fn recovery_merge_rechecks_main_control_and_head_before_exact_head_api_write() {
    for change in ["none", "main", "control", "head"] {
        let mut routes = fence_routes();
        if change == "main" {
            routes = vec![Route::get(path("commits/main"), json!({"sha":main_sha()}))];
        } else if change == "control" {
            let mut active = auth().active;
            active.asset_id += 1;
            routes[1] = content_route(
                ACTIVE,
                &auth().expected_main_sha,
                &serde_json::to_vec(&active).unwrap(),
            );
        } else {
            let mut pull = proposal();
            if change == "head" {
                pull["head"]["sha"] = json!(main_sha());
            }
            routes.push(Route::get(path("pulls/12"), pull));
            if change == "none" {
                routes.push(
                    Route::request("PUT", path("pulls/12/merge"), 200, json!({"merged":true}))
                        .with_request_body(
                            json!({"sha":auth().expected_head_sha,"merge_method":"squash"}),
                        ),
                );
            }
        }
        let fixture = Fixture::new(routes);
        let host = recovery_host(&fixture, "successor-merge");
        let writer = Writer {
            host: &host,
            main: auth().expected_main_sha,
            token: "fixture-token".into(),
            api_base: fixture.base.clone(),
            client: Client::new(),
        };
        assert_eq!(
            auth().merge_after_qualification(&host, &writer).is_ok(),
            change == "none",
            "{change}"
        );
        fixture.finish();
    }
}

#[test]
fn recovery_workflow_keeps_read_only_qualification_before_scoped_writer_and_shared_queue() {
    let workflow = include_str!("../.github/workflows/control-activation.yml");
    let qualifier = workflow
        .split("  recovery-qualify:\n")
        .nth(1)
        .unwrap()
        .split("  recovery-merge:\n")
        .next()
        .unwrap();
    assert!(
        !qualifier.contains("environment:")
            && !qualifier.contains("secrets.")
            && !qualifier.contains("permission-contents: write")
    );
    let writer = workflow.split("  recovery-merge:\n").nth(1).unwrap();
    for required in [
        "needs: [recovery-host, recovery-qualify]",
        "environment: main",
        "group: securefix-control",
        "queue: max",
        "SECUREFIX_SUCCESSOR_RECOVERY_SOURCE_SHA == github.sha",
        "repositories: securefix-server",
        "successor-recovery-merge",
    ] {
        assert!(writer.contains(required), "{required}");
    }
    assert!(
        !workflow.contains("permission-administration") && !writer.contains("securefix control")
    );
}

#[test]
fn recovery_environment_admission_does_not_enable_settings_or_distribution() {
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../.github/workflows/repo-settings.yml")).unwrap();
    for job in ["build", "prepare", "reconcile", "controlled-merges"] {
        assert!(
            workflow["jobs"][job]["if"]
                .as_str()
                .unwrap()
                .starts_with("github.ref == 'refs/heads/main'"),
            "{job}"
        );
    }
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../.github/workflows/distribute-runtime.yml")).unwrap();
    for job in ["runtime", "caller"] {
        let condition = workflow["jobs"][job]["if"].as_str().unwrap();
        assert!(
            condition.contains("github.ref == 'refs/heads/main'"),
            "{job}"
        );
        assert!(condition.contains("github.actor_id == '4525500'"), "{job}");
    }
}
