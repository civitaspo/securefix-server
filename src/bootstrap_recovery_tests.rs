use super::*;
use crate::{
    bootstrap::tests::*,
    fixtures::{Fixture, Route},
};

fn source_sha() -> String {
    "c".repeat(40)
}
fn auth() -> Authorization {
    Authorization {
        expected_main_sha: main_sha(),
        expected_head_sha: head_sha(),
        expected_tree_sha: "d".repeat(40),
        ..Authorization::load().unwrap()
    }
}
fn recovery_host(fixture: &Fixture, phase: &str) -> Host {
    let mut host = host(fixture, phase);
    let auth = auth();
    host.context.reference = format!("refs/heads/{}", auth.authority_branch);
    host.context.workflow_ref = format!(
        "{}/{BOOTSTRAP_WORKFLOW}@{}",
        host.repository(),
        host.context.reference
    );
    host.context.workflow_sha = source_sha();
    host.context.compiled_sha = source_sha();
    host.context.source_sha = source_sha();
    host.context.event["inputs"]["authority_sha"] = json!(source_sha());
    host.context.event["inputs"]["pull_request"] = json!("12");
    host
}
fn source_pull() -> Value {
    let mut pull = pull(&head_sha());
    pull["number"] = json!(auth().source_pull_request);
    pull["user"]["id"] = json!(policy().owner_id);
    pull["draft"] = json!(false);
    pull
}
fn target() -> Value {
    json!({"sha":head_sha(),"commit":{"tree":{"sha":auth().expected_tree_sha}}})
}
fn before_target() -> Vec<Route> {
    let auth = auth();
    let mut run = run_fixture(BOOTSTRAP_WORKFLOW, false);
    run["head_branch"] = json!(auth.authority_branch);
    run["head_sha"] = json!(source_sha());
    let mut routes = vec![
        main_route(),
        absent_route(),
        content_route(
            "policy.json",
            &main_sha(),
            &securefix::config::trusted_policy_bytes().unwrap(),
        ),
        Route::get(path("actions/runs/77"), run),
        Route::get(
            path(&format!("git/ref/heads/{}", auth.authority_branch)),
            json!({"object":{"type":"commit","sha":source_sha()}}),
        ),
    ];
    routes.extend(status_routes(&source_sha()));
    routes
}
fn qualified_routes() -> Vec<Route> {
    let mut routes = before_target();
    routes.push(Route::get(
        path(&format!("pulls/{}", auth().source_pull_request)),
        source_pull(),
    ));
    routes.push(Route::get(
        path(&format!("commits/{}", head_sha())),
        target(),
    ));
    routes.extend(status_routes(&head_sha()));
    routes.push(Route::get(
        path(&format!("compare/{}...{}", main_sha(), head_sha())),
        comparison(json!([{"filename":"src/bootstrap.rs"}])),
    ));
    let mut source_comparison = comparison(json!([{"filename":"src/bootstrap_recovery.rs"}]));
    source_comparison["base_commit"]["sha"] = json!(head_sha());
    source_comparison["merge_base_commit"]["sha"] = json!(head_sha());
    routes.push(Route::get(
        path(&format!("compare/{}...{}", head_sha(), source_sha())),
        source_comparison,
    ));
    routes
}
fn proposal() -> Value {
    let mut pull = pull(&head_sha());
    pull["head"]["ref"] = json!(auth().proposal_branch);
    pull["draft"] = json!(false);
    pull
}

#[test]
fn recovery_qualifies_both_signed_ci_sources_and_the_exact_target_without_writes() {
    let fixture = Fixture::new(qualified_routes());
    auth()
        .qualify(
            &recovery_host(&fixture, "recovery-qualify"),
            "recovery-qualify",
        )
        .unwrap();
    fixture.finish();
}

#[test]
fn recovery_dispatch_is_bound_to_its_source_branch_and_owner() {
    let fixture = Fixture::new(vec![]);
    for field in [
        "authority_sha",
        "compiled_sha",
        "workflow_sha",
        "source_sha",
        "owner",
        "branch",
        "workflow",
        "phase",
        "attempt",
    ] {
        let mut host = recovery_host(&fixture, "recovery-propose");
        auth().dispatch(&host, "recovery-propose").unwrap();
        match field {
            "authority_sha" => host.context.event["inputs"][field] = json!(head_sha()),
            "compiled_sha" => host.context.compiled_sha = head_sha(),
            "workflow_sha" => host.context.workflow_sha = head_sha(),
            "source_sha" => host.context.source_sha = head_sha(),
            "owner" => host.context.actor_id = "1".into(),
            "branch" => host.context.reference = "refs/heads/main".into(),
            "workflow" => host.context.workflow_ref = "other".into(),
            "phase" => host.context.event["inputs"][field] = json!("repair-merge"),
            "attempt" => host.context.attempt = "2".into(),
            _ => unreachable!(),
        }
        assert!(
            auth().dispatch(&host, "recovery-propose").is_err(),
            "{field}"
        );
    }
    fixture.finish();
}

#[test]
fn recovery_requires_an_out_of_band_approval_for_the_exact_executor_source() {
    let fixture = Fixture::new(vec![]);
    let host = recovery_host(&fixture, "recovery-propose");
    require_source_approval(&host, &source_sha()).unwrap();
    for wrong in ["", "main", &head_sha()] {
        assert!(require_source_approval(&host, wrong).is_err());
    }
    fixture.finish();
}

#[test]
fn recovery_stops_after_main_advances_or_descriptor_appears() {
    for active in [false, true] {
        let routes = if active {
            vec![
                main_route(),
                Route::get(
                    path(&format!("contents/{ACTIVE}?ref={}", main_sha())),
                    json!({}),
                ),
            ]
        } else {
            vec![Route::get(path("commits/main"), json!({"sha":head_sha()}))]
        };
        let fixture = Fixture::new(routes);
        assert!(
            auth()
                .qualify(
                    &recovery_host(&fixture, "recovery-propose"),
                    "recovery-propose"
                )
                .is_err()
        );
        fixture.finish();
    }
}

#[test]
fn recovery_rejects_changed_target_pr_identity_or_tree_before_any_writer() {
    for field in ["head", "base", "author", "repo", "draft", "merged", "tree"] {
        let mut routes = before_target();
        let mut pull = source_pull();
        let mut target = target();
        match field {
            "head" => pull["head"]["sha"] = json!(source_sha()),
            "base" => pull["base"]["sha"] = json!(source_sha()),
            "author" => pull["user"]["id"] = json!(1),
            "repo" => pull["head"]["repo"]["id"] = json!(1),
            "draft" => pull["draft"] = json!(true),
            "merged" => pull["merged_at"] = json!("2026-10-17T00:00:00Z"),
            "tree" => target["commit"]["tree"]["sha"] = json!(source_sha()),
            _ => unreachable!(),
        }
        routes.push(Route::get(
            path(&format!("pulls/{}", auth().source_pull_request)),
            pull,
        ));
        if field == "tree" {
            routes.push(Route::get(path(&format!("commits/{}", head_sha())), target));
        }
        let fixture = Fixture::new(routes);
        assert!(
            auth()
                .qualify(
                    &recovery_host(&fixture, "recovery-propose"),
                    "recovery-propose"
                )
                .is_err(),
            "{field}"
        );
        fixture.finish();
    }
}

#[test]
fn recovery_merge_requires_the_reserved_bot_pr_and_latest_exact_head_owner_review() {
    let reviews = json!([{"user":{"id":policy().owner_id},"submitted_at":"2026-10-17T06:00:00Z","state":"APPROVED","commit_id":head_sha()}]);
    for valid in [true, false] {
        let mut latest = reviews.clone();
        if !valid {
            latest.as_array_mut().unwrap().push(json!({"user":{"id":policy().owner_id},"submitted_at":"2026-10-17T06:01:00Z","state":"CHANGES_REQUESTED","commit_id":head_sha()}));
        }
        let fixture = Fixture::new(vec![
            Route::get(path("pulls/12"), proposal()),
            Route::get(path("pulls/12/reviews?per_page=100&page=1"), latest),
        ]);
        assert_eq!(
            auth()
                .approved_pull(&recovery_host(&fixture, "recovery-merge"))
                .is_ok(),
            valid
        );
        fixture.finish();
    }
    let fixture = Fixture::new(vec![]);
    let host = recovery_host(&fixture, "recovery-merge");
    for field in ["branch", "head", "author", "draft"] {
        let mut pull = proposal();
        match field {
            "branch" => pull["head"]["ref"] = json!("other"),
            "head" => pull["head"]["sha"] = json!(source_sha()),
            "author" => pull["user"]["id"] = json!(policy().owner_id),
            "draft" => pull["draft"] = json!(true),
            _ => unreachable!(),
        }
        assert!(auth().proposal_identity(&host, &pull).is_err());
    }
    fixture.finish();
}
