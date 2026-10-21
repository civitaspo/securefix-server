use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use sha2::Digest;
use std::{thread, time::Duration};

use crate::config;
use crate::request::{self, Authorization, RequestKind, RequestManifest};
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy},
};

#[derive(Subcommand)]
pub enum Command {
    Validate,
    Apply,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Validate => validate(),
        Command::Apply => apply(),
        Command::Cleanup => cleanup(),
    }
}

fn approval_source(label: &str) -> Result<(u64, RequestKind)> {
    let suffix = label
        .strip_prefix(
            &config::trusted()?
                .deployment
                .label_prefix("approve-request-"),
        )
        .context("unexpected approval request label")?;
    let (run, kind) = if let Some(run) = suffix.strip_prefix("renovate-") {
        (run, RequestKind::Merge)
    } else {
        (suffix, RequestKind::Approve)
    };
    let run_id = run.parse()?;
    ensure!(run_id > 0, "invalid approval source run");
    Ok((run_id, kind))
}

fn approval_authorization_allowed(kind: RequestKind, authorization: &Authorization) -> bool {
    matches!(
        (kind, authorization),
        (
            RequestKind::Approve,
            Authorization::OwnerComment { .. } | Authorization::Automatic { .. }
        ) | (RequestKind::Merge, Authorization::RenovateComment { .. })
    )
}

pub(crate) fn validate_approval_policy(
    api: &GitHub,
    policy: &Policy,
    manifest: &RequestManifest,
) -> Result<bool> {
    ensure!(
        approval_authorization_allowed(manifest.kind, &manifest.authorization),
        "request cannot authorize an approval"
    );
    if matches!(
        manifest.authorization,
        Authorization::RenovateComment { .. }
    ) {
        crate::merge::validate_state(api, policy, manifest)?;
        request::validate_merge_policy(api, policy, manifest, false)
    } else {
        request::validate_pr_authorization(
            api,
            policy,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            matches!(manifest.authorization, Authorization::OwnerComment { .. }),
        )
    }
}

fn validate() -> Result<()> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    let source_sha =
        securefix::workflow::require_current_runtime(&api, ".github/workflows/approve.yml")?;
    let control = policy
        .control
        .as_ref()
        .context("active control revision is missing")?;
    securefix::control::ControlRevision::require_current(&api, control)?;
    let payload = event()?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == server
            && payload["repository"]["id"].as_u64() == Some(deployment.server.id),
        "approval processor must run in the server repository"
    );
    ensure!(
        payload["action"] == "created" && payload["label"]["name"].is_string(),
        "event is not a label creation"
    );
    let label = payload["label"]["name"]
        .as_str()
        .context("missing label name")?;
    let (run_id, kind) = approval_source(label)?;
    ensure!(
        request::matches_principal(
            &payload["sender"],
            config::trusted()?.client_bot_id,
            &deployment.client_bot_login,
            "Bot",
        ),
        "approval request label was not created by the Client App"
    );
    let description = payload["label"]["description"]
        .as_str()
        .context("missing label description")?;
    let (repository, described_run) = description
        .rsplit_once('/')
        .context("invalid request label description")?;
    ensure!(
        described_run.parse::<u64>()? == run_id,
        "label description run ID mismatch"
    );
    let repo_policy = policy.repository(repository)?;
    repo_policy.require(Capability::Approve)?;
    let manifest = request::load_source_request(&api, &policy, repository, run_id, kind)?;
    let pr: Value = api.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    ensure!(
        pr["state"] == "open"
            && pr["draft"] == false
            && pr["head"]["sha"] == manifest.pull_request.head_sha
            && pr["base"]["ref"] == manifest.pull_request.base_ref,
        "pull request changed after the approval request was captured"
    );
    validate_approval_policy(&api, &policy, &manifest)?;
    securefix::workflow::write_json("approval/manifest.json", &manifest)?;
    output("repository", repository)?;
    output(
        "repository_name",
        repository.rsplit('/').next().unwrap_or_default(),
    )?;
    output("pull_number", manifest.pull_request.number.to_string())?;
    output("head_sha", manifest.pull_request.head_sha)?;
    output("source_sha", source_sha)?;
    Ok(())
}

fn authenticate_reviewer(api: &GitHub, reviewer: &config::Principal) -> Result<()> {
    let approver: Value = api.get("/user")?;
    ensure!(
        approver["login"] == reviewer.login
            && approver["id"].as_u64() == Some(reviewer.id)
            && approver["type"] == "User",
        "approval token must authenticate as the configured review account"
    );
    Ok(())
}

fn create_configured_review(read: &GitHub, manifest: &RequestManifest) -> Result<()> {
    let reviewer = &config::trusted()?.deployment.approval_reviewer;
    let approve = GitHub::from_env("SECUREFIX_APPROVE_TOKEN")?;
    authenticate_reviewer(&approve, reviewer)?;
    approve_current_head(
        read,
        &approve,
        &manifest.repository.full_name,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        (reviewer, "User"),
        &manifest.control,
    )
}

fn apply() -> Result<()> {
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    let manifest: RequestManifest =
        serde_json::from_slice(&std::fs::read("approval/manifest.json")?)?;
    manifest.validate()?;
    ensure!(
        approval_authorization_allowed(manifest.kind, &manifest.authorization)
            && manifest.workflow_sha == policy.revision,
        "approval manifest is invalid or stale"
    );
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    let source = request::load_source_request(
        &read,
        &policy,
        &manifest.repository.full_name,
        manifest.run_id,
        manifest.kind,
    )?;
    ensure!(
        source == manifest,
        "source request changed after validation"
    );
    let repository = &manifest.repository.full_name;
    policy
        .repository(repository)?
        .require(Capability::Approve)?;
    let pr: Value = read.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    ensure!(
        pr["state"] == "open"
            && pr["draft"] == false
            && pr["head"]["sha"] == manifest.pull_request.head_sha
            && pr["base"]["ref"] == manifest.pull_request.base_ref,
        "pull request changed before approval"
    );
    let owner_requested = matches!(&manifest.authorization, Authorization::OwnerComment { .. });
    validate_approval_policy(&read, &policy, &manifest)?;
    let write = GitHub::from_env("SECUREFIX_WRITE_TOKEN")?;
    if owner_requested {
        request::acknowledge_request(
            &read,
            &write,
            &policy,
            repository,
            manifest.pull_request.number,
            &manifest.authorization,
            manifest.kind,
        )?;
    }
    if owner_requested
        && let Authorization::OwnerComment { comment_id, .. } = &manifest.authorization
    {
        request::post_owner_marker(
            &write,
            repository,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            *comment_id,
            &manifest.control,
        )?;
    }
    create_configured_review(&read, &manifest)?;
    let current_policy = Policy::active(&read)?;
    ensure!(
        current_policy.revision == manifest.workflow_sha,
        "server policy revision changed before policy check publication"
    );
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    let current_pr: Value = read.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    ensure!(
        current_pr["state"] == "open"
            && current_pr["head"]["sha"] == manifest.pull_request.head_sha,
        "pull request head changed before policy check publication"
    );
    let sensitive = validate_approval_policy(&read, &current_policy, &manifest)?;
    crate::policy_check::publish(
        &write,
        repository,
        &manifest.pull_request.head_sha,
        true,
        if sensitive {
            "Sensitive changes passed signature, configured approval policy, and review checks."
        } else {
            "Changes passed signature and review checks."
        },
        &manifest.control,
    )?;
    crate::policy_check::report_result(
        &write,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        true,
        "Changes passed signature and review checks.",
    )?;
    Ok(())
}

pub(crate) fn approve_current_head(
    read: &GitHub,
    review_api: &GitHub,
    repository: &str,
    pull_number: u64,
    expected_head: &str,
    reviewer: (&config::Principal, &str),
    control: &securefix::control::ControlRevision,
) -> Result<()> {
    let (reviewer, reviewer_type) = reviewer;
    securefix::policy::validate_repository(repository)?;
    securefix::policy::validate_sha(expected_head)?;
    ensure!(
        reviewer.id > 0 && !reviewer.login.is_empty(),
        "invalid reviewer identity"
    );
    ensure!(
        matches!(reviewer_type, "User" | "Bot"),
        "invalid reviewer type"
    );
    let pull: Value = read.get(&format!("/repos/{repository}/pulls/{pull_number}"))?;
    validate_review_target(&pull, expected_head, reviewer.id)?;
    let path = format!("/repos/{repository}/pulls/{pull_number}/reviews");
    control.validate()?;
    let marker = format!("<!-- securefix:control-review:{} -->", control.identity()?);
    let reviews = read.paginate(&path)?;
    let control_review_exists = reviews.iter().any(|review| {
        expected_approval(review, reviewer, reviewer_type, expected_head)
            && review["body"]
                .as_str()
                .is_some_and(|body| body.lines().any(|line| line == marker))
    });
    if !latest_reviewer_approval(&reviews, reviewer, reviewer_type, expected_head)
        || !control_review_exists
    {
        let response: Value = review_api.post(
            &path,
            &json!({"event":"APPROVE","commit_id":expected_head,"body":marker}),
        )?;
        ensure!(
            expected_approval(&response, reviewer, reviewer_type, expected_head),
            "GitHub returned an approval for a different reviewer or head"
        );
    }
    ensure!(
        request::has_current_head_approval_for_reviewer(
            read,
            repository,
            pull_number,
            expected_head,
            control,
            reviewer,
            reviewer_type,
        )?,
        "no non-author approval is attached to the accepted head"
    );
    let reviews = read.paginate(&path)?;
    ensure!(
        latest_reviewer_approval(&reviews, reviewer, reviewer_type, expected_head)
            && reviews.iter().any(|review| {
                expected_approval(review, reviewer, reviewer_type, expected_head)
                    && review["body"]
                        .as_str()
                        .is_some_and(|body| body.lines().any(|line| line == marker))
            }),
        "expected reviewer approval is not attached to the accepted head"
    );
    Ok(())
}

pub(crate) fn approve_native_current_head(
    read: &GitHub,
    review_api: &GitHub,
    manifest: &crate::native_client::RequestManifest,
    reviewer: &config::Principal,
    request_bytes: &[u8],
) -> Result<String> {
    let repository = &manifest.repository.full_name;
    let pull_number = manifest.pull_request.number;
    let expected_head = &manifest.pull_request.head_sha;
    let identity: Value = review_api.get("/user")?;
    ensure!(
        identity["id"].as_u64() == Some(reviewer.id)
            && identity["login"].as_str() == Some(reviewer.login.as_str())
            && identity["type"] == "User",
        "approval token must authenticate as the configured review account"
    );
    let pull: Value = read.get(&format!("/repos/{repository}/pulls/{pull_number}"))?;
    validate_review_target(&pull, expected_head, reviewer.id)?;
    let request_sha256 = securefix::hex_encode(sha2::Sha256::digest(request_bytes));
    let body = securefix::api::native_approval_body(
        &manifest.server_authority,
        expected_head,
        &request_sha256,
    )?;
    let marker = body["body"]
        .as_str()
        .context("native approval marker is missing")?;
    let path = format!("/repos/{repository}/pulls/{pull_number}/reviews");
    let reviews = read.paginate(&path)?;
    if !latest_reviewer_approval(&reviews, reviewer, "User", expected_head)
        || !reviews.iter().any(|review| {
            expected_approval(review, reviewer, "User", expected_head)
                && review["body"]
                    .as_str()
                    .is_some_and(|comment| comment.lines().any(|line| line == marker))
        })
    {
        let response: Value = review_api.post(&path, &body)?;
        ensure!(
            expected_approval(&response, reviewer, "User", expected_head)
                && response["body"] == marker,
            "GitHub returned an approval for a different reviewer, head, or authority"
        );
    }
    let mut confirmed = false;
    for attempt in 0..5 {
        let current_pull: Value =
            read.get_uncached(&format!("/repos/{repository}/pulls/{pull_number}"))?;
        validate_review_target(&current_pull, expected_head, reviewer.id)?;
        let current_reviews = read.paginate_uncached(&path)?;
        if latest_reviewer_approval(&current_reviews, reviewer, "User", expected_head)
            && current_reviews.iter().any(|review| {
                expected_approval(review, reviewer, "User", expected_head)
                    && review["body"]
                        .as_str()
                        .is_some_and(|comment| comment.lines().any(|line| line == marker))
            })
        {
            confirmed = true;
            break;
        }
        if attempt < 4 {
            thread::sleep(Duration::from_secs(1));
        }
    }
    ensure!(
        confirmed,
        "native approval was submitted, but bounded no-cache readback did not confirm the accepted PR head and authority; the review was not resubmitted"
    );
    Ok(marker.to_owned())
}

fn validate_review_target(pull: &Value, expected_head: &str, reviewer_id: u64) -> Result<()> {
    ensure!(
        pull["state"] == "open" && pull["head"]["sha"] == expected_head,
        "pull request is not open at the expected review head"
    );
    ensure!(
        pull["user"]["id"].as_u64() != Some(reviewer_id),
        "the review account cannot approve its own pull request"
    );
    Ok(())
}

fn expected_approval(
    review: &Value,
    reviewer: &config::Principal,
    reviewer_type: &str,
    head: &str,
) -> bool {
    request::matches_principal(&review["user"], reviewer.id, &reviewer.login, reviewer_type)
        && review["state"] == "APPROVED"
        && review["commit_id"] == head
}

fn latest_reviewer_approval(
    reviews: &[Value],
    reviewer: &config::Principal,
    reviewer_type: &str,
    head: &str,
) -> bool {
    let mut latest: Option<(&Value, (chrono::DateTime<chrono::FixedOffset>, u64))> = None;
    for review in reviews.iter().filter(|review| {
        matches!(
            review["state"].as_str(),
            Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
        )
    }) {
        let user = &review["user"];
        let Some(user_id) = user["id"].as_u64().filter(|id| *id > 0) else {
            return false;
        };
        let reviewer_candidate =
            user_id == reviewer.id || user["login"].as_str() == Some(reviewer.login.as_str());
        if !reviewer_candidate {
            continue;
        }
        if !request::matches_principal(user, reviewer.id, &reviewer.login, reviewer_type) {
            return false;
        }
        let Some(order) = request::review_order(review) else {
            return false;
        };
        if latest.is_none_or(|(_, previous_order)| order > previous_order) {
            latest = Some((review, order));
        }
    }
    latest.is_some_and(|(review, _)| expected_approval(review, reviewer, reviewer_type, head))
}

fn cleanup() -> Result<()> {
    let payload = event()?;
    let Some(label) = payload["label"]["name"].as_str() else {
        return Ok(());
    };
    if !label.starts_with(
        &config::trusted()?
            .deployment
            .label_prefix("approve-request-"),
    ) {
        return Ok(());
    }
    approval_source(label)?;
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    securefix::workflow::require_current_runtime(&api, ".github/workflows/approve.yml")?;
    match api.delete(&format!(
        "/repos/{}/labels/{label}",
        config::trusted()?.deployment.server.repository
    )) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("returned 404") => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_review_authentication_requires_the_exact_configured_user() {
        use crate::fixtures::{Fixture, Route};
        let reviewer = &config::trusted().unwrap().deployment.approval_reviewer;
        for (kind, id, login, expected) in [
            ("User", reviewer.id, reviewer.login.as_str(), true),
            ("Bot", reviewer.id, reviewer.login.as_str(), false),
            ("User", reviewer.id + 1, reviewer.login.as_str(), false),
            ("User", reviewer.id, "another-user", false),
        ] {
            let fixture = Fixture::new(vec![Route::get(
                "/user",
                json!({"type":kind,"id":id,"login":login}),
            )]);
            assert_eq!(
                authenticate_reviewer(&fixture.api, reviewer).is_ok(),
                expected
            );
            fixture.finish();
        }
    }

    #[test]
    fn renovate_review_refresh_accepts_only_the_separate_merge_authorization() {
        let owner = Authorization::OwnerComment {
            comment_id: 7,
            updated_at: None,
        };
        let automatic = Authorization::Automatic {
            actor_id: 9,
            actor_login: "updater[bot]".into(),
        };
        let bot = Authorization::RenovateComment {
            comment_id: 8,
            updated_at: chrono::Utc::now(),
        };
        assert!(approval_authorization_allowed(RequestKind::Approve, &owner));
        assert!(approval_authorization_allowed(
            RequestKind::Approve,
            &automatic
        ));
        assert!(!approval_authorization_allowed(RequestKind::Approve, &bot));
        assert!(approval_authorization_allowed(RequestKind::Merge, &bot));
        assert!(!approval_authorization_allowed(RequestKind::Merge, &owner));
        assert!(!approval_authorization_allowed(
            RequestKind::Merge,
            &automatic
        ));
        assert_eq!(
            approval_source("approve-request-12").unwrap(),
            (12, RequestKind::Approve)
        );
        assert_eq!(
            approval_source("approve-request-renovate-12").unwrap(),
            (12, RequestKind::Merge)
        );
        for invalid in [
            "approve-request-renovate-0",
            "approve-request-0",
            "merge-request-12",
            "approve-request-renovate-12-extra",
        ] {
            assert!(approval_source(invalid).is_err(), "{invalid}");
        }
    }

    fn reviewer() -> config::Principal {
        config::Principal {
            login: "securefix-reviewer[bot]".into(),
            id: 42,
        }
    }

    fn test_control() -> securefix::control::ControlRevision {
        crate::fixtures::Fixture::control_revision()
    }

    fn review(user: Value, state: &str, head: &str, id: u64) -> Value {
        json!({
            "id":id,
            "user":user,
            "state":state,
            "commit_id":head,
            "submitted_at":format!("2026-01-01T00:00:{id:02}Z"),
        })
    }

    fn reviewer_user(kind: &str, id: u64, login: &str) -> Value {
        json!({"type":kind,"id":id,"login":login})
    }

    #[test]
    fn only_the_owner_comment_authorization_can_post_sensitive_marker() {
        let manual = Authorization::OwnerComment {
            comment_id: 17,
            updated_at: None,
        };
        let automatic = Authorization::Automatic {
            actor_id: 9,
            actor_login: "renovate[bot]".into(),
        };
        assert!(matches!(
            manual,
            Authorization::OwnerComment { comment_id: 17, .. }
        ));
        assert!(!matches!(automatic, Authorization::OwnerComment { .. }));
    }

    #[test]
    fn approval_response_must_match_reviewer_type_identity_and_head() {
        let reviewer = reviewer();
        let expected = review(
            reviewer_user("Bot", reviewer.id, &reviewer.login),
            "APPROVED",
            "a".repeat(40).as_str(),
            1,
        );
        assert!(expected_approval(
            &expected,
            &reviewer,
            "Bot",
            &"a".repeat(40)
        ));
        assert!(!expected_approval(
            &reviewer_response("User", reviewer.id, &reviewer.login, &"a".repeat(40)),
            &reviewer,
            "Bot",
            &"a".repeat(40)
        ));
        assert!(!expected_approval(
            &reviewer_response("Bot", reviewer.id + 1, &reviewer.login, &"a".repeat(40)),
            &reviewer,
            "Bot",
            &"a".repeat(40)
        ));
        assert!(!expected_approval(
            &reviewer_response("Bot", reviewer.id, &reviewer.login, &"b".repeat(40)),
            &reviewer,
            "Bot",
            &"a".repeat(40)
        ));
    }

    #[test]
    fn latest_reviewer_decision_and_review_target_are_bound_to_the_head() {
        let reviewer = reviewer();
        let bot = reviewer_user("Bot", reviewer.id, &reviewer.login);
        let head = "a".repeat(40);
        let approval = review(bot.clone(), "APPROVED", &head, 1);
        assert!(latest_reviewer_approval(
            std::slice::from_ref(&approval),
            &reviewer,
            "Bot",
            &head
        ));
        assert!(!latest_reviewer_approval(
            &[approval, review(bot.clone(), "CHANGES_REQUESTED", &head, 2)],
            &reviewer,
            "Bot",
            &head
        ));
        assert!(!latest_reviewer_approval(
            &[review(bot, "APPROVED", &"b".repeat(40), 3)],
            &reviewer,
            "Bot",
            &head
        ));

        validate_review_target(
            &json!({"state":"open","head":{"sha":head},"user":{"id":7}}),
            &head,
            reviewer.id,
        )
        .unwrap();
        assert!(
            validate_review_target(
                &json!({"state":"open","head":{"sha":head},"user":{"id":reviewer.id}}),
                &head,
                reviewer.id,
            )
            .is_err()
        );
        assert!(
            validate_review_target(
                &json!({"state":"open","head":{"sha":"b"},"user":{"id":7}}),
                &head,
                reviewer.id,
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_reviewer_decisions_fail_closed_and_timezone_offsets_are_ordered() {
        let reviewer = reviewer();
        let head = "a".repeat(40);
        let bot = reviewer_user("Bot", reviewer.id, &reviewer.login);
        let approved = review(bot.clone(), "APPROVED", &head, 1);
        let malformed_changes = json!({
            "user":bot,
            "state":"CHANGES_REQUESTED",
            "commit_id":head,
            "submitted_at":"2026-01-02T00:00:00Z"
        });
        assert!(!latest_reviewer_approval(
            &[approved.clone(), malformed_changes],
            &reviewer,
            "Bot",
            &head
        ));

        let invalid_timestamp = json!({
            "id":2,
            "user":reviewer_user("Bot", reviewer.id, &reviewer.login),
            "state":"CHANGES_REQUESTED",
            "commit_id":head,
            "submitted_at":"yesterday"
        });
        assert!(!latest_reviewer_approval(
            &[approved.clone(), invalid_timestamp],
            &reviewer,
            "Bot",
            &head
        ));

        let missing_timestamp = json!({
            "id":2,
            "user":reviewer_user("Bot", reviewer.id, &reviewer.login),
            "state":"DISMISSED",
            "commit_id":head
        });
        assert!(!latest_reviewer_approval(
            &[approved.clone(), missing_timestamp],
            &reviewer,
            "Bot",
            &head
        ));

        let timezone_order = vec![
            json!({
                "id":3,
                "user":reviewer_user("Bot", reviewer.id, &reviewer.login),
                "state":"APPROVED",
                "commit_id":head,
                "submitted_at":"2026-01-01T01:00:00+01:00"
            }),
            json!({
                "id":4,
                "user":reviewer_user("Bot", reviewer.id, &reviewer.login),
                "state":"CHANGES_REQUESTED",
                "commit_id":head,
                "submitted_at":"2026-01-01T00:30:00Z"
            }),
        ];
        assert!(!latest_reviewer_approval(
            &timezone_order,
            &reviewer,
            "Bot",
            &head
        ));
    }

    fn reviewer_response(kind: &str, id: u64, login: &str, head: &str) -> Value {
        review(reviewer_user(kind, id, login), "APPROVED", head, 1)
    }

    #[test]
    fn approve_current_head_posts_exact_head_and_retries_without_a_second_post() {
        use crate::fixtures::{Fixture, Route};

        let deployment = &config::trusted().unwrap().deployment;
        let repository = &deployment.integration.repository;
        let number = 23;
        let reviewer = deployment.approval_reviewer.clone();
        let head = "a".repeat(40);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let reviews_path = format!("{pull_path}/reviews");
        let page_path = format!("{reviews_path}?per_page=100&page=1");
        let pull = json!({
            "state":"open",
            "head":{"sha":head},
            "user":{"id":7}
        });
        let control = test_control();
        let marker = format!(
            "<!-- securefix:control-review:{} -->",
            control.identity().unwrap()
        );
        let mut approval = reviewer_response("User", reviewer.id, &reviewer.login, &head);
        approval["body"] = json!(marker);

        let fixture = Fixture::new(vec![
            Route::get(&pull_path, pull.clone()),
            Route::get(&page_path, json!([])),
            Route::active_control(&control),
            Route::request("POST", &reviews_path, 200, approval.clone())
                .with_request_body(json!({"event":"APPROVE","commit_id":head,"body":marker})),
            Route::get(&pull_path, pull.clone()),
            Route::get(&page_path, json!([approval.clone()])),
            Route::get(&page_path, json!([approval.clone()])),
            Route::get(&pull_path, pull.clone()),
            Route::get(&page_path, json!([approval.clone()])),
            Route::get(&pull_path, pull),
            Route::get(&page_path, json!([approval.clone()])),
            Route::get(&page_path, json!([approval])),
        ]);

        approve_current_head(
            &fixture.api,
            &fixture.api,
            repository,
            number,
            &head,
            (&reviewer, "User"),
            &control,
        )
        .unwrap();
        approve_current_head(
            &fixture.api,
            &fixture.api,
            repository,
            number,
            &head,
            (&reviewer, "User"),
            &control,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn approve_current_head_accepts_a_control_bound_bot_reviewer() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let number = 23;
        let reviewer = config::Principal {
            id: 50_001,
            login: "scratch-reviewer[bot]".into(),
        };
        let head = "a".repeat(40);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let reviews_path = format!("{pull_path}/reviews");
        let page_path = format!("{reviews_path}?per_page=100&page=1");
        let pull = json!({"state":"open","head":{"sha":head},"user":{"id":7}});
        let control = test_control();
        let marker = format!(
            "<!-- securefix:control-review:{} -->",
            control.identity().unwrap()
        );
        let mut approval = reviewer_response("Bot", reviewer.id, &reviewer.login, &head);
        approval["body"] = json!(marker);
        let fixture = Fixture::new(vec![
            Route::get(&pull_path, pull.clone()),
            Route::get(&page_path, json!([])),
            Route::active_control(&control),
            Route::request("POST", &reviews_path, 200, approval.clone())
                .with_request_body(json!({"event":"APPROVE","commit_id":head,"body":marker})),
            Route::get(&pull_path, pull),
            Route::get(&page_path, json!([approval.clone()])),
            Route::get(&page_path, json!([approval])),
        ]);
        approve_current_head(
            &fixture.api,
            &fixture.api,
            repository,
            number,
            &head,
            (&reviewer, "Bot"),
            &control,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn approve_current_head_rejects_stale_target_before_posting() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let number = 23;
        let reviewer = reviewer();
        let head = "a".repeat(40);
        let stale_head = "b".repeat(40);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let fixture = Fixture::new(vec![Route::get(
            pull_path,
            json!({
                "state":"open",
                "head":{"sha":stale_head},
                "user":{"id":7}
            }),
        )]);

        assert!(
            approve_current_head(
                &fixture.api,
                &fixture.api,
                repository,
                number,
                &head,
                (&reviewer, "Bot"),
                &test_control(),
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn native_approval_posts_only_the_current_authorized_head_and_reads_it_back() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let number = 23;
        let reviewer = config::trusted()
            .unwrap()
            .deployment
            .approval_reviewer
            .clone();
        let head = "a".repeat(40);
        let request_bytes = br#"{"request":"bound"}"#;
        let authority = securefix::api::NativeAuthoritySnapshot {
            instance_repository: "civitaspo/securefix-server".to_owned(),
            instance_id: 1250079425,
            default_branch: "main".to_owned(),
            config_path: "repo-settings/native-securefix-test-instance.toml".to_owned(),
            config_sha256: "b".repeat(64),
            epoch: "c".repeat(40),
            workflows: vec![],
        };
        let manifest = native_approval_manifest(repository, number, &head, &authority);
        let body = securefix::api::native_approval_body(
            &authority,
            &head,
            &securefix::hex_encode(sha2::Sha256::digest(request_bytes)),
        )
        .unwrap();
        let marker = body["body"].as_str().unwrap().to_owned();
        let mut approval = reviewer_response("User", reviewer.id, &reviewer.login, &head);
        approval["body"] = json!(marker);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let reviews_path = format!("{pull_path}/reviews");
        let pull = json!({"state":"open","head":{"sha":head},"user":{"id":7}});
        let control = test_control();
        let fixture = Fixture::new(vec![
            Route::get(
                "/user",
                json!({"id":reviewer.id,"login":reviewer.login,"type":"User"}),
            ),
            Route::get(&pull_path, pull.clone()),
            Route::get(format!("{reviews_path}?per_page=100&page=1"), json!([])),
            Route::active_control(&control),
            Route::request("POST", &reviews_path, 200, approval.clone()).with_request_body(body),
            Route::get(&pull_path, pull).with_request_header("Cache-Control", "no-cache"),
            Route::get(
                format!("{reviews_path}?per_page=100&page=1"),
                json!([approval]),
            )
            .with_request_header("Cache-Control", "no-cache"),
        ]);
        approve_native_current_head(
            &fixture.api,
            &fixture.api,
            &manifest,
            &reviewer,
            request_bytes,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn native_approval_readback_retries_without_resubmitting_the_review() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let number = 26;
        let reviewer = config::trusted()
            .unwrap()
            .deployment
            .approval_reviewer
            .clone();
        let head = "a".repeat(40);
        let request_bytes = br#"{"request":"delayed"}"#;
        let authority = securefix::api::NativeAuthoritySnapshot {
            instance_repository: "civitaspo/securefix-server".to_owned(),
            instance_id: 1250079425,
            default_branch: "main".to_owned(),
            config_path: "repo-settings/native-securefix-test-instance.toml".to_owned(),
            config_sha256: "b".repeat(64),
            epoch: "c".repeat(40),
            workflows: vec![],
        };
        let manifest = native_approval_manifest(repository, number, &head, &authority);
        let body = securefix::api::native_approval_body(
            &authority,
            &head,
            &securefix::hex_encode(sha2::Sha256::digest(request_bytes)),
        )
        .unwrap();
        let mut approval = reviewer_response("User", reviewer.id, &reviewer.login, &head);
        approval["body"] = json!(body["body"]);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let reviews_path = format!("{pull_path}/reviews");
        let pull = json!({"state":"open","head":{"sha":head},"user":{"id":7}});
        let control = test_control();
        let fixture = Fixture::new(vec![
            Route::get(
                "/user",
                json!({"id":reviewer.id,"login":reviewer.login,"type":"User"}),
            ),
            Route::get(&pull_path, pull.clone()),
            Route::get(format!("{reviews_path}?per_page=100&page=1"), json!([])),
            Route::active_control(&control),
            Route::request("POST", &reviews_path, 200, approval.clone()).with_request_body(body),
            Route::get(&pull_path, pull.clone()).with_request_header("Cache-Control", "no-cache"),
            Route::get(format!("{reviews_path}?per_page=100&page=1"), json!([]))
                .with_request_header("Cache-Control", "no-cache"),
            Route::get(&pull_path, pull).with_request_header("Cache-Control", "no-cache"),
            Route::get(
                format!("{reviews_path}?per_page=100&page=1"),
                json!([approval]),
            )
            .with_request_header("Cache-Control", "no-cache"),
        ]);

        approve_native_current_head(
            &fixture.api,
            &fixture.api,
            &manifest,
            &reviewer,
            request_bytes,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn native_approval_rejects_a_stale_head_or_self_review_before_posting() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let number = 24;
        let reviewer = config::trusted()
            .unwrap()
            .deployment
            .approval_reviewer
            .clone();
        let expected_head = "a".repeat(40);
        let request_bytes = br#"{"request":"bound"}"#;
        let authority = securefix::api::NativeAuthoritySnapshot {
            instance_repository: "civitaspo/securefix-server".to_owned(),
            instance_id: 1250079425,
            default_branch: "main".to_owned(),
            config_path: "repo-settings/native-securefix-test-instance.toml".to_owned(),
            config_sha256: "b".repeat(64),
            epoch: "c".repeat(40),
            workflows: vec![],
        };
        let manifest = native_approval_manifest(repository, number, &expected_head, &authority);
        let pull_path = format!("/repos/{repository}/pulls/{number}");

        for pull in [
            json!({"state":"open","head":{"sha":"d".repeat(40)},"user":{"id":7}}),
            json!({"state":"open","head":{"sha":expected_head},"user":{"id":reviewer.id}}),
        ] {
            let fixture = Fixture::new(vec![
                Route::get(
                    "/user",
                    json!({"id":reviewer.id,"login":reviewer.login,"type":"User"}),
                ),
                Route::get(&pull_path, pull),
            ]);
            assert!(
                approve_native_current_head(
                    &fixture.api,
                    &fixture.api,
                    &manifest,
                    &reviewer,
                    request_bytes,
                )
                .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn native_approval_rejects_a_non_user_or_wrong_reviewer_token() {
        use crate::fixtures::{Fixture, Route};

        let repository = &config::trusted().unwrap().deployment.integration.repository;
        let reviewer = config::trusted()
            .unwrap()
            .deployment
            .approval_reviewer
            .clone();
        let head = "a".repeat(40);
        let authority = securefix::api::NativeAuthoritySnapshot {
            instance_repository: "civitaspo/securefix-server".to_owned(),
            instance_id: 1250079425,
            default_branch: "main".to_owned(),
            config_path: "repo-settings/native-securefix-test-instance.toml".to_owned(),
            config_sha256: "b".repeat(64),
            epoch: "c".repeat(40),
            workflows: vec![],
        };
        let manifest = native_approval_manifest(repository, 25, &head, &authority);

        for identity in [
            json!({"id":reviewer.id,"login":reviewer.login,"type":"Bot"}),
            json!({"id":reviewer.id + 1,"login":"different-user","type":"User"}),
        ] {
            let fixture = Fixture::new(vec![Route::get("/user", identity)]);
            assert!(
                approve_native_current_head(
                    &fixture.api,
                    &fixture.api,
                    &manifest,
                    &reviewer,
                    br#"{"request":"bound"}"#,
                )
                .is_err()
            );
            fixture.finish();
        }
    }

    fn native_approval_manifest(
        repository: &str,
        number: u64,
        head: &str,
        authority: &securefix::api::NativeAuthoritySnapshot,
    ) -> crate::native_client::RequestManifest {
        crate::native_client::RequestManifest {
            protocol: "securefix-native-request-v1".to_owned(),
            operation: "approval".to_owned(),
            repository: crate::native_client::RepositoryIdentity {
                id: 1,
                full_name: repository.to_owned(),
            },
            pull_request: crate::native_client::PullRequestIdentity {
                number,
                head_sha: head.to_owned(),
                head_branch: "owner/change".to_owned(),
                head_repository_id: 1,
                base_sha: "e".repeat(40),
                base_ref: "main".to_owned(),
                author_id: 7,
                author_login: "owner".to_owned(),
            },
            producer: crate::native_client::ProducerIdentity {
                run_id: 1,
                run_attempt: 1,
                event: "workflow_dispatch".to_owned(),
                context_sha: head.to_owned(),
                source_sha: head.to_owned(),
                workflow_path: ".github/workflows/request-producer-probe.yml".to_owned(),
                workflow_ref: "civitaspo/securefix-server/.github/workflows/request-producer-probe.yml@refs/heads/main".to_owned(),
                workflow_sha: "f".repeat(40),
                actor_id: 7,
                actor_login: "owner".to_owned(),
            },
            securefix_artifact: None,
            client_workflow_epoch: "d".repeat(40),
            server_authority: authority.clone(),
        }
    }
}
