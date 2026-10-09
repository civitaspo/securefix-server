use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};

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

fn validate() -> Result<()> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    let source_sha =
        securefix::workflow::require_current_runtime(&api, ".github/workflows/approve.yml")?;
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
    let run_id: u64 = label
        .strip_prefix("approve-request-")
        .context("unexpected approval request label")?
        .parse()?;
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
    let manifest =
        request::load_source_request(&api, &policy, repository, run_id, RequestKind::Approve)?;
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
    let owner_requested = matches!(&manifest.authorization, Authorization::OwnerComment { .. });
    request::validate_pr_authorization(
        &api,
        &policy,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        owner_requested,
    )?;
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

fn apply() -> Result<()> {
    let deployment = &config::trusted()?.deployment;
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    let manifest: RequestManifest =
        serde_json::from_slice(&std::fs::read("approval/manifest.json")?)?;
    manifest.validate()?;
    ensure!(
        manifest.kind == RequestKind::Approve && manifest.workflow_sha == policy.revision,
        "approval manifest is invalid or stale"
    );
    let source = request::load_source_request(
        &read,
        &policy,
        &manifest.repository.full_name,
        manifest.run_id,
        RequestKind::Approve,
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
    request::validate_pr_authorization(
        &read,
        &policy,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        owner_requested,
    )?;
    let write = GitHub::from_env("SECUREFIX_WRITE_TOKEN")?;
    if owner_requested
        && let Authorization::OwnerComment { comment_id, .. } = &manifest.authorization
    {
        request::post_owner_marker(
            &write,
            repository,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            *comment_id,
        )?;
    }
    let approve = GitHub::from_env("SECUREFIX_APPROVE_TOKEN")?;
    let approver: Value = approve.get("/user")?;
    ensure!(
        approver["login"] == deployment.approval_reviewer.login
            && approver["id"].as_u64() == Some(deployment.approval_reviewer.id)
            && approver["type"] == "User",
        "approval token must authenticate as the configured review account"
    );
    approve_current_head(
        &read,
        &approve,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        &deployment.approval_reviewer,
        "User",
    )?;
    let current_policy = Policy::active(&read)?;
    ensure!(
        current_policy.revision == manifest.workflow_sha,
        "server policy revision changed before policy check publication"
    );
    let current_pr: Value = read.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    ensure!(
        current_pr["state"] == "open"
            && current_pr["head"]["sha"] == manifest.pull_request.head_sha,
        "pull request head changed before policy check publication"
    );
    let sensitive = request::validate_pr_authorization(
        &read,
        &current_policy,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        owner_requested,
    )?;
    crate::policy_check::publish(
        &write,
        repository,
        &manifest.pull_request.head_sha,
        true,
        if sensitive {
            "Sensitive changes passed signature, owner authorization, and review checks."
        } else {
            "Changes passed signature and review checks."
        },
    )?;
    Ok(())
}

pub(crate) fn approve_current_head(
    read: &GitHub,
    review_api: &GitHub,
    repository: &str,
    pull_number: u64,
    expected_head: &str,
    reviewer: &config::Principal,
    reviewer_type: &str,
) -> Result<()> {
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
    let reviews = read.paginate(&path)?;
    if !latest_reviewer_approval(&reviews, reviewer, reviewer_type, expected_head) {
        let response: Value =
            review_api.post(&path, &json!({"event":"APPROVE","commit_id":expected_head}))?;
        ensure!(
            expected_approval(&response, reviewer, reviewer_type, expected_head),
            "GitHub returned an approval for a different reviewer or head"
        );
    }
    ensure!(
        request::has_current_head_approval(read, repository, pull_number, expected_head)?,
        "no non-author approval is attached to the accepted head"
    );
    let reviews = read.paginate(&path)?;
    ensure!(
        latest_reviewer_approval(&reviews, reviewer, reviewer_type, expected_head),
        "expected reviewer approval is not attached to the accepted head"
    );
    Ok(())
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
    let Some(suffix) = label.strip_prefix("approve-request-") else {
        return Ok(());
    };
    ensure!(
        suffix.parse::<u64>().is_ok(),
        "invalid approval request label"
    );
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

    fn reviewer() -> config::Principal {
        config::Principal {
            login: "securefix-reviewer[bot]".into(),
            id: 42,
        }
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
        let reviewer = reviewer();
        let head = "a".repeat(40);
        let pull_path = format!("/repos/{repository}/pulls/{number}");
        let reviews_path = format!("{pull_path}/reviews");
        let page_path = format!("{reviews_path}?per_page=100&page=1");
        let pull = json!({
            "state":"open",
            "head":{"sha":head},
            "user":{"id":7}
        });
        let approval = reviewer_response("Bot", reviewer.id, &reviewer.login, &head);

        let fixture = Fixture::new(vec![
            Route::get(&pull_path, pull.clone()),
            Route::get(&page_path, json!([])),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    deployment.server.repository, deployment.server.default_branch
                ),
                json!({"sha":head}),
            ),
            Route::request("POST", &reviews_path, 200, approval.clone())
                .with_request_body(json!({"event":"APPROVE","commit_id":head})),
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
            &reviewer,
            "Bot",
        )
        .unwrap();
        approve_current_head(
            &fixture.api,
            &fixture.api,
            repository,
            number,
            &head,
            &reviewer,
            "Bot",
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
                &reviewer,
                "Bot",
            )
            .is_err()
        );
        fixture.finish();
    }
}
