use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{thread, time::Duration};

use crate::config;
use crate::request::{self, Authorization, RequestKind, RequestManifest};
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, validate_repository},
    workflow,
};

const INVALIDATING_EVENTS: &[&str] = &[
    "head_ref_force_pushed",
    "head_ref_deleted",
    "base_ref_force_pushed",
    "base_ref_deleted",
    "base_ref_changed",
    "merged",
    "closed",
    "reopened",
    "convert_to_draft",
    "ready_for_review",
];
const MAX_WAIT_SECONDS: i64 = 60 * 60;

#[derive(Subcommand)]
pub enum Command {
    Validate,
    Authorize,
    Wait,
    Apply,
    Notify,
    Cleanup,
    RetryRenovateTargets,
    RetryRenovate,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Validate => validate(),
        Command::Authorize => authorize(),
        Command::Wait => wait(),
        Command::Apply => apply(),
        Command::Notify => notify(),
        Command::Cleanup => cleanup(),
        Command::RetryRenovateTargets => retry_renovate_targets(),
        Command::RetryRenovate => retry_renovate(),
    }
}

fn validate() -> Result<()> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    let source_sha = workflow::require_current_runtime(&api, ".github/workflows/merge.yml")?;
    let control = policy
        .control
        .as_ref()
        .context("active control revision is missing")?;
    securefix::control::ControlRevision::require_current(&api, control)?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == server,
        "merge processor must run in the server repository"
    );
    let payload = event()?;
    ensure!(
        payload["action"] == "created"
            && payload["repository"]["id"].as_u64() == Some(deployment.server.id),
        "event is not a label creation"
    );
    let label = payload["label"]["name"]
        .as_str()
        .context("missing label name")?;
    let run_id: u64 = label
        .strip_prefix("merge-request-")
        .context("unexpected merge request label")?
        .parse()?;
    ensure!(
        request::matches_principal(
            &payload["sender"],
            config::trusted()?.client_bot_id,
            &deployment.client_bot_login,
            "Bot",
        ),
        "merge request label was not created by the Client App"
    );
    let description = payload["label"]["description"]
        .as_str()
        .context("missing label description")?;
    let (repository, described_run) = description
        .rsplit_once('/')
        .context("invalid request label description")?;
    validate_repository(repository)?;
    ensure!(
        described_run.parse::<u64>()? == run_id,
        "label description run ID mismatch"
    );
    policy.repository(repository)?.require(Capability::Merge)?;
    let manifest =
        request::load_source_request(&api, &policy, repository, run_id, RequestKind::Merge)?;
    validate_state(&api, &policy, &manifest)?;
    let (comment_id, _) = request::command_identity(&manifest.authorization)?;
    if request::validate_merge_policy(&api, &policy, &manifest, true)? {
        output("sensitive", "true")?;
    } else {
        output("sensitive", "false")?;
    }
    workflow::write_json("merge/manifest.json", &manifest)?;
    output("repository", repository)?;
    output(
        "repository_name",
        repository.rsplit('/').next().unwrap_or_default(),
    )?;
    output("pull_number", manifest.pull_request.number.to_string())?;
    output("head_sha", &manifest.pull_request.head_sha)?;
    output("source_sha", source_sha)?;
    output("comment_id", comment_id.to_string())?;
    output("manifest", serde_json::to_string(&manifest)?)?;
    Ok(())
}

fn authorize() -> Result<()> {
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    let manifest = read_manifest()?;
    ensure!(
        manifest.kind == RequestKind::Merge && manifest.workflow_sha == policy.revision,
        "merge manifest is invalid or stale"
    );
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    let source = request::load_source_request(
        &read,
        &policy,
        &manifest.repository.full_name,
        manifest.run_id,
        RequestKind::Merge,
    )?;
    ensure!(
        source == manifest,
        "source request changed after validation"
    );
    validate_state(&read, &policy, &manifest)?;
    request::validate_merge_policy(&read, &policy, &manifest, true)?;
    {
        let write = GitHub::from_env("SECUREFIX_AUTHORIZATION_TOKEN")?;
        if let Authorization::OwnerComment { comment_id, .. } = &manifest.authorization {
            request::post_owner_marker(
                &write,
                &manifest.repository.full_name,
                manifest.pull_request.number,
                &manifest.pull_request.head_sha,
                *comment_id,
                &manifest.control,
            )?;
        }
        if request::has_current_head_approval_for_control(
            &read,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            &manifest.control,
        )? {
            crate::policy_check::publish(
                &write,
                &manifest.repository.full_name,
                &manifest.pull_request.head_sha,
                true,
                "Changes passed signature, authorization, and current-head review checks.",
                &manifest.control,
            )?;
        }
    }
    Ok(())
}

fn wait() -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    let manifest = read_manifest()?;
    ensure!(
        manifest.kind == RequestKind::Merge && manifest.workflow_sha == policy.revision,
        "merge manifest is invalid or stale"
    );
    securefix::control::ControlRevision::require_current(&api, &manifest.control)?;
    let deadline = manifest.accepted_at + chrono::Duration::seconds(MAX_WAIT_SECONDS);
    loop {
        securefix::control::ControlRevision::require_current(&api, &manifest.control)?;
        validate_state(&api, &policy, &manifest)?;
        request::validate_merge_policy(&api, &policy, &manifest, false)?;
        if ready(&api, &manifest)? {
            output("ready", "true")?;
            return Ok(());
        }
        let remaining = deadline.signed_duration_since(Utc::now()).num_seconds();
        ensure!(
            remaining > 0,
            "required status-check and approved review did not become ready within 60 minutes"
        );
        thread::sleep(Duration::from_secs(remaining.min(30) as u64));
    }
}

fn apply() -> Result<()> {
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    let manifest = read_manifest()?;
    ensure!(
        manifest.kind == RequestKind::Merge && manifest.workflow_sha == policy.revision,
        "merge manifest is invalid or stale"
    );
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    let source = request::load_source_request(
        &read,
        &policy,
        &manifest.repository.full_name,
        manifest.run_id,
        RequestKind::Merge,
    )?;
    ensure!(source == manifest, "source request changed before merge");
    validate_state(&read, &policy, &manifest)?;
    request::validate_merge_policy(&read, &policy, &manifest, false)?;
    ensure!(
        ready(&read, &manifest)?,
        "merge prerequisites are not ready; retry outside the protected apply lane"
    );
    crate::control_commands::validate_activation_merge(&read, &manifest)?;
    let commits = read.paginate(&format!(
        "/repos/{}/pulls/{}/commits",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    ensure!(
        !commits.is_empty()
            && commits.len() < 250
            && commits.last().and_then(|c| c["sha"].as_str())
                == Some(&manifest.pull_request.head_sha),
        "commit list is incomplete or does not end at the accepted head"
    );
    let message = merge_message(&read, &manifest, &commits)?;
    let write = GitHub::from_env("SECUREFIX_MERGE_TOKEN")?;
    match write.put::<Value>(
        &format!(
            "/repos/{}/pulls/{}/merge",
            manifest.repository.full_name, manifest.pull_request.number
        ),
        &json!({
            "sha":manifest.pull_request.head_sha, "merge_method":"squash", "commit_message":message
        }),
    ) {
        Ok(result) => {
            ensure!(
                result["merged"] == true,
                "GitHub did not confirm the squash merge"
            );
            let merge_sha = result["sha"]
                .as_str()
                .context("merge response has no SHA")?;
            ensure!(
                merge_sha.len() == 40
                    && merge_sha
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "merge response contains an invalid SHA"
            );
            output("merge_sha", merge_sha)?;
            Ok(())
        }
        Err(error) if retryable_merge_error(&error) => {
            Err(error.context("merge API is not ready; retry outside the protected apply lane"))
        }
        Err(error) => Err(error),
    }
}

fn retryable_merge_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<securefix::api::ApiError>()
        .is_some_and(|api| matches!(api.status.as_u16(), 405 | 422 | 503))
}

fn read_manifest() -> Result<RequestManifest> {
    let manifest: RequestManifest = serde_json::from_slice(&std::fs::read("merge/manifest.json")?)?;
    manifest.validate()?;
    Ok(manifest)
}

pub(crate) fn validate_state(
    api: &GitHub,
    policy: &Policy,
    manifest: &RequestManifest,
) -> Result<()> {
    ensure!(
        policy.control.as_ref() == Some(&manifest.control),
        "merge manifest control revision differs from supplied policy"
    );
    ensure!(
        manifest.run_attempt == 1 && manifest.kind == RequestKind::Merge,
        "invalid or replayed merge request"
    );
    policy
        .repository(&manifest.repository.full_name)?
        .require(Capability::Merge)?;
    let repo: Value = api.get(&format!("/repos/{}", manifest.repository.full_name))?;
    ensure!(
        repo["id"].as_u64() == Some(manifest.repository.id),
        "repository identity changed"
    );
    let pr: Value = api.get(&format!(
        "/repos/{}/pulls/{}",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    ensure!(
        pr["state"] == "open"
            && pr["draft"] == false
            && pr["base"]["repo"]["full_name"] == manifest.repository.full_name
            && pr["base"]["ref"] == repo["default_branch"]
            && pr["base"]["ref"] == manifest.pull_request.base_ref
            && pr["head"]["repo"]["full_name"] == manifest.repository.full_name
            && pr["head"]["sha"] == manifest.pull_request.head_sha,
        "pull request is closed, retargeted, forked, draft, or has a different head"
    );
    let (comment_id, _) = request::command_identity(&manifest.authorization)?;
    if matches!(
        manifest.authorization,
        Authorization::RenovateComment { .. }
    ) {
        request::require_renovate_author(policy, &pr)?;
    }
    let comment: Value = api.get(&format!(
        "/repos/{}/issues/comments/{comment_id}",
        manifest.repository.full_name
    ))?;
    ensure!(
        request::command_matches(
            policy,
            &manifest.authorization,
            RequestKind::Merge,
            &comment,
            manifest.pull_request.number
        ),
        "merge command was changed or removed"
    );
    let events = api.paginate(&format!(
        "/repos/{}/issues/{}/timeline",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    ensure!(
        !has_invalidating_event(&events, manifest.accepted_at),
        "pull request timeline contains a change after acceptance"
    );
    Ok(())
}

fn has_invalidating_event(events: &[Value], accepted_at: DateTime<Utc>) -> bool {
    let cutoff = accepted_at.timestamp();
    events.iter().any(|event| {
        event["created_at"]
            .as_str()
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|time| time.timestamp() >= cutoff)
            && event["event"]
                .as_str()
                .is_some_and(|name| INVALIDATING_EVENTS.contains(&name))
    })
}

pub(crate) fn ready(api: &GitHub, manifest: &RequestManifest) -> Result<bool> {
    let reviewer = &config::trusted()?.deployment.approval_reviewer;
    ready_with_reviewer(api, manifest, (reviewer, "User"))
}

pub(crate) fn ready_with_reviewer(
    api: &GitHub,
    manifest: &RequestManifest,
    reviewer: (&config::Principal, &str),
) -> Result<bool> {
    let expected_external_id = format!(
        "{}:{}",
        manifest.pull_request.head_sha,
        manifest.control.identity()?
    );
    let deployment_checks = &config::trusted()?.deployment.checks;
    let repository = &manifest.repository.full_name;
    let mut checks = Vec::new();
    for page in 1..=100 {
        let response: Value = api.get(&format!(
            "/repos/{repository}/commits/{}/check-runs?per_page=100&page={page}&filter=latest",
            manifest.pull_request.head_sha
        ))?;
        let batch = response["check_runs"]
            .as_array()
            .context("check runs are malformed")?;
        let done = batch.len() < 100;
        checks.extend(batch.iter().cloned());
        if done {
            break;
        }
        ensure!(page < 100, "check run pagination exceeded limit");
    }
    let check_ok = exact_latest_check(
        &checks,
        "status-check",
        deployment_checks.status_app_id,
        true,
    );
    let policy_checks: Vec<_> = checks
        .iter()
        .filter(|check| {
            check["name"] == "securefix-policy-check"
                && check["app"]["id"] == deployment_checks.policy_app_id
        })
        .collect();
    ensure!(
        policy_checks.len() <= 1,
        "duplicate Securefix policy checks for the accepted head"
    );
    let policy_ok = policy_checks.first().is_some_and(|check| {
        check["external_id"] == expected_external_id && exact_completed_success(check)
    });
    let review = api.graphql("query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}", json!({
        "owner":repository.split('/').next().unwrap_or_default(), "name":repository.split('/').nth(1).unwrap_or_default(), "number":manifest.pull_request.number
    }))?;
    let approved = review["repository"]["pullRequest"]["reviewDecision"] == "APPROVED"
        && request::has_current_head_approval_for_reviewer(
            api,
            repository,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            &manifest.control,
            reviewer.0,
            reviewer.1,
        )?;
    Ok(check_ok && policy_ok && approved)
}

fn exact_latest_check(checks: &[Value], name: &str, app_id: u64, allow_skipped: bool) -> bool {
    let latest = checks
        .iter()
        .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
        .max_by_key(|check| check["id"].as_u64().unwrap_or_default());
    latest.is_some_and(|check| {
        exact_completed_success(check)
            || (allow_skipped && check["status"] == "completed" && check["conclusion"] == "skipped")
    })
}

fn exact_completed_success(check: &Value) -> bool {
    check["status"] == "completed" && check["conclusion"] == "success"
}

fn merge_message(api: &GitHub, manifest: &RequestManifest, commits: &[Value]) -> Result<String> {
    let pr: Value = api.get(&format!(
        "/repos/{}/pulls/{}",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    let commit_messages = commits
        .iter()
        .filter_map(|commit| commit["commit"]["message"].as_str())
        .collect::<Vec<_>>();
    Ok(merge_commit_message(
        pr["body"].as_str().unwrap_or_default(),
        &commit_messages,
    ))
}

fn merge_commit_message(body: &str, commit_messages: &[&str]) -> String {
    let mut lines = body
        .trim_end()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut existing = lines
        .iter()
        .filter(|line| line.to_ascii_lowercase().starts_with("co-authored-by:"))
        .map(|line| line.to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>();
    let mut trailers = Vec::new();
    for message in commit_messages {
        for line in message.lines().filter(|line| {
            line.to_ascii_lowercase().starts_with("co-authored-by:")
                && line.contains('<')
                && line.contains('>')
        }) {
            if existing.insert(line.to_ascii_lowercase()) {
                trailers.push(line.to_owned());
            }
        }
    }
    if !trailers.is_empty() {
        lines.push(String::new());
        lines.extend(trailers);
    }
    lines.join("\n")
}

fn notify() -> Result<()> {
    let trusted = config::trusted()?;
    let server = trusted.deployment.server.repository.as_str();
    let manifest = read_manifest()?;
    let token = GitHub::from_env("SECUREFIX_NOTIFY_TOKEN")?;
    let marker = format!("<!-- securefix-merge-request:{} -->", manifest.run_id);
    let comments = token.paginate(&format!(
        "/repos/{}/issues/{}/comments",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    ensure!(
        !comments.iter().any(|comment| request::matches_principal(
            &comment["user"],
            trusted.server_bot_id,
            &trusted.deployment.server_bot_login,
            "Bot",
        ) && comment["body"]
            .as_str()
            .is_some_and(|body| body.lines().any(|line| line == marker))),
        "terminal result was already recorded"
    );
    let result = std::env::var("SECUREFIX_MERGE_RESULT").unwrap_or_else(|_| "failure".into());
    let sha = std::env::var("SECUREFIX_MERGE_SHA").unwrap_or_default();
    let (message, terminal) = if result == "success" {
        ensure!(
            sha.len() == 40
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "successful merge result lacks a valid SHA"
        );
        (
            format!("Securefix merged this pull request with squash at {sha}."),
            true,
        )
    } else {
        ("Securefix could not merge this request. Resolve the validation failure and post a new exact `/merge` comment.".to_owned(), false)
    };
    let server_url =
        std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
    let run_id = std::env::var("GITHUB_RUN_ID")?;
    let body =
        format!("{marker}\n{message}\n\nServer run: {server_url}/{server}/actions/runs/{run_id}");
    let _: Value = token.post(
        &format!(
            "/repos/{}/issues/{}/comments",
            manifest.repository.full_name, manifest.pull_request.number
        ),
        &json!({"body":body}),
    )?;
    if terminal {
        output("notified", "merged")?;
    } else {
        output("notified", "rejected")?;
    }
    Ok(())
}

fn cleanup() -> Result<()> {
    let server = config::trusted()?.deployment.server.repository.clone();
    let payload = event()?;
    let Some(label) = payload["label"]["name"].as_str() else {
        return Ok(());
    };
    let Some(suffix) = label.strip_prefix("merge-request-") else {
        return Ok(());
    };
    ensure!(suffix.parse::<u64>().is_ok(), "invalid merge request label");
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    workflow::require_current_runtime(&api, ".github/workflows/merge.yml")?;
    match api.delete(&format!("/repos/{server}/labels/{label}")) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("returned 404") => Ok(()),
        Err(error) => Err(error),
    }
}

// Renovate's pr-comment mode keeps an existing identical comment indefinitely.
// Remove only expired bot requests so Renovate can reevaluate its own rules and
// submit a new first-attempt request, bound to the then-current head and control.
fn retry_renovate_policy() -> Result<(GitHub, Policy)> {
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&read)?;
    workflow::require_current_runtime(&read, ".github/workflows/renovate-merge-retry.yml")?;
    let deployment = &policy.deployment;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == deployment.server.repository
            && std::env::var("GITHUB_REF")?
                == format!("refs/heads/{}", deployment.server.default_branch)
            && std::env::var("GITHUB_WORKFLOW_REF")?
                == format!(
                    "{}/.github/workflows/renovate-merge-retry.yml@refs/heads/{}",
                    deployment.server.repository, deployment.server.default_branch
                )
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1",
        "Renovate retry must use the server default-branch workflow's first attempt"
    );
    match std::env::var("GITHUB_EVENT_NAME")?.as_str() {
        "schedule" => {}
        "workflow_dispatch" => ensure!(
            std::env::var("GITHUB_ACTOR_ID")?.parse::<u64>()? == policy.owner_id,
            "only the owner may dispatch Renovate retries"
        ),
        _ => anyhow::bail!("unsupported Renovate retry event"),
    }
    Ok((read, policy))
}

fn retry_renovate_targets() -> Result<()> {
    let (_, policy) = retry_renovate_policy()?;
    let repositories: Vec<_> = policy.repositories.iter()
        .filter(|repo| policy.renovate_merge_bot.is_some() && repo.capabilities.contains(&Capability::Merge))
        .map(|repo| json!({"repository": repo.repository, "name": repo.repository.rsplit('/').next().unwrap_or_default()})).collect();
    output("repositories", serde_json::to_string(&repositories)?)
}

fn expired_renovate_command(
    policy: &Policy,
    comment: &Value,
    number: u64,
    cutoff: DateTime<Utc>,
) -> Option<Authorization> {
    let updated_at = DateTime::parse_from_rfc3339(comment["updated_at"].as_str()?)
        .ok()?
        .with_timezone(&Utc);
    let comment_id = comment["id"].as_u64().filter(|id| *id > 0)?;
    let authorization = Authorization::RenovateComment {
        comment_id,
        updated_at,
    };
    (updated_at < cutoff
        && request::command_matches(policy, &authorization, RequestKind::Merge, comment, number))
    .then_some(authorization)
}

fn retry_renovate() -> Result<()> {
    let (read, policy) = retry_renovate_policy()?;
    let control = policy
        .control
        .as_ref()
        .context("missing active control revision")?;
    let bot = policy
        .renovate_merge_bot
        .as_ref()
        .context("Renovate merge requests are disabled")?;
    let repository = std::env::var("SECUREFIX_REPOSITORY")?;
    policy.repository(&repository)?.require(Capability::Merge)?;
    let api = GitHub::from_env("SECUREFIX_RENOVATE_TOKEN")?;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["full_name"] == repository
            && repo["owner"]["id"].as_u64() == Some(policy.deployment.repository_owner.id),
        "retry repository identity differs from the configured owner"
    );
    let eligible = |pr: &Value| {
        pr["state"] == "open"
            && pr["draft"] == false
            && pr["head"]["repo"]["full_name"] == repository
            && pr["base"]["ref"] == repo["default_branch"]
            && request::matches_principal(&pr["user"], bot.id, &bot.login, "Bot")
    };
    let cutoff = Utc::now() - chrono::Duration::hours(2);
    for pr in api.paginate(&format!("/repos/{repository}/pulls?state=open"))? {
        if !eligible(&pr) {
            continue;
        }
        let number = pr["number"].as_u64().context("missing PR number")?;
        for comment in api.paginate(&format!("/repos/{repository}/issues/{number}/comments"))? {
            let Some(authorization) = expired_renovate_command(&policy, &comment, number, cutoff)
            else {
                continue;
            };
            let (comment_id, _) = request::command_identity(&authorization)?;
            let current_pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
            if !eligible(&current_pr) {
                break;
            }
            let current_comment: Value =
                api.get(&format!("/repos/{repository}/issues/comments/{comment_id}"))?;
            if current_comment["id"].as_u64() != Some(comment_id)
                || !request::command_matches(
                    &policy,
                    &authorization,
                    RequestKind::Merge,
                    &current_comment,
                    number,
                )
            {
                continue;
            }
            securefix::control::ControlRevision::require_current(&read, control)?;
            api.delete(&format!("/repos/{repository}/issues/comments/{comment_id}"))?;
            println!(
                "Removed expired Renovate merge request {repository}#{number} comment {comment_id}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

    #[test]
    fn renovate_retry_selects_only_expired_unedited_configured_bot_commands() {
        let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
        policy.renovate_merge_bot = Some(crate::config::Principal {
            id: 43,
            login: "updater[bot]".into(),
        });
        let cutoff = DateTime::parse_from_rfc3339("2026-01-01T02:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let comment = json!({"id":8,"body":"/merge","user":{"id":43,"login":"updater[bot]","type":"Bot"},
            "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z",
            "issue_url":"https://api.github.com/repos/civitaspo/example/issues/7"});
        assert!(expired_renovate_command(&policy, &comment, 7, cutoff).is_some());
        for (pointer, value) in [
            ("/id", json!(0)),
            (
                "/user",
                json!({"id":policy.owner_id,"login":policy.deployment.owner_login,"type":"User"}),
            ),
            ("/body", json!("/approve")),
            ("/created_at", json!("2025-12-31T23:59:59Z")),
            ("/updated_at", json!("invalid")),
        ] {
            let mut changed = comment.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                expired_renovate_command(&policy, &changed, 7, cutoff).is_none(),
                "{pointer}"
            );
        }
        for time in ["2026-01-01T02:00:00Z", "2026-01-01T03:00:00Z"] {
            let mut fresh = comment.clone();
            fresh["created_at"] = json!(time);
            fresh["updated_at"] = json!(time);
            assert!(expired_renovate_command(&policy, &fresh, 7, cutoff).is_none());
        }
        policy.renovate_merge_bot = None;
        assert!(expired_renovate_command(&policy, &comment, 7, cutoff).is_none());
    }

    fn state_manifest() -> RequestManifest {
        RequestManifest {
            version: 1,
            kind: RequestKind::Merge,
            repository: crate::request::RepositoryRef {
                id: 1,
                full_name: "civitaspo/dbt-authorized-models".into(),
            },
            pull_request: crate::request::PullRequestRef {
                number: 7,
                head_sha: "a".repeat(40),
                base_ref: "main".into(),
            },
            authorization: Authorization::OwnerComment {
                comment_id: 8,
                updated_at: Some(
                    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
            },
            accepted_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            run_id: 4,
            run_attempt: 1,
            workflow_sha: "b".repeat(40),
            caller_workflow_sha: "c".repeat(40),
            control: securefix::control::ControlRevision {
                version: 1,
                generation: 1,
                source_sha: "b".repeat(40),
                policy_sha256: "1".repeat(64),
                archive_sha256: "2".repeat(64),
                release_id: 3,
                asset_id: 4,
                publisher_run_id: 5,
                verification_run_id: 6,
                previous: "0".repeat(64),
            },
        }
    }

    fn state_prefix(pr: Value) -> Vec<Route> {
        vec![
            Route::get(
                "/repos/civitaspo/dbt-authorized-models",
                json!({"id":1,"default_branch":"main"}),
            ),
            Route::get("/repos/civitaspo/dbt-authorized-models/pulls/7", pr),
        ]
    }

    fn valid_pr() -> Value {
        json!({"state":"open","draft":false,
            "base":{"repo":{"full_name":"civitaspo/dbt-authorized-models"},"ref":"main"},
            "head":{"repo":{"full_name":"civitaspo/dbt-authorized-models"},"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})
    }

    fn validate_state_with(api_routes: Vec<Route>) -> Result<()> {
        let fixture = Fixture::new(api_routes);
        let mut policy = Policy::load("tests/fixtures/policy.json")?;
        let manifest = state_manifest();
        policy.control = Some(manifest.control.clone());
        let result = validate_state(&fixture.api, &policy, &manifest);
        fixture.finish();
        result
    }

    #[test]
    fn validate_state_rejects_changed_head_base_draft_and_closed_prs() {
        let mut cases = Vec::new();
        let mut changed_head = valid_pr();
        changed_head["head"]["sha"] = json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        cases.push(changed_head);
        let mut changed_base = valid_pr();
        changed_base["base"]["ref"] = json!("release");
        cases.push(changed_base);
        let mut draft = valid_pr();
        draft["draft"] = json!(true);
        cases.push(draft);
        let mut closed = valid_pr();
        closed["state"] = json!("closed");
        cases.push(closed);
        for pr in cases {
            assert!(validate_state_with(state_prefix(pr)).is_err());
        }
    }

    fn comment_routes(comment: Value) -> Vec<Route> {
        let mut routes = state_prefix(valid_pr());
        routes.push(Route::get(
            "/repos/civitaspo/dbt-authorized-models/issues/comments/8",
            comment,
        ));
        routes
    }

    fn valid_owner_comment() -> Value {
        let owner = &crate::config::trusted().unwrap().deployment.owner_login;
        json!({"body":"/merge","user":{"id":crate::config::trusted().unwrap().owner_id,"login":owner,"type":"User"},
            "issue_url":"https://api.github.com/repos/civitaspo/dbt-authorized-models/issues/7",
            "updated_at":"2026-01-01T00:00:00Z"})
    }

    #[test]
    fn validate_state_rejects_changed_owner_comment_identity_body_url_and_edit_time() {
        let mut wrong_actor = valid_owner_comment();
        wrong_actor["user"]["id"] = json!(999);
        let mut wrong_type = valid_owner_comment();
        wrong_type["user"]["type"] = json!("Bot");
        let mut wrong_url = valid_owner_comment();
        wrong_url["issue_url"] =
            json!("https://api.github.com/repos/civitaspo/dbt-authorized-models/issues/8");
        let mut wrong_body = valid_owner_comment();
        wrong_body["body"] = json!("/approve");
        let mut edited = valid_owner_comment();
        edited["updated_at"] = json!("2026-01-01T00:00:01Z");
        for comment in [wrong_actor, wrong_type, wrong_url, wrong_body, edited] {
            assert!(validate_state_with(comment_routes(comment)).is_err());
        }
    }

    #[test]
    fn validate_state_accepts_ascii_whitespace_around_the_owner_command() {
        for body in ["/merge", " \t/merge\r\n"] {
            let mut comment = valid_owner_comment();
            comment["body"] = json!(body);
            let mut routes = comment_routes(comment);
            let timeline =
                "/repos/civitaspo/dbt-authorized-models/issues/7/timeline?per_page=100&page=1";
            routes.push(Route::get(timeline, json!([])));
            let fixture = Fixture::new(routes);
            let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
            let manifest = state_manifest();
            policy.control = Some(manifest.control.clone());
            let result = validate_state(&fixture.api, &policy, &manifest);
            if result.is_err() {
                let _: Value = fixture.api.get(timeline).unwrap();
            }
            fixture.finish();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn validate_state_rejects_deleted_owner_comment() {
        let mut routes = state_prefix(valid_pr());
        routes.push(Route::request(
            "GET",
            "/repos/civitaspo/dbt-authorized-models/issues/comments/8",
            404,
            json!({"message":"Not Found"}),
        ));
        assert!(validate_state_with(routes).is_err());
    }

    #[test]
    fn force_push_invalidates_even_when_the_pr_head_returns_to_the_accepted_sha() {
        let mut routes = comment_routes(valid_owner_comment());
        routes.push(Route::get(
            "/repos/civitaspo/dbt-authorized-models/issues/7/timeline?per_page=100&page=1",
            json!([{"event":"head_ref_force_pushed","created_at":"2026-01-01T00:00:01Z"}]),
        ));
        assert!(validate_state_with(routes).is_err());
    }

    #[test]
    fn reopen_and_ready_for_review_events_invalidate_the_accepted_request() {
        for event in ["reopened", "ready_for_review"] {
            let mut routes = comment_routes(valid_owner_comment());
            routes.push(Route::get(
                "/repos/civitaspo/dbt-authorized-models/issues/7/timeline?per_page=100&page=1",
                json!([{"event":event,"created_at":"2026-01-01T00:00:01Z"}]),
            ));
            assert!(validate_state_with(routes).is_err());
        }
    }
    #[test]
    fn timeline_invalidation_is_conservative_within_acceptance_second() {
        let accepted = DateTime::parse_from_rfc3339("2026-01-01T00:00:00.900Z")
            .unwrap()
            .with_timezone(&Utc);
        let events =
            vec![json!({"event":"head_ref_force_pushed","created_at":"2026-01-01T00:00:00.100Z"})];
        assert!(has_invalidating_event(&events, accepted));
        let old_events =
            vec![json!({"event":"head_ref_force_pushed","created_at":"2025-12-31T23:59:59Z"})];
        assert!(!has_invalidating_event(&old_events, accepted));
    }

    #[test]
    fn only_the_latest_status_check_from_the_required_app_counts() {
        let checks = vec![
            json!({"id":1,"name":"status-check","app":{"id":crate::config::trusted().unwrap().deployment.checks.status_app_id},"status":"completed","conclusion":"success"}),
            json!({"id":2,"name":"status-check","app":{"id":crate::config::trusted().unwrap().deployment.checks.status_app_id},"status":"completed","conclusion":"failure"}),
            json!({"id":3,"name":"status-check","app":{"id":99},"status":"completed","conclusion":"success"}),
        ];
        assert!(!exact_latest_check(
            &checks,
            "status-check",
            crate::config::trusted()
                .unwrap()
                .deployment
                .checks
                .status_app_id,
            true
        ));
        assert!(exact_latest_check(&checks, "status-check", 99, true));
    }

    #[test]
    fn merge_retries_only_transient_policy_responses() {
        for status in [405, 422, 503] {
            let error = anyhow::Error::new(securefix::api::ApiError {
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                method: reqwest::Method::PUT,
                path: "/merge".into(),
            });
            assert!(retryable_merge_error(&error));
        }
        let conflict = anyhow::Error::new(securefix::api::ApiError {
            status: reqwest::StatusCode::CONFLICT,
            method: reqwest::Method::PUT,
            path: "/merge".into(),
        });
        assert!(!retryable_merge_error(&conflict));
    }

    #[test]
    fn merge_message_deduplicates_trailers_case_insensitively() {
        let message = merge_commit_message(
            "body\n\nCo-authored-by: A <a@example.com>",
            &["subject\n\nco-authored-by: a <a@example.com>\nCo-authored-by: B <b@example.com>"],
        );
        assert_eq!(
            message,
            "body\n\nCo-authored-by: A <a@example.com>\n\nCo-authored-by: B <b@example.com>"
        );
    }
}
