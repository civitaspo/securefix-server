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
const RENOVATE_REBASE_MARKER: &str = "<!-- securefix-renovate-rebase:v1 -->";

#[derive(Subcommand)]
pub enum Command {
    Validate,
    Authorize,
    Wait,
    Apply,
    Notify,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Validate => validate(),
        Command::Authorize => authorize(),
        Command::Wait => wait(),
        Command::Apply => apply(),
        Command::Notify => notify(),
        Command::Cleanup => cleanup(),
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
        .strip_prefix(&config::trusted()?.deployment.label_prefix("merge-request-"))
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
        if matches!(
            &manifest.authorization,
            Authorization::OwnerComment { .. } | Authorization::RenovateComment { .. }
        ) {
            request::acknowledge_request(
                &read,
                &write,
                &policy,
                &manifest.repository.full_name,
                manifest.pull_request.number,
                &manifest.authorization,
                RequestKind::Merge,
            )?;
        }
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

pub(crate) fn has_invalidating_event(events: &[Value], accepted_at: DateTime<Utc>) -> bool {
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
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    workflow::require_current_runtime(&read, ".github/workflows/merge.yml")?;
    let manifest: RequestManifest = serde_json::from_slice(&std::fs::read("merge/manifest.json")?)?;
    manifest.validate_notification()?;
    let payload = event()?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == server
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1"
            && manifest.kind == RequestKind::Merge
            && policy.control.as_ref() == Some(&manifest.control)
            && payload["action"] == "created"
            && payload["repository"]["id"].as_u64() == Some(trusted.deployment.server.id)
            && payload["label"]["name"]
                == config::trusted()?
                    .deployment
                    .label_prefix(&format!("merge-request-{}", manifest.run_id))
            && payload["label"]["description"]
                == format!("{}/{}", manifest.repository.full_name, manifest.run_id)
            && request::matches_principal(
                &payload["sender"],
                trusted.client_bot_id,
                &trusted.deployment.client_bot_login,
                "Bot",
            ),
        "notification is not the accepted merge workflow's first attempt"
    );
    let token = GitHub::from_env("SECUREFIX_NOTIFY_TOKEN")?;
    let result = std::env::var("SECUREFIX_MERGE_RESULT").unwrap_or_else(|_| "failure".into());
    let sha = std::env::var("SECUREFIX_MERGE_SHA").unwrap_or_default();
    let server_url =
        std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
    let run_id = std::env::var("GITHUB_RUN_ID")?;
    let run_url = format!("{server_url}/{server}/actions/runs/{run_id}");
    notify_result(&read, &token, &policy, &manifest, &result, &sha, &run_url)
}

pub(crate) fn notify_result(
    read: &GitHub,
    token: &GitHub,
    policy: &Policy,
    manifest: &RequestManifest,
    result: &str,
    sha: &str,
    run_url: &str,
) -> Result<()> {
    let trusted = config::trusted()?;
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
    let (mut message, terminal) = if result == "success" {
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
    if !terminal
        && matches!(
            manifest.authorization,
            Authorization::RenovateComment { .. }
        )
    {
        message = match request_renovate_rebase(read, token, policy, manifest) {
            Ok(true) => "Securefix could not merge this request and added the `rebase` label. Renovate will reevaluate the PR after rebasing and rerunning CI. No further automatic rebase will be requested on this PR.".into(),
            Ok(false) => "Securefix could not merge this request. Its automatic rebase was already requested or a rebase is pending. Resolve the failure and use Renovate's rebase/retry checkbox for another attempt.".into(),
            Err(error) => {
                eprintln!("Renovate rebase was not requested: {error:#}");
                "Securefix could not merge this request and could not safely request a rebase. Inspect the server run, resolve the failure, and use Renovate's rebase/retry checkbox for another attempt.".into()
            }
        };
    }
    let body = format!("{marker}\n{message}\n\nServer run: {run_url}");
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

pub(crate) fn request_renovate_rebase(
    read: &GitHub,
    write: &GitHub,
    policy: &Policy,
    manifest: &RequestManifest,
) -> Result<bool> {
    manifest.validate_notification()?;
    ensure!(
        matches!(
            manifest.authorization,
            Authorization::RenovateComment { .. }
        ),
        "only an accepted Renovate request may request a rebase"
    );
    validate_state(read, policy, manifest)?;
    request::validate_merge_policy(read, policy, manifest, false)?;
    let repository = &manifest.repository.full_name;
    let number = manifest.pull_request.number;
    let comments = read.paginate(&format!("/repos/{repository}/issues/{number}/comments"))?;
    if comments.iter().any(|comment| {
        request::matches_principal(
            &comment["user"],
            policy.server_bot_id,
            &policy.deployment.server_bot_login,
            "Bot",
        ) && comment["body"]
            .as_str()
            .is_some_and(|body| body.lines().any(|line| line == RENOVATE_REBASE_MARKER))
    }) {
        return Ok(false);
    }
    let pr: Value = read.get(&format!("/repos/{repository}/pulls/{number}"))?;
    if pr["labels"]
        .as_array()
        .is_some_and(|labels| labels.iter().any(|label| label["name"] == "rebase"))
    {
        return Ok(false);
    }
    validate_state(read, policy, manifest)?;
    let _: Value = write.post(
        &format!("/repos/{repository}/issues/{number}/comments"),
        &json!({"body":format!("{RENOVATE_REBASE_MARKER}\nSecurefix is requesting this PR's one automatic Renovate rebase. Further failures require a manual Renovate rebase/retry.")}),
    )?;
    validate_state(read, policy, manifest)?;
    let labels: Vec<Value> = write.post(
        &format!("/repos/{repository}/issues/{number}/labels"),
        &json!({"labels":["rebase"]}),
    )?;
    ensure!(
        labels.iter().any(|label| label["name"] == "rebase"),
        "GitHub did not confirm the rebase label"
    );
    Ok(true)
}

fn cleanup() -> Result<()> {
    let server = config::trusted()?.deployment.server.repository.clone();
    let payload = event()?;
    let Some(label) = payload["label"]["name"].as_str() else {
        return Ok(());
    };
    let Some(suffix) =
        label.strip_prefix(&config::trusted()?.deployment.label_prefix("merge-request-"))
    else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

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

    fn renovate_manifest() -> RequestManifest {
        let mut manifest = state_manifest();
        let control = Fixture::control_revision();
        manifest.authorization = Authorization::RenovateComment {
            comment_id: 8,
            updated_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        manifest.accepted_at = Utc::now();
        manifest.workflow_sha = control.source_sha.clone();
        manifest.control = control;
        manifest
    }

    fn renovate_policy(manifest: &RequestManifest) -> Policy {
        let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
        policy.control = Some(manifest.control.clone());
        policy.renovate_merge_bot = Some(crate::config::Principal {
            id: 43,
            login: "updater[bot]".into(),
        });
        policy.trusted_committers.push("updater[bot]".into());
        policy
    }

    fn renovate_pr(manifest: &RequestManifest) -> Value {
        json!({"state":"open","draft":false,
            "user":{"id":43,"login":"updater[bot]","type":"Bot"},
            "labels":[],
            "base":{"repo":{"full_name":manifest.repository.full_name},"ref":manifest.pull_request.base_ref},
            "head":{"repo":{"full_name":manifest.repository.full_name},"sha":manifest.pull_request.head_sha}})
    }

    fn renovate_command(manifest: &RequestManifest) -> Value {
        let (comment_id, updated_at) = request::command_identity(&manifest.authorization).unwrap();
        let updated_at = updated_at.unwrap().to_rfc3339();
        json!({"id":comment_id,"body":"/merge",
            "user":{"id":43,"login":"updater[bot]","type":"Bot"},
            "issue_url":format!("https://api.github.com/repos/{}/issues/{}", manifest.repository.full_name, manifest.pull_request.number),
            "created_at":updated_at.clone(),
            "updated_at":updated_at})
    }

    fn renovate_state_routes(manifest: &RequestManifest, pr: Value) -> Vec<Route> {
        let repository = &manifest.repository.full_name;
        vec![
            Route::get(
                format!("/repos/{repository}"),
                json!({"id":1,"default_branch":"main"}),
            ),
            Route::get(format!("/repos/{repository}/pulls/7"), pr),
            Route::get(
                format!(
                    "/repos/{repository}/issues/comments/{}",
                    request::command_identity(&manifest.authorization)
                        .unwrap()
                        .0
                ),
                renovate_command(manifest),
            ),
            Route::get(
                format!("/repos/{repository}/issues/7/timeline?per_page=100&page=1"),
                json!([]),
            ),
        ]
    }

    fn renovate_policy_routes(manifest: &RequestManifest) -> Vec<Route> {
        let repository = &manifest.repository.full_name;
        vec![
            Route::get(
                format!("/repos/{repository}/pulls/7"),
                renovate_pr(manifest),
            ),
            Route::get(
                format!("/repos/{repository}/pulls/7/commits?per_page=100&page=1"),
                json!([{
                    "sha":manifest.pull_request.head_sha,
                    "commit":{"verification":{"verified":true}},
                    "author":{"id":43,"login":"updater[bot]","type":"Bot"},
                    "committer":{"id":43,"login":"updater[bot]","type":"Bot"}
                }]),
            ),
            Route::get(
                format!("/repos/{repository}/pulls/7/files?per_page=100&page=1"),
                json!([]),
            ),
        ]
    }

    fn renovate_validation_routes(manifest: &RequestManifest, pr: Value) -> Vec<Route> {
        let mut routes = renovate_state_routes(manifest, pr);
        routes.extend(renovate_policy_routes(manifest));
        routes
    }

    fn append_rebase_success_routes(
        routes: &mut Vec<Route>,
        manifest: &RequestManifest,
        marker_comments: Value,
        labels: Value,
    ) {
        let repository = &manifest.repository.full_name;
        routes.push(Route::get(
            format!("/repos/{repository}/issues/7/comments?per_page=100&page=1"),
            marker_comments,
        ));
        routes.push(Route::get(format!("/repos/{repository}/pulls/7"), {
            let mut pr = renovate_pr(manifest);
            pr["labels"] = labels;
            pr
        }));
        routes.extend(renovate_state_routes(manifest, renovate_pr(manifest)));
        routes.push(Route::active_control(&manifest.control));
        routes.push(Route::request(
            "POST",
            format!("/repos/{repository}/issues/7/comments"),
            201,
            json!({"id":99}),
        ).with_request_body(json!({"body":format!("{RENOVATE_REBASE_MARKER}\nSecurefix is requesting this PR's one automatic Renovate rebase. Further failures require a manual Renovate rebase/retry.")})));
        routes.extend(renovate_state_routes(manifest, renovate_pr(manifest)));
        routes.push(Route::active_control(&manifest.control));
        routes.push(
            Route::request(
                "POST",
                format!("/repos/{repository}/issues/7/labels"),
                200,
                json!([{"name":"rebase"}]),
            )
            .with_request_body(json!({"labels":["rebase"]})),
        );
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
    fn successful_renovate_notification_posts_sha_and_run_without_rebasing_or_merging() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        let sha = "d".repeat(40);
        let run_url = "https://github.com/civitaspo/securefix-server/actions/runs/42";
        for status in [201, 403] {
            let fixture = Fixture::new(vec![
                Route::get("/repos/civitaspo/dbt-authorized-models/issues/7/comments?per_page=100&page=1", json!([])),
                Route::active_control(&Fixture::control_revision()),
                Route::request("POST", "/repos/civitaspo/dbt-authorized-models/issues/7/comments", status, json!({}))
                    .with_request_body(json!({"body":format!(
                        "<!-- securefix-merge-request:4 -->\nSecurefix merged this pull request with squash at {sha}.\n\nServer run: {run_url}") })),
            ]);
            let result = notify_result(
                &fixture.api,
                &fixture.api,
                &policy,
                &manifest,
                "success",
                &sha,
                run_url,
            );
            assert_eq!(result.is_ok(), status == 201);
            fixture.finish();
        }
    }

    #[test]
    fn successful_notification_rejects_missing_sha_and_duplicate_receipts() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        for (comments, sha) in [
            (json!([]), "".to_owned()),
            (
                json!([{"user":{"id":288069019,"login":"civitaspo-securefix-server[bot]","type":"Bot"},
                "body":"<!-- securefix-merge-request:4 -->\nalready reported"}]),
                "d".repeat(40),
            ),
        ] {
            let fixture = Fixture::new(vec![Route::get(
                "/repos/civitaspo/dbt-authorized-models/issues/7/comments?per_page=100&page=1",
                comments,
            )]);
            assert!(
                notify_result(
                    &fixture.api,
                    &fixture.api,
                    &policy,
                    &manifest,
                    "success",
                    &sha,
                    "https://github.com/civitaspo/securefix-server/actions/runs/42"
                )
                .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn accepted_renovate_failure_records_pr_budget_and_adds_rebase_label_once() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        let mut routes = renovate_validation_routes(&manifest, renovate_pr(&manifest));
        append_rebase_success_routes(
            &mut routes,
            &manifest,
            json!([{"user":{"id":999,"login":"human","type":"User"},"body":RENOVATE_REBASE_MARKER}]),
            json!([]),
        );
        let fixture = Fixture::new(routes);
        assert!(request_renovate_rebase(&fixture.api, &fixture.api, &policy, &manifest).unwrap());
        fixture.finish();
    }

    #[test]
    fn replacement_head_and_command_do_not_reset_rebase_budget_for_pr() {
        let mut manifest = renovate_manifest();
        manifest.pull_request.head_sha = "d".repeat(40);
        manifest.authorization = Authorization::RenovateComment {
            comment_id: 91,
            updated_at: DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let policy = renovate_policy(&manifest);
        let mut routes = renovate_validation_routes(&manifest, renovate_pr(&manifest));
        routes.push(Route::get(
            "/repos/civitaspo/dbt-authorized-models/issues/7/comments?per_page=100&page=1",
            json!([{"user":{"id":crate::config::trusted().unwrap().server_bot_id,
                "login":crate::config::trusted().unwrap().deployment.server_bot_login,"type":"Bot"},
                "body":RENOVATE_REBASE_MARKER}]),
        ));
        let fixture = Fixture::new(routes);
        assert!(!request_renovate_rebase(&fixture.api, &fixture.api, &policy, &manifest).unwrap());
        fixture.finish();
    }

    #[test]
    fn preexisting_rebase_label_does_not_consume_another_budget() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        let mut routes = renovate_validation_routes(&manifest, renovate_pr(&manifest));
        routes.push(Route::get(
            "/repos/civitaspo/dbt-authorized-models/issues/7/comments?per_page=100&page=1",
            json!([]),
        ));
        let mut pr = renovate_pr(&manifest);
        pr["labels"] = json!([{"name":"rebase"}]);
        routes.push(Route::get(
            "/repos/civitaspo/dbt-authorized-models/pulls/7",
            pr,
        ));
        let fixture = Fixture::new(routes);
        assert!(!request_renovate_rebase(&fixture.api, &fixture.api, &policy, &manifest).unwrap());
        fixture.finish();
    }

    #[test]
    fn changed_head_is_rejected_before_any_rebase_write() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        let mut pr = renovate_pr(&manifest);
        pr["head"]["sha"] = json!("e".repeat(40));
        let routes = vec![
            Route::get(
                "/repos/civitaspo/dbt-authorized-models",
                json!({"id":1,"default_branch":"main"}),
            ),
            Route::get("/repos/civitaspo/dbt-authorized-models/pulls/7", pr),
        ];
        let fixture = Fixture::new(routes);
        assert!(request_renovate_rebase(&fixture.api, &fixture.api, &policy, &manifest).is_err());
        fixture.finish();
    }

    #[test]
    fn current_policy_without_merge_capability_rejects_rebase_before_api_access() {
        let manifest = renovate_manifest();
        let mut policy = renovate_policy(&manifest);
        policy
            .repositories
            .iter_mut()
            .find(|repository| repository.repository == manifest.repository.full_name)
            .unwrap()
            .capabilities
            .retain(|capability| *capability != Capability::Merge);
        let fixture = Fixture::new(vec![]);
        assert!(request_renovate_rebase(&fixture.api, &fixture.api, &policy, &manifest).is_err());
        fixture.finish();
    }

    #[test]
    fn signature_and_effective_committer_failures_never_write_rebase_marker() {
        let manifest = renovate_manifest();
        let policy = renovate_policy(&manifest);
        for (verified, committer) in [(false, "updater[bot]"), (true, "human")] {
            let mut routes = renovate_validation_routes(&manifest, renovate_pr(&manifest));
            routes[5] = Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/commits?per_page=100&page=1",
                json!([{
                    "sha":manifest.pull_request.head_sha,
                    "commit":{"verification":{"verified":verified}},
                    "author":{"id":43,"login":"updater[bot]","type":"Bot"},
                    "committer":{"id":43,"login":committer,"type":"Bot"}
                }]),
            );
            routes.truncate(6);
            let mut case_policy = policy.clone();
            if committer == "human" {
                case_policy.trusted_committers.push("human".into());
            }
            let fixture = Fixture::new(routes);
            assert!(
                request_renovate_rebase(&fixture.api, &fixture.api, &case_policy, &manifest)
                    .is_err()
            );
            fixture.finish();
        }
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
