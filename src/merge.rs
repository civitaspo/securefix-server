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
    let owner_comment_id = match &manifest.authorization {
        Authorization::OwnerComment { comment_id, .. } => *comment_id,
        _ => anyhow::bail!("merge requires an owner comment"),
    };
    if request::validate_pr_authorization(
        &api,
        &policy,
        repository,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        true,
    )? {
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
    output("owner_comment_id", owner_comment_id.to_string())?;
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
    request::validate_pr_authorization(
        &read,
        &policy,
        &manifest.repository.full_name,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        true,
    )?;
    {
        let write = GitHub::from_env("SECUREFIX_AUTHORIZATION_TOKEN")?;
        let Authorization::OwnerComment { comment_id, .. } = &manifest.authorization else {
            anyhow::bail!("merge authorization requires an owner comment")
        };
        request::post_owner_marker(
            &write,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
            *comment_id,
        )?;
        if request::has_current_head_approval(
            &read,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
        )? {
            crate::policy_check::publish(
                &write,
                &manifest.repository.full_name,
                &manifest.pull_request.head_sha,
                true,
                "Changes passed signature, owner authorization, and current-head review checks.",
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
    let deadline = manifest.accepted_at + chrono::Duration::seconds(MAX_WAIT_SECONDS);
    loop {
        validate_state(&api, &policy, &manifest)?;
        request::validate_pr_policy(
            &api,
            &policy,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
        )?;
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
    let write = GitHub::from_env("SECUREFIX_MERGE_TOKEN")?;
    let deadline = manifest.accepted_at + chrono::Duration::seconds(MAX_WAIT_SECONDS);
    loop {
        let policy = Policy::active(&read)?;
        ensure!(
            policy.revision == manifest.workflow_sha,
            "server policy revision changed before merge"
        );
        let source = request::load_source_request(
            &read,
            &policy,
            &manifest.repository.full_name,
            manifest.run_id,
            RequestKind::Merge,
        )?;
        ensure!(source == manifest, "source request changed before merge");
        validate_state(&read, &policy, &manifest)?;
        request::validate_pr_policy(
            &read,
            &policy,
            &manifest.repository.full_name,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
        )?;
        if !ready(&read, &manifest)? {
            sleep_until_retry(deadline)?;
            continue;
        }
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
        match write.put::<Value>(&format!("/repos/{}/pulls/{}/merge", manifest.repository.full_name, manifest.pull_request.number), &json!({
            "sha":manifest.pull_request.head_sha, "merge_method":"squash", "commit_message":message
        })) {
            Ok(result) => {
                ensure!(result["merged"] == true, "GitHub did not confirm the squash merge");
                let merge_sha = result["sha"].as_str().context("merge response has no SHA")?;
                ensure!(merge_sha.len() == 40 && merge_sha.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "merge response contains an invalid SHA");
                output("merge_sha", merge_sha)?;
                return Ok(());
            }
            Err(error) if retryable_merge_error(&error) => sleep_until_retry(deadline)?,
            Err(error) => return Err(error),
        }
    }
}

fn retryable_merge_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<securefix::api::ApiError>()
        .is_some_and(|api| matches!(api.status.as_u16(), 405 | 422 | 503))
}

fn sleep_until_retry(deadline: DateTime<Utc>) -> Result<()> {
    let remaining = deadline.signed_duration_since(Utc::now()).num_seconds();
    ensure!(
        remaining > 0,
        "GitHub did not accept the merge before the fixed 60-minute deadline"
    );
    thread::sleep(Duration::from_secs(remaining.min(30) as u64));
    Ok(())
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
    let Authorization::OwnerComment {
        comment_id,
        updated_at,
    } = &manifest.authorization
    else {
        anyhow::bail!("merge request lacks owner authorization")
    };
    let trusted = config::trusted()?;
    let comment: Value = api.get(&format!(
        "/repos/{}/issues/comments/{comment_id}",
        manifest.repository.full_name
    ))?;
    ensure!(
        RequestKind::Merge.matches_comment_body(&comment["body"])
            && request::matches_principal(
                &comment["user"],
                trusted.owner_id,
                &trusted.deployment.owner_login,
                "User",
            )
            && comment["issue_url"].as_str().is_some_and(
                |url| url.ends_with(&format!("/issues/{}", manifest.pull_request.number))
            )
            && comment["updated_at"]
                .as_str()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|v| v.with_timezone(&Utc))
                .as_ref()
                == updated_at.as_ref(),
        "owner merge comment was changed or removed"
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
    let policy_ok = policy_checks
        .first()
        .is_some_and(|check| exact_completed_success(check));
    let review = api.graphql("query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}", json!({
        "owner":repository.split('/').next().unwrap_or_default(), "name":repository.split('/').nth(1).unwrap_or_default(), "number":manifest.pull_request.number
    }))?;
    let approved = review["repository"]["pullRequest"]["reviewDecision"] == "APPROVED"
        && request::has_current_head_approval(
            api,
            repository,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
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
        let policy = Policy::load("tests/fixtures/policy.json")?;
        let result = validate_state(&fixture.api, &policy, &state_manifest());
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
            let policy = Policy::load("tests/fixtures/policy.json").unwrap();
            let result = validate_state(&fixture.api, &policy, &state_manifest());
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
