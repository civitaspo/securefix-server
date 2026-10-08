use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, SERVER, validate_repository, validate_sha},
    workflow,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;

const WRAPPER: &str = ".github/workflows/policy-check.yml";
const REUSABLE: &str = ".github/workflows/reusable-policy-check.yml";
const CHECK: &str = "securefix-policy-check";
const APP_ID: u64 = 3872533;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    repository: String,
    repository_id: u64,
    target: Target,
    run_id: u64,
    run_attempt: u32,
    source_sha: String,
    accepted_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Target {
    PullRequest {
        number: u64,
        head_sha: String,
        base_ref: String,
    },
    DefaultBranch {
        head_sha: String,
        branch: String,
    },
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.repository_id > 0 && self.run_id > 0 && self.run_attempt == 1,
            "invalid policy request identity"
        );
        validate_repository(&self.repository)?;
        validate_sha(&self.source_sha)?;
        let age = Utc::now() - self.accepted_at;
        ensure!(
            age >= chrono::Duration::zero() && age < chrono::Duration::hours(1),
            "policy request expired"
        );
        match &self.target {
            Target::PullRequest {
                number,
                head_sha,
                base_ref,
            } => {
                ensure!(*number > 0 && !base_ref.is_empty(), "invalid PR target");
                validate_sha(head_sha)?;
            }
            Target::DefaultBranch { head_sha, branch } => {
                validate_sha(head_sha)?;
                ensure!(!branch.is_empty(), "invalid default branch");
            }
        }
        Ok(())
    }
    fn sha(&self) -> &str {
        match &self.target {
            Target::PullRequest { head_sha, .. } | Target::DefaultBranch { head_sha, .. } => {
                head_sha
            }
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    Capture,
    Dispatch,
    Locate,
    Validate,
    Apply,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Capture => capture(),
        Command::Dispatch => dispatch(),
        Command::Locate => locate(),
        Command::Validate => validate(),
        Command::Apply => apply(),
        Command::Cleanup => cleanup(),
    }
}

fn capture() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let payload = event()?;
    let repository = std::env::var("GITHUB_REPOSITORY")?;
    let policy = Policy::active(&api)?;
    policy.repository(&repository)?.require(Capability::Merge)?;
    let source_sha = workflow::require_current_runtime(&api, REUSABLE)?;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["id"] == payload["repository"]["id"] && repo["owner"]["id"] == policy.owner_id,
        "policy request repository mismatch"
    );
    let branch = repo["default_branch"]
        .as_str()
        .context("missing default branch")?;
    let target = match std::env::var("GITHUB_EVENT_NAME")?.as_str() {
        "pull_request_target" => {
            let number = payload["pull_request"]["number"]
                .as_u64()
                .context("missing PR number")?;
            let pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
            ensure!(
                pr["state"] == "open"
                    && pr["head"]["sha"] == payload["pull_request"]["head"]["sha"]
                    && pr["base"]["ref"] == branch,
                "PR changed before policy capture"
            );
            Target::PullRequest {
                number,
                head_sha: pr["head"]["sha"]
                    .as_str()
                    .context("missing PR head")?
                    .into(),
                base_ref: branch.into(),
            }
        }
        "push" => {
            ensure!(
                payload["ref"] == format!("refs/heads/{branch}") && payload["deleted"] == false,
                "policy push is not to the default branch"
            );
            Target::DefaultBranch {
                head_sha: payload["after"]
                    .as_str()
                    .context("missing push SHA")?
                    .into(),
                branch: branch.into(),
            }
        }
        _ => anyhow::bail!("unsupported policy request event"),
    };
    let manifest = Manifest {
        version: 1,
        repository,
        repository_id: repo["id"].as_u64().context("missing repo ID")?,
        target,
        run_id: std::env::var("GITHUB_RUN_ID")?.parse()?,
        run_attempt: std::env::var("GITHUB_RUN_ATTEMPT")?.parse()?,
        source_sha,
        accepted_at: Utc::now(),
    };
    manifest.validate()?;
    workflow::write_json("policy-request/manifest.json", &manifest)?;
    output(
        "artifact_name",
        format!("securefix-policy-request-{}", manifest.run_id),
    )
}

fn dispatch() -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(&fs::read("policy-request/manifest.json")?)?;
    manifest.validate()?;
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&read)?;
    ensure!(
        policy.revision == manifest.source_sha,
        "policy request runtime is stale"
    );
    policy
        .repository(&manifest.repository)?
        .require(Capability::Merge)?;
    let api = GitHub::from_env("SECUREFIX_APP_TOKEN")?;
    let _: Value = api.post(&format!("/repos/{SERVER}/labels"), &json!({"name":format!("policy-request-{}",manifest.run_id),"description":format!("{}/{}",manifest.repository,manifest.run_id),"color":"1f6feb"}))?;
    Ok(())
}

fn label(policy: &Policy) -> Result<(String, u64)> {
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == SERVER
            && std::env::var("GITHUB_EVENT_NAME")? == "label"
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1",
        "policy processor must be a first-attempt server label run"
    );
    let payload = event()?;
    ensure!(
        payload["action"] == "created"
            && payload["sender"]["id"] == policy.client_bot_id
            && payload["sender"]["type"] == "Bot",
        "unauthorized policy request sender"
    );
    let id: u64 = payload["label"]["name"]
        .as_str()
        .context("missing policy label")?
        .strip_prefix("policy-request-")
        .context("invalid policy label")?
        .parse()?;
    let (repository, run) = payload["label"]["description"]
        .as_str()
        .context("missing policy locator")?
        .rsplit_once('/')
        .context("invalid policy locator")?;
    ensure!(
        id > 0 && run.parse::<u64>()? == id,
        "policy locator mismatch"
    );
    validate_repository(repository)?;
    policy.repository(repository)?.require(Capability::Merge)?;
    Ok((repository.into(), id))
}

fn locate() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&api)?;
    workflow::require_current_runtime(&api, WRAPPER)?;
    let (repository, _) = label(&policy)?;
    output(
        "repository_name",
        repository.split('/').nth(1).context("invalid repository")?,
    )
}

fn source(api: &GitHub, policy: &Policy) -> Result<Manifest> {
    let (repository, run_id) = label(policy)?;
    let run = workflow::successful_source_run(api, &repository, run_id)?;
    ensure!(
        run["path"] == WRAPPER && run["head_repository"]["full_name"] == repository,
        "policy source run is not a successful default workflow"
    );
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["owner"]["id"] == policy.owner_id
            && run["repository"]["id"] == repo["id"]
            && run["head_repository"]["id"] == repo["id"],
        "policy source repository changed"
    );
    let caller_sha = run["head_sha"].as_str().context("missing caller SHA")?;
    validate_sha(caller_sha)?;
    let branch = repo["default_branch"]
        .as_str()
        .context("missing default branch")?;
    let base: Value = api.get(&format!("/repos/{repository}/commits/{branch}"))?;
    let current_base = base["sha"].as_str().context("missing default SHA")?;
    let compare: Value = api.get(&format!(
        "/repos/{repository}/compare/{caller_sha}...{current_base}"
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "policy caller is not from default branch history"
    );
    let wrapper = api.content(&repository, WRAPPER, caller_sha)?;
    if repository != SERVER {
        workflow::require_reusable_pin(&wrapper, REUSABLE, &policy.revision)?;
        let referenced: Vec<workflow::ReferencedWorkflow> =
            serde_json::from_value(run["referenced_workflows"].clone())?;
        workflow::referenced_revision(&referenced, REUSABLE, &policy.revision)?;
    } else {
        ensure!(
            caller_sha == policy.revision,
            "server policy workflow source is stale"
        );
    }
    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    let name = format!("securefix-policy-request-{run_id}");
    let matching: Vec<_> = artifacts["artifacts"]
        .as_array()
        .context("missing policy artifacts")?
        .iter()
        .filter(|a| a["name"] == name)
        .collect();
    ensure!(
        matching.len() == 1
            && matching[0]["expired"] == false
            && matching[0]["size_in_bytes"]
                .as_u64()
                .is_some_and(|s| s <= 65536),
        "invalid policy artifact"
    );
    let id = matching[0]["id"]
        .as_u64()
        .context("missing policy artifact ID")?;
    let bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{id}/zip"),
        65536,
    )?;
    let manifest: Manifest = workflow::manifest_from_zip(&bytes)?;
    manifest.validate()?;
    ensure!(
        manifest.repository == repository
            && manifest.repository_id == repo["id"].as_u64().context("missing repo ID")?
            && manifest.run_id == run_id
            && manifest.source_sha == policy.revision,
        "policy manifest is not bound to its source"
    );
    match &manifest.target {
        Target::PullRequest { base_ref, .. } => ensure!(
            run["event"] == "pull_request_target" && base_ref == branch,
            "invalid policy PR event"
        ),
        Target::DefaultBranch {
            head_sha,
            branch: request_branch,
        } => ensure!(
            run["event"] == "push"
                && head_sha == caller_sha
                && request_branch == branch
                && head_sha == current_base,
            "default branch policy head changed"
        ),
    }
    Ok(manifest)
}

fn validate() -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    workflow::require_current_runtime(&api, WRAPPER)?;
    let manifest = source(&api, &policy)?;
    workflow::write_json("policy-check/manifest.json", &manifest)?;
    output(
        "repository_name",
        manifest
            .repository
            .split('/')
            .nth(1)
            .context("invalid repository")?,
    )
}

fn apply() -> Result<()> {
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    workflow::require_current_runtime(&read, WRAPPER)?;
    let manifest = source(&read, &policy)?;
    let result: Result<()> = (|| match &manifest.target {
        Target::PullRequest {
            number,
            head_sha,
            base_ref,
        } => {
            require_current_target(&read, &manifest.repository, *number, head_sha, base_ref)?;
            crate::request::validate_pr_policy(
                &read,
                &policy,
                &manifest.repository,
                *number,
                head_sha,
            )?;
            ensure!(
                crate::request::has_current_head_approval(
                    &read,
                    &manifest.repository,
                    *number,
                    head_sha
                )?,
                "approval for the current PR head is missing"
            );
            Ok(())
        }
        Target::DefaultBranch { .. } => Ok(()),
    })();
    let success = result.is_ok();
    let summary = result
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_else(|| "Current head passed the active Securefix policy.".into());
    let write = GitHub::from_env("SECUREFIX_WRITE_TOKEN")?;
    workflow::require_current_runtime(&read, WRAPPER)?;
    publish(
        &write,
        &manifest.repository,
        manifest.sha(),
        success,
        &summary,
    )?;
    Ok(())
}

pub fn publish(
    api: &GitHub,
    repository: &str,
    sha: &str,
    success: bool,
    summary: &str,
) -> Result<()> {
    validate_repository(repository)?;
    validate_sha(sha)?;
    let value: Value = api.get(&format!(
        "/repos/{repository}/commits/{sha}/check-runs?per_page=100&filter=latest"
    ))?;
    let matches: Vec<_> = value["check_runs"]
        .as_array()
        .context("missing check runs")?
        .iter()
        .filter(|c| c["name"] == CHECK && c["app"]["id"] == APP_ID)
        .collect();
    ensure!(matches.len() <= 1, "duplicate policy check source");
    let body = json!({"name":CHECK,"head_sha":sha,"status":"completed","conclusion":if success {"success"} else {"failure"},"output":{"title":if success {"Policy accepted"} else {"Policy rejected"},"summary":summary}});
    if let Some(existing) = matches.first() {
        let id = existing["id"].as_u64().context("missing check ID")?;
        let mut update = body.clone();
        update
            .as_object_mut()
            .context("invalid check body")?
            .remove("head_sha");
        let _: Value = api.patch(&format!("/repos/{repository}/check-runs/{id}"), &update)?;
    } else {
        let _: Value = api.post(&format!("/repos/{repository}/check-runs"), &body)?;
    }
    Ok(())
}

fn cleanup() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&api)?;
    let (_, id) = label(&policy)?;
    if let Err(error) = api.delete(&format!("/repos/{SERVER}/labels/policy-request-{id}")) {
        ensure!(
            error
                .downcast_ref::<securefix::api::ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND),
            "policy label cleanup failed"
        );
    }
    Ok(())
}

fn require_current_target(
    api: &GitHub,
    repository: &str,
    number: u64,
    sha: &str,
    base: &str,
) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    ensure!(
        pr["state"] == "open"
            && pr["head"]["sha"] == sha
            && pr["base"]["repo"]["full_name"] == repository
            && pr["base"]["ref"] == base
            && repo["default_branch"] == base,
        "policy target is closed, retargeted, or has a different head"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

    #[test]
    fn policy_target_rejects_same_head_retargeting_and_head_changes() {
        for (head, base, state, accepted) in [
            ("a".repeat(40), "main", "open", true),
            ("b".repeat(40), "main", "open", false),
            ("a".repeat(40), "release/next", "open", false),
            ("a".repeat(40), "main", "closed", false),
        ] {
            let fixture = Fixture::new(vec![
                Route::get("/repos/civitaspo/example", json!({"default_branch":"main"})),
                Route::get(
                    "/repos/civitaspo/example/pulls/7",
                    json!({"state":state,"head":{"sha":head},"base":{"ref":base,"repo":{"full_name":"civitaspo/example"}}}),
                ),
            ]);
            assert_eq!(
                require_current_target(
                    &fixture.api,
                    "civitaspo/example",
                    7,
                    &"a".repeat(40),
                    "main"
                )
                .is_ok(),
                accepted
            );
            fixture.finish();
        }
    }

    #[test]
    fn policy_check_updates_its_own_app_check_and_ignores_other_apps() {
        let sha = "a".repeat(40);
        let check_path =
            format!("/repos/civitaspo/example/commits/{sha}/check-runs?per_page=100&filter=latest");
        let body = json!({"name":CHECK,"status":"completed","conclusion":"failure","output":{"title":"Policy rejected","summary":"Changed head"}});
        let fixture = Fixture::new(vec![
            Route::get(
                check_path,
                json!({"check_runs":[{"id":17,"name":CHECK,"app":{"id":APP_ID}},{"id":18,"name":CHECK,"app":{"id":99}}]}),
            ),
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                json!({"sha":sha}),
            ),
            Route::request(
                "PATCH",
                "/repos/civitaspo/example/check-runs/17",
                200,
                json!({}),
            )
            .with_request_body(body),
        ]);
        publish(
            &fixture.api,
            "civitaspo/example",
            &sha,
            false,
            "Changed head",
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn duplicate_policy_checks_are_rejected_without_writing() {
        let sha = "a".repeat(40);
        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/civitaspo/example/commits/{sha}/check-runs?per_page=100&filter=latest"),
            json!({"check_runs":[{"id":17,"name":CHECK,"app":{"id":APP_ID}},{"id":18,"name":CHECK,"app":{"id":APP_ID}}]}),
        )]);
        assert!(publish(&fixture.api, "civitaspo/example", &sha, true, "Accepted").is_err());
        fixture.finish();
    }
    #[test]
    fn head_and_source_are_immutable_manifest_fields() {
        let mut manifest = Manifest {
            version: 1,
            repository: "civitaspo/securefix-server".into(),
            repository_id: 1,
            target: Target::PullRequest {
                number: 1,
                head_sha: "a".repeat(40),
                base_ref: "main".into(),
            },
            run_id: 1,
            run_attempt: 1,
            source_sha: "b".repeat(40),
            accepted_at: Utc::now(),
        };
        assert!(manifest.validate().is_ok());
        manifest.run_attempt = 2;
        assert!(manifest.validate().is_err());
        manifest.run_attempt = 1;
        manifest.accepted_at -= chrono::Duration::hours(1);
        assert!(manifest.validate().is_err());
    }
}
