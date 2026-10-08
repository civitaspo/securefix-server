use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;

use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, SERVER, validate_repository, validate_sha},
    workflow::{self, ReferencedWorkflow, successful_source_run, write_json},
};

const OWNER_ID: u64 = 4_525_500;
const CLIENT_BOT_ID: u64 = 288_068_203;
const SERVER_BOT_ID: u64 = 288_069_019;
const ARTIFACT_PREFIX: &str = "securefix-request-";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestManifest {
    pub version: u32,
    pub kind: RequestKind,
    pub repository: RepositoryRef,
    pub pull_request: PullRequestRef,
    pub authorization: Authorization,
    pub accepted_at: DateTime<Utc>,
    pub run_id: u64,
    pub run_attempt: u32,
    pub workflow_sha: String,
    pub caller_workflow_sha: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RequestKind {
    Approve,
    Merge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Authorization {
    OwnerComment {
        comment_id: u64,
        updated_at: Option<DateTime<Utc>>,
    },
    Automatic {
        actor_id: u64,
        actor_login: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRef {
    pub id: u64,
    pub full_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestRef {
    pub number: u64,
    pub head_sha: String,
    pub base_ref: String,
}

impl RequestManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.run_id > 0 && self.run_attempt == 1,
            "invalid request version or attempt"
        );
        validate_repository(&self.repository.full_name)?;
        validate_sha(&self.pull_request.head_sha)?;
        validate_sha(&self.workflow_sha)?;
        validate_sha(&self.caller_workflow_sha)?;
        ensure!(
            self.repository.id > 0 && self.pull_request.number > 0,
            "invalid request identity"
        );
        ensure!(
            !self.pull_request.base_ref.is_empty() && self.pull_request.base_ref.len() <= 255,
            "invalid base branch"
        );
        match &self.authorization {
            Authorization::OwnerComment { comment_id, .. } => {
                ensure!(*comment_id > 0, "invalid owner comment ID")
            }
            Authorization::Automatic {
                actor_id,
                actor_login,
            } => ensure!(
                *actor_id > 0 && !actor_login.is_empty(),
                "invalid automatic authorization"
            ),
        }
        let age = Utc::now().signed_duration_since(self.accepted_at);
        ensure!(
            age.num_seconds() >= 0,
            "request acceptance time is in the future"
        );
        if self.kind == RequestKind::Merge {
            ensure!(age.num_minutes() < 60, "merge request has expired");
        }
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Command {
    CaptureApprove,
    CaptureMerge,
    Dispatch,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::CaptureApprove => capture(RequestKind::Approve),
        Command::CaptureMerge => capture(RequestKind::Merge),
        Command::Dispatch => dispatch(),
    }
}

fn capture(kind: RequestKind) -> Result<()> {
    let payload = event()?;
    let repo = std::env::var("GITHUB_REPOSITORY")?;
    validate_repository(&repo)?;
    let policy_api = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&policy_api)?;
    let repo_policy = policy.repository(&repo)?;
    repo_policy.require(match kind {
        RequestKind::Approve => Capability::Approve,
        RequestKind::Merge => Capability::Merge,
    })?;
    ensure!(
        policy.owner_id == OWNER_ID
            && policy.client_bot_id == CLIENT_BOT_ID
            && policy.server_bot_id == SERVER_BOT_ID,
        "unexpected principals"
    );
    let source_sha = std::env::var("SECUREFIX_SOURCE_SHA")?;
    ensure!(
        source_sha == policy.revision,
        "workflow runtime is not the current server revision"
    );
    let event_name = std::env::var("GITHUB_EVENT_NAME")?;
    let token = GitHub::from_env("GITHUB_TOKEN")?;
    let authorization = if event_name == "issue_comment" {
        ensure!(
            payload["issue"]["pull_request"].is_object(),
            "event is not a pull request issue comment"
        );
        ensure!(
            kind == RequestKind::Approve || kind == RequestKind::Merge,
            "unsupported owner request"
        );
        let comment = &payload["comment"];
        let expected = match kind {
            RequestKind::Approve => "/approve",
            RequestKind::Merge => "/merge",
        };
        ensure!(
            comment["body"] == expected
                && comment["user"]["id"] == OWNER_ID
                && comment["user"]["type"] == "User",
            "request comment is unauthorized"
        );
        let comment_id = comment["id"].as_u64().context("missing comment ID")?;
        let current_comment: Value =
            token.get(&format!("/repos/{repo}/issues/comments/{comment_id}"))?;
        ensure!(
            current_comment["body"] == expected
                && current_comment["user"]["id"] == OWNER_ID
                && current_comment["user"]["type"] == "User",
            "request comment changed during capture"
        );
        Authorization::OwnerComment {
            comment_id,
            updated_at: current_comment["updated_at"]
                .as_str()
                .map(DateTime::parse_from_rfc3339)
                .transpose()?
                .map(|v| v.with_timezone(&Utc)),
        }
    } else {
        ensure!(
            kind == RequestKind::Approve && event_name == "pull_request_target",
            "automatic approval is not permitted for this event"
        );
        let actor_id = payload["sender"]["id"]
            .as_u64()
            .context("missing actor ID")?;
        let actor_login = payload["sender"]["login"]
            .as_str()
            .context("missing actor login")?
            .to_owned();
        ensure!(
            policy
                .trusted_committers
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&actor_login)),
            "automatic approval actor is not trusted"
        );
        Authorization::Automatic {
            actor_id,
            actor_login,
        }
    };
    let number = if event_name == "pull_request_target" {
        payload["pull_request"]["number"]
            .as_u64()
            .context("missing pull request number")?
    } else {
        payload["issue"]["number"]
            .as_u64()
            .context("missing issue number")?
    };
    let repository: Value = token.get(&format!("/repos/{repo}"))?;
    let pr: Value = token.get(&format!("/repos/{repo}/pulls/{number}"))?;
    ensure!(
        repository["id"].as_u64() == payload["repository"]["id"].as_u64(),
        "repository identity changed"
    );
    ensure!(
        pr["state"] == "open"
            && pr["draft"] == false
            && pr["head"]["repo"]["full_name"] == repo
            && pr["base"]["ref"] == repository["default_branch"],
        "pull request must be same-repository, open, ready, and target the default branch"
    );
    let caller_workflow_sha = std::env::var("GITHUB_SHA")?;
    validate_sha(&caller_workflow_sha)?;
    if event_name == "pull_request_target" {
        ensure!(
            payload["pull_request"]["base"]["sha"] == caller_workflow_sha,
            "pull request base SHA differs from the workflow source"
        );
    }
    let manifest = RequestManifest {
        version: 1,
        kind,
        repository: RepositoryRef {
            id: repository["id"].as_u64().context("missing repository ID")?,
            full_name: repo.clone(),
        },
        pull_request: PullRequestRef {
            number,
            head_sha: pr["head"]["sha"]
                .as_str()
                .context("missing head SHA")?
                .to_owned(),
            base_ref: pr["base"]["ref"]
                .as_str()
                .context("missing base ref")?
                .to_owned(),
        },
        authorization,
        accepted_at: Utc::now(),
        run_id: std::env::var("GITHUB_RUN_ID")?.parse()?,
        run_attempt: std::env::var("GITHUB_RUN_ATTEMPT")?.parse()?,
        workflow_sha: source_sha,
        caller_workflow_sha,
    };
    manifest.validate()?;
    write_json("request/manifest.json", &manifest)?;
    output(
        "request_name",
        format!("{}{}", ARTIFACT_PREFIX, manifest.run_id),
    )?;
    output("request_run_id", manifest.run_id.to_string())?;
    output("repository", repo)?;
    output(
        "repository_name",
        manifest
            .repository
            .full_name
            .split('/')
            .nth(1)
            .unwrap_or_default(),
    )?;
    output("pull_number", manifest.pull_request.number.to_string())?;
    Ok(())
}

fn dispatch() -> Result<()> {
    let app = GitHub::from_env("SECUREFIX_APP_TOKEN")?;
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&read)?;
    let manifest: RequestManifest = serde_json::from_slice(&fs::read("request/manifest.json")?)?;
    manifest.validate()?;
    ensure!(
        manifest.workflow_sha == policy.revision,
        "request was captured by a stale server revision"
    );
    let repo_policy = policy.repository(&manifest.repository.full_name)?;
    repo_policy.require(match manifest.kind {
        RequestKind::Approve => Capability::Approve,
        RequestKind::Merge => Capability::Merge,
    })?;
    let label = format!(
        "{}{}",
        match manifest.kind {
            RequestKind::Approve => "approve-request-",
            RequestKind::Merge => "merge-request-",
        },
        manifest.run_id
    );
    let description = format!("{}/{}", manifest.repository.full_name, manifest.run_id);
    ensure!(
        label.len() <= 50 && description.len() <= 100,
        "request label exceeds GitHub limits"
    );
    let _: Value = app.post(
        &format!("/repos/{SERVER}/labels"),
        &json!({"name":label,"color":"1f6feb","description":description}),
    )?;
    output("label", label)?;
    Ok(())
}

pub fn load_source_request(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    run_id: u64,
    kind: RequestKind,
) -> Result<RequestManifest> {
    validate_repository(repository)?;
    ensure!(run_id > 0, "invalid source run ID");
    let current = Policy::latest_revision(api, ".github/workflows/ci.yml")?;
    ensure!(
        policy.revision == current,
        "policy/runtime revision is stale"
    );
    let run = successful_source_run(api, repository, run_id)?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"].as_u64() == Some(1)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && (run["event"] == "issue_comment"
                || (kind == RequestKind::Approve && run["event"] == "pull_request_target")),
        "source workflow run is not eligible"
    );
    let run_repository = run["repository"]["full_name"]
        .as_str()
        .unwrap_or(repository);
    ensure!(
        run_repository.eq_ignore_ascii_case(repository),
        "source run repository mismatch"
    );
    let caller_path = match kind {
        RequestKind::Approve => ".github/workflows/approve-request.yml",
        RequestKind::Merge => ".github/workflows/merge-request.yml",
    };
    ensure!(
        run["path"] == caller_path,
        "source run used an unexpected workflow"
    );
    let source_sha = run["head_sha"]
        .as_str()
        .context("source run has no source revision")?;
    validate_sha(source_sha)?;
    let source_repo: Value = api.get(&format!("/repos/{repository}"))?;
    let default_branch = source_repo["default_branch"]
        .as_str()
        .context("source default branch is missing")?;
    let refs: Vec<ReferencedWorkflow> = serde_json::from_value(run["referenced_workflows"].clone())
        .context("source run lacks reusable workflow provenance")?;
    let reusable_path = match kind {
        RequestKind::Approve => ".github/workflows/reusable-approve-request.yml",
        RequestKind::Merge => ".github/workflows/reusable-merge-request.yml",
    };
    workflow::referenced_revision(&refs, reusable_path, &policy.revision)?;

    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts"
    ))?;
    let name = format!("{ARTIFACT_PREFIX}{run_id}");
    let matches: Vec<_> = artifacts["artifacts"]
        .as_array()
        .context("source artifacts missing")?
        .iter()
        .filter(|a| a["name"] == name)
        .collect();
    ensure!(
        matches.len() == 1,
        "source request artifact is missing or duplicated"
    );
    let artifact = matches[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size <= 64 * 1024),
        "source request artifact is expired or oversized"
    );
    let artifact_id = artifact["id"].as_u64().context("artifact has no ID")?;
    let zip = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        64 * 1024,
    )?;
    let manifest: RequestManifest = workflow::manifest_from_zip(&zip)?;
    manifest.validate()?;
    ensure!(
        manifest.kind == kind
            && manifest
                .repository
                .full_name
                .eq_ignore_ascii_case(repository)
            && manifest.run_id == run_id
            && manifest.workflow_sha == policy.revision
            && manifest.pull_request.number > 0,
        "source request artifact does not match its run"
    );
    ensure!(
        manifest.repository.id
            == source_repo["id"]
                .as_u64()
                .context("source repository has no ID")?,
        "source repository ID mismatch"
    );
    if run["event"] == "issue_comment" {
        ensure!(
            run["head_branch"] == default_branch && manifest.caller_workflow_sha == source_sha,
            "comment workflow did not run from the default branch source SHA"
        );
    }
    let current_default: Value =
        api.get(&format!("/repos/{repository}/commits/{default_branch}"))?;
    let current_default_sha = current_default["sha"]
        .as_str()
        .context("source default branch has no SHA")?;
    let comparison: Value = api.get(&format!(
        "/repos/{repository}/compare/{}...{current_default_sha}",
        manifest.caller_workflow_sha
    ))?;
    ensure!(
        matches!(comparison["status"].as_str(), Some("ahead" | "identical")),
        "caller workflow SHA is not on default-branch history"
    );
    let wrapper = api.content(repository, caller_path, &manifest.caller_workflow_sha)?;
    require_exact_reusable_pin(&wrapper, kind, &policy.revision, repository == SERVER)?;
    let authorization_matches = match (
        &manifest.authorization,
        run["event"].as_str().unwrap_or_default(),
    ) {
        (
            Authorization::OwnerComment {
                comment_id,
                updated_at,
            },
            "issue_comment",
        ) => {
            let comment: Value =
                api.get(&format!("/repos/{repository}/issues/comments/{comment_id}"))?;
            comment["user"]["id"] == OWNER_ID
                && comment["user"]["type"] == "User"
                && comment["issue_url"].as_str().is_some_and(|url| {
                    url.ends_with(&format!("/issues/{}", manifest.pull_request.number))
                })
                && comment["body"]
                    == if kind == RequestKind::Approve {
                        "/approve"
                    } else {
                        "/merge"
                    }
                && comment["updated_at"]
                    .as_str()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.with_timezone(&Utc))
                    == *updated_at
        }
        (
            Authorization::Automatic {
                actor_id,
                actor_login,
            },
            "pull_request_target",
        ) => {
            run["actor"]["id"].as_u64() == Some(*actor_id)
                && run["actor"]["login"].as_str() == Some(actor_login.as_str())
                && policy
                    .trusted_committers
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(actor_login))
        }
        _ => false,
    };
    ensure!(
        authorization_matches,
        "source authorization does not match its triggering event"
    );
    if kind == RequestKind::Merge {
        let comments = api.paginate(&format!(
            "/repos/{repository}/issues/{}/comments",
            manifest.pull_request.number
        ))?;
        let receipt = format!("<!-- securefix-merge-request:{run_id} -->");
        ensure!(
            !comments.iter().any(|comment| comment["user"]["id"].as_u64()
                == Some(policy.server_bot_id)
                && comment["user"]["type"] == "Bot"
                && comment["body"]
                    .as_str()
                    .is_some_and(|body| body.lines().any(|line| line == receipt))),
            "source merge request already has a terminal receipt"
        );
    }
    Ok(manifest)
}

fn require_exact_reusable_pin(
    bytes: &[u8],
    kind: RequestKind,
    revision: &str,
    local: bool,
) -> Result<()> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_slice(bytes).context("caller workflow YAML is invalid")?;
    let reusable = match kind {
        RequestKind::Approve => ".github/workflows/reusable-approve-request.yml",
        RequestKind::Merge => ".github/workflows/reusable-merge-request.yml",
    };
    let expected = if local {
        format!("./{reusable}")
    } else {
        format!("{SERVER}/{reusable}@{revision}")
    };
    fn collect(value: &serde_yaml::Value, uses: &mut Vec<String>) {
        match value {
            serde_yaml::Value::Mapping(map) => {
                for (key, item) in map {
                    if key.as_str() == Some("uses")
                        && let Some(value) = item.as_str()
                    {
                        uses.push(value.to_owned());
                    }
                    collect(item, uses);
                }
            }
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    collect(item, uses);
                }
            }
            _ => {}
        }
    }
    let mut uses = Vec::new();
    collect(&yaml, &mut uses);
    let prefix = if local {
        format!("./{reusable}")
    } else {
        format!("{SERVER}/{reusable}@")
    };
    let calls: Vec<_> = uses
        .iter()
        .filter(|value| value.starts_with(&prefix))
        .collect();
    ensure!(
        calls.len() == 1 && calls[0].as_str() == expected,
        "caller workflow does not make one exact full-SHA reusable call"
    );
    Ok(())
}

pub fn validate_pr_policy(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    number: u64,
    sha: &str,
) -> Result<()> {
    validate_pr_authorization(api, policy, repository, number, sha, false)?;
    Ok(())
}

/// Returns true only when a non-author reviewer has an effective approval for this exact head.
/// The caller should still use branch protection's aggregate review decision as an additional gate.
pub fn has_current_head_approval(
    api: &GitHub,
    repository: &str,
    number: u64,
    sha: &str,
) -> Result<bool> {
    validate_repository(repository)?;
    validate_sha(sha)?;
    let pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    ensure!(
        pr["state"] == "open" && pr["head"]["sha"] == sha,
        "pull request changed while checking its review"
    );
    let author_id = pr["user"]["id"]
        .as_u64()
        .context("pull request author has no ID")?;
    let reviews = api.paginate(&format!("/repos/{repository}/pulls/{number}/reviews"))?;
    Ok(current_review_approval(&reviews, sha, author_id))
}

fn current_review_approval(reviews: &[Value], head_sha: &str, author_id: u64) -> bool {
    let mut latest = std::collections::HashMap::<u64, &Value>::new();
    for review in reviews.iter().filter(|review| {
        matches!(
            review["state"].as_str(),
            Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
        )
    }) {
        let Some(user_id) = review["user"]["id"].as_u64().filter(|id| *id != author_id) else {
            continue;
        };
        let replace = latest.get(&user_id).is_none_or(|previous| {
            (
                review["submitted_at"].as_str().unwrap_or_default(),
                review["id"].as_u64().unwrap_or_default(),
            ) > (
                previous["submitted_at"].as_str().unwrap_or_default(),
                previous["id"].as_u64().unwrap_or_default(),
            )
        });
        if replace {
            latest.insert(user_id, review);
        }
    }
    latest
        .values()
        .any(|review| review["state"] == "APPROVED" && review["commit_id"] == head_sha)
}

pub fn validate_pr_authorization(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    number: u64,
    sha: &str,
    owner_requested: bool,
) -> Result<bool> {
    validate_repository(repository)?;
    validate_sha(sha)?;
    let repo = policy.repository(repository)?;
    let pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    ensure!(
        pr["state"] == "open"
            && pr["head"]["repo"]["full_name"] == repository
            && pr["head"]["sha"] == sha,
        "pull request is not open at the authorized head"
    );
    let commits = api.paginate(&format!("/repos/{repository}/pulls/{number}/commits"))?;
    ensure!(
        !commits.is_empty()
            && commits.len() < 250
            && commits.last().and_then(|c| c["sha"].as_str()) == Some(sha),
        "commit list is incomplete or does not end at the current head"
    );
    ensure!(
        commits
            .iter()
            .all(|c| c["commit"]["verification"]["verified"] == true),
        "every commit must have a verified signature"
    );
    ensure!(
        commits
            .iter()
            .all(|c| repo_trusted_committer(c, &policy.trusted_committers)),
        "commit committer is not an allowed committer"
    );
    let files = api.paginate(&format!("/repos/{repository}/pulls/{number}/files"))?;
    ensure!(
        files.len() < 3000,
        "pull request file list is incomplete or exceeds the API limit"
    );
    let paths = files
        .iter()
        .flat_map(|f| [f["filename"].as_str(), f["previous_filename"].as_str()])
        .flatten()
        .collect::<Vec<_>>();
    let sensitive = repo.sensitive(paths.iter().copied())?;
    if sensitive && !owner_requested {
        require_owner_marker(api, policy, repository, number, sha)?;
    }
    Ok(sensitive)
}

fn repo_trusted_committer(commit: &Value, trusted: &[String]) -> bool {
    commit["committer"]["login"]
        .as_str()
        .or_else(|| commit["author"]["login"].as_str())
        .is_some_and(|login| {
            trusted
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(login))
        })
}

pub fn require_owner_marker(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    number: u64,
    head_sha: &str,
) -> Result<()> {
    validate_repository(repository)?;
    validate_sha(head_sha)?;
    let comments = api.paginate(&format!("/repos/{repository}/issues/{number}/comments"))?;
    let prefix = format!("<!-- securefix:v2:owner:{head_sha}:");
    ensure!(
        comments.iter().any(|comment| {
            comment["user"]["id"].as_u64() == Some(policy.server_bot_id)
                && comment["user"]["type"] == "Bot"
                && comment["body"].as_str().is_some_and(|body| {
                    body.lines().any(|line| {
                        line.starts_with(&prefix)
                            && line.ends_with(" -->")
                            && line[prefix.len()..line.len() - 4]
                                .bytes()
                                .all(|b| b.is_ascii_digit())
                    })
                })
        }),
        "owner authorization for this exact pull request head is missing"
    );
    Ok(())
}

pub fn post_owner_marker(
    api: &GitHub,
    repository: &str,
    number: u64,
    head_sha: &str,
    comment_id: u64,
) -> Result<()> {
    validate_repository(repository)?;
    validate_sha(head_sha)?;
    ensure!(comment_id > 0, "invalid owner comment ID");
    let marker = format!("<!-- securefix:v2:owner:{head_sha}:{comment_id} -->");
    let _: Value = api.post(
        &format!("/repos/{repository}/issues/{number}/comments"),
        &json!({"body":marker}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};
    fn manifest() -> RequestManifest {
        RequestManifest {
            version: 1,
            kind: RequestKind::Merge,
            repository: RepositoryRef {
                id: 1,
                full_name: "civitaspo/example".into(),
            },
            pull_request: PullRequestRef {
                number: 2,
                head_sha: "a".repeat(40),
                base_ref: "main".into(),
            },
            authorization: Authorization::OwnerComment {
                comment_id: 3,
                updated_at: None,
            },
            accepted_at: Utc::now(),
            run_id: 4,
            run_attempt: 1,
            workflow_sha: "b".repeat(40),
            caller_workflow_sha: "c".repeat(40),
        }
    }

    fn source_run_fixture(run: Value) -> (Fixture, Policy) {
        let revision = "b".repeat(40);
        let mut policy = Policy::load("policy.json").unwrap();
        policy.revision = revision.clone();
        let fixture = Fixture::new(vec![
            Route::get(
                "/repos/civitaspo/securefix-server",
                json!({"default_branch":"main"}),
            ),
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                json!({"sha":revision}),
            ),
            Route::get("/repos/civitaspo/example/actions/runs/4", run),
        ]);
        (fixture, policy)
    }

    fn run_metadata() -> Value {
        json!({"id":4,"run_attempt":1,"status":"completed","conclusion":"success",
            "event":"issue_comment","path":".github/workflows/merge-request.yml",
            "head_sha":"cccccccccccccccccccccccccccccccccccccccc",
            "repository":{"full_name":"civitaspo/example"}})
    }

    #[test]
    fn source_provenance_rejects_wrong_workflow_event_and_attempt_before_artifact_fetch() {
        let mut wrong_path = run_metadata();
        wrong_path["path"] = json!(".github/workflows/untrusted.yml");
        let mut wrong_event = run_metadata();
        wrong_event["event"] = json!("workflow_dispatch");
        let mut retry = run_metadata();
        retry["run_attempt"] = json!(2);
        for run in [wrong_path, wrong_event, retry] {
            let (fixture, policy) = source_run_fixture(run);
            assert!(
                load_source_request(
                    &fixture.api,
                    &policy,
                    "civitaspo/example",
                    4,
                    RequestKind::Merge
                )
                .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn source_provenance_waits_for_completion_then_rejects_failed_run() {
        let mut running = run_metadata();
        running["status"] = json!("in_progress");
        let mut failed = run_metadata();
        failed["conclusion"] = json!("failure");
        let revision = "b".repeat(40);
        let mut policy = Policy::load("policy.json").unwrap();
        policy.revision = revision.clone();
        let fixture = Fixture::new(vec![
            Route::get(
                "/repos/civitaspo/securefix-server",
                json!({"default_branch":"main"}),
            ),
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                json!({"sha":revision}),
            ),
            Route::get("/repos/civitaspo/example/actions/runs/4", running),
            Route::get("/repos/civitaspo/example/actions/runs/4", failed),
        ]);
        assert!(
            load_source_request(
                &fixture.api,
                &policy,
                "civitaspo/example",
                4,
                RequestKind::Merge
            )
            .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn request_manifest_rejects_replays_expiry_and_malformed_ids() {
        assert!(manifest().validate().is_ok());
        let mut stale = manifest();
        stale.accepted_at = Utc::now() - chrono::Duration::hours(1);
        assert!(stale.validate().is_err());
        let mut automatic = manifest();
        automatic.authorization = Authorization::Automatic {
            actor_id: CLIENT_BOT_ID,
            actor_login: "civitaspo-securefix-server[bot]".into(),
        };
        assert!(automatic.validate().is_ok());
        let mut retry = manifest();
        retry.run_attempt = 2;
        assert!(retry.validate().is_err());
    }

    #[test]
    fn authorization_rejects_untrusted_committer_even_when_author_is_trusted() {
        let policy = Policy::load("policy.json").unwrap();
        let sha = "a".repeat(40);
        let commit = json!({"sha":sha,"commit":{"verification":{"verified":true}},
            "author":{"login":"civitaspo"},"committer":{"login":"attacker"}});
        let routes = vec![
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7",
                json!({
                    "state":"open","head":{"repo":{"full_name":"civitaspo/dbt-authorized-models"},"sha":sha}
                }),
            ),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/commits?per_page=100&page=1",
                json!([commit]),
            ),
        ];
        let fixture = Fixture::new(routes);
        assert!(
            validate_pr_authorization(
                &fixture.api,
                &policy,
                "civitaspo/dbt-authorized-models",
                7,
                &sha,
                false
            )
            .is_err()
        );
        fixture.finish();
    }

    fn authorization_route(sha: &str) -> Route {
        Route::get(
            "/repos/civitaspo/dbt-authorized-models/pulls/7",
            json!({"state":"open","head":{"repo":{"full_name":"civitaspo/dbt-authorized-models"},"sha":sha}}),
        )
    }

    fn valid_commit(sha: &str) -> Value {
        json!({"sha":sha,"commit":{"verification":{"verified":true}},
            "author":{"login":"civitaspo"},"committer":{"login":"civitaspo"}})
    }

    #[test]
    fn authorization_rejects_a_head_that_changed_after_capture() {
        let policy = Policy::load("policy.json").unwrap();
        let accepted = "a".repeat(40);
        let current = "b".repeat(40);
        let fixture = Fixture::new(vec![Route::get(
            "/repos/civitaspo/dbt-authorized-models/pulls/7",
            json!({"state":"open","head":{"repo":{"full_name":"civitaspo/dbt-authorized-models"},"sha":current}}),
        )]);
        assert!(
            validate_pr_authorization(
                &fixture.api,
                &policy,
                "civitaspo/dbt-authorized-models",
                7,
                &accepted,
                false
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn authorization_rejects_an_unsigned_parent_commit() {
        let policy = Policy::load("policy.json").unwrap();
        let sha = "a".repeat(40);
        let mut parent = valid_commit(&"b".repeat(40));
        parent["commit"]["verification"]["verified"] = json!(false);
        let fixture = Fixture::new(vec![
            authorization_route(&sha),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/commits?per_page=100&page=1",
                json!([parent, valid_commit(&sha)]),
            ),
        ]);
        assert!(
            validate_pr_authorization(
                &fixture.api,
                &policy,
                "civitaspo/dbt-authorized-models",
                7,
                &sha,
                false
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn authorization_rejects_an_empty_commit_list() {
        let policy = Policy::load("policy.json").unwrap();
        let sha = "a".repeat(40);
        let fixture = Fixture::new(vec![
            authorization_route(&sha),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/commits?per_page=100&page=1",
                json!([]),
            ),
        ]);
        assert!(
            validate_pr_authorization(
                &fixture.api,
                &policy,
                "civitaspo/dbt-authorized-models",
                7,
                &sha,
                false
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn rename_out_of_sensitive_path_still_requires_owner_marker() {
        let policy = Policy::load("policy.json").unwrap();
        let sha = "a".repeat(40);
        let fixture = Fixture::new(vec![
            authorization_route(&sha),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/commits?per_page=100&page=1",
                json!([valid_commit(&sha)]),
            ),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/pulls/7/files?per_page=100&page=1",
                json!([{"filename":"README.md","previous_filename":".github/workflows/ci.yml"}]),
            ),
            Route::get(
                "/repos/civitaspo/dbt-authorized-models/issues/7/comments?per_page=100&page=1",
                json!([]),
            ),
        ]);
        assert!(
            validate_pr_authorization(
                &fixture.api,
                &policy,
                "civitaspo/dbt-authorized-models",
                7,
                &sha,
                false
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn owner_marker_must_be_from_server_bot_and_match_the_exact_head() {
        let policy = Policy::load("policy.json").unwrap();
        let head = "a".repeat(40);
        let wrong_head = "b".repeat(40);
        let cases = [
            json!({"user":{"id":SERVER_BOT_ID,"type":"Bot"},"body":format!("<!-- securefix:v2:owner:{wrong_head}:12 -->")}),
            json!({"user":{"id":CLIENT_BOT_ID,"type":"Bot"},"body":format!("<!-- securefix:v2:owner:{head}:12 -->")}),
            json!({"user":{"id":SERVER_BOT_ID,"type":"User"},"body":format!("<!-- securefix:v2:owner:{head}:12 -->")}),
        ];
        for comment in cases {
            let fixture = Fixture::new(vec![Route::get(
                "/repos/civitaspo/example/issues/7/comments?per_page=100&page=1",
                json!([comment]),
            )]);
            assert!(
                require_owner_marker(&fixture.api, &policy, "civitaspo/example", 7, &head).is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn trusted_committer_is_used_in_preference_to_trusted_author() {
        let commit = json!({"author":{"login":"trusted"},"committer":{"login":"untrusted"}});
        assert!(!repo_trusted_committer(&commit, &["trusted".into()]));
        let missing_committer = json!({"author":{"login":"trusted"},"committer":{}});
        assert!(repo_trusted_committer(
            &missing_committer,
            &["TRUSTED".into()]
        ));
    }

    #[test]
    fn old_head_approval_and_author_self_approval_do_not_authorize_new_head() {
        let old = "a".repeat(40);
        let new = "b".repeat(40);
        let reviews = vec![
            json!({"id":1,"user":{"id":9},"state":"APPROVED","commit_id":old,"submitted_at":"2026-01-01T00:00:00Z"}),
        ];
        assert!(!current_review_approval(&reviews, &new, 1));
        let author_only = vec![
            json!({"id":2,"user":{"id":1},"state":"APPROVED","commit_id":new,"submitted_at":"2026-01-01T00:00:00Z"}),
        ];
        assert!(!current_review_approval(&author_only, &new, 1));
        let current = vec![
            json!({"id":3,"user":{"id":9},"state":"APPROVED","commit_id":new,"submitted_at":"2026-01-02T00:00:00Z"}),
        ];
        assert!(current_review_approval(&current, &new, 1));
    }

    #[test]
    fn a_later_change_request_cancels_that_reviewers_earlier_approval() {
        let head = "b".repeat(40);
        let reviews = vec![
            json!({"id":1,"user":{"id":9},"state":"APPROVED","commit_id":head,"submitted_at":"2026-01-01T00:00:00Z"}),
            json!({"id":2,"user":{"id":9},"state":"CHANGES_REQUESTED","commit_id":head,"submitted_at":"2026-01-02T00:00:00Z"}),
        ];
        assert!(!current_review_approval(&reviews, &head, 1));
    }
}
