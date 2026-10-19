use crate::config;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, validate_repository, validate_sha},
    workflow,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;

const WRAPPER: &str = ".github/workflows/policy-check.yml";
const REUSABLE: &str = ".github/workflows/reusable-policy-check.yml";
const CHECK: &str = "securefix-policy-check";
pub(crate) const COMMENT_MARKER: &str = securefix::api::POLICY_FAILURE_COMMENT_MARKER;

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
    control: securefix::control::ControlRevision,
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
        #[serde(default)]
        publisher_run_id: Option<u64>,
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
        self.control.validate()?;
        ensure!(
            self.source_sha == self.control.source_sha,
            "policy runtime source differs from its control revision"
        );
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
            Target::DefaultBranch {
                head_sha,
                branch,
                publisher_run_id,
            } => {
                validate_sha(head_sha)?;
                ensure!(
                    !branch.is_empty() && publisher_run_id.is_none_or(|id| id > 0),
                    "invalid default branch target"
                );
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

pub(crate) fn validate_testing_capture(
    bytes: &[u8],
    repository: &str,
    repository_id: u64,
    source: &str,
    control: &str,
    run_id: u64,
) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    manifest.validate()?;
    ensure!(
        manifest.repository == repository
            && manifest.repository_id == repository_id
            && manifest.source_sha == source
            && manifest.control.identity()? == control
            && manifest.run_id == run_id,
        "testing policy capture differs from the qualified runtime or client run"
    );
    Ok(())
}

#[derive(Subcommand)]
pub enum Command {
    Capture,
    Dispatch,
    Locate,
    Validate,
    Apply,
    /// Candidate sandbox: process a host-relayed policy run with test-only credentials.
    ApplyForTesting {
        #[arg(long)]
        source_run_id: u64,
    },
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Capture => capture(),
        Command::Dispatch => dispatch(),
        Command::Locate => locate(),
        Command::Validate => validate(),
        Command::Apply => apply(None),
        Command::ApplyForTesting { source_run_id } => apply(Some(source_run_id)),
        Command::Cleanup => cleanup(),
    }
}

fn capture() -> Result<()> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let payload = event()?;
    let repository = std::env::var("GITHUB_REPOSITORY")?;
    let policy = Policy::active(&api)?;
    policy.repository(&repository)?.require(Capability::Merge)?;
    let source_sha = workflow::require_current_runtime(&api, REUSABLE)?;
    let control = policy
        .control
        .clone()
        .context("active control revision is missing")?;
    securefix::control::ControlRevision::require_current(&api, &control)?;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["id"] == payload["repository"]["id"]
            && repo["owner"]["id"] == deployment.repository_owner.id
            && repo["owner"]["login"].as_str().is_some_and(|login| {
                login.eq_ignore_ascii_case(&deployment.repository_owner.login)
            }),
        "policy request repository mismatch"
    );
    if repository == server {
        ensure!(
            repo["id"].as_u64() == Some(deployment.server.id),
            "server repository identity differs from trusted deployment config"
        );
    }
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
                repository != server
                    && payload["ref"] == format!("refs/heads/{branch}")
                    && payload["deleted"] == false,
                "policy push is not an allowed caller default-branch update"
            );
            Target::DefaultBranch {
                head_sha: payload["after"]
                    .as_str()
                    .context("missing push SHA")?
                    .to_owned(),
                branch: branch.to_owned(),
                publisher_run_id: None,
            }
        }
        "workflow_run" => {
            let publisher_run_id = payload["workflow_run"]["id"]
                .as_u64()
                .context("missing publisher run ID")?;
            ensure!(
                std::env::var("GITHUB_REPOSITORY")? == server
                    && branch == deployment.server.default_branch,
                "published runtime policy check must target the server default branch"
            );
            let promotion =
                crate::distribution::validate_promotion(&api, &policy, publisher_run_id)?;
            ensure!(
                promotion.source_sha == payload["workflow_run"]["head_sha"],
                "policy check publisher SHA mismatch"
            );
            Target::DefaultBranch {
                head_sha: promotion.source_sha,
                branch: branch.into(),
                publisher_run_id: Some(publisher_run_id),
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
        control,
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
    let server = config::trusted()?.deployment.server.repository.clone();
    let manifest: Manifest = serde_json::from_slice(&fs::read("policy-request/manifest.json")?)?;
    manifest.validate()?;
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&read)?;
    ensure!(
        policy.revision == manifest.source_sha,
        "policy request runtime is stale"
    );
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    policy
        .repository(&manifest.repository)?
        .require(Capability::Merge)?;
    let api = GitHub::client_from_env("SECUREFIX_APP_TOKEN")?;
    let _: Value = api.post(&format!("/repos/{server}/labels"), &json!({"name":format!("policy-request-{}",manifest.run_id),"description":format!("{}/{}",manifest.repository,manifest.run_id),"color":"1f6feb"}))?;
    Ok(())
}

fn label(policy: &Policy) -> Result<(String, u64)> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    let payload = event()?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == server
            && std::env::var("GITHUB_EVENT_NAME")? == "label"
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1"
            && payload["repository"]["id"].as_u64() == Some(deployment.server.id),
        "policy processor must be a first-attempt server label run"
    );
    ensure!(
        payload["action"] == "created"
            && crate::request::matches_principal(
                &payload["sender"],
                config::trusted()?.client_bot_id,
                &deployment.client_bot_login,
                "Bot",
            ),
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
    source_for(api, policy, &repository, run_id)
}

fn source_for(api: &GitHub, policy: &Policy, repository: &str, run_id: u64) -> Result<Manifest> {
    let deployment = &config::trusted()?.deployment;
    let server = deployment.server.repository.as_str();
    securefix::policy::validate_repository(repository)?;
    ensure!(run_id > 0, "invalid policy source run");
    policy.repository(repository)?.require(Capability::Merge)?;
    let run = workflow::successful_source_run(api, repository, run_id)?;
    ensure!(
        run["path"] == config::workflow_path(WRAPPER)?
            && run["head_repository"]["full_name"] == repository,
        "policy source run is not a successful default workflow"
    );
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["owner"]["id"] == deployment.repository_owner.id
            && repo["owner"]["login"]
                .as_str()
                .is_some_and(|login| login.eq_ignore_ascii_case(&deployment.repository_owner.login))
            && run["repository"]["id"] == repo["id"]
            && run["head_repository"]["id"] == repo["id"],
        "policy source repository changed"
    );
    if repository == server {
        ensure!(
            repo["id"].as_u64() == Some(deployment.server.id),
            "server repository identity differs from trusted deployment config"
        );
    }
    let branch = repo["default_branch"]
        .as_str()
        .context("missing default branch")?;
    let base: Value = api.get(&format!("/repos/{repository}/commits/{branch}"))?;
    let current_base = base["sha"].as_str().context("missing default SHA")?;
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
            && manifest.source_sha == policy.revision
            && policy.control.as_ref() == Some(&manifest.control),
        "policy manifest is not bound to its source"
    );
    let caller_sha = caller_revision(&run, manifest.repository_id, branch, &manifest.target)?;
    let compare: Value = api.get(&format!(
        "/repos/{repository}/compare/{caller_sha}...{current_base}"
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "policy caller is not from default branch history"
    );
    let wrapper = api.content(repository, &config::workflow_path(WRAPPER)?, caller_sha)?;
    if repository != server {
        workflow::require_reusable_pin(&wrapper, REUSABLE, &policy.revision)?;
        let referenced: Vec<workflow::ReferencedWorkflow> =
            serde_json::from_value(run["referenced_workflows"].clone())?;
        workflow::referenced_revision(&referenced, REUSABLE, &policy.revision)?;
    } else {
        let referenced: Vec<workflow::ReferencedWorkflow> =
            serde_json::from_value(run["referenced_workflows"].clone())?;
        workflow::referenced_revision(&referenced, ".github/workflows/load-cli.yml", caller_sha)?;
    }
    match &manifest.target {
        Target::PullRequest { base_ref, .. } => ensure!(
            run["event"] == "pull_request_target" && base_ref == branch,
            "invalid policy PR event"
        ),
        Target::DefaultBranch {
            head_sha,
            branch: request_branch,
            publisher_run_id,
        } => {
            ensure!(
                head_sha == caller_sha && head_sha == current_base && request_branch == branch,
                "default branch policy head changed"
            );
            if repository == server {
                let publisher_run_id = publisher_run_id.context(
                    "server default-branch policy check is not bound to a publisher run",
                )?;
                let promotion =
                    crate::distribution::validate_promotion(api, policy, publisher_run_id)?;
                ensure!(
                    run["event"] == "workflow_run" && head_sha == &promotion.source_sha,
                    "server default-branch policy check is not bound to the successful runtime publication"
                );
            } else {
                ensure!(
                    publisher_run_id.is_none() && run["event"] == "push",
                    "caller default-branch check has invalid publisher binding"
                );
            }
        }
    }
    Ok(manifest)
}

fn caller_revision<'a>(
    run: &'a Value,
    repository_id: u64,
    branch: &str,
    target: &Target,
) -> Result<&'a str> {
    let sha = match target {
        Target::PullRequest {
            number,
            head_sha,
            base_ref,
        } => {
            let pulls = run["pull_requests"]
                .as_array()
                .context("missing source run PR association")?;
            ensure!(pulls.len() == 1, "ambiguous source run PR association");
            let pr = &pulls[0];
            ensure!(
                run["event"] == "pull_request_target"
                    && pr["number"] == *number
                    && pr["base"]["ref"] == branch
                    && base_ref == branch
                    && pr["base"]["repo"]["id"] == repository_id
                    && pr["head"]["repo"]["id"] == repository_id
                    && pr["head"]["sha"] == *head_sha
                    && run["head_sha"] == *head_sha,
                "policy target is not bound to its source run PR"
            );
            pr["base"]["sha"]
                .as_str()
                .context("missing caller base SHA")?
        }
        Target::DefaultBranch { head_sha, .. } => {
            ensure!(
                run["event"] != "pull_request_target"
                    && run["head_branch"] == branch
                    && run["head_sha"] == *head_sha,
                "policy source is not bound to its default-branch target"
            );
            run["head_sha"].as_str().context("missing caller SHA")?
        }
    };
    validate_sha(sha)?;
    Ok(sha)
}

fn validate() -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    workflow::require_current_runtime(&api, WRAPPER)?;
    let manifest = source(&api, &policy)?;
    securefix::control::ControlRevision::require_current(&api, &manifest.control)?;
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

pub(crate) fn prepare_testing_request(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    run_id: u64,
) -> Result<()> {
    let manifest = source_for(api, policy, repository, run_id)?;
    securefix::control::ControlRevision::require_current(api, &manifest.control)?;
    workflow::write_json("policy-check/manifest.json", &manifest)
}

fn apply(testing_run: Option<u64>) -> Result<()> {
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    workflow::require_current_runtime(&read, WRAPPER)?;
    let manifest = if let Some(run_id) = testing_run {
        let deployment = &config::trusted()?.deployment;
        ensure!(
            deployment.workflow_prefix == "testing-"
                && deployment.control_repository.as_ref() == Some(&deployment.integration),
            "relayed policy apply requires isolated testing configuration"
        );
        let requested: Manifest = serde_json::from_slice(&fs::read("policy-check/manifest.json")?)?;
        let manifest = source_for(&read, &policy, &deployment.integration.repository, run_id)?;
        ensure!(
            serde_json::to_value(&requested)? == serde_json::to_value(&manifest)?,
            "relayed policy source changed after host qualification"
        );
        manifest
    } else {
        source(&read, &policy)?
    };
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
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
                crate::request::has_current_head_approval_for_control(
                    &read,
                    &manifest.repository,
                    *number,
                    head_sha,
                    &manifest.control,
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
    securefix::control::ControlRevision::require_current(&read, &manifest.control)?;
    publish(
        &write,
        &manifest.repository,
        manifest.sha(),
        success,
        &summary,
        &manifest.control,
    )?;
    if let Target::PullRequest {
        number, head_sha, ..
    } = &manifest.target
    {
        report_result(
            &write,
            &manifest.repository,
            *number,
            head_sha,
            success,
            &summary,
        )?;
    }
    Ok(())
}

fn server_run_url() -> Result<String> {
    let run: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let attempt: u32 = std::env::var("GITHUB_RUN_ATTEMPT")?.parse()?;
    ensure!(run > 0 && attempt > 0, "invalid server CI identity");
    Ok(format!(
        "https://github.com/{}/actions/runs/{run}/attempts/{attempt}",
        config::trusted()?.deployment.server.repository
    ))
}

pub(crate) fn report_result(
    api: &GitHub,
    repository: &str,
    number: u64,
    sha: &str,
    success: bool,
    summary: &str,
) -> Result<()> {
    report_result_with_url(
        api,
        repository,
        number,
        sha,
        success,
        summary,
        &server_run_url()?,
    )
}

fn report_result_with_url(
    api: &GitHub,
    repository: &str,
    number: u64,
    sha: &str,
    success: bool,
    summary: &str,
    run_url: &str,
) -> Result<()> {
    validate_repository(repository)?;
    validate_sha(sha)?;
    ensure!(number > 0, "invalid policy comment PR number");
    if !current_report_target(api, repository, number, sha, success)? {
        return Ok(());
    }
    let comments: Vec<Value> =
        api.paginate(&format!("/repos/{repository}/issues/{number}/comments"))?;
    let trusted = config::trusted()?;
    let previous: Vec<_> = comments
        .iter()
        .filter(|comment| {
            crate::request::matches_principal(
                &comment["user"],
                trusted.server_bot_id,
                &trusted.deployment.server_bot_login,
                "Bot",
            ) && comment["body"]
                .as_str()
                .is_some_and(|body| body.starts_with(COMMENT_MARKER))
        })
        .collect();
    let body = policy_failure_comment(repository, sha, summary, run_url);
    let keep = if success {
        None
    } else {
        previous
            .iter()
            .rev()
            .find(|comment| comment["body"] == body)
            .and_then(|comment| comment["id"].as_u64())
    };
    if !success && keep.is_none() {
        if !current_report_target(api, repository, number, sha, success)? {
            return Ok(());
        }
        let _: Value = api.post(
            &format!("/repos/{repository}/issues/{number}/comments"),
            &json!({"body":body}),
        )?;
    }
    for comment in previous {
        let id = comment["id"].as_u64().context("policy comment has no ID")?;
        if Some(id) != keep {
            if !current_report_target(api, repository, number, sha, success)? {
                return Ok(());
            }
            api.minimize_policy_comment(repository, number, id)?;
        }
    }
    Ok(())
}

fn current_report_target(
    api: &GitHub,
    repository: &str,
    number: u64,
    sha: &str,
    success: bool,
) -> Result<bool> {
    let pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    Ok(pr["head"]["sha"] == sha && (success || pr["state"] == "open"))
}

fn policy_failure_comment(repository: &str, sha: &str, summary: &str, run_url: &str) -> String {
    let summary: String = summary.chars().take(6000).collect();
    let paragraphs = summary
        .split("\n\n")
        .map(|paragraph| {
            let lines = paragraph
                .lines()
                .map(policy_failure_line)
                .collect::<Vec<_>>();
            format!("<p>{}</p>", lines.join("<br>\n"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{COMMENT_MARKER}\n**Securefix policy check failed**\n\n{paragraphs}\n\n<sub><a href=\"{run_url}\">Server CI: policy decision</a> · <a href=\"https://github.com/{repository}/commit/{sha}\">Commit {}</a></sub>",
        &sha[..12]
    )
}

fn policy_failure_line(line: &str) -> String {
    let filename = line
        .strip_prefix("- ")
        .and_then(|value| serde_json::from_str::<String>(value).ok());
    let escaped: String = filename
        .as_deref()
        .unwrap_or(line)
        .chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '@' => "&#64;".to_owned(),
            _ => c.to_string(),
        })
        .collect();
    if filename.is_some() {
        return format!("- <code>{escaped}</code>");
    }
    escaped
        .split_inclusive(char::is_whitespace)
        .map(|token| {
            let word = token
                .trim_end()
                .trim_end_matches(['.', ',', ';', ':', '!', '?']);
            if matches!(word, "/approve" | "/merge") {
                format!("<code>{word}</code>{}", &token[word.len()..])
            } else {
                token.to_owned()
            }
        })
        .collect()
}

pub fn publish(
    api: &GitHub,
    repository: &str,
    sha: &str,
    success: bool,
    summary: &str,
    control: &securefix::control::ControlRevision,
) -> Result<()> {
    let policy_app_id = config::trusted()?.deployment.checks.policy_app_id;
    validate_repository(repository)?;
    validate_sha(sha)?;
    let value: Value = api.get(&format!(
        "/repos/{repository}/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={CHECK}&app_id={policy_app_id}"
    ))?;
    let check_runs = value["check_runs"]
        .as_array()
        .context("missing check runs")?;
    ensure!(
        value["total_count"].as_u64() == Some(check_runs.len() as u64),
        "named policy check response is incomplete"
    );
    let matches: Vec<_> = check_runs
        .iter()
        .filter(|c| c["name"] == CHECK && c["app"]["id"] == policy_app_id)
        .collect();
    ensure!(matches.len() <= 1, "duplicate policy check source");
    control.validate()?;
    let external_id = format!("{sha}:{}", control.identity()?);
    let mut body = json!({"name":CHECK,"head_sha":sha,"external_id":external_id,"status":"completed","conclusion":if success {"success"} else {"failure"},"output":{"title":if success {"Policy accepted"} else {"Policy rejected"},"summary":summary}});
    if std::env::var_os("GITHUB_RUN_ID").is_some() {
        body["details_url"] = json!(server_run_url()?);
    }
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
    let server = config::trusted()?.deployment.server.repository.clone();
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = Policy::active(&api)?;
    let (_, id) = label(&policy)?;
    if let Err(error) = api.delete(&format!("/repos/{server}/labels/policy-request-{id}")) {
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

    fn test_control() -> securefix::control::ControlRevision {
        securefix::control::ControlRevision {
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
        }
    }

    fn report_pr(sha: &str) -> Value {
        json!({"state":"open","head":{"sha":sha}})
    }

    fn existing_policy_comment(id: u64, body: &str) -> Value {
        let trusted = config::trusted().unwrap();
        json!({
            "id":id,
            "node_id":format!("IC_{id}"),
            "issue_url":"https://api.github.com/repos/civitaspo/example/issues/7",
            "body":body,
            "user":{"id":trusted.server_bot_id,"login":trusted.deployment.server_bot_login,"type":"Bot"}
        })
    }

    fn pr_source() -> (Value, Target) {
        (
            serde_json::from_str(include_str!("../tests/fixtures/policy-pr-target-run.json"))
                .unwrap(),
            Target::PullRequest {
                number: 63,
                head_sha: "c234f933b830e801436647725028f4945d7618e7".into(),
                base_ref: "main".into(),
            },
        )
    }

    #[test]
    fn pr_target_source_uses_actual_base_revision_and_binds_the_target_head() {
        let (run, target) = pr_source();
        let source = caller_revision(&run, 1250079425, "main", &target).unwrap();
        assert_eq!(source, "7819d4abb70af791715492ec21b20563df4815df");
        assert_ne!(source, run["head_sha"].as_str().unwrap());
        for (number, head, base) in [
            (64, "c234f933b830e801436647725028f4945d7618e7", "main"),
            (63, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "main"),
            (
                63,
                "c234f933b830e801436647725028f4945d7618e7",
                "release/next",
            ),
        ] {
            let mismatched = Target::PullRequest {
                number,
                head_sha: head.into(),
                base_ref: base.into(),
            };
            assert!(caller_revision(&run, 1250079425, "main", &mismatched).is_err());
        }
    }

    #[test]
    fn failure_posts_actionable_escaped_report_and_hides_only_previous_server_reports() {
        let sha = "a".repeat(40);
        let trusted = config::trusted().unwrap();
        let run_url = "https://github.com/civitaspo/securefix-server/actions/runs/42/attempts/1";
        let old_id = 101;
        let old_body = format!("{COMMENT_MARKER}\nOld report");
        let unmarked = existing_policy_comment(102, "unrelated bot comment");
        let mut owner_report =
            existing_policy_comment(103, &format!("{COMMENT_MARKER}\nOwner report"));
        owner_report["user"] =
            json!({"id":trusted.owner_id,"login":trusted.deployment.owner_login,"type":"User"});
        let summary = "bad <script> @team & more\n\nNext step: /approve or /merge.\n- \"Cargo.toml\"\n- \"<script> @team & file.rs\"";
        let expected_body = policy_failure_comment("civitaspo/example", &sha, summary, run_url);
        assert!(!expected_body.contains("<pre>"));
        assert!(expected_body.contains("bad &lt;script&gt; &#64;team &amp; more</p>"));
        assert!(
            expected_body
                .contains("<p>Next step: <code>/approve</code> or <code>/merge</code>.<br>\n- <code>Cargo.toml</code><br>\n- <code>&lt;script&gt; &#64;team &amp; file.rs</code></p>")
        );
        let gql = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let fixture = Fixture::new(vec![
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::get("/repos/civitaspo/example/issues/7/comments?per_page=100&page=1", json!([
                existing_policy_comment(old_id, &old_body), unmarked, owner_report
            ])),
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST", "/repos/civitaspo/example/issues/7/comments", 201,
                json!({"id":104,"body":expected_body}),
            ).with_request_body(json!({"body":expected_body})),
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::get(
                format!("/repos/civitaspo/example/issues/comments/{old_id}"),
                existing_policy_comment(old_id, &old_body),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST", "/graphql", 200,
                json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            ).with_request_body(json!({"query":gql,"variables":{"input":{"subjectId":format!("IC_{old_id}"),"classifier":"OUTDATED"}}})),
        ]);
        report_result_with_url(
            &fixture.api,
            "civitaspo/example",
            7,
            &sha,
            false,
            summary,
            run_url,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn successful_policy_report_posts_nothing_and_hides_prior_failure() {
        let sha = "a".repeat(40);
        let id = 101;
        let body = format!("{COMMENT_MARKER}\nOld failure");
        let gql = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let fixture = Fixture::new(vec![
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::get("/repos/civitaspo/example/issues/7/comments?per_page=100&page=1", json!([
                existing_policy_comment(id, &body)
            ])),
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::get(
                format!("/repos/civitaspo/example/issues/comments/{id}"),
                existing_policy_comment(id, &body),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST", "/graphql", 200,
                json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            ).with_request_body(json!({"query":gql,"variables":{"input":{"subjectId":format!("IC_{id}"),"classifier":"OUTDATED"}}})),
        ]);
        report_result_with_url(
            &fixture.api,
            "civitaspo/example",
            7,
            &sha,
            true,
            "accepted",
            "https://example.invalid/run",
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn stale_policy_failure_is_ignored_before_listing_or_writing_comments() {
        let fixture = Fixture::new(vec![Route::get(
            "/repos/civitaspo/example/pulls/7",
            report_pr(&"b".repeat(40)),
        )]);
        report_result_with_url(
            &fixture.api,
            "civitaspo/example",
            7,
            &"a".repeat(40),
            false,
            "stale failure",
            "https://example.invalid/run",
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn retry_with_an_identical_failure_report_does_not_post_a_duplicate() {
        let sha = "a".repeat(40);
        let run_url = "https://github.com/civitaspo/securefix-server/actions/runs/42/attempts/1";
        let body = policy_failure_comment("civitaspo/example", &sha, "same failure", run_url);
        let fixture = Fixture::new(vec![
            Route::get("/repos/civitaspo/example/pulls/7", report_pr(&sha)),
            Route::get(
                "/repos/civitaspo/example/issues/7/comments?per_page=100&page=1",
                json!([existing_policy_comment(101, &body)]),
            ),
        ]);
        report_result_with_url(
            &fixture.api,
            "civitaspo/example",
            7,
            &sha,
            false,
            "same failure",
            run_url,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn pr_source_rejects_ambiguous_associations_wrong_repositories_and_retargeting() {
        let (original, target) = pr_source();
        for (pointer, replacement) in [
            ("/event", json!("pull_request")),
            ("/pull_requests", Value::Null),
            ("/pull_requests", json!([])),
            (
                "/pull_requests",
                json!([original["pull_requests"][0], original["pull_requests"][0]]),
            ),
            ("/pull_requests/0/number", json!(64)),
            ("/pull_requests/0/base/ref", json!("release/next")),
            ("/pull_requests/0/base/repo/id", json!(999)),
            ("/pull_requests/0/head/repo/id", json!(999)),
            ("/pull_requests/0/head/sha", json!("a".repeat(40))),
            ("/head_sha", json!("a".repeat(40))),
            ("/pull_requests/0/base/sha", json!("main")),
        ] {
            let mut run = original.clone();
            *run.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                caller_revision(&run, 1250079425, "main", &target).is_err(),
                "accepted altered source field {pointer}"
            );
        }
    }

    #[test]
    fn default_branch_source_keeps_its_own_head_revision() {
        let sha = "a".repeat(40);
        let target = Target::DefaultBranch {
            head_sha: sha.clone(),
            branch: "main".into(),
            publisher_run_id: None,
        };
        for event in ["push", "workflow_run"] {
            let mut run = json!({"event":event,"head_sha":sha,"head_branch":"main"});
            assert_eq!(caller_revision(&run, 1, "main", &target).unwrap(), sha);
            run["head_sha"] = json!("b".repeat(40));
            assert!(caller_revision(&run, 1, "main", &target).is_err());
            run["head_sha"] = json!(sha);
            run["head_branch"] = json!("release/next");
            assert!(caller_revision(&run, 1, "main", &target).is_err());
        }
        let run = json!({"event":"pull_request_target","head_sha":sha,"head_branch":"main"});
        assert!(caller_revision(&run, 1, "main", &target).is_err());
    }

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
        let policy_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .policy_app_id;
        let check_path = format!(
            "/repos/civitaspo/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={CHECK}&app_id={policy_app_id}"
        );
        let control = test_control();
        let mut body = json!({"name":CHECK,"external_id":format!("{sha}:{}", control.identity().unwrap()),"status":"completed","conclusion":"failure","output":{"title":"Policy rejected","summary":"Changed head"}});
        if std::env::var_os("GITHUB_RUN_ID").is_some() {
            body["details_url"] = json!(server_run_url().unwrap());
        }
        let fixture = Fixture::new(vec![
            Route::get(
                check_path,
                json!({"total_count":2,"check_runs":[{"id":17,"name":CHECK,"app":{"id":crate::config::trusted().unwrap().deployment.checks.policy_app_id}},{"id":18,"name":CHECK,"app":{"id":99}}]}),
            ),
            Route::active_control(&Fixture::control_revision()),
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
            &control,
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn duplicate_policy_checks_are_rejected_without_writing() {
        let sha = "a".repeat(40);
        let policy_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .policy_app_id;
        let fixture = Fixture::new(vec![Route::get(
            format!(
                "/repos/civitaspo/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={CHECK}&app_id={policy_app_id}"
            ),
            json!({"total_count":2,"check_runs":[{"id":17,"name":CHECK,"app":{"id":crate::config::trusted().unwrap().deployment.checks.policy_app_id}},{"id":18,"name":CHECK,"app":{"id":crate::config::trusted().unwrap().deployment.checks.policy_app_id}}]}),
        )]);
        assert!(
            publish(
                &fixture.api,
                "civitaspo/example",
                &sha,
                true,
                "Accepted",
                &test_control()
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn incomplete_policy_check_listing_never_creates_a_duplicate() {
        let sha = "a".repeat(40);
        let policy_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .policy_app_id;
        let fixture = Fixture::new(vec![Route::get(
            format!(
                "/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={CHECK}&app_id={policy_app_id}"
            ),
            json!({"total_count":101,"check_runs":[]}),
        )]);
        assert!(
            publish(
                &fixture.api,
                "forge/example",
                &sha,
                true,
                "Accepted",
                &test_control()
            )
            .is_err()
        );
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
