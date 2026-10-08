use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::request::{self, Authorization, RequestKind, RequestManifest};
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, SERVER},
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
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&api)?;
    let source_sha =
        securefix::workflow::require_current_runtime(&api, ".github/workflows/approve.yml")?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == SERVER,
        "approval processor must run in the server repository"
    );
    let payload = event()?;
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
        payload["sender"]["id"].as_u64() == Some(policy.client_bot_id)
            && payload["sender"]["type"] == "Bot",
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
        approver["login"] == "civitaspo-bot" && approver["type"] == "User",
        "approval token must authenticate as civitaspo-bot"
    );
    ensure!(
        approver["id"] != pr["user"]["id"],
        "the approval account cannot approve its own pull request"
    );
    let approver_id = approver["id"]
        .as_u64()
        .context("approval token has no user identity")?;
    let reviews = read.paginate(&format!(
        "/repos/{repository}/pulls/{}/reviews",
        manifest.pull_request.number
    ))?;
    let already_approved = reviews.iter().any(|review| {
        review["user"]["id"].as_u64() == Some(approver_id)
            && review["state"] == "APPROVED"
            && review["commit_id"] == manifest.pull_request.head_sha
    });
    if !already_approved {
        let _: Value = approve.post(&format!("/repos/{repository}/pulls/{}/reviews", manifest.pull_request.number),
            &json!({"event":"APPROVE","commit_id":manifest.pull_request.head_sha,"body":"Securefix approval after policy validation."}))?;
    }
    ensure!(
        request::has_current_head_approval(
            &read,
            repository,
            manifest.pull_request.number,
            &manifest.pull_request.head_sha,
        )?,
        "no non-author approval is attached to the accepted head"
    );
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
    match api.delete(&format!("/repos/{SERVER}/labels/{label}")) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("returned 404") => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
