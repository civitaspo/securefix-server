//! Receiver-side validation for the initial native request protocol.
//!
//! This module accepts only a bounded manifest whose local GitHub artifact
//! attestation is verified by the official `gh` verifier. It can publish one
//! narrowly scoped scratch check after current-state fences.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf};

use crate::native_client::RequestManifest;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
const SLSA_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const REQUEST_ARTIFACT_NAME: &str = "native-request-proof";

#[derive(clap::Subcommand)]
pub enum CommandArgs {
    #[command(about = "Validate one native request and its producer attestation")]
    PolicyCheck {
        #[arg(long)]
        config: PathBuf,
        /// Explicit path, relative to the Server instance repository root.
        #[arg(long)]
        config_path: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        /// Create the scratch-only proof check after all current-state fences pass.
        #[arg(long, default_value_t = false)]
        publish: bool,
    },
    #[command(about = "Validate a bound Securefix artifact and commit its exact PR changes")]
    SecurefixApply {
        #[arg(long)]
        config: PathBuf,
        /// Explicit path, relative to the Server instance repository root.
        #[arg(long)]
        config_path: String,
        /// Exact Client repository that owns the producer run.
        #[arg(long)]
        producer_repository: String,
        /// Successful Client workflow run containing the attested request and fix artifact.
        #[arg(long)]
        producer_run_id: u64,
    },
    #[command(
        about = "Validate an owner-authorized request and optionally apply its exact-head approval"
    )]
    Approval {
        #[arg(long)]
        config: PathBuf,
        /// Explicit path, relative to the Server instance repository root.
        #[arg(long)]
        config_path: String,
        /// Exact Client repository that owns the producer run.
        #[arg(long)]
        producer_repository: String,
        /// Successful Client workflow run containing the attested approval request.
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        expected_head_sha: String,
        /// Post the review using the configured User credential after all fences pass.
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    #[command(
        about = "Validate paired native approval and merge requests and optionally squash-merge the exact PR head"
    )]
    Merge {
        #[arg(long)]
        config: PathBuf,
        /// Explicit path, relative to the Server instance repository root.
        #[arg(long)]
        config_path: String,
        /// Exact Client repository that owns both producer runs.
        #[arg(long)]
        producer_repository: String,
        /// Successful Client workflow run containing the attested merge request.
        #[arg(long)]
        producer_run_id: u64,
        /// Successful Client workflow run containing the attested native approval request.
        #[arg(long)]
        approval_producer_run_id: u64,
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        expected_head_sha: String,
        /// Merge the exact PR head after all proof, approval, and check fences pass.
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
}

pub fn run(command: CommandArgs) -> Result<()> {
    match command {
        CommandArgs::PolicyCheck {
            config,
            config_path,
            manifest,
            bundle,
            publish,
        } => {
            let verified = verify_request(
                &config,
                &config_path,
                &manifest,
                &bundle,
                securefix::api::NativeScratchMode::PolicyCheck,
                securefix::api::NativeScratchMode::PolicyCheck,
                publish,
            )?;
            if publish {
                publish_scratch_result(&verified)?;
            }
            println!(
                "request_sha256={}",
                securefix::hex_encode(Sha256::digest(&verified.manifest_bytes))
            );
            println!("producer_run_id={}", verified.manifest.producer.run_id);
            println!(
                "producer_run_attempt={}",
                verified.manifest.producer.run_attempt
            );
            println!(
                "request_head_sha={}",
                verified.manifest.pull_request.head_sha
            );
            println!("result_published={publish}");
            Ok(())
        }
        CommandArgs::SecurefixApply {
            config,
            config_path,
            producer_repository,
            producer_run_id,
        } => apply_securefix_from_run(&config, &config_path, &producer_repository, producer_run_id),
        CommandArgs::Approval {
            config,
            config_path,
            producer_repository,
            producer_run_id,
            pull_request_number,
            expected_head_sha,
            apply,
        } => apply_native_approval_from_run(
            &config,
            &config_path,
            &producer_repository,
            producer_run_id,
            pull_request_number,
            &expected_head_sha,
            apply,
        ),
        CommandArgs::Merge {
            config,
            config_path,
            producer_repository,
            producer_run_id,
            approval_producer_run_id,
            pull_request_number,
            expected_head_sha,
            apply,
        } => apply_native_merge_from_runs(
            &config,
            &config_path,
            &producer_repository,
            NativeMergeRunIds {
                merge: producer_run_id,
                approval: approval_producer_run_id,
            },
            pull_request_number,
            &expected_head_sha,
            apply,
        ),
    }
}

struct VerifiedRequest {
    config: securefix::instance_config::InstanceConfig,
    config_bytes: Vec<u8>,
    manifest: RequestManifest,
    manifest_bytes: Vec<u8>,
    target_policy_control_identity: Option<String>,
    writer: Option<securefix::api::GitHub>,
    client_api: securefix::api::GitHub,
    producer_run: Value,
}

fn verify_request(
    config_path: &std::path::Path,
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
    mode: securefix::api::NativeScratchMode,
    execution_mode: securefix::api::NativeScratchMode,
    publish: bool,
) -> Result<VerifiedRequest> {
    let config_bytes = read_bounded(config_path, 256 * 1024)?;
    let config = securefix::instance_config::InstanceConfig::parse(&config_bytes)?;
    securefix::api::validate_native_instance_config_path(instance_config_path)?;
    let manifest_bytes = read_bounded(manifest_path, MAX_REQUEST_BYTES)?;
    let manifest: RequestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse native request manifest")?;
    manifest.validate()?;
    ensure!(
        match mode {
            securefix::api::NativeScratchMode::PolicyCheck => manifest.operation == "policy_check",
            securefix::api::NativeScratchMode::Approval => manifest.operation == "approval",
            securefix::api::NativeScratchMode::Merge => manifest.operation == "merge",
            securefix::api::NativeScratchMode::Securefix => manifest.operation == "securefix",
        },
        "native request operation does not match the Server command"
    );
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(config.instance.repository.as_str()),
        "native Server config does not match the current job repository"
    );
    ensure!(
        config.repositories.iter().any(|repository| {
            repository.id == manifest.repository.id
                && repository.repository == manifest.repository.full_name
        }),
        "native request repository is not configured"
    );
    securefix::api::validate_native_test_host_context(&config, execution_mode)?;
    validate_request_server_locator(&config, instance_config_path, &manifest.server_authority)?;
    validate_first_slice_policy(&config, &manifest, mode)?;
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let server_api = securefix::api::GitHub::new("https://api.github.com", token)?;
    let (remote_config, server_authority) =
        server_api.capture_native_server_authority(&config, instance_config_path, &config_bytes)?;
    ensure!(
        remote_config == config_bytes,
        "Server config is not the protected default-branch snapshot"
    );
    securefix::api::require_native_authority_unchanged(
        &manifest.server_authority,
        &server_authority,
    )?;
    let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
        .context("missing GITHUB_WORKFLOW_REF for native Server execution")?;
    let workflow_sha = std::env::var("GITHUB_WORKFLOW_SHA")
        .context("missing GITHUB_WORKFLOW_SHA for native Server execution")?;
    let role = match execution_mode {
        securefix::api::NativeScratchMode::PolicyCheck => {
            securefix::instance_config::WorkflowRole::PolicyCheck
        }
        securefix::api::NativeScratchMode::Approval => {
            securefix::instance_config::WorkflowRole::Approve
        }
        securefix::api::NativeScratchMode::Merge => securefix::instance_config::WorkflowRole::Merge,
        securefix::api::NativeScratchMode::Securefix => {
            securefix::instance_config::WorkflowRole::Securefix
        }
    };
    let workflow_path = config
        .workflow_roles
        .get(&role)
        .context("native Server workflow role is not configured")?;
    let workflow_bytes =
        server_api.content(&config.instance.repository, workflow_path, &workflow_sha)?;
    securefix::api::validate_native_server_execution_workflow(
        &server_authority,
        execution_mode,
        &workflow_ref,
        &workflow_sha,
        &workflow_bytes,
    )?;
    let bundle_bytes = read_bounded(bundle_path, MAX_BUNDLE_BYTES)?;
    ensure!(!bundle_bytes.is_empty(), "attestation bundle is empty");
    let api = securefix::api::GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    let target_policy_control_identity = if mode == securefix::api::NativeScratchMode::Merge {
        Some(securefix::api::native_target_policy_control_identity(
            &api,
            &manifest.repository.full_name,
            manifest.repository.id,
            &manifest.pull_request.base_ref,
        )?)
    } else {
        None
    };
    let acceptable_client: Value =
        server_api.get(&format!("/repos/{}", config.acceptable_clients.repository))?;
    ensure!(
        acceptable_client["id"].as_u64() == Some(config.acceptable_clients.id)
            && acceptable_client["full_name"].as_str()
                == Some(config.acceptable_clients.repository.as_str()),
        "configured Client repository identity mismatch"
    );
    let producer_repository = &manifest.repository.full_name;
    let run: Value = api.get(&format!(
        "/repos/{producer_repository}/actions/runs/{}",
        manifest.producer.run_id
    ))?;
    verify_run_identity(&run, &manifest)?;
    verify_artifact_binding(&api, &manifest, manifest_path, bundle_path)?;
    verify_current_pull_request(&api, &manifest)?;
    crate::request::validate_native_pr_commit_policy(
        &api,
        &manifest.repository.full_name,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        &config.policy.trusted_committers,
    )?;
    let current_client_epoch = securefix::api::capture_native_client_workflow_epoch(
        &api,
        &manifest.repository.full_name,
        manifest.repository.id,
        &manifest.pull_request.base_ref,
        &manifest.producer.workflow_path,
        &manifest.producer.workflow_sha,
    )?;
    securefix::api::require_native_client_workflow_epoch_unchanged(
        &manifest.client_workflow_epoch,
        &current_client_epoch,
    )?;

    let references: Vec<securefix::workflow::ReferencedWorkflow> = serde_json::from_value(
        run.get("referenced_workflows")
            .cloned()
            .context("source run has no reusable-workflow references")?,
    )
    .context("parse reusable-workflow references")?;
    let signer_prefix = format!(
        "{}/{}@",
        config.acceptable_clients.repository, config.acceptable_clients.producer_workflow
    );
    let signer_reference = references
        .iter()
        .filter(|reference| reference.path.starts_with(&signer_prefix))
        .collect::<Vec<_>>();
    ensure!(
        signer_reference.len() == 1,
        "source run does not name exactly one configured Client producer workflow"
    );
    let signer_sha = &signer_reference[0].sha;
    securefix::policy::validate_sha(signer_sha)?;
    let caller_yaml = api.content(
        &manifest.repository.full_name,
        &manifest.producer.workflow_path,
        &manifest.producer.workflow_sha,
    )?;
    securefix::workflow::require_reusable_correspondence(
        &references,
        &manifest.producer.workflow_sha,
        &caller_yaml,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
    )?;

    let verified = verify_with_gh(
        manifest_path,
        bundle_path,
        &manifest.repository.full_name,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
    )?;
    verify_certificate(
        &verified,
        &manifest,
        &run,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
        &manifest_bytes,
    )?;
    let writer = if publish
        && matches!(
            mode,
            securefix::api::NativeScratchMode::PolicyCheck
                | securefix::api::NativeScratchMode::Approval
                | securefix::api::NativeScratchMode::Merge
        ) {
        Some(native_scratch_writer(
            &config,
            &config_bytes,
            instance_config_path,
            &manifest,
            &manifest_bytes,
            mode,
            target_policy_control_identity.as_deref(),
        )?)
    } else {
        None
    };
    Ok(VerifiedRequest {
        config,
        config_bytes,
        manifest,
        manifest_bytes,
        target_policy_control_identity,
        writer,
        client_api: api,
        producer_run: run,
    })
}

fn validate_request_server_locator(
    config: &securefix::instance_config::InstanceConfig,
    config_path: &str,
    captured: &securefix::api::NativeAuthoritySnapshot,
) -> Result<()> {
    securefix::api::validate_native_authority_snapshot(captured)?;
    ensure!(
        captured.instance_repository == config.instance.repository
            && captured.instance_id == config.instance.id
            && captured.default_branch == config.instance.default_branch
            && captured.config_path == config_path,
        "request Server locator does not match the authenticated execution instance and config path"
    );
    Ok(())
}

fn verify_run_identity(run: &Value, manifest: &RequestManifest) -> Result<()> {
    ensure!(
        run["id"].as_u64() == Some(manifest.producer.run_id)
            && run["run_attempt"].as_u64() == Some(u64::from(manifest.producer.run_attempt))
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["event"].as_str() == Some(manifest.producer.event.as_str())
            && run["head_sha"].as_str() == Some(manifest.producer.source_sha.as_str())
            && run["repository"]["id"].as_u64() == Some(manifest.repository.id)
            && run["repository"]["full_name"].as_str()
                == Some(manifest.repository.full_name.as_str())
            && run["head_branch"]
                .as_str()
                .is_some_and(|branch| { securefix::config::validate_branch(branch).is_ok() })
            && run["actor"]["id"].as_u64() == Some(manifest.producer.actor_id)
            && run["actor"]["login"].as_str() == Some(manifest.producer.actor_login.as_str())
            && run["path"].as_str() == Some(manifest.producer.workflow_path.as_str()),
        "native request producer run identity or conclusion mismatch"
    );
    crate::native_client::validate_pull_request_target_identity(
        &manifest.producer.event,
        &manifest.producer.source_sha,
        &manifest.producer.context_sha,
        run["head_branch"]
            .as_str()
            .context("producer run head branch is missing")?,
        &manifest.pull_request.head_sha,
        &manifest.pull_request.head_branch,
        &manifest.pull_request.base_sha,
    )
}

fn verify_current_pull_request(
    api: &securefix::api::GitHub,
    manifest: &RequestManifest,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let pull: Value = api.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    validate_current_pull_request_state(&repo, &pull, manifest)
}

fn validate_current_pull_request_state(
    repo: &Value,
    pull: &Value,
    manifest: &RequestManifest,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    ensure!(
        repo["id"].as_u64() == Some(manifest.repository.id)
            && repo["full_name"].as_str() == Some(repository.as_str())
            && pull["number"].as_u64() == Some(manifest.pull_request.number)
            && pull["state"] == "open"
            && pull["base"]["repo"]["id"].as_u64() == Some(manifest.repository.id)
            && pull["base"]["repo"]["full_name"].as_str() == Some(repository.as_str())
            && pull["base"]["sha"].as_str() == Some(manifest.pull_request.base_sha.as_str())
            && pull["base"]["ref"].as_str() == Some(manifest.pull_request.base_ref.as_str())
            && pull["head"]["sha"].as_str() == Some(manifest.pull_request.head_sha.as_str())
            && pull["head"]["ref"].as_str() == Some(manifest.pull_request.head_branch.as_str())
            && pull["head"]["repo"]["id"].as_u64()
                == Some(manifest.pull_request.head_repository_id)
            && pull["user"]["id"].as_u64() == Some(manifest.pull_request.author_id)
            && manifest.pull_request.author_id == manifest.producer.actor_id
            && manifest.pull_request.author_login == manifest.producer.actor_login
            && pull["user"]["login"].as_str() == Some(manifest.pull_request.author_login.as_str()),
        "native request PR is closed, retargeted, or has a different head or identity"
    );
    ensure!(
        repo["default_branch"].as_str() == Some(manifest.pull_request.base_ref.as_str()),
        "native request PR does not target the repository default branch"
    );
    Ok(())
}

fn validate_first_slice_policy(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    mode: securefix::api::NativeScratchMode,
) -> Result<()> {
    let repository = config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == manifest.repository.full_name
                && repository.id == manifest.repository.id
        })
        .context("native request repository is not configured")?;
    let required_capability = match mode {
        securefix::api::NativeScratchMode::PolicyCheck => securefix::policy::Capability::Merge,
        securefix::api::NativeScratchMode::Approval => securefix::policy::Capability::Approve,
        securefix::api::NativeScratchMode::Merge => securefix::policy::Capability::Merge,
        securefix::api::NativeScratchMode::Securefix => securefix::policy::Capability::Securefix,
    };
    repository
        .policy()
        .require(required_capability)
        .context("native request repository lacks the required capability")?;
    ensure!(
        config.identities.owner.id == manifest.producer.actor_id
            && config.identities.owner.login == manifest.producer.actor_login
            && config.identities.owner.id == manifest.pull_request.author_id
            && config.identities.owner.login == manifest.pull_request.author_login,
        "first-slice policy requires the configured owner as producer actor and PR author"
    );
    Ok(())
}

fn native_scratch_writer(
    config: &securefix::instance_config::InstanceConfig,
    config_bytes: &[u8],
    config_path: &str,
    manifest: &RequestManifest,
    manifest_bytes: &[u8],
    mode: securefix::api::NativeScratchMode,
    target_policy_control_identity: Option<&str>,
) -> Result<securefix::api::GitHub> {
    let request_sha256 = securefix::hex_encode(Sha256::digest(manifest_bytes));
    let target = securefix::api::NativeScratchTarget {
        mode,
        repository: &manifest.repository.full_name,
        repository_id: manifest.repository.id,
        pull_number: manifest.pull_request.number,
        head_sha: &manifest.pull_request.head_sha,
        head_repository_id: manifest.pull_request.head_repository_id,
        base_ref: &manifest.pull_request.base_ref,
        author_id: manifest.pull_request.author_id,
        author_login: &manifest.pull_request.author_login,
        actor_id: manifest.producer.actor_id,
        actor_login: &manifest.producer.actor_login,
        request_sha256: &request_sha256,
        server_authority: &manifest.server_authority,
        caller_workflow_path: &manifest.producer.workflow_path,
        caller_workflow_sha: &manifest.producer.workflow_sha,
        client_workflow_epoch: &manifest.client_workflow_epoch,
        target_policy_control_identity,
        destination_branch: (mode == securefix::api::NativeScratchMode::Securefix)
            .then_some(manifest.pull_request.head_branch.as_str()),
    };
    let write_token = match mode {
        securefix::api::NativeScratchMode::PolicyCheck => "SECUREFIX_NATIVE_CHECK_TOKEN",
        securefix::api::NativeScratchMode::Approval => "SECUREFIX_APPROVE_TOKEN",
        securefix::api::NativeScratchMode::Merge => "SECUREFIX_NATIVE_MERGE_TOKEN",
        securefix::api::NativeScratchMode::Securefix => "SECUREFIX_WRITE_TOKEN",
    };
    securefix::api::GitHub::native_scratch_from_env(
        "SECUREFIX_CLIENT_TOKEN",
        write_token,
        config,
        config_path,
        config_bytes,
        &target,
    )
}

fn publish_scratch_result(verified: &VerifiedRequest) -> Result<()> {
    let manifest = &verified.manifest;
    let api = verified
        .writer
        .as_ref()
        .context("native scratch writer was not captured before proof validation")?;
    let checks: Value = api.get(&format!(
        "/repos/{}/commits/{}/check-runs?per_page=100&page=1&filter=latest&check_name={}&app_id={}",
        manifest.repository.full_name,
        manifest.pull_request.head_sha,
        securefix::api::NATIVE_POLICY_CHECK_NAME,
        verified.config.apps.policy_check_id
    ))?;
    let existing = checks["check_runs"]
        .as_array()
        .context("native check listing is missing")?;
    ensure!(
        checks["total_count"].as_u64() == Some(existing.len() as u64) && existing.is_empty(),
        "native request proof check already exists or check listing is incomplete"
    );
    let request_sha = securefix::hex_encode(Sha256::digest(&verified.manifest_bytes));
    let body =
        securefix::api::native_policy_check_body(&manifest.pull_request.head_sha, &request_sha);
    let result: Value = api.post(
        &format!("/repos/{}/check-runs", manifest.repository.full_name),
        &body,
    )?;
    ensure!(
        result["name"] == securefix::api::NATIVE_POLICY_CHECK_NAME
            && result["head_sha"].as_str() == Some(manifest.pull_request.head_sha.as_str())
            && result["status"] == "completed"
            && result["conclusion"] == "success"
            && result["app"]["id"].as_u64() == Some(verified.config.apps.policy_check_id),
        "GitHub returned a different native request proof check"
    );
    println!("native_check_run_id={}", result["id"]);
    Ok(())
}

fn apply_securefix(
    config_path: &std::path::Path,
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<()> {
    let verified = verify_request(
        config_path,
        instance_config_path,
        manifest_path,
        bundle_path,
        securefix::api::NativeScratchMode::Securefix,
        securefix::api::NativeScratchMode::Securefix,
        true,
    )?;
    let manifest = &verified.manifest;
    let artifact_identity = manifest
        .securefix_artifact
        .as_ref()
        .context("Securefix request has no bound source artifact")?;
    let run_branch = verified.producer_run["head_branch"]
        .as_str()
        .context("Securefix producer run branch is missing")?;
    securefix::config::validate_branch(run_branch)?;
    ensure!(
        manifest.producer.event == "pull_request_target",
        "native Securefix requires pull_request_target"
    );
    let artifact_bytes =
        download_securefix_artifact(&verified.client_api, manifest, artifact_identity)?;
    let fix = crate::securefix_gate::artifact::parse(
        &artifact_bytes,
        &artifact_identity.name,
        &manifest.repository.full_name,
        manifest.producer.run_id,
        &manifest.producer.source_sha,
        &manifest.pull_request.head_branch,
    )?;
    validate_securefix_artifact_context(manifest, run_branch, &fix)?;
    let source = crate::securefix_gate::SourceRequest {
        repository: &manifest.repository.full_name,
        run_id: manifest.producer.run_id,
        label: &artifact_identity.name,
        branch: run_branch,
        sha: &manifest.producer.source_sha,
    };
    let plan = crate::securefix_gate::FixPlan {
        version: 1,
        source_repository: manifest.repository.full_name.clone(),
        source_run_id: manifest.producer.run_id,
        source_sha: manifest.producer.source_sha.clone(),
        artifact_name: artifact_identity.name.clone(),
        artifact_id: artifact_identity.id,
        destination_repository: fix.repository.clone(),
        destination_branch: fix.branch.clone(),
        expected_head: manifest.pull_request.head_sha.clone(),
        destination_branch_exists: true,
        existing_pull_request: Some(manifest.pull_request.number),
    };
    let writer = native_scratch_writer(
        &verified.config,
        &verified.config_bytes,
        instance_config_path,
        manifest,
        &verified.manifest_bytes,
        securefix::api::NativeScratchMode::Securefix,
        None,
    )?;
    let server_run = std::env::var("GITHUB_RUN_ID").unwrap_or_default();
    let server_url =
        std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".to_owned());
    let result = crate::securefix_gate::apply_core(crate::securefix_gate::ApplyCore {
        read_api: &verified.client_api,
        write_api: &writer,
        server_bot_id: verified.config.identities.server_bot.id,
        source,
        plan: &plan,
        fix: &fix,
        server_url: &server_url,
        server_repository: &verified.config.instance.repository,
        server_run: &server_run,
    })?;
    println!("commit_sha={}", result.commit_sha);
    println!("already_applied={}", result.already_applied);
    println!("pull_request_number={}", manifest.pull_request.number);
    Ok(())
}

fn validate_securefix_artifact_context(
    manifest: &RequestManifest,
    run_branch: &str,
    fix: &crate::securefix_gate::artifact::FixArtifact,
) -> Result<()> {
    ensure!(
        manifest.producer.event == "pull_request_target"
            && run_branch == manifest.pull_request.head_branch
            && fix.event_name == manifest.producer.event,
        "native Securefix requires a pull_request_target run for the exact PR head"
    );
    let event_pr = fix
        .pull_request_context
        .as_ref()
        .context("Securefix artifact does not contain its pull_request_target context")?;
    ensure!(
        event_pr.number == manifest.pull_request.number
            && event_pr.head_sha == manifest.pull_request.head_sha
            && event_pr.head_branch == manifest.pull_request.head_branch
            && event_pr.head_repository_id == manifest.pull_request.head_repository_id
            && event_pr.head_repository == manifest.repository.full_name
            && event_pr.base_sha == manifest.pull_request.base_sha
            && event_pr.base_sha == manifest.producer.context_sha
            && event_pr.base_branch == manifest.pull_request.base_ref
            && event_pr.base_repository_id == manifest.repository.id
            && event_pr.base_repository == manifest.repository.full_name
            && fix.repository == manifest.repository.full_name
            && fix.branch == manifest.pull_request.head_branch
            && fix.create_pull_request.is_none(),
        "Securefix artifact event does not match the attested exact PR and producer context"
    );
    ensure!(
        manifest.pull_request.head_repository_id == manifest.repository.id,
        "native Securefix cannot write to a fork PR branch"
    );
    Ok(())
}

fn apply_securefix_from_run(
    config_path: &std::path::Path,
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
) -> Result<()> {
    let (manifest_bytes, bundle_bytes) = download_request_from_run(
        config_path,
        producer_repository,
        producer_run_id,
        securefix::policy::Capability::Securefix,
    )?;
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, bundle_bytes)?;
    apply_securefix(
        config_path,
        instance_config_path,
        &manifest_path,
        &bundle_path,
    )
}

fn apply_native_approval_from_run(
    config_path: &std::path::Path,
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
    pull_request_number: u64,
    expected_head_sha: &str,
    apply: bool,
) -> Result<()> {
    securefix::policy::validate_sha(expected_head_sha)?;
    ensure!(pull_request_number > 0, "invalid approval PR number");
    let (manifest_bytes, bundle_bytes) = download_request_from_run(
        config_path,
        producer_repository,
        producer_run_id,
        securefix::policy::Capability::Approve,
    )?;
    let manifest: RequestManifest = serde_json::from_slice(&manifest_bytes)
        .context("parse downloaded native approval request")?;
    ensure!(
        manifest.pull_request.number == pull_request_number
            && manifest.pull_request.head_sha == expected_head_sha,
        "producer request does not match the owner-selected PR number and head"
    );
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, bundle_bytes)?;
    let verified = verify_request(
        config_path,
        instance_config_path,
        &manifest_path,
        &bundle_path,
        securefix::api::NativeScratchMode::Approval,
        securefix::api::NativeScratchMode::Approval,
        apply,
    )?;
    if apply {
        let writer = verified
            .writer
            .as_ref()
            .context("native approval writer was not captured before apply")?;
        let marker = crate::approval::approve_native_current_head(
            &verified.client_api,
            writer,
            &verified.manifest,
            &verified.config.identities.approval_reviewer,
            &verified.manifest_bytes,
        )?;
        println!("approval_marker={marker}");
    }
    println!("approval_validated=true");
    println!("approval_applied={apply}");
    println!("producer_run_id={}", verified.manifest.producer.run_id);
    println!(
        "pull_request_number={}",
        verified.manifest.pull_request.number
    );
    println!(
        "request_head_sha={}",
        verified.manifest.pull_request.head_sha
    );
    Ok(())
}

struct NativeMergeRunIds {
    merge: u64,
    approval: u64,
}

fn apply_native_merge_from_runs(
    config_path: &std::path::Path,
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_ids: NativeMergeRunIds,
    pull_request_number: u64,
    expected_head_sha: &str,
    apply: bool,
) -> Result<()> {
    securefix::policy::validate_sha(expected_head_sha)?;
    ensure!(pull_request_number > 0, "invalid merge PR number");
    ensure!(
        producer_run_ids.merge > 0
            && producer_run_ids.approval > 0
            && producer_run_ids.merge != producer_run_ids.approval,
        "merge and approval proof must come from different successful runs"
    );

    let (merge_bytes, merge_bundle) = download_request_from_run(
        config_path,
        producer_repository,
        producer_run_ids.merge,
        securefix::policy::Capability::Merge,
    )?;
    let (approval_bytes, approval_bundle) = download_request_from_run(
        config_path,
        producer_repository,
        producer_run_ids.approval,
        securefix::policy::Capability::Approve,
    )?;
    let merge_manifest: RequestManifest =
        serde_json::from_slice(&merge_bytes).context("parse downloaded native merge request")?;
    let approval_manifest: RequestManifest = serde_json::from_slice(&approval_bytes)
        .context("parse downloaded native approval request")?;
    ensure!(
        merge_manifest.pull_request.number == pull_request_number
            && merge_manifest.pull_request.head_sha == expected_head_sha
            && approval_manifest.pull_request.number == pull_request_number
            && approval_manifest.pull_request.head_sha == expected_head_sha,
        "producer proofs do not match the owner-selected PR number and head"
    );

    let merge_directory = tempfile::tempdir()?;
    let merge_manifest_path = merge_directory.path().join("manifest.json");
    let merge_bundle_path = merge_directory.path().join("bundle.json");
    fs::write(&merge_manifest_path, merge_bytes)?;
    fs::write(&merge_bundle_path, merge_bundle)?;
    let approval_directory = tempfile::tempdir()?;
    let approval_manifest_path = approval_directory.path().join("manifest.json");
    let approval_bundle_path = approval_directory.path().join("bundle.json");
    fs::write(&approval_manifest_path, approval_bytes)?;
    fs::write(&approval_bundle_path, approval_bundle)?;

    let approval = verify_request(
        config_path,
        instance_config_path,
        &approval_manifest_path,
        &approval_bundle_path,
        securefix::api::NativeScratchMode::Approval,
        securefix::api::NativeScratchMode::Merge,
        false,
    )?;
    let merge = verify_request(
        config_path,
        instance_config_path,
        &merge_manifest_path,
        &merge_bundle_path,
        securefix::api::NativeScratchMode::Merge,
        securefix::api::NativeScratchMode::Merge,
        apply,
    )?;
    validate_native_merge_pair(&merge.manifest, &approval.manifest)?;
    validate_native_merge_readiness(&merge, &approval)?;

    if apply {
        let writer = merge
            .writer
            .as_ref()
            .context("native merge writer was not captured before apply")?;
        let sha = writer.merge_native_pull_request()?;
        println!("merge_commit_sha={sha}");
    }
    println!("merge_validated=true");
    println!("merge_applied={apply}");
    println!("producer_run_id={}", producer_run_ids.merge);
    println!("approval_producer_run_id={}", producer_run_ids.approval);
    println!("pull_request_number={pull_request_number}");
    println!("request_head_sha={expected_head_sha}");
    Ok(())
}

fn validate_native_merge_pair(merge: &RequestManifest, approval: &RequestManifest) -> Result<()> {
    ensure!(
        merge.operation == "merge"
            && approval.operation == "approval"
            && merge.producer.run_id != approval.producer.run_id
            && merge.repository == approval.repository
            && merge.pull_request == approval.pull_request
            && merge.server_authority == approval.server_authority,
        "native merge and approval proofs do not bind the same PR and Server authority"
    );
    Ok(())
}

fn validate_native_merge_readiness(
    merge: &VerifiedRequest,
    approval: &VerifiedRequest,
) -> Result<()> {
    validate_native_merge_pair(&merge.manifest, &approval.manifest)?;
    let manifest = &merge.manifest;
    let api = &merge.client_api;
    verify_current_pull_request(api, manifest)?;

    let current_policy_control = securefix::api::native_target_policy_control_identity(
        api,
        &manifest.repository.full_name,
        manifest.repository.id,
        &manifest.pull_request.base_ref,
    )?;
    let expected_control = merge
        .target_policy_control_identity
        .as_deref()
        .context("native merge request lacks its target policy control identity")?;
    ensure!(
        current_policy_control == expected_control,
        "native target policy control identity changed during request validation"
    );
    let expected_policy_id = format!("{}:{}", manifest.pull_request.head_sha, expected_control);

    let mut checks = Vec::new();
    for page in 1..=100 {
        let response: Value = api.get_uncached(&format!(
            "/repos/{}/commits/{}/check-runs?per_page=100&page={page}&filter=latest",
            manifest.repository.full_name, manifest.pull_request.head_sha
        ))?;
        let batch = response["check_runs"]
            .as_array()
            .context("native merge check runs are malformed")?;
        let done = batch.len() < 100;
        checks.extend(batch.iter().cloned());
        if done {
            break;
        }
        ensure!(
            page < 100,
            "native merge check run pagination exceeded limit"
        );
    }
    let checks_ok = native_merge_checks_ready(
        &checks,
        merge.config.apps.status_check_id,
        merge.config.apps.policy_check_id,
        &expected_policy_id,
    )?;

    let reviewer = &merge.config.identities.approval_reviewer;
    let approval_digest = securefix::hex_encode(Sha256::digest(&approval.manifest_bytes));
    let expected_marker = securefix::api::native_approval_body(
        &approval.manifest.server_authority,
        &approval.manifest.pull_request.head_sha,
        &approval_digest,
    )?["body"]
        .as_str()
        .context("native approval body has no marker")?
        .to_owned();
    let reviews = api.paginate_uncached(&format!(
        "/repos/{}/pulls/{}/reviews",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    let review_ok = has_native_approval_review(
        &reviews,
        reviewer.id,
        &reviewer.login,
        &manifest.pull_request.head_sha,
        &expected_marker,
    );
    let decision = api.graphql(
        "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}",
        serde_json::json!({
            "owner": manifest.repository.full_name.split('/').next().unwrap_or_default(),
            "name": manifest.repository.full_name.split('/').nth(1).unwrap_or_default(),
            "number": manifest.pull_request.number
        }),
    )?;
    ensure!(
        checks_ok
            && review_ok
            && decision["repository"]["pullRequest"]["reviewDecision"] == "APPROVED",
        "native merge requires current required checks and the exact native approval marker"
    );
    Ok(())
}

fn native_latest_check<'a>(checks: &'a [Value], name: &str, app_id: u64) -> Option<&'a Value> {
    checks
        .iter()
        .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
        .max_by_key(|check| check["id"].as_u64().unwrap_or_default())
}

fn native_merge_checks_ready(
    checks: &[Value],
    status_app_id: u64,
    policy_app_id: u64,
    expected_policy_id: &str,
) -> Result<bool> {
    let ci_ok = native_latest_check(checks, "status-check", status_app_id).is_some_and(|check| {
        check["status"] == "completed"
            && (check["conclusion"] == "success" || check["conclusion"] == "skipped")
    });
    let policy_checks: Vec<_> = checks
        .iter()
        .filter(|check| {
            check["name"] == "securefix-policy-check"
                && check["app"]["id"].as_u64() == Some(policy_app_id)
        })
        .collect();
    ensure!(
        policy_checks.len() <= 1,
        "duplicate Securefix policy checks for the native merge head"
    );
    let policy_ok = policy_checks.first().is_some_and(|check| {
        check["external_id"] == expected_policy_id
            && check["status"] == "completed"
            && check["conclusion"] == "success"
    });
    Ok(ci_ok && policy_ok)
}

fn has_native_approval_review(
    reviews: &[Value],
    reviewer_id: u64,
    reviewer_login: &str,
    expected_head: &str,
    expected_marker: &str,
) -> bool {
    let decisions = reviews
        .iter()
        .filter(|review| {
            matches!(
                review["state"].as_str(),
                Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
            ) && review["user"]["id"].as_u64() == Some(reviewer_id)
                && review["user"]["login"].as_str() == Some(reviewer_login)
                && review["user"]["type"] == "User"
        })
        .collect::<Vec<_>>();
    if decisions
        .iter()
        .any(|review| crate::request::review_order(review).is_none())
    {
        return false;
    }
    let latest = decisions
        .into_iter()
        .max_by_key(|review| crate::request::review_order(review));
    latest.is_some_and(|review| {
        review["state"] == "APPROVED"
            && review["commit_id"].as_str() == Some(expected_head)
            && review["body"].as_str() == Some(expected_marker)
    })
}

fn download_request_from_run(
    config_path: &std::path::Path,
    producer_repository: &str,
    producer_run_id: u64,
    capability: securefix::policy::Capability,
) -> Result<(Vec<u8>, Vec<u8>)> {
    securefix::policy::validate_repository(producer_repository)?;
    ensure!(producer_run_id > 0, "invalid producer run ID");
    let config_bytes = read_bounded(config_path, 256 * 1024)?;
    let config = securefix::instance_config::InstanceConfig::parse(&config_bytes)?;
    let target = config
        .repositories
        .iter()
        .find(|repository| repository.repository == producer_repository)
        .context("producer Client repository is not configured")?;
    target
        .policy()
        .require(capability)
        .context("producer Client repository lacks the required capability")?;
    let api = securefix::api::GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    let repository: Value = api.get(&format!("/repos/{producer_repository}"))?;
    ensure!(
        repository["id"].as_u64() == Some(target.id)
            && repository["full_name"].as_str() == Some(producer_repository),
        "producer Client repository identity mismatch"
    );
    let run: Value = api.get(&format!(
        "/repos/{producer_repository}/actions/runs/{producer_run_id}"
    ))?;
    ensure!(
        run["id"].as_u64() == Some(producer_run_id)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["repository"]["id"].as_u64() == Some(target.id)
            && run["repository"]["full_name"].as_str() == Some(producer_repository),
        "producer run is incomplete, unsuccessful, or belongs to another repository"
    );
    let artifacts: Value = api.get(&format!(
        "/repos/{producer_repository}/actions/runs/{producer_run_id}/artifacts?per_page=100"
    ))?;
    let rows = artifacts["artifacts"]
        .as_array()
        .context("producer artifact list is missing")?;
    ensure!(
        artifacts["total_count"].as_u64() == Some(rows.len() as u64),
        "producer artifact listing is incomplete"
    );
    let named: Vec<_> = rows
        .iter()
        .filter(|artifact| artifact["name"] == REQUEST_ARTIFACT_NAME)
        .collect();
    ensure!(
        named.len() == 1,
        "producer run must contain exactly one native request proof artifact"
    );
    let artifact_id = named[0]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("native request proof artifact ID is missing")?;
    let artifact: Value = api.get(&format!(
        "/repos/{producer_repository}/actions/artifacts/{artifact_id}"
    ))?;
    let (size, digest) = validate_request_artifact_metadata(
        &artifact,
        &run,
        artifact_id,
        producer_run_id,
        target.id,
    )?;
    let bytes = api.download(
        &format!("/repos/{producer_repository}/actions/artifacts/{artifact_id}/zip"),
        MAX_ARTIFACT_ARCHIVE_BYTES,
    )?;
    ensure!(
        bytes.len() as u64 == size && securefix::hex_encode(Sha256::digest(&bytes)) == digest,
        "native request proof artifact bytes differ from GitHub metadata"
    );
    let (manifest_bytes, bundle_bytes) = request_files_from_zip(&bytes)?;
    let manifest: RequestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse downloaded request manifest")?;
    manifest.validate()?;
    ensure!(
        manifest.producer.run_id == producer_run_id
            && manifest.repository.id == target.id
            && manifest.repository.full_name == producer_repository,
        "downloaded request does not identify the selected producer run and Client repository"
    );
    Ok((manifest_bytes, bundle_bytes))
}

fn validate_request_artifact_metadata(
    artifact: &Value,
    run: &Value,
    artifact_id: u64,
    producer_run_id: u64,
    repository_id: u64,
) -> Result<(u64, String)> {
    let size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_ARTIFACT_ARCHIVE_BYTES as u64)
        .context("native request proof artifact size is invalid")?;
    let digest = artifact["digest"]
        .as_str()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .context("native request proof artifact has no SHA-256 digest")?;
    crate::native_client::validate_artifact_run_binding(
        artifact,
        artifact_id,
        REQUEST_ARTIFACT_NAME,
        producer_run_id,
        repository_id,
        run["head_sha"]
            .as_str()
            .context("producer run head SHA is missing")?,
    )?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && artifact["expired"] == false,
        "native request proof artifact metadata does not match its producer run"
    );
    Ok((size, digest.to_owned()))
}

fn download_securefix_artifact(
    api: &securefix::api::GitHub,
    manifest: &RequestManifest,
    identity: &crate::native_client::SecurefixArtifactIdentity,
) -> Result<Vec<u8>> {
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    let repository = &manifest.repository.full_name;
    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{}/artifacts?per_page=100",
        manifest.producer.run_id
    ))?;
    let rows = artifacts["artifacts"]
        .as_array()
        .context("source run artifact list is missing")?;
    ensure!(
        artifacts["total_count"].as_u64() == Some(rows.len() as u64),
        "source run artifact list is incomplete"
    );
    let named: Vec<_> = rows
        .iter()
        .filter(|row| row["name"] == identity.name)
        .collect();
    ensure!(
        named.len() == 1 && named[0]["id"].as_u64() == Some(identity.id),
        "Securefix artifact ID is not the unique artifact with the accepted name"
    );
    let artifact: Value = api.get(&format!(
        "/repos/{repository}/actions/artifacts/{}",
        identity.id
    ))?;
    let size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_BYTES)
        .context("Securefix artifact size is invalid")?;
    crate::native_client::validate_artifact_run_binding(
        &artifact,
        identity.id,
        &identity.name,
        manifest.producer.run_id,
        manifest.repository.id,
        &manifest.producer.source_sha,
    )?;
    ensure!(
        artifact["digest"].as_str() == Some(identity.digest.as_str())
            && artifact["expired"] == false,
        "Securefix artifact metadata does not match the signed request"
    );
    let bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{}/zip", identity.id),
        MAX_BYTES as usize,
    )?;
    ensure!(
        bytes.len() as u64 == size
            && format!("sha256:{}", securefix::hex_encode(Sha256::digest(&bytes)))
                == identity.digest,
        "Securefix artifact bytes differ from the signed request digest"
    );
    Ok(bytes)
}

fn verify_artifact_binding(
    api: &securefix::api::GitHub,
    manifest: &RequestManifest,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    let run_artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{}/artifacts?per_page=100",
        manifest.producer.run_id
    ))?;
    let artifacts = run_artifacts["artifacts"]
        .as_array()
        .context("producer artifact list is missing")?;
    ensure!(
        run_artifacts["total_count"].as_u64() == Some(artifacts.len() as u64),
        "producer artifact listing is incomplete"
    );
    let matches: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact["name"] == REQUEST_ARTIFACT_NAME)
        .collect();
    ensure!(
        matches.len() == 1,
        "producer run must contain one native request artifact"
    );
    let artifact_id = matches[0]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("native request artifact ID is missing")?;
    let artifact: Value = api.get(&format!(
        "/repos/{repository}/actions/artifacts/{artifact_id}"
    ))?;
    ensure!(
        artifact["id"].as_u64() == Some(artifact_id)
            && artifact["name"] == REQUEST_ARTIFACT_NAME
            && artifact["expired"] == false
            && artifact["workflow_run"]["id"].as_u64() == Some(manifest.producer.run_id)
            && artifact["workflow_run"]["repository_id"].as_u64() == Some(manifest.repository.id)
            && artifact["workflow_run"]["head_sha"].as_str()
                == Some(manifest.producer.source_sha.as_str()),
        "native request artifact is not bound to the claimed producer run"
    );
    let declared_size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_ARTIFACT_ARCHIVE_BYTES as u64)
        .context("native request artifact size is invalid")?;
    let declared_digest = artifact["digest"]
        .as_str()
        .and_then(|value| value.strip_prefix("sha256:"))
        .context("native request artifact has no SHA-256 digest")?;
    ensure!(
        declared_digest.len() == 64
            && declared_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "native request artifact digest is not canonical SHA-256"
    );
    let zip_bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        MAX_ARTIFACT_ARCHIVE_BYTES,
    )?;
    ensure!(
        zip_bytes.len() as u64 == declared_size
            && securefix::hex_encode(Sha256::digest(&zip_bytes)) == declared_digest,
        "native request artifact bytes differ from GitHub metadata"
    );
    let (archived_manifest, archived_bundle) = request_files_from_zip(&zip_bytes)?;
    ensure!(
        archived_manifest == read_bounded(manifest_path, MAX_REQUEST_BYTES)?
            && archived_bundle == read_bounded(bundle_path, MAX_BUNDLE_BYTES)?,
        "local request files differ from the identified producer artifact"
    );
    Ok(())
}

fn request_files_from_zip(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() == 2,
        "request artifact must contain exactly two files"
    );
    let mut manifest = None;
    let mut bundle = None;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        ensure!(
            file.is_file()
                && file
                    .unix_mode()
                    .is_none_or(|mode| { matches!(mode & 0o170000, 0 | 0o100000) }),
            "request artifact contains a non-regular file"
        );
        let (slot, max) = match file.name() {
            "manifest.json" => (&mut manifest, MAX_REQUEST_BYTES),
            "bundle.json" => (&mut bundle, MAX_BUNDLE_BYTES),
            _ => anyhow::bail!("request artifact contains an unexpected file"),
        };
        ensure!(slot.is_none(), "request artifact contains a duplicate file");
        let size = file.size();
        ensure!(
            size <= max as u64,
            "request artifact file exceeds size limit"
        );
        let mut content = Vec::with_capacity(size as usize);
        (&mut file).take(max as u64 + 1).read_to_end(&mut content)?;
        ensure!(
            content.len() as u64 == size,
            "request artifact file size mismatch"
        );
        *slot = Some(content);
    }
    Ok((
        manifest.context("request artifact is missing manifest.json")?,
        bundle.context("request artifact is missing bundle.json")?,
    ))
}

fn verify_with_gh(
    manifest: &std::path::Path,
    bundle: &std::path::Path,
    attestation_repository: &str,
    signer_repository: &str,
    signer_workflow: &str,
    signer_sha: &str,
) -> Result<Value> {
    securefix::attestation::verify_with_gh(
        manifest,
        bundle,
        securefix::attestation::VerifyRequest {
            repository: attestation_repository,
            signer_repository,
            signer_workflow,
            signer_sha,
            source: None,
        },
    )
}

fn verify_certificate(
    verified: &Value,
    manifest: &RequestManifest,
    run: &Value,
    signer_repository: &str,
    signer_workflow: &str,
    signer_sha: &str,
    manifest_bytes: &[u8],
) -> Result<()> {
    ensure!(
        verified
            .as_array()
            .is_some_and(|results| results.len() == 1),
        "attestation verifier must return exactly one result"
    );
    let result = &verified[0]["verificationResult"];
    let certificate = &result["signature"]["certificate"];
    let statement = &result["statement"];
    let expected_run = format!(
        "https://github.com/{}/actions/runs/{}/attempts/{}",
        manifest.repository.full_name, manifest.producer.run_id, manifest.producer.run_attempt
    );
    let expected_signer =
        format!("https://github.com/{signer_repository}/{signer_workflow}@{signer_sha}");
    let expected_config_prefix = format!(
        "https://github.com/{}/{}@",
        manifest.repository.full_name, manifest.producer.workflow_path
    );
    let workflow_ref = certificate["githubWorkflowRef"]
        .as_str()
        .context("attestation caller workflow ref is missing")?;
    let expected_config = format!("{expected_config_prefix}{}", manifest.producer.workflow_ref);
    let owner_id = run["repository"]["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("producer repository owner ID is missing")?;
    ensure!(
        certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["githubWorkflowRepository"].as_str()
                == Some(manifest.repository.full_name.as_str())
            && certificate["githubWorkflowSHA"].as_str()
                == Some(manifest.producer.context_sha.as_str())
            && certificate["buildConfigDigest"].as_str()
                == Some(manifest.producer.workflow_sha.as_str())
            && workflow_ref == manifest.producer.workflow_ref
            && certificate["buildConfigURI"].as_str() == Some(expected_config.as_str())
            && certificate["githubWorkflowTrigger"].as_str()
                == Some(manifest.producer.event.as_str())
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", manifest.repository.full_name)
            && certificate["sourceRepositoryDigest"].as_str()
                == Some(manifest.producer.context_sha.as_str())
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(manifest.repository.id))
            && certificate["sourceRepositoryOwnerIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(owner_id))
            && certificate["runInvocationURI"].as_str() == Some(expected_run.as_str())
            && certificate["runnerEnvironment"] == "github-hosted"
            && certificate["buildSignerDigest"].as_str() == Some(signer_sha)
            && certificate["buildSignerURI"].as_str() == Some(expected_signer.as_str())
            && certificate["subjectAlternativeName"].as_str() == Some(expected_signer.as_str()),
        "attestation certificate does not match the configured producer run"
    );
    let expected_sha = securefix::hex_encode(Sha256::digest(manifest_bytes));
    let subjects = statement["subject"]
        .as_array()
        .context("attested subject is missing")?;
    ensure!(
        statement["predicateType"] == SLSA_PREDICATE
            && subjects.len() == 1
            && subjects[0]["name"] == "manifest.json"
            && subjects[0]["digest"]["sha256"].as_str() == Some(expected_sha.as_str()),
        "attestation subject differs from the request manifest bytes"
    );
    Ok(())
}

fn read_bounded(path: &std::path::Path, max: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len().min(max as u64) as usize);
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "{} exceeds size limit", path.display());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> RequestManifest {
        RequestManifest {
            protocol: "securefix-native-request/v1".to_owned(),
            operation: "policy_check".to_owned(),
            repository: crate::native_client::RepositoryIdentity {
                id: 10,
                full_name: "owner/project".to_owned(),
            },
            pull_request: crate::native_client::PullRequestIdentity {
                number: 7,
                head_sha: "d".repeat(40),
                head_branch: "scratch".to_owned(),
                head_repository_id: 10,
                base_sha: "e".repeat(40),
                base_ref: "main".to_owned(),
                author_id: 11,
                author_login: "contributor".to_owned(),
            },
            producer: crate::native_client::ProducerIdentity {
                run_id: 42,
                run_attempt: 2,
                event: "workflow_dispatch".to_owned(),
                context_sha: "f".repeat(40),
                source_sha: "a".repeat(40),
                workflow_path: ".github/workflows/client.yml".to_owned(),
                workflow_ref: "refs/heads/main".to_owned(),
                workflow_sha: "b".repeat(40),
                actor_id: 12,
                actor_login: "maintainer".to_owned(),
            },
            securefix_artifact: None,
            client_workflow_epoch: "4".repeat(40),
            server_authority: securefix::api::NativeAuthoritySnapshot {
                instance_repository: "example-org/securefix-server".to_owned(),
                instance_id: 404,
                default_branch: "main".to_owned(),
                config_path: "securefix-server.toml".to_owned(),
                config_sha256: "5".repeat(64),
                epoch: "6".repeat(40),
                workflows: vec![securefix::api::NativeWorkflowAuthority {
                    role: securefix::instance_config::WorkflowRole::PolicyCheck,
                    path: ".github/workflows/policy-check.yml".to_owned(),
                    sha256: "7".repeat(64),
                    pins: vec!["actions/checkout@".to_owned() + &"8".repeat(40)],
                }],
            },
        }
    }

    #[test]
    fn securefix_artifact_binds_protected_base_run_to_separate_pr_head() {
        let mut manifest = manifest();
        manifest.operation = "securefix".into();
        manifest.producer.event = "pull_request_target".into();
        manifest.pull_request.base_sha = "f".repeat(40);
        manifest.producer.context_sha = manifest.pull_request.base_sha.clone();
        manifest.producer.source_sha = manifest.pull_request.head_sha.clone();
        let fix = crate::securefix_gate::artifact::FixArtifact {
            repository: manifest.repository.full_name.clone(),
            branch: manifest.pull_request.head_branch.clone(),
            run_id: manifest.producer.run_id,
            source_sha: manifest.producer.source_sha.clone(),
            event_name: "pull_request_target".into(),
            pull_request_context: Some(
                crate::securefix_gate::artifact::PullRequestArtifactContext {
                    number: manifest.pull_request.number,
                    head_sha: manifest.pull_request.head_sha.clone(),
                    head_branch: manifest.pull_request.head_branch.clone(),
                    head_repository_id: manifest.pull_request.head_repository_id,
                    head_repository: manifest.repository.full_name.clone(),
                    base_sha: manifest.pull_request.base_sha.clone(),
                    base_branch: manifest.pull_request.base_ref.clone(),
                    base_repository_id: manifest.repository.id,
                    base_repository: manifest.repository.full_name.clone(),
                },
            ),
            commit_message: "test".into(),
            create_pull_request: None,
            additions: std::collections::BTreeMap::from([("README.md".into(), b"test".to_vec())]),
            deletions: vec![],
        };
        assert!(validate_securefix_artifact_context(&manifest, "scratch", &fix).is_ok());
        assert!(validate_securefix_artifact_context(&manifest, "main", &fix).is_err());

        let mut changed = fix;
        changed.pull_request_context.as_mut().unwrap().head_sha = "e".repeat(40);
        assert!(validate_securefix_artifact_context(&manifest, "scratch", &changed).is_err());
        changed.pull_request_context.as_mut().unwrap().head_sha =
            manifest.pull_request.head_sha.clone();
        changed.pull_request_context.as_mut().unwrap().base_sha = "9".repeat(40);
        assert!(validate_securefix_artifact_context(&manifest, "scratch", &changed).is_err());
    }

    fn verifier_result(manifest: &RequestManifest, run_invocation: String) -> Value {
        let bytes = serde_json::to_vec(manifest).unwrap();
        let subject_sha = securefix::hex_encode(Sha256::digest(&bytes));
        let signer_sha = "c".repeat(40);
        let signer = format!(
            "https://github.com/client-org/securefix-client/.github/workflows/request-producer.yml@{signer_sha}"
        );
        let config = format!(
            "https://github.com/{}/{}@{}",
            manifest.repository.full_name,
            manifest.producer.workflow_path,
            manifest.producer.workflow_ref
        );
        serde_json::json!([{
            "verificationResult": {
                "signature": { "certificate": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "githubWorkflowRepository": manifest.repository.full_name,
                    "githubWorkflowSHA": manifest.producer.context_sha,
                    "buildConfigDigest": manifest.producer.workflow_sha,
                    "buildConfigURI": config,
                    "githubWorkflowRef": manifest.producer.workflow_ref,
                    "githubWorkflowTrigger": manifest.producer.event,
                    "sourceRepositoryURI": format!("https://github.com/{}", manifest.repository.full_name),
                    "sourceRepositoryDigest": manifest.producer.context_sha,
                    "sourceRepositoryIdentifier": "10",
                    "sourceRepositoryOwnerIdentifier": "20",
                    "runInvocationURI": run_invocation,
                    "runnerEnvironment": "github-hosted",
                    "buildSignerDigest": signer_sha,
                    "buildSignerURI": signer,
                    "subjectAlternativeName": signer
                }},
                "statement": {
                    "predicateType": SLSA_PREDICATE,
                    "subject": [{"name":"manifest.json","digest":{"sha256":subject_sha}}],
                    "predicate": {"runDetails":{"metadata":{"invocationId":"untrusted"}}}
                }
            }
        }])
    }

    #[test]
    fn accepts_attested_run_head_context_and_workflow_shas_as_distinct_claims() {
        let manifest = manifest();
        let run = serde_json::json!({
            "head_branch":"testing/pr-head",
            "repository":{"owner":{"id":20}}
        });
        let invocation = "https://github.com/owner/project/actions/runs/42/attempts/2";
        let verified = verifier_result(&manifest, invocation.to_owned());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(
            verify_certificate(
                &verified,
                &manifest,
                &run,
                "client-org/securefix-client",
                ".github/workflows/request-producer.yml",
                &"c".repeat(40),
                &bytes,
            )
            .is_ok()
        );
        assert_ne!(manifest.producer.source_sha, manifest.producer.context_sha);
        assert_ne!(
            manifest.producer.context_sha,
            manifest.producer.workflow_sha
        );
    }

    #[test]
    fn pull_request_target_binds_run_head_and_context_sha_to_separate_pr_facts() {
        let mut manifest = manifest();
        manifest.producer.event = "pull_request_target".to_owned();
        manifest.producer.source_sha = "a499b4ede1752c1ddb83e0651d74d1ce73faa76d".to_owned();
        manifest.pull_request.head_sha = manifest.producer.source_sha.clone();
        manifest.pull_request.head_branch =
            "testing/native-producer-trigger-20261021-c80e".to_owned();
        manifest.producer.context_sha = "ceb1faee17b5c13817b089dc5f956ba472b0b43f".to_owned();
        manifest.pull_request.base_sha = manifest.producer.context_sha.clone();

        assert!(
            verify_run_identity(
                &serde_json::json!({
                    "id":42,"run_attempt":2,"status":"completed","conclusion":"success",
                    "event":"pull_request_target","head_sha":manifest.producer.source_sha,
                    "head_branch":manifest.pull_request.head_branch,
                    "repository":{"id":10,"full_name":"owner/project"},
                    "actor":{"id":12,"login":"maintainer"},
                    "path":".github/workflows/client.yml"
                }),
                &manifest
            )
            .is_ok()
        );

        let wrong_attempt = serde_json::json!({
            "id":42,"run_attempt":1,"status":"completed","conclusion":"success",
            "event":"pull_request_target","head_sha":manifest.producer.source_sha,
            "head_branch":manifest.pull_request.head_branch,
            "repository":{"id":10,"full_name":"owner/project"},
            "actor":{"id":12,"login":"maintainer"},
            "path":".github/workflows/client.yml"
        });
        assert!(verify_run_identity(&wrong_attempt, &manifest).is_err());

        assert!(
            crate::native_client::validate_pull_request_target_identity(
                "pull_request_target",
                "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
                "ceb1faee17b5c13817b089dc5f956ba472b0b43f",
                "testing/native-producer-trigger-20261021-c80e",
                "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
                "testing/native-producer-trigger-20261021-c80e",
                "ceb1faee17b5c13817b089dc5f956ba472b0b43f",
            )
            .is_ok()
        );
        assert!(
            crate::native_client::validate_pull_request_target_identity(
                "pull_request_target",
                "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
                "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
                "testing/native-producer-trigger-20261021-c80e",
                "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
                "testing/native-producer-trigger-20261021-c80e",
                "ceb1faee17b5c13817b089dc5f956ba472b0b43f",
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_replayed_run_and_predicate_only_provenance() {
        let manifest = manifest();
        let run = serde_json::json!({
            "head_branch":"main",
            "repository":{"owner":{"id":20}}
        });
        let verified = verifier_result(
            &manifest,
            "https://github.com/owner/project/actions/runs/41/attempts/2".to_owned(),
        );
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(
            verify_certificate(
                &verified,
                &manifest,
                &run,
                "client-org/securefix-client",
                ".github/workflows/request-producer.yml",
                &"c".repeat(40),
                &bytes,
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reader_stops_after_limit_plus_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large");
        fs::write(&path, vec![b'x'; 64]).unwrap();
        assert!(read_bounded(&path, 32).is_err());
    }

    #[test]
    fn request_artifact_requires_exact_bounded_regular_files() {
        fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
            let cursor = std::io::Cursor::new(Vec::new());
            let mut writer = zip::ZipWriter::new(cursor);
            for (name, bytes) in entries {
                writer
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut writer, bytes).unwrap();
            }
            writer.finish().unwrap().into_inner()
        }
        let manifest = b"{}";
        let bundle = b"{}";
        let valid = archive(&[("manifest.json", manifest), ("bundle.json", bundle)]);
        assert_eq!(
            request_files_from_zip(&valid).unwrap(),
            (manifest.to_vec(), bundle.to_vec())
        );
        let forged = archive(&[("manifest.json", manifest)]);
        assert!(request_files_from_zip(&forged).is_err());
        let extra = archive(&[
            ("manifest.json", manifest),
            ("bundle.json", bundle),
            ("extra.txt", b"x"),
        ]);
        assert!(request_files_from_zip(&extra).is_err());
    }

    #[test]
    fn first_slice_policy_requires_configured_merge_owner_actor_and_author() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();
        assert_ne!(config.instance.repository, request.repository.full_name);
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
            )
            .is_ok()
        );

        request.producer.actor_id = 12;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
            )
            .is_err()
        );
        request.producer.actor_id = 101;
        request.pull_request.author_login = "contributor".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
            )
            .is_err()
        );
    }

    #[test]
    fn securefix_first_slice_requires_securefix_capability() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Securefix,
            )
            .is_ok()
        );

        request.repository.id += 1;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Securefix,
            )
            .is_err()
        );
    }

    #[test]
    fn native_approval_requires_approve_capability_and_owner_request() {
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.operation = "approval".to_owned();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Approval,
            )
            .is_ok()
        );

        config.repositories[0]
            .capabilities
            .retain(|capability| *capability != securefix::policy::Capability::Approve);
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Approval,
            )
            .is_err()
        );

        config.repositories[0]
            .capabilities
            .push(securefix::policy::Capability::Approve);
        request.producer.actor_id = 12;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Approval,
            )
            .is_err()
        );
    }

    #[test]
    fn native_merge_requires_merge_capability_and_owner_request() {
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.operation = "merge".to_owned();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Merge,
            )
            .is_ok()
        );

        config.repositories[0]
            .capabilities
            .retain(|capability| *capability != securefix::policy::Capability::Merge);
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Merge,
            )
            .is_err()
        );
    }

    #[test]
    fn native_merge_requires_paired_proofs_and_the_exact_latest_approval_marker() {
        let mut merge = manifest();
        merge.operation = "merge".to_owned();
        let mut approval = merge.clone();
        approval.operation = "approval".to_owned();
        approval.producer.run_id += 1;
        validate_native_merge_pair(&merge, &approval).unwrap();

        let mut stale_authority = approval.clone();
        stale_authority.server_authority.epoch.push('a');
        assert!(validate_native_merge_pair(&merge, &stale_authority).is_err());
        let mut stale_head = approval.clone();
        stale_head.pull_request.head_sha = "f".repeat(40);
        assert!(validate_native_merge_pair(&merge, &stale_head).is_err());
        let same_run = approval.clone();
        let mut same_run = same_run;
        same_run.producer.run_id = merge.producer.run_id;
        assert!(validate_native_merge_pair(&merge, &same_run).is_err());

        let approval_bytes = serde_json::to_vec(&approval).unwrap();
        let approval_digest = crate::hex_encode(Sha256::digest(&approval_bytes));
        let marker = securefix::api::native_approval_body(
            &approval.server_authority,
            &approval.pull_request.head_sha,
            &approval_digest,
        )
        .unwrap()["body"]
            .as_str()
            .unwrap()
            .to_owned();
        let review = serde_json::json!({
            "id": 10,
            "state": "APPROVED",
            "submitted_at": "2026-10-22T00:00:00Z",
            "commit_id": merge.pull_request.head_sha,
            "body": marker,
            "user": {"id": 20, "login": "reviewer", "type": "User"}
        });
        assert!(has_native_approval_review(
            std::slice::from_ref(&review),
            20,
            "reviewer",
            &merge.pull_request.head_sha,
            &marker
        ));
        let mut old_marker = review.clone();
        old_marker["body"] = serde_json::json!("<!-- securefix:control-review:old -->");
        assert!(!has_native_approval_review(
            &[old_marker],
            20,
            "reviewer",
            &merge.pull_request.head_sha,
            &marker
        ));
        let mut dismissed = review.clone();
        dismissed["id"] = 11.into();
        dismissed["submitted_at"] = serde_json::json!("2026-10-22T00:01:00Z");
        dismissed["state"] = "DISMISSED".into();
        assert!(!has_native_approval_review(
            &[review, dismissed],
            20,
            "reviewer",
            &merge.pull_request.head_sha,
            &marker
        ));

        let checks = vec![
            serde_json::json!({
                "id": 1,
                "name": "status-check",
                "status": "completed",
                "conclusion": "success",
                "app": {"id": 701}
            }),
            serde_json::json!({
                "id": 2,
                "name": "securefix-policy-check",
                "status": "completed",
                "conclusion": "success",
                "external_id": "head:control",
                "app": {"id": 502}
            }),
        ];
        assert!(native_merge_checks_ready(&checks, 701, 502, "head:control").unwrap());
        assert!(!native_merge_checks_ready(&checks, 701, 502, "head:stale").unwrap());
        let mut failed_ci = checks.clone();
        failed_ci[0]["conclusion"] = "failure".into();
        assert!(!native_merge_checks_ready(&failed_ci, 701, 502, "head:control").unwrap());
        let mut duplicate = checks.clone();
        duplicate.push(checks[1].clone());
        assert!(native_merge_checks_ready(&duplicate, 701, 502, "head:control").is_err());
    }

    #[test]
    fn native_merge_policy_check_is_bound_to_the_target_controller_not_server_instance() {
        let server_control: securefix::control::ControlRevision = serde_json::from_slice(
            include_bytes!("../tests/fixtures/native-server-instance-control.json"),
        )
        .unwrap();
        let target_control: securefix::control::ControlRevision = serde_json::from_slice(
            include_bytes!("../tests/fixtures/native-target-control.json"),
        )
        .unwrap();
        let server_identity = server_control.identity().unwrap();
        let target_identity = target_control.identity().unwrap();
        assert_ne!(server_identity, target_identity);

        let head = "f".repeat(40);
        let checks = vec![
            serde_json::json!({
                "id": 1,
                "name": "status-check",
                "status": "completed",
                "conclusion": "success",
                "app": {"id": 701}
            }),
            serde_json::json!({
                "id": 2,
                "name": "securefix-policy-check",
                "status": "completed",
                "conclusion": "success",
                "external_id": format!("{head}:{target_identity}"),
                "app": {"id": 502}
            }),
        ];
        assert!(
            native_merge_checks_ready(&checks, 701, 502, &format!("{head}:{target_identity}"))
                .unwrap()
        );
        assert!(
            !native_merge_checks_ready(&checks, 701, 502, &format!("{head}:{server_identity}"))
                .unwrap()
        );
    }

    #[test]
    fn native_repository_policy_rejects_missing_capability_and_wrong_identity() {
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();

        config.repositories[0]
            .capabilities
            .retain(|capability| *capability != securefix::policy::Capability::Securefix);
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Securefix,
            )
            .is_err()
        );

        config.repositories[0]
            .capabilities
            .push(securefix::policy::Capability::Securefix);
        request.repository.id += 1;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Securefix,
            )
            .is_err()
        );
    }

    #[test]
    fn server_authority_and_client_request_identity_are_separate() {
        let server = securefix::api::NativeAuthoritySnapshot {
            instance_repository: "example-org/securefix-server".to_owned(),
            instance_id: 404,
            default_branch: "main".to_owned(),
            config_path: "securefix-server.toml".to_owned(),
            config_sha256: "a".repeat(64),
            epoch: "b".repeat(40),
            workflows: vec![securefix::api::NativeWorkflowAuthority {
                role: securefix::instance_config::WorkflowRole::PolicyCheck,
                path: ".github/workflows/policy-check.yml".to_owned(),
                sha256: "c".repeat(64),
                pins: vec![
                    "owner/server/.github/actions/install-cli@".to_owned() + &"d".repeat(40),
                ],
            }],
        };
        assert!(securefix::api::require_native_authority_unchanged(&server, &server).is_ok());
        let mut other_instance = server.clone();
        other_instance.instance_id += 1;
        assert!(
            securefix::api::require_native_authority_unchanged(&server, &other_instance).is_err()
        );
        let mut changed_role_pin = server.clone();
        changed_role_pin.workflows[0].pins[0].push('e');
        assert!(
            securefix::api::require_native_authority_unchanged(&server, &changed_role_pin).is_err()
        );

        let request = manifest();
        let serialized = serde_json::to_value(request).unwrap();
        assert!(serialized.get("client_workflow_epoch").is_some());
        assert!(serialized.get("authority").is_none());
        assert!(serialized.get("server_authority").is_some());
    }

    #[test]
    fn request_server_locator_must_match_authenticated_instance_and_config_path() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        assert!(
            validate_request_server_locator(
                &config,
                "securefix-server.toml",
                &request.server_authority
            )
            .is_ok()
        );
        request.server_authority.config_path = "another-config.toml".to_owned();
        assert!(
            validate_request_server_locator(
                &config,
                "securefix-server.toml",
                &request.server_authority
            )
            .is_err()
        );
        request.server_authority.config_path = "securefix-server.toml".to_owned();
        request.server_authority.instance_repository = "attacker/securefix-server".to_owned();
        assert!(
            validate_request_server_locator(
                &config,
                "securefix-server.toml",
                &request.server_authority
            )
            .is_err()
        );
    }

    #[test]
    fn stale_pull_request_head_is_rejected() {
        let mut request = manifest();
        request.pull_request.author_id = request.producer.actor_id;
        request.pull_request.author_login = request.producer.actor_login.clone();
        let repo = serde_json::json!({
            "id":10,"full_name":"owner/project","default_branch":"main"
        });
        let pull = serde_json::json!({
            "number":7,"state":"open",
            "base":{"repo":{"id":10,"full_name":"owner/project"},"ref":"main","sha":request.pull_request.base_sha},
            "head":{"repo":{"id":10},"ref":request.pull_request.head_branch,"sha":request.pull_request.head_sha},
            "user":{"id":12,"login":"maintainer"}
        });
        assert!(validate_current_pull_request_state(&repo, &pull, &request).is_ok());
        request.pull_request.head_sha = "e".repeat(40);
        assert!(validate_current_pull_request_state(&repo, &pull, &request).is_err());
        request.pull_request.head_sha = "d".repeat(40);
        request.pull_request.base_sha = "f".repeat(40);
        assert!(validate_current_pull_request_state(&repo, &pull, &request).is_err());
    }

    #[test]
    fn request_artifact_metadata_is_bound_to_selected_run_and_repository() {
        let run = serde_json::json!({
            "id":42,"run_attempt":2,"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let artifact = serde_json::json!({
            "id":99,"name":REQUEST_ARTIFACT_NAME,"expired":false,
            "size_in_bytes":123,"digest":format!("sha256:{}", "b".repeat(64)),
            "workflow_run":{
                "id":42,"repository_id":10,
                "head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        });
        assert_eq!(
            validate_request_artifact_metadata(&artifact, &run, 99, 42, 10).unwrap(),
            (123, "b".repeat(64))
        );

        for (field, value) in [
            ("id", serde_json::json!(43)),
            ("repository_id", serde_json::json!(11)),
            ("head_sha", serde_json::json!("c".repeat(40))),
        ] {
            let mut changed = artifact.clone();
            changed["workflow_run"][field] = value;
            assert!(
                validate_request_artifact_metadata(&changed, &run, 99, 42, 10).is_err(),
                "accepted changed workflow_run.{field}"
            );
        }

        let mut uppercase_digest = artifact;
        uppercase_digest["digest"] = format!("sha256:{}", "B".repeat(64)).into();
        assert!(validate_request_artifact_metadata(&uppercase_digest, &run, 99, 42, 10).is_err());
    }
}
