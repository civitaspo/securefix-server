//! Receiver-side validation for the native request protocol.
//!
//! Requests are bounded manifests whose GitHub artifact attestations are verified
//! by the official `gh` verifier. Scratch and normal instance authority stay on
//! separate write paths.

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
const REQUEST_PROTOCOL: &str = "securefix-native-request/v1";

#[derive(clap::Subcommand)]
pub enum CommandArgs {
    #[command(about = "Validate a native request label event and resolve its producer run")]
    LocateInstanceEvent {
        #[arg(long, default_value = "securefix-server.toml")]
        config_path: String,
        #[arg(long)]
        operation: String,
    },
    #[command(about = "Validate one scratch native request and its producer attestation")]
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
    #[command(about = "Validate one attested policy-check request selected by producer run")]
    PolicyCheckRun {
        /// Explicit path, relative to the authenticated Server repository root.
        #[arg(long)]
        config_path: String,
        /// Client repository that owns the producer run; validated against protected config.
        #[arg(long)]
        producer_repository: String,
        /// Successful Client workflow run containing the request proof artifact.
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        expected_head_sha: String,
        /// Create the scratch-only proof check after all current-state fences pass.
        #[arg(long, default_value_t = false)]
        publish: bool,
    },
    #[command(about = "Validate and publish a normal instance-bound native policy check")]
    InstancePolicyCheckRun {
        #[arg(long, default_value = "securefix-server.toml")]
        config_path: String,
        #[arg(long)]
        producer_repository: String,
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long, default_value_t = false)]
        publish: bool,
        /// Owner-dispatched scratch package qualification; still enforces ordinary Client command policy.
        #[arg(long, default_value_t = false)]
        owner_selected_test_package: bool,
    },
    #[command(about = "Validate and apply a normal instance-bound Securefix request")]
    InstanceSecurefixApply {
        #[arg(long, default_value = "securefix-server.toml")]
        config_path: String,
        #[arg(long)]
        producer_repository: String,
        #[arg(long)]
        producer_run_id: u64,
        /// Owner-dispatched scratch package qualification; still enforces ordinary Client request policy.
        #[arg(long, default_value_t = false)]
        owner_selected_test_package: bool,
    },
    #[command(about = "Validate and apply a normal instance-bound owner approval")]
    InstanceApproval {
        #[arg(long, default_value = "securefix-server.toml")]
        config_path: String,
        #[arg(long)]
        producer_repository: String,
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long, default_value_t = false)]
        apply: bool,
        /// Owner-dispatched scratch package qualification; still requires a real owner command comment.
        #[arg(long, default_value_t = false)]
        owner_selected_test_package: bool,
    },
    #[command(about = "Validate and apply a normal instance-bound merge request")]
    InstanceMerge {
        #[arg(long, default_value = "securefix-server.toml")]
        config_path: String,
        #[arg(long)]
        producer_repository: String,
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long, default_value_t = false)]
        apply: bool,
        /// Owner-dispatched scratch package qualification; still requires real merge and approval comments.
        #[arg(long, default_value_t = false)]
        owner_selected_test_package: bool,
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
        CommandArgs::LocateInstanceEvent {
            config_path,
            operation,
        } => locate_instance_event(&config_path, &operation),
        CommandArgs::PolicyCheck {
            config: _config,
            config_path,
            manifest,
            bundle,
            publish,
        } => {
            let verified = verify_request(
                &config_path,
                &manifest,
                &bundle,
                securefix::api::NativeScratchMode::PolicyCheck,
                securefix::api::NativeScratchMode::PolicyCheck,
                publish,
            )?;
            if publish {
                publish_request_proof_check(&verified)?;
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
        CommandArgs::PolicyCheckRun {
            config_path,
            producer_repository,
            producer_run_id,
            pull_request_number,
            expected_head_sha,
            publish,
        } => run_policy_check_from_run(
            &config_path,
            &producer_repository,
            producer_run_id,
            Some((pull_request_number, expected_head_sha)),
            publish,
            true,
            false,
        ),
        CommandArgs::InstancePolicyCheckRun {
            config_path,
            producer_repository,
            producer_run_id,
            publish,
            owner_selected_test_package,
        } => run_policy_check_from_run(
            &config_path,
            &producer_repository,
            producer_run_id,
            None,
            publish,
            false,
            owner_selected_test_package,
        ),
        CommandArgs::SecurefixApply {
            config: _config,
            config_path,
            producer_repository,
            producer_run_id,
        } => apply_securefix_from_run(&config_path, &producer_repository, producer_run_id),
        CommandArgs::InstanceSecurefixApply {
            config_path,
            producer_repository,
            producer_run_id,
            owner_selected_test_package,
        } => apply_securefix_from_run_mode(
            &config_path,
            &producer_repository,
            producer_run_id,
            false,
            owner_selected_test_package,
        ),
        CommandArgs::Approval {
            config: _config,
            config_path,
            producer_repository,
            producer_run_id,
            pull_request_number,
            expected_head_sha,
            apply,
        } => apply_native_approval_from_run(
            &config_path,
            &producer_repository,
            producer_run_id,
            Some((pull_request_number, expected_head_sha)),
            apply,
            true,
            false,
        ),
        CommandArgs::InstanceApproval {
            config_path,
            producer_repository,
            producer_run_id,
            apply,
            owner_selected_test_package,
        } => apply_native_approval_from_run(
            &config_path,
            &producer_repository,
            producer_run_id,
            None,
            apply,
            false,
            owner_selected_test_package,
        ),
        CommandArgs::Merge {
            config: _config,
            config_path,
            producer_repository,
            producer_run_id,
            approval_producer_run_id,
            pull_request_number,
            expected_head_sha,
            apply,
        } => apply_native_merge_from_runs(
            &config_path,
            &producer_repository,
            NativeMergeRunIds {
                merge: producer_run_id,
                approval: approval_producer_run_id,
            },
            Some((pull_request_number, expected_head_sha)),
            apply,
            true,
            false,
        ),
        CommandArgs::InstanceMerge {
            config_path,
            producer_repository,
            producer_run_id,
            apply,
            owner_selected_test_package,
        } => apply_native_merge_from_runs(
            &config_path,
            &producer_repository,
            NativeMergeRunIds {
                merge: producer_run_id,
                approval: 0,
            },
            None,
            apply,
            false,
            owner_selected_test_package,
        ),
    }
}

fn locate_instance_event(config_path: &str, operation: &str) -> Result<()> {
    let expected_role = native_operation_role(operation)?;
    let (server_api, captured) = capture_remote_instance_authority(config_path)?;
    let config = &captured.config;
    let event_path = std::env::var("GITHUB_EVENT_PATH")
        .context("missing GITHUB_EVENT_PATH for native request event")?;
    let payload: Value = serde_json::from_slice(&fs::read(event_path)?)
        .context("parse native request label event")?;
    let server_repository = std::env::var("GITHUB_REPOSITORY")
        .context("missing GITHUB_REPOSITORY for native Server event")?;
    ensure!(
        payload["action"] == "created"
            && payload["repository"]["full_name"].as_str() == Some(server_repository.as_str())
            && server_repository == config.instance.repository,
        "native request event is not a newly created label in the authenticated Server instance"
    );
    let client_bot = &config.identities.client_bot;
    ensure!(
        crate::request::matches_principal(
            &payload["sender"],
            client_bot.id,
            &client_bot.login,
            "Bot"
        ),
        "native request label was not created by the configured Client App"
    );
    let (repository, run_id) = native_request_event_locator(&payload, expected_role)?;
    let capability = match operation {
        "policy_check" | "merge" => securefix::policy::Capability::Merge,
        "approval" => securefix::policy::Capability::Approve,
        "securefix" => securefix::policy::Capability::Securefix,
        _ => anyhow::bail!("unsupported native request operation"),
    };
    config
        .repositories
        .iter()
        .find(|configured| configured.repository == repository)
        .with_context(|| format!("native request repository {repository} is not configured"))?
        .policy()
        .require(capability)?;
    ensure!(
        captured.authority.instance_repository == server_repository,
        "native Server instance authority does not match the event repository"
    );
    server_api.require_remote_native_server_instance_authority_unchanged(&captured)?;
    let (owner, repository_name) = repository
        .split_once('/')
        .context("producer repository must contain owner/name")?;
    securefix::output("producer_repository", &repository)?;
    securefix::output("producer_owner", owner)?;
    securefix::output("producer_repository_name", repository_name)?;
    securefix::output("producer_run_id", run_id.to_string())?;
    securefix::output("operation", operation)?;
    securefix::output("server_app_id", config.apps.server_id.to_string())?;
    securefix::output("client_app_id", config.apps.client_id.to_string())?;
    securefix::output(
        "status_check_app_id",
        config.apps.status_check_id.to_string(),
    )?;
    securefix::output(
        "policy_check_app_id",
        config.apps.policy_check_id.to_string(),
    )?;
    Ok(())
}

fn native_operation_role(operation: &str) -> Result<&'static str> {
    match operation {
        "policy_check" => Ok("policy-check"),
        "securefix" => Ok("securefix"),
        "approval" => Ok("approve"),
        "merge" => Ok("merge"),
        _ => anyhow::bail!("unsupported native request operation"),
    }
}

pub(crate) fn native_request_event_locator(payload: &Value, role: &str) -> Result<(String, u64)> {
    let label = payload["label"]["name"]
        .as_str()
        .context("native label event has no name")?;
    let prefix = format!("securefix-native-{role}-");
    let run_id = label
        .strip_prefix(&prefix)
        .context("native label event has the wrong operation")?
        .parse::<u64>()?;
    ensure!(run_id > 0, "native label has invalid producer run ID");
    let description = payload["label"]["description"]
        .as_str()
        .context("native label event has no producer locator")?;
    let (repository, described_run_id) = description
        .rsplit_once('/')
        .context("native label locator must be owner/repository/run_id")?;
    securefix::policy::validate_repository(repository)?;
    ensure!(
        described_run_id.parse::<u64>()? == run_id,
        "native label name and producer locator disagree"
    );
    Ok((repository.to_owned(), run_id))
}

fn validate_native_request_event(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    execution_mode: securefix::api::NativeScratchMode,
) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("label"),
        "normal native requests must be received from a Server label event"
    );
    let event_path = std::env::var("GITHUB_EVENT_PATH")
        .context("missing GITHUB_EVENT_PATH for native request verification")?;
    let payload: Value = serde_json::from_slice(&fs::read(event_path)?)
        .context("parse native request label event")?;
    validate_native_request_event_payload(config, manifest, &payload, execution_mode)
}

fn validate_native_request_event_payload(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    payload: &Value,
    execution_mode: securefix::api::NativeScratchMode,
) -> Result<()> {
    ensure!(
        payload["action"] == "created"
            && payload["repository"]["full_name"].as_str()
                == Some(config.instance.repository.as_str()),
        "native request did not originate from a newly created Server label"
    );
    let client_bot = &config.identities.client_bot;
    ensure!(
        crate::request::matches_principal(
            &payload["sender"],
            client_bot.id,
            &client_bot.login,
            "Bot"
        ),
        "native request label was not created by the configured Client App"
    );
    let paired_approval = execution_mode == securefix::api::NativeScratchMode::Merge
        && manifest.operation == "approval";
    // The merge request owns the event; its approval is bound by the review marker and pair check.
    let role = native_operation_role(if paired_approval {
        "merge"
    } else {
        &manifest.operation
    })?;
    let (repository, run_id) = native_request_event_locator(payload, role)?;
    ensure!(
        repository == manifest.repository.full_name
            && if paired_approval {
                run_id != manifest.producer.run_id
            } else {
                run_id == manifest.producer.run_id
            },
        "native request manifest does not match the triggering Server label"
    );
    if config.scratch_package_repository.is_some() {
        validate_owner_selected_request_caller(config, manifest)?;
        let owner = &config.identities.owner;
        let server = &config.identities.server_bot;
        let owner_producer =
            owner.id == manifest.producer.actor_id && owner.login == manifest.producer.actor_login;
        let server_policy_producer = manifest.operation == "policy_check"
            && server.id == manifest.producer.actor_id
            && server.login == manifest.producer.actor_login;
        let owner_author = owner.id == manifest.pull_request.author_id
            && owner.login == manifest.pull_request.author_login;
        let server_author = server.id == manifest.pull_request.author_id
            && server.login == manifest.pull_request.author_login;
        ensure!(
            (owner_producer || server_policy_producer) && (owner_author || server_author),
            "scratch package requests require owner commands or Server policy production and an owner or Server PR author"
        );
    }
    Ok(())
}

fn run_policy_check_from_run(
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
    expected_target: Option<(u64, String)>,
    publish: bool,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<()> {
    if let Some((pull_request_number, expected_head_sha)) = &expected_target {
        securefix::policy::validate_sha(expected_head_sha)?;
        ensure!(*pull_request_number > 0, "invalid policy-check PR number");
    }
    let (manifest_bytes, bundle_bytes) = download_request_from_run(
        instance_config_path,
        producer_repository,
        producer_run_id,
        securefix::policy::Capability::Merge,
    )?;
    let manifest: RequestManifest = serde_json::from_slice(&manifest_bytes)
        .context("parse downloaded native policy-check request")?;
    if let Some((pull_request_number, expected_head_sha)) = expected_target.as_ref() {
        validate_policy_check_request_locator(
            &manifest,
            producer_run_id,
            producer_repository,
            *pull_request_number,
            expected_head_sha,
        )?;
    } else {
        ensure!(
            manifest.operation == "policy_check"
                && manifest.producer.run_id == producer_run_id
                && manifest.repository.full_name == producer_repository,
            "producer request does not match the authenticated policy-check label"
        );
    }
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, bundle_bytes)?;
    let verified = verify_request_with_deployment(
        instance_config_path,
        &manifest_path,
        &bundle_path,
        securefix::api::NativeScratchMode::PolicyCheck,
        securefix::api::NativeScratchMode::PolicyCheck,
        publish,
        scratch,
        owner_selected_test_package,
    )?;
    if publish {
        publish_request_proof_check(&verified)?;
    }
    println!(
        "request_sha256={}",
        securefix::hex_encode(Sha256::digest(&verified.manifest_bytes))
    );
    println!("producer_run_id={producer_run_id}");
    println!("pull_request_number={}", manifest.pull_request.number);
    println!("request_head_sha={}", manifest.pull_request.head_sha);
    println!("result_published={publish}");
    let (target_owner, target_repository) = manifest
        .repository
        .full_name
        .split_once('/')
        .context("validated Client repository has no owner/name separator")?;
    securefix::output("target_owner", target_owner)?;
    securefix::output("target_repository", target_repository)?;
    securefix::output("target_repository_id", manifest.repository.id.to_string())?;
    Ok(())
}

fn validate_policy_check_request_locator(
    manifest: &RequestManifest,
    producer_run_id: u64,
    producer_repository: &str,
    pull_request_number: u64,
    expected_head_sha: &str,
) -> Result<()> {
    ensure!(
        manifest.operation == "policy_check"
            && manifest.producer.run_id == producer_run_id
            && manifest.repository.full_name == producer_repository
            && manifest.pull_request.number == pull_request_number
            && manifest.pull_request.head_sha == expected_head_sha,
        "producer request does not match the selected policy-check run, PR, and head"
    );
    Ok(())
}

struct VerifiedRequest {
    config: securefix::instance_config::InstanceConfig,
    config_bytes: Vec<u8>,
    instance_authority: securefix::api::NativeServerInstanceAuthority,
    instance_config_path: String,
    manifest: RequestManifest,
    manifest_bytes: Vec<u8>,
    target_policy_control_identity: Option<String>,
    writer: Option<securefix::api::GitHub>,
    client_api: securefix::api::GitHub,
    producer_run: Value,
}

fn verify_request(
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
    mode: securefix::api::NativeScratchMode,
    execution_mode: securefix::api::NativeScratchMode,
    publish: bool,
) -> Result<VerifiedRequest> {
    verify_request_with_deployment(
        instance_config_path,
        manifest_path,
        bundle_path,
        mode,
        execution_mode,
        publish,
        true,
        false,
    )
}

#[allow(clippy::too_many_arguments)] // These flags are the fixed legacy/scratch admission modes.
fn verify_request_with_deployment(
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
    mode: securefix::api::NativeScratchMode,
    execution_mode: securefix::api::NativeScratchMode,
    publish: bool,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<VerifiedRequest> {
    ensure!(
        !(scratch && owner_selected_test_package),
        "native scratch write mode cannot be combined with candidate package qualification"
    );
    // The checked-out file is only an execution locator. The policy and its
    // workflow authority come from the authenticated protected default branch.
    let (server_api, captured) = capture_remote_instance_authority(instance_config_path)?;
    let config = captured.config.clone();
    let config_bytes = captured.config_bytes.clone();
    let server_authority = captured.authority.clone();
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
    if !scratch && !owner_selected_test_package {
        validate_native_request_event(&config, &manifest, execution_mode)?;
    }
    if owner_selected_test_package {
        validate_owner_selected_request_caller(&config, &manifest)?;
    }
    ensure!(
        config.repositories.iter().any(|repository| {
            repository.id == manifest.repository.id
                && repository.repository == manifest.repository.full_name
        }),
        "native request repository is not configured"
    );
    if scratch || owner_selected_test_package {
        securefix::api::validate_native_test_host_context(&config, execution_mode)?;
    }
    validate_request_server_locator(&config, instance_config_path, &manifest.server_authority)?;
    validate_first_slice_policy(
        &config,
        &manifest,
        mode,
        scratch || owner_selected_test_package,
    )?;
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
    let target_policy_control_identity =
        if scratch && mode == securefix::api::NativeScratchMode::Merge {
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
    validate_native_command_comment(&api, &server_api, &config, &manifest, &run, scratch)?;
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
        (manifest.producer.event == "pull_request")
            .then_some(manifest.pull_request.head_sha.as_str()),
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
    let signer_sha = unique_referenced_workflow_sha(
        &references,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
    )?;
    let signer_workflow_yaml = server_api.content(
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
    )?;
    let loader_action =
        native_client_package_action(&signer_workflow_yaml, &config.acceptable_clients.repository)?;
    let verified = verify_with_gh(
        manifest_path,
        bundle_path,
        &manifest.repository.full_name,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
    )?;
    verify_certificate(
        &verified,
        &manifest,
        &run,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
        &manifest_bytes,
    )?;
    let verified_client_package = if scratch || owner_selected_test_package {
        let publication_json =
            std::env::var("SECUREFIX_NATIVE_SCRATCH_PACKAGE_PUBLICATION_JSON")
                .context("missing owner-selected native scratch package publication record")?;
        let publication = scratch_package_publication(&publication_json, &config)?;
        securefix::package::verify_native_client_package_scratch(
            &server_api,
            &config,
            &config.acceptable_clients,
            &signer_sha,
            &loader_action,
            REQUEST_PROTOCOL,
            Some(&publication),
        )?
    } else {
        verify_configured_client_package(&server_api, &config, &signer_sha, &loader_action)?
    };
    ensure!(
        verified_client_package.implementation_sha == signer_sha
            && verified_client_package.loader_action_sha == loader_action.revision()
            && verified_client_package.protocol == REQUEST_PROTOCOL,
        "verified Client package does not match the accepted producer workflow and request protocol"
    );
    let writer = if publish
        && matches!(
            mode,
            securefix::api::NativeScratchMode::PolicyCheck
                | securefix::api::NativeScratchMode::Approval
                | securefix::api::NativeScratchMode::Merge
                | securefix::api::NativeScratchMode::Securefix
        ) {
        if !scratch && mode == securefix::api::NativeScratchMode::Merge {
            None
        } else {
            Some(if scratch {
                native_scratch_writer(
                    &config,
                    &config_bytes,
                    instance_config_path,
                    &manifest,
                    &manifest_bytes,
                    mode,
                    target_policy_control_identity.as_deref(),
                )?
            } else {
                native_instance_writer(
                    &captured,
                    instance_config_path,
                    &manifest,
                    &manifest_bytes,
                    mode,
                    None,
                )?
            })
        }
    } else {
        None
    };
    Ok(VerifiedRequest {
        config,
        config_bytes,
        instance_authority: captured,
        instance_config_path: instance_config_path.to_owned(),
        manifest,
        manifest_bytes,
        target_policy_control_identity,
        writer,
        client_api: api,
        producer_run: run,
    })
}

fn native_instance_writer(
    instance: &securefix::api::NativeServerInstanceAuthority,
    config_path: &str,
    manifest: &RequestManifest,
    manifest_bytes: &[u8],
    mode: securefix::api::NativeScratchMode,
    merge_fence: Option<&securefix::api::NativeInstanceMergeFence>,
) -> Result<securefix::api::GitHub> {
    let instance_mode = match mode {
        securefix::api::NativeScratchMode::PolicyCheck => {
            securefix::api::NativeInstanceMode::PolicyCheck
        }
        securefix::api::NativeScratchMode::Securefix => {
            securefix::api::NativeInstanceMode::Securefix
        }
        securefix::api::NativeScratchMode::Approval => securefix::api::NativeInstanceMode::Approve,
        securefix::api::NativeScratchMode::Merge => securefix::api::NativeInstanceMode::Merge,
    };
    let write_token = match mode {
        securefix::api::NativeScratchMode::PolicyCheck => "SECUREFIX_NATIVE_CHECK_TOKEN",
        securefix::api::NativeScratchMode::Approval => "SECUREFIX_APPROVE_TOKEN",
        securefix::api::NativeScratchMode::Merge => "SECUREFIX_NATIVE_MERGE_TOKEN",
        securefix::api::NativeScratchMode::Securefix => "SECUREFIX_WRITE_TOKEN",
    };
    let request_sha256 = securefix::hex_encode(Sha256::digest(manifest_bytes));
    let target = securefix::api::NativeInstanceWriteTarget {
        mode: instance_mode,
        config_path,
        repository: &manifest.repository.full_name,
        repository_id: manifest.repository.id,
        pull_number: manifest.pull_request.number,
        head_sha: &manifest.pull_request.head_sha,
        head_branch: &manifest.pull_request.head_branch,
        head_repository_id: manifest.pull_request.head_repository_id,
        base_sha: &manifest.pull_request.base_sha,
        base_ref: &manifest.pull_request.base_ref,
        author_id: manifest.pull_request.author_id,
        author_login: &manifest.pull_request.author_login,
        actor_id: manifest.producer.actor_id,
        actor_login: &manifest.producer.actor_login,
        request_sha256: &request_sha256,
        producer_run_id: manifest.producer.run_id,
        producer_run_attempt: manifest.producer.run_attempt,
        producer_workflow_path: &manifest.producer.workflow_path,
        producer_workflow_sha: &manifest.producer.workflow_sha,
        client_workflow_epoch: &manifest.client_workflow_epoch,
        merge_fence,
    };
    securefix::api::GitHub::native_instance_from_env(
        "SECUREFIX_CLIENT_TOKEN",
        write_token,
        instance,
        &target,
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScratchPackagePublicationInput {
    source_sha: String,
    source_branch: String,
    tag: String,
    release_id: u64,
    asset_id: u64,
    asset_sha256: String,
    asset_size: u64,
    producer_run_id: u64,
    producer_run_attempt: u64,
    publisher_workflow: String,
    publisher_branch: String,
    publisher_sha: String,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
}

fn scratch_package_publication(
    json: &str,
    config: &securefix::instance_config::InstanceConfig,
) -> Result<securefix::package::ScratchPackagePublication> {
    let input = parse_scratch_package_publication_input(json)?;
    let destination = config
        .scratch_package_repository
        .as_ref()
        .context("scratch package repository is not configured")?;
    Ok(securefix::package::ScratchPackagePublication {
        source_repository: config.acceptable_clients.repository.clone(),
        source_repository_id: config.acceptable_clients.id,
        destination_repository: destination.repository.clone(),
        destination_repository_id: destination.id,
        source_sha: input.source_sha,
        source_branch: input.source_branch,
        tag: input.tag,
        release_id: input.release_id,
        asset_id: input.asset_id,
        asset_sha256: input.asset_sha256,
        asset_size: input.asset_size,
        producer_run_id: input.producer_run_id,
        producer_run_attempt: input.producer_run_attempt,
        publisher_workflow: input.publisher_workflow,
        publisher_branch: input.publisher_branch,
        publisher_sha: input.publisher_sha,
        publisher_run_id: input.publisher_run_id,
        publisher_run_attempt: input.publisher_run_attempt,
    })
}

fn parse_scratch_package_publication_input(json: &str) -> Result<ScratchPackagePublicationInput> {
    ensure!(
        json.len() <= 4096,
        "native scratch package publication record exceeds its size limit"
    );
    serde_json::from_str(json).context("parse native scratch package publication record")
}

fn capture_remote_instance_authority(
    instance_config_path: &str,
) -> Result<(
    securefix::api::GitHub,
    securefix::api::NativeServerInstanceAuthority,
)> {
    securefix::api::validate_native_instance_config_path(instance_config_path)?;
    let repository = std::env::var("GITHUB_REPOSITORY")
        .context("missing authenticated Server repository context")?;
    let api = securefix::api::GitHub::from_env("GITHUB_TOKEN")?;
    let captured =
        api.capture_remote_native_server_instance_authority(&repository, instance_config_path)?;
    ensure!(
        captured.config.instance.repository == repository,
        "captured Server config does not match the authenticated job repository"
    );
    Ok((api, captured))
}

pub(crate) fn unique_referenced_workflow_sha(
    references: &[securefix::workflow::ReferencedWorkflow],
    repository: &str,
    workflow_path: &str,
) -> Result<String> {
    securefix::policy::validate_repository(repository)?;
    ensure!(
        workflow_path.starts_with(".github/workflows/")
            && workflow_path.ends_with(".yml")
            && !workflow_path.contains(['\\', '%', '?', '#'])
            && !workflow_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "configured Client producer workflow path is invalid"
    );
    let prefix = format!("{repository}/{workflow_path}@");
    let matching = references
        .iter()
        .filter(|reference| reference.path.starts_with(&prefix))
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "source run does not name exactly one configured Client producer workflow"
    );
    let reference = matching[0];
    securefix::policy::validate_sha(&reference.sha)?;
    ensure!(
        reference.path == format!("{prefix}{}", reference.sha),
        "configured Client producer workflow reference is not an exact immutable pin"
    );
    Ok(reference.sha.clone())
}

pub(crate) fn native_client_package_action(
    workflow_yaml: &[u8],
    repository: &str,
) -> Result<securefix::package::PinnedPackageAction> {
    securefix::policy::validate_repository(repository)?;
    ensure!(
        !workflow_yaml.is_empty() && workflow_yaml.len() <= 64 * 1024,
        "Client producer workflow is empty or exceeds its size limit"
    );
    let yaml: serde_yaml::Value = serde_yaml::from_slice(workflow_yaml)
        .context("parse Client producer workflow for its fixed package loader")?;
    let repository_prefix = format!("{repository}/");
    let mut matches = Vec::new();
    fn visit(
        value: &serde_yaml::Value,
        repository: &str,
        repository_prefix: &str,
        matches: &mut Vec<securefix::package::PinnedPackageAction>,
    ) -> Result<()> {
        match value {
            serde_yaml::Value::Mapping(mapping) => {
                if let Some(uses_value) = mapping.get(serde_yaml::Value::String("uses".to_owned()))
                {
                    let uses = uses_value
                        .as_str()
                        .context("Client producer workflow has a non-string uses entry")?;
                    if let Some(reference) = uses.strip_prefix(repository_prefix) {
                        let (path, sha) = reference
                            .rsplit_once('@')
                            .context("Client package Action has no immutable revision")?;
                        ensure!(!path.is_empty(), "Client package Action path is empty");
                        matches.push(securefix::package::PinnedPackageAction::new(
                            repository.to_owned(),
                            path.to_owned(),
                            sha.to_owned(),
                        )?);
                    } else if uses.contains(".github/actions/") {
                        anyhow::bail!("Client producer workflow uses an unconfigured local Action");
                    }
                }
                for child in mapping.values() {
                    visit(child, repository, repository_prefix, matches)?;
                }
            }
            serde_yaml::Value::Sequence(items) => {
                for child in items {
                    visit(child, repository, repository_prefix, matches)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(&yaml, repository, &repository_prefix, &mut matches)?;
    ensure!(
        !matches.is_empty(),
        "Client producer workflow has no configured package Action"
    );
    let selected = matches[0].clone();
    ensure!(
        matches.iter().all(|binding| binding == &selected),
        "Client producer workflow mixes package Action bindings"
    );
    Ok(selected)
}

/// Resolve the source branch for release attestation only after authenticating
/// the configured Client repository through GitHub's repository API. The
/// branch is repository metadata, never a request or dispatch claim.
fn verified_client_default_branch(
    repository: &Value,
    acceptable: &securefix::instance_config::AcceptableClients,
) -> Result<String> {
    ensure!(
        repository["id"].as_u64() == Some(acceptable.id)
            && repository["full_name"].as_str() == Some(acceptable.repository.as_str()),
        "configured Client repository identity mismatch"
    );
    let branch = repository["default_branch"]
        .as_str()
        .context("configured Client repository has no default branch")?;
    securefix::config::validate_branch(branch)?;
    Ok(branch.to_owned())
}

pub(crate) fn verify_configured_client_package(
    server_api: &securefix::api::GitHub,
    config: &securefix::instance_config::InstanceConfig,
    signer_sha: &str,
    loader_action: &securefix::package::PinnedPackageAction,
) -> Result<securefix::package::VerifiedNativeClientPackage> {
    if config.scratch_package_repository.is_some() {
        return securefix::package::verify_native_client_package_scratch(
            server_api,
            config,
            &config.acceptable_clients,
            signer_sha,
            loader_action,
            REQUEST_PROTOCOL,
            None,
        );
    }
    let repository: Value =
        server_api.get(&format!("/repos/{}", config.acceptable_clients.repository))?;
    let default_branch = verified_client_default_branch(&repository, &config.acceptable_clients)?;
    securefix::package::verify_native_client_package(
        server_api,
        &config.acceptable_clients,
        signer_sha,
        loader_action,
        REQUEST_PROTOCOL,
        &default_branch,
    )
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
    crate::native_client::validate_pull_request_run_head(
        &manifest.producer.event,
        &manifest.producer.source_sha,
        run["head_branch"]
            .as_str()
            .context("producer run head branch is missing")?,
        &manifest.pull_request.head_sha,
        &manifest.pull_request.head_branch,
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

fn validate_native_command_comment(
    api: &securefix::api::GitHub,
    server_api: &securefix::api::GitHub,
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    run: &Value,
    scratch: bool,
) -> Result<()> {
    if !matches!(manifest.operation.as_str(), "approval" | "merge") {
        ensure!(
            manifest.command_comment.is_none(),
            "non-command request contains an owner command locator"
        );
        return Ok(());
    }
    if scratch {
        ensure!(
            manifest.command_comment.is_none(),
            "owner-dispatched scratch commands must not claim an issue-comment authorization"
        );
        return Ok(());
    }
    ensure!(
        manifest.producer.event == "issue_comment" && manifest.producer.run_attempt == 1,
        "ordinary approval and merge require the original issue-comment workflow run"
    );
    let locator = manifest
        .command_comment
        .as_ref()
        .context("ordinary approval and merge require a captured command comment")?;
    let comment: Value = api.get(&format!(
        "/repos/{}/issues/comments/{}",
        manifest.repository.full_name, locator.id
    ))?;
    let owner = &config.identities.owner;
    let is_owner =
        crate::request::matches_principal(&comment["user"], owner.id, &owner.login, "User")
            && crate::request::matches_principal(&run["actor"], owner.id, &owner.login, "User");
    let is_renovate = if manifest.operation == "merge" {
        config
            .identities
            .renovate_merge_bot
            .as_ref()
            .is_some_and(|bot| {
                crate::request::matches_principal(&comment["user"], bot.id, &bot.login, "Bot")
                    && crate::request::matches_principal(&run["actor"], bot.id, &bot.login, "Bot")
            })
    } else {
        false
    };
    let expected_command = if manifest.operation == "approval" {
        "/approve"
    } else {
        "/merge"
    };
    let issue_url_suffix = format!(
        "/repos/{}/issues/{}",
        manifest.repository.full_name, manifest.pull_request.number
    );
    let comment_created = parse_comment_time(&comment["created_at"])?;
    let comment_updated = parse_comment_time(&comment["updated_at"])?;
    ensure!(
        comment["id"].as_u64() == Some(locator.id)
            && comment["body"]
                .as_str()
                .is_some_and(|body| body.trim_ascii() == expected_command)
            && comment["issue_url"]
                .as_str()
                .is_some_and(|url| url.ends_with(&issue_url_suffix))
            && comment_created == locator.created_at
            && comment_updated == locator.updated_at
            && comment_created == comment_updated
            && (is_owner || is_renovate),
        "native command comment is missing, changed, edited, or unauthorized"
    );
    if is_renovate {
        let pull: Value = api.get(&format!(
            "/repos/{}/pulls/{}",
            manifest.repository.full_name, manifest.pull_request.number
        ))?;
        crate::request::require_renovate_author_for_instance(config, &pull)?;
    }
    securefix::api::require_native_instance_command_after_authority_epoch(
        server_api,
        &manifest.server_authority,
        locator.created_at,
    )?;
    let events = api.paginate(&format!(
        "/repos/{}/issues/{}/timeline",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    ensure!(
        !crate::merge::has_invalidating_event(&events, locator.created_at),
        "pull request changed after the owner command was created"
    );
    Ok(())
}

fn parse_comment_time(value: &Value) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(
        value.as_str().context("timestamp is missing or invalid")?,
    )?
    .with_timezone(&chrono::Utc))
}

fn native_release_approval_locator(
    api: &securefix::api::GitHub,
    config: &securefix::instance_config::InstanceConfig,
    authority: &securefix::api::NativeAuthoritySnapshot,
    repository: &str,
    pull_number: u64,
    head_sha: &str,
    merged_at: &chrono::DateTime<chrono::Utc>,
) -> Result<(u64, u32, String, String, u64)> {
    let reviews =
        api.paginate_uncached(&format!("/repos/{repository}/pulls/{pull_number}/reviews"))?;
    let reviewer = &config.identities.approval_reviewer;
    let mut decisions = reviews
        .iter()
        .filter(|review| {
            matches!(
                review["state"].as_str(),
                Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
            ) && review["user"]["id"].as_u64() == Some(reviewer.id)
                && review["user"]["login"].as_str() == Some(reviewer.login.as_str())
                && review["user"]["type"] == "User"
        })
        .collect::<Vec<_>>();
    ensure!(
        decisions
            .iter()
            .all(|review| crate::request::review_order(review).is_some()),
        "configured reviewer has a malformed review timestamp or ID"
    );
    let review = decisions
        .drain(..)
        .max_by_key(|review| crate::request::review_order(review))
        .context("configured reviewer has no approval marker review")?;
    require_no_later_release_review_decision(&reviews, review)?;
    let review_at = parse_comment_time(&review["submitted_at"])?;
    ensure!(
        review["state"] == "APPROVED"
            && review["commit_id"].as_str() == Some(head_sha)
            && review_at < *merged_at,
        "latest configured approval is not a pre-merge review on the exact release head"
    );
    let marker = securefix::api::parse_native_instance_approval_marker(
        review["body"]
            .as_str()
            .context("configured approval review has no native marker")?,
    )?;
    let current_authority_sha = securefix::api::native_authority_sha256(authority)?;
    ensure!(
        marker.authority_sha256 == current_authority_sha,
        "approval marker belongs to a different Server authority"
    );
    let review_id = review["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("approval marker review ID is missing")?;
    Ok((
        marker.producer_run_id,
        marker.producer_run_attempt,
        marker.request_sha256,
        marker.authority_sha256,
        review_id,
    ))
}

fn require_no_later_release_review_decision(reviews: &[Value], marker: &Value) -> Result<()> {
    let marker_id = marker["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("approval marker review ID is missing")?;
    let marker_order = crate::request::review_order(marker)
        .context("configured reviewer marker has no review order")?;
    ensure!(
        reviews
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate["state"].as_str(),
                    Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
                )
            })
            .all(|candidate| {
                candidate["id"].as_u64() == Some(marker_id)
                    || crate::request::review_order(candidate)
                        .is_some_and(|order| order < marker_order)
            }),
        "a review decision was submitted after the configured approval marker"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Bind the independent command, merge, and authenticated identities.
fn validate_native_release_approval_command(
    client_api: &securefix::api::GitHub,
    server_api: &securefix::api::GitHub,
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    run: &Value,
    merged_at: &chrono::DateTime<chrono::Utc>,
    merged_by: &crate::config::Principal,
    merge_sha: &str,
) -> Result<()> {
    ensure!(
        manifest.producer.event == "issue_comment" && manifest.producer.run_attempt == 1,
        "release approval must come from the original issue-comment run"
    );
    let locator = manifest
        .command_comment
        .as_ref()
        .context("release approval has no captured owner command")?;
    let comment: Value = client_api.get(&format!(
        "/repos/{}/issues/comments/{}",
        manifest.repository.full_name, locator.id
    ))?;
    let owner = &config.identities.owner;
    let issue_url_suffix = format!(
        "/repos/{}/issues/{}",
        manifest.repository.full_name, manifest.pull_request.number
    );
    let created_at = parse_comment_time(&comment["created_at"])?;
    let updated_at = parse_comment_time(&comment["updated_at"])?;
    let run_created_at = parse_comment_time(&run["created_at"])?;
    ensure!(
        comment["id"].as_u64() == Some(locator.id)
            && comment["body"]
                .as_str()
                .is_some_and(|body| body.trim_ascii() == "/approve")
            && comment["issue_url"]
                .as_str()
                .is_some_and(|url| url.ends_with(&issue_url_suffix))
            && crate::request::matches_principal(&comment["user"], owner.id, &owner.login, "User")
            && crate::request::matches_principal(&run["actor"], owner.id, &owner.login, "User")
            && created_at == locator.created_at
            && updated_at == locator.updated_at
            && created_at == updated_at
            && created_at <= run_created_at
            && run_created_at < *merged_at
            && created_at < *merged_at,
        "release approval command is edited, unauthorized, or was created after merge"
    );
    securefix::api::require_native_instance_command_after_authority_epoch(
        server_api,
        &manifest.server_authority,
        locator.created_at,
    )?;
    let events = client_api.paginate(&format!(
        "/repos/{}/issues/{}/timeline",
        manifest.repository.full_name, manifest.pull_request.number
    ))?;
    validate_native_release_timeline(&events, locator.created_at, merged_at, merged_by, merge_sha)?;
    Ok(())
}

fn validate_native_release_timeline(
    events: &[Value],
    command_at: chrono::DateTime<chrono::Utc>,
    merged_at: &chrono::DateTime<chrono::Utc>,
    merged_by: &crate::config::Principal,
    merge_sha: &str,
) -> Result<()> {
    securefix::policy::validate_sha(merge_sha)?;
    let mut merged = 0;
    let mut closed = 0;
    let mut deleted = 0;
    for event in events {
        let kind = event["event"]
            .as_str()
            .context("release timeline event kind is missing")?;
        if !crate::merge::INVALIDATING_EVENTS.contains(&kind) {
            continue;
        }
        let created_at = parse_comment_time(&event["created_at"])
            .context("release PR transition has no valid timestamp")?;
        if created_at < command_at {
            continue;
        }
        ensure!(
            event["actor"]["id"].as_u64() == Some(merged_by.id)
                && event["actor"]["login"].as_str() == Some(merged_by.login.as_str()),
            "release PR transition was not performed by the configured merger"
        );
        match kind {
            "merged"
                if created_at == *merged_at && event["commit_id"].as_str() == Some(merge_sha) =>
            {
                merged += 1
            }
            "closed" if created_at == *merged_at => closed += 1,
            "head_ref_deleted" if created_at >= *merged_at => deleted += 1,
            _ => anyhow::bail!("release PR has an unexpected post-command timeline transition"),
        }
    }
    ensure!(
        merged == 1 && closed == 1 && deleted <= 1,
        "release timeline must contain one exact configured-merger merge and close transition"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Keep independently authenticated PR, branch, and merger identities explicit.
fn verify_current_merged_release_pull_request(
    api: &securefix::api::GitHub,
    repository: &Value,
    pull: &Value,
    manifest: &RequestManifest,
    head_sha: &str,
    merge_sha: &str,
    merged_by: &crate::config::Principal,
    release_branch: &str,
    default_branch: &str,
) -> Result<()> {
    ensure!(
        repository["id"].as_u64() == Some(manifest.repository.id)
            && repository["full_name"].as_str() == Some(manifest.repository.full_name.as_str())
            && pull["number"].as_u64() == Some(manifest.pull_request.number)
            && pull["state"] == "closed"
            && pull["merged"] == true
            && pull["head"]["sha"].as_str() == Some(head_sha)
            && pull["merge_commit_sha"].as_str() == Some(merge_sha)
            && pull["base"]["ref"].as_str() == Some(default_branch)
            && manifest.pull_request.base_ref == default_branch
            && pull["head"]["ref"].as_str() == Some(release_branch)
            && manifest.pull_request.head_branch == release_branch
            && pull["head"]["repo"]["id"].as_u64() == Some(manifest.repository.id)
            && pull["base"]["repo"]["id"].as_u64() == Some(manifest.repository.id)
            && pull["user"]["id"].as_u64() == Some(manifest.pull_request.author_id)
            && pull["user"]["login"].as_str() == Some(manifest.pull_request.author_login.as_str())
            && pull["merged_by"]["id"].as_u64() == Some(merged_by.id)
            && pull["merged_by"]["login"].as_str() == Some(merged_by.login.as_str()),
        "merged release PR no longer matches the approved repository, head, base, author, or merger"
    );
    let comparison: Value = api.get(&format!(
        "/repos/{}/compare/{merge_sha}...{default_branch}",
        manifest.repository.full_name
    ))?;
    ensure!(
        matches!(comparison["status"].as_str(), Some("ahead" | "identical"))
            && comparison["base_commit"]["sha"].as_str() == Some(merge_sha),
        "approved release merge commit is not contained in the current default branch"
    );
    let base_comparison: Value = api.get(&format!(
        "/repos/{}/compare/{}...{merge_sha}",
        manifest.repository.full_name, manifest.pull_request.base_sha
    ))?;
    ensure!(
        matches!(
            base_comparison["status"].as_str(),
            Some("ahead" | "identical")
        ) && base_comparison["base_commit"]["sha"].as_str()
            == Some(manifest.pull_request.base_sha.as_str()),
        "approved release merge commit does not descend from the pre-merge base SHA"
    );
    Ok(())
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
            && pull["user"]["login"].as_str() == Some(manifest.pull_request.author_login.as_str()),
        "native request PR is closed, retargeted, or has a different head or identity"
    );
    ensure!(
        repo["default_branch"].as_str() == Some(manifest.pull_request.base_ref.as_str()),
        "native request PR does not target the repository default branch"
    );
    Ok(())
}

fn validate_owner_selected_request_caller(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
) -> Result<()> {
    ensure!(
        config.allows_scratch_request_caller(
            &manifest.repository.full_name,
            manifest.repository.id,
            &manifest.producer.workflow_path,
            &manifest.producer.workflow_ref,
            &manifest.producer.event,
            &manifest.operation,
        ),
        "owner-selected package request caller is not configured"
    );
    Ok(())
}

fn validate_first_slice_policy(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
    mode: securefix::api::NativeScratchMode,
    scratch: bool,
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
    if scratch {
        ensure!(
            config.identities.owner.id == manifest.producer.actor_id
                && config.identities.owner.login == manifest.producer.actor_login
                && config.identities.owner.id == manifest.pull_request.author_id
                && config.identities.owner.login == manifest.pull_request.author_login,
            "scratch policy requires the configured owner as producer actor and PR author"
        );
    } else if matches!(manifest.operation.as_str(), "approval" | "merge") {
        ensure!(
            manifest.command_comment.is_some(),
            "ordinary approval and merge require a validated owner command"
        );
    }
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

fn publish_request_proof_check(verified: &VerifiedRequest) -> Result<()> {
    let manifest = &verified.manifest;
    let api = verified
        .writer
        .as_ref()
        .context("native request writer was not captured before proof validation")?;
    let existing = securefix::api::native_check_runs_for_head(
        api,
        &manifest.repository.full_name,
        &manifest.pull_request.head_sha,
    )?;
    let request_sha = securefix::hex_encode(Sha256::digest(&verified.manifest_bytes));
    let body = if verified.target_policy_control_identity.is_some() {
        securefix::api::native_policy_check_body(&manifest.pull_request.head_sha, &request_sha)
    } else {
        securefix::api::native_instance_policy_check_body(
            &verified.instance_authority.authority,
            &manifest.pull_request.head_sha,
            &request_sha,
        )?
    };
    require_new_request_proof_check(
        &existing,
        verified.config.apps.policy_check_id,
        &manifest.pull_request.head_sha,
        body["external_id"]
            .as_str()
            .context("request proof identity is missing")?,
    )?;
    let result: Value = api.post(
        &format!("/repos/{}/check-runs", manifest.repository.full_name),
        &body,
    )?;
    ensure!(
        result["external_id"] == body["external_id"]
            && result["name"] == securefix::api::NATIVE_POLICY_CHECK_NAME
            && result["head_sha"].as_str() == Some(manifest.pull_request.head_sha.as_str())
            && result["status"] == "completed"
            && result["conclusion"] == "success"
            && result["app"]["id"].as_u64() == Some(verified.config.apps.policy_check_id),
        "GitHub returned a different native request proof check"
    );
    println!("native_check_run_id={}", result["id"]);
    Ok(())
}

fn require_new_request_proof_check(
    checks: &[Value],
    app_id: u64,
    head: &str,
    external_id: &str,
) -> Result<()> {
    for check in checks.iter().filter(|check| {
        check["name"] == securefix::api::NATIVE_POLICY_CHECK_NAME
            && check["app"]["id"].as_u64() == Some(app_id)
    }) {
        ensure!(
            check["head_sha"].as_str() == Some(head),
            "existing native check has a different head"
        );
        let existing_id = check["external_id"]
            .as_str()
            .context("existing native check identity is missing")?;
        if existing_id.len() != 64
            || !existing_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            let identity =
                securefix::api::parse_native_instance_policy_check_external_id(existing_id)?;
            ensure!(
                identity.head_sha == head,
                "existing native check identity has a different head"
            );
        }
        ensure!(
            existing_id != external_id,
            "native request proof already exists for this exact request"
        );
    }
    Ok(())
}

fn apply_securefix_mode(
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<()> {
    let verified = verify_request_with_deployment(
        instance_config_path,
        manifest_path,
        bundle_path,
        securefix::api::NativeScratchMode::Securefix,
        securefix::api::NativeScratchMode::Securefix,
        true,
        scratch,
        owner_selected_test_package,
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
        matches!(
            manifest.producer.event.as_str(),
            "pull_request" | "pull_request_target"
        ),
        "native Securefix requires a pull request event"
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
    let writer = if scratch {
        native_scratch_writer(
            &verified.config,
            &verified.config_bytes,
            instance_config_path,
            manifest,
            &verified.manifest_bytes,
            securefix::api::NativeScratchMode::Securefix,
            None,
        )?
    } else {
        native_instance_writer(
            &verified.instance_authority,
            &verified.instance_config_path,
            manifest,
            &verified.manifest_bytes,
            securefix::api::NativeScratchMode::Securefix,
            None,
        )?
    };
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
        matches!(
            manifest.producer.event.as_str(),
            "pull_request" | "pull_request_target"
        ) && run_branch == manifest.pull_request.head_branch
            && fix.event_name == manifest.producer.event,
        "native Securefix requires a pull request run for the exact PR head"
    );
    let event_pr = fix
        .pull_request_context
        .as_ref()
        .context("Securefix artifact does not contain its pull request context")?;
    ensure!(
        event_pr.number == manifest.pull_request.number
            && event_pr.head_sha == manifest.pull_request.head_sha
            && event_pr.head_branch == manifest.pull_request.head_branch
            && event_pr.head_repository_id == manifest.pull_request.head_repository_id
            && event_pr.head_repository == manifest.repository.full_name
            && event_pr.base_sha == manifest.pull_request.base_sha
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
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
) -> Result<()> {
    apply_securefix_from_run_mode(
        instance_config_path,
        producer_repository,
        producer_run_id,
        true,
        false,
    )
}

fn apply_securefix_from_run_mode(
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<()> {
    let (manifest_bytes, bundle_bytes) = download_request_from_run(
        instance_config_path,
        producer_repository,
        producer_run_id,
        securefix::policy::Capability::Securefix,
    )?;
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, bundle_bytes)?;
    apply_securefix_mode(
        instance_config_path,
        &manifest_path,
        &bundle_path,
        scratch,
        owner_selected_test_package,
    )
}

fn apply_native_approval_from_run(
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
    expected_target: Option<(u64, String)>,
    apply: bool,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<()> {
    if let Some((pull_request_number, expected_head_sha)) = &expected_target {
        securefix::policy::validate_sha(expected_head_sha)?;
        ensure!(*pull_request_number > 0, "invalid approval PR number");
    }
    let (manifest_bytes, bundle_bytes) = download_request_from_run(
        instance_config_path,
        producer_repository,
        producer_run_id,
        securefix::policy::Capability::Approve,
    )?;
    let manifest: RequestManifest = serde_json::from_slice(&manifest_bytes)
        .context("parse downloaded native approval request")?;
    if let Some((pull_request_number, expected_head_sha)) = expected_target.as_ref() {
        ensure!(
            manifest.pull_request.number == *pull_request_number
                && manifest.pull_request.head_sha == *expected_head_sha,
            "producer request does not match the owner-selected PR number and head"
        );
    }
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, manifest_bytes)?;
    fs::write(&bundle_path, bundle_bytes)?;
    let verified = verify_request_with_deployment(
        instance_config_path,
        &manifest_path,
        &bundle_path,
        securefix::api::NativeScratchMode::Approval,
        securefix::api::NativeScratchMode::Approval,
        apply,
        scratch,
        owner_selected_test_package,
    )?;
    if apply {
        let writer = verified
            .writer
            .as_ref()
            .context("native approval writer was not captured before apply")?;
        let marker = if scratch {
            crate::approval::approve_native_current_head(
                &verified.client_api,
                writer,
                &verified.manifest,
                &verified.config.identities.approval_reviewer,
                &verified.manifest_bytes,
            )?
        } else {
            crate::approval::approve_native_instance_current_head(
                &verified.client_api,
                writer,
                &verified.manifest,
                &verified.config.identities.approval_reviewer,
                &verified.manifest_bytes,
            )?
        };
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
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_ids: NativeMergeRunIds,
    expected_target: Option<(u64, String)>,
    apply: bool,
    scratch: bool,
    owner_selected_test_package: bool,
) -> Result<()> {
    if let Some((pull_request_number, expected_head_sha)) = &expected_target {
        securefix::policy::validate_sha(expected_head_sha)?;
        ensure!(*pull_request_number > 0, "invalid merge PR number");
    }
    ensure!(producer_run_ids.merge > 0, "invalid merge producer run ID");
    if scratch {
        ensure!(
            producer_run_ids.approval > 0 && producer_run_ids.merge != producer_run_ids.approval,
            "scratch merge and approval proof must come from different successful runs"
        );
    }

    let (merge_bytes, merge_bundle) = download_request_from_run(
        instance_config_path,
        producer_repository,
        producer_run_ids.merge,
        securefix::policy::Capability::Merge,
    )?;
    let merge_manifest: RequestManifest =
        serde_json::from_slice(&merge_bytes).context("parse downloaded native merge request")?;
    if let Some((pull_request_number, expected_head_sha)) = expected_target.as_ref() {
        ensure!(
            merge_manifest.pull_request.number == *pull_request_number
                && merge_manifest.pull_request.head_sha == *expected_head_sha,
            "producer request does not match the selected PR number and head"
        );
    }

    let approval_locator = if scratch {
        ensure!(
            producer_run_ids.approval > 0,
            "scratch merge requires the owner-selected approval proof run"
        );
        None
    } else {
        ensure!(
            producer_run_ids.approval == 0,
            "ordinary merge does not accept a caller-selected approval run"
        );
        Some(native_instance_approval_locator(
            instance_config_path,
            &merge_manifest,
        )?)
    };
    let approval_run_id = approval_locator
        .as_ref()
        .map_or(producer_run_ids.approval, |locator| locator.producer_run_id);
    let (approval_bytes, approval_bundle) = if approval_run_id > 0 {
        download_request_from_run(
            instance_config_path,
            producer_repository,
            approval_run_id,
            securefix::policy::Capability::Approve,
        )?
    } else {
        unreachable!("approval locator must be selected for the current merge mode")
    };
    let approval_manifest: RequestManifest = serde_json::from_slice(&approval_bytes)
        .context("parse downloaded native approval request")?;
    if let Some(locator) = approval_locator.as_ref() {
        ensure!(
            approval_manifest.producer.run_id == locator.producer_run_id
                && approval_manifest.producer.run_attempt == locator.producer_run_attempt
                && securefix::hex_encode(Sha256::digest(&approval_bytes)) == locator.request_sha256
                && securefix::api::native_authority_sha256(&approval_manifest.server_authority)?
                    == locator.authority_sha256
                && approval_manifest.pull_request.head_sha == merge_manifest.pull_request.head_sha,
            "approval proof does not match the authenticated current-head review marker"
        );
    }
    let pull_request_number = merge_manifest.pull_request.number;
    let expected_head_sha = merge_manifest.pull_request.head_sha.clone();

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

    let approval = verify_request_with_deployment(
        instance_config_path,
        &approval_manifest_path,
        &approval_bundle_path,
        securefix::api::NativeScratchMode::Approval,
        securefix::api::NativeScratchMode::Merge,
        false,
        scratch,
        owner_selected_test_package,
    )?;
    let merge = verify_request_with_deployment(
        instance_config_path,
        &merge_manifest_path,
        &merge_bundle_path,
        securefix::api::NativeScratchMode::Merge,
        securefix::api::NativeScratchMode::Merge,
        apply,
        scratch,
        owner_selected_test_package,
    )?;
    validate_native_merge_pair(&merge.manifest, &approval.manifest)?;
    if !scratch {
        crate::request::validate_native_instance_merge_policy(
            &merge.client_api,
            &merge.config,
            &merge.manifest,
            &approval.manifest,
        )?;
    }
    let merge_fence = validate_native_merge_readiness(&merge, &approval)?;

    if apply {
        let writer = if scratch {
            merge
                .writer
                .as_ref()
                .context("native scratch merge writer was not captured before apply")?
                .clone()
        } else {
            native_instance_writer(
                &merge.instance_authority,
                &merge.instance_config_path,
                &merge.manifest,
                &merge.manifest_bytes,
                securefix::api::NativeScratchMode::Merge,
                merge_fence.as_ref(),
            )?
        };
        let sha = writer.merge_native_pull_request()?;
        println!("merge_commit_sha={sha}");
    }
    println!("merge_validated=true");
    println!("merge_applied={apply}");
    println!("producer_run_id={}", producer_run_ids.merge);
    if approval_run_id > 0 {
        println!("approval_producer_run_id={approval_run_id}");
    }
    println!("pull_request_number={pull_request_number}");
    println!("request_head_sha={expected_head_sha}");
    Ok(())
}

struct NativeInstanceApprovalLocator {
    producer_run_id: u64,
    producer_run_attempt: u32,
    request_sha256: String,
    authority_sha256: String,
}

pub(crate) struct NativeReleaseApprovalProof {
    pub(crate) producer_run_id: u64,
    pub(crate) producer_run_attempt: u32,
    pub(crate) request_sha256: String,
    pub(crate) authority_sha256: String,
    pub(crate) workflow_sha: String,
    pub(crate) accepted_client_implementation_sha: String,
    pub(crate) client_workflow_epoch: String,
    pub(crate) command_comment_id: u64,
    pub(crate) approval_review_id: u64,
}

/// Verify the existing native owner-approval proof for a merged release PR.
/// This adapter is for the Client Release Tag workflow, so it verifies the
/// same Client request/run/package evidence as the Server lane without
/// requiring Server-only `GITHUB_REPOSITORY` or reusable-workflow context.
#[allow(clippy::too_many_arguments)] // The two APIs and each PR identity are independently authenticated inputs.
pub(crate) fn verify_native_release_approval(
    server_api: &securefix::api::GitHub,
    client_api: &securefix::api::GitHub,
    instance_config_path: &str,
    expected_instance: &securefix::api::NativeServerInstanceAuthority,
    client_repository: &str,
    client_repository_id: u64,
    pull_request_number: u64,
    merged_head_sha: &str,
    merge_sha: &str,
    merged_by: &crate::config::Principal,
) -> Result<NativeReleaseApprovalProof> {
    securefix::api::validate_native_instance_config_path(instance_config_path)?;
    securefix::policy::validate_repository(client_repository)?;
    securefix::policy::validate_sha(merged_head_sha)?;
    securefix::policy::validate_sha(merge_sha)?;
    ensure!(
        pull_request_number > 0 && client_repository_id > 0,
        "invalid release PR identity"
    );
    let current = server_api.capture_remote_native_server_instance_authority(
        &expected_instance.config.instance.repository,
        instance_config_path,
    )?;
    server_api.require_remote_native_server_instance_authority_unchanged(expected_instance)?;
    ensure!(
        current.config_bytes == expected_instance.config_bytes
            && current.authority == expected_instance.authority,
        "Server instance authority changed during release approval verification"
    );
    let config = &current.config;
    ensure!(
        config.instance.repository == current.authority.instance_repository
            && config.instance.id == current.authority.instance_id
            && config.identities.server_bot == *merged_by,
        "release merger does not match the authenticated Server instance"
    );
    let configured_target = config
        .repositories
        .iter()
        .find(|target| target.repository == client_repository && target.id == client_repository_id)
        .context("release repository is not configured in the Server instance")?;
    configured_target
        .policy()
        .require(securefix::policy::Capability::Release)
        .context("configured Client repository lacks the Release capability")?;
    let release_branch = config
        .branches
        .release
        .as_deref()
        .context("Server instance has no configured release branch")?;

    let repository: Value = client_api.get(&format!("/repos/{client_repository}"))?;
    ensure!(
        repository["id"].as_u64() == Some(client_repository_id)
            && repository["full_name"].as_str() == Some(client_repository),
        "release Client repository identity mismatch"
    );
    let default_branch = repository["default_branch"]
        .as_str()
        .context("release Client repository has no default branch")?;
    securefix::config::validate_branch(default_branch)?;

    let pull: Value = client_api.get(&format!(
        "/repos/{client_repository}/pulls/{pull_request_number}"
    ))?;
    ensure!(
        pull["number"].as_u64() == Some(pull_request_number)
            && pull["state"] == "closed"
            && pull["merged"] == true
            && pull["head"]["sha"].as_str() == Some(merged_head_sha)
            && pull["merge_commit_sha"].as_str() == Some(merge_sha)
            && pull["base"]["repo"]["id"].as_u64() == Some(client_repository_id)
            && pull["base"]["repo"]["full_name"].as_str() == Some(client_repository)
            && pull["base"]["ref"].as_str() == Some(default_branch)
            && pull["merged_by"]["id"].as_u64() == Some(merged_by.id)
            && pull["merged_by"]["login"].as_str() == Some(merged_by.login.as_str()),
        "release PR is not merged by the configured Server identity at the expected head"
    );
    let merged_at = parse_comment_time(&pull["merged_at"])?;
    let (run_id, run_attempt, request_sha256, authority_sha256, review_id) =
        native_release_approval_locator(
            client_api,
            config,
            &current.authority,
            client_repository,
            pull_request_number,
            merged_head_sha,
            &merged_at,
        )?;
    let (manifest_bytes, bundle_bytes) = download_request_from_run_for_instance(
        server_api,
        client_api,
        &current,
        client_repository,
        run_id,
        securefix::policy::Capability::Approve,
    )?;
    ensure!(
        securefix::hex_encode(Sha256::digest(&manifest_bytes)) == request_sha256,
        "release approval marker request digest does not match its producer artifact"
    );
    let manifest: RequestManifest = serde_json::from_slice(&manifest_bytes)
        .context("parse native release approval proof manifest")?;
    ensure!(
        manifest.operation == "approval"
            && manifest.producer.run_id == run_id
            && manifest.producer.run_attempt == run_attempt
            && manifest.repository.full_name == client_repository
            && manifest.repository.id == client_repository_id
            && manifest.pull_request.number == pull_request_number
            && manifest.pull_request.head_sha == merged_head_sha
            && manifest.server_authority == current.authority
            && securefix::api::native_authority_sha256(&manifest.server_authority)?
                == authority_sha256,
        "release approval proof does not bind the selected PR, head, and current Server authority"
    );
    manifest.validate()?;
    validate_request_server_locator(config, instance_config_path, &manifest.server_authority)?;
    validate_first_slice_policy(
        config,
        &manifest,
        securefix::api::NativeScratchMode::Approval,
        false,
    )?;
    let producer_run: Value =
        client_api.get(&format!("/repos/{client_repository}/actions/runs/{run_id}"))?;
    verify_run_identity(&producer_run, &manifest)?;
    ensure!(
        parse_comment_time(&producer_run["created_at"])? < merged_at,
        "approval producer run was created after the release PR was merged"
    );
    validate_native_release_approval_command(
        client_api,
        server_api,
        config,
        &manifest,
        &producer_run,
        &merged_at,
        merged_by,
        merge_sha,
    )?;
    verify_current_merged_release_pull_request(
        client_api,
        &repository,
        &pull,
        &manifest,
        merged_head_sha,
        merge_sha,
        merged_by,
        release_branch,
        default_branch,
    )?;
    crate::request::validate_native_pr_commit_policy(
        client_api,
        client_repository,
        pull_request_number,
        merged_head_sha,
        &config.policy.trusted_committers,
    )?;
    let current_client_epoch = securefix::api::capture_native_client_workflow_epoch(
        client_api,
        client_repository,
        client_repository_id,
        default_branch,
        &manifest.producer.workflow_path,
        &manifest.producer.workflow_sha,
        (manifest.producer.event == "pull_request")
            .then_some(manifest.pull_request.head_sha.as_str()),
    )?;
    securefix::api::require_native_client_workflow_epoch_unchanged(
        &manifest.client_workflow_epoch,
        &current_client_epoch,
    )?;
    let references: Vec<securefix::workflow::ReferencedWorkflow> = serde_json::from_value(
        producer_run
            .get("referenced_workflows")
            .cloned()
            .context("approval producer run has no reusable-workflow references")?,
    )
    .context("parse Client approval reusable-workflow references")?;
    let signer_sha = unique_referenced_workflow_sha(
        &references,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
    )?;
    let signer_workflow_yaml = server_api.content(
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
    )?;
    let loader_action =
        native_client_package_action(&signer_workflow_yaml, &config.acceptable_clients.repository)?;
    let directory = tempfile::tempdir()?;
    let manifest_path = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&manifest_path, &manifest_bytes)?;
    fs::write(&bundle_path, &bundle_bytes)?;
    let verified = verify_with_gh(
        &manifest_path,
        &bundle_path,
        client_repository,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
    )?;
    verify_certificate(
        &verified,
        &manifest,
        &producer_run,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        &signer_sha,
        &manifest_bytes,
    )?;
    let package =
        verify_configured_client_package(server_api, config, &signer_sha, &loader_action)?;
    ensure!(
        package.implementation_sha == signer_sha
            && package.loader_action_sha == loader_action.revision()
            && package.protocol == REQUEST_PROTOCOL,
        "verified Client package does not match the accepted approval signer and protocol"
    );
    server_api.require_remote_native_server_instance_authority_unchanged(&current)?;
    Ok(NativeReleaseApprovalProof {
        producer_run_id: run_id,
        producer_run_attempt: run_attempt,
        request_sha256,
        authority_sha256,
        workflow_sha: manifest.producer.workflow_sha,
        accepted_client_implementation_sha: package.implementation_sha,
        client_workflow_epoch: manifest.client_workflow_epoch,
        command_comment_id: manifest
            .command_comment
            .as_ref()
            .context("verified approval manifest has no command comment")?
            .id,
        approval_review_id: review_id,
    })
}

fn native_instance_approval_locator(
    instance_config_path: &str,
    merge: &RequestManifest,
) -> Result<NativeInstanceApprovalLocator> {
    let (_server_api, captured) = capture_remote_instance_authority(instance_config_path)?;
    securefix::api::require_native_authority_unchanged(
        &merge.server_authority,
        &captured.authority,
    )?;
    ensure!(
        captured.config.instance.repository == merge.server_authority.instance_repository,
        "merge request Server repository differs from current protected instance"
    );
    let api = securefix::api::GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    let reviews = api.paginate_uncached(&format!(
        "/repos/{}/pulls/{}/reviews",
        merge.repository.full_name, merge.pull_request.number
    ))?;
    let reviewer = &captured.config.identities.approval_reviewer;
    let mut decisions = reviews
        .iter()
        .filter(|review| {
            matches!(
                review["state"].as_str(),
                Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
            ) && review["user"]["id"].as_u64() == Some(reviewer.id)
                && review["user"]["login"].as_str() == Some(reviewer.login.as_str())
                && review["user"]["type"] == "User"
        })
        .collect::<Vec<_>>();
    ensure!(
        decisions
            .iter()
            .all(|review| crate::request::review_order(review).is_some()),
        "configured reviewer has a malformed review timestamp or ID"
    );
    let latest = decisions
        .drain(..)
        .max_by_key(|review| crate::request::review_order(review));
    let review = latest.context("configured reviewer has no approval marker review")?;
    ensure!(
        review["state"] == "APPROVED"
            && review["commit_id"].as_str() == Some(merge.pull_request.head_sha.as_str()),
        "latest configured reviewer decision is not an approval on the exact merge head"
    );
    let body = review["body"]
        .as_str()
        .context("latest configured reviewer approval has no body")?;
    let marker = securefix::api::parse_native_instance_approval_marker(body)?;
    ensure!(
        marker.authority_sha256 == securefix::api::native_authority_sha256(&captured.authority)?,
        "approval marker belongs to a different current Server authority"
    );
    Ok(NativeInstanceApprovalLocator {
        producer_run_id: marker.producer_run_id,
        producer_run_attempt: marker.producer_run_attempt,
        request_sha256: marker.request_sha256,
        authority_sha256: marker.authority_sha256,
    })
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
) -> Result<Option<securefix::api::NativeInstanceMergeFence>> {
    validate_native_merge_pair(&merge.manifest, &approval.manifest)?;
    let manifest = &merge.manifest;
    let api = &merge.client_api;
    verify_current_pull_request(api, manifest)?;

    let expected_policy_id =
        if let Some(expected_control) = merge.target_policy_control_identity.as_deref() {
            let current_policy_control = securefix::api::native_target_policy_control_identity(
                api,
                &manifest.repository.full_name,
                manifest.repository.id,
                &manifest.pull_request.base_ref,
            )?;
            ensure!(
                current_policy_control == expected_control,
                "native target policy control identity changed during request validation"
            );
            Some(format!(
                "{}:{}",
                manifest.pull_request.head_sha, expected_control
            ))
        } else {
            ensure!(
                merge.instance_authority.authority == approval.instance_authority.authority,
                "merge and approval use different current Server instance authorities"
            );
            None
        };

    let Some(expected_policy_id) = expected_policy_id else {
        let approval_digest = securefix::hex_encode(Sha256::digest(&approval.manifest_bytes));
        let readiness = securefix::api::NativeInstanceMergeReadiness {
            repository: &manifest.repository.full_name,
            repository_id: manifest.repository.id,
            pull_number: manifest.pull_request.number,
            head_sha: &manifest.pull_request.head_sha,
            authority: &merge.instance_authority.authority,
            approval_request_sha256: &approval_digest,
            approval_producer_run_id: approval.manifest.producer.run_id,
            approval_producer_run_attempt: approval.manifest.producer.run_attempt,
        };
        return securefix::api::capture_native_instance_merge_fence(api, &merge.config, &readiness)
            .map(Some);
    };

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
    Ok(None)
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
    instance_config_path: &str,
    producer_repository: &str,
    producer_run_id: u64,
    capability: securefix::policy::Capability,
) -> Result<(Vec<u8>, Vec<u8>)> {
    securefix::policy::validate_repository(producer_repository)?;
    ensure!(producer_run_id > 0, "invalid producer run ID");
    let (server_api, captured) = capture_remote_instance_authority(instance_config_path)?;
    let api = securefix::api::GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    download_request_from_run_for_instance(
        &server_api,
        &api,
        &captured,
        producer_repository,
        producer_run_id,
        capability,
    )
}

fn download_request_from_run_for_instance(
    server_api: &securefix::api::GitHub,
    api: &securefix::api::GitHub,
    captured: &securefix::api::NativeServerInstanceAuthority,
    producer_repository: &str,
    producer_run_id: u64,
    capability: securefix::policy::Capability,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (manifest_bytes, bundle_bytes) = download_request_proof_for_instance(
        server_api,
        api,
        captured,
        producer_repository,
        producer_run_id,
        capability,
    )?;
    let manifest: RequestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse downloaded request manifest")?;
    manifest.validate()?;
    let target = captured
        .config
        .repositories
        .iter()
        .find(|r| r.repository == producer_repository)
        .context("producer Client repository is not configured")?;
    ensure!(
        manifest.producer.run_id == producer_run_id
            && manifest.repository.id == target.id
            && manifest.repository.full_name == producer_repository,
        "downloaded request does not identify the selected producer run and Client repository"
    );
    Ok((manifest_bytes, bundle_bytes))
}

pub(crate) fn download_request_proof_for_instance(
    server_api: &securefix::api::GitHub,
    api: &securefix::api::GitHub,
    captured: &securefix::api::NativeServerInstanceAuthority,
    producer_repository: &str,
    producer_run_id: u64,
    capability: securefix::policy::Capability,
) -> Result<(Vec<u8>, Vec<u8>)> {
    securefix::policy::validate_repository(producer_repository)?;
    ensure!(producer_run_id > 0, "invalid producer run ID");
    let config = &captured.config;
    let target = config
        .repositories
        .iter()
        .find(|repository| repository.repository == producer_repository)
        .context("producer Client repository is not configured")?;
    target
        .policy()
        .require(capability)
        .context("producer Client repository lacks the required capability")?;
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
    // Keep the Server reader explicit in this helper even though its current
    // checks are already captured above; callers must not substitute a token
    // scoped only to the Client destination for protected instance reads.
    server_api.require_remote_native_server_instance_authority_unchanged(captured)?;
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
    verify_native_certificate(
        verified,
        &manifest.repository,
        &manifest.producer,
        run,
        signer_repository,
        signer_workflow,
        signer_sha,
        manifest_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_native_certificate(
    verified: &Value,
    repository: &crate::native_client::RepositoryIdentity,
    producer: &crate::native_client::ProducerIdentity,
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
        repository.full_name, producer.run_id, producer.run_attempt
    );
    let expected_signer =
        format!("https://github.com/{signer_repository}/{signer_workflow}@{signer_sha}");
    let expected_config_prefix = format!(
        "https://github.com/{}/{}@",
        repository.full_name, producer.workflow_path
    );
    let workflow_ref = certificate["githubWorkflowRef"]
        .as_str()
        .context("attestation caller workflow ref is missing")?;
    let expected_config = format!("{expected_config_prefix}{}", producer.workflow_ref);
    let owner_id = run["repository"]["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("producer repository owner ID is missing")?;
    ensure!(
        certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["githubWorkflowRepository"].as_str()
                == Some(repository.full_name.as_str())
            && certificate["githubWorkflowSHA"].as_str() == Some(producer.context_sha.as_str())
            && certificate["buildConfigDigest"].as_str() == Some(producer.workflow_sha.as_str())
            && workflow_ref == producer.workflow_ref
            && certificate["buildConfigURI"].as_str() == Some(expected_config.as_str())
            && certificate["githubWorkflowTrigger"].as_str() == Some(producer.event.as_str())
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", repository.full_name)
            && certificate["sourceRepositoryDigest"].as_str()
                == Some(producer.context_sha.as_str())
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(repository.id))
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

    #[test]
    fn request_proof_allows_new_authority_and_request_but_rejects_exact_replay() {
        let manifest = manifest();
        let old = &manifest.server_authority;
        let mut current = old.clone();
        current.config_sha256 = "8".repeat(64);
        let head = &manifest.pull_request.head_sha;
        let old_body =
            securefix::api::native_instance_policy_check_body(old, head, &"1".repeat(64)).unwrap();
        let body =
            securefix::api::native_instance_policy_check_body(&current, head, &"2".repeat(64))
                .unwrap();
        let check = |id, body: &Value| {
            let mut check = body.clone();
            check["id"] = serde_json::json!(id);
            check["app"] = serde_json::json!({"id":42});
            check
        };
        let mut checks = vec![check(1, &old_body)];
        require_new_request_proof_check(&checks, 42, head, body["external_id"].as_str().unwrap())
            .unwrap();
        checks.push(check(2, &body));
        assert!(
            require_new_request_proof_check(
                &checks,
                42,
                head,
                body["external_id"].as_str().unwrap()
            )
            .is_err()
        );
        let another =
            securefix::api::native_instance_policy_check_body(&current, head, &"3".repeat(64))
                .unwrap();
        require_new_request_proof_check(
            &checks,
            42,
            head,
            another["external_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(checks[0]["external_id"], old_body["external_id"]);
    }

    #[test]
    fn configured_client_package_keeps_prerelease_acceptance_explicit_without_fallback() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let signer = "a".repeat(40);
        let action = securefix::package::PinnedPackageAction::new(
            config.acceptable_clients.repository.clone(),
            ".github/actions/load-package".into(),
            "b".repeat(40),
        )
        .unwrap();
        let repo = config.acceptable_clients.repository.clone();
        let repository = serde_json::json!({
            "id": config.acceptable_clients.id,
            "full_name": repo,
            "default_branch": "main",
            "owner": {"id": 44, "login": "example-org"}
        });
        let cargo = r#"[package]
name = "securefix"
version = "1.4.0-pre.1"
"#;
        let stable = Fixture::new(vec![
            Route::get(format!("/repos/{repo}"), repository.clone()),
            Route::get(format!("/repos/{repo}"), repository),
            Route::get(
                format!("/repos/{repo}/contents/Cargo.toml?ref={signer}"),
                serde_json::json!({
                    "path": "Cargo.toml", "type": "file", "size": cargo.len(), "encoding": "base64",
                    "content": base64::engine::general_purpose::STANDARD.encode(cargo)
                }),
            ),
        ]);
        let error =
            verify_configured_client_package(&stable.api, &config, &signer, &action).unwrap_err();
        assert!(
            error.to_string().contains("canonical SemVer allowed"),
            "{error:#}"
        );
        stable.finish();
        config.scratch_package_repository = Some(securefix::config::Repository {
            repository: "example-org/scratch".into(),
            id: 888,
            default_branch: "main".into(),
        });
        let scratch = Fixture::new(vec![Route::get(
            format!(
                "/repos/{repo}/contents/.github/actions/load-package/package.json?ref={}",
                "b".repeat(40)
            ),
            serde_json::json!({"path": ".github/actions/load-package/package.json", "type": "file",
                "size": 2, "encoding": "base64", "content": "e30="}),
        )]);
        let error =
            verify_configured_client_package(&scratch.api, &config, &signer, &action).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pinned Client package action manifest is invalid"),
            "{error:#}"
        );
        scratch.finish();
    }

    #[test]
    fn native_label_event_locator_binds_operation_repository_and_run() {
        let payload = serde_json::json!({
            "action": "created",
            "label": {
                "name": "securefix-native-merge-123",
                "description": "owner/client-repo/123"
            }
        });
        assert_eq!(
            native_request_event_locator(&payload, "merge").unwrap(),
            ("owner/client-repo".to_owned(), 123)
        );
        assert!(native_request_event_locator(&payload, "approve").is_err());
        let mut wrong_id = payload.clone();
        wrong_id["label"]["description"] = serde_json::json!("owner/client-repo/124");
        assert!(native_request_event_locator(&wrong_id, "merge").is_err());
        let mut bad_repo = payload.clone();
        bad_repo["label"]["description"] = serde_json::json!("owner/../repo/123");
        assert!(native_request_event_locator(&bad_repo, "merge").is_err());
    }

    #[test]
    fn configured_common_signer_is_unique_without_rejecting_nested_workflows() {
        let sha = "a".repeat(40);
        let references = vec![
            securefix::workflow::ReferencedWorkflow {
                path: "owner/client/.github/workflows/approve-request.yml@refs/heads/main".into(),
                sha: "b".repeat(40),
            },
            securefix::workflow::ReferencedWorkflow {
                path: format!("owner/client/.github/workflows/reusable-approve-request.yml@{sha}"),
                sha: "c".repeat(40),
            },
            securefix::workflow::ReferencedWorkflow {
                path: format!("owner/client/.github/workflows/reusable-client-request.yml@{sha}"),
                sha: sha.clone(),
            },
        ];
        assert_eq!(
            unique_referenced_workflow_sha(
                &references,
                "owner/client",
                ".github/workflows/reusable-client-request.yml"
            )
            .unwrap(),
            sha
        );

        let mut duplicate = references.clone();
        duplicate.push(references[2].clone());
        assert!(
            unique_referenced_workflow_sha(
                &duplicate,
                "owner/client",
                ".github/workflows/reusable-client-request.yml"
            )
            .is_err()
        );

        let mut malformed = references;
        malformed[2].path.push_str("/suffix");
        assert!(
            unique_referenced_workflow_sha(
                &malformed,
                "owner/client",
                ".github/workflows/reusable-client-request.yml"
            )
            .is_err()
        );
    }

    #[test]
    fn normal_request_event_binds_client_app_instance_operation_and_run() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let manifest = RequestManifest {
            protocol: REQUEST_PROTOCOL.to_owned(),
            operation: "merge".to_owned(),
            repository: crate::native_client::RepositoryIdentity {
                id: 42,
                full_name: "owner/client".to_owned(),
            },
            pull_request: crate::native_client::PullRequestIdentity {
                number: 9,
                head_sha: "a".repeat(40),
                head_branch: "main".to_owned(),
                head_repository_id: 42,
                base_sha: "b".repeat(40),
                base_ref: "main".to_owned(),
                author_id: 1,
                author_login: "owner".to_owned(),
            },
            command_comment: None,
            producer: crate::native_client::ProducerIdentity {
                run_id: 123,
                run_attempt: 1,
                event: "issue_comment".to_owned(),
                context_sha: "b".repeat(40),
                source_sha: "a".repeat(40),
                workflow_path: ".github/workflows/client.yml".to_owned(),
                workflow_ref: "owner/client/.github/workflows/client.yml@refs/heads/main"
                    .to_owned(),
                workflow_sha: "c".repeat(40),
                actor_id: 1,
                actor_login: "owner".to_owned(),
            },
            securefix_artifact: None,
            client_workflow_epoch: "d".repeat(40),
            server_authority: securefix::api::NativeAuthoritySnapshot {
                instance_repository: config.instance.repository.clone(),
                instance_id: config.instance.id,
                default_branch: config.instance.default_branch.clone(),
                config_path: "securefix-server.toml".to_owned(),
                config_sha256: "e".repeat(64),
                epoch: "f".repeat(40),
                workflows: vec![],
            },
        };
        let client_bot = &config.identities.client_bot;
        let payload = serde_json::json!({
            "action": "created",
            "repository": { "full_name": config.instance.repository },
            "sender": { "id": client_bot.id, "login": client_bot.login, "type": "Bot" },
            "label": { "name": "securefix-native-merge-123", "description": "owner/client/123" }
        });
        assert!(
            validate_native_request_event_payload(
                &config,
                &manifest,
                &payload,
                securefix::api::NativeScratchMode::Merge
            )
            .is_ok()
        );

        let mut approval = manifest.clone();
        approval.operation = "approval".to_owned();
        approval.producer.run_id = 122;
        assert!(
            validate_native_request_event_payload(
                &config,
                &approval,
                &payload,
                securefix::api::NativeScratchMode::Merge
            )
            .is_ok()
        );
        validate_native_merge_pair(&manifest, &approval).unwrap();
        assert!(
            validate_native_request_event_payload(
                &config,
                &approval,
                &payload,
                securefix::api::NativeScratchMode::Approval
            )
            .is_err()
        );
        let mut other_client = payload.clone();
        other_client["label"]["description"] = serde_json::json!("owner/other/123");
        assert!(
            validate_native_request_event_payload(
                &config,
                &approval,
                &other_client,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
        let mut same_run = approval.clone();
        same_run.producer.run_id = manifest.producer.run_id;
        assert!(
            validate_native_request_event_payload(
                &config,
                &same_run,
                &payload,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
        for proof in [&manifest, &approval] {
            let mut forged = payload.clone();
            forged["sender"]["id"] = serde_json::json!(u64::MAX);
            assert!(
                validate_native_request_event_payload(
                    &config,
                    proof,
                    &forged,
                    securefix::api::NativeScratchMode::Merge
                )
                .is_err()
            );
        }

        let mut wrong_action = payload.clone();
        wrong_action["action"] = serde_json::json!("edited");
        assert!(
            validate_native_request_event_payload(
                &config,
                &manifest,
                &wrong_action,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
        let mut wrong_actor = payload.clone();
        wrong_actor["sender"]["id"] = serde_json::json!(u64::MAX);
        assert!(
            validate_native_request_event_payload(
                &config,
                &manifest,
                &wrong_actor,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
        let mut wrong_operation = payload.clone();
        wrong_operation["label"]["name"] = serde_json::json!("securefix-native-approve-123");
        assert!(
            validate_native_request_event_payload(
                &config,
                &manifest,
                &wrong_operation,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
        let mut wrong_run = payload.clone();
        wrong_run["label"]["description"] = serde_json::json!("owner/client/124");
        assert!(
            validate_native_request_event_payload(
                &config,
                &manifest,
                &wrong_run,
                securefix::api::NativeScratchMode::Merge
            )
            .is_err()
        );
    }

    #[test]
    fn observed_normal_merge_event_authenticates_both_request_proofs() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/native-merge-event-pair.json"
        ))
        .unwrap();
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-role-events-test-instance.toml"
        ))
        .unwrap();
        let merge: RequestManifest = serde_json::from_value(fixture["merge"].clone()).unwrap();
        let approval: RequestManifest =
            serde_json::from_value(fixture["approval"].clone()).unwrap();
        merge.validate().unwrap();
        approval.validate().unwrap();
        for request in [&merge, &approval] {
            validate_native_request_event_payload(
                &config,
                request,
                &fixture["event"],
                securefix::api::NativeScratchMode::Merge,
            )
            .unwrap();
        }
        validate_native_merge_pair(&merge, &approval).unwrap();
        let mut other_head = approval.clone();
        other_head.pull_request.head_sha = "a".repeat(40);
        assert!(validate_native_merge_pair(&merge, &other_head).is_err());
        let mut stale_authority = approval.clone();
        stale_authority.server_authority.epoch = "a".repeat(40);
        assert!(validate_native_merge_pair(&merge, &stale_authority).is_err());
    }

    #[test]
    fn normal_scratch_label_retains_client_app_and_owner_caller_authority() {
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-securefix-write-test-instance.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.operation = "securefix".to_owned();
        request.repository.id = 1410312556;
        request.repository.full_name = "civitaspo/testing-securefix-server".to_owned();
        request.producer.event = "pull_request_target".to_owned();
        request.producer.workflow_path = ".github/workflows/securefix-request.yml".to_owned();
        request.producer.workflow_ref = "refs/heads/main".to_owned();
        request.producer.actor_id = config.identities.owner.id;
        request.producer.actor_login = config.identities.owner.login.clone();
        request.pull_request.author_id = config.identities.owner.id;
        request.pull_request.author_login = config.identities.owner.login.clone();
        let payload = serde_json::json!({
            "action": "created",
            "repository": {"full_name": config.instance.repository},
            "sender": {"id": config.identities.client_bot.id, "login": config.identities.client_bot.login, "type": "Bot"},
            "label": {"name": format!("securefix-native-securefix-{}", request.producer.run_id),
                "description": format!("{}/{}", request.repository.full_name, request.producer.run_id)}
        });
        assert!(
            validate_native_request_event_payload(
                &config,
                &request,
                &payload,
                securefix::api::NativeScratchMode::Securefix
            )
            .is_ok()
        );
        let mut forged = payload.clone();
        forged["sender"]["id"] = serde_json::json!(config.identities.owner.id);
        assert!(
            validate_native_request_event_payload(
                &config,
                &request,
                &forged,
                securefix::api::NativeScratchMode::Securefix
            )
            .is_err()
        );
        request.producer.actor_id += 1;
        assert!(
            validate_native_request_event_payload(
                &config,
                &request,
                &payload,
                securefix::api::NativeScratchMode::Securefix
            )
            .is_err()
        );
        request.producer.actor_id = config.identities.owner.id;
        request.pull_request.author_id += 1;
        assert!(
            validate_native_request_event_payload(
                &config,
                &request,
                &payload,
                securefix::api::NativeScratchMode::Securefix
            )
            .is_err()
        );
        request.pull_request.author_id = config.identities.owner.id;
        config.scratch_request_callers.clear();
        assert!(
            validate_native_request_event_payload(
                &config,
                &request,
                &payload,
                securefix::api::NativeScratchMode::Securefix
            )
            .is_err()
        );
    }

    #[test]
    fn scratch_package_accepts_server_owned_prs_without_minting_owner_commands() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-role-events-test-instance.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.repository.id = 1410312556;
        request.repository.full_name = "civitaspo/testing-securefix-server".into();
        request.producer.workflow_ref = "refs/heads/main".into();
        request.pull_request.author_id = config.identities.server_bot.id;
        request.pull_request.author_login = config.identities.server_bot.login.clone();
        for (operation, mode, caller, event) in [
            (
                "policy_check",
                securefix::api::NativeScratchMode::PolicyCheck,
                "policy-check.yml",
                "pull_request_target",
            ),
            (
                "approval",
                securefix::api::NativeScratchMode::Approval,
                "approve-request.yml",
                "issue_comment",
            ),
            (
                "merge",
                securefix::api::NativeScratchMode::Merge,
                "merge-request.yml",
                "issue_comment",
            ),
        ] {
            request.operation = operation.into();
            request.producer.workflow_path = format!(".github/workflows/{caller}");
            request.producer.event = event.into();
            request.producer.actor_id = config.identities.owner.id;
            request.producer.actor_login = config.identities.owner.login.clone();
            let label =
                securefix::api::native_client_request_label(operation, request.producer.run_id)
                    .unwrap();
            let payload = serde_json::json!({
                "action":"created", "repository":{"full_name":config.instance.repository},
                "sender":{"id":config.identities.client_bot.id,"login":config.identities.client_bot.login,"type":"Bot"},
                "label":{"name":label,"description":format!("{}/{}",request.repository.full_name,request.producer.run_id)}
            });
            validate_native_request_event_payload(&config, &request, &payload, mode).unwrap();
            request.producer.actor_id = config.identities.server_bot.id;
            request.producer.actor_login = config.identities.server_bot.login.clone();
            assert_eq!(
                validate_native_request_event_payload(&config, &request, &payload, mode).is_ok(),
                operation == "policy_check"
            );
            request.producer.actor_login.push_str("-forged");
            assert!(
                validate_native_request_event_payload(&config, &request, &payload, mode).is_err()
            );
            request.producer.actor_id = config.identities.owner.id;
            request.producer.actor_login = config.identities.owner.login.clone();
            request.pull_request.author_login.push_str("-forged");
            assert!(
                validate_native_request_event_payload(&config, &request, &payload, mode).is_err()
            );
            request.pull_request.author_login = config.identities.server_bot.login.clone();
        }
    }

    #[test]
    fn stable_client_branch_requires_authenticated_configured_repository_identity() {
        let acceptable = securefix::instance_config::AcceptableClients {
            repository: "owner/client".to_owned(),
            id: 42,
            producer_workflow: ".github/workflows/producer.yml".to_owned(),
            version: semver::VersionReq::parse(">=1.4.0").unwrap(),
        };
        let metadata = serde_json::json!({
            "id": 42,
            "full_name": "owner/client",
            "default_branch": "main"
        });
        assert_eq!(
            verified_client_default_branch(&metadata, &acceptable).unwrap(),
            "main"
        );
        let wrong_id = serde_json::json!({
            "id": 43,
            "full_name": "owner/client",
            "default_branch": "main"
        });
        assert!(verified_client_default_branch(&wrong_id, &acceptable).is_err());
        let wrong_name = serde_json::json!({
            "id": 42,
            "full_name": "owner/other",
            "default_branch": "main"
        });
        assert!(verified_client_default_branch(&wrong_name, &acceptable).is_err());
        let invalid_branch = serde_json::json!({
            "id": 42,
            "full_name": "owner/client",
            "default_branch": "../main"
        });
        assert!(verified_client_default_branch(&invalid_branch, &acceptable).is_err());
    }

    #[test]
    fn policy_check_run_locators_must_match_the_attested_request() {
        let request = manifest();
        assert!(
            validate_policy_check_request_locator(
                &request,
                42,
                "owner/project",
                7,
                &"d".repeat(40)
            )
            .is_ok()
        );
        assert!(
            validate_policy_check_request_locator(
                &request,
                43,
                "owner/project",
                7,
                &"d".repeat(40)
            )
            .is_err()
        );
        assert!(
            validate_policy_check_request_locator(
                &request,
                42,
                "other/project",
                7,
                &"d".repeat(40)
            )
            .is_err()
        );
        assert!(
            validate_policy_check_request_locator(
                &request,
                42,
                "owner/project",
                8,
                &"d".repeat(40)
            )
            .is_err()
        );
        assert!(
            validate_policy_check_request_locator(
                &request,
                42,
                "owner/project",
                7,
                &"c".repeat(40)
            )
            .is_err()
        );
        let mut wrong_operation = request;
        wrong_operation.operation = "approval".to_owned();
        assert!(
            validate_policy_check_request_locator(
                &wrong_operation,
                42,
                "owner/project",
                7,
                &"d".repeat(40)
            )
            .is_err()
        );
    }

    #[test]
    fn client_package_action_repeated_bindings_must_be_identical_immutable_pins() {
        let repo = "client-org/securefix-server";
        let sha = "a".repeat(40);
        let workflow = format!(
            "jobs:\n  request:\n    steps:\n      - uses: {repo}/.github/actions/load-package@{sha}\n"
        );
        assert_eq!(
            native_client_package_action(workflow.as_bytes(), repo).unwrap(),
            securefix::package::PinnedPackageAction::new(
                repo.to_owned(),
                ".github/actions/load-package".to_owned(),
                sha.clone(),
            )
            .unwrap()
        );

        let mutable_ref = workflow.replace(&sha, "main");
        assert!(native_client_package_action(mutable_ref.as_bytes(), repo).is_err());
        let duplicate =
            format!("{workflow}  second:\n    uses: {repo}/.github/actions/load-package@{sha}\n");
        assert_eq!(
            native_client_package_action(duplicate.as_bytes(), repo).unwrap(),
            securefix::package::PinnedPackageAction::new(
                repo.to_owned(),
                ".github/actions/load-package".to_owned(),
                sha.clone(),
            )
            .unwrap()
        );

        let mixed = duplicate.replacen(&sha, &"b".repeat(40), 1);
        assert!(native_client_package_action(mixed.as_bytes(), repo).is_err());

        let relocated = workflow.replace(
            ".github/actions/load-package",
            "actions/packages/Native Client loader",
        );
        assert_eq!(
            native_client_package_action(relocated.as_bytes(), repo).unwrap(),
            securefix::package::PinnedPackageAction::new(
                repo.to_owned(),
                "actions/packages/Native Client loader".to_owned(),
                sha.clone(),
            )
            .unwrap()
        );
        let mixed_path = format!(
            "{workflow}  other:\n    uses: {repo}/actions/packages/Native Client loader@{sha}\n"
        );
        assert!(native_client_package_action(mixed_path.as_bytes(), repo).is_err());

        assert!(
            securefix::package::PinnedPackageAction::new(
                repo.to_owned(),
                "../outside".to_owned(),
                sha.clone(),
            )
            .is_err()
        );
        assert!(
            securefix::package::PinnedPackageAction::new(
                repo.to_owned(),
                "/absolute/action".to_owned(),
                sha.clone(),
            )
            .is_err()
        );

        let other_repository = workflow.replace(
            &format!("{repo}/.github/actions/load-package@"),
            "attacker/securefix-server/.github/actions/load-package@",
        );
        assert!(native_client_package_action(other_repository.as_bytes(), repo).is_err());

        let absent = b"jobs:\n  request:\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n";
        assert!(native_client_package_action(absent, repo).is_err());
        assert!(native_client_package_action(workflow.as_bytes(), "other-org/server").is_err());
        let non_string_uses =
            b"jobs:\n  request:\n    steps:\n      - uses: { unexpected: value }\n";
        assert!(native_client_package_action(non_string_uses, repo).is_err());
    }

    #[test]
    fn scratch_client_signer_uses_one_repeated_immutable_package_action_binding() {
        let workflow = include_bytes!("../.github/workflows/reusable-client-request-scratch.yml");
        let action = native_client_package_action(workflow, "civitaspo/securefix-server").unwrap();
        assert_eq!(action.revision().len(), 40);
    }

    #[test]
    fn scratch_package_publication_json_is_bounded_and_strict() {
        let json = format!(
            r#"{{"source_sha":"{}","source_branch":"integration/native-package-pre23","tag":"v0.2.45-pre.23","release_id":420735040,"asset_id":665912019,"asset_sha256":"{}","asset_size":11767224,"producer_run_id":39783133806,"producer_run_attempt":1,"publisher_workflow":".github/workflows/testing-publish-native-package.yml","publisher_branch":"main","publisher_sha":"{}","publisher_run_id":39783817011,"publisher_run_attempt":1}}"#,
            "3b88bcd0e228791e355aec238d5c7e95027b3f6f",
            "fd72ab4c2f767aaaf46f8d67537187f0496e4312922e33ef6a8348ec2dac1936",
            "6be9fb42e14770a9162301787e158f7db3ab918a",
        );
        let record = parse_scratch_package_publication_input(&json).unwrap();
        assert_eq!(
            record.source_sha,
            "3b88bcd0e228791e355aec238d5c7e95027b3f6f"
        );
        assert_eq!(record.producer_run_id, 39783133806);
        assert_eq!(
            record.publisher_workflow,
            ".github/workflows/testing-publish-native-package.yml"
        );
        assert_eq!(record.publisher_branch, "main");
        assert_eq!(
            record.publisher_sha,
            "6be9fb42e14770a9162301787e158f7db3ab918a"
        );
        assert_eq!(record.publisher_run_id, 39783817011);
        assert_eq!(record.publisher_run_attempt, 1);
        let instance = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-securefix-test-instance.toml"
        ))
        .unwrap();
        let publication = scratch_package_publication(&json, &instance).unwrap();
        assert_eq!(
            publication.destination_repository,
            "civitaspo/testing-securefix-server"
        );
        assert_eq!(publication.destination_repository_id, 1_410_312_556);
        let instance_without_scratch_package = securefix::instance_config::InstanceConfig::parse(
            include_bytes!("../tests/fixtures/instance-config.toml"),
        )
        .unwrap();
        assert!(scratch_package_publication(&json, &instance_without_scratch_package).is_err());
        assert!(parse_scratch_package_publication_input(&format!("{json} ")).is_ok());
        assert!(
            parse_scratch_package_publication_input(&json.replace(
                "\"release_id\":420735040,",
                "\"release_id\":420735040,\"extra\":true,",
            ))
            .is_err()
        );
        assert!(
            parse_scratch_package_publication_input(
                &json.replace(",\"publisher_run_attempt\":1", "")
            )
            .is_err()
        );
        assert!(parse_scratch_package_publication_input(&" ".repeat(4097)).is_err());
    }

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
            command_comment: None,
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
        for event in ["pull_request_target", "pull_request"] {
            let mut manifest = manifest();
            manifest.operation = "securefix".into();
            manifest.producer.event = event.into();
            manifest.pull_request.base_sha = "f".repeat(40);
            manifest.producer.context_sha = "9".repeat(40);
            manifest.producer.source_sha = manifest.pull_request.head_sha.clone();
            let fix = crate::securefix_gate::artifact::FixArtifact {
                repository: manifest.repository.full_name.clone(),
                branch: manifest.pull_request.head_branch.clone(),
                run_id: manifest.producer.run_id,
                source_sha: manifest.producer.source_sha.clone(),
                event_name: event.into(),
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
                additions: std::collections::BTreeMap::from([(
                    "README.md".into(),
                    b"test".to_vec(),
                )]),
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
    fn pull_request_events_accept_distinct_execution_and_pr_base_snapshots() {
        let snapshots: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/native-client-base-snapshots.json"
        ))
        .unwrap();
        for (snapshot, event) in snapshots.iter().flat_map(|snapshot| {
            ["pull_request_target", "pull_request"].map(|event| (snapshot, event))
        }) {
            let mut manifest = manifest();
            manifest.producer.event = event.into();
            manifest.producer.source_sha = snapshot["source_sha"].as_str().unwrap().into();
            manifest.producer.context_sha = snapshot["context_sha"].as_str().unwrap().into();
            manifest.pull_request.head_sha = manifest.producer.source_sha.clone();
            manifest.pull_request.head_branch = snapshot["head_branch"].as_str().unwrap().into();
            manifest.pull_request.base_sha = snapshot["base_sha"].as_str().unwrap().into();
            let run = serde_json::json!({
                "id":42,"run_attempt":2,"status":"completed","conclusion":"success",
                "event":event,"head_sha":manifest.producer.source_sha,
                "head_branch":manifest.pull_request.head_branch,
                "repository":{"id":10,"full_name":"owner/project","owner":{"id":20}},
                "actor":{"id":12,"login":"maintainer"},"path":".github/workflows/client.yml"
            });
            verify_run_identity(&run, &manifest).unwrap();
            let verified = verifier_result(
                &manifest,
                "https://github.com/owner/project/actions/runs/42/attempts/2".into(),
            );
            let bytes = serde_json::to_vec(&manifest).unwrap();
            verify_certificate(
                &verified,
                &manifest,
                &run,
                "client-org/securefix-client",
                ".github/workflows/request-producer.yml",
                &"c".repeat(40),
                &bytes,
            )
            .unwrap();
            let mut changed = manifest.clone();
            changed.producer.context_sha = "0".repeat(40);
            assert!(
                verify_certificate(
                    &verified,
                    &changed,
                    &run,
                    "client-org/securefix-client",
                    ".github/workflows/request-producer.yml",
                    &"c".repeat(40),
                    &bytes
                )
                .is_err()
            );
            changed = manifest.clone();
            changed.pull_request.head_sha = "0".repeat(40);
            assert!(verify_run_identity(&run, &changed).is_err());
            changed = manifest;
            changed.pull_request.head_branch = "another-branch".into();
            assert!(verify_run_identity(&run, &changed).is_err());
        }
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
    fn owner_selected_package_requires_the_configured_scratch_caller_tuple() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-securefix-write-test-instance.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.operation = "securefix".to_owned();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 1410312556,
            full_name: "civitaspo/testing-securefix-server".to_owned(),
        };
        request.producer.event = "pull_request_target".to_owned();
        request.producer.workflow_path = ".github/workflows/securefix-request.yml".to_owned();
        request.producer.workflow_ref = "refs/heads/main".to_owned();
        assert!(validate_owner_selected_request_caller(&config, &request).is_ok());

        for (repository, repository_id, path, reference, event, operation) in [
            (
                "civitaspo/other",
                request.repository.id,
                request.producer.workflow_path.as_str(),
                request.producer.workflow_ref.as_str(),
                request.producer.event.as_str(),
                request.operation.as_str(),
            ),
            (
                request.repository.full_name.as_str(),
                request.repository.id + 1,
                request.producer.workflow_path.as_str(),
                request.producer.workflow_ref.as_str(),
                request.producer.event.as_str(),
                request.operation.as_str(),
            ),
            (
                request.repository.full_name.as_str(),
                request.repository.id,
                ".github/workflows/native-merge-producer.yml",
                request.producer.workflow_ref.as_str(),
                request.producer.event.as_str(),
                request.operation.as_str(),
            ),
            (
                request.repository.full_name.as_str(),
                request.repository.id,
                request.producer.workflow_path.as_str(),
                "refs/heads/release",
                request.producer.event.as_str(),
                request.operation.as_str(),
            ),
            (
                request.repository.full_name.as_str(),
                request.repository.id,
                request.producer.workflow_path.as_str(),
                request.producer.workflow_ref.as_str(),
                "workflow_dispatch",
                request.operation.as_str(),
            ),
            (
                request.repository.full_name.as_str(),
                request.repository.id,
                request.producer.workflow_path.as_str(),
                request.producer.workflow_ref.as_str(),
                request.producer.event.as_str(),
                "merge",
            ),
        ] {
            let mut changed = request.clone();
            changed.repository.full_name = repository.to_owned();
            changed.repository.id = repository_id;
            changed.producer.workflow_path = path.to_owned();
            changed.producer.workflow_ref = reference.to_owned();
            changed.producer.event = event.to_owned();
            changed.operation = operation.to_owned();
            assert!(validate_owner_selected_request_caller(&config, &changed).is_err());
        }

        let mut missing_caller = config;
        missing_caller.scratch_request_callers.clear();
        assert!(validate_owner_selected_request_caller(&missing_caller, &request).is_err());
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
                true,
            )
            .is_ok()
        );

        request.producer.actor_id = 12;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
                true,
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
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn owner_selected_package_requires_the_configured_owner_actor_and_author() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-securefix-test-instance.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.operation = "policy_check".to_owned();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 1410312556,
            full_name: "civitaspo/testing-securefix-server".to_owned(),
        };
        request.pull_request.head_repository_id = request.repository.id;
        request.pull_request.author_id = 4525500;
        request.pull_request.author_login = "civitaspo".to_owned();
        request.producer.actor_id = 4525500;
        request.producer.actor_login = "civitaspo".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
                true,
            )
            .is_ok()
        );

        request.producer.actor_id += 1;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
                true,
            )
            .is_err()
        );
        request.producer.actor_id = 4525500;
        request.pull_request.author_login = "another-user".to_owned();
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::PolicyCheck,
                true,
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
                true,
            )
            .is_ok()
        );

        request.repository.id += 1;
        assert!(
            validate_first_slice_policy(
                &config,
                &request,
                securefix::api::NativeScratchMode::Securefix,
                true,
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
                true,
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
                true,
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
                true,
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
                true,
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
                true,
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
                true,
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
                true,
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
        let repo = serde_json::json!({
            "id":10,"full_name":"owner/project","default_branch":"main"
        });
        let pull = serde_json::json!({
            "number":7,"state":"open",
            "base":{"repo":{"id":10,"full_name":"owner/project"},"ref":"main","sha":request.pull_request.base_sha},
            "head":{"repo":{"id":10},"ref":request.pull_request.head_branch,"sha":request.pull_request.head_sha},
            "user":{"id":11,"login":"contributor"}
        });
        // The producer can be a Server bot running CI after a signed fix;
        // the PR author remains independently bound to the live PR identity.
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

    #[test]
    fn release_timeline_binds_actual_merge_close_and_automatic_branch_deletion() {
        let events: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/native-release-merged-timeline.json"
        ))
        .unwrap();
        let command_at = parse_comment_time(&serde_json::json!("2026-10-23T10:11:48Z")).unwrap();
        let merged_at = parse_comment_time(&serde_json::json!("2026-10-23T10:19:45Z")).unwrap();
        let merger = crate::config::Principal {
            id: 288069019,
            login: "civitaspo-securefix-server[bot]".to_owned(),
        };
        let merge_sha = "3845f9810414bd818dfd2c9c818aa9014652fb3b";
        let check = |events: &[Value]| {
            validate_native_release_timeline(events, command_at, &merged_at, &merger, merge_sha)
        };
        assert!(check(&events).is_ok());
        for kind in ["merged", "closed", "head_ref_deleted"] {
            let mut wrong_actor = events.clone();
            wrong_actor
                .iter_mut()
                .find(|event| event["event"] == kind)
                .unwrap()["actor"]["id"] = serde_json::json!(7);
            assert!(check(&wrong_actor).is_err(), "{kind}");
            let mut missing_time = events.clone();
            missing_time
                .iter_mut()
                .find(|event| event["event"] == kind)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("created_at");
            assert!(check(&missing_time).is_err(), "{kind}");
        }
        let mut wrong_merge = events.clone();
        wrong_merge
            .iter_mut()
            .find(|event| event["event"] == "merged")
            .unwrap()["commit_id"] = serde_json::json!("a".repeat(40));
        assert!(check(&wrong_merge).is_err());
        for kind in ["reopened", "head_ref_force_pushed", "base_ref_changed"] {
            let mut invalidated = events.clone();
            invalidated.push(serde_json::json!({"event":kind,"created_at":"2026-10-23T10:15:00Z","actor":{"id":merger.id,"login":merger.login}}));
            assert!(check(&invalidated).is_err(), "{kind}");
        }
        let mut premature_delete = events.clone();
        premature_delete
            .iter_mut()
            .find(|event| event["event"] == "head_ref_deleted")
            .unwrap()["created_at"] = serde_json::json!("2026-10-23T10:15:00Z");
        assert!(check(&premature_delete).is_err());
        let mut duplicate = events.clone();
        duplicate.push(
            events
                .iter()
                .find(|event| event["event"] == "merged")
                .unwrap()
                .clone(),
        );
        assert!(check(&duplicate).is_err());
    }

    #[test]
    fn release_approval_marker_rejects_later_review_decisions() {
        let marker = serde_json::json!({
            "id": 9,
            "state": "APPROVED",
            "submitted_at": "2026-10-22T10:30:00Z"
        });
        let earlier = serde_json::json!({
            "id": 8,
            "state": "CHANGES_REQUESTED",
            "submitted_at": "2026-10-22T10:20:00Z"
        });
        assert!(
            require_no_later_release_review_decision(&[earlier, marker.clone()], &marker).is_ok()
        );

        let later = serde_json::json!({
            "id": 10,
            "state": "CHANGES_REQUESTED",
            "submitted_at": "2026-10-22T10:40:00Z"
        });
        assert!(
            require_no_later_release_review_decision(&[marker.clone(), later], &marker).is_err()
        );

        let same_time_later_id = serde_json::json!({
            "id": 11,
            "state": "APPROVED",
            "submitted_at": "2026-10-22T10:30:00Z"
        });
        assert!(
            require_no_later_release_review_decision(
                &[marker.clone(), same_time_later_id],
                &marker
            )
            .is_err()
        );
    }
}
