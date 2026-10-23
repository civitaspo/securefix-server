use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use crate::api::{ApiError, GitHub, NativeAuthoritySnapshot, NativeServerInstanceAuthority};
use crate::policy::{Capability, Policy, ReleaseStrategy, validate_repository};
use crate::workflow::{
    ReferencedWorkflow, referenced_revision, require_current_runtime, successful_source_run,
    write_json,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
pub use securefix::release_manifest::{
    CommitSha, ReleaseManifestV2, ReleaseTag, Repository, RunId,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_PROVIDER_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PROVIDER_ARCHIVE_FILES: usize = 32;
const MAX_NATIVE_ASSET_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NATIVE_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const NATIVE_BUNDLE_NAME: &str = "native-bundle";
const NATIVE_BUNDLE_MANIFEST: &str = "native-assets.json";
const NATIVE_TARGET_MANIFEST: &str = "native-target.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderTarget {
    pub os: &'static str,
    pub arch: &'static str,
}

pub const PROVIDER_TARGETS: &[ProviderTarget] = &[
    ProviderTarget {
        os: "freebsd",
        arch: "amd64",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "386",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "arm",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "arm64",
    },
    ProviderTarget {
        os: "windows",
        arch: "amd64",
    },
    ProviderTarget {
        os: "windows",
        arch: "386",
    },
    ProviderTarget {
        os: "windows",
        arch: "arm64",
    },
    ProviderTarget {
        os: "linux",
        arch: "amd64",
    },
    ProviderTarget {
        os: "linux",
        arch: "386",
    },
    ProviderTarget {
        os: "linux",
        arch: "arm",
    },
    ProviderTarget {
        os: "linux",
        arch: "arm64",
    },
    ProviderTarget {
        os: "darwin",
        arch: "amd64",
    },
    ProviderTarget {
        os: "darwin",
        arch: "arm64",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlanV2 {
    pub schema_version: u8,
    pub server_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_authority: Option<NativeAuthoritySnapshot>,
    /// Digest of the exact `manifest.json` bytes fetched from the source run.
    /// Older plans may deserialize, but publication requires this binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest_sha256: Option<String>,
    /// Exact release-request PR head admitted by the instance-authority path.
    /// The legacy release flow leaves this unset; native publication requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_pr_head_sha: Option<String>,
    /// OSS Client package admitted from the configured distributor and channel.
    /// Bytes are re-resolved and the full identity compared immediately before write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_package: Option<NativeClientPackageSnapshot>,
    pub repository: String,
    pub strategy: ReleaseStrategy,
    pub source_run_id: RunId,
    pub source_run_attempt: u64,
    pub source_revision: String,
    pub release_pr_number: u64,
    pub release_pr_sha: String,
    pub tag: ReleaseTag,
    pub source_manifest: ReleaseManifestV2,
    #[serde(default)]
    pub native_binary_repository: Option<String>,
    pub release_id: Option<u64>,
    #[serde(default)]
    pub existing_signature_sha256: Option<String>,
    pub assets: Vec<PlannedAsset>,
    #[serde(default)]
    pub native_assets: Vec<NativeAssetEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeClientPackageSnapshot {
    pub distributor_repository: String,
    pub distributor_id: u64,
    pub release_repository: String,
    pub release_repository_id: u64,
    pub implementation_sha: String,
    pub implementation_version: String,
    pub loader_action_sha: String,
    pub loader_action_path: String,
    pub binary_source_sha: String,
    pub binary_version: String,
    pub protocol: String,
    pub release_tag: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub asset_name: String,
    pub asset_size: u64,
    pub asset_sha256: String,
    pub package_publisher_workflow: String,
    pub package_publisher_branch: String,
    pub package_publisher_sha: String,
    pub package_publisher_run_id: u64,
    pub package_publisher_run_attempt: u64,
    pub package_producer_workflow: String,
    pub package_producer_branch: String,
    pub package_producer_run_id: u64,
    pub package_producer_run_attempt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedAsset {
    pub name: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssetManifest {
    pub schema_version: u8,
    pub repository: String,
    pub source_run_id: RunId,
    pub source_run_sha: CommitSha,
    pub run_attempt: u64,
    pub source_revision: CommitSha,
    pub release_pr_number: u64,
    pub release_pr_sha: CommitSha,
    pub tag: ReleaseTag,
    pub package_version: String,
    pub assets: Vec<NativeAssetEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssetEvidence {
    pub target: String,
    pub runner: String,
    pub runner_name: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub version_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTargetEvidence {
    pub schema_version: u8,
    pub source_run_id: RunId,
    pub source_run_attempt: u64,
    pub source_run_sha: CommitSha,
    pub release_pr_number: u64,
    pub release_pr_sha: CommitSha,
    pub package_version: String,
    pub target: String,
    pub runner: String,
    pub runner_name: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub filename: String,
    pub version_output: String,
}

impl ReleasePlanV2 {
    fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 2, "unsupported release plan schema");
        validate_repository(&self.repository)?;
        CommitSha::parse(&self.server_revision)?;
        if let Some(authority) = &self.instance_authority {
            crate::api::validate_native_authority_snapshot(authority)?;
        }
        CommitSha::parse(&self.source_revision)?;
        CommitSha::parse(&self.release_pr_sha)?;
        if let Some(digest) = &self.source_manifest_sha256 {
            validate_sha256_digest(digest)?;
        }
        if let Some(head_sha) = &self.release_pr_head_sha {
            CommitSha::parse(head_sha)?;
        }
        if let Some(package) = &self.client_package {
            validate_native_client_package_snapshot_values(package)?;
        }
        ReleaseTag::parse(self.tag.as_str())?;
        self.source_manifest.validate()?;
        ensure!(
            self.source_manifest.source_run_id == self.source_run_id
                && self.source_manifest.run_attempt == self.source_run_attempt
                && self.source_manifest.source_revision.as_str() == self.source_revision
                && self.source_manifest.release_pr_number == self.release_pr_number
                && self.source_manifest.release_pr_sha.as_str() == self.release_pr_sha
                && self.source_manifest.tag == self.tag,
            "release plan does not match its source manifest"
        );
        if self.native_assets.is_empty() {
            ensure!(
                self.source_manifest.repository == self.repository
                    && self.native_binary_repository.is_none(),
                "non-native release plan does not match its source repository"
            );
        } else {
            ensure!(
                self.strategy == ReleaseStrategy::GithubRelease
                    && self.native_binary_repository.as_deref()
                        == Some(self.source_manifest.repository.as_str()),
                "native release plan does not bind its binary source repository"
            );
        }
        ensure!(
            self.source_run_id.0 > 0 && self.source_run_attempt > 0 && self.release_pr_number > 0,
            "invalid release plan identifiers"
        );
        if self.instance_authority.is_some() {
            ensure!(
                self.source_manifest_sha256.is_some()
                    && self.release_pr_head_sha.is_some()
                    && self.client_package.is_some()
                    && self.source_manifest.source_revision.as_str()
                        == self
                            .client_package
                            .as_ref()
                            .expect("checked above")
                            .implementation_sha,
                "instance release plan lacks its exact source, PR-head, or accepted Client package binding"
            );
        }
        ensure!(
            self.release_id.is_none_or(|id| id > 0),
            "invalid release ID"
        );
        ensure!(
            self.existing_signature_sha256
                .as_ref()
                .is_none_or(|digest| {
                    self.release_id.is_some()
                        && digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                }),
            "invalid existing signature digest"
        );
        let mut names = BTreeSet::new();
        for asset in &self.assets {
            ensure!(names.insert(&asset.name), "duplicate asset name");
            ensure!(
                !asset.name.is_empty()
                    && asset
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
                "unsafe asset filename"
            );
            ensure!(
                asset.sha256.len() == 64
                    && asset
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "invalid asset digest"
            );
            ensure!(
                asset
                    .size
                    .is_none_or(|size| size > 0 && size <= MAX_NATIVE_ASSET_BYTES),
                "invalid expected asset size"
            );
        }
        validate_native_evidence(&self.native_assets)?;
        if !self.native_assets.is_empty() {
            ensure!(
                self.strategy == ReleaseStrategy::GithubRelease
                    && self.native_assets.len() == self.assets.len()
                    && self.native_assets.iter().all(|native| {
                        self.assets.iter().any(|asset| {
                            asset.name == native.filename
                                && asset.sha256 == native.sha256
                                && asset.size == Some(native.size)
                        })
                    }),
                "native release assets do not match the release plan"
            );
        }
        if self.strategy == ReleaseStrategy::GithubRelease {
            ensure!(
                self.native_assets.len() == self.assets.len(),
                "GitHub Release plan assets lack native evidence"
            );
        } else {
            ensure!(
                self.native_assets.is_empty(),
                "provider release plan contains native assets"
            );
        }
        Ok(())
    }
}

fn validate_native_evidence(assets: &[NativeAssetEvidence]) -> Result<()> {
    let mut targets = BTreeSet::new();
    let mut filenames = BTreeSet::new();
    for asset in assets {
        ensure!(
            !asset.target.is_empty()
                && asset.target.len() <= 80
                && asset.target.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                }),
            "invalid native asset target"
        );
        ensure!(
            targets.insert(asset.target.as_str()),
            "duplicate native asset target"
        );
        ensure!(
            !asset.filename.is_empty()
                && asset.filename.len() <= 120
                && asset
                    .filename
                    .bytes()
                    .all(|byte| { byte.is_ascii_alphanumeric() || b"._-".contains(&byte) }),
            "invalid native asset filename"
        );
        ensure!(
            filenames.insert(asset.filename.as_str()),
            "duplicate native asset filename"
        );
        ensure!(
            asset.size > 0 && asset.size <= MAX_NATIVE_ASSET_BYTES,
            "native asset has invalid size"
        );
        ensure!(
            asset.sha256.len() == 64
                && asset
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid native asset digest"
        );
        ensure!(
            !asset.runner_name.is_empty()
                && asset.runner_name.len() <= 200
                && !asset.runner_name.contains(['\n', '\r', '\0'])
                && matches!(asset.runner_os.as_str(), "Linux" | "macOS")
                && matches!(asset.runner_arch.as_str(), "ARM64" | "X64"),
            "invalid native runner evidence"
        );
        let (expected_os, expected_arch) = runner_platform(&asset.runner);
        ensure!(
            (asset.runner_os.as_str(), asset.runner_arch.as_str()) == (expected_os, expected_arch),
            "native runner evidence does not match its configured runner"
        );
        let (target_os, target_arch) = target_platform(&asset.target)?;
        ensure!(
            (target_os, target_arch) == (expected_os, expected_arch),
            "native target was not built on a matching runner"
        );
        ensure!(
            !asset.version_output.is_empty()
                && asset.version_output.len() <= 512
                && !asset.version_output.contains(['\n', '\r', '\0']),
            "invalid native binary version evidence"
        );
    }
    Ok(())
}

fn runner_platform(runner: &str) -> (&'static str, &'static str) {
    match runner {
        "ubuntu-24.04" => ("Linux", "X64"),
        "ubuntu-24.04-arm" => ("Linux", "ARM64"),
        "macos-15" => ("macOS", "ARM64"),
        "macos-15-intel" => ("macOS", "X64"),
        _ => ("", ""),
    }
}

fn target_platform(target: &str) -> Result<(&'static str, &'static str)> {
    let architecture = target.split('-').next().unwrap_or_default();
    let arch = match architecture {
        "aarch64" => "ARM64",
        "x86_64" => "X64",
        _ => bail!("unsupported native target architecture"),
    };
    let os = if target.ends_with("-apple-darwin") {
        "macOS"
    } else if target.contains("-linux-") {
        "Linux"
    } else {
        bail!("unsupported native target operating system")
    };
    Ok((os, arch))
}

fn validate_native_manifest(
    manifest: &NativeAssetManifest,
    repository: &Repository,
    targets: &[crate::policy::NativeBinaryTarget],
    source: &ReleaseManifestV2,
) -> Result<()> {
    ensure!(
        manifest.schema_version == 1
            && manifest.repository == repository.as_str()
            && manifest.source_run_id == source.source_run_id
            && manifest.source_run_sha == source.source_run_sha
            && manifest.run_attempt == source.run_attempt
            && manifest.source_revision == source.source_revision
            && manifest.release_pr_number == source.release_pr_number
            && manifest.release_pr_sha == source.release_pr_sha
            && manifest.tag == source.tag
            && manifest.package_version == source.package_version(),
        "native asset manifest does not match its source release"
    );
    ensure!(
        !targets.is_empty() && manifest.assets.len() == targets.len(),
        "native asset set does not match configured targets"
    );
    validate_native_evidence(&manifest.assets)?;
    Version::parse(&manifest.package_version)
        .context("native asset manifest package version is invalid")?;
    let version_prefix = format!("{} {}+", repository.name(), manifest.package_version);
    for target in targets {
        let asset = manifest
            .assets
            .iter()
            .find(|asset| asset.target == target.target)
            .with_context(|| format!("native asset target is missing: {}", target.target))?;
        ensure!(
            asset.runner == target.runner
                && asset.filename == format!("{}-{}", repository.name(), target.target),
            "native asset does not match configured target"
        );
        ensure!(
            asset.version_output.starts_with(&version_prefix),
            "native binary reports an unexpected version"
        );
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct PrArgs {
    #[arg(long)]
    pub release_pr_number: u64,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Prepare {
        #[arg(long, default_value = "")]
        version: String,
    },
    SyncPr,
    Classify,
    ResolvePr(PrArgs),
    BuildProvider(PrArgs),
    AssembleNative(PrArgs),
    TagPr {
        #[command(flatten)]
        pr: PrArgs,
        #[arg(long)]
        artifact_id: Option<u64>,
    },
    RequestServer,
    ParseRequest,
    Preflight,
    Sign,
    Publish,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Prepare { version } => prepare(&version),
        Command::SyncPr => sync_pr(),
        Command::Classify => classify(),
        Command::ResolvePr(pr) => resolve_pr_command(pr.release_pr_number),
        Command::BuildProvider(pr) => build_provider(pr.release_pr_number),
        Command::AssembleNative(pr) => assemble_native(pr.release_pr_number),
        Command::TagPr { pr, artifact_id } => tag_pr(pr.release_pr_number, artifact_id),
        Command::RequestServer => request_server(),
        Command::ParseRequest => parse_request(),
        Command::Preflight => preflight(),
        Command::Sign => sign(),
        Command::Publish => publish(),
        Command::Cleanup => cleanup(),
    }
}

#[derive(Debug, Deserialize)]
struct PullRequest {
    number: u64,
    merged: Option<bool>,
    merged_at: Option<DateTime<Utc>>,
    merge_commit_sha: Option<String>,
    merged_by: Option<Actor>,
    head: PullRequestBranch,
    base: PullRequestBranch,
}

#[derive(Debug, Deserialize)]
struct PullRequestBranch {
    #[serde(rename = "ref")]
    name: String,
    sha: String,
    repo: Option<PullRequestRepository>,
}

#[derive(Debug, Deserialize)]
struct PullRequestRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct Actor {
    id: u64,
    #[serde(rename = "type")]
    kind: String,
}

fn env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("missing {name}"))?;
    ensure!(!value.is_empty(), "{name} is empty");
    Ok(value)
}

fn api() -> Result<GitHub> {
    GitHub::from_env("GITHUB_TOKEN")
}

fn current_repository() -> Result<Repository> {
    Repository::parse(&env("GITHUB_REPOSITORY")?)
}

fn current_policy(api: &GitHub) -> Result<Policy> {
    Policy::active(api)
}

fn authorized_release_pr(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    number: u64,
) -> Result<(PullRequest, CommitSha)> {
    let release_branch = crate::config::trusted()?.deployment.release_branch.as_str();
    let repository: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = repository["default_branch"]
        .as_str()
        .context("release caller default branch missing")?;
    ensure!(number > 0, "release PR number must be positive");
    let pr: PullRequest = api.get(&format!("/repos/{}/pulls/{number}", repo.as_str()))?;
    ensure!(
        pr.number == number,
        "GitHub returned a different pull request"
    );
    ensure!(
        pr.merged == Some(true) && pr.merged_at.is_some(),
        "release PR is not merged"
    );
    ensure!(
        pr.base.name == default_branch && pr.head.name == release_branch,
        "release PR must merge the configured release branch into the caller default branch"
    );
    ensure!(
        pr.head
            .repo
            .as_ref()
            .is_some_and(|head| head.full_name == repo.as_str()),
        "release PR must come from the same repository"
    );
    ensure!(
        pr.base
            .repo
            .as_ref()
            .is_some_and(|base| base.full_name == repo.as_str()),
        "release PR base must be the same repository"
    );
    ensure!(
        pr.merged_by
            .as_ref()
            .is_some_and(|actor| actor.id == policy.server_bot_id && actor.kind == "Bot"),
        "release PR was not merged by Securefix Server"
    );
    let merge_sha = CommitSha::parse(
        pr.merge_commit_sha
            .as_deref()
            .context("merged PR lacks a merge commit SHA")?,
    )?;
    CommitSha::parse(&pr.head.sha)?;
    crate::request::require_owner_marker(api, policy, repo.as_str(), number, &pr.head.sha)?;
    let compare: Value = api.get(&format!(
        "/repos/{}/compare/{}...{}",
        repo.as_str(),
        merge_sha.as_str(),
        default_branch
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "release PR merge commit is not contained in main"
    );
    Ok((pr, merge_sha))
}

fn strategy_for(api: &GitHub, repo: &Repository) -> Result<ReleaseStrategy> {
    let policy = current_policy(api)?;
    let repository = policy.repository(repo.as_str())?;
    repository.require(Capability::Release)?;
    repository
        .release
        .context("release strategy is not configured")
}

fn resolve_pr_command(number: u64) -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;

    // Native Client releases use the instance configuration and the accepted
    // fixed Release Tag package. They do not need the live control descriptor
    // or the Server's deployment policy file to resolve a reviewed PR.
    let native_locator = match (
        std::env::var("SECUREFIX_SERVER_REPOSITORY"),
        std::env::var("SECUREFIX_INSTANCE_CONFIG_PATH"),
    ) {
        (Ok(server_repository), Ok(config_path)) => {
            ensure!(
                !server_repository.is_empty() && !config_path.is_empty(),
                "native release instance locator is empty"
            );
            Some((server_repository, config_path))
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => None,
        _ => bail!(
            "native release instance locator must include both SECUREFIX_SERVER_REPOSITORY and SECUREFIX_INSTANCE_CONFIG_PATH"
        ),
    };
    if let Some((server_repository, config_path)) = native_locator {
        let instance = native_release_instance_for(&api, &server_repository, &config_path)?;
        let repository_id = configured_release_destination(&instance.config, &repo)?;
        let configured = instance
            .config
            .repositories
            .iter()
            .find(|configured| configured.repository == repo.as_str())
            .context("release destination is absent from the protected Server instance")?;
        let strategy = configured
            .release
            .context("release strategy is not configured")?;
        let (pr, merge_sha, _proof) =
            verify_native_release_pr(&api, &config_path, &instance, &repo, repository_id, number)?;
        verify_current_native_release_tag_package(
            &api,
            &repo,
            repository_id,
            &instance,
            number,
            pr["head"]["sha"]
                .as_str()
                .context("release PR lacks a head SHA")?,
        )?;
        let head_sha = pr["head"]["sha"]
            .as_str()
            .context("release PR lacks a head SHA")?;
        let (server_owner, server_repository_name) = instance
            .config
            .instance
            .repository
            .split_once('/')
            .context("Server instance repository is invalid")?;
        crate::output("merge_sha", merge_sha.as_str())?;
        crate::output("head_sha", head_sha)?;
        crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
        crate::output(
            "native_targets",
            serde_json::to_string(&configured.native_binaries)?,
        )?;
        crate::output("server_owner", server_owner)?;
        crate::output("server_repository_name", server_repository_name)?;
        crate::output("client_app_id", instance.config.apps.client_id.to_string())?;
        return Ok(());
    }

    let policy = current_policy(&api)?;
    require_dispatch_owner(&api, &policy)?;
    let (pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, number)?;
    let repository_policy = policy.repository(repo.as_str())?;
    let strategy = repository_policy
        .release
        .context("release strategy is not configured")?;
    crate::output("merge_sha", merge_sha.as_str())?;
    crate::output("head_sha", &pr.head.sha)?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    crate::output(
        "native_targets",
        serde_json::to_string(&repository_policy.native_binaries)?,
    )?;
    Ok(())
}

fn classify() -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    let repository_policy = policy.repository(repo.as_str())?;
    let strategy = repository_policy
        .release
        .context("release strategy is not configured")?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    crate::output(
        "build_provider",
        if strategy == ReleaseStrategy::TerraformProvider {
            "true"
        } else {
            "false"
        },
    )?;
    crate::output(
        "native_targets",
        serde_json::to_string(&repository_policy.native_binaries)?,
    )?;
    Ok(())
}

fn git_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .output()
        .context("run git")?;
    ensure!(
        output.status.success(),
        "git {} failed",
        args.first().copied().unwrap_or_default()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn tool_output(program: &str, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    ensure!(output.status.success(), "{program} command failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn next_version(input: &str) -> Result<Option<Version>> {
    if !input.is_empty() {
        let version = input.strip_prefix('v').unwrap_or(input);
        ensure!(
            !version.contains('+'),
            "build metadata is not supported for release versions"
        );
        return Ok(Some(
            Version::parse(version).context("invalid explicit release version")?,
        ));
    }
    let base = stable_release_base()?;
    ensure_cliff_base_tag(&base)?;
    let raw = tool_output("git-cliff", &["--bumped-version"])?;
    let version = raw.strip_prefix('v').unwrap_or(&raw);
    let bumped = Version::parse(version).context("git-cliff returned an invalid version")?;
    if bumped == base {
        return Ok(None);
    }
    ensure!(
        bumped > base,
        "git-cliff returned a version older than the release base"
    );
    Ok(Some(bumped))
}

fn ensure_cliff_base_tag(base: &Version) -> Result<()> {
    if base == &Version::new(0, 0, 0) {
        return Ok(());
    }
    let tag = format!("v{base}");
    let exists = ProcessCommand::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/tags/{tag}^{{commit}}"),
        ])
        .status()?;
    if exists.success() {
        return Ok(());
    }
    let commit = [
        format!("^chore(release): {tag}$"),
        format!("^chore(release): prepare {tag}$"),
    ]
    .iter()
    .find_map(|pattern| {
        git_output(&["log", "--grep", pattern, "--format=%H", "-1"])
            .ok()
            .filter(|commit| !commit.is_empty())
    })
    .context("shipped version has no matching release commit for git-cliff base")?;
    git_output(&["tag", "-f", &tag, &commit])?;
    Ok(())
}

fn stable_release_base() -> Result<Version> {
    let tagged = ProcessCommand::new("git")
        .args([
            "describe",
            "--tags",
            "--abbrev=0",
            "--match",
            "v[0-9]*",
            "--exclude",
            "v*-*",
        ])
        .output()?;
    let tagged = if tagged.status.success() {
        String::from_utf8(tagged.stdout)?
            .trim()
            .trim_start_matches('v')
            .to_owned()
    } else {
        "0.0.0".to_owned()
    };
    let mut base =
        Version::parse(&tagged).context("latest stable tag is not semantic versioning")?;
    if let Ok(shipped) = std::fs::read_to_string(".release-version") {
        let shipped = shipped.trim();
        if let Ok(version) = Version::parse(shipped)
            && version.pre.is_empty()
            && version.build.is_empty()
            && version > base
        {
            base = version;
        }
    }
    Ok(base)
}

fn release_changelog_range(base: &Version) -> Option<String> {
    (base != &Version::new(0, 0, 0)).then(|| format!("v{base}..HEAD"))
}

fn prepare(input_version: &str) -> Result<()> {
    let api = api()?;
    let policy = current_policy(&api)?;
    policy
        .repository(current_repository()?.as_str())?
        .require(Capability::Release)?;
    require_current_runtime(&api, ".github/workflows/reusable-release-pr.yml")?;
    prepare_metadata(input_version)
}

pub(crate) fn prepare_metadata(input_version: &str) -> Result<()> {
    let base = stable_release_base()?;
    let Some(version) = next_version(input_version)? else {
        crate::output("releasable", "false")?;
        return Ok(());
    };
    ensure_cliff_base_tag(&base)?;
    let version = version.to_string();
    let tag = format!("v{version}");
    let existing = ProcessCommand::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/tags/{tag}"),
        ])
        .status()?;
    if existing.success() {
        bail!("release tag {tag} already exists");
    }
    let range = release_changelog_range(&base);
    let mut cliff_args = vec!["--unreleased"];
    if let Some(range) = range.as_deref() {
        cliff_args.push(range);
    }
    cliff_args.extend(["--tag", &tag]);
    cliff_args.extend(if Path::new("CHANGELOG.md").is_file() {
        ["--prepend", "CHANGELOG.md"]
    } else {
        ["--output", "CHANGELOG.md"]
    });
    let _ = tool_output("git-cliff", &cliff_args)?;
    std::fs::write(".release-version", format!("{version}\n"))?;
    if Path::new("dbt_project.yml").is_file() {
        update_top_level_yaml_version(Path::new("dbt_project.yml"), &version)?;
    }
    if Path::new("pyproject.toml").is_file() {
        update_pyproject_version(Path::new("pyproject.toml"), &version)?;
    }
    let mut files = vec![".release-version", "CHANGELOG.md"];
    if Path::new("dbt_project.yml").is_file() {
        files.push("dbt_project.yml");
    }
    if Path::new("pyproject.toml").is_file() {
        files.push("pyproject.toml");
    }
    output_multiline("files", &files)?;
    crate::output("version", &version)?;
    crate::output(
        "body_extra",
        if files.len() > 2 {
            "package version metadata"
        } else {
            "release metadata"
        },
    )?;
    crate::output("releasable", "true")?;
    Ok(())
}

fn update_top_level_yaml_version(path: &Path, version: &str) -> Result<()> {
    let source = std::fs::read_to_string(path)?;
    let mut matches = 0;
    let mut lines = Vec::new();
    for line in source.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.starts_with("version:") {
            matches += 1;
            let comment = line
                .split_once(" #")
                .map(|(_, comment)| format!(" #{comment}"))
                .unwrap_or_default();
            lines.push(format!("version: {version}{comment}"));
        } else {
            lines.push(line.to_owned());
        }
    }
    ensure!(
        matches == 1,
        "{} must contain exactly one top-level version field",
        path.display()
    );
    let mut updated = lines.join("\n");
    if source.ends_with('\n') {
        updated.push('\n');
    }
    std::fs::write(path, updated)?;
    Ok(())
}

fn update_pyproject_version(path: &Path, version: &str) -> Result<()> {
    let source = std::fs::read_to_string(path)?;
    let mut document = source
        .parse::<toml_edit::DocumentMut>()
        .context("parse pyproject.toml")?;
    let project = document
        .get_mut("project")
        .and_then(toml_edit::Item::as_table_like_mut)
        .context("pyproject.toml must have a [project] table")?;
    let item = project
        .get_mut("version")
        .context("[project] lacks version")?;
    *item = toml_edit::value(version);
    std::fs::write(path, document.to_string())?;
    Ok(())
}

fn output_multiline(name: &str, values: &[&str]) -> Result<()> {
    let delimiter = "SECUREFIX_RELEASE_FILES";
    ensure!(
        values.iter().all(|value| !value.contains(delimiter)),
        "unsafe multiline output value"
    );
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        writeln!(file, "{name}<<{delimiter}")?;
        for value in values {
            writeln!(file, "{value}")?;
        }
        writeln!(file, "{delimiter}")?;
    } else {
        println!("{}", values.join("\n"));
    }
    Ok(())
}

fn sync_pr() -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-pr-sync.yml")?;
    policy
        .repository(repo.as_str())?
        .require(Capability::Release)?;
    let version = std::fs::read_to_string(".release-version")?;
    let version = version.split_whitespace().collect::<String>();
    ensure!(
        Version::parse(&version).is_ok() && !version.contains('+'),
        "invalid .release-version"
    );
    let release_branch = crate::config::trusted()?.deployment.release_branch.as_str();
    let repo_info: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = repo_info["default_branch"]
        .as_str()
        .context("caller default branch missing")?;
    let head = format!(
        "{}:{release_branch}",
        repo.as_str().split('/').next().unwrap_or_default()
    );
    let encoded_head = url_encode(&head);
    let pulls: Vec<Value> = api.get(&format!(
        "/repos/{}/pulls?state=open&head={encoded_head}&base={}",
        repo.as_str(),
        url_encode(default_branch)
    ))?;
    let Some(pr) = pulls.first() else {
        return Ok(());
    };
    ensure!(pulls.len() == 1, "multiple open release PRs found");
    let number = pr["number"]
        .as_u64()
        .context("release PR response lacks number")?;
    let metadata =
        if Path::new("dbt_project.yml").is_file() || Path::new("pyproject.toml").is_file() {
            "package version metadata"
        } else {
            "release metadata"
        };
    let body = format!(
        "## Summary\n- Prepare release v{version}\n- Update the changelog and {metadata}\n\nThis pull request is managed by the Release PR workflow."
    );
    let _: Value = api.patch(
        &format!("/repos/{}/pulls/{number}", repo.as_str()),
        &json!({"title":format!("chore(release): v{version}"),"body":body}),
    )?;
    Ok(())
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn build_provider(release_pr_number: u64) -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let native_locator = match (
        std::env::var("SECUREFIX_SERVER_REPOSITORY"),
        std::env::var("SECUREFIX_INSTANCE_CONFIG_PATH"),
    ) {
        (Ok(server_repository), Ok(config_path)) => {
            ensure!(
                !server_repository.is_empty() && !config_path.is_empty(),
                "release instance locator is empty"
            );
            Some((server_repository, config_path))
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => None,
        _ => bail!(
            "release instance locator must include both SECUREFIX_SERVER_REPOSITORY and SECUREFIX_INSTANCE_CONFIG_PATH"
        ),
    };
    let (repository_policy, merge_sha) = if let Some((server_repository, config_path)) =
        native_locator
    {
        let instance = native_release_instance_for(&api, &server_repository, &config_path)?;
        let repository_id = configured_release_destination(&instance.config, &repo)?;
        let configured = instance
            .config
            .repositories
            .iter()
            .find(|configured| configured.repository == repo.as_str())
            .context("release destination is absent from the protected Server instance")?;
        ensure!(
            configured.release == Some(ReleaseStrategy::TerraformProvider),
            "provider build is not enabled for this configured repository"
        );
        let (pull, merge_sha, _proof) = verify_native_release_pr(
            &api,
            &config_path,
            &instance,
            &repo,
            repository_id,
            release_pr_number,
        )?;
        verify_current_native_release_tag_package(
            &api,
            &repo,
            repository_id,
            &instance,
            release_pr_number,
            pull["head"]["sha"]
                .as_str()
                .context("release PR lacks a head SHA")?,
        )?;
        (configured.policy(), merge_sha)
    } else {
        let policy = current_policy(&api)?;
        let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-tag.yml")?;
        require_dispatch_owner(&api, &policy)?;
        ensure!(
            strategy_for(&api, &repo)? == ReleaseStrategy::TerraformProvider,
            "provider build is not enabled for this repository"
        );
        let (_pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, release_pr_number)?;
        (policy.repository(repo.as_str())?.clone(), merge_sha)
    };
    ensure!(
        repository_policy.release == Some(ReleaseStrategy::TerraformProvider),
        "provider build is not enabled for this repository"
    );
    let project = repo.name();
    ensure!(
        git_output(&["rev-parse", "HEAD"])? == merge_sha.as_str(),
        "checked out source is not the approved release merge commit"
    );
    let version = std::fs::read_to_string(".release-version")?;
    let version = version.trim();
    let tag = ReleaseTag::parse(&format!("v{version}"))?;
    let manifest: Value =
        serde_json::from_slice(&std::fs::read("terraform-registry-manifest.json")?)?;
    ensure!(
        manifest["version"] == 1 && manifest["metadata"]["protocol_versions"] == json!(["6.0"]),
        "unexpected Terraform Registry manifest"
    );
    let output_dir = Path::new("dist/release-assets");
    if output_dir.exists() {
        std::fs::remove_dir_all(output_dir)?;
    }
    std::fs::create_dir_all(output_dir)?;
    for target in PROVIDER_TARGETS {
        build_provider_target(Path::new("."), project, &tag, *target, output_dir)?;
    }
    let manifest_name = format!("{project}_{}_manifest.json", tag.version());
    std::fs::copy(
        "terraform-registry-manifest.json",
        output_dir.join(manifest_name),
    )?;
    let files = validate_asset_directory(output_dir, &tag, project)?;
    crate::output("tag", tag.as_str())?;
    crate::output("merge_sha", merge_sha.as_str())?;
    crate::output("asset_count", files.len().to_string())?;
    Ok(())
}

fn assemble_native(release_pr_number: u64) -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let native_locator = match (
        std::env::var("SECUREFIX_SERVER_REPOSITORY"),
        std::env::var("SECUREFIX_INSTANCE_CONFIG_PATH"),
    ) {
        (Ok(server_repository), Ok(config_path)) => {
            ensure!(
                !server_repository.is_empty() && !config_path.is_empty(),
                "native release instance locator is empty"
            );
            Some((server_repository, config_path))
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => None,
        _ => bail!(
            "native release instance locator must include both SECUREFIX_SERVER_REPOSITORY and SECUREFIX_INSTANCE_CONFIG_PATH"
        ),
    };
    let (repository_policy, merge_sha, source_revision) =
        if let Some((server_repository, config_path)) = native_locator {
            let instance = native_release_instance_for(&api, &server_repository, &config_path)?;
            let repository_id = configured_release_destination(&instance.config, &repo)?;
            let configured = instance
                .config
                .repositories
                .iter()
                .find(|configured| configured.repository == repo.as_str())
                .context("release destination is absent from the protected Server instance")?;
            ensure!(
                configured.release == Some(ReleaseStrategy::GithubRelease)
                    && !configured.native_binaries.is_empty(),
                "native binary assembly is not enabled for this repository"
            );
            let (pull, merge_sha, _proof) = verify_native_release_pr(
                &api,
                &config_path,
                &instance,
                &repo,
                repository_id,
                release_pr_number,
            )?;
            let head_sha = pull["head"]["sha"]
                .as_str()
                .context("release PR lacks a head SHA")?;
            let source_revision = verify_current_native_release_tag_package(
                &api,
                &repo,
                repository_id,
                &instance,
                release_pr_number,
                head_sha,
            )?;
            (configured.policy(), merge_sha, source_revision)
        } else {
            let policy = current_policy(&api)?;
            let _runtime =
                require_current_runtime(&api, ".github/workflows/reusable-release-tag.yml")?;
            require_dispatch_owner(&api, &policy)?;
            let repository_policy = policy.repository(repo.as_str())?;
            ensure!(
                repository_policy.release == Some(ReleaseStrategy::GithubRelease)
                    && !repository_policy.native_binaries.is_empty(),
                "native binary assembly is not enabled for this repository"
            );
            let (_pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, release_pr_number)?;
            (
                repository_policy.clone(),
                merge_sha,
                CommitSha::parse(&policy.revision)?,
            )
        };
    ensure!(
        git_output(&["rev-parse", "HEAD"])? == merge_sha.as_str(),
        "checked out source is not the approved release merge commit"
    );
    let version = std::fs::read_to_string(".release-version")?;
    let tag = ReleaseTag::parse(&format!("v{}", version.trim()))?;
    let run_id = RunId(env("GITHUB_RUN_ID")?.parse()?);
    let run_attempt = env("GITHUB_RUN_ATTEMPT")?.parse()?;
    let source_run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        run_id.0
    ))?;
    ensure!(
        source_run["status"] == "in_progress"
            && source_run["run_attempt"].as_u64() == Some(run_attempt),
        "release source run attempt changed during native assembly"
    );
    let source_run_sha = CommitSha::parse(
        source_run["head_sha"]
            .as_str()
            .context("release source run lacks head SHA")?,
    )?;
    ensure!(
        source_run_sha.as_str() == env("GITHUB_SHA")?,
        "release source run head changed"
    );
    let artifact_list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        run_id.0
    ))?;
    let expected_artifacts: BTreeSet<_> = repository_policy
        .native_binaries
        .iter()
        .map(|target| format!("native-target-{}-{run_attempt}", target.target))
        .collect();
    let native_artifacts: Vec<_> = artifact_list
        .artifacts
        .iter()
        .filter_map(|artifact| artifact["name"].as_str())
        .filter(|name| {
            name.starts_with("native-target-") && name.ends_with(&format!("-{run_attempt}"))
        })
        .collect();
    let actual_artifacts: BTreeSet<_> = native_artifacts
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    ensure!(
        native_artifacts.len() == expected_artifacts.len()
            && actual_artifacts == expected_artifacts,
        "native build artifacts do not match the configured target set"
    );
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_bytes = 0_u64;
    for artifact in artifact_list.artifacts.iter().filter(|artifact| {
        artifact["name"].as_str().is_some_and(|name| {
            name.starts_with("native-target-") && name.ends_with(&format!("-{run_attempt}"))
        })
    }) {
        ensure!(
            artifact["expired"] == false
                && artifact["size_in_bytes"].as_u64().unwrap_or_default() > 0,
            "native build artifact is expired or empty"
        );
        ensure!(
            artifact_ids.insert(
                artifact["id"]
                    .as_u64()
                    .context("native artifact lacks ID")?
            ),
            "duplicate native build artifact ID"
        );
        artifact_bytes =
            artifact_bytes.saturating_add(artifact["size_in_bytes"].as_u64().unwrap_or_default());
        ensure!(
            artifact_bytes <= MAX_NATIVE_BUNDLE_BYTES,
            "native build artifacts exceed the bundle size limit"
        );
    }
    let input_dir = Path::new("native-input");
    let package_version = tag.version().to_owned();
    let mut found = BTreeSet::new();
    let mut asset_paths = std::collections::BTreeMap::new();
    let mut total_size = 0_u64;
    let mut manifest = NativeAssetManifest {
        schema_version: 1,
        repository: repo.as_str().to_owned(),
        source_run_id: run_id,
        source_run_sha: source_run_sha.clone(),
        run_attempt,
        source_revision,
        release_pr_number,
        release_pr_sha: merge_sha.clone(),
        tag,
        package_version: package_version.clone(),
        assets: Vec::new(),
    };
    for entry in std::fs::read_dir(input_dir).context("native target artifacts are missing")? {
        let directory = entry?.path();
        let directory_metadata = std::fs::symlink_metadata(&directory)?;
        ensure!(
            directory_metadata.file_type().is_dir() && !directory_metadata.file_type().is_symlink(),
            "native target artifact is not a regular directory"
        );
        let target_manifest_path = directory.join(NATIVE_TARGET_MANIFEST);
        let metadata = std::fs::symlink_metadata(&target_manifest_path)?;
        ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() > 0
                && metadata.len() <= 1024 * 1024,
            "native target artifact metadata has invalid size or type"
        );
        let build: NativeTargetEvidence =
            serde_json::from_slice(&std::fs::read(&target_manifest_path)?)?;
        ensure!(
            build.schema_version == 1
                && build.source_run_id == run_id
                && build.source_run_attempt == run_attempt
                && build.source_run_sha == source_run_sha
                && build.release_pr_number == release_pr_number
                && build.release_pr_sha == merge_sha
                && build.package_version == package_version,
            "native target evidence does not match the current source run and release PR"
        );
        ensure!(
            repository_policy
                .native_binaries
                .iter()
                .any(|target| target.target == build.target),
            "native target artifact is not configured"
        );
        ensure!(
            directory.file_name().and_then(|name| name.to_str())
                == Some(format!("native-target-{}-{run_attempt}", build.target).as_str()),
            "native target artifact name does not match its target"
        );
        ensure!(
            found.insert(build.target.clone()),
            "duplicate native target artifact"
        );
        let mut files = std::fs::read_dir(&directory)?;
        let file_names = files
            .by_ref()
            .map(|entry| {
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("native target artifact filename is not UTF-8"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            file_names.len() == 2
                && file_names.contains(NATIVE_TARGET_MANIFEST)
                && file_names.contains(&build.filename),
            "native target artifact contains unexpected files"
        );
        let binary_path = directory.join(&build.filename);
        let binary_metadata = std::fs::symlink_metadata(&binary_path)?;
        ensure!(
            binary_metadata.file_type().is_file()
                && !binary_metadata.file_type().is_symlink()
                && binary_metadata.len() > 0
                && binary_metadata.len() <= MAX_NATIVE_ASSET_BYTES,
            "native target artifact file has invalid type or size"
        );
        total_size = total_size
            .saturating_add(binary_metadata.len())
            .saturating_add(metadata.len());
        ensure!(
            total_size <= MAX_NATIVE_BUNDLE_BYTES,
            "native target artifacts exceed the bundle size limit"
        );
        asset_paths.insert(build.target.clone(), binary_path.clone());
        manifest.assets.push(NativeAssetEvidence {
            target: build.target,
            runner: build.runner,
            runner_name: build.runner_name,
            runner_os: build.runner_os,
            runner_arch: build.runner_arch,
            filename: build.filename,
            size: binary_metadata.len(),
            sha256: sha256_file(&binary_path)?,
            version_output: build.version_output,
        });
    }
    let expected: BTreeSet<_> = repository_policy
        .native_binaries
        .iter()
        .map(|target| target.target.as_str())
        .collect();
    ensure!(
        found.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "native target artifacts do not match the configured target set"
    );
    let source_manifest = ReleaseManifestV2 {
        schema_version: 2,
        repository: manifest.repository.clone(),
        source_run_id: manifest.source_run_id,
        source_run_sha,
        run_attempt: manifest.run_attempt,
        source_revision: manifest.source_revision.clone(),
        release_pr_number: manifest.release_pr_number,
        release_pr_sha: manifest.release_pr_sha.clone(),
        tag: manifest.tag.clone(),
        package_version: Some(manifest.package_version.clone()),
        artifact_id: None,
    };
    validate_native_manifest(
        &manifest,
        &repo,
        &repository_policy.native_binaries,
        &source_manifest,
    )?;
    let output_dir = Path::new("dist/native-release-assets");
    if output_dir.exists() {
        std::fs::remove_dir_all(output_dir)?;
    }
    std::fs::create_dir_all(output_dir)?;
    for asset in &manifest.assets {
        let source = asset_paths
            .get(&asset.target)
            .map(PathBuf::as_path)
            .context("native asset disappeared during assembly")?
            .to_owned();
        std::fs::copy(source, output_dir.join(&asset.filename))?;
    }
    write_json(output_dir.join(NATIVE_BUNDLE_MANIFEST), &manifest)?;
    crate::output("asset_count", manifest.assets.len().to_string())?;
    crate::output(
        "manifest_path",
        output_dir
            .join(NATIVE_BUNDLE_MANIFEST)
            .display()
            .to_string(),
    )?;
    Ok(())
}

fn build_provider_target(
    source_dir: &Path,
    project: &str,
    tag: &ReleaseTag,
    target: ProviderTarget,
    output_dir: &Path,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let source_dir = source_dir.canonicalize()?;
    let output_dir = output_dir.canonicalize()?;
    let windows = target.os == "windows";
    let binary_name = format!(
        "{project}_v{}{}",
        tag.version(),
        if windows { ".exe" } else { "" }
    );
    let binary_path = output_dir.join(format!(
        ".build-{}-{}{}",
        target.os,
        target.arch,
        if windows { ".exe" } else { "" }
    ));
    let mut cmd = ProcessCommand::new("go");
    cmd.current_dir(&source_dir)
        .args([
            "build",
            "-mod=readonly",
            "-trimpath",
            "-ldflags",
            &format!("-s -w -X main.version={}", tag.version()),
            "-o",
        ])
        .arg(&binary_path)
        .arg(".")
        .env("CGO_ENABLED", "0")
        .env("GOOS", target.os)
        .env("GOARCH", target.arch);
    match target.arch {
        "amd64" => {
            cmd.env("GOAMD64", "v1");
        }
        "arm" => {
            cmd.env("GOARM", "6");
        }
        "arm64" => {
            cmd.env("GOARM64", "v8.0");
        }
        _ => {}
    }
    let status = cmd
        .status()
        .with_context(|| format!("build {} {} provider", target.os, target.arch))?;
    ensure!(
        status.success(),
        "Go provider build failed for {} {}",
        target.os,
        target.arch
    );
    let archive_name = format!(
        "{project}_{}_{}_{}.zip",
        tag.version(),
        target.os,
        target.arch
    );
    let archive_path = output_dir.join(archive_name);
    write_provider_zip(&binary_path, &binary_name, &source_dir, &archive_path)?;
    std::fs::remove_file(binary_path)?;
    Ok(archive_path)
}

fn write_provider_zip(
    binary_path: &Path,
    binary_name: &str,
    documentation_dir: &Path,
    archive_path: &Path,
) -> Result<()> {
    let output = std::fs::File::create(archive_path)?;
    let mut archive = zip::ZipWriter::new(output);
    for (path, name, mode) in [
        (
            documentation_dir.join("CHANGELOG.md"),
            "CHANGELOG.md",
            0o644,
        ),
        (documentation_dir.join("LICENSE"), "LICENSE", 0o644),
        (documentation_dir.join("README.md"), "README.md", 0o644),
        (binary_path.to_owned(), binary_name, 0o755),
    ] {
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "provider archive input must be a regular file: {}",
            path.display()
        );
        ensure!(
            metadata.len() > 0 && metadata.len() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider archive input has invalid size: {}",
            path.display()
        );
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode);
        archive.start_file(name, options)?;
        let copied = std::io::copy(
            &mut std::fs::File::open(path)?.take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut archive,
        )?;
        ensure!(
            copied == metadata.len() && copied <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider archive input changed while packaging: {name}"
        );
    }
    archive.finish()?;
    Ok(())
}

fn tag_pr(release_pr_number: u64, artifact_id: Option<u64>) -> Result<()> {
    let artifact_id = artifact_id.filter(|id| *id != 0);
    let api = api()?;
    let repo = current_repository()?;

    // The protected Server instance and its existing native approval proof
    // authorize every managed Release Tag invocation. Keep the legacy
    // runtime-bound route only for callers that do not yet pass an instance
    // locator.
    match (
        std::env::var("SECUREFIX_SERVER_REPOSITORY"),
        std::env::var("SECUREFIX_INSTANCE_CONFIG_PATH"),
    ) {
        (Ok(server_repository), Ok(config_path)) => {
            ensure!(
                !server_repository.is_empty() && !config_path.is_empty(),
                "native release instance locator is empty"
            );
            let instance = native_release_instance_for(&api, &server_repository, &config_path)?;
            let repository_id = configured_release_destination(&instance.config, &repo)?;
            return tag_configured_release_pr(
                &api,
                &repo,
                repository_id,
                &config_path,
                &instance,
                release_pr_number,
                artifact_id,
            );
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {}
        _ => bail!(
            "native release instance locator must include both SECUREFIX_SERVER_REPOSITORY and SECUREFIX_INSTANCE_CONFIG_PATH"
        ),
    }

    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-tag.yml")?;
    require_dispatch_owner(&api, &policy)?;
    let repository_policy = policy.repository(repo.as_str())?;
    let strategy = repository_policy
        .release
        .context("release strategy is not configured")?;
    let has_native_assets = !repository_policy.native_binaries.is_empty();
    ensure!(
        strategy != ReleaseStrategy::TerraformProvider || artifact_id.is_some_and(|id| id > 0),
        "provider release requires an unsigned build artifact ID"
    );
    ensure!(
        strategy != ReleaseStrategy::GithubRelease || has_native_assets == artifact_id.is_some(),
        "GitHub release artifact does not match its configured native assets"
    );
    let (pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, release_pr_number)?;
    let version_bytes = api.content(repo.as_str(), ".release-version", merge_sha.as_str())?;
    let version = String::from_utf8(version_bytes)?.trim().to_owned();
    let tag = ReleaseTag::parse(&format!("v{version}"))?;
    create_annotated_tag(&api, &repo, &tag, &merge_sha)?;
    let run_id = RunId(env("GITHUB_RUN_ID")?.parse()?);
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        run_id.0
    ))?;
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("workflow run lacks head SHA")?,
    )?;
    let source_revision = CommitSha::parse(&env("SECUREFIX_SOURCE_SHA")?)?;
    ensure!(
        source_revision.as_str() == policy.revision,
        "release tag runtime is stale"
    );
    let manifest = ReleaseManifestV2 {
        schema_version: 2,
        repository: repo.as_str().to_owned(),
        source_run_id: run_id,
        source_run_sha,
        run_attempt: run["run_attempt"]
            .as_u64()
            .context("workflow run lacks attempt")?,
        source_revision,
        release_pr_number,
        release_pr_sha: merge_sha,
        tag,
        package_version: Some(version),
        artifact_id,
    };
    manifest.validate()?;
    let path = PathBuf::from("manifest.json");
    write_json(&path, &manifest)?;
    crate::output("tag", manifest.tag.as_str())?;
    crate::output("merge_sha", manifest.release_pr_sha.as_str())?;
    crate::output("head_sha", &pr.head.sha)?;
    crate::output("manifest_path", path.display().to_string())?;
    Ok(())
}

fn tag_configured_release_pr(
    api: &GitHub,
    repo: &Repository,
    repository_id: u64,
    config_path: &str,
    instance: &NativeServerInstanceAuthority,
    release_pr_number: u64,
    artifact_id: Option<u64>,
) -> Result<()> {
    let configured = instance
        .config
        .repositories
        .iter()
        .find(|configured| configured.repository == repo.as_str())
        .context("release destination is absent from the protected Server instance")?;
    ensure!(
        configured.id == repository_id,
        "release destination ID differs from the protected Server instance"
    );
    let strategy = configured
        .release
        .context("release strategy is not configured")?;
    ensure!(
        match strategy {
            ReleaseStrategy::TerraformProvider => artifact_id.is_some_and(|id| id > 0),
            ReleaseStrategy::GithubRelease => {
                configured.native_binaries.is_empty() == artifact_id.is_none()
            }
        },
        "release artifact does not match the configured release strategy"
    );
    let run_id = RunId(env("GITHUB_RUN_ID")?.parse()?);
    ensure!(run_id.0 > 0, "release tag source run ID must be positive");
    let run_attempt = env("GITHUB_RUN_ATTEMPT")?.parse::<u64>()?;
    ensure!(
        run_attempt > 0,
        "release tag source attempt must be positive"
    );
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        run_id.0
    ))?;
    ensure!(
        run["id"].as_u64() == Some(run_id.0)
            && run["run_attempt"].as_u64() == Some(run_attempt)
            && run["repository"]["full_name"].as_str() == Some(repo.as_str())
            && run["repository"]["id"].as_u64() == Some(repository_id)
            && run["head_repository"]["full_name"].as_str() == Some(repo.as_str())
            && matches!(
                run["event"].as_str(),
                Some("pull_request" | "workflow_dispatch")
            ),
        "release tag source run does not match the current Client repository and attempt"
    );
    let references: Vec<ReferencedWorkflow> = serde_json::from_value(
        run.get("referenced_workflows")
            .cloned()
            .context("release tag source run lacks reusable-workflow references")?,
    )
    .context("parse release tag reusable-workflow references")?;
    let source_revision =
        release_tag_reusable_revision(&references, &instance.config.acceptable_clients.repository)?;
    let package = verify_accepted_client_package(api, &instance.config, source_revision.as_str())?;
    let package_snapshot = native_client_package_snapshot(&package, &instance.config)?;
    validate_native_client_package_snapshot_for_config(&package_snapshot, &instance.config)?;
    ensure!(
        package.implementation_sha == source_revision.as_str(),
        "Release Tag workflow revision is not the admitted fixed-package implementation"
    );

    let pull: Value = api.get(&format!(
        "/repos/{}/pulls/{release_pr_number}",
        repo.as_str()
    ))?;
    ensure!(
        pull["number"].as_u64() == Some(release_pr_number)
            && pull["merged"] == true
            && pull["state"] == "closed",
        "release PR is not merged"
    );
    let head_sha = CommitSha::parse(
        pull["head"]["sha"]
            .as_str()
            .context("merged release PR lacks its head SHA")?,
    )?;
    let merge_sha = CommitSha::parse(
        pull["merge_commit_sha"]
            .as_str()
            .context("merged release PR lacks its merge SHA")?,
    )?;
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("release tag source run lacks a head SHA")?,
    )?;
    match run["event"].as_str() {
        Some("pull_request") => {
            let associated = run["pull_requests"]
                .as_array()
                .context("pull request release run lacks its associated PR identity")?;
            ensure!(
                associated.iter().any(|candidate| {
                    candidate["number"].as_u64() == Some(release_pr_number)
                        && candidate["head"]["sha"].as_str() == Some(head_sha.as_str())
                }),
                "release tag source run is not associated with the exact merged release PR head"
            );
        }
        Some("workflow_dispatch") => {
            let owner = &instance.config.identities.owner;
            ensure!(
                crate::request::matches_principal(
                    &run["triggering_actor"],
                    owner.id,
                    &owner.login,
                    "User",
                ),
                "release tag retry was not dispatched by the configured owner"
            );
        }
        _ => bail!("unsupported Release Tag source event"),
    }
    let merged_by = &instance.config.identities.server_bot;
    let first_proof = crate::native_server::verify_native_release_approval(
        api,
        api,
        config_path,
        instance,
        repo.as_str(),
        repository_id,
        release_pr_number,
        head_sha.as_str(),
        merge_sha.as_str(),
        merged_by,
    )?;
    let authority_sha256 = crate::api::native_authority_sha256(&instance.authority)?;
    ensure!(
        first_proof.authority_sha256 == authority_sha256
            && first_proof.producer_run_id > 0
            && first_proof.producer_run_attempt > 0
            && first_proof.command_comment_id > 0
            && first_proof.approval_review_id > 0,
        "native approval proof does not bind the current instance authority and review"
    );

    let version_bytes = api.content(repo.as_str(), ".release-version", merge_sha.as_str())?;
    let version = String::from_utf8(version_bytes)?.trim().to_owned();
    let tag = ReleaseTag::parse(&format!("v{version}"))?;
    let manifest = ReleaseManifestV2 {
        schema_version: 2,
        repository: repo.as_str().to_owned(),
        source_run_id: run_id,
        source_run_sha,
        run_attempt,
        // This SHA is the exact Server Release Tag reusable signer admitted
        // above. The approval producer's signer is independently verified by
        // `verify_native_release_approval` and can have a different revision.
        source_revision,
        release_pr_number,
        release_pr_sha: merge_sha.clone(),
        tag: tag.clone(),
        package_version: Some(version),
        artifact_id,
    };
    manifest.validate()?;
    write_json(Path::new("manifest.json"), &manifest)?;

    let tag_target = crate::api::NativeReleaseTagWriteTarget {
        instance,
        config_path,
        repository: repo.as_str(),
        repository_id,
        release_pr_number,
        release_pr_head_sha: head_sha.as_str(),
        release_pr_merge_sha: merge_sha.as_str(),
        tag: tag.as_str(),
    };
    let tag_writer = GitHub::native_release_tag_from_env("GITHUB_TOKEN", &tag_target)?;

    // Re-read the accepted Release Tag package and complete approval proof
    // at each tag-object/ref write boundary. A changed authority, package,
    // current review marker, command, or PR head stops the write.
    let mut verify_before_write = || -> Result<()> {
        api.require_remote_native_server_instance_authority_unchanged(instance)?;
        let current_package = verify_accepted_client_package(
            api,
            &instance.config,
            manifest.source_revision.as_str(),
        )?;
        let current_package_snapshot =
            native_client_package_snapshot(&current_package, &instance.config)?;
        validate_native_client_package_snapshot_for_config(
            &current_package_snapshot,
            &instance.config,
        )?;
        ensure!(
            current_package_snapshot == package_snapshot,
            "accepted Release Tag package changed before the tag write"
        );
        let current_proof = crate::native_server::verify_native_release_approval(
            api,
            api,
            config_path,
            instance,
            repo.as_str(),
            repository_id,
            release_pr_number,
            head_sha.as_str(),
            merge_sha.as_str(),
            merged_by,
        )?;
        ensure!(
            current_proof.producer_run_id == first_proof.producer_run_id
                && current_proof.producer_run_attempt == first_proof.producer_run_attempt
                && current_proof.request_sha256 == first_proof.request_sha256
                && current_proof.authority_sha256 == first_proof.authority_sha256
                && current_proof.workflow_sha == first_proof.workflow_sha
                && current_proof.accepted_client_implementation_sha
                    == first_proof.accepted_client_implementation_sha
                && current_proof.client_workflow_epoch == first_proof.client_workflow_epoch
                && current_proof.command_comment_id == first_proof.command_comment_id
                && current_proof.approval_review_id == first_proof.approval_review_id,
            "native approval proof changed before the tag write"
        );
        Ok(())
    };
    create_annotated_tag_with_fence(
        &tag_writer,
        repo,
        &tag,
        &merge_sha,
        &mut verify_before_write,
    )?;
    crate::output("tag", tag.as_str())?;
    crate::output("merge_sha", merge_sha.as_str())?;
    crate::output("head_sha", head_sha.as_str())?;
    crate::output("manifest_path", "manifest.json")?;
    crate::output(
        "approval_producer_run_id",
        first_proof.producer_run_id.to_string(),
    )?;
    crate::output(
        "approval_producer_run_attempt",
        first_proof.producer_run_attempt.to_string(),
    )?;
    crate::output(
        "approval_review_id",
        first_proof.approval_review_id.to_string(),
    )?;
    crate::output("approval_request_sha256", &first_proof.request_sha256)?;
    crate::output("native_authority_sha256", &first_proof.authority_sha256)?;
    Ok(())
}

fn release_tag_reusable_revision(
    references: &[ReferencedWorkflow],
    distributor_repository: &str,
) -> Result<CommitSha> {
    validate_repository(distributor_repository)?;
    let workflow_path = ".github/workflows/reusable-release-tag.yml";
    let prefix = format!("{distributor_repository}/{workflow_path}@");
    let matching = references
        .iter()
        .filter(|reference| reference.path.starts_with(&prefix))
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "release tag run must name exactly one distributor reusable Release Tag workflow"
    );
    let reference = matching[0];
    let revision = CommitSha::parse(&reference.sha)?;
    ensure!(
        reference.path == format!("{prefix}{}", revision.as_str()),
        "distributor reusable Release Tag workflow reference is not an exact immutable pin"
    );
    Ok(revision)
}

pub(crate) fn create_annotated_tag(
    api: &GitHub,
    repo: &Repository,
    tag: &ReleaseTag,
    target: &CommitSha,
) -> Result<()> {
    create_annotated_tag_with_fence(api, repo, tag, target, &mut || Ok(()))
}

fn create_annotated_tag_with_fence(
    api: &GitHub,
    repo: &Repository,
    tag: &ReleaseTag,
    target: &CommitSha,
    before_write: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let ref_path = format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(tag.as_str())
    );
    match api.get::<Value>(&ref_path) {
        Ok(reference) => {
            ensure!(
                reference["object"]["type"] == "tag",
                "existing release tag is not annotated"
            );
            let object_sha = reference["object"]["sha"]
                .as_str()
                .context("tag reference lacks object SHA")?;
            let object: Value =
                api.get(&format!("/repos/{}/git/tags/{object_sha}", repo.as_str()))?;
            ensure!(
                object["object"]["sha"] == target.as_str(),
                "existing release tag points to a different commit"
            );
            return Ok(());
        }
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) => {}
        Err(error) => return Err(error),
    }
    before_write()?;
    let tag_object: Value = api.post(&format!("/repos/{}/git/tags", repo.as_str()), &json!({"tag":tag.as_str(),"message":format!("Release {}",tag.as_str()),"object":target.as_str(),"type":"commit"}))?;
    let object_sha = tag_object["sha"]
        .as_str()
        .context("GitHub did not return an annotated tag SHA")?;
    before_write()?;
    match api.post::<Value>(
        &format!("/repos/{}/git/refs", repo.as_str()),
        &json!({"ref":format!("refs/tags/{}",tag.as_str()),"sha":object_sha}),
    ) {
        Ok(_) => Ok(()),
        Err(error) => {
            let verify: Value = api
                .get(&ref_path)
                .context("tag creation failed and no matching existing tag was found")?;
            ensure!(
                verify["object"]["type"] == "tag",
                "release tag was created as a lightweight tag"
            );
            let actual: Value = api.get(&format!(
                "/repos/{}/git/tags/{}",
                repo.as_str(),
                verify["object"]["sha"]
                    .as_str()
                    .context("tag lacks object SHA")?
            ))?;
            ensure!(
                actual["object"]["sha"] == target.as_str(),
                "concurrent release tag points to a different commit"
            );
            let _ = error;
            Ok(())
        }
    }
}

fn request_server() -> Result<()> {
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let server_repository = env("SECUREFIX_SERVER_REPOSITORY")?;
    let config_path = env("SECUREFIX_INSTANCE_CONFIG_PATH")?;
    let instance = native_release_instance_for(&read, &server_repository, &config_path)?;
    let repo = current_repository()?;
    let repository_id = configured_release_destination(&instance.config, &repo)?;
    let run_id = env("GITHUB_RUN_ID")?.parse::<u64>()?;
    let label =
        native_release_request_label_name(&instance.config.release_request_label_prefix, run_id)?;
    let target = crate::api::NativeClientReleaseLabelTarget {
        instance: &instance,
        config_path: &config_path,
        release_repository: repo.as_str(),
        release_repository_id: repository_id,
        source_run_id: run_id,
    };
    let api = GitHub::native_client_release_label_from_env("SECUREFIX_SERVER_TOKEN", &target)?;
    let path = format!("/repos/{server_repository}/labels/{}", url_encode(&label));
    match api.get::<Value>(&path) {
        Ok(existing) => ensure!(
            existing["description"] == format!("{}/{run_id}", repo.as_str()),
            "release request label already exists with different provenance"
        ),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            let _: Value = api.post(
                &format!("/repos/{server_repository}/labels"),
                &json!({
                    "name":label,
                    "color":"1f6feb",
                    "description":format!("{}/{run_id}", repo.as_str())
                }),
            )?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn native_release_instance_for(
    api: &GitHub,
    repository: &str,
    config_path: &str,
) -> Result<NativeServerInstanceAuthority> {
    let instance = api.capture_remote_native_server_instance_authority(repository, config_path)?;
    ensure!(
        instance
            .config
            .workflow_roles
            .contains_key(&securefix::instance_config::WorkflowRole::Release),
        "Server Release workflow role is not configured"
    );
    Ok(instance)
}

fn native_release_instance(api: &GitHub) -> Result<NativeServerInstanceAuthority> {
    native_release_instance_for(
        api,
        &env("GITHUB_REPOSITORY")?,
        &env("SECUREFIX_INSTANCE_CONFIG_PATH")?,
    )
}

fn configured_release_destination(
    config: &securefix::instance_config::InstanceConfig,
    repository: &Repository,
) -> Result<u64> {
    let configured = config
        .repositories
        .iter()
        .find(|configured| configured.repository == repository.as_str())
        .context("release destination is not configured")?;
    configured
        .policy()
        .require(Capability::Release)
        .context("release destination lacks its configured capability")?;
    ensure!(
        configured.release.is_some(),
        "release destination has no configured strategy"
    );
    Ok(configured.id)
}

fn verify_current_native_release_tag_package(
    api: &GitHub,
    repository: &Repository,
    repository_id: u64,
    instance: &NativeServerInstanceAuthority,
    pull_request_number: u64,
    pull_request_head_sha: &str,
) -> Result<CommitSha> {
    let run_id = RunId(env("GITHUB_RUN_ID")?.parse()?);
    let attempt = env("GITHUB_RUN_ATTEMPT")?.parse::<u64>()?;
    ensure!(
        run_id.0 > 0 && attempt > 0,
        "invalid Release Tag run identity"
    );
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repository.as_str(),
        run_id.0
    ))?;
    ensure!(
        run["id"].as_u64() == Some(run_id.0)
            && run["run_attempt"].as_u64() == Some(attempt)
            && run["repository"]["id"].as_u64() == Some(repository_id)
            && run["repository"]["full_name"].as_str() == Some(repository.as_str())
            && run["head_repository"]["full_name"].as_str() == Some(repository.as_str())
            && run["status"] == "in_progress"
            && matches!(
                run["event"].as_str(),
                Some("pull_request" | "workflow_dispatch")
            ),
        "Release Tag run does not match the configured release destination"
    );
    match run["event"].as_str() {
        Some("pull_request") => {
            let associated = run["pull_requests"]
                .as_array()
                .context("Release Tag pull request run lacks PR association")?;
            ensure!(
                associated.iter().any(|candidate| {
                    candidate["number"].as_u64() == Some(pull_request_number)
                        && candidate["head"]["sha"].as_str() == Some(pull_request_head_sha)
                }),
                "Release Tag run is not associated with the exact merged PR head"
            );
        }
        Some("workflow_dispatch") => {
            let owner = &instance.config.identities.owner;
            ensure!(
                crate::request::matches_principal(
                    &run["triggering_actor"],
                    owner.id,
                    &owner.login,
                    "User",
                ),
                "Release Tag retry was not dispatched by the configured owner"
            );
        }
        _ => bail!("unsupported Release Tag source event"),
    }
    let references: Vec<ReferencedWorkflow> = serde_json::from_value(
        run.get("referenced_workflows")
            .cloned()
            .context("Release Tag run lacks reusable workflow references")?,
    )
    .context("parse Release Tag reusable workflow references")?;
    let signer_sha =
        release_tag_reusable_revision(&references, &instance.config.acceptable_clients.repository)?;
    let package = verify_accepted_client_package(api, &instance.config, signer_sha.as_str())?;
    let snapshot = native_client_package_snapshot(&package, &instance.config)?;
    validate_native_client_package_snapshot_for_config(&snapshot, &instance.config)?;
    ensure!(
        package.implementation_sha == signer_sha.as_str(),
        "Release Tag signer is not the admitted fixed-package implementation"
    );
    Ok(signer_sha)
}

fn verify_native_release_pr(
    api: &GitHub,
    config_path: &str,
    instance: &NativeServerInstanceAuthority,
    repository: &Repository,
    repository_id: u64,
    pull_request_number: u64,
) -> Result<(
    Value,
    CommitSha,
    crate::native_server::NativeReleaseApprovalProof,
)> {
    ensure!(
        pull_request_number > 0,
        "release PR number must be positive"
    );
    let pull: Value = api.get(&format!(
        "/repos/{}/pulls/{pull_request_number}",
        repository.as_str()
    ))?;
    ensure!(
        pull["number"].as_u64() == Some(pull_request_number)
            && pull["merged"] == true
            && pull["state"] == "closed",
        "release PR is not merged"
    );
    let head_sha = CommitSha::parse(
        pull["head"]["sha"]
            .as_str()
            .context("merged release PR lacks its head SHA")?,
    )?;
    let merge_sha = CommitSha::parse(
        pull["merge_commit_sha"]
            .as_str()
            .context("merged release PR lacks its merge SHA")?,
    )?;
    let proof = crate::native_server::verify_native_release_approval(
        api,
        api,
        config_path,
        instance,
        repository.as_str(),
        repository_id,
        pull_request_number,
        head_sha.as_str(),
        merge_sha.as_str(),
        &instance.config.identities.server_bot,
    )?;
    ensure!(
        proof.authority_sha256 == crate::api::native_authority_sha256(&instance.authority)?
            && proof.producer_run_id > 0
            && proof.producer_run_attempt > 0
            && proof.command_comment_id > 0
            && proof.approval_review_id > 0,
        "native release approval proof does not bind the current instance and review"
    );
    Ok((pull, merge_sha, proof))
}

fn native_release_request_label_name(prefix: &str, run_id: u64) -> Result<String> {
    ensure!(run_id > 0, "release request run ID must be positive");
    let label = format!("{prefix}securefix-native-release-{run_id}");
    ensure!(
        label.len() <= 50,
        "release request label exceeds GitHub's name limit"
    );
    Ok(label)
}

fn native_release_request_parts(
    event: &Value,
    config: &securefix::instance_config::InstanceConfig,
) -> Result<(Repository, RunId, u64)> {
    ensure!(
        event["sender"]["id"].as_u64() == Some(config.identities.client_bot.id)
            && event["sender"]["type"] == "Bot",
        "release request was not created by the configured Client App"
    );
    let label = event["label"]["name"]
        .as_str()
        .context("event lacks release request label")?;
    let prefix = format!(
        "{}securefix-native-release-",
        config.release_request_label_prefix
    );
    let run_suffix = label
        .strip_prefix(&prefix)
        .context("label is not a configured Securefix release request")?;
    let run_id = RunId(
        run_suffix
            .parse()
            .context("release request label has an invalid run ID")?,
    );
    ensure!(run_id.0 > 0, "release request run ID must be positive");
    let description = event["label"]["description"]
        .as_str()
        .context("release request label lacks its repository/run description")?;
    let (repository, described_run) = description
        .rsplit_once('/')
        .context("release request description is invalid")?;
    ensure!(
        described_run == run_suffix && description.matches('/').count() == 2,
        "release request label and description identify different runs"
    );
    let repository = Repository::parse(repository)?;
    let repository_id = configured_release_destination(config, &repository)?;
    Ok((repository, run_id, repository_id))
}

fn verify_native_release_target_policy(
    instance: &NativeServerInstanceAuthority,
    repository: &Repository,
    repository_id: u64,
) -> Result<crate::policy::RepositoryPolicy> {
    let configured = instance
        .config
        .repositories
        .iter()
        .find(|configured| configured.repository == repository.as_str())
        .context("release destination is absent from the protected Server instance config")?;
    ensure!(
        configured.id == repository_id,
        "release destination ID differs from the protected Server instance config"
    );
    let configured_policy = configured.policy();
    configured_policy.require(Capability::Release)?;
    Ok(configured_policy)
}

fn verify_accepted_client_package(
    server_api: &GitHub,
    instance: &securefix::instance_config::InstanceConfig,
    signer_sha: &str,
) -> Result<securefix::package::VerifiedNativeClientPackage> {
    let workflow = server_api.content(
        &instance.acceptable_clients.repository,
        ".github/workflows/reusable-release-tag.yml",
        signer_sha,
    )?;
    let loader_action = crate::native_server::native_client_package_action(
        &workflow,
        &instance.acceptable_clients.repository,
    )?;
    if instance.scratch_package_repository.is_some() {
        return securefix::package::verify_native_client_package_scratch(
            server_api,
            instance,
            &instance.acceptable_clients,
            signer_sha,
            &loader_action,
            "securefix-native-request/v1",
            None,
        );
    }
    let repository: Value = server_api.get(&format!(
        "/repos/{}",
        instance.acceptable_clients.repository
    ))?;
    ensure!(
        repository["id"].as_u64() == Some(instance.acceptable_clients.id)
            && repository["full_name"] == instance.acceptable_clients.repository,
        "configured Client distributor repository identity is invalid"
    );
    let default_branch = repository["default_branch"]
        .as_str()
        .context("configured Client distributor has no default branch")?;
    securefix::package::verify_native_client_package(
        server_api,
        &instance.acceptable_clients,
        signer_sha,
        &loader_action,
        "securefix-native-request/v1",
        default_branch,
    )
}

fn parse_request() -> Result<()> {
    let api = api()?;
    let instance = native_release_instance(&api)?;
    let event = crate::event()?;
    let (repo, run_id, repository_id) = native_release_request_parts(&event, &instance.config)?;
    let (repo_owner, repo_name) = repo
        .as_str()
        .split_once('/')
        .context("release destination repository is invalid")?;
    crate::output("repository", repo.as_str())?;
    crate::output("repo_owner", repo_owner)?;
    crate::output("repo_name", repo_name)?;
    crate::output("repository_id", repository_id.to_string())?;
    crate::output("server_app_id", instance.config.apps.server_id.to_string())?;
    crate::output("run_id", run_id.0.to_string())?;
    Ok(())
}

fn preflight() -> Result<()> {
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let app = GitHub::new(
        "https://api.github.com",
        env("SECUREFIX_RELEASE_READ_TOKEN")?,
    )?;
    let instance = native_release_instance(&read)?;
    let event = crate::event()?;
    let (repo, run_id, repository_id) = native_release_request_parts(&event, &instance.config)?;
    let repo_policy = verify_native_release_target_policy(&instance, &repo, repository_id)?;
    let strategy = repo_policy
        .release
        .context("release strategy is not configured")?;
    let source = validated_native_source(&read, &app, &instance, &repo, run_id)?;
    verify_release_manifest_attestation(
        &app,
        &repo,
        repository_id,
        &source,
        &instance.config.acceptable_clients.repository,
        source.manifest.source_revision.as_str(),
    )?;
    let package = verify_accepted_client_package(
        &read,
        &instance.config,
        source.manifest.source_revision.as_str(),
    )?;
    let package_snapshot = native_client_package_snapshot(&package, &instance.config)?;
    let manifest = source.manifest.clone();
    let tag = manifest.tag.clone();
    let release = find_release(&app, &repo, &tag)?;
    let release_id = release
        .as_ref()
        .map(|release| release["id"].as_u64().context("existing release lacks ID"))
        .transpose()?;
    if let Some(id) = release_id {
        let release: Value = app.get(&format!("/repos/{}/releases/{id}", repo.as_str()))?;
        ensure!(
            release["tag_name"] == tag.as_str(),
            "existing release uses a different tag"
        );
        ensure!(
            release["draft"] == true || release["draft"] == false,
            "existing release lacks draft state"
        );
        ensure!(
            release["draft"] == true || release["immutable"] == true,
            "published release is not marked immutable"
        );
    }
    let server_revision = crate::api::native_server_release_pin(&instance.authority)?;
    let mut plan = ReleasePlanV2 {
        schema_version: 2,
        server_revision,
        instance_authority: Some(instance.authority.clone()),
        source_manifest_sha256: Some(source.manifest_sha256.clone()),
        release_pr_head_sha: Some(source.release_pr_head_sha.clone()),
        client_package: Some(package_snapshot),
        repository: repo.as_str().to_owned(),
        strategy,
        source_run_id: manifest.source_run_id,
        source_run_attempt: manifest.run_attempt,
        source_revision: manifest.source_revision.as_str().to_owned(),
        release_pr_number: manifest.release_pr_number,
        release_pr_sha: manifest.release_pr_sha.as_str().to_owned(),
        tag,
        source_manifest: manifest.clone(),
        native_binary_repository: None,
        release_id,
        existing_signature_sha256: None,
        assets: Vec::new(),
        native_assets: Vec::new(),
    };
    let input_dir = PathBuf::from("release-input");
    if input_dir.exists() {
        std::fs::remove_dir_all(&input_dir)?;
    }
    std::fs::create_dir_all(&input_dir)?;
    if strategy == ReleaseStrategy::TerraformProvider || !repo_policy.native_binaries.is_empty() {
        let artifact_name = if strategy == ReleaseStrategy::TerraformProvider {
            "provider-bundle"
        } else {
            NATIVE_BUNDLE_NAME
        };
        let maximum_size = if strategy == ReleaseStrategy::TerraformProvider {
            512 * 1024 * 1024
        } else {
            MAX_NATIVE_BUNDLE_BYTES
        };
        let bundle_id = manifest
            .artifact_id
            .context("release manifest lacks its bundle artifact ID")?;
        let artifact = get_artifact(&app, &repo, bundle_id, run_id, artifact_name)?;
        ensure!(
            artifact["size_in_bytes"].as_u64().unwrap_or_default() <= maximum_size,
            "release bundle artifact is too large"
        );
        let bytes = app.download(
            &format!("/repos/{}/actions/artifacts/{bundle_id}/zip", repo.as_str()),
            maximum_size as usize,
        )?;
        let assets_dir = input_dir.join("assets");
        std::fs::create_dir_all(&assets_dir)?;
        if strategy == ReleaseStrategy::TerraformProvider {
            unpack_provider_bundle(&bytes, &assets_dir, &plan.tag, repo.name())?;
            let assets = validate_asset_directory(&assets_dir, &plan.tag, repo.name())?;
            plan.assets = assets
                .iter()
                .map(|path| {
                    Ok(PlannedAsset {
                        name: path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .context("invalid asset filename")?
                            .to_owned(),
                        sha256: sha256_file(path)?,
                        size: None,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if let Some(release) = release.as_ref() {
                let existing_assets: Vec<Value> = app.paginate(&format!(
                    "/repos/{}/releases/{}/assets",
                    repo.as_str(),
                    release_id.context("existing release lacks ID")?
                ))?;
                plan.existing_signature_sha256 = prepare_existing_provider_signature(
                    &app,
                    &repo,
                    release,
                    &existing_assets,
                    &plan,
                    &assets_dir,
                    &input_dir,
                )?;
            }
        } else {
            unpack_native_bundle(&bytes, &assets_dir, &repo, &repo_policy.native_binaries)?;
            let native_manifest: NativeAssetManifest =
                serde_json::from_slice(&std::fs::read(assets_dir.join(NATIVE_BUNDLE_MANIFEST))?)?;
            validate_native_manifest(
                &native_manifest,
                &repo,
                &repo_policy.native_binaries,
                &manifest,
            )?;
            validate_native_asset_files(&assets_dir, &native_manifest)?;
            plan.assets = native_manifest
                .assets
                .iter()
                .map(|asset| PlannedAsset {
                    name: asset.filename.clone(),
                    sha256: asset.sha256.clone(),
                    size: Some(asset.size),
                })
                .collect();
            plan.native_binary_repository = Some(native_manifest.repository.clone());
            plan.native_assets = native_manifest.assets;
        }
    } else {
        ensure!(
            manifest.artifact_id.is_none(),
            "GitHub Release manifest unexpectedly names a bundle artifact"
        );
    }
    if strategy == ReleaseStrategy::GithubRelease
        && let Some(release) = release.as_ref()
    {
        let existing_assets: Vec<Value> = app.paginate(&format!(
            "/repos/{}/releases/{}/assets",
            repo.as_str(),
            release_id.context("existing release lacks ID")?
        ))?;
        validate_release_asset_state(&plan.assets, &existing_assets, release["draft"] == false)?;
    }
    plan.validate()?;
    write_json(input_dir.join("plan.json"), &plan)?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    crate::output("tag", plan.tag.as_str())?;
    crate::output("repository", repo.as_str())?;
    crate::output("release_pr_number", plan.release_pr_number.to_string())?;
    let label_name = event["label"]["name"]
        .as_str()
        .context("missing release label name")?;
    crate::output("request_label", label_name)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ArtifactList {
    artifacts: Vec<Value>,
}

fn get_artifact(
    api: &GitHub,
    repo: &Repository,
    artifact_id: u64,
    run_id: RunId,
    expected_name: &str,
) -> Result<Value> {
    let list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        run_id.0
    ))?;
    let mut found = list
        .artifacts
        .into_iter()
        .filter(|artifact| artifact["id"].as_u64() == Some(artifact_id));
    let artifact = found
        .next()
        .context("release artifact is not attached to the source run")?;
    ensure!(found.next().is_none(), "duplicate artifact ID");
    ensure!(
        artifact["expired"] == false && artifact["name"] == expected_name,
        "unexpected or expired release bundle artifact"
    );
    ensure!(
        artifact["size_in_bytes"].as_u64().unwrap_or_default() > 0,
        "release bundle artifact is empty"
    );
    Ok(artifact)
}

fn unpack_provider_bundle(
    bytes: &[u8],
    destination: &Path,
    tag: &ReleaseTag,
    project: &str,
) -> Result<()> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("read uploaded provider artifact")?;
    ensure!(
        archive.len() == PROVIDER_TARGETS.len() + 1,
        "provider artifact has an unexpected entry count"
    );
    let expected = provider_asset_names(tag, project);
    let mut found = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("read provider artifact entry")?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        ensure!(
            path.components().count() == 1
                && !path.is_absolute()
                && !name.contains(['/', '\\'])
                && !entry.is_dir(),
            "provider artifact contains an invalid path"
        );
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "provider artifact contains a symbolic link"
        );
        ensure!(
            expected.contains(&name) && found.insert(name.clone()),
            "provider artifact contains an unexpected or duplicate asset"
        );
        ensure!(
            entry.size() > 0 && entry.size() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider artifact asset has invalid size"
        );
        let output_path = destination.join(&name);
        let mut output = std::fs::File::create(&output_path)
            .with_context(|| format!("create native artifact entry {}", output_path.display()))?;
        let declared_size = entry.size();
        let copied = std::io::copy(
            &mut entry.by_ref().take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut output,
        )?;
        ensure!(
            copied == declared_size && copied <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider artifact asset size or checksum is invalid"
        );
    }
    ensure!(found == expected, "provider artifact is incomplete");
    Ok(())
}

fn unpack_native_bundle(
    bytes: &[u8],
    destination: &Path,
    repository: &Repository,
    targets: &[crate::policy::NativeBinaryTarget],
) -> Result<()> {
    ensure!(
        !targets.is_empty() && targets.len() <= 8,
        "native release target set is invalid"
    );
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("read uploaded native artifact")?;
    ensure!(
        archive.len() == targets.len() + 1,
        "native artifact has an unexpected entry count"
    );
    let mut expected: BTreeSet<String> = targets
        .iter()
        .map(|target| format!("{}-{}", repository.name(), target.target))
        .collect();
    expected.insert(NATIVE_BUNDLE_MANIFEST.to_owned());
    let mut found = BTreeSet::new();
    let mut total_size = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("read native artifact entry")?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        ensure!(
            path.components().count() == 1
                && !path.is_absolute()
                && !name.contains(['/', '\\'])
                && !entry.is_dir(),
            "native artifact contains an invalid path"
        );
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "native artifact contains a symbolic link"
        );
        ensure!(
            expected.contains(&name) && found.insert(name.clone()),
            "native artifact contains an unexpected or duplicate asset"
        );
        let limit = if name == NATIVE_BUNDLE_MANIFEST {
            1024 * 1024
        } else {
            MAX_NATIVE_ASSET_BYTES
        };
        ensure!(
            entry.size() > 0 && entry.size() <= limit,
            "native artifact entry has invalid size"
        );
        total_size = total_size.saturating_add(entry.size());
        ensure!(
            total_size <= MAX_NATIVE_BUNDLE_BYTES,
            "native artifact exceeds its uncompressed size limit"
        );
        let mut output = std::fs::File::create(destination.join(&name))?;
        let declared_size = entry.size();
        let copied = std::io::copy(&mut entry.by_ref().take(limit + 1), &mut output)?;
        ensure!(
            copied == declared_size && copied <= limit,
            "native artifact entry size changed during extraction"
        );
    }
    ensure!(found == expected, "native artifact is incomplete");
    Ok(())
}

fn validate_native_asset_files(directory: &Path, manifest: &NativeAssetManifest) -> Result<()> {
    let mut expected: BTreeSet<String> = manifest
        .assets
        .iter()
        .map(|asset| asset.filename.clone())
        .collect();
    expected.insert(NATIVE_BUNDLE_MANIFEST.to_owned());
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("native asset path is not UTF-8")?;
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "native asset directory contains a non-file entry"
        );
        ensure!(
            actual.insert(name.to_owned()),
            "native asset directory has duplicate names"
        );
    }
    ensure!(
        actual == expected,
        "native asset directory does not match its manifest"
    );
    for asset in &manifest.assets {
        let path = directory.join(&asset.filename);
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == asset.size
                && sha256_file(&path)? == asset.sha256,
            "native release asset differs from its manifest: {}",
            asset.filename
        );
    }
    Ok(())
}

fn validate_source_manifest_provenance(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    manifest: &ReleaseManifestV2,
    strategy: ReleaseStrategy,
) -> Result<()> {
    manifest.validate()?;
    ensure!(
        manifest.repository == repo.as_str(),
        "source manifest repository changed"
    );
    ensure!(
        manifest.source_revision.as_str() == policy.revision,
        "source runtime revision is stale"
    );
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        manifest.source_run_id.0
    ))?;
    ensure!(
        run["name"]
            == format!(
                "{}Release Tag",
                crate::config::trusted()?.deployment.workflow_prefix
            )
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "source Release Tag run is not successful"
    );
    ensure!(
        run["repository"]["full_name"] == repo.as_str()
            && run["head_repository"]["full_name"] == repo.as_str(),
        "source run is not from the same repository"
    );
    ensure!(
        run["head_sha"] == manifest.source_run_sha.as_str()
            && run["run_attempt"].as_u64() == Some(manifest.run_attempt),
        "source run identity changed"
    );
    let referenced: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("source workflow lacks referenced workflow provenance")?;
    referenced_revision(
        &referenced,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let wrapper_path = run["path"]
        .as_str()
        .context("source run lacks caller workflow path")?;
    ensure_valid_caller_path(wrapper_path)?;
    let wrapper_sha = CommitSha::parse(run["head_sha"].as_str().unwrap_or_default())?;
    let default_branch: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = default_branch["default_branch"]
        .as_str()
        .filter(|branch| !branch.is_empty() && !branch.contains(['/', '\\', '@']))
        .context("repository has no valid default branch")?;
    let (pr, merge_sha) = authorized_release_pr(api, policy, repo, manifest.release_pr_number)?;
    ensure!(
        merge_sha == manifest.release_pr_sha,
        "source release PR merge SHA changed"
    );
    let release_version = api.content(repo.as_str(), ".release-version", merge_sha.as_str())?;
    let release_version = String::from_utf8(release_version)?;
    let expected_tag = ReleaseTag::parse(&format!("v{}", release_version.trim()))?;
    ensure!(
        manifest.tag == expected_tag,
        "release tag does not match .release-version at the merged commit"
    );
    let caller_sha = match run["event"].as_str() {
        Some("pull_request") => {
            ensure!(
                run["head_branch"] == pr.head.name
                    && manifest.source_run_sha.as_str() == pr.head.sha,
                "source PR head does not match the release PR"
            );
            // GitHub's run head_sha and pull_requests[].head.sha identify the
            // PR head. Read the caller workflow from the validated merge
            // commit so changes to the wrapper in the merged PR are included.
            let ancestry: Value = api.get(&format!(
                "/repos/{}/compare/{}...{}",
                repo.as_str(),
                merge_sha.as_str(),
                url_encode(default_branch)
            ))?;
            ensure!(
                matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
                "release caller merge revision is not on the default branch"
            );
            merge_sha.clone()
        }
        Some("workflow_dispatch") => {
            ensure!(
                run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id)
                    && run["triggering_actor"]["type"] == "User",
                "manual retry was not dispatched by the repository owner"
            );
            ensure!(
                wrapper_sha.as_str() == manifest.source_run_sha.as_str(),
                "manual retry wrapper revision changed"
            );
            let ancestry: Value = api.get(&format!(
                "/repos/{}/compare/{}...{}",
                repo.as_str(),
                wrapper_sha.as_str(),
                url_encode(default_branch)
            ))?;
            ensure!(
                matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
                "manual retry caller workflow revision is not on the default branch"
            );
            wrapper_sha.clone()
        }
        _ => bail!("unsupported Release Tag event"),
    };
    let wrapper = api.content(repo.as_str(), wrapper_path, caller_sha.as_str())?;
    crate::workflow::require_reusable_pin(
        &wrapper,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(manifest.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == merge_sha.as_str(),
        "release tag points to a different commit"
    );
    if strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0),
            "provider manifest lacks artifact provenance"
        );
    } else {
        let native_assets = !policy.repository(repo.as_str())?.native_binaries.is_empty();
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0) == native_assets,
            "GitHub Release bundle provenance does not match its native asset policy"
        );
    }
    Ok(())
}

fn ensure_valid_caller_path(path: &str) -> Result<()> {
    let prefix = &crate::config::trusted()?.deployment.workflow_prefix;
    ensure!(
        path.starts_with(".github/workflows/")
            && (prefix.is_empty() || path.starts_with(".github/workflows/testing-"))
            && path.ends_with(".yml")
            && path.len() <= 200
            && !path.contains(['\\', '@', '?', '#'])
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "source run has an invalid caller workflow path"
    );
    Ok(())
}

struct SourcePrAssociation<'a> {
    run: &'a Value,
    source_run_sha: &'a CommitSha,
    release_pr_number: u64,
    pr: &'a PullRequest,
    merge_sha: &'a CommitSha,
}

fn validate_source_pr_association(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    source: SourcePrAssociation<'_>,
) -> Result<()> {
    let SourcePrAssociation {
        run,
        source_run_sha,
        release_pr_number,
        pr,
        merge_sha,
    } = source;
    let associated = run["pull_requests"]
        .as_array()
        .context("source run pull request associations are missing or invalid")?;
    ensure!(
        source_run_sha.as_str() == pr.head.sha,
        "source pull request run head does not match the release PR head"
    );
    // GitHub can update this list when the release branch is reused; only a
    // matching PR number is authoritative here, otherwise bind by source commit.
    if associated
        .iter()
        .any(|candidate| candidate["number"].as_u64() == Some(release_pr_number))
    {
        return Ok(());
    }

    let trusted = crate::config::trusted()?;
    ensure!(
        run["head_branch"] == pr.head.name,
        "source PR associations do not match the release branch"
    );
    ensure!(
        run["actor"]["id"].as_u64() == Some(policy.server_bot_id) && run["actor"]["type"] == "Bot",
        "source PR association fallback is only accepted for a Server App run"
    );
    ensure!(
        pr.number == release_pr_number
            && pr.merged == Some(true)
            && pr.merged_at.is_some()
            && pr.merge_commit_sha.as_deref() == Some(merge_sha.as_str())
            && pr.head.name == trusted.deployment.release_branch,
        "fallback release PR is not the authorized merged release"
    );
    let associated_prs = api.paginate(&format!(
        "/repos/{}/commits/{}/pulls",
        repo.as_str(),
        source_run_sha.as_str()
    ))?;
    let matching: Vec<_> = associated_prs
        .iter()
        .filter(|candidate| candidate["number"].as_u64() == Some(release_pr_number))
        .collect();
    ensure!(
        matching.len() == 1,
        "source commit does not identify exactly one release PR"
    );
    let candidate = matching[0];
    let candidate_merged_at: DateTime<Utc> = serde_json::from_value(
        candidate
            .get("merged_at")
            .cloned()
            .context("associated release PR has no merge timestamp")?,
    )
    .context("associated release PR merge timestamp is invalid")?;
    ensure!(
        candidate["state"] == "closed"
            && pr.merged_at.as_ref() == Some(&candidate_merged_at)
            && candidate["merge_commit_sha"] == merge_sha.as_str()
            && candidate["head"]["sha"] == pr.head.sha
            && candidate["head"]["ref"] == trusted.deployment.release_branch
            && candidate["head"]["repo"]["full_name"] == repo.as_str()
            && candidate["base"]["ref"] == pr.base.name
            && candidate["base"]["repo"]["full_name"] == repo.as_str(),
        "source commit association does not match the authorized merged release PR"
    );
    Ok(())
}

struct ValidatedReleaseSource {
    manifest: ReleaseManifestV2,
    manifest_bytes: Vec<u8>,
    manifest_sha256: String,
    release_pr_head_sha: String,
}

fn source_run_manifest(
    api: &GitHub,
    repo: &Repository,
    run_id: RunId,
    run: &Value,
    source_revision: &CommitSha,
) -> Result<(ReleaseManifestV2, Vec<u8>)> {
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("source workflow lacks head SHA")?,
    )?;
    let artifact_list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        run_id.0
    ))?;
    let mut manifests = artifact_list
        .artifacts
        .into_iter()
        .filter(|artifact| artifact["name"] == "release-manifest" && artifact["expired"] == false);
    let manifest_artifact = manifests
        .next()
        .context("source run lacks release manifest artifact")?;
    ensure!(
        manifests.next().is_none(),
        "source run has multiple release manifest artifacts"
    );
    let manifest_id = manifest_artifact["id"]
        .as_u64()
        .context("manifest artifact lacks ID")?;
    ensure!(
        manifest_artifact["size_in_bytes"]
            .as_u64()
            .unwrap_or_default()
            <= 1024 * 1024,
        "release manifest artifact is too large"
    );
    let bytes = api.download(
        &format!(
            "/repos/{}/actions/artifacts/{manifest_id}/zip",
            repo.as_str()
        ),
        1024 * 1024,
    )?;
    let manifest_bytes = release_manifest_bytes_from_zip(&bytes)?;
    let manifest: ReleaseManifestV2 =
        serde_json::from_slice(&manifest_bytes).context("release manifest JSON is invalid")?;
    manifest.validate()?;
    ensure!(
        manifest.repository == repo.as_str() && manifest.source_run_id == run_id,
        "release manifest does not match the source run"
    );
    ensure!(
        manifest.source_run_sha == source_run_sha
            && manifest.run_attempt
                == run["run_attempt"]
                    .as_u64()
                    .context("source run lacks attempt")?,
        "release manifest does not match the source attempt"
    );
    ensure!(
        manifest.source_revision == *source_revision,
        "release manifest runtime revision does not match workflow provenance"
    );
    Ok((manifest, manifest_bytes))
}

fn validated_native_source(
    server_api: &GitHub,
    client_api: &GitHub,
    instance: &NativeServerInstanceAuthority,
    repo: &Repository,
    run_id: RunId,
) -> Result<ValidatedReleaseSource> {
    let repository_id = configured_release_destination(&instance.config, repo)?;
    let run = successful_source_run(client_api, repo.as_str(), run_id.0)?;
    ensure!(
        run["repository"]["id"].as_u64() == Some(repository_id)
            && run["repository"]["full_name"] == repo.as_str()
            && run["head_repository"]["id"].as_u64() == Some(repository_id)
            && run["head_repository"]["full_name"] == repo.as_str(),
        "release source run is outside the configured Client repository"
    );
    let references: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("release source run lacks reusable workflow provenance")?;
    let signer =
        release_tag_reusable_revision(&references, &instance.config.acceptable_clients.repository)?;
    let (manifest, manifest_bytes) = source_run_manifest(client_api, repo, run_id, &run, &signer)?;
    let (pull, merge_sha, _) = verify_native_release_pr(
        client_api,
        &instance.authority.config_path,
        instance,
        repo,
        repository_id,
        manifest.release_pr_number,
    )?;
    ensure!(
        manifest.release_pr_sha == merge_sha,
        "release manifest names a different merge commit"
    );
    match run["event"].as_str() {
        Some("pull_request") => {
            ensure!(
                run["head_sha"] == pull["head"]["sha"],
                "release source run does not match the exact merged PR head"
            );
            let associated = run["pull_requests"]
                .as_array()
                .context("release run lacks PR associations")?;
            if !associated
                .iter()
                .any(|candidate| candidate["number"].as_u64() == Some(manifest.release_pr_number))
            {
                let bot = &instance.config.identities.server_bot;
                ensure!(
                    crate::request::matches_principal(&run["actor"], bot.id, &bot.login, "Bot")
                        && run["head_branch"] == pull["head"]["ref"],
                    "release source association fallback is not the configured Server App branch"
                );
                let associated: Vec<Value> = client_api.paginate(&format!(
                    "/repos/{}/commits/{}/pulls",
                    repo.as_str(),
                    manifest.source_run_sha.as_str(),
                ))?;
                let matching: Vec<_> = associated
                    .iter()
                    .filter(|candidate| {
                        candidate["number"].as_u64() == Some(manifest.release_pr_number)
                    })
                    .collect();
                ensure!(
                    matching.len() == 1
                        && matching[0]["head"]["sha"] == pull["head"]["sha"]
                        && matching[0]["merge_commit_sha"] == pull["merge_commit_sha"]
                        && matching[0]["base"]["repo"]["full_name"] == repo.as_str()
                        && matching[0]["state"] == "closed",
                    "release source commit does not identify its exact merged PR"
                );
            }
        }
        Some("workflow_dispatch") => {
            let owner = &instance.config.identities.owner;
            ensure!(
                crate::request::matches_principal(
                    &run["triggering_actor"],
                    owner.id,
                    &owner.login,
                    "User"
                ),
                "release retry was not dispatched by the configured owner"
            );
        }
        _ => bail!("unsupported Release Tag source event"),
    }
    let tag_ref: Value = client_api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(manifest.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = client_api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("release tag object SHA is missing")?,
    ))?;
    ensure!(
        tag_object["object"]["type"] == "commit"
            && tag_object["object"]["sha"] == merge_sha.as_str(),
        "release tag points to a different commit"
    );
    let policy = verify_native_release_target_policy(instance, repo, repository_id)?;
    let requires_bundle = policy.release == Some(ReleaseStrategy::TerraformProvider)
        || !policy.native_binaries.is_empty();
    ensure!(
        manifest.artifact_id.is_some_and(|id| id > 0) == requires_bundle,
        "release bundle does not match the configured asset policy"
    );
    server_api.require_remote_native_server_instance_authority_unchanged(instance)?;
    Ok(ValidatedReleaseSource {
        release_pr_head_sha: pull["head"]["sha"]
            .as_str()
            .context("merged release PR lacks head SHA")?
            .to_owned(),
        manifest,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        manifest_bytes,
    })
}

fn validated_source(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    run_id: RunId,
    strategy: ReleaseStrategy,
) -> Result<ValidatedReleaseSource> {
    let run = successful_source_run(api, repo.as_str(), run_id.0)?;
    ensure!(
        run["name"]
            == format!(
                "{}Release Tag",
                crate::config::trusted()?.deployment.workflow_prefix
            ),
        "source workflow is not named Release Tag"
    );
    ensure!(
        run["repository"]["full_name"] == repo.as_str()
            && run["head_repository"]["full_name"] == repo.as_str(),
        "source workflow must run in the allowlisted repository"
    );
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("source workflow lacks head SHA")?,
    )?;
    let referenced: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("source workflow lacks referenced workflow provenance")?;
    referenced_revision(
        &referenced,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let reusable_path = crate::config::workflow_path(".github/workflows/reusable-release-tag.yml")?;
    let source_revision = CommitSha::parse(
        &referenced
            .iter()
            .find(|workflow| {
                workflow
                    .path
                    .starts_with(&format!("{server_repository}/{reusable_path}@"))
            })
            .context("source workflow did not call pinned Release Tag reusable")?
            .sha,
    )?;
    let (manifest, manifest_bytes) =
        source_run_manifest(api, repo, run_id, &run, &source_revision)?;
    ensure!(
        manifest.source_revision.as_str() == policy.revision,
        "release runtime revision is stale"
    );
    let release_pr_number = manifest.release_pr_number;
    let (pr, merge_sha) = authorized_release_pr(api, policy, repo, release_pr_number)?;
    ensure!(
        manifest.release_pr_sha == merge_sha,
        "release manifest names a different merge commit"
    );
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(manifest.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == merge_sha.as_str(),
        "release tag points to a different commit"
    );
    if strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0),
            "provider release manifest lacks artifact provenance"
        );
    } else {
        let native_assets = !policy.repository(repo.as_str())?.native_binaries.is_empty();
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0) == native_assets,
            "GitHub Release bundle provenance does not match its native asset policy"
        );
    }
    if run["event"] == "pull_request" {
        validate_source_pr_association(
            api,
            policy,
            repo,
            SourcePrAssociation {
                run: &run,
                source_run_sha: &source_run_sha,
                release_pr_number,
                pr: &pr,
                merge_sha: &merge_sha,
            },
        )?;
    } else if run["event"] == "workflow_dispatch" {
        ensure!(
            run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id),
            "manual release retries must be dispatched by the owner"
        );
    } else {
        bail!("unsupported Release Tag event");
    }
    Ok(ValidatedReleaseSource {
        release_pr_head_sha: pr.head.sha.clone(),
        manifest,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        manifest_bytes,
    })
}

fn release_manifest_proof_from_zip(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 2 * 1024 * 1024,
        "release manifest proof artifact is empty or too large"
    );
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("read release manifest proof artifact")?;
    ensure!(
        archive.len() == 2,
        "release manifest proof must contain exactly manifest.json and bundle.json"
    );
    let mut manifest = None;
    let mut bundle = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        ensure!(
            entry.is_file()
                && !entry.is_dir()
                && entry
                    .unix_mode()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000)
                && Path::new(&name).components().count() == 1
                && !name.contains(['/', '\\']),
            "release manifest proof contains an unsafe path or file type"
        );
        let max = match name.as_str() {
            "manifest.json" => 16 * 1024,
            "bundle.json" => 1024 * 1024,
            _ => bail!("release manifest proof contains an unexpected file"),
        };
        ensure!(
            entry.size() > 0 && entry.size() <= max,
            "release proof file has invalid size"
        );
        let declared_size = entry.size();
        let mut output = Vec::with_capacity(declared_size as usize);
        (&mut entry).take(max + 1).read_to_end(&mut output)?;
        ensure!(
            output.len() as u64 == declared_size && output.len() <= max as usize,
            "release proof file size does not match its archive metadata"
        );
        match name.as_str() {
            "manifest.json" => ensure!(
                manifest.replace(output).is_none(),
                "duplicate release manifest"
            ),
            "bundle.json" => ensure!(
                bundle.replace(output).is_none(),
                "duplicate release attestation bundle"
            ),
            _ => unreachable!(),
        }
    }
    Ok((
        manifest.context("release manifest proof lacks manifest.json")?,
        bundle.context("release manifest proof lacks bundle.json")?,
    ))
}

fn verify_release_manifest_attestation(
    api: &GitHub,
    repo: &Repository,
    repository_id: u64,
    source: &ValidatedReleaseSource,
    signer_repository: &str,
    signer_sha: &str,
) -> Result<()> {
    ensure!(
        source.manifest.source_revision.as_str() == signer_sha,
        "release manifest signer differs from the admitted Client implementation"
    );
    // The attested manifest proof is a separate artifact from the optional
    // native binary bundle; resolve it by exact run and name, not a caller ID.
    let list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        source.manifest.source_run_id.0
    ))?;
    let mut matches = list.artifacts.into_iter().filter(|artifact| {
        artifact["name"] == "release-manifest-proof" && artifact["expired"] == false
    });
    let proof_artifact = matches
        .next()
        .context("source run lacks release manifest proof")?;
    ensure!(
        matches.next().is_none(),
        "source run has duplicate release manifest proofs"
    );
    ensure!(
        proof_artifact["size_in_bytes"].as_u64().unwrap_or_default() <= 2 * 1024 * 1024,
        "release manifest proof artifact exceeds its size limit"
    );
    let proof_id = proof_artifact["id"]
        .as_u64()
        .context("release proof artifact lacks ID")?;
    let zip = api.download(
        &format!("/repos/{}/actions/artifacts/{proof_id}/zip", repo.as_str()),
        2 * 1024 * 1024,
    )?;
    let (attested_manifest, bundle_bytes) = release_manifest_proof_from_zip(&zip)?;
    ensure!(
        attested_manifest == source.manifest_bytes,
        "attested release manifest differs from the source run manifest artifact"
    );
    let run = successful_source_run(api, repo.as_str(), source.manifest.source_run_id.0)?;
    let temporary = tempfile::tempdir()?;
    let manifest_path = temporary.path().join("manifest.json");
    let bundle_path = temporary.path().join("bundle.json");
    std::fs::write(&manifest_path, &source.manifest_bytes)?;
    std::fs::write(&bundle_path, &bundle_bytes)?;
    let signer_workflow = ".github/workflows/reusable-release-tag.yml";
    let verified = securefix::attestation::verify_with_gh(
        &manifest_path,
        &bundle_path,
        securefix::attestation::VerifyRequest {
            repository: repo.as_str(),
            signer_repository,
            signer_workflow,
            signer_sha,
            source: None,
        },
    )?;
    validate_release_manifest_certificate(
        &verified,
        &source.manifest,
        &run,
        repository_id,
        signer_repository,
        signer_workflow,
        signer_sha,
        &source.manifest_bytes,
    )
}

fn release_manifest_bytes_from_zip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        archive.len() == 1,
        "release manifest artifact must contain exactly one file"
    );
    let mut file = archive.by_index(0)?;
    ensure!(
        file.name() == "manifest.json"
            && file.is_file()
            && file.size() <= 16_384
            && file
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
        "invalid release manifest artifact entry"
    );
    let declared_size = file.size();
    let mut manifest_bytes = Vec::with_capacity(declared_size as usize);
    (&mut file).take(16_385).read_to_end(&mut manifest_bytes)?;
    ensure!(
        manifest_bytes.len() <= 16_384 && manifest_bytes.len() as u64 == declared_size,
        "release manifest artifact size mismatch or exceeds limit"
    );
    Ok(manifest_bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    securefix::hex_encode(Sha256::digest(bytes))
}

fn validate_sha256_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "expected a lowercase SHA-256 digest"
    );
    Ok(())
}

fn validate_native_client_package_snapshot_values(
    package: &NativeClientPackageSnapshot,
) -> Result<()> {
    validate_repository(&package.distributor_repository)?;
    validate_repository(&package.release_repository)?;
    ensure!(
        package.distributor_id > 0 && package.release_repository_id > 0,
        "Client distributor or release repository ID is invalid"
    );
    CommitSha::parse(&package.implementation_sha)?;
    CommitSha::parse(&package.loader_action_sha)?;
    CommitSha::parse(&package.binary_source_sha)?;
    securefix::package::PinnedPackageAction::new(
        package.distributor_repository.clone(),
        package.loader_action_path.clone(),
        package.loader_action_sha.clone(),
    )?;
    let implementation_version = Version::parse(&package.implementation_version)?;
    let binary_version = Version::parse(&package.binary_version)?;
    ensure!(
        implementation_version.build.is_empty()
            && binary_version.build.is_empty()
            && package.release_tag == format!("v{binary_version}")
            && package.protocol == "securefix-native-request/v1"
            && package.release_id > 0
            && package.asset_id > 0
            && !package.asset_name.is_empty()
            && package.asset_size > 0
            && package.package_producer_run_id > 0
            && package.package_producer_run_attempt > 0
            && package.package_publisher_run_id > 0
            && package.package_publisher_run_attempt > 0,
        "accepted Client package snapshot contains an invalid release identity"
    );
    ensure!(
        package
            .package_producer_workflow
            .starts_with(".github/workflows/")
            && package.package_producer_workflow.ends_with(".yml")
            && !package.package_producer_workflow.contains("..")
            && package.package_producer_branch.len() <= 255
            && crate::config::validate_branch(&package.package_producer_branch).is_ok()
            && package
                .package_publisher_workflow
                .starts_with(".github/workflows/")
            && package.package_publisher_workflow.ends_with(".yml")
            && !package.package_publisher_workflow.contains("..")
            && package.package_publisher_branch.len() <= 255
            && crate::config::validate_branch(&package.package_publisher_branch).is_ok(),
        "accepted Client package snapshot contains an invalid publisher identity"
    );
    CommitSha::parse(&package.package_publisher_sha)?;
    validate_sha256_digest(&package.asset_sha256)
}

fn native_client_package_snapshot(
    package: &securefix::package::VerifiedNativeClientPackage,
    config: &securefix::instance_config::InstanceConfig,
) -> Result<NativeClientPackageSnapshot> {
    let release = package.package.release();
    let producer_run = package.package.producer_run();
    ensure!(
        producer_run
            == (
                package.package_producer_run_id,
                package.package_producer_run_attempt
            ),
        "verified package producer run differs from its explicit identity"
    );
    let snapshot = NativeClientPackageSnapshot {
        distributor_repository: config.acceptable_clients.repository.clone(),
        distributor_id: config.acceptable_clients.id,
        release_repository: release.publisher.repository.clone(),
        release_repository_id: release.publisher.repository_id,
        implementation_sha: package.implementation_sha.clone(),
        implementation_version: package.implementation_version.to_string(),
        loader_action_sha: package.loader_action_sha.clone(),
        loader_action_path: package.loader_action_path.clone(),
        binary_source_sha: package.binary_source_sha.clone(),
        binary_version: package.binary_version.to_string(),
        protocol: package.protocol.clone(),
        release_tag: release.tag.clone(),
        release_id: release.release_id,
        asset_id: release.asset.id,
        asset_name: release.asset.name.clone(),
        asset_size: release.asset.size,
        asset_sha256: release.asset.sha256.clone(),
        package_publisher_workflow: package.package_publisher_workflow.clone(),
        package_publisher_branch: package.package_publisher_branch.clone(),
        package_publisher_sha: package.package_publisher_sha.clone(),
        package_publisher_run_id: package.package_publisher_run_id,
        package_publisher_run_attempt: package.package_publisher_run_attempt,
        package_producer_workflow: package.package_producer_workflow.clone(),
        package_producer_branch: package.package_producer_branch.clone(),
        package_producer_run_id: package.package_producer_run_id,
        package_producer_run_attempt: package.package_producer_run_attempt,
    };
    validate_native_client_package_snapshot_for_config(&snapshot, config)?;
    Ok(snapshot)
}

fn validate_native_client_package_snapshot_for_config(
    package: &NativeClientPackageSnapshot,
    config: &securefix::instance_config::InstanceConfig,
) -> Result<()> {
    validate_native_client_package_snapshot_values(package)?;
    let implementation_version = Version::parse(&package.implementation_version)?;
    securefix::package::validate_native_client_package_destination(
        config,
        &securefix::package::TrustedPublisher {
            repository: package.release_repository.clone(),
            repository_id: package.release_repository_id,
        },
        &implementation_version,
        &Version::parse(&package.binary_version)?,
    )?;
    ensure!(
        package.distributor_repository == config.acceptable_clients.repository
            && package.distributor_id == config.acceptable_clients.id,
        "accepted Client package snapshot no longer matches the instance distributor policy"
    );
    Ok(())
}

// This validator compares a verified bundle against the exact selected run,
// signer, repository, and manifest bytes; keeping those values explicit makes
// the trust bindings visible at the call site.
#[allow(clippy::too_many_arguments)]
fn validate_release_manifest_certificate(
    verified: &Value,
    manifest: &ReleaseManifestV2,
    run: &Value,
    repository_id: u64,
    signer_repository: &str,
    signer_workflow: &str,
    signer_sha: &str,
    manifest_bytes: &[u8],
) -> Result<()> {
    ensure!(
        verified
            .as_array()
            .is_some_and(|results| results.len() == 1),
        "release manifest attestation verifier must return exactly one result"
    );
    let result = &verified[0]["verificationResult"];
    let certificate = &result["signature"]["certificate"];
    let statement = &result["statement"];
    let source_run_id = manifest.source_run_id.0;
    let source_run_attempt = manifest.run_attempt;
    let expected_run = format!(
        "https://github.com/{}/actions/runs/{source_run_id}/attempts/{source_run_attempt}",
        manifest.repository
    );
    let expected_signer =
        format!("https://github.com/{signer_repository}/{signer_workflow}@{signer_sha}");
    let source_sha = manifest.source_run_sha.as_str();
    let owner_id = run["repository"]["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("release source repository owner ID is missing")?;
    ensure!(
        run["id"].as_u64() == Some(source_run_id)
            && run["run_attempt"].as_u64() == Some(source_run_attempt)
            && run["head_sha"].as_str() == Some(source_sha)
            && run["repository"]["id"].as_u64() == Some(repository_id)
            && run["repository"]["full_name"].as_str() == Some(manifest.repository.as_str())
            && run["event"].as_str().is_some()
            && certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["githubWorkflowRepository"].as_str()
                == Some(manifest.repository.as_str())
            && certificate["githubWorkflowTrigger"].as_str() == run["event"].as_str()
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", manifest.repository)
            && certificate["sourceRepositoryDigest"].as_str() == Some(source_sha)
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(repository_id))
            && certificate["sourceRepositoryOwnerIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(owner_id))
            && certificate["runInvocationURI"].as_str() == Some(expected_run.as_str())
            && certificate["runnerEnvironment"] == "github-hosted"
            && certificate["buildSignerDigest"].as_str() == Some(signer_sha)
            && certificate["buildSignerURI"].as_str() == Some(expected_signer.as_str())
            && certificate["subjectAlternativeName"].as_str() == Some(expected_signer.as_str()),
        "release manifest attestation certificate does not match its source run and signer"
    );
    let expected_sha = sha256_bytes(manifest_bytes);
    let subjects = statement["subject"]
        .as_array()
        .context("release manifest attestation subject is missing")?;
    ensure!(
        statement["predicateType"] == "https://slsa.dev/provenance/v1"
            && subjects.len() == 1
            && subjects[0]["name"] == "manifest.json"
            && subjects[0]["digest"]["sha256"].as_str() == Some(expected_sha.as_str()),
        "release manifest attestation subject differs from exact manifest bytes"
    );
    Ok(())
}

fn require_dispatch_owner(api: &GitHub, policy: &Policy) -> Result<()> {
    if std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch") {
        let run_id: u64 = env("GITHUB_RUN_ID")?.parse()?;
        let run: Value = api.get(&format!(
            "/repos/{}/actions/runs/{run_id}",
            current_repository()?.as_str()
        ))?;
        ensure!(
            run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id),
            "manual release retries must be dispatched by the repository owner"
        );
        ensure!(
            run["triggering_actor"]["type"] == "User",
            "manual release retry actor is not a user"
        );
    }
    Ok(())
}

fn find_release(api: &GitHub, repo: &Repository, tag: &ReleaseTag) -> Result<Option<Value>> {
    let path = format!(
        "/repos/{}/releases/tags/{}",
        repo.as_str(),
        url_encode(tag.as_str())
    );
    match api.get::<Value>(&path) {
        Ok(release) => {
            ensure!(
                release["tag_name"] == tag.as_str(),
                "release lookup returned a different tag"
            );
            Ok(Some(release))
        }
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            // GitHub's tag lookup may not expose draft releases. Listing requires
            // push access to include drafts, which the preflight token has.
            let releases = api.paginate(&format!("/repos/{}/releases", repo.as_str()))?;
            release_with_tag(&releases, tag)
        }
        Err(error) => Err(error),
    }
}

fn release_with_tag(releases: &[Value], tag: &ReleaseTag) -> Result<Option<Value>> {
    let mut matching = releases
        .iter()
        .filter(|release| release["tag_name"] == tag.as_str());
    let release = matching.next().cloned();
    ensure!(
        matching.next().is_none(),
        "multiple releases use the requested tag"
    );
    Ok(release)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(securefix::hex_encode(digest.finalize()))
}

const MAX_PROVIDER_SIGNATURE_BYTES: usize = 1024 * 1024;

fn canonical_provider_sums(assets_dir: &Path, assets: &[PlannedAsset]) -> Result<Vec<u8>> {
    let mut sums = String::new();
    for asset in assets {
        let path = assets_dir.join(&asset.name);
        ensure!(
            sha256_file(&path)? == asset.sha256,
            "provider asset digest changed: {}",
            asset.name
        );
        sums.push_str(&format!("{}  {}\n", asset.sha256, asset.name));
    }
    Ok(sums.into_bytes())
}

fn prepare_existing_provider_signature(
    api: &GitHub,
    repo: &Repository,
    release: &Value,
    existing: &[Value],
    plan: &ReleasePlanV2,
    assets_dir: &Path,
    input_dir: &Path,
) -> Result<Option<String>> {
    let project = Repository::parse(&plan.repository)?;
    let project = project.name();
    let sums_name = format!("{project}_{}_SHA256SUMS", plan.tag.version());
    let signature_name = format!("{sums_name}.sig");
    let mut expected: std::collections::BTreeMap<String, String> = plan
        .assets
        .iter()
        .map(|asset| (asset.name.clone(), asset.sha256.clone()))
        .collect();
    expected.insert(
        sums_name.clone(),
        securefix::hex_encode(Sha256::digest(canonical_provider_sums(
            assets_dir,
            &plan.assets,
        )?)),
    );
    let mut by_name = std::collections::BTreeMap::new();
    for asset in existing {
        let name = asset["name"]
            .as_str()
            .context("existing release asset lacks name")?;
        ensure!(
            name == signature_name || expected.contains_key(name),
            "release contains an unexpected asset: {name}"
        );
        ensure!(
            by_name.insert(name.to_owned(), asset).is_none(),
            "duplicate release asset: {name}"
        );
        if name != signature_name {
            let digest = format!("sha256:{}", expected.get(name).expect("checked above"));
            ensure!(
                asset["digest"] == digest,
                "existing release asset has different bytes: {name}"
            );
        }
    }
    if release["draft"] == false {
        ensure!(
            by_name.len() == expected.len() + 1,
            "published provider release is incomplete"
        );
    }
    let Some(signature) = by_name.get(&signature_name) else {
        return Ok(None);
    };
    ensure!(
        by_name.contains_key(&sums_name),
        "existing signature has no checksum asset"
    );
    let size = signature["size"].as_u64().unwrap_or_default();
    ensure!(
        size > 0 && size <= MAX_PROVIDER_SIGNATURE_BYTES as u64,
        "existing signature has invalid size"
    );
    let asset_id = signature["id"]
        .as_u64()
        .context("existing signature lacks asset ID")?;
    let digest = signature["digest"]
        .as_str()
        .context("existing signature lacks digest")?;
    ensure!(
        digest.starts_with("sha256:") && digest.len() == 71,
        "existing signature has invalid digest"
    );
    let bytes = api.download(
        &format!("/repos/{}/releases/assets/{asset_id}", repo.as_str()),
        MAX_PROVIDER_SIGNATURE_BYTES,
    )?;
    ensure!(
        bytes.len() as u64 == size,
        "existing signature size changed during download"
    );
    let downloaded_digest = format!("sha256:{}", securefix::hex_encode(Sha256::digest(&bytes)));
    ensure!(
        downloaded_digest == digest,
        "existing signature digest changed during download"
    );
    std::fs::write(input_dir.join("existing-signature.sig"), &bytes)?;
    Ok(Some(
        downloaded_digest.trim_start_matches("sha256:").to_owned(),
    ))
}

fn sign() -> Result<()> {
    let server = GitHub::from_env("GITHUB_TOKEN")?;
    let public = GitHub::anonymous()?;
    let input = PathBuf::from("release-input");
    let assets_dir = input.join("assets");
    let mut plan: ReleasePlanV2 = serde_json::from_slice(&std::fs::read(input.join("plan.json"))?)?;
    plan.validate()?;
    let repo = Repository::parse(&plan.repository)?;
    ensure!(
        plan.strategy == ReleaseStrategy::TerraformProvider,
        "signing is only allowed for Terraform provider releases"
    );
    if plan.instance_authority.is_some() {
        let instance = native_release_instance(&server)?;
        ensure!(
            plan.instance_authority.as_ref() == Some(&instance.authority)
                && plan.server_revision
                    == crate::api::native_server_release_pin(&instance.authority)?,
            "signing plan has a stale Server deployment or configuration"
        );
        let repository_id = configured_release_destination(&instance.config, &repo)?;
        ensure!(
            verify_native_release_target_policy(&instance, &repo, repository_id)?.release
                == Some(plan.strategy),
            "signing strategy changed after preflight"
        );
        let source =
            validated_native_source(&server, &public, &instance, &repo, plan.source_run_id)?;
        ensure!(
            source.manifest == plan.source_manifest
                && Some(&source.manifest_sha256) == plan.source_manifest_sha256.as_ref()
                && Some(&source.release_pr_head_sha) == plan.release_pr_head_sha.as_ref(),
            "signing source changed after preflight"
        );
        verify_release_manifest_attestation(
            &public,
            &repo,
            repository_id,
            &source,
            &instance.config.acceptable_clients.repository,
            source.manifest.source_revision.as_str(),
        )?;
        let package = verify_accepted_client_package(
            &server,
            &instance.config,
            source.manifest.source_revision.as_str(),
        )?;
        ensure!(
            plan.client_package.as_ref()
                == Some(&native_client_package_snapshot(&package, &instance.config)?),
            "signing Client package changed after preflight"
        );
    } else {
        let policy = current_policy(&server)?;
        let _runtime = require_current_runtime(&server, ".github/workflows/release.yml")?;
        ensure!(
            plan.server_revision == policy.revision,
            "signing plan is stale"
        );
        let repo_policy = policy.repository(repo.as_str())?;
        repo_policy.require(Capability::Release)?;
        ensure!(
            repo_policy.release == Some(plan.strategy),
            "signing strategy changed after preflight"
        );
        validate_source_manifest_provenance(
            &public,
            &policy,
            &repo,
            &plan.source_manifest,
            plan.strategy,
        )?;
    }
    let assets = validate_asset_directory(&assets_dir, &plan.tag, repo.name())?;
    ensure!(
        assets.len() == plan.assets.len(),
        "signing bundle asset count changed"
    );
    for asset in &plan.assets {
        let path = assets_dir.join(&asset.name);
        ensure!(
            sha256_file(&path)? == asset.sha256,
            "signing bundle asset digest changed: {}",
            asset.name
        );
    }
    let sums = canonical_provider_sums(&assets_dir, &plan.assets)?;
    let sums_path = assets_dir.join(format!("{}_{}_SHA256SUMS", repo.name(), plan.tag.version()));
    std::fs::write(&sums_path, &sums)?;
    let signature_path = assets_dir.join(format!(
        "{}_{}_SHA256SUMS.sig",
        repo.name(),
        plan.tag.version()
    ));
    let fingerprint = env("GPG_FINGERPRINT")?;
    let signature_input = input.join("existing-signature.sig");
    reuse_or_sign_checksum(
        &sums_path,
        &signature_path,
        &signature_input,
        plan.existing_signature_sha256.as_deref(),
        &fingerprint,
        &std::env::var("GPG_PASSPHRASE").unwrap_or_default(),
        None,
    )?;
    ensure!(
        plan.assets
            .iter()
            .all(|asset| assets_dir.join(&asset.name).is_file()),
        "signed bundle is incomplete"
    );
    plan.assets.push(PlannedAsset {
        name: sums_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid checksum filename")?
            .to_owned(),
        sha256: sha256_file(&sums_path)?,
        size: None,
    });
    plan.assets.push(PlannedAsset {
        name: signature_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid signature filename")?
            .to_owned(),
        sha256: sha256_file(&signature_path)?,
        size: None,
    });
    plan.validate()?;
    validate_signed_provider_assets(&assets_dir, &plan)?;
    write_json(input.join("plan.json"), &plan)?;
    Ok(())
}

fn sign_checksum(
    sums_path: &Path,
    signature_path: &Path,
    fingerprint: &str,
    passphrase: &str,
    homedir: Option<&Path>,
) -> Result<()> {
    let mut gpg = ProcessCommand::new("gpg");
    gpg.arg("--batch");
    gpg.args(["--no-auto-key-retrieve", "--no-auto-key-import"]);
    if let Some(homedir) = homedir {
        gpg.arg("--homedir").arg(homedir);
    }
    gpg.args([
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--local-user",
    ])
    .arg(fingerprint)
    .arg("--output")
    .arg(signature_path)
    .arg("--detach-sign")
    .arg(sums_path)
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let mut child = gpg.spawn().context("start checksum signing")?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{passphrase}")?;
    }
    let result = child.wait_with_output()?;
    ensure!(result.status.success(), "checksum signing failed");
    ensure!(
        signature_path.metadata()?.len() > 0,
        "signing produced an empty signature"
    );
    verify_checksum_signature(signature_path, sums_path, fingerprint, homedir)
}

fn reuse_or_sign_checksum(
    sums_path: &Path,
    signature_path: &Path,
    existing_path: &Path,
    expected_digest: Option<&str>,
    fingerprint: &str,
    passphrase: &str,
    homedir: Option<&Path>,
) -> Result<()> {
    if let Some(expected_digest) = expected_digest {
        ensure!(
            existing_path.is_file(),
            "planned existing signature is missing"
        );
        ensure!(
            sha256_file(existing_path)? == expected_digest,
            "existing signature artifact digest changed"
        );
        std::fs::copy(existing_path, signature_path)?;
        verify_checksum_signature(signature_path, sums_path, fingerprint, homedir)?;
    } else {
        ensure!(
            !existing_path.exists(),
            "unplanned existing signature is present"
        );
        sign_checksum(sums_path, signature_path, fingerprint, passphrase, homedir)?;
    }
    Ok(())
}

fn verify_checksum_signature(
    signature_path: &Path,
    sums_path: &Path,
    fingerprint: &str,
    homedir: Option<&Path>,
) -> Result<()> {
    let mut gpg = ProcessCommand::new("gpg");
    gpg.arg("--batch");
    gpg.args(["--no-auto-key-retrieve", "--no-auto-key-import"]);
    if let Some(homedir) = homedir {
        gpg.arg("--homedir").arg(homedir);
    }
    let output = gpg
        .args(["--status-fd", "1", "--verify"])
        .arg(signature_path)
        .arg(sums_path)
        .output()
        .context("start checksum signature verification")?;
    ensure!(
        output.status.success(),
        "checksum signature verification failed"
    );
    let status = String::from_utf8(output.stdout).context("GPG status is not UTF-8")?;
    validate_gpg_status(&status, fingerprint)
}

fn validate_gpg_status(status: &str, fingerprint: &str) -> Result<()> {
    let expected = fingerprint.trim().to_ascii_uppercase();
    ensure!(!expected.is_empty(), "configured GPG fingerprint is empty");
    let mut valid_signatures = Vec::new();
    for line in status.lines() {
        let Some(payload) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let mut fields = payload.split_ascii_whitespace();
        let Some(kind) = fields.next() else { continue };
        ensure!(
            !matches!(
                kind,
                "BADSIG"
                    | "ERRSIG"
                    | "NO_PUBKEY"
                    | "EXPSIG"
                    | "EXPKEYSIG"
                    | "REVKEYSIG"
                    | "KEYEXPIRED"
                    | "KEYREVOKED"
                    | "SIGEXPIRED"
            ),
            "GPG reported an invalid or expired signature"
        );
        if kind == "VALIDSIG" {
            let signer = fields
                .next()
                .context("GPG VALIDSIG lacks signer fingerprint")?
                .to_ascii_uppercase();
            let remaining: Vec<_> = fields.collect();
            let primary = remaining.get(8).map(|value| value.to_ascii_uppercase());
            valid_signatures.push((signer, primary));
        }
    }
    ensure!(
        valid_signatures.len() == 1,
        "GPG did not report exactly one valid signature"
    );
    let (signer, primary) = &valid_signatures[0];
    ensure!(
        signer == &expected || primary.as_ref() == Some(&expected),
        "checksum signature uses an unexpected key"
    );
    Ok(())
}

fn publish() -> Result<()> {
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let input = PathBuf::from("release-package");
    let assets_dir = input.join("assets");
    let plan: ReleasePlanV2 = serde_json::from_slice(&std::fs::read(input.join("plan.json"))?)?;
    plan.validate()?;
    if plan.instance_authority.is_some() {
        return publish_native_release(&read, &plan, &assets_dir);
    }
    let policy = current_policy(&read)?;
    let _runtime = require_current_runtime(&read, ".github/workflows/reusable-server-release.yml")?;
    ensure!(
        plan.server_revision == policy.revision,
        "publish plan is stale"
    );
    let repo = Repository::parse(&plan.repository)?;
    let repo_policy = policy.repository(repo.as_str())?;
    repo_policy.require(Capability::Release)?;
    ensure!(
        repo_policy.release == Some(plan.strategy),
        "release strategy changed after preflight"
    );
    let api = GitHub::from_env("GH_TOKEN")?;
    if plan.strategy == ReleaseStrategy::GithubRelease {
        ensure!(
            repo_policy.native_binaries.is_empty() == plan.native_assets.is_empty(),
            "native release plan does not match its asset policy"
        );
        if !repo_policy.native_binaries.is_empty() {
            ensure!(
                plan.native_binary_repository.as_deref() == Some(repo.as_str()),
                "native release plan source repository differs from its release repository"
            );
            let native_manifest = NativeAssetManifest {
                schema_version: 1,
                repository: plan.native_binary_repository.clone().unwrap_or_default(),
                source_run_id: plan.source_manifest.source_run_id,
                source_run_sha: plan.source_manifest.source_run_sha.clone(),
                run_attempt: plan.source_manifest.run_attempt,
                source_revision: plan.source_manifest.source_revision.clone(),
                release_pr_number: plan.source_manifest.release_pr_number,
                release_pr_sha: plan.source_manifest.release_pr_sha.clone(),
                tag: plan.source_manifest.tag.clone(),
                package_version: plan.source_manifest.package_version().to_owned(),
                assets: plan.native_assets.clone(),
            };
            validate_native_manifest(
                &native_manifest,
                &repo,
                &repo_policy.native_binaries,
                &plan.source_manifest,
            )?;
            validate_native_asset_files(&assets_dir, &native_manifest)?;
        }
    }
    let source = validated_source(&read, &policy, &repo, plan.source_run_id, plan.strategy)?;
    let expected_manifest_sha256 = plan
        .source_manifest_sha256
        .as_deref()
        .context("publish plan lacks the source manifest digest")?;
    validate_sha256_digest(expected_manifest_sha256)?;
    ensure!(
        sha256_bytes(&source.manifest_bytes) == source.manifest_sha256
            && source.manifest_sha256 == expected_manifest_sha256,
        "source manifest bytes differ from the preflight plan"
    );
    let manifest = &source.manifest;
    ensure!(
        manifest.release_pr_number == plan.release_pr_number
            && manifest.release_pr_sha.as_str() == plan.release_pr_sha
            && manifest.tag == plan.tag
            && manifest.package_version() == plan.source_manifest.package_version(),
        "publish plan no longer matches authorized source"
    );
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(plan.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == plan.release_pr_sha,
        "release tag moved after preflight"
    );
    let existing = find_release(&api, &repo, &plan.tag)?;
    let current_id = existing
        .as_ref()
        .map(|release| release["id"].as_u64().context("existing release lacks ID"))
        .transpose()?;
    validate_release_identity(plan.release_id, current_id)?;
    let release = match existing {
        Some(release) => {
            ensure!(
                release["draft"] == true || release["immutable"] == true,
                "existing published release is not immutable"
            );
            release
        }
        None => {
            let repository: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
            let default_branch = repository["default_branch"]
                .as_str()
                .context("release repository default branch missing")?;
            api.post(&format!("/repos/{}/releases", repo.as_str()), &json!({"tag_name":plan.tag.as_str(),"name":plan.tag.as_str(),"generate_release_notes":true,"prerelease":!plan.tag.version().split('-').nth(1).unwrap_or_default().is_empty(),"draft":true,"target_commitish":default_branch}))?
        }
    };
    let release_id = release["id"]
        .as_u64()
        .context("release response lacks ID")?;
    if plan.strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            plan.assets.len() == PROVIDER_TARGETS.len() + 3,
            "signed provider asset set is incomplete"
        );
        validate_signed_provider_assets(&assets_dir, &plan)?;
    }
    publish_release_assets(&api, &repo, release_id, &plan, &assets_dir)
}

fn publish_native_release(
    server_api: &GitHub,
    plan: &ReleasePlanV2,
    assets_dir: &Path,
) -> Result<()> {
    let repository = Repository::parse(&plan.repository)?;
    let instance = native_release_instance(server_api)?;
    ensure!(
        plan.instance_authority.as_ref() == Some(&instance.authority),
        "native release instance authority changed after preflight"
    );
    let instance_policy = verify_native_release_target_policy(
        &instance,
        &repository,
        instance
            .config
            .repositories
            .iter()
            .find(|configured| configured.repository == repository.as_str())
            .map(|configured| configured.id)
            .context("native release target is absent from the protected instance config")?,
    )?;
    ensure!(
        instance_policy.release == Some(plan.strategy)
            && plan.server_revision == crate::api::native_server_release_pin(&instance.authority)?,
        "native release plan no longer matches its configured release strategy"
    );
    let read_api = GitHub::from_env("SECUREFIX_RELEASE_READ_TOKEN")?;
    let source = validated_native_source(
        server_api,
        &read_api,
        &instance,
        &repository,
        plan.source_run_id,
    )?;
    ensure!(
        source.manifest_sha256 == plan.source_manifest_sha256.as_deref().unwrap_or_default()
            && source.release_pr_head_sha
                == plan.release_pr_head_sha.as_deref().unwrap_or_default()
            && source.manifest == plan.source_manifest,
        "native release source manifest or PR head changed after preflight"
    );
    verify_release_manifest_attestation(
        &read_api,
        &repository,
        instance
            .config
            .repositories
            .iter()
            .find(|configured| configured.repository == repository.as_str())
            .context("native release target is absent from the protected instance config")?
            .id,
        &source,
        &instance.config.acceptable_clients.repository,
        source.manifest.source_revision.as_str(),
    )?;
    let package = verify_accepted_client_package(
        server_api,
        &instance.config,
        source.manifest.source_revision.as_str(),
    )?;
    let package_snapshot = native_client_package_snapshot(&package, &instance.config)?;
    validate_native_client_package_snapshot_for_config(&package_snapshot, &instance.config)?;
    ensure!(
        plan.client_package.as_ref() == Some(&package_snapshot),
        "accepted Client package changed after release preflight"
    );
    if plan.strategy == ReleaseStrategy::TerraformProvider {
        validate_signed_provider_assets(assets_dir, plan)?;
    } else {
        ensure!(
            instance_policy.native_binaries.is_empty() == plan.native_assets.is_empty(),
            "release assets no longer match the configured native target set"
        );
        if !plan.native_assets.is_empty() {
            let native_manifest = NativeAssetManifest {
                schema_version: 1,
                repository: plan
                    .native_binary_repository
                    .clone()
                    .context("native release lacks its source repository")?,
                source_run_id: plan.source_manifest.source_run_id,
                source_run_sha: plan.source_manifest.source_run_sha.clone(),
                run_attempt: plan.source_manifest.run_attempt,
                source_revision: plan.source_manifest.source_revision.clone(),
                release_pr_number: plan.release_pr_number,
                release_pr_sha: plan.source_manifest.release_pr_sha.clone(),
                tag: plan.tag.clone(),
                package_version: plan.source_manifest.package_version().to_owned(),
                assets: plan.native_assets.clone(),
            };
            validate_native_manifest(
                &native_manifest,
                &repository,
                &instance_policy.native_binaries,
                &plan.source_manifest,
            )?;
            validate_native_asset_files(assets_dir, &native_manifest)?;
        }
    }

    let mut assets = Vec::with_capacity(plan.assets.len());
    for asset in &plan.assets {
        let path = assets_dir.join(&asset.name);
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() > 0
                && metadata.len() <= MAX_NATIVE_ASSET_BYTES
                && sha256_file(&path)? == asset.sha256
                && asset.size.is_none_or(|size| size == metadata.len()),
            "native release asset changed after preflight: {}",
            asset.name
        );
        assets.push(crate::api::NativeReleaseAsset {
            name: asset.name.clone(),
            size: metadata.len(),
            sha256: asset.sha256.clone(),
            content_type: "application/octet-stream".to_owned(),
        });
    }
    let native_names: BTreeSet<_> = plan
        .native_assets
        .iter()
        .map(|asset| asset.filename.as_str())
        .collect();
    let native_assets: Vec<_> = assets
        .iter()
        .filter(|asset| native_names.contains(asset.name.as_str()))
        .cloned()
        .collect();
    ensure!(
        native_assets.len() == plan.native_assets.len(),
        "native release asset plan is incomplete"
    );
    let config_path = env("SECUREFIX_INSTANCE_CONFIG_PATH")?;
    let target = crate::api::NativeReleaseWriteTarget {
        config_path: &config_path,
        instance: &instance,
        repository: repository.as_str(),
        repository_id: instance
            .config
            .repositories
            .iter()
            .find(|configured| configured.repository == repository.as_str())
            .context("native release target is absent from the protected instance config")?
            .id,
        release_pr_number: source.manifest.release_pr_number,
        release_pr_head_sha: &source.release_pr_head_sha,
        release_pr_merge_sha: source.manifest.release_pr_sha.as_str(),
        tag: source.manifest.tag.as_str(),
        release_source_run_id: source.manifest.source_run_id.0,
        release_source_run_attempt: source.manifest.run_attempt,
        release_source_run_sha: source.manifest.source_run_sha.as_str(),
        release_source_workflow_sha: source.manifest.source_revision.as_str(),
        release_manifest: &source.manifest,
        release_manifest_bytes: &source.manifest_bytes,
        client_package: &package,
        assets: &assets,
        native_assets: &native_assets,
        release_id: plan.release_id,
    };
    let mut writer = GitHub::native_release_from_env(
        "SECUREFIX_RELEASE_READ_TOKEN",
        "SECUREFIX_RELEASE_WRITE_TOKEN",
        &instance,
        &target,
    )?;
    let existing = find_release(&writer, &repository, &plan.tag)?;
    let release = match existing {
        Some(release) => {
            ensure!(
                release["draft"] == true || release["immutable"] == true,
                "existing published native release is not immutable"
            );
            release
        }
        None => {
            let destination: Value = writer.get(&format!("/repos/{}", repository.as_str()))?;
            let default_branch = destination["default_branch"]
                .as_str()
                .context("native release repository default branch is missing")?;
            let prerelease = !Version::parse(plan.tag.version())?.pre.is_empty();
            writer.post(
                &format!("/repos/{}/releases", repository.as_str()),
                &json!({"tag_name":plan.tag.as_str(),"name":plan.tag.as_str(),"generate_release_notes":true,"prerelease":prerelease,"draft":true,"target_commitish":default_branch}),
            )?
        }
    };
    let release_id = release["id"]
        .as_u64()
        .context("native release response lacks ID")?;
    if plan.release_id.is_none() {
        writer.native_release_select(release_id)?;
    }
    publish_release_assets(&writer, &repository, release_id, plan, assets_dir)
}

fn publish_release_assets(
    api: &GitHub,
    repo: &Repository,
    release_id: u64,
    plan: &ReleasePlanV2,
    assets_dir: &Path,
) -> Result<()> {
    let mut upload = |api: &GitHub, path: &str, bytes: Vec<u8>, content_type: &str| {
        api.upload(path, bytes, content_type)
    };
    publish_release_assets_with_upload(api, repo, release_id, plan, assets_dir, &mut upload)
}

fn publish_release_assets_with_upload<F>(
    api: &GitHub,
    repo: &Repository,
    release_id: u64,
    plan: &ReleasePlanV2,
    assets_dir: &Path,
    upload: &mut F,
) -> Result<()>
where
    F: FnMut(&GitHub, &str, Vec<u8>, &str) -> Result<Value>,
{
    let release_path = format!("/repos/{}/releases/{release_id}", repo.as_str());
    let release: Value = api.get(&release_path)?;
    ensure!(
        release["id"].as_u64() == Some(release_id) && release["tag_name"] == plan.tag.as_str(),
        "release identity changed before asset publication"
    );
    let asset_path = format!("/repos/{}/releases/{release_id}/assets", repo.as_str());
    let existing: Vec<Value> = api.paginate(&asset_path)?;
    if release["draft"] == false {
        validate_release_asset_state(&plan.assets, &existing, true)?;
        ensure_published_immutable_release(&release, release_id, &plan.tag)?;
        return Ok(());
    }
    ensure!(release["draft"] == true, "release draft state is missing");
    upload_release_assets(
        api,
        repo,
        release_id,
        assets_dir,
        &plan.assets,
        &existing,
        upload,
    )?;
    let ready: Vec<Value> = api.paginate(&asset_path)?;
    validate_release_asset_state(&plan.assets, &ready, true)?;
    let before_publish: Value = api.get(&release_path)?;
    ensure!(
        before_publish["id"].as_u64() == Some(release_id)
            && before_publish["tag_name"] == plan.tag.as_str()
            && before_publish["draft"] == true,
        "release changed before publication"
    );
    let _: Value = api.patch(&release_path, &json!({"draft":false}))?;

    let published: Value = api.get(&release_path)?;
    ensure_published_immutable_release(&published, release_id, &plan.tag)?;
    let published_assets: Vec<Value> = api.paginate(&asset_path)?;
    validate_release_asset_state(&plan.assets, &published_assets, true)
}

fn upload_release_assets<F>(
    api: &GitHub,
    repo: &Repository,
    release_id: u64,
    assets_dir: &Path,
    expected: &[PlannedAsset],
    existing: &[Value],
    upload: &mut F,
) -> Result<()>
where
    F: FnMut(&GitHub, &str, Vec<u8>, &str) -> Result<Value>,
{
    validate_release_asset_state(expected, existing, false)?;
    let mut local_assets = Vec::with_capacity(expected.len());
    for asset in expected {
        let path = assets_dir.join(&asset.name);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect release asset {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() > 0
                && metadata.len() <= MAX_NATIVE_ASSET_BYTES
                && sha256_file(&path)
                    .with_context(|| format!("hash release asset {}", path.display()))?
                    == asset.sha256,
            "publish asset digest mismatch or invalid file: {}",
            asset.name
        );
        local_assets.push((asset, path));
    }
    for (asset, path) in local_assets {
        if existing
            .iter()
            .any(|published| published["name"] == asset.name)
        {
            continue;
        }
        let upload_url = format!(
            "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
            repo.as_str(),
            url_encode(&asset.name)
        );
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read release asset {}", path.display()))?;
        upload(api, &upload_url, bytes, "application/octet-stream")?;
    }
    let uploaded: Vec<Value> = api.paginate(&format!(
        "/repos/{}/releases/{release_id}/assets",
        repo.as_str()
    ))?;
    validate_release_asset_state(expected, &uploaded, true)
}

fn ensure_published_immutable_release(
    release: &Value,
    expected_id: u64,
    tag: &ReleaseTag,
) -> Result<()> {
    ensure!(
        release["id"].as_u64() == Some(expected_id),
        "published release identity changed"
    );
    ensure!(
        release["tag_name"] == tag.as_str(),
        "published release tag changed"
    );
    ensure!(release["draft"] == false, "release remains a draft");
    ensure!(
        release["immutable"] == true,
        "published release is not immutable"
    );
    Ok(())
}

fn validate_release_identity(expected: Option<u64>, current: Option<u64>) -> Result<()> {
    ensure!(
        expected == current,
        "release identity changed after preflight"
    );
    Ok(())
}

fn validate_release_asset_state(
    expected: &[PlannedAsset],
    existing: &[Value],
    require_complete: bool,
) -> Result<()> {
    let expected: std::collections::BTreeMap<_, _> = expected
        .iter()
        .map(|asset| (asset.name.as_str(), asset))
        .collect();
    let mut found = BTreeSet::new();
    for asset in existing {
        let name = asset["name"]
            .as_str()
            .context("existing release asset lacks name")?;
        let expected_asset = expected
            .get(name)
            .with_context(|| format!("release contains an unexpected asset: {name}"))?;
        ensure!(
            asset["digest"] == format!("sha256:{}", expected_asset.sha256),
            "release asset already exists with different bytes: {name}"
        );
        if let Some(size) = expected_asset.size {
            ensure!(
                asset["size"].as_u64() == Some(size),
                "release asset size does not match the expected bytes: {name}"
            );
        }
        ensure!(found.insert(name), "duplicate release asset: {name}");
    }
    if require_complete {
        ensure!(
            found.len() == expected.len(),
            "published immutable release is missing an expected asset"
        );
    }
    Ok(())
}

fn validate_signed_provider_assets(directory: &Path, plan: &ReleasePlanV2) -> Result<()> {
    let repository = Repository::parse(&plan.repository)?;
    validate_signed_provider_assets_for_project(directory, plan, repository.name())
}

fn validate_signed_provider_assets_for_project(
    directory: &Path,
    plan: &ReleasePlanV2,
    project: &str,
) -> Result<()> {
    let mut expected = provider_asset_names(&plan.tag, project);
    let sums_name = format!("{project}_{}_SHA256SUMS", plan.tag.version());
    let signature_name = format!("{sums_name}.sig");
    expected.insert(sums_name.clone());
    expected.insert(signature_name.clone());
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "signed provider asset directory contains a non-file"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("provider asset name is not UTF-8"))?;
        ensure!(
            expected.contains(&name) && found.insert(name.clone()),
            "signed provider bundle has unexpected or duplicate asset {name}"
        );
        ensure!(
            entry.metadata()?.len() > 0 && entry.metadata()?.len() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "signed provider asset has invalid size"
        );
        if name.ends_with(".zip") {
            validate_provider_archive(&entry.path(), &name, &plan.tag, project)?;
        }
    }
    ensure!(found == expected, "signed provider asset set is incomplete");
    let planned = plan
        .assets
        .iter()
        .map(|asset| asset.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = expected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        planned == expected_names,
        "signed plan asset names do not match the canonical set"
    );
    for asset in &plan.assets {
        ensure!(
            sha256_file(&directory.join(&asset.name))? == asset.sha256,
            "signed asset digest mismatch: {}",
            asset.name
        );
    }
    let mut sums = String::new();
    for name in provider_asset_names(&plan.tag, project) {
        sums.push_str(&format!(
            "{}  {}\n",
            sha256_file(&directory.join(&name))?,
            name
        ));
    }
    ensure!(
        std::fs::read_to_string(directory.join(sums_name))? == sums,
        "checksum file does not match provider assets"
    );
    Ok(())
}

fn cleanup() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let event = crate::event()?;
    if std::env::var_os("SECUREFIX_INSTANCE_CONFIG_PATH").is_some() {
        let instance = native_release_instance(&api)?;
        let (_, run, _) = native_release_request_parts(&event, &instance.config)?;
        let label = native_release_request_label_name(
            &instance.config.release_request_label_prefix,
            run.0,
        )?;
        let writer = GitHub::native_release_cleanup_from_env("GITHUB_TOKEN", &instance, &label)?;
        let path = format!(
            "/repos/{}/labels/{}",
            instance.config.instance.repository,
            url_encode(&label)
        );
        return match writer.delete(&path) {
            Ok(()) => Ok(()),
            Err(error)
                if error.downcast_ref::<ApiError>().is_some_and(|api_error| {
                    api_error.status == reqwest::StatusCode::NOT_FOUND
                }) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        };
    }
    let _runtime = require_current_runtime(&api, ".github/workflows/release.yml")?;
    let Some(label) = event["label"]["name"].as_str() else {
        return Ok(());
    };
    if !label.starts_with(
        &crate::config::trusted()?
            .deployment
            .label_prefix("release-request-"),
    ) {
        return Ok(());
    }
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let path = format!("/repos/{server_repository}/labels/{}", url_encode(label));
    match api.delete(&path) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub fn provider_asset_names(tag: &ReleaseTag, project: &str) -> BTreeSet<String> {
    let mut files = PROVIDER_TARGETS
        .iter()
        .map(|target| {
            format!(
                "{project}_{}_{}_{}.zip",
                tag.version(),
                target.os,
                target.arch
            )
        })
        .collect::<BTreeSet<_>>();
    files.insert(format!("{project}_{}_manifest.json", tag.version()));
    files
}

pub fn validate_asset_directory(
    directory: &Path,
    tag: &ReleaseTag,
    project: &str,
) -> Result<Vec<PathBuf>> {
    let expected = provider_asset_names(tag, project);
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(directory).context("read provider asset directory")? {
        let entry = entry.context("read provider asset entry")?;
        let metadata = entry.file_type().context("inspect provider asset entry")?;
        if !metadata.is_file() || metadata.is_symlink() {
            bail!("provider asset directory may contain regular files only");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("provider asset filename is not UTF-8"))?;
        if !expected.contains(&name) {
            bail!("unexpected provider asset: {name}");
        }
        if !found.insert(name.clone()) {
            bail!("duplicate provider asset: {name}");
        }
        let size = entry
            .metadata()
            .context("inspect provider asset size")?
            .len();
        if size == 0 || size > MAX_PROVIDER_ARCHIVE_BYTES {
            bail!("provider asset has an invalid size: {name}");
        }
        if name.ends_with(".zip") {
            validate_provider_archive(&entry.path(), &name, tag, project)?;
        }
    }
    if found != expected {
        let missing = expected.difference(&found).cloned().collect::<Vec<_>>();
        bail!(
            "provider asset set is incomplete; missing: {}",
            missing.join(", ")
        );
    }
    Ok(found.into_iter().map(|name| directory.join(name)).collect())
}

fn validate_provider_archive(
    path: &Path,
    archive_name: &str,
    tag: &ReleaseTag,
    project: &str,
) -> Result<()> {
    let file = std::fs::File::open(path).context("open provider archive")?;
    let mut zip = zip::ZipArchive::new(file).context("read provider archive")?;
    ensure!(
        zip.len() == 4 && zip.len() <= MAX_PROVIDER_ARCHIVE_FILES,
        "provider archive must contain exactly four files: {archive_name}"
    );
    let expected_binary = format!(
        "{project}_v{}{}",
        tag.version(),
        if archive_name.contains("_windows_") {
            ".exe"
        } else {
            ""
        }
    );
    let mut found = BTreeSet::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).context("read provider archive entry")?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || name.contains('\\')
            || entry.is_dir()
        {
            bail!("provider archive contains an invalid entry path: {name}");
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            bail!("provider archive contains a symbolic link: {name}");
        }
        let declared_size = entry.size();
        if declared_size > MAX_PROVIDER_ARCHIVE_BYTES {
            bail!("provider archive entry is too large: {name}");
        }
        let copied = std::io::copy(
            &mut entry.by_ref().take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut std::io::sink(),
        )?;
        ensure!(
            copied == declared_size,
            "provider archive entry size or checksum is invalid: {name}"
        );
        ensure!(
            [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                expected_binary.as_str()
            ]
            .contains(&name.as_str())
                && found.insert(name.clone()),
            "provider archive contains an unexpected or duplicate file: {name}"
        );
    }
    ensure!(
        found
            == [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                expected_binary.as_str()
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "provider archive lacks required files: {archive_name}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tag_signer_uses_the_separate_distributor_repository() {
        let signer = "a".repeat(40);
        let instance_repository = "civitaspo/testing-securefix-server";
        let release_repository = "civitaspo/herdr-linear-agent";
        let distributor_repository = "civitaspo/securefix-server";
        let references = vec![
            ReferencedWorkflow {
                path: format!(
                    "{distributor_repository}/.github/workflows/reusable-release-tag.yml@{signer}"
                ),
                sha: signer.clone(),
            },
            ReferencedWorkflow {
                path: format!(
                    "{instance_repository}/.github/workflows/reusable-server-release.yml@{}",
                    "b".repeat(40)
                ),
                sha: "b".repeat(40),
            },
        ];
        assert_eq!(
            release_tag_reusable_revision(&references, distributor_repository)
                .unwrap()
                .as_str(),
            signer
        );
        assert!(release_tag_reusable_revision(&references, instance_repository).is_err());
        assert!(release_tag_reusable_revision(&references, release_repository).is_err());

        let duplicated = [references[0].clone(), references[0].clone()];
        assert!(release_tag_reusable_revision(&duplicated, distributor_repository).is_err());

        let mutable = [ReferencedWorkflow {
            path: format!(
                "{distributor_repository}/.github/workflows/reusable-release-tag.yml@main"
            ),
            sha: "a".repeat(40),
        }];
        assert!(release_tag_reusable_revision(&mutable, distributor_repository).is_err());
    }

    fn release_manifest_certificate_fixture() -> (ReleaseManifestV2, Value, Vec<u8>, Value) {
        let repository = "example-org/client";
        let source_sha = "c".repeat(40);
        let signer_sha = "a".repeat(40);
        let manifest = ReleaseManifestV2 {
            schema_version: 2,
            repository: repository.to_owned(),
            source_run_id: RunId(42),
            source_run_sha: CommitSha::parse(&source_sha).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&signer_sha).unwrap(),
            release_pr_number: 9,
            release_pr_sha: CommitSha::parse(&"b".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            package_version: Some("1.2.3".into()),
            artifact_id: None,
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let run = json!({
            "id":42,
            "run_attempt":1,
            "head_sha":source_sha,
            "event":"workflow_dispatch",
            "repository":{"id":77,"full_name":repository,"owner":{"id":88}}
        });
        let signer_repository = "example-org/securefix-server";
        let signer_workflow = ".github/workflows/reusable-release-tag.yml";
        let signer =
            format!("https://github.com/{signer_repository}/{signer_workflow}@{signer_sha}");
        let expected_run = format!("https://github.com/{repository}/actions/runs/42/attempts/1");
        let verified = json!([{
            "verificationResult": {
                "signature": {"certificate": {
                    "issuer":"https://token.actions.githubusercontent.com",
                    "githubWorkflowRepository":repository,
                    "githubWorkflowTrigger":"workflow_dispatch",
                    "sourceRepositoryURI":format!("https://github.com/{repository}"),
                    "sourceRepositoryDigest":source_sha,
                    "sourceRepositoryIdentifier":"77",
                    "sourceRepositoryOwnerIdentifier":"88",
                    "runInvocationURI":expected_run,
                    "runnerEnvironment":"github-hosted",
                    "buildSignerDigest":signer_sha,
                    "buildSignerURI":signer,
                    "subjectAlternativeName":signer
                }},
                "statement": {
                    "predicateType":"https://slsa.dev/provenance/v1",
                    "subject":[{"name":"manifest.json","digest":{"sha256":sha256_bytes(&bytes)}}]
                }
            }
        }]);
        (manifest, run, bytes, verified)
    }

    #[test]
    fn release_manifest_attestation_binds_exact_run_signer_and_bytes() {
        let (manifest, run, bytes, verified) = release_manifest_certificate_fixture();
        let signer_sha = "a".repeat(40);
        assert!(
            validate_release_manifest_certificate(
                &verified,
                &manifest,
                &run,
                77,
                "example-org/securefix-server",
                ".github/workflows/reusable-release-tag.yml",
                &signer_sha,
                &bytes,
            )
            .is_ok()
        );

        let mut wrong_run = run.clone();
        wrong_run["run_attempt"] = json!(2);
        assert!(
            validate_release_manifest_certificate(
                &verified,
                &manifest,
                &wrong_run,
                77,
                "example-org/securefix-server",
                ".github/workflows/reusable-release-tag.yml",
                &signer_sha,
                &bytes,
            )
            .is_err()
        );

        let mut wrong_subject = verified.clone();
        wrong_subject[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] =
            json!("d".repeat(64));
        assert!(
            validate_release_manifest_certificate(
                &wrong_subject,
                &manifest,
                &run,
                77,
                "example-org/securefix-server",
                ".github/workflows/reusable-release-tag.yml",
                &signer_sha,
                &bytes,
            )
            .is_err()
        );
    }

    #[test]
    fn native_release_request_uses_configured_prefix_bot_and_repository_identity() {
        let mut config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        config.release_request_label_prefix = "testing-".to_owned();
        let event = json!({
            "sender": {"id": 202, "type": "Bot"},
            "label": {
                "name": "testing-securefix-native-release-12345",
                "description": "example-org/project/12345"
            }
        });
        let (repository, run_id, repository_id) =
            native_release_request_parts(&event, &config).unwrap();
        assert_eq!(repository.as_str(), "example-org/project");
        assert_eq!(run_id.0, 12345);
        assert_eq!(repository_id, 987654);

        for invalid in [
            json!({
                "sender": {"id": 999, "type": "Bot"},
                "label": {
                    "name": "testing-securefix-native-release-12345",
                    "description": "example-org/project/12345"
                }
            }),
            json!({
                "sender": {"id": 202, "type": "Bot"},
                "label": {
                    "name": "securefix-native-release-12345",
                    "description": "example-org/project/12345"
                }
            }),
            json!({
                "sender": {"id": 202, "type": "Bot"},
                "label": {
                    "name": "testing-securefix-native-release-12345",
                    "description": "example-org/unconfigured/12345"
                }
            }),
        ] {
            assert!(native_release_request_parts(&invalid, &config).is_err());
        }
    }

    #[test]
    fn release_changelog_range_starts_at_stable_base() {
        let stable_base = Version::parse("0.2.2").unwrap();
        assert_eq!(
            release_changelog_range(&stable_base).as_deref(),
            Some("v0.2.2..HEAD")
        );
        assert_eq!(release_changelog_range(&Version::new(0, 0, 0)), None);
    }

    #[test]
    fn release_manifest_artifact_preserves_exact_bounded_bytes() {
        let expected = br#"{"schema_version":2}"#;
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file("manifest.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(expected).unwrap();
        let bytes = archive.finish().unwrap().into_inner();
        assert_eq!(release_manifest_bytes_from_zip(&bytes).unwrap(), expected);

        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file("manifest.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(expected).unwrap();
        archive
            .start_file("extra.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"{}").unwrap();
        assert!(release_manifest_bytes_from_zip(&archive.finish().unwrap().into_inner()).is_err());
    }

    #[test]
    fn release_source_manifest_binds_client_signer_run_attempt_and_exact_bytes() {
        use crate::fixtures::{Fixture, Route};
        let manifest = provenance_test_manifest();
        let repo = Repository::parse(&manifest.repository).unwrap();
        let expected = serde_json::to_vec(&manifest).unwrap();
        let run = json!({"head_sha":manifest.source_run_sha.as_str(), "run_attempt":manifest.run_attempt});
        for (source_run, signer, accepted) in [
            (run.clone(), manifest.source_revision.clone(), true),
            (
                run.clone(),
                CommitSha::parse(&"f".repeat(40)).unwrap(),
                false,
            ),
            (
                json!({"head_sha":"e".repeat(40), "run_attempt":manifest.run_attempt}),
                manifest.source_revision.clone(),
                false,
            ),
            (
                json!({"head_sha":manifest.source_run_sha.as_str(), "run_attempt":manifest.run_attempt+1}),
                manifest.source_revision.clone(),
                false,
            ),
        ] {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            zip.start_file("manifest.json", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(&expected).unwrap();
            let archive = zip.finish().unwrap().into_inner();
            let fixture = Fixture::new(vec![
                Route::get(
                    format!(
                        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
                        repo.as_str(),
                        manifest.source_run_id.0
                    ),
                    json!({"artifacts":[{"name":"release-manifest","expired":false,"id":71,"size_in_bytes":archive.len()}]}),
                ),
                Route::raw(
                    "GET",
                    format!("/repos/{}/actions/artifacts/71/zip", repo.as_str()),
                    200,
                    archive,
                ),
            ]);
            let actual = source_run_manifest(
                &fixture.api,
                &repo,
                manifest.source_run_id,
                &source_run,
                &signer,
            );
            assert_eq!(actual.is_ok(), accepted);
            if let Ok((parsed, bytes)) = actual {
                assert_eq!(parsed, manifest);
                assert_eq!(bytes, expected);
            }
            fixture.finish();
        }
    }

    // This ignored probe is invoked only by the frozen, trusted integration
    // workflow. Every phase is explicitly selected; production release
    // commands never expose this mode.
    #[test]
    #[ignore = "requires isolated provider probe workflow and credentials"]
    fn provider_no_publish_probe() {
        provider_no_publish_probe_inner().unwrap();
    }

    fn provider_no_publish_probe_inner() -> Result<()> {
        let phase = env("SECUREFIX_PROVIDER_PROBE_PHASE")?;
        let project = env("SECUREFIX_PROVIDER_PROBE_PROJECT")?;
        Repository::parse(&format!("probe/{project}"))?;
        let tag = ReleaseTag::parse(&env("SECUREFIX_PROVIDER_PROBE_TAG")?)?;
        let assets = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_ASSET_DIR")?);
        std::fs::create_dir_all(&assets)?;
        match phase.as_str() {
            "build-target" => {
                let source = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_SOURCE_DIR")?);
                let output = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_OUTPUT_DIR")?);
                let os = env("SECUREFIX_PROVIDER_PROBE_OS")?;
                let arch = env("SECUREFIX_PROVIDER_PROBE_ARCH")?;
                let target = PROVIDER_TARGETS
                    .iter()
                    .copied()
                    .find(|target| target.os == os && target.arch == arch)
                    .context("target is not in the supported provider matrix")?;
                build_provider_target(&source, &project, &tag, target, &output)?;
            }
            "build-manifest" => {
                let source = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_SOURCE_DIR")?);
                let name = format!("{project}_{}_manifest.json", tag.version());
                std::fs::copy(
                    source.join("terraform-registry-manifest.json"),
                    assets.join(name),
                )?;
            }
            "fresh-sign" => {
                let fingerprint = env("GPG_FINGERPRINT")?;
                ensure!(
                    fingerprint == env("SECUREFIX_PROVIDER_PROBE_EXPECTED_GPG_FINGERPRINT")?,
                    "signing key differs from configured Registry key"
                );
                export_probe_public_key(&fingerprint)?;
                let passphrase = std::env::var("GPG_PASSPHRASE").unwrap_or_default();
                let input = assets.join("existing-signature.sig");
                let sums_name = format!("{project}_{}_SHA256SUMS", tag.version());
                let mut plan = probe_plan(&assets, &project, tag.clone())?;
                let sums = canonical_provider_sums(&assets, &plan.assets)?;
                let sums_path = assets.join(&sums_name);
                std::fs::write(&sums_path, sums)?;
                let signature_path = assets.join(format!("{sums_name}.sig"));
                reuse_or_sign_checksum(
                    &sums_path,
                    &signature_path,
                    &input,
                    None,
                    &fingerprint,
                    &passphrase,
                    None,
                )?;
                append_signed_assets(&mut plan, &assets, &sums_path, &signature_path)?;
                validate_signed_provider_assets_for_project(&assets, &plan, &project)?;
            }
            "create-draft" => {
                let (api, repo) = probe_write_api()?;
                let target_sha = probe_scratch_target_sha(&repo)?;
                let tag_ref = format!(
                    "/repos/{}/git/ref/tags/{}",
                    repo.as_str(),
                    url_encode(tag.as_str())
                );
                ensure!(
                    probe_not_found(&api, &tag_ref)?,
                    "scratch tag already exists"
                );
                let release: Value = api.post(
                    &format!("/repos/{}/releases", repo.as_str()),
                    &json!({"tag_name":tag.as_str(),"target_commitish":target_sha,"name":tag.as_str(),"draft":true,"prerelease":true,"generate_release_notes":false}),
                )?;
                let release_id = release["id"].as_u64().context("created draft lacks ID")?;
                crate::output("release_id", release_id.to_string())?;
                crate::output("target_sha", &target_sha)?;
                write_probe_receipt(release_id, tag.as_str(), &target_sha)?;
                ensure!(
                    release["draft"] == true && release["tag_name"] == tag.as_str(),
                    "created release is not the expected draft"
                );
                ensure!(
                    probe_not_found(&api, &tag_ref)?
                        || probe_tag_points_to_commit(&api, &repo, tag.as_str(), &target_sha)?,
                    "created probe tag does not point to the recorded target commit"
                );
                crate::output("tag", tag.as_str())?;
            }
            "recover-download" => {
                let repo_name = env("SECUREFIX_PROVIDER_PROBE_REPOSITORY")?;
                ensure!(
                    repo_name == crate::config::trusted()?.deployment.integration.repository,
                    "provider probe repository is not the trusted integration repository"
                );
                let repo = Repository::parse(&repo_name)?;
                let release_id = probe_release_id()?;
                ensure!(release_id > 0, "release ID must be positive");
                let api = GitHub::new("https://api.github.com", env("GH_TOKEN")?)?;
                let found = find_release(&api, &repo, &tag)?;
                ensure!(
                    found.as_ref().and_then(|release| release["id"].as_u64()) == Some(release_id),
                    "scratch tag does not resolve to the receipt-bound draft release"
                );
                let release: Value =
                    api.get(&format!("/repos/{}/releases/{release_id}", repo.as_str()))?;
                ensure!(
                    release["id"].as_u64() == Some(release_id)
                        && release["draft"] == true
                        && release["tag_name"] == tag.as_str(),
                    "probe target is not the expected draft release"
                );
                let target_sha = probe_target_sha()?;
                write_probe_receipt(release_id, tag.as_str(), &target_sha)?;
                crate::output("release_id", release_id.to_string())?;
                let existing: Vec<Value> = api.paginate(&format!(
                    "/repos/{}/releases/{release_id}/assets",
                    repo.as_str()
                ))?;
                let plan = probe_plan(&assets, &project, tag.clone())?;
                let input = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_OUTPUT_DIR")?);
                std::fs::create_dir_all(&input)?;
                let digest = prepare_existing_provider_signature(
                    &api, &repo, &release, &existing, &plan, &assets, &input,
                )?
                .context("scratch draft has no signature to recover")?;
                write_json(
                    input.join("receipt.json"),
                    &json!({"release_id":release_id,"tag":tag.as_str(),"sha256":digest}),
                )?;
                write_probe_receipt(release_id, tag.as_str(), &probe_target_sha()?)?;
                crate::output("release_id", release_id.to_string())?;
            }
            "stage-draft" | "complete-draft" => {
                let repo_name = env("SECUREFIX_PROVIDER_PROBE_REPOSITORY")?;
                ensure!(
                    repo_name == crate::config::trusted()?.deployment.integration.repository,
                    "provider probe repository is not the trusted integration repository"
                );
                let repo = Repository::parse(&repo_name)?;
                let (api, _) = probe_write_api()?;
                let release_id = probe_release_id()?;
                let release: Value =
                    api.get(&format!("/repos/{}/releases/{release_id}", repo.as_str()))?;
                ensure!(
                    release["id"].as_u64() == Some(release_id)
                        && release["draft"] == true
                        && release["tag_name"] == tag.as_str(),
                    "probe target is not the expected draft release"
                );
                write_probe_receipt(release_id, tag.as_str(), &probe_target_sha()?)?;
                crate::output("release_id", release_id.to_string())?;
                let mut expected = probe_plan(&assets, &project, tag.clone())?;
                if phase == "complete-draft" {
                    let sums = assets.join(format!("{project}_{}_SHA256SUMS", tag.version()));
                    let sig = assets.join(format!("{project}_{}_SHA256SUMS.sig", tag.version()));
                    append_signed_assets(&mut expected, &assets, &sums, &sig)?;
                    validate_signed_provider_assets_for_project(&assets, &expected, &project)?;
                } else {
                    for name in [
                        format!("{project}_{}_SHA256SUMS", tag.version()),
                        format!("{project}_{}_SHA256SUMS.sig", tag.version()),
                    ] {
                        let path = assets.join(&name);
                        expected.assets.push(PlannedAsset {
                            name,
                            sha256: sha256_file(&path)?,
                            size: None,
                        });
                    }
                }
                let mut existing: Vec<Value> = api.paginate(&format!(
                    "/repos/{}/releases/{release_id}/assets",
                    repo.as_str()
                ))?;
                validate_release_asset_state(&expected.assets, &existing, false)?;
                let names: Vec<String> = if phase == "stage-draft" {
                    expected
                        .assets
                        .iter()
                        .filter(|asset| {
                            asset.name.ends_with("SHA256SUMS")
                                || asset.name.ends_with("SHA256SUMS.sig")
                        })
                        .map(|asset| asset.name.clone())
                        .collect()
                } else {
                    expected
                        .assets
                        .iter()
                        .map(|asset| asset.name.clone())
                        .collect()
                };
                for name in names {
                    if existing.iter().any(|asset| asset["name"] == name) {
                        continue;
                    }
                    let path = assets.join(&name);
                    let url = format!(
                        "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
                        repo.as_str(),
                        url_encode(&name)
                    );
                    api.upload(&url, std::fs::read(path)?, "application/octet-stream")?;
                }
                existing = api.paginate(&format!(
                    "/repos/{}/releases/{release_id}/assets",
                    repo.as_str()
                ))?;
                validate_release_asset_state(
                    &expected.assets,
                    &existing,
                    phase == "complete-draft",
                )?;
                if phase == "complete-draft" {
                    let snapshot = existing
                        .iter()
                        .map(|asset| {
                            Ok((
                                asset["name"]
                                    .as_str()
                                    .context("release asset lacks name")?
                                    .to_owned(),
                                json!({"id":asset["id"],"digest":asset["digest"]}),
                            ))
                        })
                        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
                    let snapshot_path = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_STATE_DIR")?)
                        .join("uploaded-assets.json");
                    if snapshot_path.exists() {
                        let previous: Value =
                            serde_json::from_slice(&std::fs::read(&snapshot_path)?)?;
                        ensure!(
                            serde_json::to_value(&snapshot)? == previous,
                            "scratch draft asset IDs or digests changed after completion"
                        );
                    } else {
                        write_json(&snapshot_path, &serde_json::to_value(&snapshot)?)?;
                    }
                }
                crate::output("release_id", release_id.to_string())?;
                crate::output("tag", tag.as_str())?;
            }
            "recover-sign" => {
                let fingerprint = env("GPG_FINGERPRINT")?;
                ensure!(
                    fingerprint == env("SECUREFIX_PROVIDER_PROBE_EXPECTED_GPG_FINGERPRINT")?,
                    "signing key differs from configured Registry key"
                );
                let passphrase = std::env::var("GPG_PASSPHRASE").unwrap_or_default();
                let recovery = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_RECOVERY_DIR")?);
                let receipt: Value =
                    serde_json::from_slice(&std::fs::read(recovery.join("receipt.json"))?)?;
                ensure!(
                    receipt["release_id"].as_u64() == Some(probe_release_id()?),
                    "recovery receipt release ID mismatch"
                );
                ensure!(
                    receipt["tag"] == tag.as_str(),
                    "recovery receipt tag mismatch"
                );
                let plan = probe_plan(&assets, &project, tag.clone())?;
                let sums = canonical_provider_sums(&assets, &plan.assets)?;
                let digest = receipt["sha256"]
                    .as_str()
                    .context("receipt lacks signature digest")?;
                let sums_path = assets.join(format!("{project}_{}_SHA256SUMS", tag.version()));
                std::fs::write(&sums_path, sums)?;
                let signature_path =
                    assets.join(format!("{project}_{}_SHA256SUMS.sig", tag.version()));
                let recovered = recovery.join("existing-signature.sig");
                ensure!(
                    sha256_file(&recovered)? == digest,
                    "recovery artifact digest mismatch"
                );
                reuse_or_sign_checksum(
                    &sums_path,
                    &signature_path,
                    &recovered,
                    Some(digest),
                    &fingerprint,
                    &passphrase,
                    None,
                )?;
                ensure!(
                    std::fs::read(&signature_path)? == std::fs::read(&recovered)?,
                    "recovered signature bytes changed"
                );
                verify_checksum_signature(&signature_path, &sums_path, &fingerprint, None)?;
            }
            "verify-draft" => {
                let repo_name = env("SECUREFIX_PROVIDER_PROBE_REPOSITORY")?;
                ensure!(
                    repo_name == crate::config::trusted()?.deployment.integration.repository,
                    "provider probe repository is not the trusted integration repository"
                );
                let repo = Repository::parse(&repo_name)?;
                let release_id = probe_release_id()?;
                let api = GitHub::new("https://api.github.com", env("GH_TOKEN")?)?;
                let release: Value =
                    api.get(&format!("/repos/{}/releases/{release_id}", repo.as_str()))?;
                ensure!(
                    release["id"].as_u64() == Some(release_id)
                        && release["draft"] == true
                        && release["tag_name"] == tag.as_str(),
                    "probe target is not the expected draft release"
                );
                write_probe_receipt(release_id, tag.as_str(), &probe_target_sha()?)?;
                crate::output("release_id", release_id.to_string())?;
                let existing: Vec<Value> = api.paginate(&format!(
                    "/repos/{}/releases/{release_id}/assets",
                    repo.as_str()
                ))?;
                let mut plan = probe_plan(&assets, &project, tag)?;
                for entry in std::fs::read_dir(&assets)? {
                    let path = entry?.path();
                    let name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("invalid asset name")?
                        .to_owned();
                    if name.ends_with("SHA256SUMS") || name.ends_with("SHA256SUMS.sig") {
                        plan.assets.push(PlannedAsset {
                            name,
                            sha256: sha256_file(&path)?,
                            size: None,
                        });
                    }
                }
                validate_signed_provider_assets_for_project(&assets, &plan, &project)?;
                validate_release_asset_state(&plan.assets, &existing, true)?;
                let state = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_STATE_DIR")?);
                let import = ProcessCommand::new("gpg")
                    .arg("--batch")
                    .arg("--import")
                    .arg(state.join("public-key.asc"))
                    .output()
                    .context("import public provider signing key")?;
                ensure!(
                    import.status.success(),
                    "could not import public provider signing key"
                );
                let fingerprint = env("SECUREFIX_PROVIDER_PROBE_EXPECTED_GPG_FINGERPRINT")?;
                ensure!(
                    fingerprint == env("GPG_FINGERPRINT")?,
                    "verification key differs from configured Registry key"
                );
                verify_checksum_signature(
                    &assets.join(format!("{project}_{}_SHA256SUMS.sig", plan.tag.version())),
                    &assets.join(format!("{project}_{}_SHA256SUMS", plan.tag.version())),
                    &fingerprint,
                    None,
                )?;
            }
            "cleanup-draft" => {
                let repo_name = env("SECUREFIX_PROVIDER_PROBE_REPOSITORY")?;
                ensure!(
                    repo_name == crate::config::trusted()?.deployment.integration.repository,
                    "provider probe repository is not the trusted integration repository"
                );
                let release_id = probe_release_id()?;
                let (api, repo) = probe_write_api()?;
                let release_path = format!("/repos/{}/releases/{release_id}", repo.as_str());
                let ref_path = format!(
                    "/repos/{}/git/ref/tags/{}",
                    repo.as_str(),
                    url_encode(tag.as_str())
                );
                let receipt = load_probe_receipt()?;
                ensure!(
                    receipt["tag"] == tag.as_str(),
                    "cleanup receipt tag mismatch"
                );
                ensure!(
                    receipt["release_id"].as_u64() == Some(release_id),
                    "cleanup receipt release ID mismatch"
                );
                let recorded_target = receipt["target_sha"]
                    .as_str()
                    .context("cleanup receipt lacks target SHA")?;
                crate::policy::validate_sha(recorded_target)?;
                if let Ok(expected_target) =
                    std::env::var("SECUREFIX_PROVIDER_PROBE_EXPECTED_TARGET_SHA")
                {
                    ensure!(
                        recorded_target == expected_target,
                        "cleanup target SHA differs from recorded workflow output"
                    );
                }
                let tag_exists = !probe_not_found(&api, &ref_path)?;
                if tag_exists {
                    ensure!(
                        probe_tag_points_to_commit(&api, &repo, tag.as_str(), recorded_target)?,
                        "scratch tag differs from receipt target; refusing cleanup"
                    );
                }
                if !probe_not_found(&api, &release_path)? {
                    let release: Value = api.get(&release_path)?;
                    ensure!(
                        release["id"].as_u64() == Some(release_id)
                            && release["draft"] == true
                            && release["tag_name"] == tag.as_str(),
                        "refusing to delete a non-matching draft"
                    );
                    api.delete(&release_path)?;
                }
                if tag_exists && !probe_not_found(&api, &ref_path)? {
                    ensure!(
                        probe_tag_points_to_commit(&api, &repo, tag.as_str(), recorded_target)?,
                        "scratch tag changed during cleanup; refusing deletion"
                    );
                    api.delete(&format!(
                        "/repos/{}/git/refs/tags/{}",
                        repo.as_str(),
                        url_encode(tag.as_str())
                    ))?;
                }
                ensure!(
                    probe_not_found(&api, &release_path)?,
                    "scratch release still exists after cleanup"
                );
                ensure!(
                    probe_not_found(&api, &ref_path)?,
                    "scratch tag exists after cleanup"
                );
            }
            _ => bail!("unsupported provider probe phase"),
        }
        Ok(())
    }

    const NATIVE_PROBE_CLIENT_REPOSITORY: &str = "civitaspo/herdr-linear-agent";
    const NATIVE_PROBE_CLIENT_SHA: &str = "ccdaada3efa78ebdef58f2db38aaf6ec5a8c8e00";

    struct NativeProbeInputs {
        client_repository: Repository,
        client_sha: CommitSha,
        client_pr_number: u64,
        package_version: String,
        harness_sha: CommitSha,
        server_sha: CommitSha,
        run_id: RunId,
        run_attempt: u64,
        targets: Vec<crate::policy::NativeBinaryTarget>,
        artifacts: Vec<Value>,
        manifest: NativeAssetManifest,
        asset_paths: std::collections::BTreeMap<String, PathBuf>,
    }

    #[test]
    #[ignore = "requires isolated native release probe workflow and read-only artifact access"]
    fn native_release_assets_validate_probe_inputs() {
        let inputs = native_probe_inputs().unwrap();
        let output = PathBuf::from(env("SECUREFIX_NATIVE_RELEASE_PROBE_OUTPUT_DIR").unwrap());
        std::fs::create_dir_all(&output).unwrap();
        let evidence = native_probe_input_evidence(&inputs).unwrap();
        write_json(output.join("native-release-assets-inputs.json"), &evidence).unwrap();
    }

    // The frozen release rehearsal verifies the exact native artifacts from
    // this workflow run, then feeds those same bytes through the trusted
    // scratch release writer and immutable-state reread.
    #[test]
    #[ignore = "requires isolated native release probe workflow and scratch token"]
    fn native_release_assets_scratch_publish_probe() {
        native_release_assets_scratch_publish_probe_inner().unwrap();
    }

    #[test]
    #[ignore = "requires local active-control and candidate-policy fixtures"]
    fn native_release_assets_scratch_write_context_preflight() {
        use crate::fixtures::{Fixture, Route};

        let control: crate::control::ControlRevision = serde_json::from_slice(
            &std::fs::read(env("SECUREFIX_NATIVE_RELEASE_PROBE_CONTROL_PATH").unwrap()).unwrap(),
        )
        .unwrap();
        let active_policy = crate::config::trusted_policy_bytes().unwrap();
        use sha2::Digest;
        assert_eq!(
            control.policy_sha256,
            crate::hex_encode(sha2::Sha256::digest(active_policy))
        );
        assert_eq!(
            env("GITHUB_REPOSITORY").unwrap(),
            "civitaspo/securefix-server"
        );
        let server_sha =
            CommitSha::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA").unwrap()).unwrap();
        let harness_sha =
            CommitSha::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA").unwrap()).unwrap();
        assert_eq!(harness_sha.as_str(), env("GITHUB_SHA").unwrap());
        assert!(server_sha.as_str() != harness_sha.as_str());
        assert_eq!(
            env("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT").unwrap(),
            "1"
        );

        let candidate_policy = crate::policy::Policy::load(
            env("SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH").unwrap(),
        )
        .unwrap();
        assert_eq!(
            candidate_policy
                .repository(NATIVE_PROBE_CLIENT_REPOSITORY)
                .unwrap()
                .native_binaries
                .len(),
            4
        );

        let repo_name = env("SECUREFIX_NATIVE_RELEASE_PROBE_REPOSITORY").unwrap();
        assert_eq!(
            repo_name,
            crate::config::trusted()
                .unwrap()
                .deployment
                .integration
                .repository
        );
        let repo = Repository::parse(&repo_name).unwrap();
        let run_id = env("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(run_id > 0);
        let tag = ReleaseTag::parse(&format!("v0.8.1-pre.{run_id}.missing")).unwrap();
        let tag_path = format!(
            "/repos/{}/git/ref/tags/{}",
            repo.as_str(),
            url_encode(tag.as_str())
        );
        let tag_release_path = format!(
            "/repos/{}/releases/tags/{}",
            repo.as_str(),
            url_encode(tag.as_str())
        );
        let release_list_path = format!("/repos/{}/releases?per_page=100&page=1", repo.as_str());
        let release_path = format!("/repos/{}/releases", repo.as_str());
        let target_sha = "c".repeat(40);
        let expected_body = json!({
            "tag_name":tag.as_str(),
            "target_commitish":target_sha,
            "name":tag.as_str(),
            "draft":true,
            "prerelease":true,
            "generate_release_notes":false,
        });
        let fixture = Fixture::new(vec![
            Route::request("GET", tag_path, 404, json!({})),
            Route::request("GET", tag_release_path, 404, json!({})),
            Route::get(release_list_path, json!([])),
            Route::active_control(&control),
            Route::request(
                "POST",
                release_path,
                201,
                json!({
                    "id": 9001,
                    "tag_name":tag.as_str(),
                    "draft":true,
                    "prerelease":true,
                }),
            )
            .with_request_body(expected_body),
            Route::get(
                format!(
                    "/repos/{}/git/ref/tags/{}",
                    repo.as_str(),
                    url_encode(tag.as_str())
                ),
                json!({"object":{"type":"commit","sha":target_sha}}),
            ),
        ]);
        let api = GitHub::new(&fixture.base, "fixture-token".into())
            .unwrap()
            .with_control_revision(&control)
            .unwrap();
        assert_eq!(
            create_native_probe_draft(&api, &repo, &tag, &target_sha).unwrap(),
            9001
        );
        fixture.finish();
    }

    #[test]
    fn native_probe_draft_binds_tag_to_exact_scratch_target() {
        use crate::fixtures::{Fixture, Route};

        let check_target = |tag_target_sha: &str, expected_success: bool| {
            let repo = Repository::parse("civitaspo/testing-securefix-server").unwrap();
            let tag = ReleaseTag::parse("v0.8.1-pre.39728542160.native").unwrap();
            let tag_path = format!(
                "/repos/{}/git/ref/tags/{}",
                repo.as_str(),
                url_encode(tag.as_str())
            );
            let tag_release_path = format!(
                "/repos/{}/releases/tags/{}",
                repo.as_str(),
                url_encode(tag.as_str())
            );
            let release_list_path =
                format!("/repos/{}/releases?per_page=100&page=1", repo.as_str());
            let release_path = format!("/repos/{}/releases", repo.as_str());
            let target_sha = "c".repeat(40);
            let control = Fixture::control_revision();
            let fixture = Fixture::new(vec![
                Route::request("GET", &tag_path, 404, json!({})),
                Route::request("GET", tag_release_path, 404, json!({})),
                Route::get(release_list_path, json!([])),
                Route::active_control(&control),
                Route::request(
                    "POST",
                    release_path,
                    201,
                    json!({
                        "id": 9001,
                        "tag_name": tag.as_str(),
                        "draft": true,
                        "prerelease": true,
                    }),
                )
                .with_request_body(json!({
                    "tag_name": tag.as_str(),
                    "target_commitish": target_sha,
                    "name": tag.as_str(),
                    "draft": true,
                    "prerelease": true,
                    "generate_release_notes": false,
                })),
                Route::get(
                    &tag_path,
                    json!({"object":{"type":"commit","sha":tag_target_sha}}),
                ),
            ]);
            let api = GitHub::new(&fixture.base, "fixture-token".into())
                .unwrap()
                .with_control_revision(&control)
                .unwrap();
            let result = create_native_probe_draft(&api, &repo, &tag, &target_sha);
            if expected_success {
                assert_eq!(result.unwrap(), 9001);
            } else {
                assert!(result.is_err(), "mismatched tag target was accepted");
            }
            fixture.finish();
        };

        let target_sha = "c".repeat(40);
        let other_sha = "d".repeat(40);
        check_target(&target_sha, true);
        check_target(&other_sha, false);
    }

    #[test]
    #[ignore = "requires exact saved native artifacts, policy fixtures, and read-only GitHub access"]
    fn native_release_assets_scratch_publish_probe_fixture() {
        use crate::fixtures::{Fixture, Route};

        let inputs = native_probe_inputs().unwrap();
        let repo =
            Repository::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_REPOSITORY").unwrap()).unwrap();
        let scratch_sha = probe_scratch_target_sha(&repo).unwrap();
        let missing_tag = ReleaseTag::parse(&format!(
            "v{}-pre.{}.missing",
            inputs.package_version, inputs.run_id.0
        ))
        .unwrap();
        let success_tag = ReleaseTag::parse(&format!(
            "v{}-pre.{}.native",
            inputs.package_version, inputs.run_id.0
        ))
        .unwrap();
        let control = Fixture::control_revision();
        let releases_path = format!("/repos/{}/releases", repo.as_str());
        let mut routes = Vec::new();
        let push_draft_routes = |routes: &mut Vec<Route>, tag: &ReleaseTag, release_id| {
            let ref_path = format!(
                "/repos/{}/git/ref/tags/{}",
                repo.as_str(),
                url_encode(tag.as_str())
            );
            routes.push(Route::request("GET", &ref_path, 404, json!({})));
            routes.push(Route::request(
                "GET",
                format!(
                    "/repos/{}/releases/tags/{}",
                    repo.as_str(),
                    url_encode(tag.as_str())
                ),
                404,
                json!({}),
            ));
            routes.push(Route::get(
                format!("{releases_path}?per_page=100&page=1"),
                json!([]),
            ));
            routes.push(Route::active_control(&control));
            let body = json!({
                "tag_name": tag.as_str(),
                "target_commitish": scratch_sha,
                "name": tag.as_str(),
                "draft": true,
                "prerelease": true,
                "generate_release_notes": false,
            });
            routes.push(
                Route::request(
                    "POST",
                    &releases_path,
                    201,
                    json!({
                        "id": release_id,
                        "tag_name": tag.as_str(),
                        "draft": true,
                        "prerelease": true,
                    }),
                )
                .with_request_body(body),
            );
            routes.push(Route::get(
                &ref_path,
                json!({"object":{"type":"commit","sha":scratch_sha}}),
            ));
        };
        push_draft_routes(&mut routes, &missing_tag, 9001);

        let missing_release_path = format!("{releases_path}/9001");
        let missing_release = json!({
            "id": 9001,
            "tag_name": missing_tag.as_str(),
            "draft": true,
            "prerelease": true,
        });
        routes.push(Route::get(&missing_release_path, missing_release.clone()));
        routes.push(Route::get(
            format!("{missing_release_path}/assets?per_page=100&page=1"),
            json!([]),
        ));
        routes.push(Route::get(&missing_release_path, missing_release));
        routes.push(Route::get(
            &missing_release_path,
            json!({
                "id": 9001,
                "tag_name": missing_tag.as_str(),
                "draft": true,
                "prerelease": true,
            }),
        ));
        routes.push(Route::active_control(&control));
        routes.push(Route::request(
            "DELETE",
            &missing_release_path,
            204,
            json!({}),
        ));
        let missing_ref_path = format!(
            "/repos/{}/git/ref/tags/{}",
            repo.as_str(),
            url_encode(missing_tag.as_str())
        );
        let tag_ref = json!({"object":{"type":"commit","sha":scratch_sha}});
        routes.push(Route::get(&missing_ref_path, tag_ref.clone()));
        routes.push(Route::get(&missing_ref_path, tag_ref.clone()));
        routes.push(Route::active_control(&control));
        routes.push(Route::request(
            "DELETE",
            format!(
                "/repos/{}/git/refs/tags/{}",
                repo.as_str(),
                url_encode(missing_tag.as_str())
            ),
            204,
            json!({}),
        ));
        routes.push(Route::request("GET", &missing_release_path, 404, json!({})));
        routes.push(Route::request("GET", &missing_ref_path, 404, json!({})));

        push_draft_routes(&mut routes, &success_tag, 9002);
        let success_release_path = format!("{releases_path}/9002");
        let success_release = json!({
            "id": 9002,
            "tag_name": success_tag.as_str(),
            "draft": true,
            "prerelease": true,
        });
        let published_release = json!({
            "id": 9002,
            "tag_name": success_tag.as_str(),
            "draft": false,
            "prerelease": true,
            "immutable": true,
        });
        let published_assets: Vec<_> = inputs
            .manifest
            .assets
            .iter()
            .enumerate()
            .map(|(index, asset)| {
                json!({
                    "id": 9100 + index as u64,
                    "name": asset.filename,
                    "size": asset.size,
                    "digest": format!("sha256:{}", asset.sha256),
                })
            })
            .collect();
        routes.push(Route::get(&success_release_path, success_release.clone()));
        routes.push(Route::get(
            format!("{success_release_path}/assets?per_page=100&page=1"),
            json!([]),
        ));
        routes.push(Route::get(
            format!("{success_release_path}/assets?per_page=100&page=1"),
            json!(published_assets.clone()),
        ));
        routes.push(Route::get(
            format!("{success_release_path}/assets?per_page=100&page=1"),
            json!(published_assets.clone()),
        ));
        routes.push(Route::get(&success_release_path, success_release.clone()));
        routes.push(Route::active_control(&control));
        routes.push(
            Route::request(
                "PATCH",
                &success_release_path,
                200,
                published_release.clone(),
            )
            .with_request_body(json!({"draft":false})),
        );
        routes.push(Route::get(&success_release_path, published_release.clone()));
        routes.push(Route::get(
            format!("{success_release_path}/assets?per_page=100&page=1"),
            json!(published_assets.clone()),
        ));
        routes.push(Route::get(&success_release_path, published_release.clone()));
        routes.push(Route::get(
            format!("{success_release_path}/assets?per_page=100&page=1"),
            json!(published_assets.clone()),
        ));
        routes.push(Route::get(&success_release_path, published_release.clone()));
        routes.push(Route::get(&success_release_path, published_release));
        let success_ref_path = format!(
            "/repos/{}/git/ref/tags/{}",
            repo.as_str(),
            url_encode(success_tag.as_str())
        );
        routes.push(Route::get(&success_ref_path, tag_ref));

        let fixture = Fixture::new(routes);
        let api = GitHub::new(&fixture.base, "fixture-token".into())
            .unwrap()
            .with_control_revision(&control)
            .unwrap();
        let work = PathBuf::from(env("SECUREFIX_NATIVE_RELEASE_PROBE_ASSET_DIR").unwrap());
        let mut uploaded = BTreeSet::new();
        let mut upload = |_: &GitHub, path: &str, bytes: Vec<u8>, content_type: &str| {
            assert_eq!(content_type, "application/octet-stream");
            let name = path.split_once("?name=").unwrap().1;
            let asset = inputs
                .manifest
                .assets
                .iter()
                .find(|asset| url_encode(&asset.filename) == name)
                .unwrap();
            assert_eq!(bytes.len() as u64, asset.size);
            assert_eq!(crate::hex_encode(Sha256::digest(&bytes)), asset.sha256);
            assert!(uploaded.insert(asset.filename.clone()));
            Ok(json!({"name":asset.filename,"size":asset.size}))
        };
        native_release_assets_scratch_publish_probe_with_inputs(
            &inputs,
            &api,
            &repo,
            &scratch_sha,
            &work,
            &mut upload,
        )
        .unwrap();
        assert_eq!(uploaded.len(), inputs.targets.len());
        fixture.finish();
    }

    fn native_release_assets_scratch_publish_probe_inner() -> Result<()> {
        let inputs = native_probe_inputs().context("validate exact native probe inputs")?;
        let repo_name = env("SECUREFIX_NATIVE_RELEASE_PROBE_REPOSITORY")?;
        let (api, repo) = probe_scratch_write_api(&repo_name, "SECUREFIX_SERVER_APP_TOKEN")
            .context("load scratch-scoped release writer")?;
        let scratch_sha =
            probe_scratch_target_sha(&repo).context("read scratch default-branch SHA")?;
        let work = PathBuf::from(env("SECUREFIX_NATIVE_RELEASE_PROBE_ASSET_DIR")?);
        let mut upload = |api: &GitHub, path: &str, bytes: Vec<u8>, content_type: &str| {
            api.upload(path, bytes, content_type)
        };
        native_release_assets_scratch_publish_probe_with_inputs(
            &inputs,
            &api,
            &repo,
            &scratch_sha,
            &work,
            &mut upload,
        )
    }

    fn native_release_assets_scratch_publish_probe_with_inputs<F>(
        inputs: &NativeProbeInputs,
        api: &GitHub,
        repo: &Repository,
        scratch_sha: &str,
        work: &Path,
        upload: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&GitHub, &str, Vec<u8>, &str) -> Result<Value>,
    {
        let candidate_sha = inputs.harness_sha.as_str().to_owned();
        let run_component = inputs.run_id.0;
        let missing_tag = ReleaseTag::parse(&format!(
            "v{}-pre.{run_component}.missing",
            inputs.package_version
        ))?;
        let success_tag = ReleaseTag::parse(&format!(
            "v{}-pre.{run_component}.native",
            inputs.package_version
        ))?;
        if work.exists() {
            std::fs::remove_dir_all(work).with_context(|| {
                format!("remove native probe asset workspace {}", work.display())
            })?;
        }
        std::fs::create_dir_all(work)
            .with_context(|| format!("create native probe asset workspace {}", work.display()))?;
        let mut drafts = Vec::new();

        let result = (|| -> Result<Value> {
            let mut incomplete = native_probe_manifest(inputs, missing_tag.clone());
            incomplete.assets.pop();
            let missing_bundle = native_probe_bundle(&incomplete, &inputs.asset_paths)
                .context("bundle the incomplete native target set")?;
            let missing_id = create_native_probe_draft(api, repo, &missing_tag, scratch_sha)
                .context("create incomplete native probe draft")?;
            drafts.push((missing_id, missing_tag.clone()));
            let rejected = work.join("missing-artifact");
            std::fs::create_dir_all(&rejected).with_context(|| {
                format!(
                    "create incomplete artifact directory {}",
                    rejected.display()
                )
            })?;
            ensure!(
                unpack_native_bundle(
                    &missing_bundle,
                    &rejected,
                    &inputs.client_repository,
                    &inputs.targets
                )
                .with_context(|| format!(
                    "unpack incomplete native bundle into {}",
                    rejected.display()
                ))
                .is_err(),
                "incomplete native target set was accepted"
            );
            let missing_release: Value = api
                .get(&format!("/repos/{}/releases/{missing_id}", repo.as_str()))
                .context("read incomplete native probe draft")?;
            let missing_assets: Vec<Value> = api
                .paginate(&format!(
                    "/repos/{}/releases/{missing_id}/assets",
                    repo.as_str()
                ))
                .context("read incomplete native probe draft assets")?;
            ensure!(
                missing_release["draft"] == true && missing_assets.is_empty(),
                "incomplete native target set reached release publication"
            );
            cleanup_native_probe_draft(api, repo, missing_id, &missing_tag, scratch_sha)
                .context("remove incomplete native probe draft")?;
            drafts.retain(|(id, _)| *id != missing_id);

            let manifest = native_probe_manifest(inputs, success_tag.clone());
            let bundle = native_probe_bundle(&manifest, &inputs.asset_paths)
                .context("bundle the complete native target set")?;
            let assets_dir = work.join("publish-assets");
            if assets_dir.exists() {
                std::fs::remove_dir_all(&assets_dir).with_context(|| {
                    format!(
                        "remove native publish asset directory {}",
                        assets_dir.display()
                    )
                })?;
            }
            std::fs::create_dir_all(&assets_dir).with_context(|| {
                format!(
                    "create native publish asset directory {}",
                    assets_dir.display()
                )
            })?;
            unpack_native_bundle(
                &bundle,
                &assets_dir,
                &inputs.client_repository,
                &inputs.targets,
            )
            .with_context(|| {
                format!(
                    "unpack complete native bundle into {}",
                    assets_dir.display()
                )
            })?;
            let decoded: NativeAssetManifest = serde_json::from_slice(
                &std::fs::read(assets_dir.join(NATIVE_BUNDLE_MANIFEST)).with_context(|| {
                    format!("read native bundle manifest from {}", assets_dir.display())
                })?,
            )?;
            let source_manifest = native_probe_source_manifest(inputs, success_tag.clone());
            validate_native_manifest(
                &decoded,
                &inputs.client_repository,
                &inputs.targets,
                &source_manifest,
            )?;
            validate_native_asset_files(&assets_dir, &decoded).with_context(|| {
                format!(
                    "validate extracted native assets in {}",
                    assets_dir.display()
                )
            })?;
            let release_id = create_native_probe_draft(api, repo, &success_tag, scratch_sha)
                .context("create complete native probe draft")?;
            drafts.push((release_id, success_tag.clone()));
            let assets = decoded
                .assets
                .iter()
                .map(|asset| PlannedAsset {
                    name: asset.filename.clone(),
                    sha256: asset.sha256.clone(),
                    size: Some(asset.size),
                })
                .collect();
            let plan = ReleasePlanV2 {
                schema_version: 2,
                server_revision: candidate_sha.clone(),
                instance_authority: None,
                source_manifest_sha256: None,
                release_pr_head_sha: None,
                client_package: None,
                repository: repo.as_str().to_owned(),
                strategy: ReleaseStrategy::GithubRelease,
                source_run_id: inputs.run_id,
                source_run_attempt: inputs.run_attempt,
                source_revision: inputs.server_sha.as_str().to_owned(),
                release_pr_number: source_manifest.release_pr_number,
                release_pr_sha: source_manifest.release_pr_sha.as_str().to_owned(),
                tag: success_tag.clone(),
                source_manifest,
                native_binary_repository: Some(inputs.client_repository.as_str().to_owned()),
                release_id: Some(release_id),
                existing_signature_sha256: None,
                assets,
                native_assets: decoded.assets.clone(),
            };
            plan.validate()?;
            publish_release_assets_with_upload(api, repo, release_id, &plan, &assets_dir, upload)
                .with_context(|| {
                format!("publish native probe assets from {}", assets_dir.display())
            })?;
            let published: Value = api
                .get(&format!("/repos/{}/releases/{release_id}", repo.as_str()))
                .context("reread published native probe release")?;
            ensure_published_immutable_release(&published, release_id, &success_tag)?;
            ensure!(
                published["prerelease"] == true,
                "native scratch release is not a prerelease"
            );
            let published_assets: Vec<Value> = api
                .paginate(&format!(
                    "/repos/{}/releases/{release_id}/assets",
                    repo.as_str()
                ))
                .context("reread published native probe assets")?;
            validate_release_asset_state(&plan.assets, &published_assets, true)?;
            let assets = published_assets
                .iter()
                .map(|asset| {
                    Ok(json!({
                        "id": asset["id"].as_u64().context("published native asset lacks ID")?,
                        "name": asset["name"].as_str().context("published native asset lacks name")?,
                        "digest": asset["digest"].as_str().context("published native asset lacks digest")?,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({
                "schema_version": 1,
                "candidate_sha": candidate_sha,
                "scratch_repository": repo.as_str(),
                "target_commit": scratch_sha,
                "rejected_incomplete_artifact": {
                    "tag": missing_tag.as_str(),
                    "release_id": missing_id,
                    "draft_after_rejection": true,
                    "published_assets": 0,
                    "draft_deleted": true,
                },
                "published_prerelease": {
                    "tag": success_tag.as_str(),
                    "release_id": release_id,
                    "draft": false,
                    "immutable": true,
                    "assets": assets,
                },
                "source": native_probe_input_evidence(inputs)?,
            }))
        })();

        let cleanup = drafts.iter().try_for_each(|(release_id, tag)| {
            cleanup_native_probe_draft(api, repo, *release_id, tag, scratch_sha)
        });
        cleanup?;
        let evidence = result?;
        let output = PathBuf::from(env("SECUREFIX_NATIVE_RELEASE_PROBE_OUTPUT_DIR")?);
        std::fs::create_dir_all(&output).with_context(|| {
            format!(
                "create native probe evidence directory {}",
                output.display()
            )
        })?;
        write_json(output.join("native-release-assets-probe.json"), &evidence)
            .with_context(|| format!("write native probe evidence in {}", output.display()))?;
        crate::output("scratch_repository", repo.as_str())?;
        crate::output("published_prerelease", success_tag.as_str())?;
        crate::output(
            "published_release_id",
            evidence["published_prerelease"]["release_id"]
                .as_u64()
                .context("probe evidence lacks published release ID")?
                .to_string(),
        )?;
        Ok(())
    }

    fn native_probe_inputs() -> Result<NativeProbeInputs> {
        let source_repository = Repository::parse(NATIVE_PROBE_CLIENT_REPOSITORY)?;
        let client_sha = CommitSha::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_CLIENT_SHA")?)?;
        ensure!(
            client_sha.as_str() == NATIVE_PROBE_CLIENT_SHA,
            "native release probe Client source SHA differs from the reviewed pin"
        );
        let server_sha = CommitSha::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA")?)?;
        let harness_sha = CommitSha::parse(&env("SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA")?)?;
        let run_id = RunId(env("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID")?.parse()?);
        let run_attempt =
            env("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT")?.parse::<u64>()?;
        ensure!(
            run_id.0 > 0 && run_attempt == 1,
            "native release probe run identity is invalid"
        );

        let read_api = GitHub::new("https://api.github.com", env("GITHUB_TOKEN")?)?;
        let commit: Value = read_api.get(&format!(
            "/repos/{}/commits/{}",
            source_repository.as_str(),
            client_sha.as_str()
        ))?;
        ensure!(
            commit["sha"] == client_sha.as_str()
                && commit["commit"]["verification"]["verified"] == true,
            "native release probe Client source is not the pinned verified commit"
        );
        let package_version = String::from_utf8(read_api.content(
            source_repository.as_str(),
            ".release-version",
            client_sha.as_str(),
        )?)?
        .trim()
        .to_owned();
        Version::parse(&package_version).context("Client source package version is invalid")?;
        let source_prs = read_api.paginate(&format!(
            "/repos/{}/commits/{}/pulls",
            source_repository.as_str(),
            client_sha.as_str()
        ))?;
        let source_prs: Vec<_> = source_prs
            .into_iter()
            .filter(|pr| {
                pr["state"] == "closed"
                    && pr["merged_at"].is_string()
                    && pr["merge_commit_sha"] == client_sha.as_str()
            })
            .collect();
        ensure!(
            source_prs.len() == 1,
            "pinned Client source does not identify exactly one merged PR"
        );
        let client_pr_number = source_prs[0]["number"]
            .as_u64()
            .context("pinned Client source PR lacks a number")?;
        ensure!(
            client_pr_number > 0,
            "pinned Client source PR number is invalid"
        );

        let policy =
            crate::policy::Policy::load(env("SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH")?)?;
        let targets = policy
            .repository(source_repository.as_str())?
            .native_binaries
            .clone();
        ensure!(
            targets.len() == 4,
            "native release probe policy does not contain exactly four Client targets"
        );
        let expected_artifacts: BTreeSet<_> = targets
            .iter()
            .map(|target| format!("native-target-{}-{run_attempt}", target.target))
            .collect();
        let artifact_list: ArtifactList = read_api.get(&format!(
            "/repos/{}/actions/runs/{}/artifacts?per_page=100",
            env("GITHUB_REPOSITORY")?,
            run_id.0
        ))?;
        let native_artifacts: Vec<_> = artifact_list
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact["name"].as_str().is_some_and(|name| {
                    name.starts_with("native-target-") && name.ends_with(&format!("-{run_attempt}"))
                })
            })
            .cloned()
            .collect();
        let actual_artifacts: BTreeSet<_> = native_artifacts
            .iter()
            .map(|artifact| {
                artifact["name"]
                    .as_str()
                    .context("native target artifact lacks name")
                    .map(str::to_owned)
            })
            .collect::<Result<_>>()?;
        ensure!(
            actual_artifacts == expected_artifacts && native_artifacts.len() == targets.len(),
            "current run does not contain the exact native target artifact set"
        );
        let mut artifact_ids = BTreeSet::new();
        let mut artifact_bytes = 0_u64;
        for artifact in &native_artifacts {
            ensure!(
                artifact["expired"] == false,
                "native target artifact is expired"
            );
            let artifact_id = artifact["id"]
                .as_u64()
                .context("native target artifact lacks ID")?;
            ensure!(
                artifact_ids.insert(artifact_id),
                "duplicate native target artifact ID"
            );
            let size = artifact["size_in_bytes"]
                .as_u64()
                .context("native target artifact lacks size")?;
            ensure!(size > 0, "native target artifact is empty");
            artifact_bytes = artifact_bytes.saturating_add(size);
            ensure!(
                artifact_bytes <= MAX_NATIVE_BUNDLE_BYTES,
                "native target artifacts exceed the size limit"
            );
            let digest = artifact["digest"]
                .as_str()
                .context("native target artifact lacks a digest")?;
            ensure!(
                digest.starts_with("sha256:")
                    && digest.len() == 71
                    && digest[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "native target artifact digest is invalid"
            );
        }

        let input_dir = PathBuf::from(env("SECUREFIX_NATIVE_RELEASE_PROBE_INPUT_DIR")?);
        let expected_directories: BTreeSet<_> = expected_artifacts.clone();
        let mut actual_directories = BTreeSet::new();
        let mut assets = Vec::with_capacity(targets.len());
        let mut asset_paths = std::collections::BTreeMap::new();
        let mut native_artifact_evidence = std::collections::BTreeMap::new();
        let mut total_size = 0_u64;
        for entry in
            std::fs::read_dir(&input_dir).context("native target artifact inputs are missing")?
        {
            let directory = entry?.path();
            let directory_metadata = std::fs::symlink_metadata(&directory)?;
            ensure!(
                directory_metadata.file_type().is_dir()
                    && !directory_metadata.file_type().is_symlink(),
                "native target artifact is not a regular directory"
            );
            let directory_name = directory
                .file_name()
                .and_then(|name| name.to_str())
                .context("native artifact directory name is invalid")?
                .to_owned();
            ensure!(
                actual_directories.insert(directory_name.clone()),
                "duplicate native artifact directory"
            );
            let metadata_path = directory.join(NATIVE_TARGET_MANIFEST);
            let metadata = std::fs::symlink_metadata(&metadata_path)?;
            ensure!(
                metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() > 0
                    && metadata.len() <= 1024 * 1024,
                "native artifact metadata has invalid size or type"
            );
            let build: NativeTargetEvidence =
                serde_json::from_slice(&std::fs::read(&metadata_path)?)?;
            let target = targets
                .iter()
                .find(|target| target.target == build.target)
                .context("native artifact target is not configured")?;
            ensure!(
                build.schema_version == 1
                    && build.source_run_id == run_id
                    && build.source_run_attempt == run_attempt
                    && build.source_run_sha == server_sha
                    && build.release_pr_number == client_pr_number
                    && build.release_pr_sha == client_sha
                    && build.package_version == package_version
                    && build.runner == target.runner
                    && directory_name == format!("native-target-{}-{run_attempt}", target.target),
                "native target metadata does not match this run and pinned Client source"
            );
            let (expected_os, expected_arch) = runner_platform(&target.runner);
            ensure!(
                build.runner_os == expected_os
                    && build.runner_arch == expected_arch
                    && target_platform(&target.target)? == (expected_os, expected_arch),
                "native artifact was not built on its configured target runner"
            );
            ensure!(
                build.filename == format!("{}-{}", source_repository.name(), target.target)
                    && build.version_output.starts_with(&format!(
                        "{} {}+",
                        source_repository.name(),
                        package_version
                    )),
                "native artifact name or executed version does not match the Client source"
            );
            let mut entries = std::fs::read_dir(&directory)?;
            let names = entries
                .by_ref()
                .map(|entry| {
                    entry?
                        .file_name()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("native artifact filename is not UTF-8"))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                names.len() == 2
                    && names.contains(NATIVE_TARGET_MANIFEST)
                    && names.contains(&build.filename),
                "native artifact contains unexpected files"
            );
            let binary_path = directory.join(&build.filename);
            let binary_metadata = std::fs::symlink_metadata(&binary_path)?;
            ensure!(
                binary_metadata.file_type().is_file()
                    && !binary_metadata.file_type().is_symlink()
                    && binary_metadata.len() > 0
                    && binary_metadata.len() <= MAX_NATIVE_ASSET_BYTES,
                "native binary artifact has invalid size or type"
            );
            total_size = total_size
                .saturating_add(binary_metadata.len())
                .saturating_add(metadata.len());
            ensure!(
                total_size <= MAX_NATIVE_BUNDLE_BYTES,
                "native target artifacts exceed the bundle size limit"
            );
            let digest = sha256_file(&binary_path)?;
            asset_paths.insert(build.target.clone(), binary_path);
            assets.push(NativeAssetEvidence {
                target: build.target.clone(),
                runner: build.runner.clone(),
                runner_name: build.runner_name.clone(),
                runner_os: build.runner_os.clone(),
                runner_arch: build.runner_arch.clone(),
                filename: build.filename.clone(),
                size: binary_metadata.len(),
                sha256: digest,
                version_output: build.version_output.clone(),
            });
            let artifact_name = format!("native-target-{}-{run_attempt}", build.target);
            let artifact = native_artifacts
                .iter()
                .find(|artifact| artifact["name"] == artifact_name)
                .context("native target artifact lacks its workflow-run record")?;
            native_artifact_evidence.insert(artifact_name, json!({
                "id": artifact["id"],
                "digest": artifact["digest"],
                "archive_size": artifact["size_in_bytes"],
                "binary_size": binary_metadata.len(),
                "binary_sha256": assets.last().map(|asset| asset.sha256.clone()).unwrap_or_default(),
            }));
        }
        ensure!(
            actual_directories == expected_directories,
            "downloaded native target artifact directories do not match configured targets"
        );
        assets.sort_by(|left, right| left.target.cmp(&right.target));
        let manifest = NativeAssetManifest {
            schema_version: 1,
            repository: source_repository.as_str().to_owned(),
            source_run_id: run_id,
            source_run_sha: server_sha.clone(),
            run_attempt,
            source_revision: server_sha.clone(),
            release_pr_number: client_pr_number,
            release_pr_sha: client_sha.clone(),
            tag: ReleaseTag::parse(&format!("v{package_version}"))?,
            package_version: package_version.clone(),
            assets,
        };
        let source_manifest = ReleaseManifestV2 {
            schema_version: 2,
            repository: source_repository.as_str().to_owned(),
            source_run_id: run_id,
            source_run_sha: server_sha.clone(),
            run_attempt,
            source_revision: server_sha.clone(),
            release_pr_number: client_pr_number,
            release_pr_sha: client_sha.clone(),
            tag: manifest.tag.clone(),
            package_version: Some(package_version.clone()),
            artifact_id: None,
        };
        validate_native_manifest(&manifest, &source_repository, &targets, &source_manifest)?;
        Ok(NativeProbeInputs {
            client_repository: source_repository,
            client_sha,
            client_pr_number,
            package_version,
            harness_sha,
            server_sha,
            run_id,
            run_attempt,
            targets,
            artifacts: native_artifact_evidence.into_values().collect(),
            manifest,
            asset_paths,
        })
    }

    fn native_probe_manifest(inputs: &NativeProbeInputs, tag: ReleaseTag) -> NativeAssetManifest {
        let mut manifest = inputs.manifest.clone();
        manifest.tag = tag;
        manifest
    }

    fn native_probe_source_manifest(
        inputs: &NativeProbeInputs,
        tag: ReleaseTag,
    ) -> ReleaseManifestV2 {
        ReleaseManifestV2 {
            schema_version: 2,
            repository: inputs.client_repository.as_str().to_owned(),
            source_run_id: inputs.run_id,
            source_run_sha: inputs.server_sha.clone(),
            run_attempt: inputs.run_attempt,
            source_revision: inputs.server_sha.clone(),
            release_pr_number: inputs.client_pr_number,
            release_pr_sha: inputs.client_sha.clone(),
            tag,
            package_version: Some(inputs.package_version.clone()),
            artifact_id: None,
        }
    }

    fn native_probe_bundle(
        manifest: &NativeAssetManifest,
        asset_paths: &std::collections::BTreeMap<String, PathBuf>,
    ) -> Result<Vec<u8>> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        archive.start_file(NATIVE_BUNDLE_MANIFEST, options)?;
        archive.write_all(&serde_json::to_vec(manifest)?)?;
        for asset in &manifest.assets {
            archive.start_file(&asset.filename, options)?;
            let path = asset_paths
                .get(&asset.target)
                .context("verified native asset path is missing")?;
            ensure!(
                sha256_file(path)? == asset.sha256,
                "verified native asset changed before bundling"
            );
            let mut file = std::fs::File::open(path)?;
            std::io::copy(&mut file, &mut archive)?;
        }
        Ok(archive.finish()?.into_inner())
    }

    fn native_probe_input_evidence(inputs: &NativeProbeInputs) -> Result<Value> {
        Ok(json!({
            "schema_version": 1,
            "server_repository": env("GITHUB_REPOSITORY")?,
            "server_harness_sha": inputs.harness_sha.as_str(),
            "server_run_id": inputs.run_id.0,
            "server_run_attempt": inputs.run_attempt,
            "server_source_sha": inputs.server_sha.as_str(),
            "client_repository": inputs.client_repository.as_str(),
            "client_source_sha": inputs.client_sha.as_str(),
            "client_source_pr_number": inputs.client_pr_number,
            "client_package_version": inputs.package_version,
            "artifacts": inputs.artifacts,
            "binaries": inputs.manifest.assets.iter().map(|asset| json!({
                "target": asset.target,
                "filename": asset.filename,
                "size": asset.size,
                "sha256": asset.sha256,
                "version_output": asset.version_output,
            })).collect::<Vec<_>>(),
        }))
    }

    fn create_native_probe_draft(
        api: &GitHub,
        repo: &Repository,
        tag: &ReleaseTag,
        target_sha: &str,
    ) -> Result<u64> {
        let tag_ref = format!(
            "/repos/{}/git/ref/tags/{}",
            repo.as_str(),
            url_encode(tag.as_str())
        );
        ensure!(
            probe_not_found(api, &tag_ref)?,
            "scratch probe tag already exists"
        );
        ensure!(
            find_release(api, repo, tag)?.is_none(),
            "scratch probe release already exists"
        );
        let release: Value = api.post(
            &format!("/repos/{}/releases", repo.as_str()),
            &json!({"tag_name":tag.as_str(),"target_commitish":target_sha,"name":tag.as_str(),"draft":true,"prerelease":true,"generate_release_notes":false}),
        )?;
        let release_id = release["id"]
            .as_u64()
            .context("created native probe draft lacks ID")?;
        ensure!(
            release_id > 0
                && release["tag_name"] == tag.as_str()
                && release["draft"] == true
                && release["prerelease"] == true,
            "created native probe release is not the expected prerelease draft"
        );
        ensure!(
            probe_tag_points_to_commit(api, repo, tag.as_str(), target_sha)?,
            "created native probe tag does not point to the exact scratch target"
        );
        Ok(release_id)
    }

    fn cleanup_native_probe_draft(
        api: &GitHub,
        repo: &Repository,
        release_id: u64,
        tag: &ReleaseTag,
        target_sha: &str,
    ) -> Result<()> {
        let release_path = format!("/repos/{}/releases/{release_id}", repo.as_str());
        if !probe_not_found(api, &release_path)? {
            let release: Value = api.get(&release_path)?;
            ensure!(
                release["id"].as_u64() == Some(release_id) && release["tag_name"] == tag.as_str(),
                "native probe cleanup release identity changed"
            );
            if release["draft"] == true {
                api.delete(&release_path)?;
            } else {
                ensure_published_immutable_release(&release, release_id, tag)?;
                ensure!(
                    probe_tag_points_to_commit(api, repo, tag.as_str(), target_sha)?,
                    "published native probe tag does not point to the exact scratch target"
                );
                return Ok(());
            }
        }
        let ref_path = format!(
            "/repos/{}/git/ref/tags/{}",
            repo.as_str(),
            url_encode(tag.as_str())
        );
        if !probe_not_found(api, &ref_path)? {
            ensure!(
                probe_tag_points_to_commit(api, repo, tag.as_str(), target_sha)?,
                "native probe cleanup tag differs from its exact scratch target"
            );
            api.delete(&format!(
                "/repos/{}/git/refs/tags/{}",
                repo.as_str(),
                url_encode(tag.as_str())
            ))?;
        }
        ensure!(
            probe_not_found(api, &release_path)? && probe_not_found(api, &ref_path)?,
            "native probe draft or tag remains after cleanup"
        );
        Ok(())
    }

    fn probe_release_id() -> Result<u64> {
        if let Ok(value) = std::env::var("SECUREFIX_PROVIDER_PROBE_RELEASE_ID") {
            let id = value.parse::<u64>()?;
            ensure!(id > 0, "release ID must be positive");
            return Ok(id);
        }
        let receipt = load_probe_receipt()?;
        let id = receipt["release_id"]
            .as_u64()
            .context("receipt lacks release ID")?;
        ensure!(id > 0, "release ID must be positive");
        Ok(id)
    }

    fn write_probe_receipt(release_id: u64, tag: &str, target_sha: &str) -> Result<()> {
        ensure!(release_id > 0, "release ID must be positive");
        crate::policy::validate_sha(target_sha)?;
        let state = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_STATE_DIR")?);
        std::fs::create_dir_all(&state)?;
        let path = state.join("receipt.json");
        if path.exists() {
            let previous: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            ensure!(
                previous["release_id"].as_u64() == Some(release_id)
                    && previous["tag"] == tag
                    && previous["target_sha"] == target_sha,
                "probe receipt identity changed"
            );
            return Ok(());
        }
        write_json(
            path,
            &json!({"release_id":release_id,"tag":tag,"target_sha":target_sha}),
        )
    }

    fn load_probe_receipt() -> Result<Value> {
        let state = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_STATE_DIR")?);
        let path = state.join("receipt.json");
        if path.exists() {
            return Ok(serde_json::from_slice(&std::fs::read(path)?)?);
        }
        let release_id = env("SECUREFIX_PROVIDER_PROBE_RELEASE_ID")?.parse::<u64>()?;
        ensure!(release_id > 0, "release ID must be positive");
        let tag = env("SECUREFIX_PROVIDER_PROBE_TAG")?;
        let target_sha = env("SECUREFIX_PROVIDER_PROBE_EXPECTED_TARGET_SHA")?;
        crate::policy::validate_sha(&target_sha)?;
        Ok(json!({"release_id":release_id,"tag":tag,"target_sha":target_sha}))
    }

    fn probe_target_sha() -> Result<String> {
        let receipt = load_probe_receipt()?;
        let target = receipt["target_sha"]
            .as_str()
            .context("probe receipt lacks target SHA")?;
        crate::policy::validate_sha(target)?;
        Ok(target.to_owned())
    }

    fn probe_tag_points_to_commit(
        api: &GitHub,
        repo: &Repository,
        tag: &str,
        expected: &str,
    ) -> Result<bool> {
        let path = format!("/repos/{}/git/ref/tags/{}", repo.as_str(), url_encode(tag));
        let reference: Value = match api.get(&path) {
            Ok(reference) => reference,
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let object = &reference["object"];
        let sha = object["sha"].as_str().context("tag ref lacks object SHA")?;
        match object["type"]
            .as_str()
            .context("tag ref lacks object type")?
        {
            "commit" => Ok(sha == expected),
            "tag" => {
                let annotation: Value =
                    api.get(&format!("/repos/{}/git/tags/{sha}", repo.as_str()))?;
                Ok(annotation["object"]["type"] == "commit"
                    && annotation["object"]["sha"] == expected)
            }
            _ => Ok(false),
        }
    }

    fn probe_scratch_target_sha(repo: &Repository) -> Result<String> {
        let api = GitHub::anonymous()?;
        let repository: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
        let branch = repository["default_branch"]
            .as_str()
            .context("scratch repository default branch missing")?;
        let commit: Value = api.get(&format!(
            "/repos/{}/commits/{}",
            repo.as_str(),
            url_encode(branch)
        ))?;
        let sha = commit["sha"]
            .as_str()
            .context("scratch default branch lacks commit SHA")?;
        crate::policy::validate_sha(sha)?;
        Ok(sha.to_owned())
    }

    fn export_probe_public_key(fingerprint: &str) -> Result<()> {
        let state = PathBuf::from(env("SECUREFIX_PROVIDER_PROBE_STATE_DIR")?);
        std::fs::create_dir_all(&state)?;
        let output = ProcessCommand::new("gpg")
            .arg("--batch")
            .arg("--armor")
            .arg("--export")
            .arg(fingerprint)
            .output()
            .context("export provider signing public key")?;
        ensure!(
            output.status.success() && !output.stdout.is_empty(),
            "could not export provider signing public key"
        );
        std::fs::write(state.join("public-key.asc"), output.stdout)?;
        Ok(())
    }

    fn probe_not_found(api: &GitHub, path: &str) -> Result<bool> {
        match api.get::<Value>(path) {
            Ok(_) => Ok(false),
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
            {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    fn probe_write_api() -> Result<(GitHub, Repository)> {
        let repo_name = env("SECUREFIX_PROVIDER_PROBE_REPOSITORY")?;
        probe_scratch_write_api(&repo_name, "SECUREFIX_SERVER_APP_TOKEN")
    }

    fn probe_scratch_write_api(repo_name: &str, token_name: &str) -> Result<(GitHub, Repository)> {
        ensure!(
            repo_name == crate::config::trusted()?.deployment.integration.repository,
            "release probe repository is not the trusted integration repository"
        );
        let repo = Repository::parse(repo_name)?;
        let token = env(token_name)?;
        // This validation requires the installation to be scoped to the one configured scratch repository.
        let candidate_sha = env("GITHUB_SHA")?;
        let _validated_scratch_token = GitHub::scratch_from_env(token_name, &candidate_sha)?;
        let anonymous = GitHub::anonymous()?;
        let control = crate::control::ControlRevision::load(&anonymous)?;
        Ok((
            GitHub::new("https://api.github.com", token)?.with_control_revision(&control)?,
            repo,
        ))
    }

    fn probe_plan(assets: &Path, project: &str, tag: ReleaseTag) -> Result<ReleasePlanV2> {
        for name in provider_asset_names(&tag, project) {
            let path = assets.join(&name);
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "provider probe asset must be a regular file"
            );
            ensure!(
                metadata.len() > 0 && metadata.len() <= MAX_PROVIDER_ARCHIVE_BYTES,
                "provider probe asset has invalid size"
            );
            if name.ends_with(".zip") {
                validate_provider_archive(&path, &name, &tag, project)?;
            } else {
                let manifest: Value = serde_json::from_slice(&std::fs::read(path)?)?;
                ensure!(
                    manifest["version"] == 1
                        && manifest["metadata"]["protocol_versions"] == json!(["6.0"]),
                    "unexpected Terraform Registry manifest"
                );
            }
        }
        let assets = provider_asset_names(&tag, project)
            .into_iter()
            .map(|name| {
                Ok(PlannedAsset {
                    sha256: sha256_file(&assets.join(&name))?,
                    name,
                    size: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ReleasePlanV2 {
            schema_version: 2,
            server_revision: "provider-no-publish-probe".to_owned(),
            instance_authority: None,
            source_manifest_sha256: None,
            release_pr_head_sha: None,
            client_package: None,
            repository: format!("probe/{project}"),
            strategy: ReleaseStrategy::TerraformProvider,
            source_run_id: RunId(1),
            source_run_attempt: 1,
            source_revision: "0".repeat(40),
            release_pr_number: 1,
            release_pr_sha: "0".repeat(40),
            tag,
            source_manifest: ReleaseManifestV2 {
                schema_version: 2,
                repository: format!("probe/{project}"),
                source_run_id: RunId(1),
                source_run_sha: CommitSha::parse(&"0".repeat(40))?,
                run_attempt: 1,
                source_revision: CommitSha::parse(&"0".repeat(40))?,
                release_pr_number: 1,
                release_pr_sha: CommitSha::parse(&"0".repeat(40))?,
                tag: ReleaseTag::parse("v0.0.1")?,
                package_version: Some("0.0.1".into()),
                artifact_id: None,
            },
            native_binary_repository: None,
            release_id: Some(1),
            existing_signature_sha256: None,
            assets,
            native_assets: Vec::new(),
        })
    }

    fn append_signed_assets(
        plan: &mut ReleasePlanV2,
        assets: &Path,
        sums: &Path,
        signature: &Path,
    ) -> Result<()> {
        for path in [sums, signature] {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("invalid signed asset name")?
                .to_owned();
            plan.assets.push(PlannedAsset {
                sha256: sha256_file(assets.join(&name).as_path())?,
                name,
                size: None,
            });
        }
        Ok(())
    }

    #[test]
    fn repository_rejects_path_injection() {
        assert!(Repository::parse("civitaspo/terraform-provider-sigma").is_ok());
        assert!(Repository::parse("civitaspo/../secrets").is_err());
        assert!(Repository::parse("civitaspo/terraform-provider-sigma/extra").is_err());
    }

    #[test]
    fn release_tag_requires_prefixed_semver() {
        assert_eq!(
            ReleaseTag::parse("v0.0.1-pre.1").unwrap().version(),
            "0.0.1-pre.1"
        );
        assert!(ReleaseTag::parse("0.0.1").is_err());
        assert!(ReleaseTag::parse("v01.0.0").is_err());
    }

    #[test]
    fn manifest_requires_supported_version_and_identifiers() {
        let valid = ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/terraform-provider-sigma".into(),
            source_run_id: RunId(7),
            source_revision: CommitSha::parse(&"a".repeat(40)).unwrap(),
            release_pr_number: 8,
            release_pr_sha: CommitSha::parse(&"b".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            package_version: Some("1.2.3".into()),
            source_run_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            run_attempt: 1,
            artifact_id: Some(9),
        };
        assert!(valid.validate().is_ok());
        let mut wrong_schema = valid.clone();
        wrong_schema.schema_version = 1;
        assert!(wrong_schema.validate().is_err());
        let mut zero_artifact = valid;
        zero_artifact.artifact_id = Some(0);
        assert!(zero_artifact.validate().is_err());
    }

    #[test]
    fn release_plan_is_bound_to_its_verified_source_manifest() {
        let source_manifest = ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/example".into(),
            source_run_id: RunId(7),
            source_run_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"b".repeat(40)).unwrap(),
            release_pr_number: 8,
            release_pr_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            package_version: Some("1.2.3".into()),
            artifact_id: None,
        };
        let plan = ReleasePlanV2 {
            schema_version: 2,
            server_revision: "d".repeat(40),
            instance_authority: None,
            source_manifest_sha256: None,
            release_pr_head_sha: None,
            client_package: None,
            repository: source_manifest.repository.clone(),
            strategy: ReleaseStrategy::GithubRelease,
            source_run_id: source_manifest.source_run_id,
            source_run_attempt: source_manifest.run_attempt,
            source_revision: source_manifest.source_revision.as_str().to_owned(),
            release_pr_number: source_manifest.release_pr_number,
            release_pr_sha: source_manifest.release_pr_sha.as_str().to_owned(),
            tag: source_manifest.tag.clone(),
            source_manifest: source_manifest.clone(),
            native_binary_repository: None,
            release_id: None,
            existing_signature_sha256: None,
            assets: Vec::new(),
            native_assets: Vec::new(),
        };
        assert!(plan.validate().is_ok());
        let mut native_plan = plan.clone();
        native_plan.instance_authority = Some(NativeAuthoritySnapshot {
            instance_repository: "example-org/server".to_owned(),
            instance_id: 404,
            default_branch: "main".to_owned(),
            config_path: "securefix-server.toml".to_owned(),
            config_sha256: "e".repeat(64),
            epoch: "f".repeat(40),
            workflows: vec![crate::api::NativeWorkflowAuthority {
                role: securefix::instance_config::WorkflowRole::Release,
                path: ".github/workflows/server-release.yml".to_owned(),
                sha256: "a".repeat(64),
                pins: vec![format!(
                    "example-org/distributor/.github/workflows/reusable-server-release.yml@{}",
                    native_plan.server_revision
                )],
            }],
        });
        native_plan.source_manifest_sha256 =
            Some(sha256_bytes(&serde_json::to_vec(&source_manifest).unwrap()));
        native_plan.release_pr_head_sha = Some("9".repeat(40));
        let mut package = native_client_snapshot_fixture();
        package.implementation_sha = source_manifest.source_revision.as_str().to_owned();
        native_plan.client_package = Some(package);
        native_plan.validate().unwrap();
        let mut invalid_digest = native_plan.clone();
        invalid_digest
            .instance_authority
            .as_mut()
            .unwrap()
            .config_sha256 = "e".repeat(40);
        assert!(invalid_digest.validate().is_err());
        let mut mismatched_client = native_plan;
        mismatched_client
            .client_package
            .as_mut()
            .unwrap()
            .implementation_sha = "8".repeat(40);
        assert!(mismatched_client.validate().is_err());
        let mut tampered = plan;
        tampered.release_pr_sha = "e".repeat(40);
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn native_asset_bundle_is_bound_to_source_targets_and_exact_file_bytes() {
        let repository = Repository::parse("civitaspo/herdr-linear-agent").unwrap();
        let targets = vec![
            crate::policy::NativeBinaryTarget {
                target: "aarch64-apple-darwin".into(),
                runner: "macos-15".into(),
            },
            crate::policy::NativeBinaryTarget {
                target: "x86_64-apple-darwin".into(),
                runner: "macos-15-intel".into(),
            },
            crate::policy::NativeBinaryTarget {
                target: "aarch64-unknown-linux-musl".into(),
                runner: "ubuntu-24.04-arm".into(),
            },
            crate::policy::NativeBinaryTarget {
                target: "x86_64-unknown-linux-musl".into(),
                runner: "ubuntu-24.04".into(),
            },
        ];
        let source = ReleaseManifestV2 {
            schema_version: 2,
            repository: repository.as_str().into(),
            source_run_id: RunId(17),
            source_run_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"b".repeat(40)).unwrap(),
            release_pr_number: 23,
            release_pr_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v0.8.2-pre.17.native").unwrap(),
            package_version: Some("0.8.2".into()),
            artifact_id: Some(29),
        };
        let mut manifest = NativeAssetManifest {
            schema_version: 1,
            repository: repository.as_str().into(),
            source_run_id: source.source_run_id,
            source_run_sha: source.source_run_sha.clone(),
            run_attempt: source.run_attempt,
            source_revision: source.source_revision.clone(),
            release_pr_number: source.release_pr_number,
            release_pr_sha: source.release_pr_sha.clone(),
            tag: source.tag.clone(),
            package_version: source.package_version().to_owned(),
            assets: Vec::new(),
        };
        let contents = [
            b"arm macOS".as_slice(),
            b"x64 macOS",
            b"arm Linux",
            b"x64 Linux",
        ];
        for (target, bytes) in targets.iter().zip(contents) {
            let (runner_os, runner_arch) = runner_platform(&target.runner);
            manifest.assets.push(NativeAssetEvidence {
                target: target.target.clone(),
                runner: target.runner.clone(),
                runner_name: format!("{} release runner", target.runner),
                runner_os: runner_os.into(),
                runner_arch: runner_arch.into(),
                filename: format!("{}-{}", repository.name(), target.target),
                size: bytes.len() as u64,
                sha256: securefix::hex_encode(Sha256::digest(bytes)),
                version_output: "herdr-linear-agent 0.8.2+candidate".into(),
            });
        }
        validate_native_manifest(&manifest, &repository, &targets, &source).unwrap();
        let destination = Repository::parse("civitaspo/testing-securefix-server").unwrap();
        let plan = ReleasePlanV2 {
            schema_version: 2,
            server_revision: "d".repeat(40),
            instance_authority: None,
            source_manifest_sha256: None,
            release_pr_head_sha: None,
            client_package: None,
            repository: destination.as_str().to_owned(),
            strategy: ReleaseStrategy::GithubRelease,
            source_run_id: source.source_run_id,
            source_run_attempt: source.run_attempt,
            source_revision: source.source_revision.as_str().to_owned(),
            release_pr_number: source.release_pr_number,
            release_pr_sha: source.release_pr_sha.as_str().to_owned(),
            tag: source.tag.clone(),
            source_manifest: source.clone(),
            native_binary_repository: Some(repository.as_str().to_owned()),
            release_id: None,
            existing_signature_sha256: None,
            assets: manifest
                .assets
                .iter()
                .map(|asset| PlannedAsset {
                    name: asset.filename.clone(),
                    sha256: asset.sha256.clone(),
                    size: Some(asset.size),
                })
                .collect(),
            native_assets: manifest.assets.clone(),
        };
        plan.validate().unwrap();
        let mut wrong_binary_repository = plan.clone();
        wrong_binary_repository.native_binary_repository = Some(destination.as_str().to_owned());
        assert!(wrong_binary_repository.validate().is_err());
        let mut stale_version = source.clone();
        stale_version.package_version = Some("0.8.3".into());
        assert!(
            validate_native_manifest(&manifest, &repository, &targets, &stale_version).is_err()
        );

        let temp = tempfile::tempdir().unwrap();
        for (asset, bytes) in manifest.assets.iter().zip(contents) {
            std::fs::write(temp.path().join(&asset.filename), bytes).unwrap();
        }
        std::fs::write(
            temp.path().join(NATIVE_BUNDLE_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        validate_native_asset_files(temp.path(), &manifest).unwrap();
        std::fs::write(
            temp.path().join(&manifest.assets[0].filename),
            b"changed bytes",
        )
        .unwrap();
        assert!(validate_native_asset_files(temp.path(), &manifest).is_err());

        let make_bundle = |assets: usize| {
            let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o644);
            archive.start_file(NATIVE_BUNDLE_MANIFEST, options).unwrap();
            archive
                .write_all(&serde_json::to_vec(&manifest).unwrap())
                .unwrap();
            for (asset, bytes) in manifest.assets.iter().zip(contents).take(assets) {
                archive.start_file(&asset.filename, options).unwrap();
                archive.write_all(bytes).unwrap();
            }
            archive.finish().unwrap().into_inner()
        };
        let complete = make_bundle(manifest.assets.len());
        let extracted = tempfile::tempdir().unwrap();
        unpack_native_bundle(&complete, extracted.path(), &repository, &targets).unwrap();
        validate_native_asset_files(extracted.path(), &manifest).unwrap();
        let missing = make_bundle(manifest.assets.len() - 1);
        let rejected = tempfile::tempdir().unwrap();
        assert!(unpack_native_bundle(&missing, rejected.path(), &repository, &targets).is_err());

        let mut stale_source = source.clone();
        stale_source.source_run_sha = CommitSha::parse(&"d".repeat(40)).unwrap();
        assert!(validate_native_manifest(&manifest, &repository, &targets, &stale_source).is_err());
        let mut missing_target = manifest;
        missing_target.assets.pop();
        assert!(validate_native_manifest(&missing_target, &repository, &targets, &source).is_err());
    }

    #[test]
    fn release_identity_requires_exact_preflight_binding() {
        assert!(validate_release_identity(None, None).is_ok());
        assert!(validate_release_identity(Some(7), Some(7)).is_ok());
        assert!(validate_release_identity(None, Some(7)).is_err());
        assert!(validate_release_identity(Some(7), None).is_err());
        assert!(validate_release_identity(Some(7), Some(8)).is_err());
    }

    #[test]
    fn find_release_falls_back_to_paginated_listing_for_drafts_and_fails_closed() {
        use crate::fixtures::{Fixture, Route};

        let repo = Repository::parse("example/provider").unwrap();
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let lookup = "/repos/example/provider/releases/tags/v1.2.3";
        let listing = "/repos/example/provider/releases?per_page=100&page=1";

        let fixture = Fixture::new(vec![Route::get(
            lookup,
            json!({"id":7,"tag_name":"v1.2.3","draft":false}),
        )]);
        let found = find_release(&fixture.api, &repo, &tag).unwrap().unwrap();
        assert_eq!(found["id"], 7);
        assert_eq!(found["draft"], false);
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::request("GET", lookup, 404, json!({"message":"Not Found"})),
            Route::get(
                listing,
                json!([
                    {"id":10,"tag_name":"v1.2.2","draft":false},
                    {"id":42,"tag_name":"v1.2.3","draft":true}
                ]),
            ),
        ]);
        let found = find_release(&fixture.api, &repo, &tag).unwrap().unwrap();
        assert_eq!(found["id"], 42);
        assert_eq!(found["draft"], true);
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::request("GET", lookup, 404, json!({"message":"Not Found"})),
            Route::get(listing, json!([{"id":10,"tag_name":"v1.2.2"}])),
        ]);
        assert!(find_release(&fixture.api, &repo, &tag).unwrap().is_none());
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::request("GET", lookup, 404, json!({"message":"Not Found"})),
            Route::get(
                listing,
                json!([
                    {"id":42,"tag_name":"v1.2.3","draft":true},
                    {"id":43,"tag_name":"v1.2.3","draft":true}
                ]),
            ),
        ]);
        assert!(find_release(&fixture.api, &repo, &tag).is_err());
        fixture.finish();

        let fixture = Fixture::new(vec![Route::request(
            "GET",
            lookup,
            403,
            json!({"message":"Forbidden"}),
        )]);
        assert!(find_release(&fixture.api, &repo, &tag).is_err());
        fixture.finish();
    }

    #[test]
    fn gpg_status_rejects_expired_revoked_and_multiple_signatures() {
        let expected = "A".repeat(40);
        let signer = "B".repeat(40);
        let valid = format!(
            "[GNUPG:] VALIDSIG {signer} 2026-01-01 1767225600 0 4 0 1 10 00 {expected} future-field\n"
        );
        assert!(validate_gpg_status(&valid, &expected).is_ok());
        for rejected in ["EXPSIG", "EXPKEYSIG", "REVKEYSIG"] {
            let status = format!("[GNUPG:] {rejected} keyid user\n{valid}");
            assert!(
                validate_gpg_status(&status, &expected).is_err(),
                "{rejected}"
            );
        }
        assert!(validate_gpg_status(&(valid.clone() + &valid), &expected).is_err());
    }

    fn provider_signature_test_plan(assets_dir: &Path) -> ReleasePlanV2 {
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let repository = "example/terraform-provider-sigma".to_owned();
        let source_manifest = ReleaseManifestV2 {
            schema_version: 2,
            repository: repository.clone(),
            source_run_id: RunId(7),
            source_run_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"b".repeat(40)).unwrap(),
            release_pr_number: 8,
            release_pr_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            tag: tag.clone(),
            package_version: Some("1.2.3".into()),
            artifact_id: Some(9),
        };
        let mut plan = ReleasePlanV2 {
            schema_version: 2,
            server_revision: "d".repeat(40),
            instance_authority: None,
            source_manifest_sha256: None,
            release_pr_head_sha: None,
            client_package: None,
            repository,
            strategy: ReleaseStrategy::TerraformProvider,
            source_run_id: RunId(7),
            source_run_attempt: 1,
            source_revision: "b".repeat(40),
            release_pr_number: 8,
            release_pr_sha: "c".repeat(40),
            tag,
            source_manifest,
            native_binary_repository: None,
            release_id: Some(17),
            existing_signature_sha256: None,
            assets: Vec::new(),
            native_assets: Vec::new(),
        };
        let asset = assets_dir.join("provider.zip");
        std::fs::write(&asset, b"provider bytes").unwrap();
        plan.assets.push(PlannedAsset {
            name: "provider.zip".into(),
            sha256: sha256_file(&asset).unwrap(),
            size: None,
        });
        plan
    }

    fn expected_release_asset(name: &str, digest: &str, id: u64, size: u64) -> Value {
        json!({"name":name,"digest":format!("sha256:{digest}"),"id":id,"size":size})
    }

    #[test]
    fn preflight_downloads_only_the_bounded_digest_matched_signature_asset() {
        use crate::fixtures::{Fixture, Route};
        let input = tempfile::tempdir().unwrap();
        let assets_dir = input.path().join("assets");
        std::fs::create_dir_all(&assets_dir).unwrap();
        let plan = provider_signature_test_plan(&assets_dir);
        let sums = canonical_provider_sums(&assets_dir, &plan.assets).unwrap();
        let project = Repository::parse(&plan.repository).unwrap();
        let sums_name = format!("{}_{}_SHA256SUMS", project.name(), plan.tag.version());
        let sums_digest = securefix::hex_encode(Sha256::digest(&sums));
        let signature = b"opaque test signature";
        let signature_digest = securefix::hex_encode(Sha256::digest(signature));
        let existing = vec![
            expected_release_asset(&sums_name, &sums_digest, 41, sums.len() as u64),
            expected_release_asset(
                &format!("{sums_name}.sig"),
                &signature_digest,
                42,
                signature.len() as u64,
            ),
        ];
        let release = json!({"draft":true});
        let fixture = Fixture::new(vec![
            Route::raw(
                "GET",
                "/repos/example/terraform-provider-sigma/releases/assets/42",
                200,
                signature.to_vec(),
            )
            .with_request_header("Accept", "application/octet-stream"),
        ]);
        let digest = prepare_existing_provider_signature(
            &fixture.api,
            &project,
            &release,
            &existing,
            &plan,
            &assets_dir,
            input.path(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(digest, signature_digest);
        assert_eq!(
            std::fs::read(input.path().join("existing-signature.sig")).unwrap(),
            signature
        );
        fixture.finish();
    }

    #[test]
    fn preflight_allows_checksum_only_draft_and_rejects_unexpected_or_duplicate_assets() {
        let input = tempfile::tempdir().unwrap();
        let assets_dir = input.path().join("assets");
        std::fs::create_dir_all(&assets_dir).unwrap();
        let plan = provider_signature_test_plan(&assets_dir);
        let sums = canonical_provider_sums(&assets_dir, &plan.assets).unwrap();
        let project = Repository::parse(&plan.repository).unwrap();
        let sums_name = format!("{}_{}_SHA256SUMS", project.name(), plan.tag.version());
        let checksum = expected_release_asset(
            &sums_name,
            &securefix::hex_encode(Sha256::digest(&sums)),
            41,
            sums.len() as u64,
        );
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        assert!(
            prepare_existing_provider_signature(
                &api,
                &project,
                &json!({"draft":true}),
                std::slice::from_ref(&checksum),
                &plan,
                &assets_dir,
                input.path(),
            )
            .unwrap()
            .is_none()
        );
        let unexpected = expected_release_asset("other.zip", &"e".repeat(64), 43, 1);
        assert!(
            prepare_existing_provider_signature(
                &api,
                &project,
                &json!({"draft":true}),
                &[unexpected],
                &plan,
                &assets_dir,
                input.path(),
            )
            .is_err()
        );
        assert!(
            prepare_existing_provider_signature(
                &api,
                &project,
                &json!({"draft":true}),
                &[checksum.clone(), checksum],
                &plan,
                &assets_dir,
                input.path(),
            )
            .is_err()
        );
    }

    #[test]
    fn preflight_rejects_signature_digest_mismatch_and_download_over_limit() {
        use crate::fixtures::{Fixture, Route};
        let input = tempfile::tempdir().unwrap();
        let assets_dir = input.path().join("assets");
        std::fs::create_dir_all(&assets_dir).unwrap();
        let plan = provider_signature_test_plan(&assets_dir);
        let sums = canonical_provider_sums(&assets_dir, &plan.assets).unwrap();
        let project = Repository::parse(&plan.repository).unwrap();
        let sums_name = format!("{}_{}_SHA256SUMS", project.name(), plan.tag.version());
        let sums_asset = expected_release_asset(
            &sums_name,
            &securefix::hex_encode(Sha256::digest(&sums)),
            41,
            sums.len() as u64,
        );
        let signature_name = format!("{sums_name}.sig");
        let bytes = b"actual signature bytes";
        let bad_asset =
            expected_release_asset(&signature_name, &"0".repeat(64), 42, bytes.len() as u64);
        let fixture = Fixture::new(vec![Route::raw(
            "GET",
            "/repos/example/terraform-provider-sigma/releases/assets/42",
            200,
            bytes.to_vec(),
        )]);
        assert!(
            prepare_existing_provider_signature(
                &fixture.api,
                &project,
                &json!({"draft":true}),
                &[sums_asset.clone(), bad_asset],
                &plan,
                &assets_dir,
                input.path(),
            )
            .is_err()
        );
        fixture.finish();

        let oversized = vec![b'x'; MAX_PROVIDER_SIGNATURE_BYTES + 1];
        let oversized_asset = expected_release_asset(
            &signature_name,
            &securefix::hex_encode(Sha256::digest(&oversized)),
            42,
            1,
        );
        let fixture = Fixture::new(vec![Route::raw(
            "GET",
            "/repos/example/terraform-provider-sigma/releases/assets/42",
            200,
            oversized,
        )]);
        assert!(
            prepare_existing_provider_signature(
                &fixture.api,
                &project,
                &json!({"draft":true}),
                &[sums_asset, oversized_asset],
                &plan,
                &assets_dir,
                input.path(),
            )
            .is_err()
        );
        fixture.finish();
    }

    fn test_gpg(home: &Path, args: &[&str]) -> std::process::Output {
        ProcessCommand::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(home)
            .args(args)
            .output()
            .expect("GPG must be installed for release signing tests")
    }

    struct ScopedGpgHome(tempfile::TempDir);

    impl ScopedGpgHome {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                home.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            Self(home)
        }

        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    impl Drop for ScopedGpgHome {
        fn drop(&mut self) {
            let _ = ProcessCommand::new("gpgconf")
                .arg("--homedir")
                .arg(self.path())
                .args(["--kill", "gpg-agent"])
                .output();
        }
    }

    fn generate_test_signing_key(home: &Path, email: &str) -> String {
        let output = test_gpg(
            home,
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                &format!("Securefix Test <{email}>"),
                "ed25519",
                "sign",
                "0",
            ],
        );
        assert!(
            output.status.success(),
            "GPG test key generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = test_gpg(home, &["--with-colons", "--list-secret-keys", email]);
        assert!(output.status.success(), "GPG test key listing failed");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("fpr:")
                    .and_then(|line| line.split(':').nth(8))
            })
            .expect("generated GPG key fingerprint")
            .to_owned()
    }

    #[test]
    fn provider_signature_retry_reuses_verified_bytes_and_rejects_wrong_or_tampered_signatures() {
        let home = ScopedGpgHome::new();
        let output = test_gpg(home.path(), &["--version"]);
        assert!(
            output.status.success(),
            "GPG must be installed for release signing tests"
        );
        let fingerprint = generate_test_signing_key(home.path(), "release@example.test");
        let wrong_fingerprint = generate_test_signing_key(home.path(), "other@example.test");
        let sums = home.path().join("SHA256SUMS");
        std::fs::write(&sums, b"0123456789abcdef  provider.zip\n").unwrap();
        let first = home.path().join("first.sig");
        sign_checksum(&sums, &first, &fingerprint, "", Some(home.path())).unwrap();
        let original = std::fs::read(&first).unwrap();

        let reusable = home.path().join("existing-signature.sig");
        std::fs::write(&reusable, &original).unwrap();
        let output_signature = home.path().join("retry.sig");
        reuse_or_sign_checksum(
            &sums,
            &output_signature,
            &reusable,
            Some(&securefix::hex_encode(Sha256::digest(&original))),
            &fingerprint,
            "",
            Some(home.path()),
        )
        .unwrap();
        assert_eq!(std::fs::read(&output_signature).unwrap(), original);

        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = home.path().join("second.sig");
        sign_checksum(&sums, &second, &fingerprint, "", Some(home.path())).unwrap();
        assert_ne!(
            std::fs::read(&second).unwrap(),
            original,
            "fresh signatures should differ across signing times"
        );
        assert!(
            verify_checksum_signature(&first, &sums, &wrong_fingerprint, Some(home.path()))
                .is_err()
        );

        std::fs::write(&sums, b"tampered checksum contents\n").unwrap();
        assert!(verify_checksum_signature(&first, &sums, &fingerprint, Some(home.path())).is_err());
        assert!(
            reuse_or_sign_checksum(
                &sums,
                &home.path().join("bad-retry.sig"),
                &reusable,
                Some(&securefix::hex_encode(Sha256::digest(&original))),
                &fingerprint,
                "",
                Some(home.path()),
            )
            .is_err()
        );
    }

    #[test]
    fn sigma_asset_names_are_fixed_and_versioned() {
        let names = provider_asset_names(
            &ReleaseTag::parse("v1.2.3").unwrap(),
            "terraform-provider-sigma",
        );
        assert_eq!(PROVIDER_TARGETS.len(), 13);
        assert!(names.contains("terraform-provider-sigma_1.2.3_manifest.json"));
        assert!(names.contains("terraform-provider-sigma_1.2.3_linux_amd64.zip"));
        assert!(!names.contains("terraform-provider-sigma_1.2.3_darwin_arm.zip"));
    }

    #[test]
    fn provider_archives_reject_path_traversal_and_extra_files() {
        let dir = tempfile::tempdir().unwrap();
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let archive_path = dir.path().join("provider.zip");
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&archive_path).unwrap());
        archive
            .start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
        assert!(
            validate_provider_archive(
                &archive_path,
                "terraform-provider-sigma_1.2.3_linux_amd64.zip",
                &tag,
                "terraform-provider-sigma"
            )
            .is_err()
        );

        let mut archive = zip::ZipWriter::new(std::fs::File::create(&archive_path).unwrap());
        archive
            .start_file(
                "terraform-provider-sigma_v1.2.3",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"provider").unwrap();
        archive
            .start_file("README.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"extra").unwrap();
        archive.finish().unwrap();
        assert!(
            validate_provider_archive(
                &archive_path,
                "terraform-provider-sigma_1.2.3_linux_amd64.zip",
                &tag,
                "terraform-provider-sigma"
            )
            .is_err()
        );
    }

    #[test]
    fn provider_archive_preserves_registry_four_file_contract() {
        let dir = tempfile::tempdir().unwrap();
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let binary = dir.path().join("provider");
        std::fs::write(&binary, b"provider").unwrap();
        let docs = dir.path().join("docs");
        std::fs::create_dir(&docs).unwrap();
        for name in ["CHANGELOG.md", "LICENSE", "README.md"] {
            std::fs::write(docs.join(name), format!("{name} contents")).unwrap();
        }
        let archive_path = dir.path().join("provider.zip");
        write_provider_zip(
            &binary,
            "terraform-provider-sigma_v1.2.3",
            &docs,
            &archive_path,
        )
        .unwrap();
        validate_provider_archive(
            &archive_path,
            "terraform-provider-sigma_1.2.3_darwin_arm64.zip",
            &tag,
            "terraform-provider-sigma",
        )
        .unwrap();
        let mut archive = zip::ZipArchive::new(std::fs::File::open(archive_path).unwrap()).unwrap();
        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                "terraform-provider-sigma_v1.2.3",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }

    #[test]
    fn release_caller_workflow_paths_are_confined() {
        assert!(ensure_valid_caller_path(".github/workflows/release-tag.yml").is_ok());
        for path in [
            "../release-tag.yml",
            ".github/workflows/../release.yml",
            ".github/workflows/release.yml@refs/heads/main",
            ".github/workflows/release-tag.yaml",
        ] {
            assert!(ensure_valid_caller_path(path).is_err(), "accepted {path}");
        }
    }

    fn provenance_test_policy() -> Policy {
        let mut policy = Policy::parse(include_bytes!("../policy.json")).unwrap();
        policy.revision = "a".repeat(40);
        policy.control = Some(crate::fixtures::Fixture::control_revision());
        policy
    }

    fn provenance_test_manifest() -> ReleaseManifestV2 {
        ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/terraform-provider-sigma".into(),
            source_run_id: RunId(99),
            source_run_sha: CommitSha::parse(&"b".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"a".repeat(40)).unwrap(),
            release_pr_number: 55,
            release_pr_sha: CommitSha::parse(&"d".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            package_version: Some("1.2.3".into()),
            artifact_id: None,
        }
    }

    fn associated_release_pr() -> PullRequest {
        serde_json::from_value(json!({
            "number":87,
            "merged":true,
            "merged_at":"2026-10-10T12:40:48Z",
            "merge_commit_sha":"c".repeat(40),
            "merged_by":{"id":crate::config::trusted().unwrap().server_bot_id,"type":"Bot"},
            "head":{"ref":"release/next","sha":"a".repeat(40),"repo":{"full_name":"civitaspo/terraform-provider-sigma"}},
            "base":{"ref":"main","sha":"c".repeat(40),"repo":{"full_name":"civitaspo/terraform-provider-sigma"}}
        })).unwrap()
    }

    fn associated_release_pr_response() -> Value {
        json!({
            "number":87,
            "state":"closed",
            "merged_at":"2026-10-10T12:40:48Z",
            "merge_commit_sha":"c".repeat(40),
            "head":{"ref":"release/next","sha":"a".repeat(40),"repo":{"full_name":"civitaspo/terraform-provider-sigma"}},
            "base":{"ref":"main","repo":{"full_name":"civitaspo/terraform-provider-sigma"}}
        })
    }

    fn empty_association_run() -> Value {
        json!({
            "head_branch":"release/next",
            "pull_requests":[],
            "actor":{"id":crate::config::trusted().unwrap().server_bot_id,"type":"Bot"}
        })
    }

    #[test]
    fn empty_source_run_associations_accept_only_the_exact_merged_release_pr() {
        use crate::fixtures::{Fixture, Route};
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let pr = associated_release_pr();
        let head = CommitSha::parse(&"a".repeat(40)).unwrap();
        let merge = CommitSha::parse(&"c".repeat(40)).unwrap();
        let fixture = Fixture::new(vec![Route::get(
            format!(
                "/repos/{}/commits/{}/pulls?per_page=100&page=1",
                repo.as_str(),
                head.as_str()
            ),
            json!([associated_release_pr_response()]),
        )]);
        validate_source_pr_association(
            &fixture.api,
            &policy,
            &repo,
            SourcePrAssociation {
                run: &empty_association_run(),
                source_run_sha: &head,
                release_pr_number: 87,
                pr: &pr,
                merge_sha: &merge,
            },
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn unrelated_source_run_associations_fall_back_to_the_exact_merged_release_pr() {
        use crate::fixtures::{Fixture, Route};
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let pr = associated_release_pr();
        let head = CommitSha::parse(&"a".repeat(40)).unwrap();
        let merge = CommitSha::parse(&"c".repeat(40)).unwrap();
        let fixture = Fixture::new(vec![Route::get(
            format!(
                "/repos/{}/commits/{}/pulls?per_page=100&page=1",
                repo.as_str(),
                head.as_str()
            ),
            json!([associated_release_pr_response()]),
        )]);
        let mut run = empty_association_run();
        run["pull_requests"] = json!([{"number":96,"head":{"sha":"79cd"}}]);
        validate_source_pr_association(
            &fixture.api,
            &policy,
            &repo,
            SourcePrAssociation {
                run: &run,
                source_run_sha: &head,
                release_pr_number: 87,
                pr: &pr,
                merge_sha: &merge,
            },
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn empty_source_run_associations_reject_unrelated_or_changed_pull_requests() {
        use crate::fixtures::{Fixture, Route};
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let pr = associated_release_pr();
        let head = CommitSha::parse(&"a".repeat(40)).unwrap();
        let merge = CommitSha::parse(&"c".repeat(40)).unwrap();
        let mut variants = Vec::new();
        for (pointer, replacement) in [
            ("/number", json!(88)),
            ("/head/sha", json!("d".repeat(40))),
            ("/head/ref", json!("feature")),
            ("/head/repo/full_name", json!("attacker/repo")),
            ("/base/ref", json!("release/next")),
            ("/base/repo/full_name", json!("attacker/repo")),
            ("/state", json!("open")),
            ("/merged_at", json!("2026-10-10T12:41:00Z")),
            ("/merge_commit_sha", json!("d".repeat(40))),
        ] {
            let mut candidate = associated_release_pr_response();
            *candidate.pointer_mut(pointer).unwrap() = replacement;
            variants.push(candidate);
        }
        for candidate in variants {
            for associations in [json!([]), json!([{"number":96}])] {
                let fixture = Fixture::new(vec![Route::get(
                    format!(
                        "/repos/{}/commits/{}/pulls?per_page=100&page=1",
                        repo.as_str(),
                        head.as_str()
                    ),
                    json!([candidate.clone()]),
                )]);
                let mut run = empty_association_run();
                run["pull_requests"] = associations;
                assert!(
                    validate_source_pr_association(
                        &fixture.api,
                        &policy,
                        &repo,
                        SourcePrAssociation {
                            run: &run,
                            source_run_sha: &head,
                            release_pr_number: 87,
                            pr: &pr,
                            merge_sha: &merge,
                        },
                    )
                    .is_err()
                );
                fixture.finish();
            }
        }
    }

    #[test]
    fn source_run_pr_associations_retain_nonempty_match_and_reject_missing_values() {
        use crate::fixtures::Fixture;
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let pr = associated_release_pr();
        let head = CommitSha::parse(&"a".repeat(40)).unwrap();
        let merge = CommitSha::parse(&"c".repeat(40)).unwrap();
        let fixture = Fixture::new(vec![]);
        let mut run = empty_association_run();
        run["pull_requests"] = json!([{"number":87}]);
        validate_source_pr_association(
            &fixture.api,
            &policy,
            &repo,
            SourcePrAssociation {
                run: &run,
                source_run_sha: &head,
                release_pr_number: 87,
                pr: &pr,
                merge_sha: &merge,
            },
        )
        .unwrap();
        let mut missing = run.clone();
        missing.as_object_mut().unwrap().remove("pull_requests");
        assert!(
            validate_source_pr_association(
                &fixture.api,
                &policy,
                &repo,
                SourcePrAssociation {
                    run: &missing,
                    source_run_sha: &head,
                    release_pr_number: 87,
                    pr: &pr,
                    merge_sha: &merge,
                },
            )
            .is_err()
        );
        for invalid in [json!(null), json!({"number":87})] {
            run["pull_requests"] = invalid;
            assert!(
                validate_source_pr_association(
                    &fixture.api,
                    &policy,
                    &repo,
                    SourcePrAssociation {
                        run: &run,
                        source_run_sha: &head,
                        release_pr_number: 87,
                        pr: &pr,
                        merge_sha: &merge,
                    },
                )
                .is_err()
            );
        }
        run["pull_requests"] = json!([{"number":99}]);
        let unrelated_fixture = Fixture::new(vec![crate::fixtures::Route::get(
            format!(
                "/repos/{}/commits/{}/pulls?per_page=100&page=1",
                repo.as_str(),
                head.as_str()
            ),
            json!([associated_release_pr_response()]),
        )]);
        validate_source_pr_association(
            &unrelated_fixture.api,
            &policy,
            &repo,
            SourcePrAssociation {
                run: &run,
                source_run_sha: &head,
                release_pr_number: 87,
                pr: &pr,
                merge_sha: &merge,
            },
        )
        .unwrap();
        unrelated_fixture.finish();
        let mut wrong_actor = empty_association_run();
        wrong_actor["actor"]["id"] = json!(policy.owner_id);
        assert!(
            validate_source_pr_association(
                &fixture.api,
                &policy,
                &repo,
                SourcePrAssociation {
                    run: &wrong_actor,
                    source_run_sha: &head,
                    release_pr_number: 87,
                    pr: &pr,
                    merge_sha: &merge,
                },
            )
            .is_err()
        );
        fixture.finish();
    }

    fn successful_pr_provenance_routes(version: &str) -> Vec<crate::fixtures::Route> {
        successful_pr_provenance_routes_with_wrapper_pin(version, &"a".repeat(40))
    }

    fn successful_pr_provenance_routes_with_wrapper_pin(
        version: &str,
        wrapper_pin: &str,
    ) -> Vec<crate::fixtures::Route> {
        use crate::fixtures::Route;
        use base64::Engine;
        let trusted = crate::config::trusted().unwrap();
        let repo = "civitaspo/terraform-provider-sigma";
        let server_repository = trusted.deployment.server.repository.as_str();
        let release_branch = trusted.deployment.release_branch.as_str();
        let default_branch = trusted.deployment.server.default_branch.as_str();
        let name = format!("{}Release Tag", trusted.deployment.workflow_prefix);
        let wrapper_path = trusted
            .deployment
            .workflow_path(".github/workflows/release-tag.yml")
            .unwrap();
        let reusable_path = trusted
            .deployment
            .workflow_path(".github/workflows/reusable-release-tag.yml")
            .unwrap();
        let head = "b".repeat(40);
        let base = "c".repeat(40);
        let merge = "d".repeat(40);
        let workflow = format!(
            "name: {name}\non:\n  pull_request:\njobs:\n  tag:\n    uses: {server_repository}/{reusable_path}@{}\n",
            wrapper_pin
        );
        let content = |path: &str, sha: &str, text: &str| {
            Route::get(
                format!("/repos/{repo}/contents/{path}?ref={sha}"),
                json!({
                    "encoding":"base64",
                    "content":base64::engine::general_purpose::STANDARD.encode(text)
                }),
            )
        };
        vec![
            Route::get(
                format!("/repos/{repo}/actions/runs/99"),
                json!({
                    "name":name,
                    "status":"completed",
                    "conclusion":"success",
                    "repository":{"full_name":repo},
                    "head_repository":{"full_name":repo},
                    "head_sha":head,
                    "head_branch":release_branch,
                    "run_attempt":1,
                    "path":wrapper_path,
                    "event":"pull_request",
                    "pull_requests":[{"number":115}],
                    "referenced_workflows":[{
                        "path":format!("{server_repository}/{reusable_path}@{}", "a".repeat(40)),
                        "sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }]
                }),
            ),
            Route::get(
                format!("/repos/{repo}"),
                json!({"default_branch":default_branch}),
            ),
            Route::get(
                format!("/repos/{repo}"),
                json!({"default_branch":default_branch}),
            ),
            Route::get(
                format!("/repos/{repo}/pulls/55"),
                json!({
                    "number":55,
                    "merged":true,
                    "merged_at":"2026-01-01T00:00:00Z",
                    "merge_commit_sha":merge,
                    "merged_by":{"id":trusted.server_bot_id,"type":"Bot"},
                    "head":{"ref":release_branch,"sha":head,"repo":{"full_name":repo}},
                    "base":{"ref":default_branch,"sha":base,"repo":{"full_name":repo}}
                }),
            ),
            Route::get(
                format!("/repos/{repo}/issues/55/comments?per_page=100&page=1"),
                json!([{
                    "user":{
                        "id":trusted.server_bot_id,
                        "login":trusted.deployment.server_bot_login,
                        "type":"Bot"
                    },
                    "body":format!("<!-- securefix:v3:owner:{head}:{}:101 -->", crate::fixtures::Fixture::control_revision().identity().unwrap())
                }]),
            ),
            Route::get(
                format!("/repos/{repo}/compare/{merge}...{default_branch}"),
                json!({"status":"identical"}),
            ),
            content(".release-version", &merge, version),
            Route::get(
                format!("/repos/{repo}/compare/{merge}...{default_branch}"),
                json!({"status":"identical"}),
            ),
            content(&wrapper_path, &merge, &workflow),
            Route::get(
                format!("/repos/{repo}/git/ref/tags/v1.2.3"),
                json!({"object":{"type":"tag","sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}),
            ),
            Route::get(
                format!("/repos/{repo}/git/tags/{}", "e".repeat(40)),
                json!({"object":{"type":"commit","sha":merge}}),
            ),
        ]
    }

    #[test]
    fn testing_deployment_release_provenance_round_trip() {
        const CHILD: &str = "SECUREFIX_TEST_RELEASE_NAMESPACE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("policy.json");
            let mut policy: Value =
                serde_json::from_slice(include_bytes!("../policy.json")).unwrap();
            policy["deployment"]["workflow_prefix"] = json!("testing-");
            std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "release::tests::testing_deployment_release_provenance_round_trip",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("SECUREFIX_POLICY_PATH", path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        merged_pr_provenance_uses_merged_wrapper_and_verified_version();
        assert!(ensure_valid_caller_path(".github/workflows/testing-release-tag.yml").is_ok());
        assert!(ensure_valid_caller_path(".github/workflows/release-tag.yml").is_err());
    }

    #[test]
    fn merged_pr_provenance_uses_merged_wrapper_and_verified_version() {
        let api = crate::fixtures::Fixture::new(successful_pr_provenance_routes("1.2.3"));
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        validate_source_manifest_provenance(
            &api.api,
            &policy,
            &repo,
            &provenance_test_manifest(),
            ReleaseStrategy::GithubRelease,
        )
        .unwrap();
        api.finish();
    }

    #[test]
    fn merged_pr_provenance_rejects_stale_wrapper_at_merge_commit() {
        let mut routes = successful_pr_provenance_routes_with_wrapper_pin("1.2.3", &"f".repeat(40));
        routes.truncate(9);
        let api = crate::fixtures::Fixture::new(routes);
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let error = validate_source_manifest_provenance(
            &api.api,
            &policy,
            &repo,
            &provenance_test_manifest(),
            ReleaseStrategy::GithubRelease,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("caller must pin one current reusable workflow"),
            "stale merged wrapper was rejected for the wrong reason: {error:#}"
        );
        api.finish();
    }

    #[test]
    fn merged_pr_provenance_rejects_mismatched_version_repository_and_run_sha() {
        let mut wrong_version_routes = successful_pr_provenance_routes("1.2.4");
        wrong_version_routes.truncate(7);
        let api = crate::fixtures::Fixture::new(wrong_version_routes);
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        assert!(
            validate_source_manifest_provenance(
                &api.api,
                &policy,
                &repo,
                &provenance_test_manifest(),
                ReleaseStrategy::GithubRelease,
            )
            .is_err()
        );
        api.finish();

        for (run_repo, run_sha) in [
            ("civitaspo/other", "b".repeat(40)),
            ("civitaspo/terraform-provider-sigma", "f".repeat(40)),
        ] {
            let api = crate::fixtures::Fixture::new(vec![crate::fixtures::Route::get(
                "/repos/civitaspo/terraform-provider-sigma/actions/runs/99",
                json!({
                    "name":"Release Tag",
                    "status":"completed",
                    "conclusion":"success",
                    "repository":{"full_name":run_repo},
                    "head_repository":{"full_name":run_repo},
                    "head_sha":run_sha,
                    "run_attempt":1
                }),
            )]);
            assert!(
                validate_source_manifest_provenance(
                    &api.api,
                    &policy,
                    &repo,
                    &provenance_test_manifest(),
                    ReleaseStrategy::GithubRelease,
                )
                .is_err()
            );
            api.finish();
        }
    }

    #[test]
    fn draft_release_recovery_accepts_only_matching_expected_assets() {
        let expected = vec![
            PlannedAsset {
                name: "one.zip".into(),
                sha256: "a".repeat(64),
                size: None,
            },
            PlannedAsset {
                name: "two.zip".into(),
                sha256: "b".repeat(64),
                size: None,
            },
        ];
        let partial = vec![json!({"name":"one.zip","digest":format!("sha256:{}", "a".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &partial, false).is_ok());
        assert!(validate_release_asset_state(&expected, &partial, true).is_err());
        let mismatch =
            vec![json!({"name":"one.zip","digest":format!("sha256:{}", "c".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &mismatch, false).is_err());
        let unexpected =
            vec![json!({"name":"extra.zip","digest":format!("sha256:{}", "a".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &unexpected, false).is_err());
    }

    #[test]
    fn native_release_assets_require_exact_published_size() {
        let expected = [PlannedAsset {
            name: "herdr-linear-agent-x86_64-unknown-linux-musl".into(),
            sha256: "a".repeat(64),
            size: Some(32),
        }];
        let matching = [expected_release_asset(
            &expected[0].name,
            &expected[0].sha256,
            7,
            32,
        )];
        assert!(validate_release_asset_state(&expected, &matching, true).is_ok());

        let wrong_size = [expected_release_asset(
            &expected[0].name,
            &expected[0].sha256,
            7,
            31,
        )];
        assert!(validate_release_asset_state(&expected, &wrong_size, true).is_err());

        let missing_size = [json!({
            "name": expected[0].name,
            "digest": format!("sha256:{}", expected[0].sha256),
            "id": 7
        })];
        assert!(validate_release_asset_state(&expected, &missing_size, true).is_err());
    }

    #[test]
    fn post_publish_verification_rejects_a_mutable_release() {
        use crate::fixtures::{Fixture, Route};

        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let api = Fixture::new(vec![Route::get(
            "/repos/civitaspo/terraform-provider-sigma/releases/42",
            json!({"id":42,"tag_name":"v1.2.3","draft":false,"immutable":false}),
        )]);
        let published: Value = api
            .api
            .get("/repos/civitaspo/terraform-provider-sigma/releases/42")
            .unwrap();
        assert!(ensure_published_immutable_release(&published, 42, &tag).is_err());
        api.finish();
    }

    fn native_client_snapshot_fixture() -> NativeClientPackageSnapshot {
        NativeClientPackageSnapshot {
            distributor_repository: "civitaspo/securefix-server".into(),
            distributor_id: 1_250_079_425,
            release_repository: "civitaspo/securefix-server".into(),
            release_repository_id: 1_250_079_425,
            implementation_sha: "1".repeat(40),
            implementation_version: "1.0.0".into(),
            loader_action_sha: "2".repeat(40),
            loader_action_path: ".github/actions/load-package".into(),
            binary_source_sha: "3".repeat(40),
            binary_version: "1.0.0".into(),
            protocol: "securefix-native-request/v1".into(),
            release_tag: "v1.0.0".into(),
            release_id: 100,
            asset_id: 101,
            asset_name: "securefix-linux-x86_64".into(),
            asset_size: 1024,
            asset_sha256: "a".repeat(64),
            package_publisher_workflow: ".github/workflows/publish-native-package.yml".into(),
            package_publisher_branch: "main".into(),
            package_publisher_sha: "4".repeat(40),
            package_publisher_run_id: 202,
            package_publisher_run_attempt: 1,
            package_producer_workflow: ".github/workflows/native-package-build.yml".into(),
            package_producer_branch: "main".into(),
            package_producer_run_id: 201,
            package_producer_run_attempt: 1,
        }
    }

    #[test]
    fn native_client_snapshot_keeps_package_producer_and_publisher_separate() {
        let snapshot = native_client_snapshot_fixture();

        validate_native_client_package_snapshot_values(&snapshot).unwrap();
        assert_ne!(
            snapshot.package_producer_run_id,
            snapshot.package_publisher_run_id
        );
        assert_ne!(
            snapshot.package_producer_workflow,
            snapshot.package_publisher_workflow
        );

        let mut missing_publisher = snapshot;
        missing_publisher.package_publisher_run_attempt = 0;
        assert!(validate_native_client_package_snapshot_values(&missing_publisher).is_err());
    }
}
