use anyhow::{Context, Result, bail, ensure};
use reqwest::{Method, StatusCode, blocking::Client, redirect::Policy};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::Digest;
use std::{
    collections::BTreeMap,
    fmt,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
const SCRATCH_REPOSITORY: &str = "civitaspo/testing-securefix-server";
pub const NATIVE_POLICY_CHECK_NAME: &str = "securefix-native-request-policy-check";
pub const NATIVE_POLICY_CHECK_TITLE: &str = "Native request slice accepted";
pub const NATIVE_POLICY_CHECK_SUMMARY: &str = "Configured merge capability, owner producer and PR author identities, all PR commit signatures and trusted effective committers, and the exact current PR head and base were verified. Owner-review policy was not evaluated.";
const MAX_AUTHORITY_HISTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_AUTHORITY_DIFF_BYTES: usize = 8 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 4 * 1024;
const MAX_GIT_OPERATION_TIME: Duration = Duration::from_secs(60);
const MAX_AUTHORITY_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE_SCRATCH_ASSET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NATIVE_RELEASE_ASSET_BYTES: u64 = 128 * 1024 * 1024;
const ISOLATED_GIT_PATH: &str = "/usr/bin:/bin";

pub const POLICY_FAILURE_COMMENT_MARKER: &str = "<!-- securefix:v1:policy-check -->";

pub struct NativeScratchTarget<'a> {
    pub mode: NativeScratchMode,
    pub repository: &'a str,
    pub repository_id: u64,
    pub pull_number: u64,
    pub head_sha: &'a str,
    pub head_repository_id: u64,
    pub base_ref: &'a str,
    pub author_id: u64,
    pub author_login: &'a str,
    pub actor_id: u64,
    pub actor_login: &'a str,
    pub request_sha256: &'a str,
    pub server_authority: &'a NativeAuthoritySnapshot,
    pub caller_workflow_path: &'a str,
    pub caller_workflow_sha: &'a str,
    pub client_workflow_epoch: &'a str,
    pub target_policy_control_identity: Option<&'a str>,
    pub destination_branch: Option<&'a str>,
}

/// The exact request label a native Client dispatch may create. The Server
/// authority snapshot must be the one validated from the captured request
/// manifest before this target is constructed.
#[derive(Clone, Copy)]
pub struct NativeClientLabelTarget<'a> {
    pub server_repository: &'a str,
    pub server_authority: &'a NativeAuthoritySnapshot,
    pub client_repository: &'a str,
    pub operation: &'a str,
    pub run_id: u64,
}

/// The one release-request label a Client release producer may create in its
/// captured external Server instance. The token is scoped to the Server
/// repository; the release destination and source run are fixed from the
/// protected instance configuration and current workflow run. The accepted
/// Client distributor remains a separate package-signing authority.
#[derive(Clone, Copy)]
pub struct NativeClientReleaseLabelTarget<'a> {
    pub instance: &'a NativeServerInstanceAuthority,
    pub config_path: &'a str,
    pub release_repository: &'a str,
    pub release_repository_id: u64,
    pub source_run_id: u64,
}

/// A Client release-tag mutation bound to its protected Server instance and
/// one merged, Release-capable application repository PR.
pub struct NativeReleaseTagWriteTarget<'a> {
    pub instance: &'a NativeServerInstanceAuthority,
    pub config_path: &'a str,
    pub repository: &'a str,
    pub repository_id: u64,
    pub release_pr_number: u64,
    pub release_pr_head_sha: &'a str,
    pub release_pr_merge_sha: &'a str,
    pub tag: &'a str,
}

/// A Client metadata-only update of its configured, Server-owned release PR.
#[derive(Clone)]
pub struct NativeReleasePrMetadataTarget {
    pub instance: NativeServerInstanceAuthority,
    pub repository: String,
    pub repository_id: u64,
    pub pull_number: u64,
    pub head_sha: String,
    pub default_branch: String,
    pub workflow_path: String,
    pub workflow_sha: String,
    pub workflow_epoch: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub title: String,
    pub body: String,
}

/// One attested release-metadata artifact applied to the configured release branch.
#[derive(Clone)]
pub struct NativeReleasePreparationTarget {
    pub instance: NativeServerInstanceAuthority,
    pub repository: String,
    pub repository_id: u64,
    pub source_sha: String,
    pub default_branch: String,
    pub release_branch: String,
    pub expected_head: String,
    pub branch_exists: bool,
    pub existing_pull_request: Option<u64>,
    pub workflow_path: String,
    pub workflow_sha: String,
    pub workflow_epoch: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub additions: BTreeMap<String, Vec<u8>>,
    pub deletions: Vec<String>,
    pub commit_message: String,
    pub title: String,
    pub body: String,
    pub client_package: crate::package::VerifiedNativeClientPackage,
}

#[derive(Clone)]
struct NativeReleasePreparationWrite {
    target: NativeReleasePreparationTarget,
    package: NativeClientPackageIdentity,
    committed_head: Arc<Mutex<Option<String>>>,
}

/// The only production mutations permitted through an external-instance
/// request writer. Release publication has a separate lifecycle and writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInstanceMode {
    PolicyCheck,
    Securefix,
    Approve,
    Merge,
}

impl NativeInstanceMode {
    fn capability(self) -> crate::policy::Capability {
        match self {
            Self::PolicyCheck | Self::Merge => crate::policy::Capability::Merge,
            Self::Securefix => crate::policy::Capability::Securefix,
            Self::Approve => crate::policy::Capability::Approve,
        }
    }

    fn workflow_role(self) -> crate::instance_config::WorkflowRole {
        match self {
            Self::PolicyCheck => crate::instance_config::WorkflowRole::PolicyCheck,
            Self::Securefix => crate::instance_config::WorkflowRole::Securefix,
            Self::Approve => crate::instance_config::WorkflowRole::Approve,
            Self::Merge => crate::instance_config::WorkflowRole::Merge,
        }
    }

    fn scratch_mode(self) -> NativeScratchMode {
        match self {
            Self::PolicyCheck => NativeScratchMode::PolicyCheck,
            Self::Securefix => NativeScratchMode::Securefix,
            Self::Approve => NativeScratchMode::Approval,
            Self::Merge => NativeScratchMode::Merge,
        }
    }
}

/// Values taken from an already authenticated native request. The writer
/// binds every mutation to these identities and rechecks the request head and
/// protected instance authority immediately before the API call.
pub struct NativeInstanceWriteTarget<'a> {
    pub mode: NativeInstanceMode,
    pub config_path: &'a str,
    pub repository: &'a str,
    pub repository_id: u64,
    pub pull_number: u64,
    pub head_sha: &'a str,
    pub head_branch: &'a str,
    pub head_repository_id: u64,
    pub base_sha: &'a str,
    pub base_ref: &'a str,
    pub author_id: u64,
    pub author_login: &'a str,
    pub actor_id: u64,
    pub actor_login: &'a str,
    pub request_sha256: &'a str,
    pub producer_run_id: u64,
    pub producer_run_attempt: u32,
    pub producer_workflow_path: &'a str,
    pub producer_workflow_sha: &'a str,
    pub client_workflow_epoch: &'a str,
    pub merge_fence: Option<&'a NativeInstanceMergeFence>,
}

/// The exact reviewer approval and successful required-check state accepted
/// for one native instance merge. The writer checks this again immediately
/// before the Merge API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeInstanceMergeFence {
    repository: String,
    repository_id: u64,
    pull_number: u64,
    head_sha: String,
    authority_sha256: String,
    approval_review_id: u64,
    approval_request_sha256: String,
    approval_producer_run_id: u64,
    approval_producer_run_attempt: u32,
    reviewer_id: u64,
    reviewer_login: String,
    status_app_id: u64,
    policy_app_id: u64,
}

/// Accepted merge inputs used to capture and later revalidate the same
/// required-check and owner-review state.
pub struct NativeInstanceMergeReadiness<'a> {
    pub repository: &'a str,
    pub repository_id: u64,
    pub pull_number: u64,
    pub head_sha: &'a str,
    pub authority: &'a NativeAuthoritySnapshot,
    pub approval_request_sha256: &'a str,
    pub approval_producer_run_id: u64,
    pub approval_producer_run_attempt: u32,
}

/// One release asset admitted by an already validated immutable release plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReleaseAsset {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub content_type: String,
}

/// Release identities supplied by the source-manifest and plan verifier.
/// The writer re-fetches all remote identities before each mutation.
pub struct NativeReleaseWriteTarget<'a> {
    pub config_path: &'a str,
    pub instance: &'a NativeServerInstanceAuthority,
    pub repository: &'a str,
    pub repository_id: u64,
    pub release_pr_number: u64,
    pub release_pr_head_sha: &'a str,
    pub release_pr_merge_sha: &'a str,
    pub tag: &'a str,
    /// Client destination repository's Release Tag workflow run from the
    /// release manifest. This is distinct from the distributor package run.
    pub release_source_run_id: u64,
    pub release_source_run_attempt: u64,
    pub release_source_run_sha: &'a str,
    /// SHA of the accepted Client `reusable-release-tag.yml` implementation.
    pub release_source_workflow_sha: &'a str,
    /// Schema-2 source manifest already qualified by the release producer.
    pub release_manifest: &'a crate::release_manifest::ReleaseManifestV2,
    /// Exact attested `manifest.json` bytes; the writer binds their digest and
    /// parses them again before authorizing its first mutation.
    pub release_manifest_bytes: &'a [u8],
    /// Client package independently admitted from the configured OSS distributor.
    pub client_package: &'a crate::package::VerifiedNativeClientPackage,
    pub assets: &'a [NativeReleaseAsset],
    /// Native binaries selected by the release plan, keyed to configured targets.
    pub native_assets: &'a [NativeReleaseAsset],
    pub release_id: Option<u64>,
}

/// A package release publication has a single verified executable and a
/// separate protected publisher host. The scratch channel is available only
/// to the explicit owner-selected test path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageReleaseChannel {
    Stable,
    Scratch,
}

/// Read-only result of checking the tag before a package writer is issued.
/// Existing releases are recoverable only when their complete recorded source,
/// producer, publisher authority, and bytes match this exact candidate.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackageReleasePreflightState {
    Create,
    ResumeDraft {
        release_id: u64,
        asset_uploaded: bool,
    },
    AlreadyPublished {
        release_id: u64,
        asset_id: u64,
        publisher_run_id: u64,
        publisher_run_attempt: u64,
    },
}

pub struct PackageReleaseWriteTarget<'a> {
    pub channel: PackageReleaseChannel,
    pub source_repository: &'a str,
    pub source_repository_id: u64,
    pub source_owner_id: u64,
    pub source_branch: &'a str,
    pub source_default_branch: &'a str,
    pub source_sha: &'a str,
    pub source_manifest_sha256: &'a str,
    pub destination_repository: &'a str,
    pub destination_repository_id: u64,
    pub destination_default_branch: &'a str,
    /// Exact protected destination default-branch head observed by the writer.
    /// For stable releases this can be newer than the producer's source SHA.
    pub destination_branch_sha: &'a str,
    /// Exact commit selected by the release tag. Stable releases bind this to
    /// the producer source SHA; scratch releases bind it to the destination
    /// branch head captured for the test publication.
    pub destination_target_sha: &'a str,
    pub version: &'a str,
    pub tag: &'a str,
    pub asset_name: &'a str,
    pub asset_size: u64,
    pub asset_sha256: &'a str,
    pub max_asset_bytes: u64,
    pub producer_workflow: &'a str,
    pub producer_run_id: u64,
    pub producer_run_attempt: u64,
    pub producer_artifact_id: u64,
    pub producer_artifact_size: u64,
    pub producer_artifact_sha256: &'a str,
    pub publisher_workflow: &'a str,
    pub publisher_sha: &'a str,
    pub publisher_branch: &'a str,
    pub publisher_run_id: u64,
    pub publisher_run_attempt: u64,
    pub owner_id: u64,
    pub release_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeScratchMode {
    PolicyCheck,
    Approval,
    Merge,
    Securefix,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthoritySnapshot {
    pub instance_repository: String,
    pub instance_id: u64,
    pub default_branch: String,
    pub config_path: String,
    pub config_sha256: String,
    pub epoch: String,
    pub workflows: Vec<NativeWorkflowAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeInstancePolicyCheckIdentity {
    pub head_sha: String,
    pub authority_sha256: String,
    pub request_sha256: String,
}

/// The parsed instance configuration and exact protected-main authority used
/// by one ordinary Server operation. Callers must re-capture this snapshot
/// before any protected write; the configuration fields are claims until the
/// capture method authenticates them against GitHub's repository APIs.
#[derive(Debug, Clone)]
pub struct NativeServerInstanceAuthority {
    pub config: crate::instance_config::InstanceConfig,
    pub config_bytes: Vec<u8>,
    pub authority: NativeAuthoritySnapshot,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkflowAuthority {
    pub role: crate::instance_config::WorkflowRole,
    pub path: String,
    pub sha256: String,
    pub pins: Vec<String>,
}

/// One reviewable managed-file PR, selected from protected instance sources.
/// This writer never changes repository administration settings or merges PRs.
#[derive(Debug, Clone)]
pub struct NativeManagedFilesTarget {
    pub instance: NativeServerInstanceAuthority,
    pub repository: String,
    pub repository_id: u64,
    pub default_branch: String,
    pub base_sha: String,
    pub branch: String,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub additions: BTreeMap<String, Vec<u8>>,
    pub deletions: Vec<String>,
}

/// Administrator reconciliation is independent of the workflow PR writer.
#[derive(Debug, Clone)]
pub struct NativeRepositorySettingsTarget {
    pub instance: NativeServerInstanceAuthority,
    pub repository: String,
    pub repository_id: u64,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub repository_settings: Value,
    pub rulesets: BTreeMap<String, Value>,
    pub collaborator: Value,
}

#[derive(Clone)]
struct NativeManagedFilesWrite {
    target: NativeManagedFilesTarget,
    committed_head: Arc<Mutex<Option<String>>>,
}

#[derive(Clone)]
enum WriteContext {
    ReadOnly,
    NativeManagedFiles(Box<NativeManagedFilesWrite>),
    NativeRepositorySettings(Box<NativeRepositorySettingsTarget>),
    ClientLabel {
        server: String,
    },
    NativeClientLabel {
        server: String,
        name: String,
        description: String,
    },
    NativeClientReleaseLabel(Box<NativeClientReleaseLabelWrite>),
    NativeReleaseTag(Box<NativeReleaseTagWrite>),
    NativeReleasePrMetadata(Box<NativeReleasePrMetadataTarget>),
    NativeReleasePreparation(Box<NativeReleasePreparationWrite>),
    Production {
        revision: Option<String>,
        control_id: Option<String>,
    },
    Scratch {
        candidate_sha: String,
    },
    PackageScratch {
        candidate_sha: String,
        destination_repository: String,
        destination_repository_id: u64,
        tag: String,
        asset_name: String,
        max_asset_bytes: u64,
        release_id: Option<u64>,
    },
    PackageRelease(Box<PackageReleaseWrite>),
    NativeScratch(Box<NativeScratchWrite>),
    NativeInstance(Box<NativeInstanceWrite>),
    NativeRelease(Box<NativeReleaseWrite>),
    NativeReleaseCleanup {
        instance: Box<NativeServerInstanceAuthority>,
        label: String,
    },
}

#[derive(Clone)]
struct NativeScratchWrite {
    mode: NativeScratchMode,
    instance_repository: String,
    instance_id: u64,
    instance_owner_id: u64,
    default_branch: String,
    config_path: String,
    config_bytes: Vec<u8>,
    server_authority: NativeAuthoritySnapshot,
    target_repository: String,
    target_id: u64,
    pull_number: u64,
    head_sha: String,
    head_repository_id: u64,
    base_ref: String,
    author_id: u64,
    author_login: String,
    actor_id: u64,
    actor_login: String,
    request_sha256: String,
    caller_workflow_path: String,
    caller_workflow_sha: String,
    client_workflow_epoch: String,
    target_policy_control_identity: Option<String>,
    destination_branch: Option<String>,
}

#[derive(Clone)]
struct NativeInstanceWrite {
    mode: NativeInstanceMode,
    instance_repository: String,
    instance_id: u64,
    default_branch: String,
    config_path: String,
    config_bytes: Vec<u8>,
    server_authority: NativeAuthoritySnapshot,
    target_repository: String,
    target_id: u64,
    pull_number: u64,
    head_sha: String,
    head_branch: String,
    head_repository_id: u64,
    base_sha: String,
    base_ref: String,
    author_id: u64,
    author_login: String,
    actor_id: u64,
    actor_login: String,
    request_sha256: String,
    producer_run_id: u64,
    producer_run_attempt: u32,
    producer_workflow_path: String,
    producer_workflow_sha: String,
    client_workflow_epoch: String,
    merge_fence: Option<NativeInstanceMergeFence>,
}

#[derive(Clone)]
struct NativeReleaseWrite {
    instance_repository: String,
    instance_id: u64,
    default_branch: String,
    config_path: String,
    config_bytes: Vec<u8>,
    server_authority: NativeAuthoritySnapshot,
    target_repository: String,
    target_id: u64,
    target_default_branch: String,
    release_pr_number: u64,
    release_pr_head_sha: String,
    release_pr_merge_sha: String,
    tag: String,
    release_source_run_id: u64,
    release_source_run_attempt: u64,
    release_source_run_sha: String,
    release_source_workflow_sha: String,
    release_manifest: crate::release_manifest::ReleaseManifestV2,
    release_manifest_bytes: Vec<u8>,
    release_manifest_sha256: String,
    client_package: NativeClientPackageIdentity,
    assets: Vec<NativeReleaseAsset>,
    native_assets: Vec<NativeReleaseAsset>,
    release_id: Option<u64>,
}

#[derive(Clone)]
struct PackageReleaseWrite {
    channel: PackageReleaseChannel,
    source_repository: String,
    source_repository_id: u64,
    source_owner_id: u64,
    source_branch: String,
    source_default_branch: String,
    source_sha: String,
    source_manifest_sha256: String,
    destination_repository: String,
    destination_repository_id: u64,
    destination_default_branch: String,
    destination_branch_sha: String,
    destination_target_sha: String,
    version: String,
    tag: String,
    asset_name: String,
    asset_size: u64,
    asset_sha256: String,
    max_asset_bytes: u64,
    producer_workflow: String,
    producer_run_id: u64,
    producer_run_attempt: u64,
    producer_artifact_id: u64,
    producer_artifact_size: u64,
    producer_artifact_sha256: String,
    publisher_workflow: String,
    publisher_sha: String,
    publisher_branch: String,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
    owner_id: u64,
    preflight_state: PackageReleasePreflightState,
    recovery_body_updated: bool,
    release_id: Option<u64>,
}

#[derive(Clone)]
struct NativeClientReleaseLabelWrite {
    instance: NativeServerInstanceAuthority,
    config_path: String,
    server_repository: String,
    server_repository_id: u64,
    release_repository: String,
    release_repository_id: u64,
    release_request_label_prefix: String,
    source_run_id: u64,
    name: String,
    description: String,
}

#[derive(Clone)]
struct NativeReleaseTagWrite {
    instance: NativeServerInstanceAuthority,
    config_path: String,
    repository: String,
    repository_id: u64,
    release_pr_number: u64,
    release_pr_head_sha: String,
    release_pr_merge_sha: String,
    tag: String,
    source_run_id: u64,
    tag_object_sha: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeClientPackageIdentity {
    distributor_repository: String,
    distributor_id: u64,
    release_repository: String,
    release_repository_id: u64,
    implementation_sha: String,
    implementation_version: String,
    loader_action_sha: String,
    loader_action_path: String,
    binary_source_sha: String,
    binary_version: String,
    protocol: String,
    release_tag: String,
    release_id: u64,
    asset_id: u64,
    asset_name: String,
    asset_size: u64,
    asset_sha256: String,
    publisher_workflow: String,
    publisher_branch: String,
    publisher_sha: String,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
    producer_workflow: String,
    producer_branch: String,
    producer_run_id: u64,
    producer_run_attempt: u64,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub method: Method,
    pub path: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GitHub {} {} returned {}",
            self.method, self.path, self.status
        )
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
pub struct GitHub {
    client: Client,
    token: String,
    write_token: Option<String>,
    base: String,
    writes: WriteContext,
}

impl GitHub {
    pub fn client_from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::ClientLabel {
            server: crate::config::trusted()?
                .deployment
                .server
                .repository
                .clone(),
        };
        Ok(api)
    }

    /// Create a write-scoped Client API connection for one exact native
    /// request label. The route and request body are both fixed from the
    /// validated request manifest identities.
    pub fn native_client_label_from_env(
        name: &str,
        target: &NativeClientLabelTarget<'_>,
    ) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let (label, description) = validate_native_client_label_target(target)?;
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::NativeClientLabel {
            server: target.server_repository.to_owned(),
            name: label,
            description,
        };
        Ok(api)
    }
    /// Create a Server-scoped writer for the exact native release request
    /// label belonging to the current Client workflow run.
    pub fn native_client_release_label_from_env(
        name: &str,
        target: &NativeClientReleaseLabelTarget<'_>,
    ) -> Result<Self> {
        let write = validate_native_client_release_label_target(target)?;
        validate_native_client_release_label_execution(&write)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let api = Self::new("https://api.github.com", token)?;
        require_single_repository_installation(
            &api,
            write.server_repository_id,
            &write.server_repository,
        )?;
        let mut api = api;
        api.writes = WriteContext::NativeClientReleaseLabel(Box::new(write));
        Ok(api)
    }

    /// Create a Client-repository-scoped writer for one annotated release tag.
    /// Every mutation is checked against the captured Server authority and the
    /// current merged PR immediately before the API request.
    pub fn native_release_tag_from_env(
        name: &str,
        target: &NativeReleaseTagWriteTarget<'_>,
    ) -> Result<Self> {
        let source_run_id = std::env::var("GITHUB_RUN_ID")
            .context("missing GITHUB_RUN_ID for native release tag")?
            .parse::<u64>()
            .context("invalid GITHUB_RUN_ID for native release tag")?;
        let mut write = validate_native_release_tag_target(target, source_run_id)?;
        validate_native_release_tag_execution(&write)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let api = Self::new("https://api.github.com", token)?;
        require_single_repository_installation(&api, write.repository_id, &write.repository)?;
        write.tag_object_sha = Arc::new(Mutex::new(None));
        let mut api = api;
        api.writes = WriteContext::NativeReleaseTag(Box::new(write));
        Ok(api)
    }

    pub fn native_release_preparation_from_env(
        read_name: &str,
        write_name: &str,
        mut target: NativeReleasePreparationTarget,
    ) -> Result<Self> {
        target.instance.config =
            crate::instance_config::InstanceConfig::parse(&target.instance.config_bytes)?;
        validate_native_release_preparation_target(&target)?;
        let package =
            native_client_package_identity(&target.instance.config, &target.client_package)?;
        let mut api = Self::from_env(read_name)?;
        require_single_repository_installation(&api, target.repository_id, &target.repository)?;
        let token = std::env::var(write_name).with_context(|| format!("missing {write_name}"))?;
        ensure!(!token.is_empty(), "{write_name} is empty");
        let writer = Self::new("https://api.github.com", token.clone())?;
        require_single_repository_installation(&writer, target.repository_id, &target.repository)?;
        api.write_token = Some(token);
        api.writes =
            WriteContext::NativeReleasePreparation(Box::new(NativeReleasePreparationWrite {
                target,
                package,
                committed_head: Arc::new(Mutex::new(None)),
            }));
        api.require_current_revision()?;
        Ok(api)
    }

    pub fn native_release_pr_metadata_from_env(
        name: &str,
        target: NativeReleasePrMetadataTarget,
    ) -> Result<Self> {
        validate_native_release_pr_metadata_target(&target)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        require_single_repository_installation(&api, target.repository_id, &target.repository)?;
        api.writes = WriteContext::NativeReleasePrMetadata(Box::new(target));
        Ok(api)
    }

    pub fn from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::Production {
            revision: std::env::var("SECUREFIX_SOURCE_SHA").ok(),
            control_id: std::env::var("SECUREFIX_CONTROL_ID").ok(),
        };
        Ok(api)
    }

    pub fn anonymous() -> Result<Self> {
        Self::new("https://api.github.com", String::new())
    }

    pub fn native_release_cleanup_from_env(
        name: &str,
        instance: &NativeServerInstanceAuthority,
        label: &str,
    ) -> Result<Self> {
        validate_native_release_cleanup_event(&instance.config, label, &crate::event()?)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::NativeReleaseCleanup {
            instance: Box::new(instance.clone()),
            label: label.to_owned(),
        };
        Ok(api)
    }

    pub fn new(base: &str, token: String) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        let retry_host = reqwest::Url::parse(&base)?
            .host_str()
            .context("GitHub API base URL has no host")?
            .to_owned();
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(Policy::none())
                .retry(
                    reqwest::retry::for_host(retry_host)
                        .max_retries_per_request(1)
                        .classify_fn(|request| {
                            let safe_method =
                                matches!(request.method(), &Method::GET | &Method::HEAD);
                            let transient_failure = request
                                .error()
                                .and_then(|error| error.downcast_ref::<reqwest::Error>())
                                .is_some_and(|error| error.is_request() || error.is_connect())
                                || request
                                    .status()
                                    .is_some_and(|status| status.is_server_error());
                            if safe_method && transient_failure {
                                request.retryable()
                            } else {
                                request.success()
                            }
                        }),
                )
                .build()?,
            base,
            token,
            write_token: None,
            writes: WriteContext::ReadOnly,
        })
    }

    pub fn with_runtime_revision(mut self, revision: &str) -> Result<Self> {
        crate::policy::validate_sha(revision)?;
        self.writes = WriteContext::Production {
            revision: Some(revision.to_owned()),
            control_id: std::env::var("SECUREFIX_CONTROL_ID").ok(),
        };
        Ok(self)
    }

    pub fn with_control_revision(
        mut self,
        control: &crate::control::ControlRevision,
    ) -> Result<Self> {
        self.writes = WriteContext::Production {
            revision: Some(control.source_sha.clone()),
            control_id: Some(control.identity()?),
        };
        Ok(self)
    }

    pub fn native_managed_files_from_env(
        token_name: &str,
        target: NativeManagedFilesTarget,
    ) -> Result<Self> {
        validate_native_managed_files_target(&target)?;
        let mut api = Self::from_env(token_name)?;
        require_single_repository_installation(&api, target.repository_id, &target.repository)?;
        api.writes = WriteContext::NativeManagedFiles(Box::new(NativeManagedFilesWrite {
            target,
            committed_head: Arc::new(Mutex::new(None)),
        }));
        api.require_current_revision()?;
        Ok(api)
    }

    fn require_native_managed_files_current(&self, write: &NativeManagedFilesWrite) -> Result<()> {
        let target = &write.target;
        validate_native_managed_files_target(target)?;
        self.require_native_settings_source_current(&target.instance, &target.source_files)?;
        let repository: Value = self.get_uncached(&format!("/repos/{}", target.repository))?;
        ensure!(
            repository["id"].as_u64() == Some(target.repository_id)
                && repository["full_name"] == target.repository
                && repository["default_branch"] == target.default_branch,
            "managed-file destination identity changed"
        );
        ensure!(
            current_branch_sha(self, &target.repository, &target.default_branch)?
                == target.base_sha,
            "managed-file destination default branch changed"
        );
        if let Some(head) = write
            .committed_head
            .lock()
            .map_err(|_| anyhow::anyhow!("managed commit state poisoned"))?
            .as_ref()
        {
            ensure!(
                current_branch_sha(self, &target.repository, &target.branch)? == *head,
                "managed-file signed branch changed before PR creation"
            );
        }
        Ok(())
    }

    fn require_native_settings_source_current(
        &self,
        instance_authority: &NativeServerInstanceAuthority,
        source_files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        let instance = &instance_authority.config.instance;
        let settings_path = instance_authority
            .config
            .workflow_roles
            .get(&crate::instance_config::WorkflowRole::Settings)
            .context("managed-file settings workflow role is missing")?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(instance.repository.as_str())
                && std::env::var("GITHUB_REF").as_deref()
                    == Ok(format!("refs/heads/{}", instance.default_branch).as_str())
                && std::env::var("GITHUB_WORKFLOW_REF").as_deref()
                    == Ok(format!(
                        "{}/{}@refs/heads/{}",
                        instance.repository, settings_path, instance.default_branch
                    )
                    .as_str())
                && matches!(
                    std::env::var("GITHUB_EVENT_NAME").as_deref(),
                    Ok("schedule" | "workflow_dispatch")
                ),
            "managed-file writes require the protected repository-settings workflow"
        );
        if std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch") {
            ensure!(
                std::env::var("GITHUB_ACTOR_ID")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    == Some(instance_authority.config.identities.owner.id),
                "managed-file dispatch requires the configured owner"
            );
        }
        let server = Self::from_env("GITHUB_TOKEN")?;
        server.require_remote_native_server_instance_authority_unchanged(instance_authority)?;
        let revision = current_branch_sha(&server, &instance.repository, &instance.default_branch)?;
        for (path, expected) in source_files {
            ensure!(
                server.content_uncached(&instance.repository, path, &revision)? == *expected,
                "managed-file protected source changed: {path}"
            );
        }
        let workflow_sha =
            std::env::var("GITHUB_WORKFLOW_SHA").context("missing settings workflow SHA")?;
        crate::policy::validate_sha(&workflow_sha)?;
        ensure!(
            server.content_uncached(&instance.repository, settings_path, &workflow_sha)?
                == *source_files
                    .get(settings_path)
                    .context("missing settings workflow source")?,
            "executing settings workflow differs from protected source"
        );
        Ok(())
    }

    pub fn native_repository_settings_from_env(
        token_name: &str,
        target: NativeRepositorySettingsTarget,
    ) -> Result<Self> {
        let mut api = Self::from_env(token_name)?;
        api.writes = WriteContext::NativeRepositorySettings(Box::new(target));
        api.require_current_revision()?;
        Ok(api)
    }

    fn require_native_repository_settings_current(
        &self,
        target: &NativeRepositorySettingsTarget,
    ) -> Result<()> {
        let configured = target
            .instance
            .config
            .repositories
            .iter()
            .find(|entry| entry.repository == target.repository && entry.id == target.repository_id)
            .context("settings destination is not configured")?;
        configured
            .policy()
            .require(crate::policy::Capability::Settings)?;
        self.require_native_settings_source_current(&target.instance, &target.source_files)?;
        let owner: Value = self.get_uncached("/user")?;
        let expected = &target.instance.config.identities.owner;
        ensure!(
            owner["login"] == expected.login && owner["id"].as_u64() == Some(expected.id),
            "settings administrator must authenticate as the configured owner"
        );
        let repository: Value = self.get_uncached(&format!("/repos/{}", target.repository))?;
        ensure!(
            repository["id"].as_u64() == Some(target.repository_id)
                && repository["full_name"] == target.repository
                && repository["owner"]["id"].as_u64()
                    == Some(target.instance.config.identities.repository_owner.id),
            "settings destination identity changed"
        );
        Ok(())
    }

    fn require_native_repository_settings_body(
        &self,
        target: &NativeRepositorySettingsTarget,
        method: &Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<()> {
        let root = format!("/repos/{}", target.repository);
        let expected = if *method == Method::PATCH && path == root {
            &target.repository_settings
        } else if *method == Method::PUT && path == format!("{root}/immutable-releases") {
            ensure!(
                target
                    .instance
                    .config
                    .repositories
                    .iter()
                    .any(|entry| entry.repository == target.repository
                        && entry
                            .capabilities
                            .contains(&crate::policy::Capability::Release))
                    || target.repository == target.instance.config.instance.repository,
                "immutable release update requires release capability"
            );
            ensure!(
                body == Some(&serde_json::json!({})),
                "immutable release request must enable only"
            );
            return Ok(());
        } else if *method == Method::PUT
            && path
                == format!(
                    "{root}/collaborators/{}",
                    target.instance.config.identities.approval_reviewer.login
                )
        {
            &target.collaborator
        } else if *method == Method::POST && path == format!("{root}/rulesets") {
            let value = body.context("settings ruleset body missing")?;
            let name = value["name"]
                .as_str()
                .context("settings ruleset name missing")?;
            ensure!(
                name != "controlled-merges",
                "settings reconcile cannot activate merge controls"
            );
            target
                .rulesets
                .get(name)
                .context("unconfigured settings ruleset")?
        } else if *method == Method::PUT && path.starts_with(&format!("{root}/rulesets/")) {
            let suffix = path.strip_prefix(&format!("{root}/rulesets/")).unwrap();
            ensure!(
                suffix.parse::<u64>().is_ok_and(|id| id > 0),
                "invalid settings ruleset ID"
            );
            let existing: Value = self.get_uncached(path)?;
            ensure!(
                existing["source_type"] == "Repository",
                "settings ruleset is not repository-owned"
            );
            let name = existing["name"]
                .as_str()
                .context("settings ruleset name missing")?;
            ensure!(
                name != "controlled-merges" || existing["enforcement"] == "active",
                "settings reconcile cannot reactivate merge controls"
            );
            target
                .rulesets
                .get(name)
                .context("unconfigured settings ruleset")?
        } else {
            bail!("repository settings writer cannot mutate this endpoint");
        };
        ensure!(
            body == Some(expected),
            "settings request differs from protected desired state"
        );
        Ok(())
    }

    pub fn scratch_from_env(name: &str, candidate_sha: &str) -> Result<Self> {
        crate::policy::validate_sha(candidate_sha)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        let scratch = &crate::config::trusted()?.deployment.integration;
        let installation: Value = api.get("/installation/repositories?per_page=100")?;
        let repositories = installation["repositories"]
            .as_array()
            .context("not an installation token")?;
        ensure!(
            installation["total_count"] == 1
                && repositories.len() == 1
                && repositories[0]["full_name"] == scratch.repository
                && repositories[0]["id"].as_u64() == Some(scratch.id),
            "integration token must be installed only on the scratch repository"
        );
        api.writes = WriteContext::Scratch {
            candidate_sha: candidate_sha.to_owned(),
        };
        Ok(api)
    }

    /// Create a release writer scoped to exactly the configured test repository.
    /// This context accepts only one prerelease tag and one package asset.
    pub fn package_scratch_from_env(
        name: &str,
        candidate_sha: &str,
        tag: &str,
        asset_name: &str,
        max_asset_bytes: u64,
    ) -> Result<Self> {
        crate::policy::validate_sha(candidate_sha)?;
        validate_package_scratch_tag(tag)?;
        validate_package_asset_name(asset_name)?;
        ensure!(
            max_asset_bytes > 0 && max_asset_bytes <= MAX_PACKAGE_SCRATCH_ASSET_BYTES,
            "package scratch asset size limit is invalid"
        );
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let scratch = &crate::config::trusted()?.deployment.integration;
        let api = Self::new("https://api.github.com", token)?;
        require_single_repository_installation(&api, scratch.id, &scratch.repository)?;
        let mut api = api;
        api.writes = WriteContext::PackageScratch {
            candidate_sha: candidate_sha.to_owned(),
            destination_repository: scratch.repository.clone(),
            destination_repository_id: scratch.id,
            tag: tag.to_owned(),
            asset_name: asset_name.to_owned(),
            max_asset_bytes,
            release_id: None,
        };
        Ok(api)
    }

    pub fn package_scratch_allow_release(&mut self, release_id: u64) -> Result<()> {
        ensure!(release_id > 0, "package release ID is invalid");
        let WriteContext::PackageScratch {
            destination_repository,
            tag,
            ..
        } = &self.writes
        else {
            anyhow::bail!("package release writer context is missing");
        };
        let release: Value = self.get(&format!(
            "/repos/{destination_repository}/releases/{release_id}"
        ))?;
        ensure!(
            release["id"].as_u64() == Some(release_id)
                && release["tag_name"] == tag.as_str()
                && release["prerelease"] == true
                && (release["draft"] == true || release["immutable"] == true),
            "package release identity is not the configured scratch prerelease"
        );
        let WriteContext::PackageScratch {
            release_id: allowed,
            ..
        } = &mut self.writes
        else {
            unreachable!("package release writer context changed during validation");
        };
        *allowed = Some(release_id);
        Ok(())
    }

    /// Create a source-bound package release writer. The binary remains data:
    /// this context only verifies, uploads, and publishes its exact bytes.
    pub fn package_release_from_env(
        read_name: &str,
        write_name: &str,
        target: &PackageReleaseWriteTarget<'_>,
    ) -> Result<Self> {
        let preflight_state = Self::package_release_preflight_from_env(
            read_name,
            "SECUREFIX_PACKAGE_READ_TOKEN",
            target,
        )?;
        ensure!(
            !matches!(
                preflight_state,
                PackageReleasePreflightState::AlreadyPublished { .. }
            ),
            "an already-published package release cannot be rewritten"
        );

        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let write_token =
            std::env::var(write_name).with_context(|| format!("missing {write_name}"))?;
        ensure!(!write_token.is_empty(), "{write_name} is empty");
        ensure!(
            read_token != write_token,
            "package read and write tokens must be separate credentials"
        );
        let mut api = Self::new("https://api.github.com", read_token)?;
        let write_reader = Self::new("https://api.github.com", write_token.clone())?;
        require_single_repository_installation(
            &write_reader,
            target.destination_repository_id,
            target.destination_repository,
        )?;
        let source_repository: Value =
            api.get_uncached(&format!("/repos/{}", target.source_repository))?;
        ensure!(
            source_repository["id"].as_u64() == Some(target.source_repository_id)
                && source_repository["full_name"] == target.source_repository
                && source_repository["owner"]["id"].as_u64() == Some(target.source_owner_id)
                && source_repository["default_branch"] == target.source_default_branch,
            "package source repository identity differs from the protected policy"
        );
        let destination_repository: Value =
            write_reader.get_uncached(&format!("/repos/{}", target.destination_repository))?;
        ensure!(
            destination_repository["id"].as_u64() == Some(target.destination_repository_id)
                && destination_repository["full_name"] == target.destination_repository
                && destination_repository["owner"]["id"].as_u64() == Some(target.source_owner_id)
                && destination_repository["default_branch"] == target.destination_default_branch,
            "package release destination differs from the configured repository"
        );
        ensure!(
            write_reader.branch_head(
                target.destination_repository,
                target.destination_default_branch
            )? == target.destination_branch_sha,
            "package release destination branch head moved before publication"
        );
        api.write_token = Some(write_token);
        api.writes = WriteContext::PackageRelease(Box::new(PackageReleaseWrite {
            channel: target.channel,
            source_repository: target.source_repository.to_owned(),
            source_repository_id: target.source_repository_id,
            source_owner_id: target.source_owner_id,
            source_branch: target.source_branch.to_owned(),
            source_default_branch: target.source_default_branch.to_owned(),
            source_sha: target.source_sha.to_owned(),
            source_manifest_sha256: target.source_manifest_sha256.to_owned(),
            destination_repository: target.destination_repository.to_owned(),
            destination_repository_id: target.destination_repository_id,
            destination_default_branch: target.destination_default_branch.to_owned(),
            destination_branch_sha: target.destination_branch_sha.to_owned(),
            destination_target_sha: target.destination_target_sha.to_owned(),
            version: target.version.to_owned(),
            tag: target.tag.to_owned(),
            asset_name: target.asset_name.to_owned(),
            asset_size: target.asset_size,
            asset_sha256: target.asset_sha256.to_owned(),
            max_asset_bytes: target.max_asset_bytes,
            producer_workflow: target.producer_workflow.to_owned(),
            producer_run_id: target.producer_run_id,
            producer_run_attempt: target.producer_run_attempt,
            producer_artifact_id: target.producer_artifact_id,
            producer_artifact_size: target.producer_artifact_size,
            producer_artifact_sha256: target.producer_artifact_sha256.to_owned(),
            publisher_workflow: target.publisher_workflow.to_owned(),
            publisher_sha: target.publisher_sha.to_owned(),
            publisher_branch: target.publisher_branch.to_owned(),
            publisher_run_id: target.publisher_run_id,
            publisher_run_attempt: target.publisher_run_attempt,
            owner_id: target.owner_id,
            preflight_state,
            recovery_body_updated: false,
            release_id: target.release_id,
        }));
        api.require_package_release_current()?;
        Ok(api)
    }

    /// Run all read-only source, publisher, destination, and tag checks using
    /// separate source and destination read clients before minting the App writer.
    pub fn package_release_preflight_from_env(
        read_name: &str,
        destination_read_name: &str,
        target: &PackageReleaseWriteTarget<'_>,
    ) -> Result<PackageReleasePreflightState> {
        validate_package_release_write_target(target)?;
        validate_package_release_publisher_environment(target)?;
        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let api = Self::new("https://api.github.com", read_token.clone())?;
        let destination_token = std::env::var(destination_read_name)
            .with_context(|| format!("missing {destination_read_name}"))?;
        ensure!(
            !destination_token.is_empty(),
            "{destination_read_name} is empty"
        );
        ensure!(
            read_token != destination_token,
            "package source and destination readers must be separate credentials"
        );
        let destination_api = Self::new("https://api.github.com", destination_token)?;
        require_single_repository_installation(
            &destination_api,
            target.destination_repository_id,
            target.destination_repository,
        )?;

        let source: Value = api.get_uncached(&format!("/repos/{}", target.source_repository))?;
        ensure!(
            source["id"].as_u64() == Some(target.source_repository_id)
                && source["full_name"] == target.source_repository
                && source["owner"]["id"].as_u64() == Some(target.source_owner_id)
                && source["default_branch"] == target.source_default_branch,
            "package source repository identity differs from the protected publisher"
        );
        ensure!(
            current_branch_sha(&api, target.source_repository, target.source_default_branch)?
                == target.publisher_sha,
            "protected package publisher branch moved before token issuance"
        );
        match target.channel {
            PackageReleaseChannel::Stable => {
                let comparison: Value = api.get_uncached(&format!(
                    "/repos/{}/compare/{}...{}",
                    target.source_repository, target.source_sha, target.publisher_sha
                ))?;
                crate::package::validate_package_source_ancestor_comparison(
                    &comparison,
                    target.source_sha,
                    target.publisher_sha,
                )?;
            }
            PackageReleaseChannel::Scratch => ensure!(
                current_branch_sha(&api, target.source_repository, target.source_branch)?
                    == target.source_sha,
                "scratch package source branch moved before token issuance"
            ),
        }
        let source_commit: Value = api.get_uncached(&format!(
            "/repos/{}/commits/{}",
            target.source_repository, target.source_sha
        ))?;
        ensure!(
            source_commit["sha"] == target.source_sha
                && source_commit["commit"]["verification"]["verified"] == true
                && source_commit["commit"]["verification"]["reason"] == "valid",
            "package source commit is not GitHub-verified"
        );

        let publisher: Value = api.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            target.source_repository, target.publisher_run_id, target.publisher_run_attempt
        ))?;
        validate_package_release_publisher_run_for_target(target, &publisher)?;

        let destination: Value =
            destination_api.get_uncached(&format!("/repos/{}", target.destination_repository))?;
        ensure!(
            destination["id"].as_u64() == Some(target.destination_repository_id)
                && destination["full_name"] == target.destination_repository
                && destination["owner"]["id"].as_u64() == Some(target.source_owner_id)
                && destination["default_branch"] == target.destination_default_branch,
            "package release destination differs from the protected publisher declaration"
        );
        ensure!(
            current_branch_sha(
                &destination_api,
                target.destination_repository,
                target.destination_default_branch
            )? == target.destination_branch_sha,
            "package release destination branch head moved before token issuance"
        );

        let releases: Vec<Value> = destination_api.paginate_uncached(&format!(
            "/repos/{}/releases",
            target.destination_repository
        ))?;
        let matching: Vec<_> = releases
            .iter()
            .filter(|release| release["tag_name"] == target.tag)
            .collect();
        ensure!(matching.len() <= 1, "package release tag is duplicated");
        let refs: Vec<Value> = destination_api.get_uncached(&format!(
            "/repos/{}/git/matching-refs/tags/{}",
            target.destination_repository,
            encode_path_segment(target.tag)
        ))?;
        let exact_refs: Vec<_> = refs
            .iter()
            .filter(|reference| reference["ref"] == format!("refs/tags/{}", target.tag))
            .collect();
        ensure!(
            exact_refs.len() <= 1,
            "package release tag ref is duplicated"
        );
        let tag_commit = exact_refs
            .first()
            .map(|reference| {
                package_release_tag_ref_commit(
                    &destination_api,
                    target.destination_repository,
                    reference,
                )
            })
            .transpose()?;
        let tag_exists = tag_commit.is_some();
        let Some(release) = matching.first().copied() else {
            ensure!(
                !tag_exists,
                "package release tag already exists without a matching release"
            );
            return Ok(PackageReleasePreflightState::Create);
        };

        let release_id = release["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("existing package release ID is invalid")?;
        let record = parse_package_release_record(release)?;
        validate_package_release_record_for_target(target, &record)?;
        let prior_publisher: Value = api.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            target.source_repository, record.publisher_run_id, record.publisher_run_attempt
        ))?;
        let draft = release["draft"] == true;
        validate_package_release_prior_publisher_run(target, &record, &prior_publisher, draft)?;

        validate_package_release_tag_binding(
            target.destination_target_sha,
            release,
            tag_commit.as_deref(),
        )?;

        if draft {
            validate_package_release_recoverable_draft(target, release, release_id)?;
            let asset_uploaded =
                validate_package_release_recovery_asset(target, &destination_api, release, false)?;
            Ok(PackageReleasePreflightState::ResumeDraft {
                release_id,
                asset_uploaded,
            })
        } else {
            validate_package_release_recoverable_published(target, release, release_id)?;
            ensure!(
                prior_publisher["conclusion"] == "success",
                "immutable package release was not published by a successful recorded publisher run"
            );
            let asset_id = release["assets"][0]["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .context("published package asset ID is invalid")?;
            let asset_uploaded =
                validate_package_release_recovery_asset(target, &destination_api, release, true)?;
            ensure!(asset_uploaded, "published package release asset is missing");
            Ok(PackageReleasePreflightState::AlreadyPublished {
                release_id,
                asset_id,
                publisher_run_id: record.publisher_run_id,
                publisher_run_attempt: record.publisher_run_attempt,
            })
        }
    }

    /// Bind a release ID returned by the exact draft lookup/create call.
    pub fn package_release_select(&mut self, release_id: u64) -> Result<bool> {
        ensure!(release_id > 0, "package release ID is invalid");
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        ensure!(
            write.release_id.is_none(),
            "package release identity has already been selected"
        );
        let writer_token = self
            .write_token
            .as_deref()
            .context("package writer token is missing")?;
        let writer_reader = Self::new("https://api.github.com", writer_token.to_owned())?;
        let release: Value = writer_reader.get_uncached(&format!(
            "/repos/{}/releases/{release_id}",
            write.destination_repository
        ))?;
        let asset_uploaded = release["assets"]
            .as_array()
            .is_some_and(|assets| !assets.is_empty());
        let recovering = matches!(
            write.preflight_state,
            PackageReleasePreflightState::ResumeDraft {
                release_id: expected,
                ..
            } if expected == release_id
        );
        if recovering {
            validate_package_release_draft_recovery_record(write, &release, release_id)?;
            validate_package_release_recovery_asset_for_write(
                write,
                &writer_reader,
                &release,
                false,
            )?;
        } else {
            validate_package_release_draft(write, &release, release_id, false)?;
        }
        let WriteContext::PackageRelease(write) = &mut self.writes else {
            unreachable!("package release writer context changed during selection");
        };
        write.release_id = Some(release_id);
        self.require_package_release_current()?;
        if recovering {
            let (destination_repository, body) = {
                let WriteContext::PackageRelease(write) = &self.writes else {
                    unreachable!("package release writer context changed during recovery");
                };
                (
                    write.destination_repository.clone(),
                    package_release_record_body(write)?,
                )
            };
            let path = format!("/repos/{destination_repository}/releases/{release_id}");
            let _: Value = self.patch(&path, &serde_json::json!({"body": body}))?;
            let WriteContext::PackageRelease(write) = &mut self.writes else {
                unreachable!("package release writer context changed after recovery");
            };
            write.recovery_body_updated = true;
            let rebound: Value = writer_reader.get_uncached(&path)?;
            let WriteContext::PackageRelease(write) = &self.writes else {
                unreachable!("package release writer context changed after recovery");
            };
            validate_package_release_draft(write, &rebound, release_id, false)?;
            self.require_package_release_current()?;
        }
        Ok(asset_uploaded)
    }

    pub fn package_release_create_draft(&self) -> Result<u64> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        ensure!(
            write.release_id.is_none(),
            "package release draft already exists"
        );
        self.require_package_release_current()?;
        if let PackageReleasePreflightState::ResumeDraft { release_id, .. } = write.preflight_state
        {
            return Ok(release_id);
        }
        let target_commitish = if write.channel == PackageReleaseChannel::Scratch {
            write.destination_default_branch.as_str()
        } else {
            write.source_sha.as_str()
        };
        let path = format!("/repos/{}/releases", write.destination_repository);
        let value: Value = self.post(
            &path,
            &serde_json::json!({
                "tag_name": write.tag,
                "name": write.tag,
                "target_commitish": target_commitish,
                "draft": true,
                "prerelease": write.channel == PackageReleaseChannel::Scratch,
                "generate_release_notes": false,
                "body": package_release_record_body(write)?,
            }),
        )?;
        let release_id = value["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("created package draft has no release ID")?;
        Ok(release_id)
    }

    /// Return the one upload URL accepted for the selected package draft. Keep
    /// URL construction beside the validator so the publisher caller cannot
    /// drift from the API writer's exact target contract.
    pub fn package_release_asset_upload_endpoint(&self) -> Result<String> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        let release_id = write
            .release_id
            .context("package release draft identity is missing")?;
        let url = format!(
            "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
            write.destination_repository, write.asset_name
        );
        package_release_upload_url(write, &url)?;
        Ok(url)
    }

    pub fn package_release_publish_draft(&self) -> Result<Value> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        let release_id = write.release_id.context("package release ID is missing")?;
        self.package_release_ensure_tag()?;
        let path = format!(
            "/repos/{}/releases/{release_id}",
            write.destination_repository
        );
        self.patch(&path, &serde_json::json!({"draft": false}))
    }

    /// Create or verify the exact lightweight package tag before publishing.
    /// GitHub can create a draft release without creating its tag ref, so a
    /// tagless draft is valid only while it remains unpublished.
    fn package_release_ensure_tag(&self) -> Result<()> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        ensure!(write.release_id.is_some(), "package release ID is missing");
        self.require_package_release_current()?;

        let writer_reader = self.package_writer_reader()?;
        if let Some(commit) =
            optional_current_tag_commit(&writer_reader, &write.destination_repository, &write.tag)?
        {
            ensure!(
                commit == write.destination_target_sha,
                "package release tag does not target the exact destination commit"
            );
            return self.package_release_require_exact_tag();
        }

        let path = format!("/repos/{}/git/refs", write.destination_repository);
        self.post::<Value>(
            &path,
            &serde_json::json!({
                "ref": format!("refs/tags/{}", write.tag),
                "sha": write.destination_target_sha,
            }),
        )?;
        self.package_release_require_exact_tag()
    }

    fn package_release_require_exact_tag(&self) -> Result<()> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        self.require_package_release_current()?;
        let writer_reader = self.package_writer_reader()?;
        let tag_commit =
            optional_current_tag_commit(&writer_reader, &write.destination_repository, &write.tag)?;
        validate_package_release_tag_for_publish(
            &write.destination_target_sha,
            tag_commit.as_deref(),
        )
    }

    /// Confirm that GitHub published the exact immutable package release and
    /// that its only asset still has the producer-verified bytes.
    pub fn package_release_verify_published(&self) -> Result<Value> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        let release_id = write.release_id.context("package release ID is missing")?;
        let writer_reader = self.package_writer_reader()?;
        let release: Value = writer_reader.get_uncached(&format!(
            "/repos/{}/releases/{release_id}",
            write.destination_repository
        ))?;
        validate_package_release_published(write, &release, release_id)?;
        ensure!(
            current_tag_commit(&writer_reader, &write.destination_repository, &write.tag)?
                == write.destination_target_sha,
            "published package tag no longer targets the exact destination commit"
        );
        Ok(release)
    }

    fn package_writer_reader(&self) -> Result<Self> {
        let token = self
            .write_token
            .as_deref()
            .context("package writer token is missing")?;
        Self::new("https://api.github.com", token.to_owned())
    }

    fn require_package_release_current(&self) -> Result<()> {
        let WriteContext::PackageRelease(write) = &self.writes else {
            bail!("package release writer context is missing");
        };
        let target = package_release_write_target(write);
        validate_package_release_write_target(&target)?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.source_repository.as_str())
                && std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch")
                && parse_positive_env("GITHUB_RUN_ID")? == write.publisher_run_id
                && parse_positive_env("GITHUB_RUN_ATTEMPT")? == write.publisher_run_attempt
                && std::env::var("GITHUB_SHA").as_deref() == Ok(write.publisher_sha.as_str())
                && std::env::var("GITHUB_WORKFLOW_SHA").as_deref()
                    == Ok(write.publisher_sha.as_str())
                && std::env::var("GITHUB_REF").as_deref()
                    == Ok(format!("refs/heads/{}", write.publisher_branch).as_str()),
            "package publisher execution identity changed"
        );
        let expected_workflow_ref = format!(
            "{}/{}@refs/heads/{}",
            write.source_repository, write.publisher_workflow, write.publisher_branch
        );
        ensure!(
            std::env::var("GITHUB_WORKFLOW_REF").as_deref() == Ok(expected_workflow_ref.as_str()),
            "package publisher workflow path changed"
        );

        let source: Value = self.get_uncached(&format!("/repos/{}", write.source_repository))?;
        ensure!(
            source["id"].as_u64() == Some(write.source_repository_id)
                && source["full_name"] == write.source_repository
                && source["owner"]["id"].as_u64() == Some(write.source_owner_id)
                && source["default_branch"] == write.source_default_branch,
            "package source repository identity changed"
        );
        let publisher_branch_head =
            current_branch_sha(self, &write.source_repository, &write.source_default_branch)?;
        ensure!(
            publisher_branch_head == write.publisher_sha,
            "protected package publisher branch moved during publication"
        );
        match write.channel {
            PackageReleaseChannel::Stable => {
                let comparison: Value = self.get_uncached(&format!(
                    "/repos/{}/compare/{}...{}",
                    write.source_repository, write.source_sha, write.publisher_sha
                ))?;
                crate::package::validate_package_source_ancestor_comparison(
                    &comparison,
                    &write.source_sha,
                    &write.publisher_sha,
                )?;
            }
            PackageReleaseChannel::Scratch => ensure!(
                current_branch_sha(self, &write.source_repository, &write.source_branch)?
                    == write.source_sha,
                "scratch package source branch moved during publication"
            ),
        }
        let commit: Value = self.get_uncached(&format!(
            "/repos/{}/commits/{}",
            write.source_repository, write.source_sha
        ))?;
        ensure!(
            commit["sha"] == write.source_sha
                && commit["commit"]["verification"]["verified"] == true
                && commit["commit"]["verification"]["reason"] == "valid",
            "package source commit is not GitHub-verified"
        );
        let manifest = self.content_uncached(
            &write.source_repository,
            crate::package::SOURCE_BUILD_MANIFEST_PATH,
            &write.source_sha,
        )?;
        ensure!(
            manifest.len() <= 16 * 1024
                && crate::hex_encode(sha2::Sha256::digest(&manifest))
                    == write.source_manifest_sha256,
            "package source manifest changed during publication"
        );
        let cargo_manifest =
            self.content_uncached(&write.source_repository, "Cargo.toml", &write.source_sha)?;
        crate::package::validate_native_package_release_source(
            &cargo_manifest,
            &manifest,
            &crate::package::NativePackageReleaseSourceBinding {
                source_sha: &write.source_sha,
                version: &write.version,
                producer_workflow: &write.producer_workflow,
                publisher_workflow: &write.publisher_workflow,
                asset_name: &write.asset_name,
                max_asset_bytes: write.max_asset_bytes,
                stable: write.channel == PackageReleaseChannel::Stable,
            },
        )?;
        let producer: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            write.source_repository, write.producer_run_id, write.producer_run_attempt
        ))?;
        validate_package_release_producer_run(write, &producer)?;
        let artifacts: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/artifacts?per_page=100",
            write.source_repository, write.producer_run_id
        ))?;
        validate_package_release_artifact(write, &artifacts)?;

        let publisher: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            write.source_repository, write.publisher_run_id, write.publisher_run_attempt
        ))?;
        validate_package_release_publisher_run(write, &publisher)?;

        let writer_reader = self.package_writer_reader()?;
        require_single_repository_installation(
            &writer_reader,
            write.destination_repository_id,
            &write.destination_repository,
        )?;
        let destination: Value =
            writer_reader.get_uncached(&format!("/repos/{}", write.destination_repository))?;
        ensure!(
            destination["id"].as_u64() == Some(write.destination_repository_id)
                && destination["full_name"] == write.destination_repository
                && destination["owner"]["id"].as_u64() == Some(write.source_owner_id)
                && destination["default_branch"] == write.destination_default_branch,
            "package release destination identity changed"
        );
        ensure!(
            current_branch_sha(
                &writer_reader,
                &write.destination_repository,
                &write.destination_default_branch
            )? == write.destination_branch_sha,
            "package release destination branch head moved"
        );
        let releases: Vec<Value> = writer_reader
            .paginate_uncached(&format!("/repos/{}/releases", write.destination_repository))?;
        let matching: Vec<_> = releases
            .iter()
            .filter(|release| release["tag_name"] == write.tag)
            .collect();
        ensure!(matching.len() <= 1, "package release tag is duplicated");
        let refs: Vec<Value> = writer_reader.get_uncached(&format!(
            "/repos/{}/git/matching-refs/tags/{}",
            write.destination_repository,
            encode_path_segment(&write.tag)
        ))?;
        let exact_refs: Vec<_> = refs
            .iter()
            .filter(|reference| reference["ref"] == format!("refs/tags/{}", write.tag))
            .collect();
        ensure!(
            exact_refs.len() <= 1,
            "package release tag ref is duplicated"
        );
        let tag_commit = exact_refs
            .first()
            .map(|reference| {
                package_release_tag_ref_commit(
                    &writer_reader,
                    &write.destination_repository,
                    reference,
                )
            })
            .transpose()?;
        let tag_exists = tag_commit.is_some();
        if let Some(release_id) = write.release_id {
            let release: Value = writer_reader.get_uncached(&format!(
                "/repos/{}/releases/{release_id}",
                write.destination_repository
            ))?;
            let recovering_old_record = matches!(
                write.preflight_state,
                PackageReleasePreflightState::ResumeDraft {
                    release_id: expected,
                    ..
                } if expected == release_id
            ) && !write.recovery_body_updated;
            if recovering_old_record {
                validate_package_release_draft_recovery_record(write, &release, release_id)?;
                validate_package_release_recovery_asset_for_write(
                    write,
                    &writer_reader,
                    &release,
                    false,
                )?;
            } else {
                let require_asset = release["assets"]
                    .as_array()
                    .is_some_and(|assets| !assets.is_empty());
                validate_package_release_draft(write, &release, release_id, require_asset)?;
            }
            ensure!(
                matching.len() == 1 && matching[0]["id"].as_u64() == Some(release_id),
                "selected package draft is no longer unique"
            );
            validate_package_release_tag_binding(
                &write.destination_target_sha,
                &release,
                tag_commit.as_deref(),
            )?;
        } else {
            match write.preflight_state {
                PackageReleasePreflightState::Create => ensure!(
                    matching.is_empty() && !tag_exists,
                    "package release tag already exists without an authorized recovery"
                ),
                PackageReleasePreflightState::ResumeDraft { release_id, .. } => {
                    ensure!(
                        matching.len() == 1 && matching[0]["id"].as_u64() == Some(release_id),
                        "recoverable package draft is no longer unique"
                    );
                    let release = matching[0];
                    validate_package_release_draft_recovery_record(write, release, release_id)?;
                    validate_package_release_tag_binding(
                        &write.destination_target_sha,
                        release,
                        tag_commit.as_deref(),
                    )?;
                    validate_package_release_recovery_asset_for_write(
                        write,
                        &writer_reader,
                        release,
                        false,
                    )?;
                }
                PackageReleasePreflightState::AlreadyPublished { .. } => {
                    bail!("an already-published package release cannot be rewritten")
                }
            }
        }
        Ok(())
    }

    /// Create an ordinary instance-bound request writer. This context is
    /// separate from the owner-only scratch writer and the legacy runtime
    /// writer. The supplied instance must have been captured from protected
    /// main and the request must already have passed its operation verifier.
    pub fn native_instance_from_env(
        read_name: &str,
        write_name: &str,
        instance: &NativeServerInstanceAuthority,
        target: &NativeInstanceWriteTarget<'_>,
    ) -> Result<Self> {
        validate_instance_config_path(target.config_path)?;
        validate_native_authority_snapshot(&instance.authority)?;
        let config = crate::instance_config::InstanceConfig::parse(&instance.config_bytes)?;
        validate_native_instance_write_target(&config, target)?;
        ensure!(
            instance.authority.instance_repository == config.instance.repository
                && instance.authority.instance_id == config.instance.id
                && instance.authority.default_branch == config.instance.default_branch
                && instance.authority.config_path == target.config_path
                && instance.authority.config_sha256
                    == crate::hex_encode(sha2::Sha256::digest(&instance.config_bytes)),
            "native Server instance snapshot does not match its protected configuration"
        );
        validate_native_instance_merge_fence_target(&config, &instance.authority, target)?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref()
                == Ok(config.instance.repository.as_str()),
            "native Server instance differs from the current job repository"
        );
        let expected_ref = format!("refs/heads/{}", config.instance.default_branch);
        ensure!(
            std::env::var("GITHUB_REF").as_deref() == Ok(expected_ref.as_str()),
            "native Server writer must execute from the protected instance branch"
        );

        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let write_token =
            std::env::var(write_name).with_context(|| format!("missing {write_name}"))?;
        ensure!(!write_token.is_empty(), "{write_name} is empty");
        let mut api = Self::new("https://api.github.com", read_token)?;
        require_single_repository_installation(&api, target.repository_id, target.repository)?;
        let write_api = Self::new("https://api.github.com", write_token.clone())?;
        if target.mode == NativeInstanceMode::Approve {
            let reviewer: Value = write_api.get("/user")?;
            ensure!(
                reviewer["id"].as_u64() == Some(config.identities.approval_reviewer.id)
                    && reviewer["login"].as_str()
                        == Some(config.identities.approval_reviewer.login.as_str())
                    && reviewer["type"] == "User",
                "approval token must authenticate as the configured review account"
            );
        } else {
            require_single_repository_installation(
                &write_api,
                target.repository_id,
                target.repository,
            )?;
        }

        let server_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!server_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", server_token)?;
        let (remote_config, current_authority) = server_reader.capture_native_server_authority(
            &config,
            target.config_path,
            &instance.config_bytes,
        )?;
        ensure!(
            remote_config == instance.config_bytes,
            "native Server config does not match the protected default branch"
        );
        require_native_authority_unchanged(&instance.authority, &current_authority)?;

        let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
            .context("missing GITHUB_WORKFLOW_REF for native Server execution")?;
        let workflow_sha = std::env::var("GITHUB_WORKFLOW_SHA")
            .context("missing GITHUB_WORKFLOW_SHA for native Server execution")?;
        let role = target.mode.workflow_role();
        let workflow_path = config
            .workflow_roles
            .get(&role)
            .context("native Server workflow role is not configured")?;
        let workflow_bytes =
            server_reader.content(&config.instance.repository, workflow_path, &workflow_sha)?;
        validate_native_server_execution_workflow(
            &instance.authority,
            target.mode.scratch_mode(),
            &workflow_ref,
            &workflow_sha,
            &workflow_bytes,
        )?;

        api.write_token = Some(write_token);
        api.writes = WriteContext::NativeInstance(Box::new(NativeInstanceWrite {
            mode: target.mode,
            instance_repository: config.instance.repository,
            instance_id: config.instance.id,
            default_branch: config.instance.default_branch,
            config_path: target.config_path.to_owned(),
            config_bytes: instance.config_bytes.clone(),
            server_authority: instance.authority.clone(),
            target_repository: target.repository.to_owned(),
            target_id: target.repository_id,
            pull_number: target.pull_number,
            head_sha: target.head_sha.to_owned(),
            head_branch: target.head_branch.to_owned(),
            head_repository_id: target.head_repository_id,
            base_sha: target.base_sha.to_owned(),
            base_ref: target.base_ref.to_owned(),
            author_id: target.author_id,
            author_login: target.author_login.to_owned(),
            actor_id: target.actor_id,
            actor_login: target.actor_login.to_owned(),
            request_sha256: target.request_sha256.to_owned(),
            producer_run_id: target.producer_run_id,
            producer_run_attempt: target.producer_run_attempt,
            producer_workflow_path: target.producer_workflow_path.to_owned(),
            producer_workflow_sha: target.producer_workflow_sha.to_owned(),
            client_workflow_epoch: target.client_workflow_epoch.to_owned(),
            merge_fence: target.merge_fence.cloned(),
        }));
        if target.mode != NativeInstanceMode::Merge {
            api.require_native_instance_current()?;
        }
        Ok(api)
    }

    /// Create the API writer for one validated release plan. Reads use the
    /// existing read-only installation token; only the exact release draft,
    /// planned assets, and final draft transition use the write token.
    pub fn native_release_from_env(
        read_name: &str,
        write_name: &str,
        instance: &NativeServerInstanceAuthority,
        target: &NativeReleaseWriteTarget<'_>,
    ) -> Result<Self> {
        validate_instance_config_path(target.config_path)?;
        validate_native_authority_snapshot(&instance.authority)?;
        let config = crate::instance_config::InstanceConfig::parse(&instance.config_bytes)?;
        let (client_package, release_manifest_sha256) =
            validate_native_release_target(&config, &instance.authority, target)?;
        ensure!(
            instance.authority.instance_repository == config.instance.repository
                && instance.authority.instance_id == config.instance.id
                && instance.authority.default_branch == config.instance.default_branch
                && instance.authority.config_path == target.config_path
                && instance.authority.config_sha256
                    == crate::hex_encode(sha2::Sha256::digest(&instance.config_bytes)),
            "native Server instance snapshot does not match its protected configuration"
        );
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref()
                == Ok(config.instance.repository.as_str()),
            "native Server release differs from the current job repository"
        );
        let expected_ref = format!("refs/heads/{}", config.instance.default_branch);
        ensure!(
            std::env::var("GITHUB_REF").as_deref() == Ok(expected_ref.as_str()),
            "native Server release writer must execute from the protected instance branch"
        );

        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let write_token =
            std::env::var(write_name).with_context(|| format!("missing {write_name}"))?;
        ensure!(!write_token.is_empty(), "{write_name} is empty");
        let mut api = Self::new("https://api.github.com", read_token)?;
        require_single_repository_installation(&api, target.repository_id, target.repository)?;
        let write_api = Self::new("https://api.github.com", write_token.clone())?;
        require_single_repository_installation(
            &write_api,
            target.repository_id,
            target.repository,
        )?;

        let server_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!server_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", server_token)?;
        let (remote_config, current_authority) = server_reader.capture_native_server_authority(
            &config,
            target.config_path,
            &instance.config_bytes,
        )?;
        ensure!(
            remote_config == instance.config_bytes,
            "native Server config does not match the protected default branch"
        );
        require_native_authority_unchanged(&instance.authority, &current_authority)?;

        let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
            .context("missing GITHUB_WORKFLOW_REF for native Server release")?;
        let workflow_sha = std::env::var("GITHUB_WORKFLOW_SHA")
            .context("missing GITHUB_WORKFLOW_SHA for native Server release")?;
        let workflow_path = config
            .workflow_roles
            .get(&crate::instance_config::WorkflowRole::Release)
            .context("native Server Release workflow role is not configured")?;
        let workflow_bytes =
            server_reader.content(&config.instance.repository, workflow_path, &workflow_sha)?;
        validate_native_server_execution_workflow_role(
            &instance.authority,
            crate::instance_config::WorkflowRole::Release,
            &workflow_ref,
            &workflow_sha,
            &workflow_bytes,
        )?;

        let repository: Value = api.get_uncached(&format!("/repos/{}", target.repository))?;
        ensure!(
            repository["id"].as_u64() == Some(target.repository_id)
                && repository["full_name"].as_str() == Some(target.repository)
                && repository["default_branch"]
                    .as_str()
                    .is_some_and(|branch| !branch.is_empty()),
            "native release destination repository identity is invalid"
        );
        let default_branch = repository["default_branch"]
            .as_str()
            .context("native release destination has no default branch")?
            .to_owned();

        api.write_token = Some(write_token);
        api.writes = WriteContext::NativeRelease(Box::new(NativeReleaseWrite {
            instance_repository: config.instance.repository,
            instance_id: config.instance.id,
            default_branch: config.instance.default_branch,
            config_path: target.config_path.to_owned(),
            config_bytes: instance.config_bytes.clone(),
            server_authority: instance.authority.clone(),
            target_repository: target.repository.to_owned(),
            target_id: target.repository_id,
            target_default_branch: default_branch,
            release_pr_number: target.release_pr_number,
            release_pr_head_sha: target.release_pr_head_sha.to_owned(),
            release_pr_merge_sha: target.release_pr_merge_sha.to_owned(),
            tag: target.tag.to_owned(),
            release_source_run_id: target.release_source_run_id,
            release_source_run_attempt: target.release_source_run_attempt,
            release_source_run_sha: target.release_source_run_sha.to_owned(),
            release_source_workflow_sha: target.release_source_workflow_sha.to_owned(),
            release_manifest: target.release_manifest.clone(),
            release_manifest_bytes: target.release_manifest_bytes.to_vec(),
            release_manifest_sha256,
            client_package,
            assets: target.assets.to_vec(),
            native_assets: target.native_assets.to_vec(),
            release_id: target.release_id,
        }));
        api.require_native_release_current()?;
        Ok(api)
    }

    /// Bind the release ID returned by the exact draft-create call to this
    /// writer before uploads or publication are permitted.
    pub fn native_release_select(&mut self, release_id: u64) -> Result<()> {
        ensure!(release_id > 0, "native release ID is invalid");
        let WriteContext::NativeRelease(write) = &self.writes else {
            bail!("native release writer context is missing");
        };
        ensure!(
            write
                .release_id
                .is_none_or(|selected| selected == release_id),
            "native release writer already selected a different release"
        );
        let repository = write.target_repository.clone();
        let tag = write.tag.clone();
        let default_branch = write.target_default_branch.clone();
        let release: Value =
            self.get_uncached(&format!("/repos/{}/releases/{release_id}", repository))?;
        let version = semver::Version::parse(tag.strip_prefix('v').unwrap_or_default())?;
        ensure!(
            release["id"].as_u64() == Some(release_id)
                && release["tag_name"] == tag
                && release["name"] == tag
                && release["target_commitish"] == default_branch
                && release["prerelease"] == !version.pre.is_empty()
                && release["draft"] == true,
            "selected native release is not the exact draft"
        );
        let WriteContext::NativeRelease(write) = &mut self.writes else {
            unreachable!("native release writer context changed during selection");
        };
        write.release_id = Some(release_id);
        Ok(())
    }

    /// Create the deliberately narrow writer for the first native request
    /// scratch slice. Every check-run write reauthenticates the installation,
    /// protected configuration snapshot, and exact PR head.
    pub fn native_scratch_from_env(
        read_name: &str,
        write_name: &str,
        config: &crate::instance_config::InstanceConfig,
        config_path: &str,
        config_bytes: &[u8],
        request: &NativeScratchTarget<'_>,
    ) -> Result<Self> {
        validate_instance_config_path(config_path)?;
        crate::policy::validate_repository(request.repository)?;
        crate::policy::validate_sha(request.head_sha)?;
        crate::config::validate_branch(request.base_ref)?;
        ensure!(
            request.repository_id > 0
                && request.pull_number > 0
                && request.head_repository_id > 0
                && request.author_id > 0
                && crate::config::is_valid_login(request.author_login)
                && request.actor_id > 0
                && request.request_sha256.len() == 64
                && request
                    .request_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                && crate::config::is_valid_login(request.actor_login),
            "invalid native scratch target identity"
        );
        ensure!(
            config_bytes.len() <= 256 * 1024,
            "instance config exceeds size limit"
        );
        match (request.mode, request.target_policy_control_identity) {
            (NativeScratchMode::Merge, Some(identity)) => {
                validate_sha256(identity, "native target policy control identity")?;
            }
            (NativeScratchMode::Merge, None) => {
                anyhow::bail!("native merge lacks its target policy control identity")
            }
            (_, None) => {}
            (_, Some(_)) => {
                anyhow::bail!("target policy control identity is only valid for native merge")
            }
        }
        let configured_target = config
            .repositories
            .iter()
            .find(|repository| {
                repository.repository == request.repository
                    && repository.id == request.repository_id
            })
            .context("native request target is not configured")?;
        ensure!(
            configured_target
                .policy()
                .require(match request.mode {
                    NativeScratchMode::PolicyCheck => crate::policy::Capability::Merge,
                    NativeScratchMode::Approval => crate::policy::Capability::Approve,
                    NativeScratchMode::Merge => crate::policy::Capability::Merge,
                    NativeScratchMode::Securefix => crate::policy::Capability::Securefix,
                })
                .is_ok(),
            "native request target lacks the required capability"
        );
        ensure!(
            match request.mode {
                NativeScratchMode::PolicyCheck => request.destination_branch.is_none(),
                NativeScratchMode::Approval => request.destination_branch.is_none(),
                NativeScratchMode::Merge => request.destination_branch.is_none(),
                NativeScratchMode::Securefix => request
                    .destination_branch
                    .is_some_and(|branch| !branch.is_empty()),
            },
            "native request write target is incomplete"
        );
        ensure!(
            config.identities.owner.id == request.actor_id
                && config.identities.owner.login == request.actor_login
                && config.identities.owner.id == request.author_id
                && config.identities.owner.login == request.author_login,
            "native scratch policy requires the configured owner as actor and PR author"
        );
        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            execution_repository == config.instance.repository,
            "native Server instance differs from the current job repository"
        );
        validate_native_test_host_context(config, request.mode)?;
        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let write_token =
            std::env::var(write_name).with_context(|| format!("missing {write_name}"))?;
        ensure!(!write_token.is_empty(), "{write_name} is empty");
        let mut api = Self::new("https://api.github.com", read_token)?;
        require_single_repository_installation(&api, request.repository_id, request.repository)?;
        let write_api = Self::new("https://api.github.com", write_token.clone())?;
        if request.mode == NativeScratchMode::Approval {
            let reviewer: Value = write_api.get("/user")?;
            ensure!(
                reviewer["id"].as_u64() == Some(config.identities.approval_reviewer.id)
                    && reviewer["login"].as_str()
                        == Some(config.identities.approval_reviewer.login.as_str())
                    && reviewer["type"] == "User",
                "approval token must authenticate as the configured review account"
            );
        } else {
            require_single_repository_installation(
                &write_api,
                request.repository_id,
                request.repository,
            )?;
        }
        let read_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!read_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", read_token)?;
        let (remote_config, server_authority) =
            server_reader.capture_native_server_authority(config, config_path, config_bytes)?;
        ensure!(
            remote_config == config_bytes,
            "local native Server config does not match the protected default branch"
        );
        require_native_authority_unchanged(request.server_authority, &server_authority)?;
        api.write_token = Some(write_token);
        api.writes = WriteContext::NativeScratch(Box::new(NativeScratchWrite {
            mode: request.mode,
            instance_repository: config.instance.repository.clone(),
            instance_id: config.instance.id,
            instance_owner_id: config.identities.repository_owner.id,
            default_branch: config.instance.default_branch.clone(),
            config_path: config_path.to_owned(),
            config_bytes: config_bytes.to_vec(),
            server_authority: server_authority.clone(),
            target_repository: request.repository.to_owned(),
            target_id: request.repository_id,
            pull_number: request.pull_number,
            head_sha: request.head_sha.to_owned(),
            head_repository_id: request.head_repository_id,
            base_ref: request.base_ref.to_owned(),
            author_id: request.author_id,
            author_login: request.author_login.to_owned(),
            actor_id: request.actor_id,
            actor_login: request.actor_login.to_owned(),
            request_sha256: request.request_sha256.to_owned(),
            caller_workflow_path: request.caller_workflow_path.to_owned(),
            caller_workflow_sha: request.caller_workflow_sha.to_owned(),
            client_workflow_epoch: request.client_workflow_epoch.to_owned(),
            target_policy_control_identity: request
                .target_policy_control_identity
                .map(str::to_owned),
            destination_branch: request.destination_branch.map(str::to_owned),
        }));
        Ok(api)
    }

    pub fn capture_native_server_authority(
        &self,
        config: &crate::instance_config::InstanceConfig,
        config_path: &str,
        expected_config: &[u8],
    ) -> Result<(Vec<u8>, NativeAuthoritySnapshot)> {
        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            execution_repository == config.instance.repository,
            "native Server instance differs from the current job repository"
        );
        self.capture_native_server_authority_for_repository(
            config,
            config_path,
            expected_config,
            &execution_repository,
        )
    }

    /// Capture a protected Server authority snapshot from a request producer.
    /// The repository and path are only locators here; a consuming Server must
    /// match them to its own authenticated instance and configured path.
    pub fn capture_remote_native_server_authority(
        &self,
        repository_name: &str,
        config_path: &str,
    ) -> Result<(Vec<u8>, NativeAuthoritySnapshot)> {
        crate::policy::validate_repository(repository_name)?;
        validate_instance_config_path(config_path)?;
        let metadata: Value = self.get(&format!("/repos/{repository_name}"))?;
        ensure!(
            metadata["full_name"].as_str() == Some(repository_name),
            "native Server locator does not match repository metadata"
        );
        let repository_id = metadata["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("native Server repository ID is missing")?;
        let default_branch = metadata["default_branch"]
            .as_str()
            .context("native Server default branch is missing")?;
        crate::config::validate_branch(default_branch)?;
        let owner_id = metadata["owner"]["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("native Server owner ID is missing")?;
        let source_sha = self.branch_head(repository_name, default_branch)?;
        let config_bytes = self.content(repository_name, config_path, &source_sha)?;
        let config = crate::instance_config::InstanceConfig::parse(&config_bytes)?;
        ensure!(
            config.instance.repository == repository_name
                && config.instance.id == repository_id
                && config.instance.default_branch == default_branch
                && config.identities.repository_owner.id == owner_id,
            "native Server locator does not match its configuration identity"
        );
        self.capture_native_server_authority_for_repository(
            &config,
            config_path,
            &config_bytes,
            repository_name,
        )
    }

    /// Load an instance configuration only from the repository's current
    /// protected default branch and bind it to the selected operation wrappers.
    /// The caller supplies the repository and root-relative config path as
    /// locators; the returned configuration is usable only with this captured
    /// authority snapshot and the exact bytes it records.
    pub fn capture_remote_native_server_instance_authority(
        &self,
        repository_name: &str,
        config_path: &str,
    ) -> Result<NativeServerInstanceAuthority> {
        let (config_bytes, authority) =
            self.capture_remote_native_server_authority(repository_name, config_path)?;
        let config = crate::instance_config::InstanceConfig::parse(&config_bytes)?;
        ensure!(
            config.instance.repository == authority.instance_repository
                && config.instance.id == authority.instance_id
                && config.instance.default_branch == authority.default_branch
                && authority.config_path == config_path,
            "captured instance config does not match its authenticated authority"
        );
        Ok(NativeServerInstanceAuthority {
            config,
            config_bytes,
            authority,
        })
    }

    /// Reconstruct the protected-main config and role authority and reject a
    /// stale snapshot before the caller performs a protected write.
    pub fn require_remote_native_server_instance_authority_unchanged(
        &self,
        captured: &NativeServerInstanceAuthority,
    ) -> Result<()> {
        let current = self.capture_remote_native_server_instance_authority(
            &captured.authority.instance_repository,
            &captured.authority.config_path,
        )?;
        require_native_server_instance_authority_unchanged(captured, &current)
    }

    fn capture_native_server_authority_for_repository(
        &self,
        config: &crate::instance_config::InstanceConfig,
        config_path: &str,
        expected_config: &[u8],
        execution_repository: &str,
    ) -> Result<(Vec<u8>, NativeAuthoritySnapshot)> {
        validate_instance_config_path(config_path)?;
        ensure!(
            execution_repository == config.instance.repository,
            "native Server instance differs from the authenticated repository"
        );
        let repository: Value = self.get(&format!("/repos/{execution_repository}"))?;
        ensure!(
            repository["id"].as_u64() == Some(config.instance.id)
                && repository["full_name"].as_str() == Some(config.instance.repository.as_str())
                && repository["default_branch"].as_str()
                    == Some(config.instance.default_branch.as_str())
                && repository["owner"]["id"].as_u64()
                    == Some(config.identities.repository_owner.id),
            "native Server instance repository identity mismatch"
        );
        let default_branch = &config.instance.default_branch;
        let branch_path = format!(
            "/repos/{execution_repository}/branches/{}",
            encode_path_segment(default_branch)
        );
        let branch: Value = self.get(&branch_path)?;
        let source_sha = branch["commit"]["sha"]
            .as_str()
            .filter(|sha| crate::policy::validate_sha(sha).is_ok())
            .context("native Server default branch has no commit SHA")?;
        let tree: Value = self.get(&format!(
            "/repos/{execution_repository}/git/trees/{source_sha}?recursive=1"
        ))?;
        ensure!(
            tree["truncated"] == false,
            "native Server default-branch tree is incomplete"
        );
        let entries = tree["tree"]
            .as_array()
            .context("native Server default-branch tree is missing")?;
        let mut paths = vec![config_path.to_owned()];
        for path in config.workflow_roles.values() {
            validate_instance_config_path(path)?;
            paths.push(path.clone());
        }
        paths.sort();
        paths.dedup();
        for path in &paths {
            let matches: Vec<_> = entries
                .iter()
                .filter(|entry| entry["path"].as_str() == Some(path.as_str()))
                .collect();
            ensure!(
                matches.len() == 1
                    && matches[0]["type"] == "blob"
                    && matches[0]["mode"] == "100644",
                "native Server config or role wrapper is missing or not a regular tracked file"
            );
        }
        let remote_config = self.content(execution_repository, config_path, source_sha)?;
        ensure!(
            remote_config == expected_config,
            "native Server config differs from the protected default-branch snapshot"
        );
        let current_config = crate::instance_config::InstanceConfig::parse(&remote_config)?;
        ensure!(
            current_config.instance.repository == config.instance.repository
                && current_config.instance.id == config.instance.id
                && current_config.instance.default_branch == config.instance.default_branch
                && current_config.workflow_roles == config.workflow_roles,
            "native Server workflow-role authority changed"
        );
        let mut workflows = Vec::new();
        for (role, path) in &config.workflow_roles {
            let bytes = self.content(execution_repository, path, source_sha)?;
            ensure!(
                bytes.len() <= 256 * 1024,
                "Server role wrapper exceeds size limit"
            );
            workflows.push(NativeWorkflowAuthority {
                role: *role,
                path: path.clone(),
                sha256: crate::hex_encode(sha2::Sha256::digest(&bytes)),
                pins: workflow_uses_pins(&bytes)?,
            });
        }
        let epoch = first_parent_path_epoch(
            self,
            execution_repository,
            default_branch,
            source_sha,
            &paths,
        )?;
        ensure!(
            self.branch_head(execution_repository, default_branch)? == source_sha,
            "native Server authority ref moved during authority capture"
        );
        let snapshot = NativeAuthoritySnapshot {
            instance_repository: config.instance.repository.clone(),
            instance_id: config.instance.id,
            default_branch: config.instance.default_branch.clone(),
            config_path: config_path.to_owned(),
            config_sha256: crate::hex_encode(sha2::Sha256::digest(&remote_config)),
            epoch,
            workflows,
        };
        Ok((remote_config, snapshot))
    }

    fn require_write_target(&self, method: &Method, path: &str) -> Result<()> {
        if let WriteContext::NativeRepositorySettings(target) = &self.writes {
            let root = format!("/repos/{}", target.repository);
            ensure!(
                (*method == Method::PATCH && path == root)
                    || (*method == Method::POST && path == format!("{root}/rulesets"))
                    || (*method == Method::PUT
                        && (path == format!("{root}/immutable-releases")
                            || path
                                == format!(
                                    "{root}/collaborators/{}",
                                    target.instance.config.identities.approval_reviewer.login
                                )
                            || path.strip_prefix(&format!("{root}/rulesets/")).is_some_and(
                                |suffix| suffix.parse::<u64>().is_ok_and(|id| id > 0)
                            ))),
                "administrator writer is restricted to its configured repository settings"
            );
        }
        if let WriteContext::NativeManagedFiles(write) = &self.writes {
            let root = format!("/repos/{}", write.target.repository);
            ensure!(
                *method == Method::POST
                    && [
                        format!("{root}/git/refs"),
                        format!("{root}/git/commits"),
                        format!("{root}/pulls")
                    ]
                    .contains(&path.to_owned()),
                "managed-file writer may only create its exact branch, signed commit and reviewable PR"
            );
        }
        if let WriteContext::ClientLabel { server } = &self.writes {
            ensure!(
                path == format!("/repos/{server}/labels"),
                "client write target is not the configured request-label endpoint"
            );
        }
        if let WriteContext::NativeClientLabel { server, .. } = &self.writes {
            ensure!(
                *method == Method::POST && path == format!("/repos/{server}/labels"),
                "native Client may only create its exact request label"
            );
        }
        if let WriteContext::NativeClientReleaseLabel(write) = &self.writes {
            ensure!(
                *method == Method::POST
                    && path == format!("/repos/{}/labels", write.server_repository),
                "native Client may only create its exact release request label"
            );
        }
        if let WriteContext::NativeReleaseCleanup { instance, label } = &self.writes {
            ensure!(
                *method == Method::DELETE
                    && path
                        == format!(
                            "/repos/{}/labels/{}",
                            instance.config.instance.repository,
                            encode_path_segment(label)
                        ),
                "native release cleanup may only delete its authenticated request label"
            );
        }
        if let WriteContext::NativeReleasePreparation(write) = &self.writes {
            let t = &write.target;
            let root = format!("/repos/{}", t.repository);
            ensure!(
                (*method == Method::POST
                    && [
                        format!("{root}/git/refs"),
                        format!("{root}/git/commits"),
                        format!("{root}/pulls")
                    ]
                    .contains(&path.to_owned()))
                    || (*method == Method::PATCH
                        && t.existing_pull_request
                            .is_some_and(|n| path == format!("{root}/pulls/{n}"))),
                "release preparation may only write its exact branch, signed commit and PR"
            );
        }
        if let WriteContext::NativeReleasePrMetadata(write) = &self.writes {
            ensure!(
                *method == Method::PATCH
                    && path == format!("/repos/{}/pulls/{}", write.repository, write.pull_number),
                "native release metadata writer may only update its exact release PR"
            );
        }
        if let WriteContext::NativeReleaseTag(write) = &self.writes {
            let tag_path = format!("/repos/{}/git/tags", write.repository);
            let ref_path = format!("/repos/{}/git/refs", write.repository);
            ensure!(
                *method == Method::POST && (path == tag_path || path == ref_path),
                "native release tag writer may only create its exact annotated tag and ref"
            );
        }
        if let WriteContext::Scratch { candidate_sha } = &self.writes {
            crate::policy::validate_sha(candidate_sha)?;
        }
        if let WriteContext::PackageScratch { candidate_sha, .. } = &self.writes {
            crate::policy::validate_sha(candidate_sha)?;
        }
        if let WriteContext::NativeScratch(write) = &self.writes {
            match write.mode {
                NativeScratchMode::PolicyCheck => ensure!(
                    *method == Method::POST
                        && path == format!("/repos/{}/check-runs", write.target_repository),
                    "native scratch may only create the exact request-proof check run"
                ),
                NativeScratchMode::Securefix => ensure!(
                    *method == Method::POST
                        && path == format!("/repos/{}/git/commits", write.target_repository),
                    "native Securefix may only create a commit for the exact PR head"
                ),
                NativeScratchMode::Approval => ensure!(
                    *method == Method::POST
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/reviews",
                                write.target_repository, write.pull_number
                            ),
                    "native approval may only submit the exact PR review"
                ),
                NativeScratchMode::Merge => ensure!(
                    *method == Method::PUT
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/merge",
                                write.target_repository, write.pull_number
                            ),
                    "native merge may only merge the exact PR"
                ),
            }
        }
        if let WriteContext::NativeInstance(write) = &self.writes {
            match write.mode {
                NativeInstanceMode::PolicyCheck => ensure!(
                    *method == Method::POST
                        && path == format!("/repos/{}/check-runs", write.target_repository),
                    "native instance policy check may only create its exact check run"
                ),
                NativeInstanceMode::Securefix => ensure!(
                    *method == Method::POST
                        && path == format!("/repos/{}/git/commits", write.target_repository),
                    "native instance Securefix may only create a commit for its exact PR head"
                ),
                NativeInstanceMode::Approve => ensure!(
                    *method == Method::POST
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/reviews",
                                write.target_repository, write.pull_number
                            ),
                    "native instance approval may only submit its exact PR review"
                ),
                NativeInstanceMode::Merge => ensure!(
                    *method == Method::PUT
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/merge",
                                write.target_repository, write.pull_number
                            ),
                    "native instance merge may only merge its exact PR"
                ),
            }
        }
        if let WriteContext::NativeRelease(write) = &self.writes {
            let valid_create = *method == Method::POST
                && path == format!("/repos/{}/releases", write.target_repository);
            let valid_publish = *method == Method::PATCH
                && write.release_id.is_some_and(|id| {
                    path == format!("/repos/{}/releases/{id}", write.target_repository)
                });
            let valid_asset_upload =
                *method == Method::POST && native_release_upload_url(write, path).is_ok();
            ensure!(
                valid_create || valid_publish || valid_asset_upload,
                "native release writer target is outside its exact release lifecycle"
            );
            ensure!(
                !valid_create || write.release_id.is_none(),
                "native release draft already has a selected identity"
            );
        }
        if let WriteContext::PackageRelease(write) = &self.writes {
            let valid_create = *method == Method::POST
                && path == format!("/repos/{}/releases", write.destination_repository);
            let valid_publish = *method == Method::PATCH
                && write.release_id.is_some_and(|id| {
                    path == format!("/repos/{}/releases/{id}", write.destination_repository)
                });
            let valid_asset =
                *method == Method::POST && package_release_upload_path(write, path).is_ok();
            let valid_tag = *method == Method::POST
                && path == format!("/repos/{}/git/refs", write.destination_repository);
            ensure!(
                valid_create || valid_publish || valid_asset || valid_tag,
                "package writer target is outside its exact release lifecycle"
            );
            ensure!(
                !valid_create || write.release_id.is_none(),
                "package release draft already has a selected identity"
            );
        }
        let isolated = matches!(
            &self.writes,
            WriteContext::Scratch { .. } | WriteContext::PackageScratch { .. }
        ) || (matches!(&self.writes, WriteContext::Production { .. })
            && crate::config::trusted()?
                .deployment
                .control_repository
                .is_some());
        if isolated {
            let prefix = format!(
                "/repos/{}/",
                crate::config::trusted()?.deployment.integration.repository
            );
            let scratch_target = path.starts_with(&prefix)
                && !path.contains(['%', '\\', '?'])
                && !path.split('/').any(|part| part == "." || part == "..");
            let testing_label_cleanup = if scratch_target {
                false
            } else {
                self.is_testing_label_cleanup(method, path)?
            };
            ensure!(
                scratch_target || testing_label_cleanup,
                "integration write target is outside the scratch repository"
            );
        }
        Ok(())
    }

    fn is_testing_label_cleanup(&self, method: &Method, path: &str) -> Result<bool> {
        if *method != Method::DELETE || !matches!(self.writes, WriteContext::Production { .. }) {
            return Ok(false);
        }
        if std::env::var("GITHUB_EVENT_NAME").as_deref() != Ok("label")
            || std::env::var("GITHUB_RUN_ATTEMPT").as_deref() != Ok("1")
        {
            return Ok(false);
        }
        let trusted = crate::config::trusted()?;
        if trusted.deployment.workflow_prefix != "testing-"
            || trusted.deployment.control_repository.is_none()
        {
            return Ok(false);
        }
        let Ok(event_path) = std::env::var("GITHUB_EVENT_PATH") else {
            return Ok(false);
        };
        let Ok(bytes) = std::fs::read(event_path) else {
            return Ok(false);
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(false);
        };
        testing_label_cleanup_matches(trusted, method, path, &payload)
    }

    fn url(&self, path: &str) -> Result<String> {
        ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains(['\r', '\n', '#']),
            "invalid API path"
        );
        Ok(format!("{}{path}", self.base))
    }

    fn builder(&self, method: Method, path: &str) -> Result<reqwest::blocking::RequestBuilder> {
        self.builder_with_accept(method, path, "application/vnd.github+json")
    }

    fn builder_with_accept(
        &self,
        method: Method,
        path: &str,
        accept: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        let token = match &self.writes {
            WriteContext::NativeReleasePreparation(_)
                if method != Method::GET && method != Method::HEAD =>
            {
                self.write_token.as_deref().unwrap_or(&self.token)
            }
            WriteContext::NativeScratch(write)
                if (method == Method::POST
                    && match write.mode {
                        NativeScratchMode::PolicyCheck => {
                            path == format!("/repos/{}/check-runs", write.target_repository)
                        }
                        NativeScratchMode::Approval => {
                            path == format!(
                                "/repos/{}/pulls/{}/reviews",
                                write.target_repository, write.pull_number
                            )
                        }
                        NativeScratchMode::Merge => false,
                        NativeScratchMode::Securefix => path == "/graphql",
                    })
                    || (method == Method::PUT
                        && write.mode == NativeScratchMode::Merge
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/merge",
                                write.target_repository, write.pull_number
                            ))
                    || (method == Method::GET
                        && write.mode == NativeScratchMode::Approval
                        && path == "/user") =>
            {
                self.write_token.as_deref().unwrap_or(&self.token)
            }
            WriteContext::NativeInstance(write)
                if (method == Method::POST
                    && match write.mode {
                        NativeInstanceMode::PolicyCheck => {
                            path == format!("/repos/{}/check-runs", write.target_repository)
                        }
                        NativeInstanceMode::Approve => {
                            path == format!(
                                "/repos/{}/pulls/{}/reviews",
                                write.target_repository, write.pull_number
                            )
                        }
                        NativeInstanceMode::Merge => false,
                        NativeInstanceMode::Securefix => path == "/graphql",
                    })
                    || (method == Method::PUT
                        && write.mode == NativeInstanceMode::Merge
                        && path
                            == format!(
                                "/repos/{}/pulls/{}/merge",
                                write.target_repository, write.pull_number
                            ))
                    || (method == Method::GET
                        && write.mode == NativeInstanceMode::Approve
                        && path == "/user") =>
            {
                self.write_token.as_deref().unwrap_or(&self.token)
            }
            WriteContext::NativeRelease(write)
                if (matches!(method, Method::GET | Method::HEAD)
                    && (path == format!("/repos/{}/releases", write.target_repository)
                        || path.starts_with(&format!(
                            "/repos/{}/releases/",
                            write.target_repository
                        ))))
                    || (method == Method::POST
                        && path == format!("/repos/{}/releases", write.target_repository))
                    || (method == Method::PATCH
                        && write.release_id.is_some_and(|id| {
                            path == format!("/repos/{}/releases/{id}", write.target_repository)
                        })) =>
            {
                self.write_token.as_deref().unwrap_or(&self.token)
            }
            WriteContext::PackageRelease(write)
                if (matches!(method, Method::GET | Method::HEAD)
                    && (path == format!("/repos/{}/releases", write.destination_repository)
                        || path.starts_with(&format!(
                            "/repos/{}/releases/",
                            write.destination_repository
                        ))))
                    || (method == Method::POST
                        && path == format!("/repos/{}/releases", write.destination_repository))
                    || (method == Method::POST
                        && path == format!("/repos/{}/git/refs", write.destination_repository))
                    || (method == Method::PATCH
                        && write.release_id.is_some_and(|id| {
                            path == format!("/repos/{}/releases/{id}", write.destination_repository)
                        })) =>
            {
                self.write_token.as_deref().unwrap_or(&self.token)
            }
            _ => &self.token,
        };
        let mut request = self
            .client
            .request(method, self.url(path)?)
            .header("User-Agent", "securefix")
            .header("Accept", accept)
            .header("X-GitHub-Api-Version", "2022-11-28");
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }

    pub fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        self.request_with_cache_control(method, path, body, false)
    }

    fn request_with_cache_control(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        no_cache: bool,
    ) -> Result<Value> {
        if let WriteContext::ClientLabel { server } = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            ensure!(
                method == Method::POST && path == format!("/repos/{server}/labels"),
                "client may only create configured server request labels"
            );
        }
        if let WriteContext::NativeClientLabel {
            server,
            name,
            description,
        } = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_client_label_body(
                &method,
                path,
                server,
                name,
                description,
                body.context("native Client label body is missing")?,
            )?;
        }
        if let WriteContext::NativeClientReleaseLabel(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_client_release_label_write(write)?;
            validate_native_client_release_label_body(
                &method,
                path,
                write,
                body.context("native Client release label body is missing")?,
            )?;
        }
        if let WriteContext::NativeRepositorySettings(target) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            self.require_native_repository_settings_body(target, &method, path, body)?;
        }
        if let WriteContext::NativeManagedFiles(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_managed_files_body(
                write,
                &method,
                path,
                body.context("managed-file request body missing")?,
            )?;
        }
        if let WriteContext::NativeReleasePreparation(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_release_preparation_body(
                write,
                &method,
                path,
                body.context("release preparation body missing")?,
            )?;
        }
        if let WriteContext::NativeReleasePrMetadata(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            ensure!(
                body == Some(&serde_json::json!({"title": write.title, "body": write.body})),
                "native release metadata payload differs from the validated title and summary"
            );
        }
        if let WriteContext::NativeReleaseTag(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_release_tag_saved(write)?;
            validate_native_release_tag_body(
                write,
                &method,
                path,
                body.context("native release tag body is missing")?,
            )?;
        }
        if let WriteContext::NativeScratch(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            match write.mode {
                NativeScratchMode::PolicyCheck => validate_native_scratch_check_body(
                    &method,
                    path,
                    &write.target_repository,
                    &write.head_sha,
                    &write.request_sha256,
                    body.context("native scratch check body is missing")?,
                )?,
                NativeScratchMode::Approval => validate_native_approval_body(
                    &method,
                    path,
                    write,
                    body.context("native approval body is missing")?,
                )?,
                NativeScratchMode::Merge => validate_native_merge_body(
                    &method,
                    path,
                    write,
                    body.context("native merge body is missing")?,
                )?,
                NativeScratchMode::Securefix => {
                    bail!("Securefix writes must use the validated signed-commit path")
                }
            }
        }
        if let WriteContext::NativeInstance(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            match write.mode {
                NativeInstanceMode::PolicyCheck => validate_native_instance_check_body(
                    &method,
                    path,
                    write,
                    body.context("native instance check body is missing")?,
                )?,
                NativeInstanceMode::Approve => validate_native_instance_approval_body(
                    &method,
                    path,
                    write,
                    body.context("native instance approval body is missing")?,
                )?,
                NativeInstanceMode::Merge => validate_native_instance_merge_body(
                    &method,
                    path,
                    write,
                    body.context("native instance merge body is missing")?,
                )?,
                NativeInstanceMode::Securefix => {
                    bail!("Securefix writes must use the validated signed-commit path")
                }
            }
        }
        if let WriteContext::PackageScratch {
            destination_repository,
            destination_repository_id,
            tag,
            release_id,
            ..
        } = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            let release_path = format!("/repos/{destination_repository}/releases");
            let expected_patch =
                release_id.map(|id| format!("/repos/{destination_repository}/releases/{id}"));
            let valid_create = method == Method::POST && path == release_path;
            let valid_publish = method == Method::PATCH
                && expected_patch.as_deref() == Some(path)
                && body.is_some_and(|body| {
                    body.as_object()
                        .is_some_and(|fields| fields.len() == 1 && body["draft"] == false)
                });
            ensure!(
                valid_create || valid_publish,
                "package scratch write target is not the selected release"
            );
            if valid_create {
                let body = body.context("package release request body is missing")?;
                ensure!(
                    body["tag_name"] == tag.as_str()
                        && body["draft"] == true
                        && body["prerelease"] == true,
                    "package scratch release must be a draft prerelease for the selected tag"
                );
            }
            ensure!(
                !valid_publish || release_id.is_some(),
                "package release identity was not validated"
            );
            if valid_publish {
                let release_id =
                    release_id.context("package release identity was not validated")?;
                let release: Value = self.get(path)?;
                ensure!(
                    release["id"].as_u64() == Some(release_id)
                        && release["tag_name"] == tag.as_str()
                        && release["prerelease"] == true
                        && release["draft"] == true,
                    "package release changed before publication"
                );
            }
            let allowed_repository: Value =
                self.get(&format!("/repos/{destination_repository}"))?;
            ensure!(
                allowed_repository["id"].as_u64() == Some(*destination_repository_id)
                    && allowed_repository["full_name"] == destination_repository.as_str(),
                "package destination repository identity changed"
            );
        }
        if let WriteContext::NativeRelease(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_release_write_body(
                write,
                &method,
                path,
                body.context("native release request body is missing")?,
            )?;
            if method == Method::PATCH {
                self.validate_native_release_asset_inventory(write, true)?;
            }
        }
        if let WriteContext::PackageRelease(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_package_release_write_body(
                write,
                &method,
                path,
                body.context("package release write body is missing")?,
            )?;
            if method == Method::PATCH {
                let release_id = write.release_id.context("package release ID is missing")?;
                let release: Value = self.get_uncached(&format!(
                    "/repos/{}/releases/{release_id}",
                    write.destination_repository
                ))?;
                let rebound_body = serde_json::json!({
                    "body": package_release_record_body(write)?
                });
                let rebinding_old_record = matches!(
                    write.preflight_state,
                    PackageReleasePreflightState::ResumeDraft {
                        release_id: expected,
                        ..
                    } if expected == release_id
                ) && !write.recovery_body_updated
                    && body == Some(&rebound_body);
                if rebinding_old_record {
                    validate_package_release_draft_recovery_record(write, &release, release_id)?;
                    validate_package_release_recovery_asset_for_write(
                        write, self, &release, false,
                    )?;
                } else {
                    validate_package_release_draft(write, &release, release_id, true)?;
                }
            }
        }
        let read_only_graphql = path == "/graphql"
            && method == Method::POST
            && body
                .and_then(|body| body["query"].as_str())
                .is_some_and(read_only_query);
        if path == "/graphql" {
            ensure!(read_only_graphql, "unsupported GraphQL operation");
        }
        if method != Method::GET && method != Method::HEAD && !read_only_graphql {
            self.require_write_target(&method, path)?;
            self.require_current_revision()?;
        }
        if method == Method::PATCH
            && body.is_some_and(|body| {
                body.as_object()
                    .is_some_and(|fields| fields.len() == 1 && body["draft"] == false)
            })
            && let WriteContext::PackageRelease(write) = &self.writes
        {
            let writer_reader = self.package_writer_reader()?;
            let tag_commit = optional_current_tag_commit(
                &writer_reader,
                &write.destination_repository,
                &write.tag,
            )?;
            validate_package_release_tag_for_publish(
                &write.destination_target_sha,
                tag_commit.as_deref(),
            )?;
        }
        let mut request = self.builder(method.clone(), path)?;
        if no_cache {
            request = request.header(reqwest::header::CACHE_CONTROL, "no-cache");
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = if let WriteContext::NativeInstance(write) = &self.writes
            && method == Method::PUT
            && write.mode == NativeInstanceMode::Merge
        {
            let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes)?;
            let fence = write
                .merge_fence
                .as_ref()
                .context("native instance merge is missing its accepted readiness fence")?;
            let readiness = NativeInstanceMergeReadiness {
                repository: &write.target_repository,
                repository_id: write.target_id,
                pull_number: write.pull_number,
                head_sha: &write.head_sha,
                authority: &write.server_authority,
                approval_request_sha256: &fence.approval_request_sha256,
                approval_producer_run_id: fence.approval_producer_run_id,
                approval_producer_run_attempt: fence.approval_producer_run_attempt,
            };
            let current = capture_native_instance_merge_fence(self, &config, &readiness);
            send_after_native_instance_merge_fence(fence, current, || {
                request
                    .send()
                    .with_context(|| format!("GitHub {method} {path}"))
            })?
        } else {
            request
                .send()
                .with_context(|| format!("GitHub {method} {path}"))?
        };
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError {
                status,
                method,
                path: path.to_string(),
            }
            .into());
        }
        let bytes = bounded_read(response, 16 * 1024 * 1024)?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        let value: Value = serde_json::from_slice(&bytes).context("invalid GitHub JSON")?;
        if let WriteContext::NativeReleaseTag(write) = &self.writes
            && method == Method::POST
            && path == format!("/repos/{}/git/tags", write.repository)
        {
            record_native_release_tag_created_object(write, &value)?;
        }
        Ok(value)
    }

    fn require_current_revision(&self) -> Result<()> {
        let (expected, expected_control) = match &self.writes {
            WriteContext::ReadOnly => bail!("read-only API connection cannot write"),
            WriteContext::NativeManagedFiles(write) => {
                return self.require_native_managed_files_current(write);
            }
            WriteContext::NativeRepositorySettings(target) => {
                return self.require_native_repository_settings_current(target);
            }
            WriteContext::ClientLabel { .. } | WriteContext::NativeClientLabel { .. } => {
                return Ok(());
            }
            WriteContext::NativeClientReleaseLabel(write) => {
                return self.require_native_client_release_label_current(write);
            }
            WriteContext::NativeReleaseTag(write) => {
                return self.require_native_release_tag_current(write);
            }
            WriteContext::NativeReleasePreparation(write) => {
                return self.require_native_release_preparation_current(write);
            }
            WriteContext::NativeReleasePrMetadata(write) => {
                return self.require_native_release_pr_metadata_current(write);
            }
            WriteContext::Scratch { .. } => return Ok(()),
            WriteContext::PackageScratch { .. } => return Ok(()),
            WriteContext::NativeScratch(_) => {
                return self.require_native_scratch_current();
            }
            WriteContext::NativeInstance(_) => {
                return self.require_native_instance_current();
            }
            WriteContext::NativeRelease(_) => {
                return self.require_native_release_current();
            }
            WriteContext::NativeReleaseCleanup { instance, .. } => {
                ensure!(
                    std::env::var("GITHUB_REPOSITORY").as_deref()
                        == Ok(instance.config.instance.repository.as_str())
                        && std::env::var("GITHUB_REF").as_deref()
                            == Ok(format!(
                                "refs/heads/{}",
                                instance.config.instance.default_branch
                            )
                            .as_str()),
                    "release cleanup is outside the protected Server instance"
                );
                let workflow_sha =
                    std::env::var("GITHUB_WORKFLOW_SHA").context("missing cleanup workflow SHA")?;
                let workflow_ref =
                    std::env::var("GITHUB_WORKFLOW_REF").context("missing cleanup workflow ref")?;
                let role = crate::instance_config::WorkflowRole::Release;
                let path = instance
                    .config
                    .workflow_roles
                    .get(&role)
                    .context("Release role is not configured")?;
                let workflow =
                    self.content(&instance.config.instance.repository, path, &workflow_sha)?;
                validate_native_server_execution_workflow_role(
                    &instance.authority,
                    role,
                    &workflow_ref,
                    &workflow_sha,
                    &workflow,
                )?;
                return self.require_remote_native_server_instance_authority_unchanged(instance);
            }
            WriteContext::PackageRelease(_) => {
                return self.require_package_release_current();
            }
            WriteContext::Production {
                revision,
                control_id,
            } => (
                revision
                    .as_deref()
                    .context("missing trusted runtime revision before write")?,
                control_id
                    .as_deref()
                    .context("missing trusted control identity before write")?,
            ),
        };
        crate::policy::validate_sha(expected)?;
        let server = crate::config::trusted()?.deployment.control_repository();
        let bytes = self.content(
            &server.repository,
            "control/active.json",
            &server.default_branch,
        )?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "control descriptor exceeds size limit"
        );
        let active: crate::control::ControlRevision = serde_json::from_slice(&bytes)?;
        use sha2::Digest;
        let policy_sha =
            crate::hex_encode(sha2::Sha256::digest(crate::config::trusted_policy_bytes()?));
        ensure!(
            active.source_sha == expected
                && active.identity()? == expected_control
                && active.policy_sha256 == policy_sha,
            "control revision is no longer current; write denied"
        );
        Ok(())
    }

    fn require_native_scratch_current(&self) -> Result<()> {
        let WriteContext::NativeScratch(write) = &self.writes else {
            bail!("native scratch write context is missing");
        };
        let NativeScratchWrite {
            mode,
            instance_repository,
            instance_id,
            instance_owner_id,
            default_branch,
            config_path,
            config_bytes,
            server_authority,
            target_repository,
            target_id,
            pull_number,
            head_sha,
            head_repository_id,
            base_ref,
            author_id,
            author_login,
            actor_id,
            actor_login,
            request_sha256: _,
            caller_workflow_path,
            caller_workflow_sha,
            client_workflow_epoch,
            target_policy_control_identity,
            destination_branch,
        } = write.as_ref();

        validate_instance_config_path(config_path)?;
        require_single_repository_installation(self, *target_id, target_repository)?;
        if let Some(token) = &self.write_token
            && *mode != NativeScratchMode::Approval
        {
            let write_api = Self::new("https://api.github.com", token.clone())?;
            require_single_repository_installation(&write_api, *target_id, target_repository)?;
        }

        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            &execution_repository == instance_repository,
            "native Server instance differs from the current job repository"
        );
        let config = crate::instance_config::InstanceConfig::parse(config_bytes)?;
        if *mode == NativeScratchMode::Approval
            && let Some(token) = &self.write_token
        {
            let review_api = Self::new("https://api.github.com", token.clone())?;
            let reviewer: Value = review_api.get("/user")?;
            ensure!(
                reviewer["id"].as_u64() == Some(config.identities.approval_reviewer.id)
                    && reviewer["login"].as_str()
                        == Some(config.identities.approval_reviewer.login.as_str())
                    && reviewer["type"] == "User",
                "approval token no longer authenticates as the configured review account"
            );
        }
        ensure!(
            config.instance.repository == *instance_repository
                && config.instance.id == *instance_id
                && config.instance.default_branch == *default_branch
                && config.identities.repository_owner.id == *instance_owner_id
                && config.identities.owner.id == *actor_id
                && config.identities.owner.login == *actor_login
                && config.identities.owner.id == *author_id
                && config.identities.owner.login == *author_login
                && config.repositories.iter().any(|repository| {
                    repository.repository == *target_repository
                        && repository.id == *target_id
                        && repository
                            .policy()
                            .require(match mode {
                                NativeScratchMode::PolicyCheck => crate::policy::Capability::Merge,
                                NativeScratchMode::Approval => crate::policy::Capability::Approve,
                                NativeScratchMode::Merge => crate::policy::Capability::Merge,
                                NativeScratchMode::Securefix => {
                                    crate::policy::Capability::Securefix
                                }
                            })
                            .is_ok()
                }),
            "native request no longer matches the captured owner and repository policy"
        );
        let read_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!read_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", read_token)?;
        validate_native_test_host_context(&config, *mode)?;
        let (remote_config, current_authority) =
            server_reader.capture_native_server_authority(&config, config_path, config_bytes)?;
        ensure!(
            remote_config.as_slice() == config_bytes.as_slice(),
            "native Server config changed before write"
        );
        require_native_authority_unchanged(server_authority, &current_authority)
            .context("native Server deployment authority changed before write")?;
        if *mode == NativeScratchMode::Merge {
            let expected = target_policy_control_identity
                .as_deref()
                .context("native target policy control identity is missing")?;
            let current = native_target_policy_control_identity(
                self,
                target_repository,
                *target_id,
                base_ref,
            )?;
            ensure!(
                current == expected,
                "native target policy control identity changed before write"
            );
        }
        let current_client_epoch = capture_native_client_workflow_epoch(
            self,
            target_repository,
            *target_id,
            base_ref,
            caller_workflow_path,
            caller_workflow_sha,
            (*mode == NativeScratchMode::Securefix).then_some(head_sha.as_str()),
        )?;
        require_native_client_workflow_epoch_unchanged(
            client_workflow_epoch,
            &current_client_epoch,
        )?;
        let target: Value = self.get(&format!("/repos/{target_repository}"))?;
        ensure!(
            target["id"].as_u64() == Some(*target_id)
                && target["full_name"].as_str() == Some(target_repository.as_str())
                && target["default_branch"].as_str() == Some(base_ref.as_str()),
            "native request target repository identity changed"
        );
        let pull: Value = self.get(&format!("/repos/{target_repository}/pulls/{pull_number}"))?;
        ensure!(
            pull["number"].as_u64() == Some(*pull_number)
                && pull["state"] == "open"
                && pull["base"]["repo"]["id"].as_u64() == Some(*target_id)
                && pull["base"]["repo"]["full_name"].as_str() == Some(target_repository.as_str())
                && pull["base"]["ref"].as_str() == Some(base_ref.as_str())
                && pull["head"]["sha"].as_str() == Some(head_sha.as_str())
                && match mode {
                    NativeScratchMode::PolicyCheck => destination_branch.is_none(),
                    NativeScratchMode::Approval => destination_branch.is_none(),
                    NativeScratchMode::Merge => destination_branch.is_none(),
                    NativeScratchMode::Securefix => {
                        pull["head"]["ref"].as_str() == destination_branch.as_deref()
                    }
                }
                && pull["head"]["repo"]["id"].as_u64() == Some(*head_repository_id)
                && pull["user"]["id"].as_u64() == Some(*author_id)
                && pull["user"]["login"].as_str() == Some(author_login.as_str())
                && *author_id == *actor_id
                && author_login == actor_login,
            "native request PR is closed, retargeted, or has a different head or identity"
        );
        if *mode == NativeScratchMode::Merge {
            let expected = target_policy_control_identity
                .as_deref()
                .context("native target policy control identity is missing")?;
            let current = native_target_policy_control_identity(
                self,
                target_repository,
                *target_id,
                base_ref,
            )?;
            ensure!(
                current == expected,
                "native target policy control identity changed immediately before write"
            );
        }
        Ok(())
    }

    fn require_native_instance_current(&self) -> Result<()> {
        let WriteContext::NativeInstance(write) = &self.writes else {
            bail!("native instance write context is missing");
        };
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes)?;
        let target = NativeInstanceWriteTarget {
            mode: write.mode,
            config_path: &write.config_path,
            repository: &write.target_repository,
            repository_id: write.target_id,
            pull_number: write.pull_number,
            head_sha: &write.head_sha,
            head_branch: &write.head_branch,
            head_repository_id: write.head_repository_id,
            base_sha: &write.base_sha,
            base_ref: &write.base_ref,
            author_id: write.author_id,
            author_login: &write.author_login,
            actor_id: write.actor_id,
            actor_login: &write.actor_login,
            request_sha256: &write.request_sha256,
            producer_run_id: write.producer_run_id,
            producer_run_attempt: write.producer_run_attempt,
            producer_workflow_path: &write.producer_workflow_path,
            producer_workflow_sha: &write.producer_workflow_sha,
            client_workflow_epoch: &write.client_workflow_epoch,
            merge_fence: write.merge_fence.as_ref(),
        };
        validate_native_instance_write_target(&config, &target)?;
        validate_native_instance_merge_fence_target(&config, &write.server_authority, &target)?;
        ensure!(
            config.instance.repository == write.instance_repository
                && config.instance.id == write.instance_id
                && config.instance.default_branch == write.default_branch
                && write.server_authority.config_sha256
                    == crate::hex_encode(sha2::Sha256::digest(&write.config_bytes)),
            "native Server writer configuration differs from its authority snapshot"
        );
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.instance_repository.as_str())
                && std::env::var("GITHUB_REF").as_deref()
                    == Ok(format!("refs/heads/{}", write.default_branch).as_str()),
            "native Server writer is no longer executing from the protected instance branch"
        );

        require_single_repository_installation(self, write.target_id, &write.target_repository)?;
        if let Some(token) = &self.write_token {
            let write_api = Self::new("https://api.github.com", token.clone())?;
            if write.mode == NativeInstanceMode::Approve {
                let reviewer: Value = write_api.get_uncached("/user")?;
                ensure!(
                    reviewer["id"].as_u64() == Some(config.identities.approval_reviewer.id)
                        && reviewer["login"].as_str()
                            == Some(config.identities.approval_reviewer.login.as_str())
                        && reviewer["type"] == "User",
                    "approval token no longer authenticates as the configured review account"
                );
            } else {
                require_single_repository_installation(
                    &write_api,
                    write.target_id,
                    &write.target_repository,
                )?;
            }
        }

        let server_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!server_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", server_token)?;
        let (remote_config, current_authority) = server_reader.capture_native_server_authority(
            &config,
            &write.config_path,
            &write.config_bytes,
        )?;
        ensure!(
            remote_config == write.config_bytes,
            "native Server config changed before write"
        );
        require_native_authority_unchanged(&write.server_authority, &current_authority)
            .context("native Server configuration or role authority changed before write")?;

        let current_client_epoch = capture_native_client_workflow_epoch(
            self,
            &write.target_repository,
            write.target_id,
            &write.base_ref,
            &write.producer_workflow_path,
            &write.producer_workflow_sha,
            (write.mode == NativeInstanceMode::Securefix).then_some(write.head_sha.as_str()),
        )?;
        require_native_client_workflow_epoch_unchanged(
            &write.client_workflow_epoch,
            &current_client_epoch,
        )?;

        let target: Value = self.get_uncached(&format!("/repos/{}", write.target_repository))?;
        ensure!(
            target["id"].as_u64() == Some(write.target_id)
                && target["full_name"].as_str() == Some(write.target_repository.as_str())
                && target["default_branch"].as_str() == Some(write.base_ref.as_str()),
            "native request target repository identity changed"
        );
        let pull: Value = self.get_uncached(&format!(
            "/repos/{}/pulls/{}",
            write.target_repository, write.pull_number
        ))?;
        ensure!(
            pull["number"].as_u64() == Some(write.pull_number)
                && pull["state"] == "open"
                && pull["base"]["repo"]["id"].as_u64() == Some(write.target_id)
                && pull["base"]["repo"]["full_name"].as_str()
                    == Some(write.target_repository.as_str())
                && pull["base"]["ref"].as_str() == Some(write.base_ref.as_str())
                && pull["base"]["sha"].as_str() == Some(write.base_sha.as_str())
                && pull["head"]["sha"].as_str() == Some(write.head_sha.as_str())
                && pull["head"]["ref"].as_str() == Some(write.head_branch.as_str())
                && pull["head"]["repo"]["id"].as_u64() == Some(write.head_repository_id)
                && pull["user"]["id"].as_u64() == Some(write.author_id)
                && pull["user"]["login"].as_str() == Some(write.author_login.as_str()),
            "native request PR is closed, retargeted, or has a different head, base, or author"
        );
        if write.mode == NativeInstanceMode::Securefix {
            ensure!(
                write.head_repository_id == write.target_id,
                "native Securefix requires a same-repository PR head"
            );
        }
        Ok(())
    }

    fn require_native_client_release_label_current(
        &self,
        write: &NativeClientReleaseLabelWrite,
    ) -> Result<()> {
        validate_native_client_release_label_write(write)?;
        validate_native_client_release_label_execution(write)?;
        self.require_remote_native_server_instance_authority_unchanged(&write.instance)
    }

    fn require_native_release_preparation_current(
        &self,
        write: &NativeReleasePreparationWrite,
    ) -> Result<()> {
        let t = &write.target;
        validate_native_release_preparation_target(t)?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref()
                == Ok(t.instance.config.instance.repository.as_str())
                && std::env::var("GITHUB_REF").as_deref()
                    == Ok(
                        format!("refs/heads/{}", t.instance.config.instance.default_branch)
                            .as_str()
                    ),
            "release preparation is outside its protected Server instance"
        );
        let token = std::env::var("GITHUB_TOKEN").context("missing Server reader token")?;
        let server = Self::new("https://api.github.com", token)?;
        server.require_remote_native_server_instance_authority_unchanged(&t.instance)?;
        let role = crate::instance_config::WorkflowRole::Release;
        let path = t
            .instance
            .config
            .workflow_roles
            .get(&role)
            .context("Release role missing")?;
        let sha = std::env::var("GITHUB_WORKFLOW_SHA")?;
        let bytes = server.content(&t.instance.config.instance.repository, path, &sha)?;
        validate_native_server_execution_workflow_role(
            &t.instance.authority,
            role,
            &std::env::var("GITHUB_WORKFLOW_REF")?,
            &sha,
            &bytes,
        )?;
        server.validate_native_client_package_current(&t.instance.config, &write.package)?;
        let repo: Value = self.get_uncached(&format!("/repos/{}", t.repository))?;
        ensure!(
            repo["id"].as_u64() == Some(t.repository_id)
                && repo["full_name"] == t.repository
                && repo["default_branch"] == t.default_branch,
            "release preparation repository identity changed"
        );
        ensure!(
            self.branch_head(&t.repository, &t.default_branch)? == t.source_sha,
            "release preparation default head is stale"
        );
        let epoch = capture_native_client_workflow_epoch(
            self,
            &t.repository,
            t.repository_id,
            &t.default_branch,
            &t.workflow_path,
            &t.workflow_sha,
            None,
        )?;
        require_native_client_workflow_epoch_unchanged(&t.workflow_epoch, &epoch)?;
        let run: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}",
            t.repository, t.run_id
        ))?;
        validate_native_release_preparation_run(t, &run)?;
        let committed = write
            .committed_head
            .lock()
            .map_err(|_| anyhow::anyhow!("release commit state poisoned"))?
            .clone();
        match self.optional_branch_head(&t.repository, &t.release_branch)? {
            Some(head) => ensure!(
                head == committed.as_deref().unwrap_or(&t.expected_head),
                "release preparation branch head is stale or request was replayed"
            ),
            None => ensure!(
                !t.branch_exists && committed.is_none(),
                "release preparation branch disappeared"
            ),
        }
        if let Some(number) = t.existing_pull_request {
            let pull: Value =
                self.get_uncached(&format!("/repos/{}/pulls/{number}", t.repository))?;
            ensure!(
                pull["state"] == "open"
                    && pull["head"]["ref"] == t.release_branch
                    && pull["head"]["sha"].as_str()
                        == Some(committed.as_deref().unwrap_or(&t.expected_head))
                    && pull["head"]["repo"]["id"].as_u64() == Some(t.repository_id)
                    && pull["base"]["repo"]["id"].as_u64() == Some(t.repository_id)
                    && pull["base"]["ref"] == t.default_branch
                    && pull["user"]["id"].as_u64()
                        == Some(t.instance.config.identities.server_bot.id)
                    && pull["user"]["login"] == t.instance.config.identities.server_bot.login,
                "release preparation PR identity changed"
            );
        }
        Ok(())
    }

    fn require_native_release_pr_metadata_current(
        &self,
        write: &NativeReleasePrMetadataTarget,
    ) -> Result<()> {
        validate_native_release_pr_metadata_target(write)?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.repository.as_str())
                && std::env::var("GITHUB_SHA").as_deref() == Ok(write.head_sha.as_str())
                && std::env::var("GITHUB_RUN_ID")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(write.run_id)
                && std::env::var("GITHUB_RUN_ATTEMPT")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(write.run_attempt),
            "native release metadata execution differs from the captured Client run"
        );
        self.require_remote_native_server_instance_authority_unchanged(&write.instance)?;
        require_single_repository_installation(self, write.repository_id, &write.repository)?;
        let current_epoch = capture_native_release_sync_workflow_epoch(
            self,
            &write.repository,
            write.repository_id,
            &write.default_branch,
            &write.workflow_path,
            &write.workflow_sha,
        )?;
        require_native_client_workflow_epoch_unchanged(&write.workflow_epoch, &current_epoch)?;
        let run: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}",
            write.repository, write.run_id
        ))?;
        ensure!(
            run["repository"]["id"].as_u64() == Some(write.repository_id)
                && run["head_repository"]["id"].as_u64() == Some(write.repository_id)
                && run["head_sha"].as_str() == Some(write.head_sha.as_str())
                && run["head_branch"].as_str() == write.instance.config.branches.release.as_deref()
                && run["event"] == "push"
                && run["status"] == "in_progress"
                && run["run_attempt"].as_u64() == Some(write.run_attempt),
            "native release metadata source run changed"
        );
        let pull: Value = self.get_uncached(&format!(
            "/repos/{}/pulls/{}",
            write.repository, write.pull_number
        ))?;
        validate_native_release_pr_metadata_pull(write, &pull)?;
        ensure!(
            self.branch_head(
                &write.repository,
                write
                    .instance
                    .config
                    .branches
                    .release
                    .as_deref()
                    .context("release branch is not configured")?
            )? == write.head_sha,
            "native release PR head advanced before metadata write"
        );
        Ok(())
    }

    fn require_native_release_tag_current(&self, write: &NativeReleaseTagWrite) -> Result<()> {
        validate_native_release_tag_saved(write)?;
        validate_native_release_tag_execution(write)?;
        self.require_remote_native_server_instance_authority_unchanged(&write.instance)?;

        let config = crate::instance_config::InstanceConfig::parse(&write.instance.config_bytes)?;
        let repository: Value = self.get_uncached(&format!("/repos/{}", write.repository))?;
        let default_branch = repository["default_branch"]
            .as_str()
            .context("native release destination lacks a default branch")?;
        ensure!(
            repository["id"].as_u64() == Some(write.repository_id)
                && repository["full_name"].as_str() == Some(write.repository.as_str())
                && repository["owner"]["id"].as_u64()
                    == Some(config.identities.repository_owner.id),
            "native release destination repository identity changed"
        );
        let pull: Value = self.get_uncached(&format!(
            "/repos/{}/pulls/{}",
            write.repository, write.release_pr_number
        ))?;
        let server_bot = &config.identities.server_bot;
        ensure!(
            pull["number"].as_u64() == Some(write.release_pr_number)
                && pull["state"] == "closed"
                && pull["merged"] == true
                && pull["base"]["repo"]["id"].as_u64() == Some(write.repository_id)
                && pull["base"]["repo"]["full_name"].as_str() == Some(write.repository.as_str())
                && pull["base"]["ref"].as_str() == Some(default_branch)
                && pull["head"]["repo"]["id"].as_u64() == Some(write.repository_id)
                && pull["head"]["repo"]["full_name"].as_str() == Some(write.repository.as_str())
                && pull["head"]["sha"].as_str() == Some(write.release_pr_head_sha.as_str())
                && pull["merge_commit_sha"].as_str() == Some(write.release_pr_merge_sha.as_str())
                && pull["merged_by"]["id"].as_u64() == Some(server_bot.id)
                && pull["merged_by"]["login"].as_str() == Some(server_bot.login.as_str())
                && pull["merged_by"]["type"] == "Bot",
            "native release PR head, merge, base, repository, or Server merger changed"
        );
        let ancestry: Value = self.get_uncached(&format!(
            "/repos/{}/compare/{}...{}",
            write.repository,
            write.release_pr_merge_sha,
            encode_path_segment(default_branch),
        ))?;
        ensure!(
            matches!(ancestry["status"].as_str(), Some("ahead" | "identical"))
                && ancestry["base_commit"]["sha"].as_str()
                    == Some(write.release_pr_merge_sha.as_str()),
            "native release merge is no longer contained in the default branch"
        );
        let version_bytes = self.content(
            &write.repository,
            ".release-version",
            &write.release_pr_merge_sha,
        )?;
        let version = String::from_utf8(version_bytes)?.trim().to_owned();
        ensure!(
            format!("v{version}") == write.tag,
            "native release tag no longer matches the merged release version"
        );

        let tag_ref_path = format!(
            "/repos/{}/git/ref/tags/{}",
            write.repository,
            encode_path_segment(&write.tag),
        );
        match self.get_uncached::<Value>(&tag_ref_path) {
            Ok(reference) => {
                let state = write
                    .tag_object_sha
                    .lock()
                    .map_err(|_| anyhow::anyhow!("native release tag state is poisoned"))?;
                ensure!(
                    *state == reference["object"]["sha"].as_str().map(str::to_owned)
                        && reference["object"]["type"] == "tag",
                    "a different object now occupies the native release tag"
                );
                ensure!(
                    !state.is_none(),
                    "native release tag already exists before its authorized write"
                );
            }
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|api_error| api_error.status == StatusCode::NOT_FOUND) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn require_native_release_current(&self) -> Result<()> {
        let WriteContext::NativeRelease(write) = &self.writes else {
            bail!("native release writer context is missing");
        };
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes)?;
        validate_native_release_saved(&config, &write.server_authority, write)?;
        ensure!(
            std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.instance_repository.as_str())
                && std::env::var("GITHUB_REF").as_deref()
                    == Ok(format!("refs/heads/{}", write.default_branch).as_str()),
            "native Server release writer is no longer executing from the protected instance branch"
        );
        require_single_repository_installation(self, write.target_id, &write.target_repository)?;
        if let Some(token) = &self.write_token {
            let write_api = Self::new("https://api.github.com", token.clone())?;
            require_single_repository_installation(
                &write_api,
                write.target_id,
                &write.target_repository,
            )?;
        }

        let server_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!server_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", server_token)?;
        let (remote_config, current_authority) = server_reader.capture_native_server_authority(
            &config,
            &write.config_path,
            &write.config_bytes,
        )?;
        ensure!(
            remote_config == write.config_bytes,
            "native Server config changed before release write"
        );
        require_native_authority_unchanged(&write.server_authority, &current_authority).context(
            "native Server configuration or Release role authority changed before write",
        )?;

        let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
            .context("missing GITHUB_WORKFLOW_REF for native Server release")?;
        let workflow_sha = std::env::var("GITHUB_WORKFLOW_SHA")
            .context("missing GITHUB_WORKFLOW_SHA for native Server release")?;
        let workflow_path = config
            .workflow_roles
            .get(&crate::instance_config::WorkflowRole::Release)
            .context("native Server Release workflow role is not configured")?;
        let workflow_bytes =
            server_reader.content(&config.instance.repository, workflow_path, &workflow_sha)?;
        validate_native_server_execution_workflow_role(
            &write.server_authority,
            crate::instance_config::WorkflowRole::Release,
            &workflow_ref,
            &workflow_sha,
            &workflow_bytes,
        )?;

        let repository: Value =
            self.get_uncached(&format!("/repos/{}", write.target_repository))?;
        ensure!(
            repository["id"].as_u64() == Some(write.target_id)
                && repository["full_name"].as_str() == Some(write.target_repository.as_str())
                && repository["default_branch"].as_str()
                    == Some(write.target_default_branch.as_str()),
            "native release destination identity or default branch changed"
        );
        self.require_native_release_identity_current(write)?;
        let pull: Value = self.get_uncached(&format!(
            "/repos/{}/pulls/{}",
            write.target_repository, write.release_pr_number
        ))?;
        ensure!(
            pull["number"].as_u64() == Some(write.release_pr_number)
                && pull["state"] == "closed"
                && pull["merged"] == true
                && pull["base"]["repo"]["id"].as_u64() == Some(write.target_id)
                && pull["base"]["repo"]["full_name"] == write.target_repository
                && pull["base"]["ref"] == write.target_default_branch
                && pull["head"]["repo"]["id"].as_u64() == Some(write.target_id)
                && pull["head"]["sha"] == write.release_pr_head_sha
                && pull["merge_commit_sha"] == write.release_pr_merge_sha,
            "native release PR head, merge, repository, or base changed"
        );

        let source_run: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            write.target_repository, write.release_source_run_id, write.release_source_run_attempt
        ))?;
        validate_native_release_source_run(&config, write, &source_run)?;

        server_reader.validate_native_client_package_current(&config, &write.client_package)?;

        let tag_ref: Value = self.get_uncached(&format!(
            "/repos/{}/git/ref/tags/{}",
            write.target_repository, write.tag
        ))?;
        ensure!(
            tag_ref["object"]["type"] == "tag",
            "native release tag is not annotated"
        );
        let tag_object_sha = tag_ref["object"]["sha"]
            .as_str()
            .context("native release tag reference lacks object SHA")?;
        crate::policy::validate_sha(tag_object_sha)?;
        let tag_object: Value = self.get_uncached(&format!(
            "/repos/{}/git/tags/{tag_object_sha}",
            write.target_repository
        ))?;
        ensure!(
            tag_object["object"]["sha"] == write.release_pr_merge_sha
                && tag_object["object"]["type"] == "commit",
            "native release tag no longer targets the authorized merge commit"
        );
        Ok(())
    }

    fn require_native_release_identity_current(&self, write: &NativeReleaseWrite) -> Result<()> {
        let selected: Option<Value> = write
            .release_id
            .map(|release_id| {
                self.get_uncached(&format!(
                    "/repos/{}/releases/{release_id}",
                    write.target_repository
                ))
            })
            .transpose()?;
        if let Some(release) = &selected {
            ensure!(
                release["id"].as_u64() == write.release_id
                    && release["tag_name"] == write.tag
                    && release["name"] == write.tag
                    && release["target_commitish"] == write.target_default_branch
                    && release["prerelease"]
                        == !semver::Version::parse(
                            write.tag.strip_prefix('v').unwrap_or_default(),
                        )?
                        .pre
                        .is_empty()
                    && (release["draft"] == true || release["immutable"] == true),
                "native release identity changed"
            );
        }
        match self.get_uncached::<Value>(&format!(
            "/repos/{}/releases/tags/{}",
            write.target_repository, write.tag
        )) {
            Ok(existing) => ensure!(
                write.release_id.is_some()
                    && existing["id"].as_u64() == write.release_id
                    && existing["tag_name"] == write.tag,
                "a different release now occupies the native release tag"
            ),
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|e| e.status == StatusCode::NOT_FOUND) =>
            {
                // Tag lookup returns published releases; a selected draft is bound by ID.
                ensure!(
                    selected
                        .as_ref()
                        .is_none_or(|release| release["draft"] == true),
                    "selected published native release is no longer present for its tag"
                );
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn validate_native_client_package_current(
        &self,
        config: &crate::instance_config::InstanceConfig,
        package: &NativeClientPackageIdentity,
    ) -> Result<()> {
        validate_native_client_package_snapshot(config, package)?;
        if package.release_repository != package.distributor_repository {
            let action = crate::package::PinnedPackageAction::new(
                package.distributor_repository.clone(),
                package.loader_action_path.clone(),
                package.loader_action_sha.clone(),
            )?;
            let verified = crate::package::verify_native_client_package_scratch(
                self,
                config,
                &config.acceptable_clients,
                &package.implementation_sha,
                &action,
                &package.protocol,
                None,
            )?;
            ensure!(
                native_client_package_identity(config, &verified)? == *package,
                "accepted scratch Client package changed before the release write"
            );
            return Ok(());
        }
        let repository: Value =
            self.get_uncached(&format!("/repos/{}", package.distributor_repository))?;
        let release: Value = self.get_uncached(&format!(
            "/repos/{}/releases/{}",
            package.distributor_repository, package.release_id
        ))?;
        let tag_ref: Value = self.get_uncached(&format!(
            "/repos/{}/git/ref/tags/{}",
            package.distributor_repository, package.release_tag
        ))?;
        let publisher_run: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            package.distributor_repository, package.publisher_run_id, package.publisher_run_attempt
        ))?;
        let producer_run: Value = self.get_uncached(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            package.distributor_repository, package.producer_run_id, package.producer_run_attempt
        ))?;
        validate_native_client_package_remote_identity(
            package,
            &repository,
            &release,
            &tag_ref,
            &publisher_run,
            &producer_run,
        )
    }

    fn validate_native_release_asset_inventory(
        &self,
        write: &NativeReleaseWrite,
        require_complete: bool,
    ) -> Result<Vec<Value>> {
        let release_id = write
            .release_id
            .context("native release identity was not selected")?;
        let release: Value = self.get_uncached(&format!(
            "/repos/{}/releases/{release_id}",
            write.target_repository
        ))?;
        ensure!(
            release["id"].as_u64() == Some(release_id)
                && release["tag_name"] == write.tag
                && release["draft"] == true,
            "native release asset inventory is not the selected draft"
        );
        let existing: Vec<Value> = self.paginate_uncached(&format!(
            "/repos/{}/releases/{release_id}/assets",
            write.target_repository
        ))?;
        validate_native_release_inventory(
            write,
            release_id,
            &release,
            &existing,
            require_complete,
        )?;
        Ok(existing)
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::GET,
            path,
            None,
        )?)?)
    }
    pub fn get_uncached<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(serde_json::from_value(self.request_with_cache_control(
            Method::GET,
            path,
            None,
            true,
        )?)?)
    }
    pub fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::POST,
            path,
            Some(body),
        )?)?)
    }
    pub fn patch<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::PATCH,
            path,
            Some(body),
        )?)?)
    }
    pub fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::PUT,
            path,
            Some(body),
        )?)?)
    }
    pub fn delete(&self, path: &str) -> Result<()> {
        self.request(Method::DELETE, path, None)?;
        Ok(())
    }
    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        ensure!(read_only_query(query), "only GraphQL queries are supported");
        let response: Value = self.post(
            "/graphql",
            &serde_json::json!({"query":query,"variables":variables}),
        )?;
        if response.get("errors").is_some() {
            bail!("GitHub GraphQL query failed");
        }
        response
            .get("data")
            .cloned()
            .context("missing GraphQL data")
    }

    pub fn merge_native_pull_request(&self) -> Result<String> {
        let (repository, pull_number, head_sha) = match &self.writes {
            WriteContext::NativeScratch(write) => {
                ensure!(
                    write.mode == NativeScratchMode::Merge,
                    "native scratch writer is not authorized to merge"
                );
                (
                    write.target_repository.as_str(),
                    write.pull_number,
                    write.head_sha.as_str(),
                )
            }
            WriteContext::NativeInstance(write) => {
                ensure!(
                    write.mode == NativeInstanceMode::Merge,
                    "native instance writer is not authorized to merge"
                );
                (
                    write.target_repository.as_str(),
                    write.pull_number,
                    write.head_sha.as_str(),
                )
            }
            _ => bail!("native merge writer context is missing"),
        };
        let path = format!("/repos/{repository}/pulls/{pull_number}/merge");
        let result: Value = self.put(&path, &native_merge_body(head_sha))?;
        ensure!(
            result["merged"] == true,
            "GitHub did not merge the exact native pull request"
        );
        let merge_sha = result["sha"]
            .as_str()
            .context("GitHub native merge response has no merge commit SHA")?;
        crate::policy::validate_sha(merge_sha)?;
        Ok(merge_sha.to_owned())
    }

    pub fn minimize_policy_comment(
        &self,
        repository: &str,
        number: u64,
        comment_id: u64,
    ) -> Result<()> {
        ensure!(
            !matches!(
                &self.writes,
                WriteContext::NativeScratch(write)
                    if write.mode == NativeScratchMode::Securefix
            ),
            "native Securefix writer cannot mutate policy comments"
        );
        crate::policy::validate_repository(repository)?;
        ensure!(
            number > 0 && comment_id > 0,
            "invalid policy comment target"
        );
        ensure!(
            matches!(
                self.writes,
                WriteContext::Production { .. } | WriteContext::Scratch { .. }
            ),
            "policy comments can only be minimized by the server"
        );

        let path = format!("/repos/{repository}/issues/comments/{comment_id}");
        self.require_write_target(&Method::GET, &path)?;
        let comment: Value = self.get(&path)?;
        let policy = crate::config::trusted()?;
        let expected_issue_path = format!("/repos/{repository}/issues/{number}");
        let issue_url_matches = comment["issue_url"]
            .as_str()
            .and_then(|url| reqwest::Url::parse(url).ok())
            .is_some_and(|url| {
                url.scheme() == "https"
                    && url.host_str() == Some("api.github.com")
                    && url.path() == expected_issue_path
                    && url.query().is_none()
                    && url.fragment().is_none()
            });
        ensure!(
            comment["id"].as_u64() == Some(comment_id)
                && issue_url_matches
                && comment["user"]["id"].as_u64() == Some(policy.server_bot_id)
                && comment["user"]["login"].as_str()
                    == Some(policy.deployment.server_bot_login.as_str())
                && comment["user"]["type"] == "Bot"
                && comment["body"]
                    .as_str()
                    .is_some_and(|body| body.starts_with(POLICY_FAILURE_COMMENT_MARKER)),
            "comment is not a marked policy failure from the configured server bot on this PR"
        );
        let node_id = comment["node_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("policy comment has no GraphQL node ID")?;

        self.require_current_revision()?;
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let response = self
            .builder(Method::POST, "/graphql")?
            .json(&serde_json::json!({
                "query":query,
                "variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            }))
            .send()
            .context("GitHub policy comment minimization failed")?;
        ensure!(
            response.status().is_success(),
            "GitHub policy comment minimization returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none()
                && value["data"]["minimizeComment"]["minimizedComment"]["isMinimized"] == true,
            "GitHub did not minimize the policy failure comment"
        );
        Ok(())
    }

    pub fn create_commit(
        &self,
        repository: &str,
        branch: &str,
        expected_head: &str,
        message: &str,
        additions: BTreeMap<String, Vec<u8>>,
        deletions: Vec<String>,
    ) -> Result<String> {
        use base64::Engine;
        crate::policy::validate_repository(repository)?;
        crate::policy::validate_sha(expected_head)?;
        ensure!(
            !branch.is_empty()
                && branch.len() <= 255
                && !branch.starts_with('/')
                && !branch.ends_with('/')
                && !branch.contains("..")
                && !branch.contains("//")
                && !branch.ends_with(".lock")
                && branch
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
            "invalid commit branch"
        );
        ensure!(
            !message.trim().is_empty() && message.len() <= 65536 && !message.contains('\0'),
            "invalid commit message"
        );
        ensure!(
            !additions.is_empty() || !deletions.is_empty(),
            "commit has no file changes"
        );
        ensure!(
            additions.len() + deletions.len() <= 1000,
            "too many commit files"
        );
        for path in additions.keys().chain(deletions.iter()) {
            ensure!(
                !path.is_empty()
                    && path.len() <= 4096
                    && !path.starts_with('/')
                    && !path.contains(['\\', '\0', '\r', '\n'])
                    && path.split('/').all(|part| !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.eq_ignore_ascii_case(".git")),
                "invalid commit file path"
            );
        }
        if let WriteContext::NativeManagedFiles(write) = &self.writes {
            let t = &write.target;
            ensure!(
                repository == t.repository
                    && branch == t.branch
                    && expected_head == t.base_sha
                    && message == "Reconcile managed files"
                    && additions == t.additions
                    && deletions == t.deletions
                    && write
                        .committed_head
                        .lock()
                        .map_err(|_| anyhow::anyhow!("managed commit state poisoned"))?
                        .is_none(),
                "managed-file commit differs from the protected desired state"
            );
        }
        if let WriteContext::NativeReleasePreparation(write) = &self.writes {
            let t = &write.target;
            ensure!(
                repository == t.repository
                    && branch == t.release_branch
                    && expected_head == t.expected_head
                    && message == t.commit_message
                    && additions == t.additions
                    && deletions == t.deletions
                    && write
                        .committed_head
                        .lock()
                        .map_err(|_| anyhow::anyhow!("release commit state poisoned"))?
                        .is_none(),
                "release preparation commit differs from its verified artifact"
            );
        }
        if let WriteContext::NativeScratch(write) = &self.writes {
            ensure!(
                write.mode == NativeScratchMode::Securefix
                    && repository == write.target_repository
                    && write.destination_branch.as_deref() == Some(branch)
                    && expected_head == write.head_sha,
                "native Securefix commit differs from the exact target PR head"
            );
        }
        if let WriteContext::NativeInstance(write) = &self.writes {
            ensure!(
                write.mode == NativeInstanceMode::Securefix
                    && repository == write.target_repository
                    && branch == write.head_branch
                    && expected_head == write.head_sha,
                "native Securefix commit differs from the exact target PR head"
            );
        }
        ensure!(
            additions.values().map(Vec::len).sum::<usize>() <= 16 * 1024 * 1024,
            "commit contents exceed size limit"
        );
        ensure!(
            deletions
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == deletions.len()
                && deletions.iter().all(|path| !additions.contains_key(path)),
            "duplicate commit file change"
        );
        self.require_write_target(&Method::POST, &format!("/repos/{repository}/git/commits"))?;
        self.require_current_revision()?;
        let (headline, body) = message.split_once('\n').unwrap_or((message, ""));
        let input = serde_json::json!({
            "branch":{"repositoryNameWithOwner":repository,"branchName":branch},
            "expectedHeadOid":expected_head,
            "message":{"headline":headline,"body":body},
            "fileChanges":{
                "additions":additions.into_iter().map(|(path,bytes)| serde_json::json!({"path":path,"contents":base64::engine::general_purpose::STANDARD.encode(bytes)})).collect::<Vec<_>>(),
                "deletions":deletions.into_iter().map(|path| serde_json::json!({"path":path})).collect::<Vec<_>>()
            }
        });
        let response = self.builder(Method::POST, "/graphql")?.json(&serde_json::json!({
            "query":"mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid parents(first:2){nodes{oid}} signature{isValid state}}}}",
            "variables":{"input":input}
        })).send().context("GitHub signed commit mutation failed")?;
        ensure!(
            response.status().is_success(),
            "GitHub signed commit returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none(),
            "GitHub signed commit mutation was rejected"
        );
        let commit = &value["data"]["createCommitOnBranch"]["commit"];
        let sha = commit["oid"]
            .as_str()
            .context("signed commit response has no SHA")?;
        crate::policy::validate_sha(sha)?;
        ensure!(
            commit["signature"]["isValid"] == true && commit["signature"]["state"] == "VALID",
            "created commit does not have a verified signature"
        );
        let parents = commit["parents"]["nodes"]
            .as_array()
            .context("commit parents missing")?;
        ensure!(
            parents.len() == 1 && parents[0]["oid"] == expected_head,
            "created commit has unexpected parent"
        );
        if let WriteContext::NativeManagedFiles(write) = &self.writes {
            let mut recorded = write
                .committed_head
                .lock()
                .map_err(|_| anyhow::anyhow!("managed commit state poisoned"))?;
            ensure!(recorded.is_none(), "managed-file commit already recorded");
            *recorded = Some(sha.to_owned());
        }
        if let WriteContext::NativeReleasePreparation(write) = &self.writes {
            let mut recorded = write
                .committed_head
                .lock()
                .map_err(|_| anyhow::anyhow!("release commit state poisoned"))?;
            ensure!(
                recorded.is_none(),
                "release preparation commit already recorded"
            );
            *recorded = Some(sha.to_owned());
        }
        Ok(sha.to_owned())
    }

    pub fn enable_scratch_auto_merge(
        &self,
        repository: &str,
        number: u64,
        expected_head: &str,
    ) -> Result<()> {
        ensure!(
            matches!(self.writes, WriteContext::Scratch { .. }),
            "auto-merge probe requires scratch context"
        );
        crate::policy::validate_repository(repository)?;
        crate::policy::validate_sha(expected_head)?;
        ensure!(number > 0, "invalid auto-merge PR number");
        let path = format!("/repos/{repository}/pulls/{number}");
        self.require_write_target(&Method::GET, &path)?;
        let pull: Value = self.get(&path)?;
        ensure!(
            pull["number"] == number
                && pull["state"] == "open"
                && pull["base"]["repo"]["full_name"] == repository
                && pull["head"]["repo"]["full_name"] == repository
                && pull["head"]["sha"] == expected_head,
            "auto-merge PR no longer matches the accepted scratch head"
        );
        let node = pull["node_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("PR node ID missing")?;
        let response = self.builder(Method::POST, "/graphql")?.json(&serde_json::json!({
            "query":"mutation($input:EnablePullRequestAutoMergeInput!){enablePullRequestAutoMerge(input:$input){pullRequest{id autoMergeRequest{mergeMethod}}}}",
            "variables":{"input":{"pullRequestId":node,"expectedHeadOid":expected_head,"mergeMethod":"SQUASH"}}
        })).send().context("scratch auto-merge mutation failed")?;
        ensure!(
            response.status().is_success(),
            "scratch auto-merge returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none(),
            "scratch auto-merge was rejected"
        );
        let result = &value["data"]["enablePullRequestAutoMerge"]["pullRequest"];
        ensure!(
            result["id"] == node && result["autoMergeRequest"]["mergeMethod"] == "SQUASH",
            "scratch auto-merge was not enabled for the expected PR"
        );
        Ok(())
    }

    pub fn paginate(&self, path: &str) -> Result<Vec<Value>> {
        self.paginate_with_cache_control(path, false)
    }
    pub fn paginate_uncached(&self, path: &str) -> Result<Vec<Value>> {
        self.paginate_with_cache_control(path, true)
    }
    fn paginate_with_cache_control(&self, path: &str, no_cache: bool) -> Result<Vec<Value>> {
        let delimiter = if path.contains('?') { '&' } else { '?' };
        let mut result = Vec::new();
        for page in 1..=100 {
            let page_path = format!("{path}{delimiter}per_page=100&page={page}");
            let values: Vec<Value> = if no_cache {
                self.get_uncached(&page_path)?
            } else {
                self.get(&page_path)?
            };
            let last = values.len() < 100;
            result.extend(values);
            if last {
                return Ok(result);
            }
        }
        bail!("GitHub pagination exceeded limit")
    }
    pub fn download(&self, path: &str, max: usize) -> Result<Vec<u8>> {
        let accept = if path.contains("/releases/assets/") {
            "application/octet-stream"
        } else {
            "application/vnd.github+json"
        };
        let request = self.builder_with_accept(Method::GET, path, accept)?;
        let response = request.send()?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("missing download redirect")?
                .to_str()?;
            let url = reqwest::Url::parse(location)?;
            ensure!(
                url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
                "unsafe download redirect"
            );
            let host = url.host_str().context("missing download host")?;
            ensure!(
                host.ends_with(".blob.core.windows.net")
                    || host.ends_with(".actions.githubusercontent.com")
                    || host == "objects.githubusercontent.com"
                    || host == "release-assets.githubusercontent.com",
                "unexpected artifact host"
            );
            let download = self
                .client
                .get(url)
                .send()
                .map_err(|_| anyhow::anyhow!("artifact download failed"))?;
            ensure!(
                download.status().is_success(),
                "artifact download returned {}",
                download.status()
            );
            return bounded_read(download, max);
        }
        if !response.status().is_success() {
            return Err(ApiError {
                status: response.status(),
                method: Method::GET,
                path: path.to_string(),
            }
            .into());
        }
        bounded_read(response, max)
    }
    pub fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<Value> {
        ensure!(
            !matches!(
                self.writes,
                WriteContext::Scratch { .. } | WriteContext::NativeScratch(_)
            ),
            "integration cannot upload release assets"
        );
        if let WriteContext::PackageScratch {
            destination_repository,
            destination_repository_id,
            tag,
            asset_name,
            max_asset_bytes,
            release_id,
            ..
        } = &self.writes
        {
            let release_id = release_id.context("package release identity was not validated")?;
            let api_path = validate_package_scratch_upload(
                path,
                destination_repository,
                release_id,
                asset_name,
                *max_asset_bytes,
                bytes.len(),
                content_type,
            )?;
            self.require_write_target(&Method::POST, &api_path)?;
            let repository: Value = self.get(&format!("/repos/{destination_repository}"))?;
            ensure!(
                repository["id"].as_u64() == Some(*destination_repository_id)
                    && repository["full_name"] == destination_repository.as_str(),
                "package destination repository identity changed before upload"
            );
            let release: Value = self.get(&format!(
                "/repos/{destination_repository}/releases/{release_id}"
            ))?;
            ensure!(
                release["id"].as_u64() == Some(release_id)
                    && release["tag_name"] == tag.as_str()
                    && release["prerelease"] == true
                    && release["draft"] == true,
                "package upload release is not the selected draft prerelease"
            );
        } else if let WriteContext::NativeRelease(write) = &self.writes {
            let api_path = native_release_upload_url(write, path)?;
            let asset = write
                .assets
                .iter()
                .find(|asset| api_path.ends_with(&format!("?name={}", asset.name)))
                .context("native release upload asset is not in the verified plan")?;
            ensure!(
                bytes.len() as u64 == asset.size
                    && crate::hex_encode(sha2::Sha256::digest(&bytes)) == asset.sha256
                    && content_type == asset.content_type,
                "native release upload bytes differ from the verified plan"
            );
            let release_id = write
                .release_id
                .context("native release draft identity was not selected")?;
            let existing = self.validate_native_release_asset_inventory(write, false)?;
            ensure!(
                !existing
                    .iter()
                    .any(|existing| existing["name"] == asset.name),
                "native release asset already exists"
            );
            self.require_write_target(&Method::POST, &api_path)?;
            let release: Value = self.get_uncached(&format!(
                "/repos/{}/releases/{release_id}",
                write.target_repository
            ))?;
            ensure!(
                release["id"].as_u64() == Some(release_id)
                    && release["tag_name"] == write.tag
                    && release["draft"] == true,
                "native release asset target is not the selected draft"
            );
        } else if let WriteContext::PackageRelease(write) = &self.writes {
            let api_path = package_release_upload_url(write, path)?;
            ensure!(
                bytes.len() as u64 == write.asset_size
                    && crate::hex_encode(sha2::Sha256::digest(&bytes)) == write.asset_sha256
                    && content_type == "application/octet-stream",
                "package upload bytes differ from the exact verified asset"
            );
            let release_id = write
                .release_id
                .context("package release draft identity was not selected")?;
            self.require_write_target(&Method::POST, &api_path)?;
            self.require_current_revision()?;
            let writer_reader = self.package_writer_reader()?;
            let release: Value = writer_reader.get_uncached(&format!(
                "/repos/{}/releases/{release_id}",
                write.destination_repository
            ))?;
            validate_package_release_draft(write, &release, release_id, false)?;
            let assets = release["assets"]
                .as_array()
                .context("package release draft asset list is missing")?;
            ensure!(
                assets.is_empty(),
                "package release draft already has an asset"
            );
        } else {
            ensure!(
                !matches!(
                    self.writes,
                    WriteContext::Scratch { .. } | WriteContext::NativeScratch(_)
                ),
                "integration cannot upload release assets"
            );
        }
        self.require_current_revision()?;
        let url = reqwest::Url::parse(path)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("uploads.github.com")
                && url.username().is_empty()
                && url.password().is_none(),
            "invalid upload endpoint"
        );
        let upload_token = if matches!(
            self.writes,
            WriteContext::NativeRelease(_) | WriteContext::PackageRelease(_)
        ) {
            self.write_token
                .as_deref()
                .context("native release write token is missing")?
        } else {
            &self.token
        };
        let response = self
            .client
            .post(url)
            .bearer_auth(upload_token)
            .header("User-Agent", "securefix")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", content_type)
            .body(bytes)
            .send()?;
        let status = response.status();
        ensure!(status.is_success(), "GitHub upload returned {status}");
        Ok(response.json()?)
    }
    pub fn content(&self, repository: &str, path: &str, revision: &str) -> Result<Vec<u8>> {
        self.content_with_cache_control(repository, path, revision, false)
    }

    pub fn content_uncached(
        &self,
        repository: &str,
        path: &str,
        revision: &str,
    ) -> Result<Vec<u8>> {
        self.content_with_cache_control(repository, path, revision, true)
    }

    fn content_with_cache_control(
        &self,
        repository: &str,
        path: &str,
        revision: &str,
        no_cache: bool,
    ) -> Result<Vec<u8>> {
        use base64::Engine;
        let content_path = format!("/repos/{repository}/contents/{path}?ref={revision}");
        let value: Value = if no_cache {
            self.get_uncached(&content_path)?
        } else {
            self.get(&content_path)?
        };
        ensure!(value["encoding"] == "base64", "unexpected content encoding");
        let content = value["content"]
            .as_str()
            .context("missing file content")?
            .replace('\n', "");
        Ok(base64::engine::general_purpose::STANDARD.decode(content)?)
    }

    pub fn optional_branch_head(&self, repository: &str, branch: &str) -> Result<Option<String>> {
        crate::policy::validate_repository(repository)?;
        crate::config::validate_branch(branch)?;
        let branch: Value = match self.get_uncached(&format!(
            "/repos/{repository}/branches/{}",
            encode_path_segment(branch)
        )) {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|error| error.status == StatusCode::NOT_FOUND) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let sha = branch["commit"]["sha"]
            .as_str()
            .context("branch commit SHA is missing")?;
        crate::policy::validate_sha(sha)?;
        Ok(Some(sha.to_owned()))
    }

    pub fn branch_head(&self, repository: &str, branch: &str) -> Result<String> {
        crate::policy::validate_repository(repository)?;
        crate::config::validate_branch(branch)?;
        let commit: Value = self.get(&format!(
            "/repos/{repository}/commits/{}",
            encode_path_segment(branch)
        ))?;
        let sha = commit["sha"]
            .as_str()
            .context("branch commit SHA is missing")?;
        crate::policy::validate_sha(sha)?;
        Ok(sha.to_owned())
    }
}

fn git_authorization_header(token: &str) -> String {
    use base64::Engine;

    let credentials = format!("x-access-token:{token}");
    format!(
        "Authorization: Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    )
}

fn isolated_git_command(
    repository: &Path,
    args: &[&str],
    global_config: &Path,
    hooks: &Path,
    token: Option<&str>,
) -> Result<Command> {
    let isolation_dir = global_config
        .parent()
        .context("isolated Git config has no parent directory")?;
    let mut command = Command::new("git");
    command
        .env_clear()
        .current_dir(repository)
        .args(args)
        .stdin(Stdio::null())
        .env("PATH", ISOLATED_GIT_PATH)
        .env("HOME", isolation_dir)
        .env("XDG_CONFIG_HOME", isolation_dir)
        .env("TMPDIR", isolation_dir)
        .env("TMP", isolation_dir)
        .env("TEMP", isolation_dir)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", global_config)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    command
        .env("GIT_CONFIG_COUNT", if token.is_some() { "2" } else { "1" })
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", hooks);
    if let Some(token) = token {
        command
            .env("GIT_CONFIG_KEY_1", "http.https://github.com/.extraheader")
            .env("GIT_CONFIG_VALUE_1", git_authorization_header(token));
    }
    Ok(command)
}

fn git_output(
    repository: &Path,
    args: &[&str],
    global_config: &Path,
    hooks: &Path,
    token: Option<&str>,
    max_output: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut child = isolated_git_command(repository, args, global_config, hooks, token)?
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start isolated Git command")?;
    let stdout = child
        .stdout
        .take()
        .context("isolated Git stdout is unavailable")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(max_output as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });

    let mut output = None;
    loop {
        if output.is_none()
            && let Ok(result) = receiver.try_recv()
        {
            let bytes = match result {
                Ok(bytes) => bytes,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(error).context("read isolated Git output");
                }
            };
            if bytes.len() > max_output {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                bail!("isolated Git output exceeded size limit");
            }
            output = Some(bytes);
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(error).context("check isolated Git command");
            }
        };
        if let Some(status) = status {
            if output.is_none() {
                let result = receiver.recv_timeout(Duration::from_secs(1));
                let bytes = match result {
                    Ok(Ok(bytes)) => bytes,
                    Ok(Err(error)) => {
                        let _ = reader.join();
                        return Err(error).context("read isolated Git output");
                    }
                    Err(error) => {
                        let _ = reader.join();
                        return Err(error).context("isolated Git output did not finish");
                    }
                };
                ensure!(
                    bytes.len() <= max_output,
                    "isolated Git output exceeded size limit"
                );
                output = Some(bytes);
            }
            reader
                .join()
                .map_err(|_| anyhow::anyhow!("isolated Git output reader failed"))?;
            ensure!(status.success(), "isolated Git command failed");
            return output.context("isolated Git output is missing");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            bail!("isolated Git operation timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn git_status(
    repository: &Path,
    args: &[&str],
    global_config: &Path,
    hooks: &Path,
    token: Option<&str>,
    object_directory: &Path,
    deadline: Instant,
) -> Result<()> {
    let mut child = isolated_git_command(repository, args, global_config, hooks, token)?
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start isolated Git operation")?;
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("check isolated Git operation");
            }
        };
        if let Some(status) = status {
            ensure!(status.success(), "isolated Git operation failed");
            let object_bytes = git_object_store_size(object_directory)?;
            ensure!(
                object_bytes <= MAX_AUTHORITY_OBJECT_BYTES,
                "authority Git object store exceeded size limit"
            );
            return Ok(());
        }
        let object_bytes = match git_object_store_size(object_directory) {
            Ok(size) => size,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("check authority Git object store size");
            }
        };
        if object_bytes > MAX_AUTHORITY_OBJECT_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            bail!("authority Git object store exceeded size limit");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("isolated Git operation timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn git_object_store_size(directory: &Path) -> Result<u64> {
    let root = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("inspect Git object store"),
    };
    ensure!(
        root.is_dir() && !root.file_type().is_symlink(),
        "Git object store root is not a directory"
    );
    let mut pending = vec![directory.to_owned()];
    let mut total = 0u64;
    while let Some(current) = pending.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("read Git object store"),
        };
        for entry in entries {
            let entry = entry.context("read Git object store entry")?;
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("inspect Git object store entry"),
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let size = match entry.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error).context("read Git object size"),
                };
                total = total
                    .checked_add(size)
                    .context("Git object store size overflow")?;
            } else {
                bail!("unexpected file type in Git object store");
            }
        }
    }
    Ok(total)
}

fn first_parent_path_epoch_at(
    repository: &Path,
    revision: &str,
    paths: &[String],
    global_config: &Path,
    hooks: &Path,
    deadline: Instant,
) -> Result<String> {
    crate::policy::validate_sha(revision)?;
    ensure!(!paths.is_empty(), "authority path set is empty");
    for path in paths {
        validate_instance_config_path(path)?;
    }
    let shallow = git_output(
        repository,
        &["rev-parse", "--is-shallow-repository"],
        global_config,
        hooks,
        None,
        16,
        deadline,
    )?;
    ensure!(
        shallow.as_slice() == b"false\n",
        "authority history is shallow"
    );
    let history = git_output(
        repository,
        &["rev-list", "--first-parent", "--parents", revision],
        global_config,
        hooks,
        None,
        MAX_AUTHORITY_HISTORY_BYTES,
        deadline,
    )?;
    let history = std::str::from_utf8(&history).context("invalid Git history output")?;
    let mut commits = Vec::<(String, Option<String>)>::new();
    for line in history.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        ensure!(!fields.is_empty(), "empty Git history line");
        crate::policy::validate_sha(fields[0])?;
        for parent in &fields[1..] {
            crate::policy::validate_sha(parent)?;
        }
        commits.push((
            fields[0].to_owned(),
            fields.get(1).map(|parent| (*parent).to_owned()),
        ));
    }
    ensure!(
        commits.first().is_some_and(|commit| commit.0 == revision),
        "Git history does not start at the requested snapshot"
    );
    for pair in commits.windows(2) {
        ensure!(
            pair[0].1.as_deref() == Some(pair[1].0.as_str()),
            "Git first-parent history is incomplete"
        );
    }
    ensure!(
        commits.last().is_some_and(|commit| commit.1.is_none()),
        "Git first-parent history did not reach its root"
    );

    let path_specs = paths.iter().map(String::as_str).collect::<Vec<_>>();
    let mut epoch = None;
    let mut diff_bytes = 0usize;
    for (sha, parent) in &commits {
        let mut args = if let Some(parent) = parent {
            vec![
                "--literal-pathspecs",
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "--no-renames",
                "-r",
                "-z",
                parent.as_str(),
                sha.as_str(),
                "--",
            ]
        } else {
            vec![
                "--literal-pathspecs",
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "--no-renames",
                "-r",
                "-z",
                sha.as_str(),
                "--",
            ]
        };
        args.extend_from_slice(&path_specs);
        let changed = git_output(
            repository,
            &args,
            global_config,
            hooks,
            None,
            MAX_GIT_OUTPUT_BYTES,
            deadline,
        )?;
        diff_bytes = diff_bytes
            .checked_add(changed.len())
            .context("authority diff output size overflow")?;
        ensure!(
            diff_bytes <= MAX_AUTHORITY_DIFF_BYTES,
            "authority diff output exceeded size limit"
        );
        for path in changed
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            ensure!(
                paths.iter().any(|candidate| candidate.as_bytes() == path),
                "Git returned an unexpected authority path"
            );
            epoch.get_or_insert_with(|| sha.clone());
        }
        if epoch.is_some() {
            break;
        }
    }
    epoch.context("authority paths have no first-parent history")
}

fn first_parent_path_epoch(
    api: &GitHub,
    repository: &str,
    branch: &str,
    revision: &str,
    paths: &[String],
) -> Result<String> {
    crate::policy::validate_repository(repository)?;
    crate::config::validate_branch(branch)?;
    crate::policy::validate_sha(revision)?;
    ensure!(!paths.is_empty(), "authority path set is empty");
    for path in paths {
        validate_instance_config_path(path)?;
    }
    ensure!(
        !api.token.is_empty() && !api.token.contains(['\r', '\n']),
        "a valid GitHub read token is required for first-parent history"
    );

    let deadline = Instant::now() + MAX_GIT_OPERATION_TIME;
    let directory = tempfile::tempdir().context("create isolated authority history repository")?;
    let repository_dir = directory.path().join("repository.git");
    let object_directory = repository_dir.join("objects");
    let global_config = directory.path().join("global-config");
    let hooks = directory.path().join("empty-hooks");
    std::fs::write(
        &global_config,
        "[credential]\n\thelper =\n[http]\n\tfollowRedirects = false\n[protocol]\n\tallow = never\n[protocol \"https\"]\n\tallow = always\n",
    )?;
    std::fs::create_dir(&hooks)?;
    git_output(
        directory.path(),
        &[
            "init",
            "--bare",
            "--quiet",
            "--template=",
            repository_dir.to_str().context("Git path is not UTF-8")?,
        ],
        &global_config,
        &hooks,
        None,
        MAX_GIT_OUTPUT_BYTES,
        deadline,
    )?;
    ensure!(
        git_object_store_size(&object_directory)? == 0,
        "new authority Git object store is not empty"
    );
    let remote = format!("https://github.com/{repository}.git");
    git_output(
        &repository_dir,
        &["remote", "add", "origin", &remote],
        &global_config,
        &hooks,
        None,
        MAX_GIT_OUTPUT_BYTES,
        deadline,
    )?;
    git_status(
        &repository_dir,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--filter=blob:none",
            "origin",
            revision,
        ],
        &global_config,
        &hooks,
        Some(&api.token),
        &object_directory,
        deadline,
    )?;
    let fetched = git_output(
        &repository_dir,
        &["rev-parse", "FETCH_HEAD^{commit}"],
        &global_config,
        &hooks,
        None,
        64,
        deadline,
    )?;
    ensure!(
        std::str::from_utf8(&fetched)?.trim() == revision,
        "Git did not fetch the exact authority snapshot"
    );
    first_parent_path_epoch_at(
        &repository_dir,
        revision,
        paths,
        &global_config,
        &hooks,
        deadline,
    )
}

pub fn capture_native_release_sync_workflow_epoch(
    api: &GitHub,
    repository_name: &str,
    repository_id: u64,
    default_branch: &str,
    workflow_path: &str,
    workflow_revision: &str,
) -> Result<String> {
    crate::policy::validate_repository(repository_name)?;
    crate::config::validate_branch(default_branch)?;
    crate::policy::validate_sha(workflow_revision)?;
    validate_native_release_workflow_path(workflow_path)?;
    let protected_revision = api.branch_head(repository_name, default_branch)?;
    let protected_workflow = api.content(repository_name, workflow_path, &protected_revision)?;
    let release_workflow = api.content(repository_name, workflow_path, workflow_revision)?;
    ensure!(
        protected_workflow == release_workflow,
        "release sync caller differs from its protected default-branch version"
    );
    let epoch = capture_native_client_workflow_epoch(
        api,
        repository_name,
        repository_id,
        default_branch,
        workflow_path,
        &protected_revision,
        None,
    )?;
    ensure!(
        api.branch_head(repository_name, default_branch)? == protected_revision,
        "default branch moved during release sync authority capture"
    );
    Ok(epoch)
}

pub fn capture_native_client_workflow_epoch(
    api: &GitHub,
    repository_name: &str,
    repository_id: u64,
    default_branch: &str,
    workflow_path: &str,
    workflow_revision: &str,
    pull_request_head: Option<&str>,
) -> Result<String> {
    crate::policy::validate_repository(repository_name)?;
    ensure!(repository_id > 0, "invalid authority repository ID");
    crate::config::validate_branch(default_branch)?;
    crate::policy::validate_sha(workflow_revision)?;
    let workflow_name = workflow_path
        .strip_prefix(".github/workflows/")
        .context("caller workflow path is outside .github/workflows")?;
    ensure!(
        workflow_name.ends_with(".yml")
            && !workflow_name.is_empty()
            && !workflow_path.contains(['\\', '%', '?', '#'])
            && workflow_name
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && workflow_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "invalid caller workflow path"
    );

    let repository: Value = api.get(&format!("/repos/{repository_name}"))?;
    ensure!(
        repository["id"].as_u64() == Some(repository_id)
            && repository["full_name"].as_str() == Some(repository_name)
            && repository["default_branch"].as_str() == Some(default_branch),
        "native request repository or default branch identity changed"
    );
    let snapshot_sha = api.branch_head(repository_name, default_branch)?;
    let workflow_bytes = api.content(repository_name, workflow_path, &snapshot_sha)?;
    let captured_workflow = api.content(repository_name, workflow_path, workflow_revision)?;
    ensure!(
        workflow_bytes == captured_workflow,
        "caller workflow differs from its protected default-branch version"
    );
    require_native_client_workflow_revision(
        api,
        repository_name,
        workflow_revision,
        &snapshot_sha,
        pull_request_head,
    )?;
    let workflow_epoch = first_parent_path_epoch(
        api,
        repository_name,
        default_branch,
        &snapshot_sha,
        &[workflow_path.to_owned()],
    )?;
    ensure!(
        api.branch_head(repository_name, default_branch)? == snapshot_sha,
        "instance default branch moved during authority capture"
    );
    Ok(workflow_epoch)
}

fn require_native_client_workflow_revision(
    api: &GitHub,
    repository: &str,
    revision: &str,
    protected_revision: &str,
    pull_request_head: Option<&str>,
) -> Result<()> {
    let compare: Value = api.get(&format!(
        "/repos/{repository}/compare/{revision}...{protected_revision}"
    ))?;
    if matches!(compare["status"].as_str(), Some("ahead" | "identical")) {
        return Ok(());
    }
    let head =
        pull_request_head.context("caller workflow revision is not on default-branch history")?;
    crate::policy::validate_sha(head)?;
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{revision}"))?;
    ensure!(
        commit["sha"].as_str() == Some(revision),
        "caller merge revision identity differs"
    );
    let parents = commit["parents"]
        .as_array()
        .context("caller merge revision parents are missing")?;
    ensure!(
        parents.len() == 2 && parents[1]["sha"].as_str() == Some(head),
        "caller merge revision is not bound to the exact PR head"
    );
    let base = parents[0]["sha"]
        .as_str()
        .context("caller merge revision base is missing")?;
    crate::policy::validate_sha(base)?;
    ensure!(base != head, "caller merge revision parents are identical");
    let compare: Value = api.get(&format!(
        "/repos/{repository}/compare/{base}...{protected_revision}"
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "caller merge revision base is not on default-branch history"
    );
    Ok(())
}

pub fn require_native_authority_unchanged(
    captured: &NativeAuthoritySnapshot,
    current: &NativeAuthoritySnapshot,
) -> Result<()> {
    ensure!(
        captured == current,
        "native request configuration or caller authority history changed"
    );
    Ok(())
}

fn require_native_server_instance_authority_unchanged(
    captured: &NativeServerInstanceAuthority,
    current: &NativeServerInstanceAuthority,
) -> Result<()> {
    ensure!(
        captured.config_bytes == current.config_bytes,
        "native Server config changed since authority capture"
    );
    require_native_authority_unchanged(&captured.authority, &current.authority)
}

pub fn validate_native_authority_snapshot(snapshot: &NativeAuthoritySnapshot) -> Result<()> {
    crate::policy::validate_repository(&snapshot.instance_repository)?;
    validate_instance_config_path(&snapshot.config_path)?;
    crate::config::validate_branch(&snapshot.default_branch)?;
    ensure!(
        snapshot.instance_id > 0,
        "native Server instance ID is invalid"
    );
    validate_sha256(&snapshot.config_sha256, "native Server config digest")?;
    crate::policy::validate_sha(&snapshot.epoch)?;
    ensure!(
        !snapshot.workflows.is_empty() && snapshot.workflows.len() <= 16,
        "native Server workflow authority set is invalid"
    );
    let mut roles = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for workflow in &snapshot.workflows {
        validate_instance_config_path(&workflow.path)?;
        validate_sha256(&workflow.sha256, "native Server workflow digest")?;
        ensure!(
            roles.insert(workflow.role) && paths.insert(workflow.path.as_str()),
            "native Server workflow authority contains duplicates"
        );
        ensure!(workflow.pins.len() <= 256, "too many Server workflow pins");
        for pin in &workflow.pins {
            let (_, revision) = pin
                .rsplit_once('@')
                .context("native Server workflow pin is malformed")?;
            crate::policy::validate_sha(revision)
                .context("native Server workflow pin is not a full SHA")?;
        }
    }
    Ok(())
}

/// Return the canonical label name for a native request operation.
pub fn native_client_request_label(operation: &str, run_id: u64) -> Result<String> {
    ensure!(run_id > 0, "invalid native request run ID");
    let role = match operation {
        "policy_check" => "policy-check",
        "securefix" => "securefix",
        "approval" => "approve",
        "merge" => "merge",
        "release_prepare" => "release-prepare",
        _ => anyhow::bail!("unsupported native request operation"),
    };
    let label = format!("securefix-native-{role}-{run_id}");
    ensure!(
        label.len() <= 50,
        "native request label exceeds GitHub limit"
    );
    Ok(label)
}

fn validate_native_client_label_target(
    target: &NativeClientLabelTarget<'_>,
) -> Result<(String, String)> {
    validate_native_authority_snapshot(target.server_authority)?;
    crate::policy::validate_repository(target.server_repository)?;
    crate::policy::validate_repository(target.client_repository)?;
    ensure!(
        target.server_repository == target.server_authority.instance_repository,
        "native Client label target differs from the captured Server authority"
    );
    let label = native_client_request_label(target.operation, target.run_id)?;
    let description = format!("{}/{}", target.client_repository, target.run_id);
    ensure!(
        description.len() <= 100,
        "native request label description exceeds GitHub limit"
    );
    Ok((label, description))
}

fn validate_native_release_tag_target(
    target: &NativeReleaseTagWriteTarget<'_>,
    source_run_id: u64,
) -> Result<NativeReleaseTagWrite> {
    let instance = target.instance;
    validate_native_authority_snapshot(&instance.authority)?;
    validate_instance_config_path(target.config_path)?;
    let config = crate::instance_config::InstanceConfig::parse(&instance.config_bytes)?;
    ensure!(
        instance.authority.instance_repository == config.instance.repository
            && instance.authority.instance_id == config.instance.id
            && instance.authority.default_branch == config.instance.default_branch
            && instance.authority.config_path == target.config_path
            && instance.authority.config_sha256
                == crate::hex_encode(sha2::Sha256::digest(&instance.config_bytes))
            && instance.config.instance.repository == config.instance.repository
            && instance.config.instance.id == config.instance.id
            && instance.config.instance.default_branch == config.instance.default_branch
            && instance.config.workflow_roles == config.workflow_roles,
        "native release tag Server config does not match its captured authority"
    );
    crate::policy::validate_repository(target.repository)?;
    let destination = config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == target.repository && repository.id == target.repository_id
        })
        .context("native release tag destination is not configured")?;
    destination
        .policy()
        .require(crate::policy::Capability::Release)
        .context("native release tag destination lacks the Release capability")?;
    let captured_destination = instance
        .config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == target.repository && repository.id == target.repository_id
        })
        .context("captured native release tag destination is not configured")?;
    captured_destination
        .policy()
        .require(crate::policy::Capability::Release)
        .context("captured native release tag destination lacks the Release capability")?;
    ensure!(
        target.repository_id > 0 && target.release_pr_number > 0 && source_run_id > 0,
        "native release tag repository, PR, or run identity is invalid"
    );
    crate::release_manifest::CommitSha::parse(target.release_pr_head_sha)?;
    crate::release_manifest::CommitSha::parse(target.release_pr_merge_sha)?;
    crate::release_manifest::ReleaseTag::parse(target.tag)?;
    Ok(NativeReleaseTagWrite {
        instance: instance.clone(),
        config_path: target.config_path.to_owned(),
        repository: target.repository.to_owned(),
        repository_id: target.repository_id,
        release_pr_number: target.release_pr_number,
        release_pr_head_sha: target.release_pr_head_sha.to_owned(),
        release_pr_merge_sha: target.release_pr_merge_sha.to_owned(),
        tag: target.tag.to_owned(),
        source_run_id,
        tag_object_sha: Arc::new(Mutex::new(None)),
    })
}

fn validate_native_release_preparation_target(t: &NativeReleasePreparationTarget) -> Result<()> {
    let config = crate::instance_config::InstanceConfig::parse(&t.instance.config_bytes)?;
    validate_native_authority_snapshot(&t.instance.authority)?;
    ensure!(
        t.instance.authority.config_sha256
            == crate::hex_encode(sha2::Sha256::digest(&t.instance.config_bytes))
            && t.instance.authority.instance_repository == config.instance.repository
            && t.instance.authority.instance_id == config.instance.id,
        "release preparation config is not bound to its authority"
    );
    let repo = config
        .repositories
        .iter()
        .find(|r| r.repository == t.repository && r.id == t.repository_id)
        .context("release preparation destination is not configured")?;
    repo.policy().require(crate::policy::Capability::Release)?;
    crate::policy::validate_sha(&t.source_sha)?;
    crate::policy::validate_sha(&t.expected_head)?;
    crate::policy::validate_sha(&t.workflow_sha)?;
    crate::policy::validate_sha(&t.workflow_epoch)?;
    crate::config::validate_branch(&t.default_branch)?;
    crate::config::validate_branch(&t.release_branch)?;
    ensure!(
        Some(t.release_branch.as_str()) == config.branches.release.as_deref()
            && t.release_branch != t.default_branch
            && (t.branch_exists || t.expected_head == t.source_sha)
            && t.run_id > 0
            && t.run_attempt == 1
            && t.existing_pull_request != Some(0)
            && t.workflow_path.starts_with(".github/workflows/")
            && t.workflow_path.ends_with(".yml")
            && !t.additions.is_empty()
            && t.deletions.is_empty()
            && t.additions.keys().all(|p| [
                ".release-version",
                "CHANGELOG.md",
                "Cargo.toml",
                "Cargo.lock",
                "dbt_project.yml",
                "pyproject.toml"
            ]
            .contains(&p.as_str()))
            && !t.title.is_empty()
            && t.title.len() <= 256
            && t.body.len() <= 65536,
        "release preparation target is not bounded to release metadata"
    );
    Ok(())
}

fn validate_native_release_preparation_run(
    t: &NativeReleasePreparationTarget,
    run: &Value,
) -> Result<()> {
    let owner = &t.instance.config.identities.owner;
    let bot = &t.instance.config.identities.server_bot;
    let actor = &run["actor"];
    let principal = (actor["id"].as_u64() == Some(owner.id)
        && actor["login"] == owner.login
        && actor["type"] == "User")
        || (actor["id"].as_u64() == Some(bot.id)
            && actor["login"] == bot.login
            && actor["type"] == "Bot");
    ensure!(
        run["id"].as_u64() == Some(t.run_id)
            && run["run_attempt"].as_u64() == Some(t.run_attempt)
            && run["repository"]["id"].as_u64() == Some(t.repository_id)
            && run["repository"]["full_name"] == t.repository
            && run["head_repository"]["id"].as_u64() == Some(t.repository_id)
            && run["head_sha"] == t.source_sha
            && run["head_branch"] == t.default_branch
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && matches!(run["event"].as_str(), Some("push" | "workflow_dispatch"))
            && principal,
        "release preparation source run is unsuccessful, changed or unauthorized"
    );
    Ok(())
}

fn validate_native_release_preparation_body(
    write: &NativeReleasePreparationWrite,
    method: &Method,
    path: &str,
    body: &Value,
) -> Result<()> {
    let t = &write.target;
    let committed = write
        .committed_head
        .lock()
        .map_err(|_| anyhow::anyhow!("release commit state poisoned"))?;
    if *method == Method::POST && path == format!("/repos/{}/git/refs", t.repository) {
        ensure!(
            !t.branch_exists
                && committed.is_none()
                && body
                    == &serde_json::json!({"ref":format!("refs/heads/{}",t.release_branch),"sha":t.expected_head}),
            "release preparation ref differs from its expected head"
        );
    } else if *method == Method::POST && path == format!("/repos/{}/pulls", t.repository) {
        ensure!(
            t.existing_pull_request.is_none()
                && committed.is_some()
                && body
                    == &serde_json::json!({"title":t.title,"body":t.body,"head":t.release_branch,"base":t.default_branch,"draft":false}),
            "release preparation PR creation differs from its signed commit and metadata"
        );
    } else {
        ensure!(
            *method == Method::PATCH
                && t.existing_pull_request
                    .is_some_and(|n| path == format!("/repos/{}/pulls/{n}", t.repository))
                && committed.is_some()
                && body == &serde_json::json!({"title":t.title,"body":t.body}),
            "release preparation may only update its existing Server-owned PR metadata"
        );
    }
    Ok(())
}

fn validate_native_release_pr_metadata_target(write: &NativeReleasePrMetadataTarget) -> Result<()> {
    crate::policy::validate_repository(&write.repository)?;
    crate::policy::validate_sha(&write.head_sha)?;
    crate::policy::validate_sha(&write.workflow_sha)?;
    crate::policy::validate_sha(&write.workflow_epoch)?;
    crate::config::validate_branch(&write.default_branch)?;
    validate_native_authority_snapshot(&write.instance.authority)?;
    let config = crate::instance_config::InstanceConfig::parse(&write.instance.config_bytes)?;
    ensure!(
        write.instance.authority.config_sha256
            == crate::hex_encode(sha2::Sha256::digest(&write.instance.config_bytes)),
        "native release metadata config differs from its captured authority"
    );
    ensure!(
        config.instance.repository == write.instance.authority.instance_repository
            && config.instance.id == write.instance.authority.instance_id
            && config.instance.default_branch == write.instance.authority.default_branch,
        "native release metadata instance differs from its captured authority"
    );
    let configured = config
        .repositories
        .iter()
        .find(|r| r.repository == write.repository && r.id == write.repository_id)
        .context("native release metadata destination is not configured")?;
    configured
        .policy()
        .require(crate::policy::Capability::Release)?;
    ensure!(
        write.pull_number > 0
            && write.run_id > 0
            && write.run_attempt == 1
            && write.workflow_sha == write.head_sha
            && write.workflow_path.starts_with(".github/workflows/")
            && !write.workflow_path[18..].contains('/')
            && write.workflow_path.ends_with(".yml")
            && write.title.starts_with("chore(release): v")
            && write.title.len() <= 256
            && write.body.len() <= 65536,
        "invalid native release PR metadata target"
    );
    Ok(())
}

fn validate_native_release_pr_metadata_pull(
    write: &NativeReleasePrMetadataTarget,
    pull: &Value,
) -> Result<()> {
    let config = crate::instance_config::InstanceConfig::parse(&write.instance.config_bytes)?;
    ensure!(
        pull["number"].as_u64() == Some(write.pull_number)
            && pull["state"] == "open"
            && pull["head"]["sha"].as_str() == Some(write.head_sha.as_str())
            && pull["head"]["ref"].as_str() == config.branches.release.as_deref()
            && pull["head"]["repo"]["id"].as_u64() == Some(write.repository_id)
            && pull["head"]["repo"]["full_name"].as_str() == Some(write.repository.as_str())
            && pull["base"]["ref"].as_str() == Some(write.default_branch.as_str())
            && pull["base"]["repo"]["id"].as_u64() == Some(write.repository_id)
            && pull["base"]["repo"]["full_name"].as_str() == Some(write.repository.as_str())
            && pull["user"]["id"].as_u64() == Some(config.identities.server_bot.id)
            && pull["user"]["login"].as_str() == Some(config.identities.server_bot.login.as_str())
            && pull["user"]["type"] == "Bot",
        "native release metadata PR head, base, repository, or Server author changed"
    );
    Ok(())
}

fn validate_native_release_tag_execution(write: &NativeReleaseTagWrite) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.repository.as_str()),
        "native release tag destination differs from the current workflow repository"
    );
    let run_id = std::env::var("GITHUB_RUN_ID")
        .context("missing GITHUB_RUN_ID for native release tag")?
        .parse::<u64>()
        .context("invalid GITHUB_RUN_ID for native release tag")?;
    ensure!(
        run_id == write.source_run_id,
        "native release tag run differs from the captured workflow run"
    );
    Ok(())
}

fn validate_native_release_tag_saved(write: &NativeReleaseTagWrite) -> Result<()> {
    let target = NativeReleaseTagWriteTarget {
        instance: &write.instance,
        config_path: &write.config_path,
        repository: &write.repository,
        repository_id: write.repository_id,
        release_pr_number: write.release_pr_number,
        release_pr_head_sha: &write.release_pr_head_sha,
        release_pr_merge_sha: &write.release_pr_merge_sha,
        tag: &write.tag,
    };
    let expected = validate_native_release_tag_target(&target, write.source_run_id)?;
    ensure!(
        expected.instance.config.instance.repository == write.instance.config.instance.repository
            && expected.config_path == write.config_path
            && expected.repository == write.repository
            && expected.repository_id == write.repository_id
            && expected.release_pr_number == write.release_pr_number
            && expected.release_pr_head_sha == write.release_pr_head_sha
            && expected.release_pr_merge_sha == write.release_pr_merge_sha
            && expected.tag == write.tag,
        "saved native release tag differs from the protected instance and merged PR"
    );
    Ok(())
}

fn validate_native_release_tag_body(
    write: &NativeReleaseTagWrite,
    method: &Method,
    path: &str,
    body: &Value,
) -> Result<()> {
    let tag_path = format!("/repos/{}/git/tags", write.repository);
    if *method == Method::POST && path == tag_path {
        let state = write
            .tag_object_sha
            .lock()
            .map_err(|_| anyhow::anyhow!("native release tag state is poisoned"))?;
        ensure!(
            state.is_none(),
            "native release tag object was already created"
        );
        ensure!(
            body == &serde_json::json!({
                "tag": write.tag,
                "message": format!("Release {}", write.tag),
                "object": write.release_pr_merge_sha,
                "type": "commit",
            }),
            "native annotated tag request differs from the exact merged release plan"
        );
        return Ok(());
    }
    if *method == Method::POST && path == format!("/repos/{}/git/refs", write.repository) {
        let state = write
            .tag_object_sha
            .lock()
            .map_err(|_| anyhow::anyhow!("native release tag state is poisoned"))?;
        let object_sha = state
            .as_deref()
            .context("native release tag object response was not validated")?;
        ensure!(
            body == &serde_json::json!({
                "ref": format!("refs/tags/{}", write.tag),
                "sha": object_sha,
            }),
            "native release reference request differs from the validated annotated tag object"
        );
        return Ok(());
    }
    bail!("native release tag request is outside the exact annotated tag lifecycle")
}

fn record_native_release_tag_created_object(
    write: &NativeReleaseTagWrite,
    response: &Value,
) -> Result<()> {
    let object_sha = validate_native_release_tag_created_object(write, response)?;
    let mut state = write
        .tag_object_sha
        .lock()
        .map_err(|_| anyhow::anyhow!("native release tag state is poisoned"))?;
    ensure!(
        state.is_none(),
        "native release tag object was already created"
    );
    *state = Some(object_sha);
    Ok(())
}

fn validate_native_release_tag_created_object(
    write: &NativeReleaseTagWrite,
    response: &Value,
) -> Result<String> {
    let sha = response["sha"]
        .as_str()
        .context("GitHub did not return a native annotated tag object SHA")?;
    crate::policy::validate_sha(sha)?;
    ensure!(
        response["tag"] == write.tag
            && response["message"] == format!("Release {}", write.tag)
            && response["object"]["sha"] == write.release_pr_merge_sha
            && response["object"]["type"] == "commit",
        "GitHub returned an annotated tag object for a different release plan"
    );
    Ok(sha.to_owned())
}

fn validate_native_client_release_label_target(
    target: &NativeClientReleaseLabelTarget<'_>,
) -> Result<NativeClientReleaseLabelWrite> {
    let instance = target.instance;
    validate_native_authority_snapshot(&instance.authority)?;
    validate_instance_config_path(target.config_path)?;
    let config = crate::instance_config::InstanceConfig::parse(&instance.config_bytes)?;
    ensure!(
        instance.authority.instance_repository == config.instance.repository
            && instance.authority.instance_id == config.instance.id
            && instance.authority.default_branch == config.instance.default_branch
            && instance.authority.config_path == target.config_path
            && instance.authority.config_sha256
                == crate::hex_encode(sha2::Sha256::digest(&instance.config_bytes))
            && instance.config.instance.repository == config.instance.repository
            && instance.config.instance.id == config.instance.id
            && instance.config.instance.default_branch == config.instance.default_branch
            && instance.config.release_request_label_prefix == config.release_request_label_prefix
            && instance.config.acceptable_clients.repository
                == config.acceptable_clients.repository
            && instance.config.acceptable_clients.id == config.acceptable_clients.id,
        "native release label Server config does not match its captured authority"
    );
    crate::policy::validate_repository(target.release_repository)?;
    let release_destination = config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == target.release_repository
                && repository.id == target.release_repository_id
        })
        .context("native release label destination is not configured")?;
    release_destination
        .policy()
        .require(crate::policy::Capability::Release)
        .context("native release label destination lacks the Release capability")?;
    let captured_release_destination = instance
        .config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == target.release_repository
                && repository.id == target.release_repository_id
        })
        .context("captured native release label destination is not configured")?;
    captured_release_destination
        .policy()
        .require(crate::policy::Capability::Release)
        .context("captured native release label destination lacks the Release capability")?;
    ensure!(
        target.release_repository_id > 0,
        "native release label destination ID is invalid"
    );
    ensure!(
        target.source_run_id > 0,
        "native release label run ID is invalid"
    );
    let label = native_client_release_label_name(
        &config.release_request_label_prefix,
        target.source_run_id,
    )?;
    let description = format!("{}/{}", target.release_repository, target.source_run_id);
    ensure!(
        description.len() <= 100,
        "native release label description exceeds GitHub limit"
    );
    Ok(NativeClientReleaseLabelWrite {
        instance: instance.clone(),
        config_path: target.config_path.to_owned(),
        server_repository: config.instance.repository,
        server_repository_id: config.instance.id,
        release_repository: target.release_repository.to_owned(),
        release_repository_id: target.release_repository_id,
        release_request_label_prefix: config.release_request_label_prefix,
        source_run_id: target.source_run_id,
        name: label,
        description,
    })
}

fn native_client_release_label_name(prefix: &str, source_run_id: u64) -> Result<String> {
    ensure!(source_run_id > 0, "native release label run ID is invalid");
    let name = format!("{prefix}securefix-native-release-{source_run_id}");
    ensure!(
        name.len() <= 50,
        "native release request label exceeds GitHub limit"
    );
    Ok(name)
}

fn validate_native_client_release_label_write(write: &NativeClientReleaseLabelWrite) -> Result<()> {
    let target = NativeClientReleaseLabelTarget {
        instance: &write.instance,
        config_path: &write.config_path,
        release_repository: &write.release_repository,
        release_repository_id: write.release_repository_id,
        source_run_id: write.source_run_id,
    };
    let expected = validate_native_client_release_label_target(&target)?;
    ensure!(
        write.server_repository == expected.server_repository
            && write.server_repository_id == expected.server_repository_id
            && write.release_request_label_prefix == expected.release_request_label_prefix
            && write.name == expected.name
            && write.description == expected.description,
        "saved native release label differs from the captured Server and release destination authority"
    );
    Ok(())
}

fn validate_native_client_release_label_execution(
    write: &NativeClientReleaseLabelWrite,
) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(write.release_repository.as_str()),
        "native release label destination differs from the current workflow repository"
    );
    let run_id = std::env::var("GITHUB_RUN_ID")
        .context("missing GITHUB_RUN_ID for native release label")?
        .parse::<u64>()
        .context("invalid GITHUB_RUN_ID for native release label")?;
    ensure!(
        run_id == write.source_run_id,
        "native release label run differs from the current workflow run"
    );
    Ok(())
}

fn validate_native_client_release_label_body(
    method: &Method,
    path: &str,
    write: &NativeClientReleaseLabelWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path == format!("/repos/{}/labels", write.server_repository)
            && body
                == &serde_json::json!({
                    "name": write.name,
                    "color": "1f6feb",
                    "description": write.description,
                }),
        "native Client release label body does not match its exact source run"
    );
    Ok(())
}

fn validate_native_client_label_body(
    method: &Method,
    path: &str,
    server_repository: &str,
    label: &str,
    description: &str,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path == format!("/repos/{server_repository}/labels")
            && body
                == &serde_json::json!({
                    "name": label,
                    "color": "1f6feb",
                    "description": description,
                }),
        "native Client label body does not match its exact request manifest"
    );
    Ok(())
}

fn validate_native_instance_merge_fence_target(
    config: &crate::instance_config::InstanceConfig,
    authority: &NativeAuthoritySnapshot,
    target: &NativeInstanceWriteTarget<'_>,
) -> Result<()> {
    let fence = match (target.mode, target.merge_fence) {
        (NativeInstanceMode::Merge, Some(fence)) => fence,
        (NativeInstanceMode::Merge, None) => {
            anyhow::bail!("native instance merge requires a validated readiness fence")
        }
        (_, None) => return Ok(()),
        (_, Some(_)) => anyhow::bail!("native merge readiness fence is only valid for merges"),
    };
    let expected_authority_sha256 = native_authority_sha256(authority)?;
    validate_sha256(
        &fence.approval_request_sha256,
        "native approval request digest",
    )?;
    ensure!(
        fence.repository == target.repository
            && fence.repository_id == target.repository_id
            && fence.pull_number == target.pull_number
            && fence.head_sha == target.head_sha
            && fence.authority_sha256 == expected_authority_sha256
            && fence.approval_review_id > 0
            && fence.approval_producer_run_id > 0
            && fence.approval_producer_run_attempt > 0
            && fence.reviewer_id == config.identities.approval_reviewer.id
            && fence.reviewer_login == config.identities.approval_reviewer.login
            && fence.status_app_id == config.apps.status_check_id
            && fence.policy_app_id == config.apps.policy_check_id,
        "native merge readiness fence differs from the request or protected instance"
    );
    let marker = native_instance_approval_body(
        authority,
        target.head_sha,
        &fence.approval_request_sha256,
        fence.approval_producer_run_id,
        fence.approval_producer_run_attempt,
    )?;
    ensure!(
        parse_native_instance_approval_marker(
            marker["body"]
                .as_str()
                .context("native instance approval marker has no body")?
        )
        .is_ok(),
        "native merge readiness fence contains an invalid approval marker"
    );
    Ok(())
}

fn validate_native_instance_write_target(
    config: &crate::instance_config::InstanceConfig,
    target: &NativeInstanceWriteTarget<'_>,
) -> Result<()> {
    validate_instance_config_path(target.config_path)?;
    crate::policy::validate_repository(target.repository)?;
    crate::policy::validate_sha(target.head_sha)?;
    crate::policy::validate_sha(target.base_sha)?;
    crate::policy::validate_sha(target.producer_workflow_sha)?;
    crate::policy::validate_sha(target.client_workflow_epoch)?;
    crate::config::validate_branch(target.head_branch)?;
    crate::config::validate_branch(target.base_ref)?;
    validate_sha256(target.request_sha256, "native request digest")?;
    ensure!(
        target.repository_id > 0
            && target.pull_number > 0
            && target.head_repository_id > 0
            && target.author_id > 0
            && target.actor_id > 0
            && target.producer_run_id > 0
            && target.producer_run_attempt > 0
            && crate::config::is_valid_login(target.author_login)
            && crate::config::is_valid_login(target.actor_login),
        "native instance request target identity is invalid"
    );
    ensure!(
        target
            .producer_workflow_path
            .starts_with(".github/workflows/")
            && target.producer_workflow_path.ends_with(".yml")
            && !target
                .producer_workflow_path
                .contains(['\\', '%', '?', '#'])
            && target
                .producer_workflow_path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "native producer workflow path is invalid"
    );
    if target.mode == NativeInstanceMode::Securefix {
        ensure!(
            target.head_repository_id == target.repository_id,
            "native Securefix requires a same-repository PR head"
        );
    }
    let configured = config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == target.repository && repository.id == target.repository_id
        })
        .context("native request target repository is not configured")?;
    configured
        .policy()
        .require(target.mode.capability())
        .context("native request target lacks its configured capability")?;
    Ok(())
}

#[cfg(test)]
fn native_release_target<'a>(
    write: &'a NativeReleaseWrite,
    instance: &'a NativeServerInstanceAuthority,
    client_package: &'a crate::package::VerifiedNativeClientPackage,
) -> NativeReleaseWriteTarget<'a> {
    NativeReleaseWriteTarget {
        config_path: &write.config_path,
        instance,
        repository: &write.target_repository,
        repository_id: write.target_id,
        release_pr_number: write.release_pr_number,
        release_pr_head_sha: &write.release_pr_head_sha,
        release_pr_merge_sha: &write.release_pr_merge_sha,
        tag: &write.tag,
        release_source_run_id: write.release_source_run_id,
        release_source_run_attempt: write.release_source_run_attempt,
        release_source_run_sha: &write.release_source_run_sha,
        release_source_workflow_sha: &write.release_source_workflow_sha,
        release_manifest: &write.release_manifest,
        release_manifest_bytes: &write.release_manifest_bytes,
        client_package,
        assets: &write.assets,
        native_assets: &write.native_assets,
        release_id: write.release_id,
    }
}

fn validate_native_release_target(
    config: &crate::instance_config::InstanceConfig,
    authority: &NativeAuthoritySnapshot,
    target: &NativeReleaseWriteTarget<'_>,
) -> Result<(NativeClientPackageIdentity, String)> {
    validate_native_authority_snapshot(authority)?;
    validate_instance_config_path(target.config_path)?;
    ensure!(
        target.instance.authority == *authority
            && target.instance.config.instance.repository == config.instance.repository
            && target.instance.config.instance.id == config.instance.id
            && target.instance.config.instance.default_branch == config.instance.default_branch
            && target.instance.authority.config_sha256
                == crate::hex_encode(sha2::Sha256::digest(&target.instance.config_bytes)),
        "native release target instance differs from its protected config"
    );
    let package = native_client_package_identity(config, target.client_package)?;
    let manifest_sha256 = validate_native_release_manifest(
        target.release_manifest,
        target.release_manifest_bytes,
        target.repository,
        target.release_source_run_id,
        target.release_source_run_attempt,
        target.release_source_run_sha,
        target.release_source_workflow_sha,
        target.release_pr_number,
        target.release_pr_merge_sha,
        target.tag,
    )?;
    validate_native_release_common(
        config,
        authority,
        target.config_path,
        &target.instance.config_bytes,
        &target.instance.config.instance.repository,
        target.instance.config.instance.id,
        &target.instance.config.instance.default_branch,
        &target.instance.authority.config_sha256,
        target.repository,
        target.repository_id,
        target.release_pr_number,
        target.release_pr_head_sha,
        target.release_pr_merge_sha,
        target.tag,
        target.release_source_run_id,
        target.release_source_run_attempt,
        target.release_source_run_sha,
        target.release_source_workflow_sha,
        &package,
        target.assets,
        target.native_assets,
    )?;
    Ok((package, manifest_sha256))
}

fn validate_native_release_saved(
    config: &crate::instance_config::InstanceConfig,
    authority: &NativeAuthoritySnapshot,
    write: &NativeReleaseWrite,
) -> Result<()> {
    validate_native_authority_snapshot(authority)?;
    validate_native_client_package_snapshot(config, &write.client_package)?;
    let release_manifest_sha256 = validate_native_release_manifest(
        &write.release_manifest,
        &write.release_manifest_bytes,
        &write.target_repository,
        write.release_source_run_id,
        write.release_source_run_attempt,
        &write.release_source_run_sha,
        &write.release_source_workflow_sha,
        write.release_pr_number,
        &write.release_pr_merge_sha,
        &write.tag,
    )?;
    ensure!(
        release_manifest_sha256 == write.release_manifest_sha256,
        "saved release manifest bytes changed"
    );
    validate_native_release_common(
        config,
        authority,
        &write.config_path,
        &write.config_bytes,
        &write.instance_repository,
        write.instance_id,
        &write.default_branch,
        &authority.config_sha256,
        &write.target_repository,
        write.target_id,
        write.release_pr_number,
        &write.release_pr_head_sha,
        &write.release_pr_merge_sha,
        &write.tag,
        write.release_source_run_id,
        write.release_source_run_attempt,
        &write.release_source_run_sha,
        &write.release_source_workflow_sha,
        &write.client_package,
        &write.assets,
        &write.native_assets,
    )
}

const MAX_NATIVE_RELEASE_MANIFEST_BYTES: usize = 256 * 1024;

// Keep every provenance field explicit here so the byte-level manifest
// comparison remains auditable at the release trust boundary.
#[allow(clippy::too_many_arguments)]
fn validate_native_release_manifest(
    manifest: &crate::release_manifest::ReleaseManifestV2,
    manifest_bytes: &[u8],
    repository: &str,
    source_run_id: u64,
    source_run_attempt: u64,
    source_run_sha: &str,
    source_workflow_sha: &str,
    release_pr_number: u64,
    release_pr_merge_sha: &str,
    tag: &str,
) -> Result<String> {
    ensure!(
        !manifest_bytes.is_empty() && manifest_bytes.len() <= MAX_NATIVE_RELEASE_MANIFEST_BYTES,
        "native release manifest size is invalid"
    );
    let parsed: crate::release_manifest::ReleaseManifestV2 = serde_json::from_slice(manifest_bytes)
        .context("native release manifest bytes are invalid JSON")?;
    parsed.validate()?;
    ensure!(
        &parsed == manifest
            && manifest.repository == repository
            && manifest.source_run_id.0 == source_run_id
            && manifest.run_attempt == source_run_attempt
            && manifest.source_run_sha.as_str() == source_run_sha
            && manifest.source_revision.as_str() == source_workflow_sha
            && manifest.release_pr_number == release_pr_number
            && manifest.release_pr_sha.as_str() == release_pr_merge_sha
            && manifest.tag.as_str() == tag,
        "native release manifest does not match the admitted source, PR, and tag"
    );
    Ok(crate::hex_encode(sha2::Sha256::digest(manifest_bytes)))
}

fn validate_native_client_package_snapshot(
    config: &crate::instance_config::InstanceConfig,
    package: &NativeClientPackageIdentity,
) -> Result<()> {
    crate::policy::validate_sha(&package.implementation_sha)?;
    crate::policy::validate_sha(&package.loader_action_sha)?;
    crate::policy::validate_sha(&package.binary_source_sha)?;
    validate_native_release_workflow_path(&package.publisher_workflow)?;
    crate::config::validate_branch(&package.publisher_branch)?;
    crate::policy::validate_sha(&package.publisher_sha)?;
    validate_native_release_workflow_path(&package.producer_workflow)?;
    crate::config::validate_branch(&package.producer_branch)?;
    let implementation_version = semver::Version::parse(&package.implementation_version)?;
    let binary_version = semver::Version::parse(&package.binary_version)?;
    let scratch = crate::package::validate_native_client_package_destination(
        config,
        &crate::package::TrustedPublisher {
            repository: package.release_repository.clone(),
            repository_id: package.release_repository_id,
        },
        &implementation_version,
        &binary_version,
    )?;
    crate::package::PinnedPackageAction::new(
        package.distributor_repository.clone(),
        package.loader_action_path.clone(),
        package.loader_action_sha.clone(),
    )?;
    ensure!(
        package.distributor_repository == config.acceptable_clients.repository
            && package.distributor_id == config.acceptable_clients.id
            && package.release_tag == format!("v{binary_version}")
            && package.protocol == "securefix-native-request/v1"
            && package.release_id > 0
            && package.asset_id > 0
            && package.asset_size > 0
            && package.publisher_run_id > 0
            && package.publisher_run_attempt == 1
            && package.producer_run_id > 0
            && package.producer_run_attempt == 1
            && (scratch || package.producer_branch == package.publisher_branch),
        "saved Client package admission is invalid for the current instance policy"
    );
    validate_sha256(&package.asset_sha256, "Client package asset digest")
}

fn validate_native_release_source_run(
    config: &crate::instance_config::InstanceConfig,
    write: &NativeReleaseWrite,
    source_run: &Value,
) -> Result<()> {
    ensure!(
        source_run["id"].as_u64() == Some(write.release_source_run_id)
            && source_run["run_attempt"].as_u64() == Some(write.release_source_run_attempt)
            && source_run["status"] == "completed"
            && source_run["conclusion"] == "success"
            && source_run["head_sha"] == write.release_source_run_sha
            && source_run["repository"]["id"].as_u64() == Some(write.target_id)
            && source_run["repository"]["full_name"] == write.target_repository
            && source_run["head_repository"]["id"].as_u64() == Some(write.target_id)
            && source_run["head_repository"]["full_name"] == write.target_repository,
        "Client release source run or attempt changed"
    );
    // GitHub's referenced_workflows is checked as source-run consistency
    // metadata. The release admission verifies the signed source and exact
    // reusable-workflow provenance independently.
    let references: Vec<crate::workflow::ReferencedWorkflow> =
        serde_json::from_value(source_run["referenced_workflows"].clone())
            .context("Client release source run lacks reusable workflow metadata")?;
    let expected_reference = format!(
        "{}/{path}@{sha}",
        config.acceptable_clients.repository,
        path = ".github/workflows/reusable-release-tag.yml",
        sha = write.release_source_workflow_sha,
    );
    ensure!(
        references
            .iter()
            .filter(|reference| {
                reference.path == expected_reference
                    && reference.sha == write.release_source_workflow_sha
            })
            .count()
            == 1
            && references
                .iter()
                .filter(|reference| {
                    reference.path.starts_with(&format!(
                        "{}/{path}@",
                        config.acceptable_clients.repository,
                        path = ".github/workflows/reusable-release-tag.yml"
                    ))
                })
                .count()
                == 1,
        "Client release source run does not match the accepted distributor release-tag reference"
    );
    Ok(())
}

fn validate_native_client_package_remote_identity(
    package: &NativeClientPackageIdentity,
    repository: &Value,
    release: &Value,
    tag_ref: &Value,
    publisher_run: &Value,
    producer_run: &Value,
) -> Result<()> {
    let assets = release["assets"]
        .as_array()
        .context("accepted Client package release assets are missing")?;
    ensure!(
        repository["id"].as_u64() == Some(package.distributor_id)
            && repository["full_name"] == package.distributor_repository
            && repository["default_branch"] == package.publisher_branch,
        "accepted Client distributor identity or default branch changed"
    );
    ensure!(
        release["id"].as_u64() == Some(package.release_id)
            && release["tag_name"] == package.release_tag
            && release["target_commitish"] == package.binary_source_sha
            && release["draft"] == false
            && release["immutable"] == true
            && release["prerelease"] == false
            && assets.len() == 1
            && assets[0]["id"].as_u64() == Some(package.asset_id)
            && assets[0]["name"] == package.asset_name
            && assets[0]["state"] == "uploaded"
            && assets[0]["size"].as_u64() == Some(package.asset_size)
            && assets[0]["digest"] == format!("sha256:{}", package.asset_sha256),
        "accepted Client package release or asset identity changed"
    );
    ensure!(
        tag_ref["ref"] == format!("refs/tags/{}", package.release_tag)
            && tag_ref["object"]["type"] == "commit"
            && tag_ref["object"]["sha"] == package.binary_source_sha,
        "accepted Client package tag no longer resolves to its admitted source"
    );
    ensure!(
        publisher_run["id"].as_u64() == Some(package.publisher_run_id)
            && publisher_run["run_attempt"].as_u64() == Some(package.publisher_run_attempt)
            && publisher_run["repository"]["id"].as_u64() == Some(package.distributor_id)
            && publisher_run["repository"]["full_name"] == package.distributor_repository
            && publisher_run["head_repository"]["id"].as_u64() == Some(package.distributor_id)
            && publisher_run["path"] == package.publisher_workflow
            && publisher_run["event"] == "workflow_dispatch"
            && publisher_run["head_branch"] == package.publisher_branch
            && publisher_run["head_sha"] == package.publisher_sha
            && publisher_run["status"] == "completed"
            && publisher_run["conclusion"] == "success",
        "accepted Client package publisher run or attempt changed"
    );
    ensure!(
        producer_run["id"].as_u64() == Some(package.producer_run_id)
            && producer_run["run_attempt"].as_u64() == Some(package.producer_run_attempt)
            && producer_run["repository"]["id"].as_u64() == Some(package.distributor_id)
            && producer_run["repository"]["full_name"] == package.distributor_repository
            && producer_run["head_repository"]["id"].as_u64() == Some(package.distributor_id)
            && producer_run["path"] == package.producer_workflow
            && producer_run["event"] == "workflow_dispatch"
            && producer_run["head_branch"] == package.producer_branch
            && producer_run["head_sha"] == package.binary_source_sha
            && producer_run["status"] == "completed"
            && producer_run["conclusion"] == "success",
        "accepted Client package producer run or attempt changed"
    );
    Ok(())
}

// These are the independently captured identities the native release writer
// must bind together; grouping them would make the boundary less inspectable.
#[allow(clippy::too_many_arguments)]
fn validate_native_release_common(
    config: &crate::instance_config::InstanceConfig,
    authority: &NativeAuthoritySnapshot,
    config_path: &str,
    config_bytes: &[u8],
    instance_repository: &str,
    instance_id: u64,
    instance_default_branch: &str,
    config_sha256: &str,
    repository: &str,
    repository_id: u64,
    release_pr_number: u64,
    release_pr_head_sha: &str,
    release_pr_merge_sha: &str,
    tag: &str,
    source_run_id: u64,
    source_run_attempt: u64,
    source_run_sha: &str,
    source_workflow_sha: &str,
    client_package: &NativeClientPackageIdentity,
    assets: &[NativeReleaseAsset],
    native_assets: &[NativeReleaseAsset],
) -> Result<()> {
    validate_instance_config_path(config_path)?;
    crate::policy::validate_repository(repository)?;
    crate::policy::validate_sha(release_pr_head_sha)?;
    crate::policy::validate_sha(release_pr_merge_sha)?;
    crate::policy::validate_sha(source_run_sha)?;
    crate::policy::validate_sha(source_workflow_sha)?;
    validate_release_tag(tag)?;
    ensure!(
        instance_repository == config.instance.repository
            && instance_id == config.instance.id
            && instance_default_branch == config.instance.default_branch
            && config_sha256 == crate::hex_encode(sha2::Sha256::digest(config_bytes)),
        "native Server instance differs from its protected config authority"
    );
    ensure!(
        authority.instance_repository == config.instance.repository
            && authority.instance_id == config.instance.id
            && authority.default_branch == config.instance.default_branch
            && authority.config_path == config_path
            && authority.config_sha256 == config_sha256,
        "native Server authority snapshot differs from its protected config"
    );
    ensure!(
        repository_id > 0 && release_pr_number > 0 && source_run_id > 0 && source_run_attempt > 0,
        "native release target identity is invalid"
    );
    ensure!(
        client_package.distributor_repository == config.acceptable_clients.repository
            && client_package.distributor_id == config.acceptable_clients.id
            && source_workflow_sha == client_package.implementation_sha,
        "native Client package does not match the configured distributor admission"
    );
    let configured = config
        .repositories
        .iter()
        .find(|configured| configured.repository == repository && configured.id == repository_id)
        .context("native release destination is not configured")?;
    configured
        .policy()
        .require(crate::policy::Capability::Release)
        .context("native release destination lacks the Release capability")?;

    // These pins belong to different repositories: the Server thin wrapper
    // pins reusable-server-release, while the Client source run references the
    // accepted distributor's reusable-release-tag workflow.
    let _server_release_pin = native_server_release_pin(authority)?;
    ensure!(
        config.acceptable_clients.id > 0,
        "accepted Client distributor identity is invalid"
    );
    validate_native_release_asset_plan(configured, repository, assets, native_assets)?;
    Ok(())
}

fn native_client_package_identity(
    config: &crate::instance_config::InstanceConfig,
    client: &crate::package::VerifiedNativeClientPackage,
) -> Result<NativeClientPackageIdentity> {
    let release = client.package.release();
    let publisher_run_id = client.package_publisher_run_id;
    let publisher_run_attempt = client.package_publisher_run_attempt;
    validate_native_release_workflow_path(&client.package_publisher_workflow)?;
    crate::config::validate_branch(&client.package_publisher_branch)?;
    crate::policy::validate_sha(&client.package_publisher_sha)?;
    validate_native_release_workflow_path(&client.package_producer_workflow)?;
    crate::config::validate_branch(&client.package_producer_branch)?;
    crate::policy::validate_sha(&client.implementation_sha)?;
    crate::policy::validate_sha(&client.loader_action_sha)?;
    crate::policy::validate_sha(&client.binary_source_sha)?;
    let scratch = crate::package::validate_native_client_package_destination(
        config,
        &release.publisher,
        &client.implementation_version,
        &client.binary_version,
    )?;
    ensure!(
        release.implementation_sha == client.binary_source_sha
            && release.source_sha == client.binary_source_sha
            && release.version == client.binary_version
            && release.tag == format!("v{}", client.binary_version)
            && client.protocol == "securefix-native-request/v1"
            && release.release_id > 0
            && release.asset.id > 0
            && release.asset.size > 0
            && publisher_run_id > 0
            && publisher_run_attempt == 1
            && client.package_producer_run_id > 0
            && client.package_producer_run_attempt == 1
            && (scratch || client.package_producer_branch == client.package_publisher_branch),
        "verified Client package does not match its accepted implementation and publisher"
    );
    validate_sha256(&release.asset.sha256, "Client package asset digest")?;
    Ok(NativeClientPackageIdentity {
        distributor_repository: config.acceptable_clients.repository.clone(),
        distributor_id: config.acceptable_clients.id,
        release_repository: release.publisher.repository.clone(),
        release_repository_id: release.publisher.repository_id,
        implementation_sha: client.implementation_sha.clone(),
        implementation_version: client.implementation_version.to_string(),
        loader_action_sha: client.loader_action_sha.clone(),
        loader_action_path: client.loader_action_path.clone(),
        binary_source_sha: client.binary_source_sha.clone(),
        binary_version: client.binary_version.to_string(),
        protocol: client.protocol.clone(),
        release_tag: release.tag.clone(),
        release_id: release.release_id,
        asset_id: release.asset.id,
        asset_name: release.asset.name.clone(),
        asset_size: release.asset.size,
        asset_sha256: release.asset.sha256.clone(),
        publisher_workflow: client.package_publisher_workflow.clone(),
        publisher_branch: client.package_publisher_branch.clone(),
        publisher_sha: client.package_publisher_sha.clone(),
        publisher_run_id,
        publisher_run_attempt,
        producer_workflow: client.package_producer_workflow.clone(),
        producer_branch: client.package_producer_branch.clone(),
        producer_run_id: client.package_producer_run_id,
        producer_run_attempt: client.package_producer_run_attempt,
    })
}

pub fn native_server_release_pin(authority: &NativeAuthoritySnapshot) -> Result<String> {
    let workflow = authority
        .workflows
        .iter()
        .find(|workflow| workflow.role == crate::instance_config::WorkflowRole::Release)
        .context("Server instance does not configure a Release workflow role")?;
    let mut pins = Vec::new();
    for pin in &workflow.pins {
        let Some((target, sha)) = pin.rsplit_once('@') else {
            continue;
        };
        let Some(repository) =
            target.strip_suffix("/.github/workflows/reusable-server-release.yml")
        else {
            continue;
        };
        pins.push((repository, sha));
    }
    ensure!(
        pins.len() == 1,
        "Server Release wrapper must pin exactly one reusable-server-release workflow"
    );
    crate::policy::validate_repository(pins[0].0)?;
    crate::policy::validate_sha(pins[0].1)?;
    Ok(pins[0].1.to_owned())
}

fn validate_native_release_cleanup_event(
    config: &crate::instance_config::InstanceConfig,
    label: &str,
    event: &Value,
) -> Result<()> {
    let prefix = format!(
        "{}securefix-native-release-",
        config.release_request_label_prefix
    );
    let suffix = label
        .strip_prefix(&prefix)
        .context("cleanup label is not a native release request")?;
    let run_id = suffix
        .parse::<u64>()
        .context("cleanup label has an invalid run ID")?;
    let description = event["label"]["description"]
        .as_str()
        .context("cleanup label lacks its source run")?;
    let (repository, run) = description
        .rsplit_once('/')
        .context("cleanup label description is invalid")?;
    ensure!(
        run_id > 0
            && run_id.to_string() == suffix
            && run == suffix
            && event["action"] == "created"
            && event["repository"]["id"].as_u64() == Some(config.instance.id)
            && event["repository"]["full_name"] == config.instance.repository
            && event["sender"]["id"].as_u64() == Some(config.identities.client_bot.id)
            && event["sender"]["type"] == "Bot"
            && event["label"]["name"] == label
            && config.repositories.iter().any(|target| {
                target.repository == repository
                    && target
                        .policy()
                        .require(crate::policy::Capability::Release)
                        .is_ok()
            }),
        "release cleanup event does not match the configured instance, Client App, and exact request"
    );
    Ok(())
}

fn validate_native_release_workflow_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml"))
            && !path.contains(['\\', '%', '?', '#'])
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "native release workflow path is invalid"
    );
    Ok(())
}

fn validate_native_release_asset_plan(
    configured: &crate::instance_config::ConfiguredRepository,
    repository: &str,
    assets: &[NativeReleaseAsset],
    native_assets: &[NativeReleaseAsset],
) -> Result<()> {
    ensure!(assets.len() <= 32, "too many native release assets");
    ensure!(native_assets.len() <= 8, "too many planned native binaries");
    let mut names = std::collections::BTreeSet::new();
    for asset in assets {
        validate_native_release_asset(asset)?;
        ensure!(
            names.insert(asset.name.as_str()),
            "duplicate native release asset"
        );
    }
    let mut native_names = std::collections::BTreeSet::new();
    for asset in native_assets {
        validate_native_release_asset(asset)?;
        ensure!(
            native_names.insert(asset.name.clone())
                && assets.iter().any(|planned| planned == asset),
            "planned native binary is missing from the release asset plan"
        );
    }
    let expected = configured
        .native_binaries
        .iter()
        .map(|binary| {
            let name = repository.rsplit('/').next().unwrap_or_default();
            format!("{name}-{}", binary.target)
        })
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        native_names == expected,
        "native release plan does not contain exactly the configured binary targets"
    );
    Ok(())
}

fn validate_native_release_asset(asset: &NativeReleaseAsset) -> Result<()> {
    ensure!(
        !asset.name.is_empty()
            && asset.name.len() <= 255
            && asset.name != "."
            && asset.name != ".."
            && asset
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "native release asset name is invalid"
    );
    ensure!(
        asset.size > 0 && asset.size <= MAX_NATIVE_RELEASE_ASSET_BYTES,
        "native release asset size is invalid"
    );
    validate_sha256(&asset.sha256, "native release asset digest")?;
    ensure!(
        asset.content_type == "application/octet-stream",
        "native release asset content type is unsupported"
    );
    Ok(())
}

fn validate_release_tag(tag: &str) -> Result<()> {
    let version = tag
        .strip_prefix('v')
        .context("native release tag must start with v")?;
    let version = semver::Version::parse(version)
        .context("native release tag must contain canonical SemVer")?;
    ensure!(
        version.build.is_empty() && format!("v{version}") == tag,
        "native release tag must not contain build metadata"
    );
    Ok(())
}

fn native_release_upload_url(write: &NativeReleaseWrite, path: &str) -> Result<String> {
    let release_id = write
        .release_id
        .context("native release identity was not selected")?;
    let normalized = if path.starts_with("https://") {
        path.to_owned()
    } else {
        format!("https://uploads.github.com{path}")
    };
    let url = reqwest::Url::parse(&normalized).context("native release upload URL is invalid")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("uploads.github.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path()
                == format!(
                    "/repos/{}/releases/{release_id}/assets",
                    write.target_repository
                )
            && url.query_pairs().count() == 1,
        "native release upload URL is outside the selected release"
    );
    let (key, name) = url
        .query_pairs()
        .next()
        .context("native release upload URL lacks an asset name")?;
    ensure!(
        key == "name",
        "native release upload URL has an unexpected query"
    );
    let asset = write
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .context("native release upload asset is not in the verified plan")?;
    let expected = format!(
        "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
        write.target_repository, asset.name
    );
    ensure!(
        normalized == expected,
        "native release upload URL is not canonical"
    );
    Ok(format!(
        "/repos/{}/releases/{release_id}/assets?name={}",
        write.target_repository, asset.name
    ))
}

fn validate_native_release_write_body(
    write: &NativeReleaseWrite,
    method: &Method,
    path: &str,
    body: &Value,
) -> Result<()> {
    if *method == Method::POST && path == format!("/repos/{}/releases", write.target_repository) {
        let version = semver::Version::parse(write.tag.strip_prefix('v').unwrap_or_default())?;
        ensure!(
            write.release_id.is_none()
                && body
                    == &serde_json::json!({
                        "tag_name": write.tag,
                        "name": write.tag,
                        "generate_release_notes": true,
                        "prerelease": !version.pre.is_empty(),
                        "draft": true,
                        "target_commitish": write.target_default_branch,
                    }),
            "native release create request differs from its exact draft plan"
        );
        return Ok(());
    }
    if *method == Method::PATCH
        && write
            .release_id
            .is_some_and(|id| path == format!("/repos/{}/releases/{id}", write.target_repository))
    {
        ensure!(
            body.as_object()
                .is_some_and(|fields| fields.len() == 1 && body["draft"] == false),
            "native release publication may only set draft false"
        );
        return Ok(());
    }
    bail!("native release write is outside the exact draft lifecycle")
}

fn validate_native_release_inventory(
    write: &NativeReleaseWrite,
    release_id: u64,
    release: &Value,
    existing: &[Value],
    require_complete: bool,
) -> Result<()> {
    ensure!(
        existing.len() <= 100
            && release["id"].as_u64() == Some(release_id)
            && release["tag_name"] == write.tag
            && release["draft"] == true,
        "native release asset inventory is not the selected draft"
    );
    let mut names = std::collections::BTreeSet::new();
    for asset in existing {
        let name = asset["name"]
            .as_str()
            .context("native release asset lacks a name")?;
        let planned = write
            .assets
            .iter()
            .find(|planned| planned.name == name)
            .context("native release contains an unexpected asset")?;
        ensure!(
            names.insert(name.to_owned())
                && asset["state"] == "uploaded"
                && asset["size"].as_u64() == Some(planned.size)
                && asset["digest"] == format!("sha256:{}", planned.sha256)
                && asset["content_type"] == planned.content_type,
            "native release asset differs from the verified plan or is duplicated"
        );
    }
    if require_complete {
        ensure!(
            names.len() == write.assets.len(),
            "native release is missing a planned asset"
        );
    }
    Ok(())
}

pub fn validate_native_test_host_context(
    config: &crate::instance_config::InstanceConfig,
    mode: NativeScratchMode,
) -> Result<()> {
    let expected_ref = format!("refs/heads/{}", config.instance.default_branch);
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(config.instance.repository.as_str())
            && std::env::var("GITHUB_REF").as_deref() == Ok(expected_ref.as_str())
            && std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch"),
        "native test authority requires the configured Server repository's protected workflow-dispatch host"
    );
    let role = match mode {
        NativeScratchMode::PolicyCheck => crate::instance_config::WorkflowRole::PolicyCheck,
        NativeScratchMode::Approval => crate::instance_config::WorkflowRole::Approve,
        NativeScratchMode::Merge => crate::instance_config::WorkflowRole::Merge,
        NativeScratchMode::Securefix => crate::instance_config::WorkflowRole::Securefix,
    };
    let actor_id = std::env::var("GITHUB_ACTOR_ID")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    ensure!(
        actor_id == Some(config.identities.owner.id),
        "native test authority requires a dispatch by the configured owner"
    );
    let workflow_path = config
        .workflow_roles
        .get(&role)
        .context("native Server test host role is not configured")?;
    let expected_workflow_ref = format!(
        "{}/{workflow_path}@{expected_ref}",
        config.instance.repository
    );
    ensure!(
        std::env::var("GITHUB_WORKFLOW_REF").as_deref() == Ok(expected_workflow_ref.as_str()),
        "native test authority requires the configured workflow on the protected Server branch"
    );
    Ok(())
}

pub fn native_current_control_identity(
    api: &GitHub,
    repository: &str,
    default_branch: &str,
) -> Result<String> {
    crate::policy::validate_repository(repository)?;
    crate::config::validate_branch(default_branch)?;
    let bytes = api.content_uncached(repository, "control/active.json", default_branch)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "native control descriptor exceeds size limit"
    );
    let control: crate::control::ControlRevision =
        serde_json::from_slice(&bytes).context("parse native current control descriptor")?;
    control.identity()
}

pub fn native_target_policy_control_identity(
    api: &GitHub,
    repository: &str,
    repository_id: u64,
    default_branch: &str,
) -> Result<String> {
    crate::policy::validate_repository(repository)?;
    crate::config::validate_branch(default_branch)?;
    ensure!(
        repository_id > 0,
        "native policy target repository ID is missing"
    );
    require_single_repository_installation(api, repository_id, repository)?;
    let current: Value = api.get_uncached(&format!("/repos/{repository}"))?;
    ensure!(
        current["id"].as_u64() == Some(repository_id)
            && current["full_name"].as_str() == Some(repository)
            && current["default_branch"].as_str() == Some(default_branch),
        "native policy target repository identity or default branch changed"
    );
    native_current_control_identity(api, repository, default_branch)
}

/// Validate the exact required checks and configured review for an ordinary
/// instance merge, then capture the identity that the merge writer must
/// revalidate immediately before its Merge API call.
pub fn capture_native_instance_merge_fence(
    api: &GitHub,
    config: &crate::instance_config::InstanceConfig,
    readiness: &NativeInstanceMergeReadiness<'_>,
) -> Result<NativeInstanceMergeFence> {
    let repository = readiness.repository;
    let repository_id = readiness.repository_id;
    let pull_number = readiness.pull_number;
    let head_sha = readiness.head_sha;
    let authority = readiness.authority;
    let approval_request_sha256 = readiness.approval_request_sha256;
    let approval_producer_run_id = readiness.approval_producer_run_id;
    let approval_producer_run_attempt = readiness.approval_producer_run_attempt;
    crate::policy::validate_repository(repository)?;
    crate::policy::validate_sha(head_sha)?;
    validate_sha256(approval_request_sha256, "native approval request digest")?;
    validate_native_authority_snapshot(authority)?;
    ensure!(
        repository_id > 0
            && pull_number > 0
            && approval_producer_run_id > 0
            && approval_producer_run_attempt > 0
            && authority.instance_repository == config.instance.repository
            && authority.instance_id == config.instance.id
            && authority.default_branch == config.instance.default_branch,
        "native merge readiness identity is invalid"
    );
    config
        .repositories
        .iter()
        .find(|target| target.repository == repository && target.id == repository_id)
        .context("native merge target is not configured")?
        .policy()
        .require(crate::policy::Capability::Merge)
        .context("native merge target lacks its configured capability")?;

    let approval_body = native_instance_approval_body(
        authority,
        head_sha,
        approval_request_sha256,
        approval_producer_run_id,
        approval_producer_run_attempt,
    )?;
    let expected_marker = approval_body["body"]
        .as_str()
        .context("native approval marker has no body")?;
    let reader = GitHub::new(&api.base, api.token.clone())?;
    let checks = native_check_runs_for_head(&reader, repository, head_sha)?;
    ensure!(
        native_instance_merge_checks_ready(
            &checks,
            config.apps.status_check_id,
            config.apps.policy_check_id,
            head_sha,
            authority,
        )?,
        "native merge required checks are not successful for the accepted head and authority"
    );

    let reviewer = &config.identities.approval_reviewer;
    let reviews =
        reader.paginate_uncached(&format!("/repos/{repository}/pulls/{pull_number}/reviews"))?;
    let approval_review_id = native_instance_approval_review_id(
        &reviews,
        reviewer.id,
        &reviewer.login,
        head_sha,
        expected_marker,
    )?;
    let decision = reader.graphql(
        "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}",
        serde_json::json!({
            "owner": repository.split('/').next().unwrap_or_default(),
            "name": repository.split('/').nth(1).unwrap_or_default(),
            "number": pull_number
        }),
    )?;
    ensure!(
        decision["repository"]["pullRequest"]["reviewDecision"] == "APPROVED",
        "native merge requires an approved current review decision"
    );

    Ok(NativeInstanceMergeFence {
        repository: repository.to_owned(),
        repository_id,
        pull_number,
        head_sha: head_sha.to_owned(),
        authority_sha256: native_authority_sha256(authority)?,
        approval_review_id,
        approval_request_sha256: approval_request_sha256.to_owned(),
        approval_producer_run_id,
        approval_producer_run_attempt,
        reviewer_id: reviewer.id,
        reviewer_login: reviewer.login.clone(),
        status_app_id: config.apps.status_check_id,
        policy_app_id: config.apps.policy_check_id,
    })
}

fn send_after_native_instance_merge_fence<T>(
    accepted: &NativeInstanceMergeFence,
    current: Result<NativeInstanceMergeFence>,
    send: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let current = current?;
    ensure!(
        current == *accepted,
        "native merge required checks or accepted approval changed before write"
    );
    send()
}

pub fn native_check_runs_for_head(
    api: &GitHub,
    repository: &str,
    head_sha: &str,
) -> Result<Vec<Value>> {
    crate::policy::validate_repository(repository)?;
    crate::policy::validate_sha(head_sha)?;
    let mut checks = Vec::new();
    let mut expected_total = None;
    let mut ids = std::collections::BTreeSet::new();
    for page in 1..=100 {
        let response: Value = api.get_uncached(&format!(
            "/repos/{repository}/commits/{head_sha}/check-runs?per_page=100&page={page}&filter=all"
        ))?;
        let total = response["total_count"]
            .as_u64()
            .context("native check count is missing")?;
        ensure!(total <= 10_000, "native check listing exceeds its bound");
        ensure!(
            expected_total.is_none_or(|expected| total == expected),
            "native check listing changed during pagination"
        );
        expected_total = Some(total);
        let batch = response["check_runs"]
            .as_array()
            .context("native check listing is malformed")?;
        ensure!(
            batch.len() as u64 == (total - checks.len() as u64).min(100),
            "native check listing is incomplete"
        );
        for check in batch {
            let id = check["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .context("native check ID is invalid")?;
            ensure!(
                ids.insert(id),
                "native check listing contains duplicate IDs"
            );
            checks.push(check.clone());
        }
        if checks.len() as u64 == total {
            return Ok(checks);
        }
    }
    anyhow::bail!("native check pagination exceeded its bound")
}

fn native_instance_merge_checks_ready(
    checks: &[Value],
    status_app_id: u64,
    policy_app_id: u64,
    expected_head: &str,
    authority: &NativeAuthoritySnapshot,
) -> Result<bool> {
    let ci_ok = native_latest_check(checks, "status-check", status_app_id).is_some_and(|check| {
        check["status"] == "completed"
            && (check["conclusion"] == "success" || check["conclusion"] == "skipped")
    });
    let authority_sha256 = native_authority_sha256(authority)?;
    let mut latest: Option<(u64, &Value)> = None;
    let mut requests = std::collections::BTreeSet::new();
    for check in checks.iter().filter(|check| {
        check["name"] == NATIVE_POLICY_CHECK_NAME
            && check["app"]["id"].as_u64() == Some(policy_app_id)
    }) {
        ensure!(
            check["head_sha"].as_str() == Some(expected_head),
            "native policy check has a different head"
        );
        let external_id = check["external_id"]
            .as_str()
            .context("native instance policy check has no external identity")?;
        if external_id.len() == 64 && validate_sha256(external_id, "legacy check request").is_ok() {
            continue;
        }
        let identity = parse_native_instance_policy_check_external_id(external_id)?;
        ensure!(
            identity.head_sha == expected_head,
            "native policy check identity has a different head"
        );
        if identity.authority_sha256 != authority_sha256 {
            continue;
        }
        ensure!(
            requests.insert(identity.request_sha256),
            "duplicate native policy request proof"
        );
        let id = check["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("native policy check ID is invalid")?;
        // Check-run IDs order creation, independently of API list order or completion time.
        if latest.is_none_or(|(current, _)| id > current) {
            latest = Some((id, check));
        }
    }
    Ok(ci_ok
        && latest.is_some_and(|(_, check)| {
            check["status"] == "completed" && check["conclusion"] == "success"
        }))
}

fn native_latest_check<'a>(checks: &'a [Value], name: &str, app_id: u64) -> Option<&'a Value> {
    checks
        .iter()
        .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
        .max_by_key(|check| check["id"].as_u64().unwrap_or_default())
}

fn native_instance_approval_review_id(
    reviews: &[Value],
    reviewer_id: u64,
    reviewer_login: &str,
    expected_head: &str,
    expected_marker: &str,
) -> Result<u64> {
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
    ensure!(
        decisions
            .iter()
            .all(|review| native_instance_review_order(review).is_some()),
        "configured reviewer has a malformed review timestamp or ID"
    );
    let latest = decisions
        .into_iter()
        .max_by_key(|review| native_instance_review_order(review));
    let review = latest.context("configured reviewer has no approval marker review")?;
    ensure!(
        review["state"] == "APPROVED"
            && review["commit_id"].as_str() == Some(expected_head)
            && review["body"].as_str() == Some(expected_marker),
        "latest configured reviewer decision is not the accepted approval on the exact head"
    );
    review["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("accepted approval review ID is invalid")
}

fn native_instance_review_order(
    review: &Value,
) -> Option<(chrono::DateTime<chrono::FixedOffset>, u64)> {
    let submitted_at =
        chrono::DateTime::parse_from_rfc3339(review["submitted_at"].as_str()?).ok()?;
    let id = review["id"].as_u64().filter(|id| *id > 0)?;
    Some((submitted_at, id))
}

pub fn validate_native_server_execution_workflow(
    snapshot: &NativeAuthoritySnapshot,
    mode: NativeScratchMode,
    workflow_ref: &str,
    workflow_sha: &str,
    workflow_bytes: &[u8],
) -> Result<()> {
    let role = match mode {
        NativeScratchMode::PolicyCheck => crate::instance_config::WorkflowRole::PolicyCheck,
        NativeScratchMode::Approval => crate::instance_config::WorkflowRole::Approve,
        NativeScratchMode::Merge => crate::instance_config::WorkflowRole::Merge,
        NativeScratchMode::Securefix => crate::instance_config::WorkflowRole::Securefix,
    };
    validate_native_server_execution_workflow_role(
        snapshot,
        role,
        workflow_ref,
        workflow_sha,
        workflow_bytes,
    )
}

pub fn validate_native_server_execution_workflow_role(
    snapshot: &NativeAuthoritySnapshot,
    role: crate::instance_config::WorkflowRole,
    workflow_ref: &str,
    workflow_sha: &str,
    workflow_bytes: &[u8],
) -> Result<()> {
    validate_native_authority_snapshot(snapshot)?;
    crate::policy::validate_sha(workflow_sha)?;
    let workflow = snapshot
        .workflows
        .iter()
        .find(|workflow| workflow.role == role)
        .context("Server instance does not configure the executing workflow role")?;
    let expected = format!(
        "{}/{}@refs/heads/{}",
        snapshot.instance_repository, workflow.path, snapshot.default_branch
    );
    ensure!(
        workflow_ref == expected,
        "native Server execution is not the configured protected-default-branch workflow"
    );
    ensure!(
        workflow_bytes.len() <= 256 * 1024
            && crate::hex_encode(sha2::Sha256::digest(workflow_bytes)) == workflow.sha256
            && workflow_uses_pins(workflow_bytes)? == workflow.pins,
        "native Server workflow revision differs from the captured role wrapper"
    );
    Ok(())
}

fn validate_sha256(value: &str, description: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{description} is not canonical SHA-256"
    );
    Ok(())
}

fn validate_package_scratch_tag(tag: &str) -> Result<()> {
    let version = tag
        .strip_prefix('v')
        .context("scratch package tag must start with v")?;
    let version = semver::Version::parse(version)
        .context("scratch package tag must contain canonical SemVer")?;
    ensure!(
        !version.pre.is_empty() && version.build.is_empty() && format!("v{version}") == tag,
        "scratch package tag must be a canonical prerelease"
    );
    Ok(())
}

fn parse_positive_env(name: &str) -> Result<u64> {
    let value = std::env::var(name).with_context(|| format!("missing {name}"))?;
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("invalid {name}"))?;
    ensure!(parsed > 0 && parsed.to_string() == value, "invalid {name}");
    Ok(parsed)
}

fn validate_package_release_publisher_environment(
    target: &PackageReleaseWriteTarget<'_>,
) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(target.source_repository)
            && std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch")
            && parse_positive_env("GITHUB_RUN_ID")? == target.publisher_run_id
            && parse_positive_env("GITHUB_RUN_ATTEMPT")? == target.publisher_run_attempt
            && target.publisher_run_attempt == 1
            && parse_positive_env("GITHUB_ACTOR_ID")? == target.owner_id,
        "package publisher must be the exact owner-dispatched first attempt"
    );
    let workflow_sha =
        std::env::var("GITHUB_WORKFLOW_SHA").context("missing package publisher workflow SHA")?;
    let github_sha = std::env::var("GITHUB_SHA").context("missing package publisher SHA")?;
    crate::policy::validate_sha(&workflow_sha)?;
    ensure!(
        workflow_sha == target.publisher_sha && github_sha == target.publisher_sha,
        "package publisher host SHA differs from the selected workflow revision"
    );
    ensure!(
        std::env::var("GITHUB_REF").as_deref()
            == Ok(format!("refs/heads/{}", target.publisher_branch).as_str()),
        "package publisher must run from the protected publisher branch"
    );
    let expected_workflow_ref = format!(
        "{}/{publisher_workflow}@refs/heads/{publisher_branch}",
        target.source_repository,
        publisher_workflow = target.publisher_workflow,
        publisher_branch = target.publisher_branch,
    );
    ensure!(
        std::env::var("GITHUB_WORKFLOW_REF").as_deref() == Ok(expected_workflow_ref.as_str()),
        "package publisher workflow ref differs from the source manifest"
    );
    Ok(())
}

fn package_release_write_target<'a>(
    write: &'a PackageReleaseWrite,
) -> PackageReleaseWriteTarget<'a> {
    PackageReleaseWriteTarget {
        channel: write.channel,
        source_repository: &write.source_repository,
        source_repository_id: write.source_repository_id,
        source_owner_id: write.source_owner_id,
        source_branch: &write.source_branch,
        source_default_branch: &write.source_default_branch,
        source_sha: &write.source_sha,
        source_manifest_sha256: &write.source_manifest_sha256,
        destination_repository: &write.destination_repository,
        destination_repository_id: write.destination_repository_id,
        destination_default_branch: &write.destination_default_branch,
        destination_branch_sha: &write.destination_branch_sha,
        destination_target_sha: &write.destination_target_sha,
        version: &write.version,
        tag: &write.tag,
        asset_name: &write.asset_name,
        asset_size: write.asset_size,
        asset_sha256: &write.asset_sha256,
        max_asset_bytes: write.max_asset_bytes,
        producer_workflow: &write.producer_workflow,
        producer_run_id: write.producer_run_id,
        producer_run_attempt: write.producer_run_attempt,
        producer_artifact_id: write.producer_artifact_id,
        producer_artifact_size: write.producer_artifact_size,
        producer_artifact_sha256: &write.producer_artifact_sha256,
        publisher_workflow: &write.publisher_workflow,
        publisher_sha: &write.publisher_sha,
        publisher_branch: &write.publisher_branch,
        publisher_run_id: write.publisher_run_id,
        publisher_run_attempt: write.publisher_run_attempt,
        owner_id: write.owner_id,
        release_id: write.release_id,
    }
}

fn current_branch_sha(api: &GitHub, repository: &str, branch: &str) -> Result<String> {
    let commit: Value = api.get_uncached(&format!(
        "/repos/{repository}/commits/{}",
        encode_path_segment(branch)
    ))?;
    let sha = commit["sha"]
        .as_str()
        .context("package branch commit SHA is missing")?;
    crate::policy::validate_sha(sha)?;
    Ok(sha.to_owned())
}

fn optional_current_tag_commit(
    api: &GitHub,
    repository: &str,
    tag: &str,
) -> Result<Option<String>> {
    let refs: Vec<Value> = api.get_uncached(&format!(
        "/repos/{repository}/git/matching-refs/tags/{}",
        encode_path_segment(tag)
    ))?;
    let exact: Vec<_> = refs
        .iter()
        .filter(|reference| reference["ref"] == format!("refs/tags/{tag}"))
        .collect();
    ensure!(exact.len() <= 1, "package release tag ref is duplicated");
    exact
        .first()
        .map(|reference| package_release_tag_ref_commit(api, repository, reference))
        .transpose()
}

fn current_tag_commit(api: &GitHub, repository: &str, tag: &str) -> Result<String> {
    optional_current_tag_commit(api, repository, tag)?.context("package release tag ref is missing")
}

fn package_release_tag_ref_commit(
    api: &GitHub,
    repository: &str,
    reference: &Value,
) -> Result<String> {
    let object_sha = reference["object"]["sha"]
        .as_str()
        .context("package release tag object SHA is missing")?;
    crate::policy::validate_sha(object_sha)?;
    match reference["object"]["type"].as_str() {
        Some("commit") => Ok(object_sha.to_owned()),
        Some("tag") => {
            let object: Value =
                api.get_uncached(&format!("/repos/{repository}/git/tags/{object_sha}"))?;
            ensure!(
                object["sha"] == object_sha && object["object"]["type"] == "commit",
                "package release annotated tag does not directly target a commit"
            );
            let commit_sha = object["object"]["sha"]
                .as_str()
                .context("package release annotated tag commit SHA is missing")?;
            crate::policy::validate_sha(commit_sha)?;
            Ok(commit_sha.to_owned())
        }
        _ => anyhow::bail!("package release tag has an unsupported object type"),
    }
}

fn validate_package_release_tag_binding(
    expected_commit: &str,
    release: &Value,
    tag_commit: Option<&str>,
) -> Result<()> {
    if release["draft"] == true {
        if let Some(tag_commit) = tag_commit {
            ensure!(
                tag_commit == expected_commit,
                "package release tag does not target the exact destination commit"
            );
        }
    } else {
        ensure!(
            tag_commit == Some(expected_commit),
            "published package release tag does not target the exact destination commit"
        );
    }
    Ok(())
}

fn validate_package_release_tag_for_publish(
    expected_commit: &str,
    tag_commit: Option<&str>,
) -> Result<()> {
    ensure!(
        tag_commit == Some(expected_commit),
        "package release tag is missing or does not target the exact destination commit"
    );
    Ok(())
}

fn validate_package_release_producer_run(write: &PackageReleaseWrite, run: &Value) -> Result<()> {
    let expected_path = format!(
        "{}@refs/heads/{}",
        write.producer_workflow, write.source_branch
    );
    ensure!(
        run["id"].as_u64() == Some(write.producer_run_id)
            && run["run_attempt"].as_u64() == Some(write.producer_run_attempt)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["event"] == "workflow_dispatch"
            && run["head_sha"] == write.source_sha
            && run["head_branch"] == write.source_branch
            && run["repository"]["id"].as_u64() == Some(write.source_repository_id)
            && run["repository"]["full_name"] == write.source_repository
            && run["head_repository"]["id"].as_u64() == Some(write.source_repository_id)
            && run["head_repository"]["full_name"] == write.source_repository
            && matches!(run["path"].as_str(), Some(path) if path == write.producer_workflow || path == expected_path)
            && run["actor"]["id"].as_u64() == Some(write.owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(write.owner_id)
            && run["triggering_actor"]["type"] == "User",
        "package producer run is not the successful exact owner-dispatched source run"
    );
    Ok(())
}

fn validate_package_release_artifact(write: &PackageReleaseWrite, response: &Value) -> Result<()> {
    const ARTIFACT_NAME: &str = "native-package-attested";
    let artifacts = response["artifacts"]
        .as_array()
        .context("package producer artifact list is missing")?;
    ensure!(
        response["total_count"].as_u64() == Some(artifacts.len() as u64) && artifacts.len() < 100,
        "package producer artifact list is incomplete"
    );
    let matching: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact["name"] == ARTIFACT_NAME)
        .collect();
    ensure!(
        matching.len() == 1,
        "package producer artifact is missing or duplicated"
    );
    let artifact = matching[0];
    let digest = artifact["digest"]
        .as_str()
        .context("package producer artifact digest is missing")?;
    let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
    ensure!(
        artifact["id"].as_u64() == Some(write.producer_artifact_id)
            && artifact["expired"] == false
            && artifact["size_in_bytes"].as_u64() == Some(write.producer_artifact_size)
            && artifact["workflow_run"]["id"].as_u64() == Some(write.producer_run_id)
            && artifact["workflow_run"]["head_sha"] == write.source_sha
            && artifact["workflow_run"]["head_branch"] == write.source_branch
            && artifact["workflow_run"]["repository_id"].as_u64()
                == Some(write.source_repository_id)
            && artifact["workflow_run"]["head_repository_id"].as_u64()
                == Some(write.source_repository_id)
            && digest == write.producer_artifact_sha256,
        "package producer artifact differs from its exact source run, digest, or bounds"
    );
    Ok(())
}

fn validate_package_release_publisher_run(write: &PackageReleaseWrite, run: &Value) -> Result<()> {
    validate_package_release_publisher_run_for_target(&package_release_write_target(write), run)
}

fn validate_package_release_publisher_run_for_target(
    target: &PackageReleaseWriteTarget<'_>,
    run: &Value,
) -> Result<()> {
    let expected_path = format!(
        "{}@refs/heads/{}",
        target.publisher_workflow, target.publisher_branch
    );
    ensure!(
        run["id"].as_u64() == Some(target.publisher_run_id)
            && run["run_attempt"].as_u64() == Some(target.publisher_run_attempt)
            && run["status"] == "in_progress"
            && run["event"] == "workflow_dispatch"
            && run["head_sha"] == target.publisher_sha
            && run["head_branch"] == target.publisher_branch
            && run["repository"]["id"].as_u64() == Some(target.source_repository_id)
            && run["repository"]["full_name"] == target.source_repository
            && run["head_repository"]["id"].as_u64() == Some(target.source_repository_id)
            && run["head_repository"]["full_name"] == target.source_repository
            && matches!(run["path"].as_str(), Some(path) if path == target.publisher_workflow || path == expected_path)
            && run["actor"]["id"].as_u64() == Some(target.owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(target.owner_id)
            && run["triggering_actor"]["type"] == "User",
        "package publisher run is not the current owner-dispatched protected-source execution"
    );
    Ok(())
}

fn validate_package_release_write_target(target: &PackageReleaseWriteTarget<'_>) -> Result<()> {
    crate::policy::validate_repository(target.source_repository)?;
    crate::policy::validate_repository(target.destination_repository)?;
    crate::config::validate_branch(target.source_branch)?;
    crate::config::validate_branch(target.source_default_branch)?;
    crate::config::validate_branch(target.destination_default_branch)?;
    crate::config::validate_branch(target.publisher_branch)?;
    crate::policy::validate_sha(target.source_sha)?;
    crate::policy::validate_sha(target.destination_branch_sha)?;
    crate::policy::validate_sha(target.publisher_sha)?;
    crate::policy::validate_sha(target.destination_target_sha)?;
    validate_sha256(
        target.source_manifest_sha256,
        "package source manifest digest",
    )?;
    validate_sha256(target.asset_sha256, "package asset digest")?;
    validate_sha256(target.producer_artifact_sha256, "producer artifact digest")?;
    validate_package_asset_name(target.asset_name)?;
    validate_native_release_workflow_path(target.producer_workflow)?;
    validate_native_release_workflow_path(target.publisher_workflow)?;
    ensure!(
        target.producer_workflow == crate::package::NATIVE_PACKAGE_PRODUCER_WORKFLOW
            && target.publisher_workflow == crate::package::NATIVE_PACKAGE_PUBLISHER_WORKFLOW,
        "package release does not use the fixed package workflows"
    );
    let version = semver::Version::parse(target.version).context("package version is invalid")?;
    ensure!(
        version.build.is_empty() && version.to_string() == target.version,
        "package version is not canonical SemVer"
    );
    ensure!(
        target.tag == format!("v{version}")
            && target.asset_name == "securefix-linux-x86_64"
            && target.source_repository_id > 0
            && target.source_owner_id > 0
            && target.destination_repository_id > 0
            && target.owner_id > 0
            && target.producer_run_id > 0
            && target.producer_run_attempt == 1
            && target.producer_artifact_id > 0
            && target.producer_artifact_size > 0
            && target.producer_artifact_size <= 160 * 1024 * 1024
            && target.publisher_run_id > 0
            && target.publisher_run_attempt == 1,
        "package release identity is incomplete or inconsistent"
    );
    ensure!(
        target.asset_size > 0
            && target.max_asset_bytes > 0
            && target.max_asset_bytes <= MAX_PACKAGE_SCRATCH_ASSET_BYTES
            && target.asset_size <= target.max_asset_bytes,
        "package asset is outside its source manifest size bound"
    );
    ensure!(
        match target.channel {
            PackageReleaseChannel::Stable => {
                version.pre.is_empty()
                    && target.source_repository == target.destination_repository
                    && target.source_repository_id == target.destination_repository_id
                    && target.source_branch == target.source_default_branch
                    && target.destination_default_branch == target.source_default_branch
                    && target.destination_branch_sha == target.publisher_sha
                    && target.destination_target_sha == target.source_sha
                    && target.publisher_branch == target.source_default_branch
            }
            PackageReleaseChannel::Scratch => {
                !version.pre.is_empty()
                    && target.source_repository != target.destination_repository
                    && target.source_repository_id != target.destination_repository_id
                    && !target.source_branch.is_empty()
                    && target.destination_branch_sha == target.destination_target_sha
                    && target.publisher_branch == target.source_default_branch
            }
        },
        "package release channel does not match its source and destination"
    );
    if let Some(release_id) = target.release_id {
        ensure!(release_id > 0, "package release ID is invalid");
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageReleaseRecord {
    schema_version: u8,
    source_sha: String,
    source_manifest_sha256: String,
    producer_workflow: String,
    producer_run_id: u64,
    producer_run_attempt: u64,
    publisher_workflow: String,
    publisher_sha: String,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
    tag: String,
    asset_name: String,
    asset_size: u64,
    asset_sha256: String,
}

fn package_release_record(write: &PackageReleaseWrite) -> PackageReleaseRecord {
    PackageReleaseRecord {
        schema_version: 1,
        source_sha: write.source_sha.clone(),
        source_manifest_sha256: write.source_manifest_sha256.clone(),
        producer_workflow: write.producer_workflow.clone(),
        producer_run_id: write.producer_run_id,
        producer_run_attempt: write.producer_run_attempt,
        publisher_workflow: write.publisher_workflow.clone(),
        publisher_sha: write.publisher_sha.clone(),
        publisher_run_id: write.publisher_run_id,
        publisher_run_attempt: write.publisher_run_attempt,
        tag: write.tag.clone(),
        asset_name: write.asset_name.clone(),
        asset_size: write.asset_size,
        asset_sha256: write.asset_sha256.clone(),
    }
}

fn package_release_record_body(write: &PackageReleaseWrite) -> Result<String> {
    Ok(serde_json::to_string(&package_release_record(write))?)
}

fn validate_package_release_record(write: &PackageReleaseWrite, release: &Value) -> Result<()> {
    let body = release["body"]
        .as_str()
        .context("package release is missing its source/publication record")?;
    ensure!(
        body == package_release_record_body(write)?,
        "package release record differs from the verified source and publisher run"
    );
    Ok(())
}

fn parse_package_release_record(release: &Value) -> Result<PackageReleaseRecord> {
    let body = release["body"]
        .as_str()
        .context("package release is missing its source/publication record")?;
    let record: PackageReleaseRecord =
        serde_json::from_str(body).context("package release record is invalid JSON")?;
    ensure!(
        serde_json::to_string(&record)? == body,
        "package release record is not canonical JSON"
    );
    Ok(record)
}

fn validate_package_release_record_for_target(
    target: &PackageReleaseWriteTarget<'_>,
    record: &PackageReleaseRecord,
) -> Result<()> {
    ensure!(
        record.schema_version == 1
            && record.source_sha == target.source_sha
            && record.source_manifest_sha256 == target.source_manifest_sha256
            && record.producer_workflow == target.producer_workflow
            && record.producer_run_id == target.producer_run_id
            && record.producer_run_attempt == target.producer_run_attempt
            && record.publisher_workflow == target.publisher_workflow
            && record.publisher_sha == target.publisher_sha
            && record.publisher_run_id > 0
            && record.publisher_run_attempt == 1
            && record.tag == target.tag
            && record.asset_name == target.asset_name
            && record.asset_size == target.asset_size
            && record.asset_sha256 == target.asset_sha256,
        "existing package release record differs from the exact source, producer, publisher authority, or asset"
    );
    Ok(())
}

fn validate_package_release_prior_publisher_run(
    target: &PackageReleaseWriteTarget<'_>,
    record: &PackageReleaseRecord,
    run: &Value,
    draft: bool,
) -> Result<()> {
    let expected_path = format!(
        "{}@refs/heads/{}",
        target.publisher_workflow, target.publisher_branch
    );
    ensure!(
        run["id"].as_u64() == Some(record.publisher_run_id)
            && run["run_attempt"].as_u64() == Some(record.publisher_run_attempt)
            && run["status"] == "completed"
            && run["event"] == "workflow_dispatch"
            && run["head_sha"] == target.publisher_sha
            && run["head_branch"] == target.publisher_branch
            && run["repository"]["id"].as_u64() == Some(target.source_repository_id)
            && run["repository"]["full_name"] == target.source_repository
            && run["head_repository"]["id"].as_u64() == Some(target.source_repository_id)
            && run["head_repository"]["full_name"] == target.source_repository
            && matches!(run["path"].as_str(), Some(path) if path == target.publisher_workflow || path == expected_path)
            && run["actor"]["id"].as_u64() == Some(target.owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(target.owner_id)
            && run["triggering_actor"]["type"] == "User",
        "recorded package publisher run is not a terminal owner-dispatched protected-source execution"
    );
    ensure!(
        if draft {
            run["conclusion"] != "success"
        } else {
            run["conclusion"] == "success"
        },
        "package release state does not match the recorded publisher run conclusion"
    );
    Ok(())
}

fn validate_package_release_recoverable_draft(
    target: &PackageReleaseWriteTarget<'_>,
    release: &Value,
    release_id: u64,
) -> Result<()> {
    let prerelease = target.channel == PackageReleaseChannel::Scratch;
    let commitish = if prerelease {
        target.destination_default_branch
    } else {
        target.source_sha
    };
    ensure!(
        release["id"].as_u64() == Some(release_id)
            && release["tag_name"] == target.tag
            && release["name"] == target.tag
            && release["target_commitish"] == commitish
            && release["draft"] == true
            && release["prerelease"] == prerelease
            && release["immutable"] != true,
        "existing package release is not the exact recoverable draft"
    );
    let record = parse_package_release_record(release)?;
    validate_package_release_record_for_target(target, &record)
}

fn validate_package_release_recoverable_published(
    target: &PackageReleaseWriteTarget<'_>,
    release: &Value,
    release_id: u64,
) -> Result<()> {
    let prerelease = target.channel == PackageReleaseChannel::Scratch;
    let commitish = if prerelease {
        target.destination_default_branch
    } else {
        target.source_sha
    };
    ensure!(
        release["id"].as_u64() == Some(release_id)
            && release["tag_name"] == target.tag
            && release["name"] == target.tag
            && release["target_commitish"] == commitish
            && release["draft"] == false
            && release["prerelease"] == prerelease
            && release["immutable"] == true,
        "existing package release is not the exact immutable publication"
    );
    let record = parse_package_release_record(release)?;
    validate_package_release_record_for_target(target, &record)
}

fn validate_package_release_recovery_asset(
    target: &PackageReleaseWriteTarget<'_>,
    api: &GitHub,
    release: &Value,
    required: bool,
) -> Result<bool> {
    let Some(asset_id) = package_release_recovery_asset_id(target, release, required)? else {
        return Ok(false);
    };
    let expected_size = usize::try_from(target.asset_size)
        .context("existing package asset size exceeds this platform")?;
    let bytes = api.download(
        &format!(
            "/repos/{}/releases/assets/{asset_id}",
            target.destination_repository
        ),
        expected_size,
    )?;
    ensure!(
        bytes.len() == expected_size
            && crate::hex_encode(sha2::Sha256::digest(&bytes)) == target.asset_sha256,
        "existing package release asset bytes differ from the exact verified artifact"
    );
    Ok(true)
}

fn package_release_recovery_asset_id(
    target: &PackageReleaseWriteTarget<'_>,
    release: &Value,
    required: bool,
) -> Result<Option<u64>> {
    let assets = release["assets"]
        .as_array()
        .context("existing package release asset list is missing")?;
    ensure!(
        assets.len() <= 1,
        "existing package release has unexpected assets"
    );
    if assets.is_empty() {
        ensure!(
            !required,
            "existing published package release is missing its asset"
        );
        return Ok(None);
    }
    let asset = &assets[0];
    let asset_id = asset["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("existing package release asset ID is invalid")?;
    ensure!(
        asset["name"] == target.asset_name
            && asset["size"].as_u64() == Some(target.asset_size)
            && asset["digest"] == format!("sha256:{}", target.asset_sha256)
            && asset["state"] == "uploaded",
        "existing package release asset differs from the exact verified bytes"
    );
    Ok(Some(asset_id))
}

fn validate_package_release_draft_recovery_record(
    write: &PackageReleaseWrite,
    release: &Value,
    release_id: u64,
) -> Result<()> {
    validate_package_release_recoverable_draft(
        &package_release_write_target(write),
        release,
        release_id,
    )
}

fn validate_package_release_recovery_asset_for_write(
    write: &PackageReleaseWrite,
    api: &GitHub,
    release: &Value,
    required: bool,
) -> Result<bool> {
    validate_package_release_recovery_asset(
        &package_release_write_target(write),
        api,
        release,
        required,
    )
}

fn validate_package_release_published(
    write: &PackageReleaseWrite,
    release: &Value,
    release_id: u64,
) -> Result<()> {
    let prerelease = write.channel == PackageReleaseChannel::Scratch;
    let target = if prerelease {
        write.destination_default_branch.as_str()
    } else {
        write.source_sha.as_str()
    };
    ensure!(
        release["id"].as_u64() == Some(release_id)
            && release["tag_name"] == write.tag
            && release["name"] == write.tag
            && release["target_commitish"] == target
            && release["draft"] == false
            && release["prerelease"] == prerelease
            && release["immutable"] == true,
        "package release is not the exact immutable published release"
    );
    validate_package_release_record(write, release)?;
    validate_package_release_asset(write, release, true)
}

fn validate_package_release_draft(
    write: &PackageReleaseWrite,
    release: &Value,
    release_id: u64,
    require_asset: bool,
) -> Result<()> {
    let prerelease = write.channel == PackageReleaseChannel::Scratch;
    let target = if prerelease {
        write.destination_default_branch.as_str()
    } else {
        write.source_sha.as_str()
    };
    ensure!(
        release["id"].as_u64() == Some(release_id)
            && release["tag_name"] == write.tag
            && release["name"] == write.tag
            && release["target_commitish"] == target
            && release["draft"] == true
            && release["prerelease"] == prerelease
            && release["immutable"] != true,
        "package release is not the selected exact draft"
    );
    validate_package_release_record(write, release)?;
    validate_package_release_asset(write, release, require_asset)
}

fn validate_package_release_asset(
    write: &PackageReleaseWrite,
    release: &Value,
    required: bool,
) -> Result<()> {
    let assets = release["assets"]
        .as_array()
        .context("package draft asset list is missing")?;
    ensure!(assets.len() <= 1, "package draft has unexpected assets");
    if required {
        ensure!(
            assets.len() == 1,
            "package draft is missing its exact asset"
        );
    }
    if let Some(asset) = assets.first() {
        ensure!(
            asset["name"] == write.asset_name
                && asset["size"].as_u64() == Some(write.asset_size)
                && asset["digest"] == format!("sha256:{}", write.asset_sha256)
                && asset["state"] == "uploaded",
            "package draft contains different bytes"
        );
    }
    Ok(())
}

fn package_release_upload_url(write: &PackageReleaseWrite, url: &str) -> Result<String> {
    let release_id = write
        .release_id
        .context("package release draft identity is missing")?;
    let expected_url = format!(
        "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
        write.destination_repository, write.asset_name
    );
    ensure!(
        url == expected_url,
        "package upload differs from the selected release asset"
    );
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        parsed.scheme() == "https"
            && parsed.host_str() == Some("uploads.github.com")
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "package upload endpoint is invalid"
    );
    package_release_upload_path(
        write,
        &format!(
            "/repos/{}/releases/{release_id}/assets?name={}",
            write.destination_repository, write.asset_name
        ),
    )
}

fn package_release_upload_path(write: &PackageReleaseWrite, path: &str) -> Result<String> {
    let release_id = write
        .release_id
        .context("package release draft identity is missing")?;
    let expected_path = format!(
        "/repos/{}/releases/{release_id}/assets?name={}",
        write.destination_repository, write.asset_name
    );
    ensure!(
        path == expected_path,
        "package upload path differs from the exact release asset"
    );
    Ok(expected_path)
}

fn validate_package_release_write_body(
    write: &PackageReleaseWrite,
    method: &Method,
    path: &str,
    body: &Value,
) -> Result<()> {
    if *method == Method::POST
        && path == format!("/repos/{}/releases", write.destination_repository)
    {
        ensure!(
            write.release_id.is_none(),
            "package release draft already has a selected identity"
        );
        let target = if write.channel == PackageReleaseChannel::Scratch {
            write.destination_default_branch.as_str()
        } else {
            write.source_sha.as_str()
        };
        ensure!(
            body == &serde_json::json!({
                "tag_name": write.tag,
                "name": write.tag,
                "target_commitish": target,
                "draft": true,
                "prerelease": write.channel == PackageReleaseChannel::Scratch,
                "generate_release_notes": false,
                "body": package_release_record_body(write)?,
            }),
            "package release create body differs from the exact verified package"
        );
        return Ok(());
    }
    if *method == Method::PATCH
        && write.release_id.is_some_and(|id| {
            path == format!("/repos/{}/releases/{id}", write.destination_repository)
        })
    {
        let publish_body = serde_json::json!({"draft": false});
        let rebind_body = serde_json::json!({
            "body": package_release_record_body(write)?
        });
        let recoverable_rebind = matches!(
            write.preflight_state,
            PackageReleasePreflightState::ResumeDraft { release_id, .. }
                if Some(release_id) == write.release_id
        ) && !write.recovery_body_updated
            && body == &rebind_body;
        ensure!(
            body == &publish_body || recoverable_rebind,
            "package release patch may only rebind an exact recoverable draft or publish it"
        );
        return Ok(());
    }
    if *method == Method::POST && package_release_upload_path(write, path).is_ok() {
        return Ok(());
    }
    if *method == Method::POST
        && path == format!("/repos/{}/git/refs", write.destination_repository)
    {
        ensure!(write.release_id.is_some(), "package release ID is missing");
        ensure!(
            body == &serde_json::json!({
                "ref": format!("refs/tags/{}", write.tag),
                "sha": write.destination_target_sha,
            }),
            "package release tag creation differs from the exact verified package"
        );
        return Ok(());
    }
    bail!("package release write is outside the exact draft, asset, tag, and publish lifecycle")
}

fn validate_package_asset_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "scratch package asset name is invalid"
    );
    Ok(())
}

fn validate_package_scratch_upload(
    url: &str,
    destination_repository: &str,
    release_id: u64,
    asset_name: &str,
    max_asset_bytes: u64,
    bytes_len: usize,
    content_type: &str,
) -> Result<String> {
    crate::policy::validate_repository(destination_repository)?;
    validate_package_asset_name(asset_name)?;
    ensure!(
        release_id > 0 && max_asset_bytes > 0 && max_asset_bytes <= MAX_PACKAGE_SCRATCH_ASSET_BYTES,
        "package scratch upload identity or size limit is invalid"
    );
    ensure!(
        bytes_len > 0 && bytes_len as u64 <= max_asset_bytes,
        "package asset size is outside the configured bound"
    );
    ensure!(
        content_type == "application/octet-stream",
        "package asset content type is invalid"
    );
    let expected_url = format!(
        "https://uploads.github.com/repos/{destination_repository}/releases/{release_id}/assets?name={asset_name}"
    );
    ensure!(
        url == expected_url,
        "package asset upload target is not the selected scratch release"
    );
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        parsed.scheme() == "https"
            && parsed.host_str() == Some("uploads.github.com")
            && parsed.port().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.fragment().is_none(),
        "package asset upload endpoint is invalid"
    );
    Ok(format!(
        "/repos/{destination_repository}/releases/{release_id}/assets"
    ))
}

pub fn require_native_client_workflow_epoch_unchanged(captured: &str, current: &str) -> Result<()> {
    crate::policy::validate_sha(captured)?;
    crate::policy::validate_sha(current)?;
    ensure!(
        captured == current,
        "Client workflow authority changed since request capture"
    );
    Ok(())
}

fn testing_label_cleanup_matches(
    trusted: &crate::config::TrustedConfig,
    method: &Method,
    path: &str,
    payload: &Value,
) -> Result<bool> {
    let deployment = &trusted.deployment;
    if *method != Method::DELETE
        || deployment.workflow_prefix != "testing-"
        || deployment.control_repository.is_none()
        || payload["action"] != "created"
        || payload["repository"]["id"].as_u64() != Some(deployment.server.id)
        || payload["repository"]["full_name"] != deployment.server.repository
        || payload["sender"]["id"].as_u64() != Some(trusted.client_bot_id)
        || payload["sender"]["type"] != "Bot"
    {
        return Ok(false);
    }
    let Some(label) = payload["label"]["name"].as_str() else {
        return Ok(false);
    };
    let Some(description) = payload["label"]["description"].as_str() else {
        return Ok(false);
    };
    if label.len() > 50
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || path != format!("/repos/{}/labels/{label}", deployment.server.repository)
    {
        return Ok(false);
    }
    let request_prefixes = [
        deployment.label_prefix("approve-request-"),
        deployment.label_prefix("merge-request-"),
        deployment.label_prefix("policy-request-"),
        deployment.label_prefix("release-request-"),
    ];
    let label_run = request_prefixes.iter().find_map(|prefix| {
        let suffix = label.strip_prefix(prefix)?;
        let suffix = suffix.strip_prefix("renovate-").unwrap_or(suffix);
        let run = suffix.parse::<u64>().ok()?;
        (run > 0 && run.to_string() == suffix).then_some(run)
    });
    let label_run = label_run.or_else(|| {
        let suffix = label.strip_prefix(&deployment.label_prefix("securefix-"))?;
        let (run, digest) = suffix.split_once('-')?;
        let parsed_run = run.parse::<u64>().ok()?;
        (parsed_run > 0
            && parsed_run.to_string() == run
            && digest.len() == 12
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(parsed_run)
    });
    let Some(label_run) = label_run else {
        return Ok(false);
    };
    let Some((repository, described_run)) = description.rsplit_once('/') else {
        return Ok(false);
    };
    if repository != deployment.integration.repository {
        return Ok(false);
    }
    let Ok(described_run) = described_run.parse::<u64>() else {
        return Ok(false);
    };
    Ok(described_run > 0
        && described_run == label_run
        && described_run.to_string() == description.rsplit('/').next().unwrap_or_default())
}

fn require_single_repository_installation(
    api: &GitHub,
    repository_id: u64,
    repository_name: &str,
) -> Result<()> {
    let installation: Value = api.get("/installation/repositories?per_page=100")?;
    let repositories = installation["repositories"]
        .as_array()
        .context("native request token is not an installation token")?;
    ensure!(
        installation["total_count"].as_u64() == Some(repositories.len() as u64)
            && repositories.len() == 1
            && repositories[0]["id"].as_u64() == Some(repository_id)
            && repositories[0]["full_name"].as_str() == Some(repository_name),
        "native request token must be installed only on the configured repository"
    );
    Ok(())
}

#[cfg(test)]
fn native_installation_repository_response_fixture() -> Value {
    serde_json::from_slice(include_bytes!(
        "../tests/fixtures/native-installation-repositories-response.json"
    ))
    .unwrap()
}

fn validate_instance_config_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && !path.starts_with('/')
            && path.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && component != ".git"
                    && component
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            }),
        "invalid native Server config path"
    );
    Ok(())
}

fn validate_native_scratch_check_body(
    method: &Method,
    path: &str,
    target_repository: &str,
    head_sha: &str,
    request_sha256: &str,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path == format!("/repos/{target_repository}/check-runs")
            && body == &native_policy_check_body(head_sha, request_sha256),
        "native scratch check body does not match the verified request"
    );
    Ok(())
}

fn validate_native_instance_check_body(
    method: &Method,
    path: &str,
    write: &NativeInstanceWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path == format!("/repos/{}/check-runs", write.target_repository)
            && body
                == &native_instance_policy_check_body(
                    &write.server_authority,
                    &write.head_sha,
                    &write.request_sha256,
                )?,
        "native instance check body does not match the verified request"
    );
    Ok(())
}

fn validate_native_instance_approval_body(
    method: &Method,
    path: &str,
    write: &NativeInstanceWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path
                == format!(
                    "/repos/{}/pulls/{}/reviews",
                    write.target_repository, write.pull_number
                )
            && body
                == &native_instance_approval_body(
                    &write.server_authority,
                    &write.head_sha,
                    &write.request_sha256,
                    write.producer_run_id,
                    write.producer_run_attempt,
                )?,
        "native instance approval body does not match the verified request and Server authority"
    );
    Ok(())
}

fn validate_native_instance_merge_body(
    method: &Method,
    path: &str,
    write: &NativeInstanceWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::PUT
            && path
                == format!(
                    "/repos/{}/pulls/{}/merge",
                    write.target_repository, write.pull_number
                )
            && body == &native_merge_body(&write.head_sha),
        "native instance merge body does not match the verified exact PR head"
    );
    Ok(())
}

fn validate_native_approval_body(
    method: &Method,
    path: &str,
    write: &NativeScratchWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path
                == format!(
                    "/repos/{}/pulls/{}/reviews",
                    write.target_repository, write.pull_number
                )
            && body
                == &native_approval_body(
                    &write.server_authority,
                    &write.head_sha,
                    &write.request_sha256
                )?,
        "native approval body does not match the verified request and Server authority"
    );
    Ok(())
}

fn validate_native_merge_body(
    method: &Method,
    path: &str,
    write: &NativeScratchWrite,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::PUT
            && path
                == format!(
                    "/repos/{}/pulls/{}/merge",
                    write.target_repository, write.pull_number
                )
            && body == &native_merge_body(&write.head_sha),
        "native merge body does not match the verified exact PR head"
    );
    Ok(())
}

pub fn native_merge_body(head_sha: &str) -> Value {
    serde_json::json!({
        "sha": head_sha,
        "merge_method": "squash"
    })
}

pub fn native_approval_body(
    authority: &NativeAuthoritySnapshot,
    head_sha: &str,
    request_sha256: &str,
) -> Result<Value> {
    crate::policy::validate_sha(head_sha)?;
    validate_sha256(request_sha256, "native request digest")?;
    let authority_id = native_authority_sha256(authority)?;
    let marker = format!("<!-- securefix:native-approval:v1:{authority_id}:{request_sha256} -->");
    Ok(serde_json::json!({
        "event": "APPROVE",
        "commit_id": head_sha,
        "body": marker
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeInstanceApprovalMarker {
    pub authority_sha256: String,
    pub request_sha256: String,
    pub producer_run_id: u64,
    pub producer_run_attempt: u32,
}

/// Build the durable normal-instance approval marker. The run locator is
/// copied from the already-verified Client approval proof and remains a hint
/// until that proof is fetched and independently revalidated by merge.
pub fn native_instance_approval_body(
    authority: &NativeAuthoritySnapshot,
    head_sha: &str,
    request_sha256: &str,
    producer_run_id: u64,
    producer_run_attempt: u32,
) -> Result<Value> {
    crate::policy::validate_sha(head_sha)?;
    validate_sha256(request_sha256, "native request digest")?;
    ensure!(
        producer_run_id > 0 && producer_run_attempt > 0,
        "native approval producer run identity is invalid"
    );
    let authority_sha256 = native_authority_sha256(authority)?;
    let marker = format!(
        "<!-- securefix:native-approval:v2:{authority_sha256}:{request_sha256}:{producer_run_id}:{producer_run_attempt} -->"
    );
    Ok(serde_json::json!({
        "event": "APPROVE",
        "commit_id": head_sha,
        "body": marker
    }))
}

/// Parse the single strict normal-instance locator from an approval review.
/// The caller must treat its run ID as a fetch hint and verify the exact
/// artifact, attestation, manifest digest, head, and authority before use.
pub fn parse_native_instance_approval_marker(body: &str) -> Result<NativeInstanceApprovalMarker> {
    let marker_lines: Vec<_> = body
        .lines()
        .filter(|line| line.starts_with("<!-- securefix:native-approval:"))
        .collect();
    ensure!(
        marker_lines.len() == 1,
        "native instance approval must contain exactly one marker"
    );
    let contents = marker_lines[0]
        .strip_prefix("<!-- securefix:native-approval:v2:")
        .and_then(|line| line.strip_suffix(" -->"))
        .context("native instance approval marker has an unsupported version or shape")?;
    let parts: Vec<_> = contents.split(':').collect();
    ensure!(
        parts.len() == 4,
        "native instance approval marker has an invalid field count"
    );
    validate_sha256(parts[0], "native approval authority digest")?;
    validate_sha256(parts[1], "native approval request digest")?;
    let producer_run_id = parts[2]
        .parse::<u64>()
        .context("native approval producer run ID is invalid")?;
    let producer_run_attempt = parts[3]
        .parse::<u32>()
        .context("native approval producer run attempt is invalid")?;
    ensure!(
        producer_run_id > 0
            && producer_run_attempt > 0
            && producer_run_id.to_string() == parts[2]
            && producer_run_attempt.to_string() == parts[3],
        "native approval producer run locator is not canonical"
    );
    Ok(NativeInstanceApprovalMarker {
        authority_sha256: parts[0].to_owned(),
        request_sha256: parts[1].to_owned(),
        producer_run_id,
        producer_run_attempt,
    })
}

pub fn native_policy_check_body(head_sha: &str, request_sha256: &str) -> Value {
    serde_json::json!({
        "name": NATIVE_POLICY_CHECK_NAME,
        "head_sha": head_sha,
        "external_id": request_sha256,
        "status": "completed",
        "conclusion": "success",
        "output": {
            "title": NATIVE_POLICY_CHECK_TITLE,
            "summary": NATIVE_POLICY_CHECK_SUMMARY
        }
    })
}

/// Bind a normal-instance policy check to the exact protected Server
/// configuration/role authority and accepted request. Scratch checks retain
/// their separate request-only format.
pub fn native_instance_policy_check_external_id(
    authority: &NativeAuthoritySnapshot,
    head_sha: &str,
    request_sha256: &str,
) -> Result<String> {
    crate::policy::validate_sha(head_sha)?;
    validate_sha256(request_sha256, "native request digest")?;
    let authority_sha256 = native_authority_sha256(authority)?;
    Ok(format!(
        "native:v1:{head_sha}:{authority_sha256}:{request_sha256}"
    ))
}

pub fn parse_native_instance_policy_check_external_id(
    external_id: &str,
) -> Result<NativeInstancePolicyCheckIdentity> {
    let parts: Vec<_> = external_id.split(':').collect();
    ensure!(
        parts.len() == 5 && parts[0] == "native" && parts[1] == "v1",
        "native instance policy-check external ID has an unsupported format"
    );
    crate::policy::validate_sha(parts[2])?;
    validate_sha256(parts[3], "native policy-check authority digest")?;
    validate_sha256(parts[4], "native policy-check request digest")?;
    Ok(NativeInstancePolicyCheckIdentity {
        head_sha: parts[2].to_owned(),
        authority_sha256: parts[3].to_owned(),
        request_sha256: parts[4].to_owned(),
    })
}

pub fn native_authority_sha256(authority: &NativeAuthoritySnapshot) -> Result<String> {
    Ok(crate::hex_encode(sha2::Sha256::digest(serde_json::to_vec(
        authority,
    )?)))
}

/// Reject a normal Client command comment that predates the current Server
/// configuration or role authority epoch. The supplied snapshot must already
/// have been captured and checked against the protected Server default branch.
pub fn require_native_instance_command_after_authority_epoch(
    api: &GitHub,
    authority: &NativeAuthoritySnapshot,
    comment_created_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    validate_native_authority_snapshot(authority)?;
    let commit: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        authority.instance_repository, authority.epoch
    ))?;
    ensure!(
        commit["sha"].as_str() == Some(authority.epoch.as_str()),
        "native Server authority epoch commit identity mismatch"
    );
    let epoch_time = chrono::DateTime::parse_from_rfc3339(
        commit["commit"]["committer"]["date"]
            .as_str()
            .context("native Server authority epoch has no committer date")?,
    )?
    .with_timezone(&chrono::Utc);
    require_native_instance_command_after_time(comment_created_at, epoch_time)
}

fn require_native_instance_command_after_time(
    comment_created_at: chrono::DateTime<chrono::Utc>,
    authority_epoch_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure!(
        comment_created_at > authority_epoch_at,
        "command predates or coincides with the current Server authority epoch"
    );
    Ok(())
}

pub fn native_instance_policy_check_body(
    authority: &NativeAuthoritySnapshot,
    head_sha: &str,
    request_sha256: &str,
) -> Result<Value> {
    crate::policy::validate_sha(head_sha)?;
    Ok(serde_json::json!({
        "name": NATIVE_POLICY_CHECK_NAME,
        "head_sha": head_sha,
        "external_id": native_instance_policy_check_external_id(
            authority,
            head_sha,
            request_sha256
        )?,
        "status": "completed",
        "conclusion": "success",
        "output": {
            "title": NATIVE_POLICY_CHECK_TITLE,
            "summary": NATIVE_POLICY_CHECK_SUMMARY
        }
    }))
}

pub fn validate_native_instance_config_path(path: &str) -> Result<()> {
    validate_instance_config_path(path)
}

fn workflow_uses_pins(bytes: &[u8]) -> Result<Vec<String>> {
    fn visit(value: &serde_yaml::Value, pins: &mut Vec<String>) -> Result<()> {
        match value {
            serde_yaml::Value::Mapping(mapping) => {
                for (key, value) in mapping {
                    if key.as_str() == Some("uses") {
                        let reference = value
                            .as_str()
                            .context("workflow uses value is not a string")?;
                        if reference.starts_with("./") || reference.starts_with("$/") {
                            bail!("Server role wrapper has an unpinned local dependency");
                        }
                        let (_, revision) = reference
                            .rsplit_once('@')
                            .context("workflow dependency is not pinned")?;
                        crate::policy::validate_sha(revision)
                            .context("workflow dependency is not pinned to a full SHA")?;
                        pins.push(reference.to_owned());
                    } else {
                        visit(value, pins)?;
                    }
                }
            }
            serde_yaml::Value::Sequence(values) => {
                for value in values {
                    visit(value, pins)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    ensure!(
        bytes.len() <= 256 * 1024,
        "workflow role exceeds size limit"
    );
    let yaml: serde_yaml::Value = serde_yaml::from_slice(bytes).context("parse workflow role")?;
    let mut pins = Vec::new();
    visit(&yaml, &mut pins)?;
    pins.sort();
    pins.dedup();
    Ok(pins)
}

pub(crate) fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn read_only_query(query: &str) -> bool {
    let query = query.trim_start();
    query
        .strip_prefix("query")
        .is_some_and(|rest| rest.starts_with([' ', '\n', '\r', '\t', '(', '{']))
        && !query.contains("mutation")
}

fn bounded_read(reader: impl Read, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "download exceeded size limit");
    Ok(bytes)
}

pub fn validate_native_managed_file_path(path: &str) -> Result<()> {
    let workflow = path.strip_prefix(".github/workflows/").is_some_and(|name| {
        !name.contains('/') && (name.ends_with(".yml") || name == "actions.lock")
    });
    ensure!(
        (workflow || path == "securefix-server.toml")
            && !path.contains(['\\', '\0', '\r', '\n'])
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "invalid managed-file destination"
    );
    Ok(())
}

fn validate_native_managed_files_target(target: &NativeManagedFilesTarget) -> Result<()> {
    crate::policy::validate_repository(&target.repository)?;
    crate::policy::validate_sha(&target.base_sha)?;
    crate::config::validate_branch(&target.default_branch)?;
    crate::config::validate_branch(&target.branch)?;
    ensure!(
        target.branch.starts_with("securefix/managed-files/")
            && target.branch != target.default_branch,
        "invalid managed-file PR branch"
    );
    target
        .instance
        .config
        .repositories
        .iter()
        .find(|entry| entry.repository == target.repository && entry.id == target.repository_id)
        .context("managed-file destination is not configured")?
        .policy()
        .require(crate::policy::Capability::Settings)?;
    let settings_path = target
        .instance
        .config
        .workflow_roles
        .get(&crate::instance_config::WorkflowRole::Settings)
        .context("managed-file settings workflow role is missing")?;
    ensure!(
        target.source_files.contains_key(settings_path)
            && !target.source_files.is_empty()
            && target.source_files.len() <= 1000,
        "managed-file protected sources missing or excessive"
    );
    for (path, bytes) in &target.source_files {
        ensure!(
            (path == settings_path || path.starts_with("repo-settings/"))
                && !path.contains(['\\', '\0'])
                && path
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && bytes.len() <= 1024 * 1024,
            "invalid protected managed-file source"
        );
    }
    ensure!(
        !target.additions.is_empty() || !target.deletions.is_empty(),
        "managed-file plan is empty"
    );
    let mut paths = std::collections::BTreeSet::new();
    for path in target.additions.keys().chain(target.deletions.iter()) {
        validate_native_managed_file_path(path)?;
        ensure!(paths.insert(path), "duplicate managed-file destination");
    }
    ensure!(
        paths.len() <= 1000
            && target
                .additions
                .values()
                .all(|bytes| bytes.len() <= 1024 * 1024),
        "managed-file plan exceeds bounds"
    );
    Ok(())
}

fn validate_native_managed_files_body(
    write: &NativeManagedFilesWrite,
    method: &Method,
    path: &str,
    body: &Value,
) -> Result<()> {
    let t = &write.target;
    ensure!(
        *method == Method::POST,
        "managed-file writer cannot update or delete existing resources"
    );
    if path == format!("/repos/{}/git/refs", t.repository) {
        ensure!(
            write
                .committed_head
                .lock()
                .map_err(|_| anyhow::anyhow!("managed commit state poisoned"))?
                .is_none()
                && *body
                    == serde_json::json!({"ref":format!("refs/heads/{}", t.branch),"sha":t.base_sha}),
            "managed-file branch creation differs from the accepted base"
        );
    } else if path == format!("/repos/{}/pulls", t.repository) {
        let head = write
            .committed_head
            .lock()
            .map_err(|_| anyhow::anyhow!("managed commit state poisoned"))?;
        ensure!(
            head.is_some()
                && *body
                    == serde_json::json!({"title":"Reconcile managed files","head":t.branch,"base":t.default_branch,
            "body":"Reconcile the protected repo-settings desired files. This PR does not merge automatically."}),
            "managed-file PR differs from its signed branch"
        );
    } else {
        bail!("managed-file commits require the validated signed-commit path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONFIG_PATH: &str = "securefix-server.toml";
    const TEST_WORKFLOW_PATH: &str = ".github/workflows/policy-check.yml";

    fn test_git(repository: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(repository)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn native_managed_files_fixture() -> NativeManagedFilesWrite {
        NativeManagedFilesWrite {
            target: NativeManagedFilesTarget {
                instance: instance_authority_fixture(
                    String::from_utf8_lossy(include_bytes!(
                        "../tests/fixtures/instance-config.toml"
                    ))
                    .replace(
                        "[workflow_roles]",
                        "[workflow_roles]\nsettings = \".github/workflows/repo-settings.yml\"",
                    )
                    .as_bytes(),
                ),
                repository: "example-org/project".into(),
                repository_id: 987654,
                default_branch: "main".into(),
                base_sha: "a".repeat(40),
                branch: "securefix/managed-files/42-1".into(),
                source_files: BTreeMap::from([
                    (
                        ".github/workflows/repo-settings.yml".into(),
                        b"protected settings".to_vec(),
                    ),
                    (
                        "repo-settings/managed-files/approve.yml".into(),
                        b"protected desired".to_vec(),
                    ),
                ]),
                additions: BTreeMap::from([(
                    ".github/workflows/approve.yml".into(),
                    b"protected desired".to_vec(),
                )]),
                deletions: vec![".github/workflows/old.yml".into()],
            },
            committed_head: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn native_repository_settings_limits_endpoints_and_protected_payloads() {
        let managed = native_managed_files_fixture();
        let target = NativeRepositorySettingsTarget {
            instance: managed.target.instance,
            repository: managed.target.repository,
            repository_id: managed.target.repository_id,
            source_files: managed.target.source_files,
            repository_settings: serde_json::json!({"allow_auto_merge":false}),
            collaborator: serde_json::json!({"permission":"push"}),
            rulesets: BTreeMap::from([(
                "controlled-merges".into(),
                serde_json::json!({"name":"controlled-merges","enforcement":"active"}),
            )]),
        };
        let mut api = GitHub::new("http://127.0.0.1:1", "admin-only".into()).unwrap();
        api.writes = WriteContext::NativeRepositorySettings(Box::new(target.clone()));
        for (method, path) in [
            (Method::POST, "/graphql"),
            (Method::POST, "/repos/example-org/project/git/commits"),
            (Method::PUT, "/repos/example-org/project/pulls/4/merge"),
            (Method::PATCH, "/repos/other/project"),
            (Method::DELETE, "/repos/example-org/project/rulesets/1"),
            (Method::PUT, "/repos/example-org/project/rulesets/../1"),
        ] {
            assert!(api.require_write_target(&method, path).is_err(), "{path}");
        }
        let path = "/repos/example-org/project";
        api.require_native_repository_settings_body(
            &target,
            &Method::PATCH,
            path,
            Some(&target.repository_settings),
        )
        .unwrap();
        assert!(
            api.require_native_repository_settings_body(
                &target,
                &Method::PATCH,
                path,
                Some(&serde_json::json!({"allow_auto_merge":true}))
            )
            .is_err()
        );
        assert!(
            api.require_native_repository_settings_body(
                &target,
                &Method::POST,
                "/repos/example-org/project/rulesets",
                target.rulesets.get("controlled-merges")
            )
            .is_err()
        );
        assert!(
            api.require_native_repository_settings_body(
                &target,
                &Method::PUT,
                "/repos/example-org/project/immutable-releases",
                Some(&serde_json::json!({"enabled":false}))
            )
            .is_err()
        );
    }

    #[test]
    fn native_repository_settings_never_reactivates_disabled_controls() {
        use crate::fixtures::{Fixture, Route};
        let managed = native_managed_files_fixture();
        let target = NativeRepositorySettingsTarget {
            instance: managed.target.instance,
            repository: managed.target.repository,
            repository_id: managed.target.repository_id,
            source_files: managed.target.source_files,
            repository_settings: serde_json::json!({}),
            collaborator: serde_json::json!({"permission":"push"}),
            rulesets: BTreeMap::from([(
                "controlled-merges".into(),
                serde_json::json!({"name":"controlled-merges","enforcement":"active"}),
            )]),
        };
        let fixture = Fixture::new(vec![Route::get(
            "/repos/example-org/project/rulesets/7",
            serde_json::json!({"id":7,"name":"controlled-merges","source_type":"Repository","enforcement":"disabled"}),
        )]);
        let api = &fixture.api;
        assert!(
            api.require_native_repository_settings_body(
                &target,
                &Method::PUT,
                "/repos/example-org/project/rulesets/7",
                target.rulesets.get("controlled-merges")
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn native_managed_files_restricts_repository_capability_and_exact_files() {
        let write = native_managed_files_fixture();
        validate_native_managed_files_target(&write.target).unwrap();
        for path in [
            "../policy.json",
            ".github/workflows/../policy.json",
            ".github/workflows/nested/approve.yml",
            "Cargo.toml",
            "control/active.json",
        ] {
            let mut target = write.target.clone();
            target.additions.insert(path.into(), b"bad".to_vec());
            assert!(
                validate_native_managed_files_target(&target).is_err(),
                "{path}"
            );
        }
        let mut target = write.target.clone();
        target.repository_id += 1;
        assert!(validate_native_managed_files_target(&target).is_err());
        let mut target = write.target.clone();
        target.instance.config.repositories[0]
            .capabilities
            .retain(|cap| *cap != crate::policy::Capability::Settings);
        assert!(validate_native_managed_files_target(&target).is_err());
        let mut target = write.target.clone();
        target
            .deletions
            .push(target.additions.keys().next().unwrap().clone());
        assert!(validate_native_managed_files_target(&target).is_err());
    }

    #[test]
    fn native_managed_files_creates_only_a_reviewable_pr_from_its_signed_branch() {
        let write = native_managed_files_fixture();
        let refs = "/repos/example-org/project/git/refs";
        let pulls = "/repos/example-org/project/pulls";
        let reference = serde_json::json!({"ref":"refs/heads/securefix/managed-files/42-1","sha":"a".repeat(40)});
        validate_native_managed_files_body(&write, &Method::POST, refs, &reference).unwrap();
        let mut wrong = reference.clone();
        wrong["ref"] = serde_json::json!("refs/heads/main");
        assert!(validate_native_managed_files_body(&write, &Method::POST, refs, &wrong).is_err());
        let pull = serde_json::json!({"title":"Reconcile managed files","head":"securefix/managed-files/42-1","base":"main",
            "body":"Reconcile the protected repo-settings desired files. This PR does not merge automatically."});
        assert!(validate_native_managed_files_body(&write, &Method::POST, pulls, &pull).is_err());
        *write.committed_head.lock().unwrap() = Some("b".repeat(40));
        validate_native_managed_files_body(&write, &Method::POST, pulls, &pull).unwrap();
        assert!(
            validate_native_managed_files_body(&write, &Method::POST, refs, &reference).is_err()
        );
        for (method, path) in [
            (Method::PUT, "/repos/example-org/project/pulls/1/merge"),
            (Method::PATCH, pulls),
            (Method::POST, "/repos/example-org/project/git/commits"),
        ] {
            assert!(validate_native_managed_files_body(&write, &method, path, &pull).is_err());
        }
    }

    #[test]
    fn git_fetch_uses_basic_token_authorization() {
        assert_eq!(
            git_authorization_header("ghs_test"),
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46Z2hzX3Rlc3Q="
        );
    }

    fn instance_authority_fixture(config_bytes: &[u8]) -> NativeServerInstanceAuthority {
        let config = crate::instance_config::InstanceConfig::parse(config_bytes).unwrap();
        NativeServerInstanceAuthority {
            authority: NativeAuthoritySnapshot {
                instance_repository: config.instance.repository.clone(),
                instance_id: config.instance.id,
                default_branch: config.instance.default_branch.clone(),
                config_path: TEST_CONFIG_PATH.to_owned(),
                config_sha256: crate::hex_encode(sha2::Sha256::digest(config_bytes)),
                epoch: "a".repeat(40),
                workflows: vec![NativeWorkflowAuthority {
                    role: crate::instance_config::WorkflowRole::PolicyCheck,
                    path: config.workflow_roles[&crate::instance_config::WorkflowRole::PolicyCheck]
                        .clone(),
                    sha256: "b".repeat(64),
                    pins: vec![
                        "example-org/server/.github/workflows/policy.yml@".to_owned()
                            + &"c".repeat(40),
                    ],
                }],
            },
            config,
            config_bytes: config_bytes.to_vec(),
        }
    }

    #[test]
    fn external_instance_authority_rejects_stale_config_and_role_snapshot() {
        let config_bytes = include_bytes!("../tests/fixtures/instance-config.toml");
        let captured = instance_authority_fixture(config_bytes);
        assert!(require_native_server_instance_authority_unchanged(&captured, &captured).is_ok());

        let changed_config = [config_bytes.as_slice(), b"\n"].concat();
        let stale_config = instance_authority_fixture(&changed_config);
        assert!(
            require_native_server_instance_authority_unchanged(&captured, &stale_config).is_err()
        );

        let mut changed_role = instance_authority_fixture(config_bytes);
        changed_role.authority.workflows[0].sha256 = "d".repeat(64);
        assert!(
            require_native_server_instance_authority_unchanged(&captured, &changed_role).is_err()
        );
    }

    fn test_commit_file(repository: &Path, path: &str, contents: &str, message: &str) -> String {
        let file = repository.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
        test_git(repository, &["add", "--", path]);
        test_git(
            repository,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Securefix Test",
                "-c",
                "user.email=securefix-test@example.invalid",
                "commit",
                "-m",
                message,
            ],
        );
        String::from_utf8(test_git(repository, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn test_authority_snapshot(
        repository: &Path,
        revision: &str,
        global_config: &Path,
        hooks: &Path,
    ) -> NativeAuthoritySnapshot {
        let config = test_git(
            repository,
            &["show", &format!("{revision}:{TEST_CONFIG_PATH}")],
        );
        let workflow = test_git(
            repository,
            &["show", &format!("{revision}:{TEST_WORKFLOW_PATH}")],
        );
        let epoch = first_parent_path_epoch_at(
            repository,
            revision,
            &[TEST_CONFIG_PATH.to_owned(), TEST_WORKFLOW_PATH.to_owned()],
            global_config,
            hooks,
            Instant::now() + MAX_GIT_OPERATION_TIME,
        )
        .unwrap();
        NativeAuthoritySnapshot {
            instance_repository: "example-org/securefix-server".into(),
            instance_id: 404,
            default_branch: "main".into(),
            config_path: TEST_CONFIG_PATH.into(),
            config_sha256: crate::hex_encode(sha2::Sha256::digest(config)),
            epoch,
            workflows: vec![NativeWorkflowAuthority {
                role: crate::instance_config::WorkflowRole::PolicyCheck,
                path: TEST_WORKFLOW_PATH.into(),
                sha256: crate::hex_encode(sha2::Sha256::digest(workflow)),
                pins: Vec::new(),
            }],
        }
    }

    #[test]
    fn authority_fetch_pins_exact_sha_and_reads_complete_history() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let bare_remote = directory.path().join("remote.git");
        let checkout = directory.path().join("authority.git");
        test_git(
            directory.path(),
            &[
                "init",
                "--quiet",
                "--initial-branch=main",
                source.to_str().unwrap(),
            ],
        );
        test_commit_file(
            &source,
            TEST_CONFIG_PATH,
            "[instance]\nname = \"test\"\n",
            "initial config",
        );
        let revision = test_commit_file(
            &source,
            TEST_WORKFLOW_PATH,
            "uses: securefix@old\n",
            "initial workflow",
        );
        test_git(
            directory.path(),
            &["init", "--bare", "--quiet", bare_remote.to_str().unwrap()],
        );
        test_git(
            &source,
            &["remote", "add", "origin", bare_remote.to_str().unwrap()],
        );
        test_git(
            &source,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );

        let global_config = directory.path().join("global-config");
        let hooks = directory.path().join("empty-hooks");
        std::fs::write(
            &global_config,
            "[credential]\n\thelper =\n[protocol]\n\tallow = never\n[protocol \"file\"]\n\tallow = always\n",
        )
        .unwrap();
        std::fs::create_dir(&hooks).unwrap();
        let deadline = Instant::now() + MAX_GIT_OPERATION_TIME;
        git_output(
            directory.path(),
            &[
                "init",
                "--bare",
                "--quiet",
                "--template=",
                checkout.to_str().unwrap(),
            ],
            &global_config,
            &hooks,
            None,
            MAX_GIT_OUTPUT_BYTES,
            deadline,
        )
        .unwrap();
        let file_remote = format!("file://{}", bare_remote.display());
        git_output(
            &checkout,
            &["remote", "add", "origin", &file_remote],
            &global_config,
            &hooks,
            None,
            MAX_GIT_OUTPUT_BYTES,
            deadline,
        )
        .unwrap();
        let objects = checkout.join("objects");
        git_status(
            &checkout,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--filter=blob:none",
                "origin",
                &revision,
            ],
            &global_config,
            &hooks,
            None,
            &objects,
            deadline,
        )
        .unwrap();
        let fetched = git_output(
            &checkout,
            &["rev-parse", "FETCH_HEAD^{commit}"],
            &global_config,
            &hooks,
            None,
            64,
            deadline,
        )
        .unwrap();
        assert_eq!(std::str::from_utf8(&fetched).unwrap().trim(), revision);
        let epoch = first_parent_path_epoch_at(
            &checkout,
            &revision,
            &[TEST_CONFIG_PATH.to_owned(), TEST_WORKFLOW_PATH.to_owned()],
            &global_config,
            &hooks,
            deadline,
        )
        .unwrap();
        assert_eq!(epoch, revision);
        assert!(git_object_store_size(&objects).unwrap() <= MAX_AUTHORITY_OBJECT_BYTES);
    }

    fn native_scratch_api() -> GitHub {
        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::NativeScratch(Box::new(NativeScratchWrite {
            mode: NativeScratchMode::PolicyCheck,
            instance_repository: "civitaspo/securefix-server".into(),
            instance_id: 1,
            instance_owner_id: 2,
            default_branch: "main".into(),
            config_path: "securefix-server.toml".into(),
            config_bytes: vec![],
            server_authority: NativeAuthoritySnapshot {
                instance_repository: "civitaspo/securefix-server".into(),
                instance_id: 1,
                default_branch: "main".into(),
                config_path: "securefix-server.toml".into(),
                config_sha256: "d".repeat(64),
                epoch: "e".repeat(40),
                workflows: vec![],
            },
            target_repository: SCRATCH_REPOSITORY.into(),
            target_id: 3,
            pull_number: 4,
            head_sha: "b".repeat(40),
            head_repository_id: 3,
            base_ref: "main".into(),
            author_id: 5,
            author_login: "maintainer".into(),
            actor_id: 5,
            actor_login: "maintainer".into(),
            request_sha256: "c".repeat(64),
            caller_workflow_path: ".github/workflows/policy-check.yml".into(),
            caller_workflow_sha: "2".repeat(40),
            client_workflow_epoch: "3".repeat(40),
            target_policy_control_identity: None,
            destination_branch: None,
        }));
        api
    }

    fn native_instance_api(mode: NativeInstanceMode) -> GitHub {
        let config_bytes = include_bytes!("../tests/fixtures/instance-config.toml");
        let config = crate::instance_config::InstanceConfig::parse(config_bytes).unwrap();
        let authority = instance_authority_fixture(config_bytes).authority;
        let mut api = GitHub::new("https://api.github.com", "reader-token".into()).unwrap();
        api.write_token = Some("writer-token".into());
        api.writes = WriteContext::NativeInstance(Box::new(NativeInstanceWrite {
            mode,
            instance_repository: config.instance.repository,
            instance_id: config.instance.id,
            default_branch: config.instance.default_branch,
            config_path: TEST_CONFIG_PATH.into(),
            config_bytes: config_bytes.to_vec(),
            server_authority: authority,
            target_repository: "example-org/project".into(),
            target_id: 987_654,
            pull_number: 4,
            head_sha: "b".repeat(40),
            head_branch: "feature".into(),
            head_repository_id: 987_654,
            base_sha: "c".repeat(40),
            base_ref: "main".into(),
            author_id: 777,
            author_login: "contributor".into(),
            actor_id: 101,
            actor_login: "maintainer".into(),
            request_sha256: "d".repeat(64),
            producer_run_id: 123,
            producer_run_attempt: 1,
            producer_workflow_path: ".github/workflows/request-producer.yml".into(),
            producer_workflow_sha: "e".repeat(40),
            client_workflow_epoch: "f".repeat(40),
            merge_fence: None,
        }));
        api
    }

    fn native_instance_merge_checks_fixture(
        head_sha: &str,
        checks: Vec<Value>,
    ) -> crate::fixtures::Fixture {
        use crate::fixtures::{Fixture, Route};

        let check_path = format!(
            "/repos/example-org/project/commits/{head_sha}/check-runs?per_page=100&page=1&filter=all"
        );
        Fixture::new(vec![Route::get(
            check_path,
            serde_json::json!({"total_count":checks.len(),"check_runs":checks}),
        )])
    }

    #[test]
    fn native_check_listing_reads_all_pages_and_rejects_incomplete_or_duplicate_results() {
        use crate::fixtures::{Fixture, Route};
        let head = "a".repeat(40);
        let path = |page| {
            format!(
                "/repos/example-org/project/commits/{head}/check-runs?per_page=100&page={page}&filter=all"
            )
        };
        let first: Vec<_> = (1..=100).map(|id| serde_json::json!({"id":id})).collect();
        let fixture = Fixture::new(vec![
            Route::get(
                path(1),
                serde_json::json!({"total_count":101,"check_runs":first}),
            ),
            Route::get(
                path(2),
                serde_json::json!({"total_count":101,"check_runs":[{"id":101}]}),
            ),
        ]);
        assert_eq!(
            native_check_runs_for_head(&fixture.api, "example-org/project", &head)
                .unwrap()
                .len(),
            101
        );
        fixture.finish();
        for response in [
            serde_json::json!({"total_count":2,"check_runs":[{"id":1}]}),
            serde_json::json!({"total_count":2,"check_runs":[{"id":1},{"id":1}]}),
            serde_json::json!({"check_runs":[]}),
        ] {
            let fixture = Fixture::new(vec![Route::get(path(1), response)]);
            assert!(
                native_check_runs_for_head(&fixture.api, "example-org/project", &head).is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn native_instance_merge_fence_rejects_changed_checks_and_latest_review() {
        use crate::fixtures::{Fixture, Route};

        let config_bytes = include_bytes!("../tests/fixtures/instance-config.toml");
        let instance = instance_authority_fixture(config_bytes);
        let head_sha = "b".repeat(40);
        let approval_request_sha256 = "d".repeat(64);
        let approval_producer_run_id = 123;
        let approval_producer_run_attempt = 2;
        let marker = native_instance_approval_body(
            &instance.authority,
            &head_sha,
            &approval_request_sha256,
            approval_producer_run_id,
            approval_producer_run_attempt,
        )
        .unwrap()["body"]
            .as_str()
            .unwrap()
            .to_owned();
        let policy_external_id = native_instance_policy_check_external_id(
            &instance.authority,
            &head_sha,
            &"e".repeat(64),
        )
        .unwrap();
        let mut old_authority = instance.authority.clone();
        old_authority.config_sha256 = "1".repeat(64);
        let old_external_id =
            native_instance_policy_check_external_id(&old_authority, &head_sha, &"d".repeat(64))
                .unwrap();
        let checks = |status_conclusion: &str| {
            vec![
                serde_json::json!({
                    "id": 1,
                    "name": "status-check",
                    "app": {"id": instance.config.apps.status_check_id},
                    "status": "completed",
                    "conclusion": status_conclusion
                }),
                serde_json::json!({
                    "id": 2000,
                    "name": NATIVE_POLICY_CHECK_NAME,
                    "app": {"id": instance.config.apps.policy_check_id},
                    "head_sha": head_sha,
                    "external_id": old_external_id,
                    "status": "completed",
                    "conclusion": "success"
                }),
                serde_json::json!({
                    "id": 3,
                    "name": NATIVE_POLICY_CHECK_NAME,
                    "app": {"id": instance.config.apps.policy_check_id},
                    "head_sha": head_sha,
                    "external_id": policy_external_id,
                    "status": "completed",
                    "conclusion": "success"
                }),
            ]
        };
        let approved_review = serde_json::json!({
            "id": 42,
            "state": "APPROVED",
            "commit_id": head_sha,
            "body": marker,
            "submitted_at": "2026-10-23T01:00:00Z",
            "user": {
                "id": instance.config.identities.approval_reviewer.id,
                "login": instance.config.identities.approval_reviewer.login,
                "type": "User"
            }
        });
        let capture = |api: &GitHub| {
            let readiness = NativeInstanceMergeReadiness {
                repository: "example-org/project",
                repository_id: 987_654,
                pull_number: 4,
                head_sha: &head_sha,
                authority: &instance.authority,
                approval_request_sha256: &approval_request_sha256,
                approval_producer_run_id,
                approval_producer_run_attempt,
            };
            capture_native_instance_merge_fence(api, &instance.config, &readiness)
        };

        let successful_readiness_fixture = || {
            Fixture::new(vec![
                Route::get(
                    format!(
                        "/repos/example-org/project/commits/{head_sha}/check-runs?per_page=100&page=1&filter=all"
                    ),
                    serde_json::json!({"total_count":3,"check_runs":checks("success")}),
                ),
                Route::get(
                    "/repos/example-org/project/pulls/4/reviews?per_page=100&page=1",
                    serde_json::json!([approved_review.clone()]),
                ),
                Route::request(
                    "POST",
                    "/graphql",
                    200,
                    serde_json::json!({
                        "data": {"repository": {"pullRequest": {"reviewDecision": "APPROVED"}}}
                    }),
                )
                .with_request_header("authorization", "Bearer fixture-token"),
            ])
        };
        let accepted_fixture = successful_readiness_fixture();
        let accepted = capture(&accepted_fixture.api).unwrap();
        assert_eq!(accepted.approval_review_id, 42);
        let mut current_fixture = successful_readiness_fixture();
        current_fixture.api.writes = native_instance_api(NativeInstanceMode::Merge).writes;
        current_fixture.api.write_token = Some("merge-writer-token".into());
        let current = capture(&current_fixture.api).unwrap();
        let mut successful_merge_puts = 0;
        send_after_native_instance_merge_fence(&accepted, Ok(current), || {
            successful_merge_puts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(successful_merge_puts, 1);
        accepted_fixture.finish();
        current_fixture.finish();

        let changed_check = checks("failure");
        let changed_check_fixture = native_instance_merge_checks_fixture(&head_sha, changed_check);
        let mut changed_check_merge_puts = 0;
        let changed_check_result = send_after_native_instance_merge_fence(
            &accepted,
            capture(&changed_check_fixture.api),
            || {
                changed_check_merge_puts += 1;
                Ok(())
            },
        );
        assert!(
            changed_check_result
                .unwrap_err()
                .to_string()
                .contains("native merge required checks")
        );
        assert_eq!(changed_check_merge_puts, 0);
        changed_check_fixture.finish();

        for state in [
            "failure",
            "in_progress",
            "old_authority_only",
            "replayed_request",
        ] {
            let mut values = checks("success");
            if state == "old_authority_only" {
                values.pop();
            } else {
                let mut newer = values[2].clone();
                newer["id"] = serde_json::json!(4);
                if state != "replayed_request" {
                    newer["external_id"] = serde_json::json!(
                        native_instance_policy_check_external_id(
                            &instance.authority,
                            &head_sha,
                            &"f".repeat(64)
                        )
                        .unwrap()
                    );
                }
                if state == "in_progress" {
                    newer["status"] = serde_json::json!("in_progress");
                    newer["conclusion"] = Value::Null;
                } else if state == "failure" {
                    newer["conclusion"] = serde_json::json!("failure");
                }
                values.insert(0, newer);
            }
            let fixture = native_instance_merge_checks_fixture(&head_sha, values);
            let mut writes = 0;
            assert!(
                send_after_native_instance_merge_fence(&accepted, capture(&fixture.api), || {
                    writes += 1;
                    Ok(())
                })
                .is_err(),
                "{state}"
            );
            assert_eq!(writes, 0, "{state}");
            fixture.finish();
        }
        let mut reordered = checks("success");
        reordered.reverse();
        assert!(
            native_instance_merge_checks_ready(
                &reordered,
                instance.config.apps.status_check_id,
                instance.config.apps.policy_check_id,
                &head_sha,
                &instance.authority
            )
            .unwrap()
        );
        let mut fresh_success = reordered[0].clone();
        fresh_success["id"] = serde_json::json!(5);
        fresh_success["external_id"] = serde_json::json!(
            native_instance_policy_check_external_id(
                &instance.authority,
                &head_sha,
                &"f".repeat(64)
            )
            .unwrap()
        );
        reordered.insert(0, fresh_success);
        assert!(
            native_instance_merge_checks_ready(
                &reordered,
                instance.config.apps.status_check_id,
                instance.config.apps.policy_check_id,
                &head_sha,
                &instance.authority
            )
            .unwrap()
        );

        let mut old_review = approved_review.clone();
        old_review["body"] = native_instance_approval_body(
            &old_authority,
            &head_sha,
            &approval_request_sha256,
            approval_producer_run_id,
            approval_producer_run_attempt,
        )
        .unwrap()["body"]
            .clone();
        let old_approval_fixture = Fixture::new(vec![
            Route::get(
                format!(
                    "/repos/example-org/project/commits/{head_sha}/check-runs?per_page=100&page=1&filter=all"
                ),
                serde_json::json!({"total_count":3,"check_runs":checks("success")}),
            ),
            Route::get(
                "/repos/example-org/project/pulls/4/reviews?per_page=100&page=1",
                serde_json::json!([old_review]),
            ),
        ]);
        let mut stale_approval_writes = 0;
        assert!(
            send_after_native_instance_merge_fence(
                &accepted,
                capture(&old_approval_fixture.api),
                || {
                    stale_approval_writes += 1;
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(stale_approval_writes, 0);
        old_approval_fixture.finish();

        let mut latest_review = approved_review.clone();
        latest_review["id"] = serde_json::json!(43);
        latest_review["state"] = serde_json::json!("CHANGES_REQUESTED");
        latest_review["submitted_at"] = serde_json::json!("2026-10-23T01:01:00Z");
        let changed_review_fixture = Fixture::new(vec![
            Route::get(
                format!(
                    "/repos/example-org/project/commits/{head_sha}/check-runs?per_page=100&page=1&filter=all"
                ),
                serde_json::json!({"total_count":3,"check_runs":checks("success")}),
            ),
            Route::get(
                "/repos/example-org/project/pulls/4/reviews?per_page=100&page=1",
                serde_json::json!([approved_review.clone(), latest_review]),
            ),
        ]);
        let mut changed_review_merge_puts = 0;
        let changed_review_result = send_after_native_instance_merge_fence(
            &accepted,
            capture(&changed_review_fixture.api),
            || {
                changed_review_merge_puts += 1;
                Ok(())
            },
        );
        assert!(
            changed_review_result
                .unwrap_err()
                .to_string()
                .contains("latest configured reviewer decision")
        );
        assert_eq!(changed_review_merge_puts, 0);
        changed_review_fixture.finish();
    }

    #[test]
    fn native_merge_policy_control_identity_comes_from_the_configured_target_repository() {
        use crate::fixtures::{Fixture, Route};

        let server_control: crate::control::ControlRevision = serde_json::from_slice(
            include_bytes!("../tests/fixtures/native-server-instance-control.json"),
        )
        .unwrap();
        let target_bytes = include_bytes!("../tests/fixtures/native-target-control.json");
        let target_control: crate::control::ControlRevision =
            serde_json::from_slice(target_bytes).unwrap();
        let server_identity = server_control.identity().unwrap();
        let target_identity = target_control.identity().unwrap();
        assert_eq!(
            server_identity,
            "fbb4c101499cebb45a56b980363c70c21f15af79eff459eae6c301b56bca5209"
        );
        assert_eq!(
            target_identity,
            "824f3066c5d35178102dad38ccd00f375d5cdcd6e31343b445b653c493fb853c"
        );
        assert_ne!(server_identity, target_identity);

        use base64::Engine as _;
        let encoded_target = base64::engine::general_purpose::STANDARD.encode(target_bytes);
        let fixture = Fixture::new(vec![
            Route::get(
                "/installation/repositories?per_page=100",
                serde_json::json!({
                    "total_count":1,
                    "repositories":[{
                        "id":1_410_312_556,
                        "full_name":"civitaspo/testing-securefix-server"
                    }]
                }),
            ),
            Route::get(
                "/repos/civitaspo/testing-securefix-server",
                serde_json::json!({
                    "id":1_410_312_556,
                    "full_name":"civitaspo/testing-securefix-server",
                    "default_branch":"main"
                }),
            ),
            Route::get(
                "/repos/civitaspo/testing-securefix-server/contents/control/active.json?ref=main",
                serde_json::json!({"encoding":"base64","content":encoded_target}),
            ),
        ]);
        let actual = native_target_policy_control_identity(
            &fixture.api,
            "civitaspo/testing-securefix-server",
            1_410_312_556,
            "main",
        )
        .unwrap();
        assert_eq!(actual, target_identity);
        assert_ne!(actual, server_identity);
        fixture.finish();
    }

    #[test]
    fn native_merge_target_control_read_rejects_an_unscoped_client_token() {
        use crate::fixtures::{Fixture, Route};

        let mut installation = native_installation_repository_response_fixture();
        installation["total_count"] = 2.into();
        installation["repositories"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": 9,
                "full_name": "civitaspo/unexpected-repository"
            }));
        let fixture = Fixture::new(vec![Route::get(
            "/installation/repositories?per_page=100",
            installation,
        )]);
        assert!(
            native_target_policy_control_identity(
                &fixture.api,
                "civitaspo/testing-securefix-server",
                1_410_312_556,
                "main",
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn native_installation_check_uses_only_the_saved_supported_repository_response() {
        use crate::fixtures::{Fixture, Route};

        let fixture = Fixture::new(vec![Route::get(
            "/installation/repositories?per_page=100",
            native_installation_repository_response_fixture(),
        )]);
        require_single_repository_installation(
            &fixture.api,
            1_410_312_556,
            "civitaspo/testing-securefix-server",
        )
        .unwrap();
        fixture.finish();
    }

    #[test]
    fn native_installation_check_rejects_a_saved_response_with_an_extra_repository() {
        use crate::fixtures::{Fixture, Route};

        let mut response = native_installation_repository_response_fixture();
        response["total_count"] = 2.into();
        response["repositories"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": 9,
                "full_name": "civitaspo/unexpected-repository"
            }));
        let fixture = Fixture::new(vec![Route::get(
            "/installation/repositories?per_page=100",
            response,
        )]);
        assert!(
            require_single_repository_installation(
                &fixture.api,
                1_410_312_556,
                "civitaspo/testing-securefix-server",
            )
            .is_err()
        );
        fixture.finish();
    }

    fn native_securefix_api() -> GitHub {
        let mut api = native_scratch_api();
        let WriteContext::NativeScratch(write) = &api.writes else {
            unreachable!();
        };
        let mut write = write.as_ref().clone();
        write.mode = NativeScratchMode::Securefix;
        write.destination_branch = Some("scratch".to_owned());
        api.writes = WriteContext::NativeScratch(Box::new(write));
        api
    }

    fn native_approval_api() -> GitHub {
        let mut api = native_scratch_api();
        let WriteContext::NativeScratch(write) = &api.writes else {
            unreachable!();
        };
        let mut write = write.as_ref().clone();
        write.mode = NativeScratchMode::Approval;
        api.writes = WriteContext::NativeScratch(Box::new(write));
        api
    }

    fn native_merge_api() -> GitHub {
        let mut api = native_scratch_api();
        let WriteContext::NativeScratch(write) = &api.writes else {
            unreachable!();
        };
        let mut write = write.as_ref().clone();
        write.mode = NativeScratchMode::Merge;
        api.writes = WriteContext::NativeScratch(Box::new(write));
        api
    }

    #[test]
    fn native_scratch_writer_allows_only_one_bound_check_run() {
        let api = native_scratch_api();
        let path = format!("/repos/{SCRATCH_REPOSITORY}/check-runs");
        assert!(api.require_write_target(&Method::POST, &path).is_ok());
        for (method, path) in [
            (Method::PATCH, path.as_str()),
            (Method::DELETE, path.as_str()),
            (Method::POST, "/graphql"),
            (Method::POST, "/repos/other/repo/check-runs"),
        ] {
            assert!(api.require_write_target(&method, path).is_err());
        }
        assert!(
            api.upload(
                "https://uploads.github.com/repos/owner/repo/releases/1/assets?name=x",
                Vec::new(),
                "application/octet-stream"
            )
            .is_err()
        );
        assert!(
            api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"b".repeat(40),
                "test",
                BTreeMap::from([("file.txt".into(), b"x".to_vec())]),
                vec![],
            )
            .is_err()
        );
    }

    #[test]
    fn native_instance_writers_are_scoped_to_the_bound_operation_and_request() {
        let check_api = native_instance_api(NativeInstanceMode::PolicyCheck);
        let check_path = "/repos/example-org/project/check-runs";
        assert!(
            check_api
                .require_write_target(&Method::POST, check_path)
                .is_ok()
        );
        assert!(
            check_api
                .require_write_target(&Method::POST, "/graphql")
                .is_err()
        );
        assert!(
            check_api
                .require_write_target(&Method::PATCH, check_path)
                .is_err()
        );
        let WriteContext::NativeInstance(check_write) = &check_api.writes else {
            unreachable!();
        };
        let check_body = native_instance_policy_check_body(
            &check_write.server_authority,
            &check_write.head_sha,
            &check_write.request_sha256,
        )
        .unwrap();
        assert!(
            validate_native_instance_check_body(
                &Method::POST,
                check_path,
                check_write,
                &check_body
            )
            .is_ok()
        );
        assert!(
            validate_native_instance_check_body(
                &Method::POST,
                check_path,
                check_write,
                &serde_json::json!({"head_sha": "f".repeat(40)})
            )
            .is_err()
        );

        let approve_api = native_instance_api(NativeInstanceMode::Approve);
        let approval_path = "/repos/example-org/project/pulls/4/reviews";
        assert!(
            approve_api
                .require_write_target(&Method::POST, approval_path)
                .is_ok()
        );
        assert!(
            approve_api
                .require_write_target(&Method::POST, "/repos/example-org/project/pulls/5/reviews")
                .is_err()
        );
        let WriteContext::NativeInstance(approve_write) = &approve_api.writes else {
            unreachable!();
        };
        let approval_body = native_instance_approval_body(
            &approve_write.server_authority,
            &approve_write.head_sha,
            &approve_write.request_sha256,
            approve_write.producer_run_id,
            approve_write.producer_run_attempt,
        )
        .unwrap();
        assert!(
            validate_native_instance_approval_body(
                &Method::POST,
                approval_path,
                approve_write,
                &approval_body,
            )
            .is_ok()
        );
        assert!(
            parse_native_instance_approval_marker(approval_body["body"].as_str().unwrap()).is_ok()
        );
        let mut stale_approval_body = approval_body.clone();
        stale_approval_body["commit_id"] = serde_json::json!("a".repeat(40));
        assert!(
            validate_native_instance_approval_body(
                &Method::POST,
                approval_path,
                approve_write,
                &stale_approval_body,
            )
            .is_err()
        );
        let request = approve_api
            .builder(Method::GET, "/user")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer writer-token"
        );

        let merge_api = native_instance_api(NativeInstanceMode::Merge);
        let merge_path = "/repos/example-org/project/pulls/4/merge";
        assert!(
            merge_api
                .require_write_target(&Method::PUT, merge_path)
                .is_ok()
        );
        assert!(
            merge_api
                .require_write_target(&Method::POST, merge_path)
                .is_err()
        );
        let WriteContext::NativeInstance(merge_write) = &merge_api.writes else {
            unreachable!();
        };
        let merge_body = native_merge_body(&merge_write.head_sha);
        assert!(
            validate_native_instance_merge_body(&Method::PUT, merge_path, merge_write, &merge_body)
                .is_ok()
        );
        let mut stale_merge_body = merge_body.clone();
        stale_merge_body["sha"] = serde_json::json!("a".repeat(40));
        assert!(
            validate_native_instance_merge_body(
                &Method::PUT,
                merge_path,
                merge_write,
                &stale_merge_body
            )
            .is_err()
        );

        let securefix_api = native_instance_api(NativeInstanceMode::Securefix);
        let commit_path = "/repos/example-org/project/git/commits";
        assert!(
            securefix_api
                .require_write_target(&Method::POST, commit_path)
                .is_ok()
        );
        assert!(
            securefix_api
                .require_write_target(&Method::POST, "/repos/other/project/git/commits")
                .is_err()
        );
        let request = securefix_api
            .builder(Method::POST, "/graphql")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer writer-token"
        );
        let mut additions = BTreeMap::new();
        additions.insert("file.txt".to_owned(), b"contents".to_vec());
        assert!(
            securefix_api
                .create_commit(
                    "example-org/project",
                    "another-branch",
                    &"b".repeat(40),
                    "Securefix",
                    additions,
                    Vec::new(),
                )
                .is_err()
        );
    }

    #[test]
    fn native_instance_target_requires_configured_capability_and_same_repo_securefix_head() {
        let config = crate::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let base = NativeInstanceWriteTarget {
            mode: NativeInstanceMode::Securefix,
            config_path: TEST_CONFIG_PATH,
            repository: "example-org/project",
            repository_id: 987_654,
            pull_number: 4,
            head_sha: &"b".repeat(40),
            head_branch: "feature",
            head_repository_id: 987_654,
            base_sha: &"c".repeat(40),
            base_ref: "main",
            author_id: 777,
            author_login: "contributor",
            actor_id: 101,
            actor_login: "maintainer",
            request_sha256: &"d".repeat(64),
            producer_run_id: 123,
            producer_run_attempt: 1,
            producer_workflow_path: ".github/workflows/request-producer.yml",
            producer_workflow_sha: &"e".repeat(40),
            client_workflow_epoch: &"f".repeat(40),
            merge_fence: None,
        };
        assert!(validate_native_instance_write_target(&config, &base).is_ok());

        let fork_head = NativeInstanceWriteTarget {
            head_repository_id: 987_655,
            ..base
        };
        assert!(validate_native_instance_write_target(&config, &fork_head).is_err());

        let unconfigured_target = NativeInstanceWriteTarget {
            repository: "example-org/unconfigured",
            ..fork_head
        };
        assert!(validate_native_instance_write_target(&config, &unconfigured_target).is_err());
    }

    #[test]
    fn normal_native_approval_marker_has_a_strict_run_locator() {
        let authority = NativeAuthoritySnapshot {
            instance_repository: "example-org/securefix-server".into(),
            instance_id: 404,
            default_branch: "main".into(),
            config_path: TEST_CONFIG_PATH.into(),
            config_sha256: "a".repeat(64),
            epoch: "b".repeat(40),
            workflows: Vec::new(),
        };
        let request_sha256 = "c".repeat(64);
        let body =
            native_instance_approval_body(&authority, &"d".repeat(40), &request_sha256, 123, 2)
                .unwrap();
        let marker = body["body"].as_str().unwrap();
        let parsed = parse_native_instance_approval_marker(marker).unwrap();
        assert_eq!(parsed.request_sha256, request_sha256);
        assert_eq!(parsed.producer_run_id, 123);
        assert_eq!(parsed.producer_run_attempt, 2);

        for invalid in [
            format!("{marker}\n{marker}"),
            marker.replace(":123:2 -->", ":0123:2 -->"),
            marker.replace(":123:2 -->", ":0:2 -->"),
            marker.replace("native-approval:v2", "native-approval:v1"),
            format!("{marker} trailing"),
        ] {
            assert!(
                parse_native_instance_approval_marker(&invalid).is_err(),
                "{invalid}"
            );
        }
        assert!(
            native_instance_approval_body(&authority, &"d".repeat(40), &request_sha256, 0, 1)
                .is_err()
        );
    }

    #[test]
    fn native_securefix_writer_allows_only_a_commit_to_the_bound_pr_branch_and_head() {
        let api = native_securefix_api();
        let path = format!("/repos/{SCRATCH_REPOSITORY}/git/commits");
        assert!(api.require_write_target(&Method::POST, &path).is_ok());
        assert!(
            api.require_write_target(
                &Method::POST,
                &format!("/repos/{SCRATCH_REPOSITORY}/check-runs")
            )
            .is_err()
        );
        assert!(api.require_write_target(&Method::POST, "/graphql").is_err());
        let mut additions = std::collections::BTreeMap::new();
        additions.insert("file.txt".to_owned(), b"contents".to_vec());
        assert!(
            api.create_commit(
                SCRATCH_REPOSITORY,
                "different-branch",
                &"b".repeat(40),
                "Securefix",
                additions.clone(),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            api.create_commit(
                SCRATCH_REPOSITORY,
                "scratch",
                &"a".repeat(40),
                "Securefix",
                additions,
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            api.post::<Value>(
                &format!("/repos/{SCRATCH_REPOSITORY}/git/commits"),
                &serde_json::json!({})
            )
            .is_err()
        );
    }

    #[test]
    fn native_approval_writer_allows_only_the_bound_current_head_review() {
        let mut api = native_approval_api();
        api.token = "client-read-token".into();
        api.write_token = Some("review-user-token".into());
        let path = format!("/repos/{SCRATCH_REPOSITORY}/pulls/4/reviews");
        assert!(api.require_write_target(&Method::POST, &path).is_ok());
        assert!(api.require_write_target(&Method::POST, "/graphql").is_err());
        assert!(
            api.require_write_target(&Method::POST, "/repos/other/repo/pulls/4/reviews")
                .is_err()
        );
        assert!(api.require_write_target(&Method::PATCH, &path).is_err());

        let WriteContext::NativeScratch(write) = &api.writes else {
            unreachable!();
        };
        let body = native_approval_body(
            &write.server_authority,
            &write.head_sha,
            &write.request_sha256,
        )
        .unwrap();
        assert!(validate_native_approval_body(&Method::POST, &path, write, &body,).is_ok());
        let mut stale_write = write.clone();
        stale_write.head_sha = "f".repeat(40);
        assert!(validate_native_approval_body(&Method::POST, &path, &stale_write, &body,).is_err());
        let read = api.builder(Method::GET, &path).unwrap().build().unwrap();
        let post = api.builder(Method::POST, &path).unwrap().build().unwrap();
        assert_eq!(
            read.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer client-read-token"
        );
        assert_eq!(
            post.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer review-user-token"
        );
    }

    #[test]
    fn native_merge_writer_allows_only_a_squash_merge_of_the_bound_head() {
        let mut api = native_merge_api();
        api.token = "client-read-token".into();
        api.write_token = Some("scratch-installation-token".into());
        let path = format!("/repos/{SCRATCH_REPOSITORY}/pulls/4/merge");
        assert!(api.require_write_target(&Method::PUT, &path).is_ok());
        assert!(api.require_write_target(&Method::POST, &path).is_err());
        assert!(
            api.require_write_target(&Method::PUT, "/repos/other/repo/pulls/4/merge")
                .is_err()
        );
        assert!(
            api.require_write_target(
                &Method::PUT,
                "/repos/civitaspo/testing-securefix-server/pulls/5/merge"
            )
            .is_err()
        );

        let WriteContext::NativeScratch(write) = &api.writes else {
            unreachable!();
        };
        let body = native_merge_body(&write.head_sha);
        assert!(validate_native_merge_body(&Method::PUT, &path, write, &body).is_ok());
        let mut stale_body = body.clone();
        stale_body["sha"] = serde_json::json!("f".repeat(40));
        assert!(validate_native_merge_body(&Method::PUT, &path, write, &stale_body).is_err());
        let mut merge_method = body.clone();
        merge_method["merge_method"] = serde_json::json!("merge");
        assert!(validate_native_merge_body(&Method::PUT, &path, write, &merge_method).is_err());
        assert!(validate_native_merge_body(&Method::POST, &path, write, &body).is_err());

        let request = api.builder(Method::PUT, &path).unwrap().build().unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer scratch-installation-token"
        );
    }

    #[test]
    fn native_approval_uses_writer_token_only_for_user_and_review_requests() {
        use crate::fixtures::{Fixture, Route};

        let mut api = native_approval_api();
        api.token = "reader-test-token".into();
        api.write_token = Some("writer-test-token".into());
        let pull_path = format!("/repos/{SCRATCH_REPOSITORY}/pulls/4");
        let review_path = format!("{pull_path}/reviews");
        let fixture = Fixture::new(vec![
            Route::get(
                "/user",
                serde_json::json!({"id": 11, "login": "reviewer", "type": "User"}),
            )
            .with_request_header("Authorization", "Bearer writer-test-token"),
            Route::get(&pull_path, serde_json::json!({"state": "open"}))
                .with_request_header("Authorization", "Bearer reader-test-token"),
            Route::request("POST", &review_path, 200, serde_json::json!({"ok": true}))
                .with_request_header("Authorization", "Bearer writer-test-token"),
        ]);
        api.base = fixture.base.clone();

        api.get::<Value>("/user").unwrap();
        api.get::<Value>(&pull_path).unwrap();
        api.builder(Method::POST, &review_path)
            .unwrap()
            .json(&serde_json::json!({"event": "APPROVE"}))
            .send()
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn native_server_execution_is_bound_to_the_configured_role_and_protected_revision() {
        let snapshot = NativeAuthoritySnapshot {
            instance_repository: "example-org/securefix-server".to_owned(),
            instance_id: 404,
            default_branch: "main".to_owned(),
            config_path: "securefix-server.toml".to_owned(),
            config_sha256: "b".repeat(64),
            epoch: "c".repeat(40),
            workflows: vec![NativeWorkflowAuthority {
                role: crate::instance_config::WorkflowRole::PolicyCheck,
                path: ".github/workflows/policy-check.yml".to_owned(),
                sha256: "d".repeat(64),
                pins: vec![],
            }],
        };
        let ref_path =
            "example-org/securefix-server/.github/workflows/policy-check.yml@refs/heads/main";
        let workflow_bytes = b"name: policy check\n";
        let mut snapshot = snapshot;
        snapshot.workflows[0].sha256 = crate::hex_encode(sha2::Sha256::digest(workflow_bytes));
        assert!(
            validate_native_server_execution_workflow(
                &snapshot,
                NativeScratchMode::PolicyCheck,
                ref_path,
                &"a".repeat(40),
                workflow_bytes,
            )
            .is_ok()
        );
        assert!(
            validate_native_server_execution_workflow(
                &snapshot,
                NativeScratchMode::PolicyCheck,
                "example-org/securefix-server/.github/workflows/other.yml@refs/heads/main",
                &"a".repeat(40),
                workflow_bytes,
            )
            .is_err()
        );
        assert!(
            validate_native_server_execution_workflow(
                &snapshot,
                NativeScratchMode::PolicyCheck,
                ref_path,
                "not-a-sha",
                workflow_bytes,
            )
            .is_err()
        );
        assert!(
            validate_native_server_execution_workflow(
                &snapshot,
                NativeScratchMode::PolicyCheck,
                ref_path,
                &"a".repeat(40),
                b"name: changed\n",
            )
            .is_err()
        );
        assert!(
            validate_native_server_execution_workflow(
                &snapshot,
                NativeScratchMode::Securefix,
                ref_path,
                &"a".repeat(40),
                workflow_bytes,
            )
            .is_err()
        );
    }

    #[test]
    fn native_scratch_uses_separate_client_read_and_check_write_tokens() {
        let mut api = native_scratch_api();
        api.token = "client-read-token".into();
        api.write_token = Some("check-write-token".into());
        let path = format!("/repos/{SCRATCH_REPOSITORY}/check-runs");
        let read = api.builder(Method::GET, &path).unwrap().build().unwrap();
        let graphql_read = api
            .builder(Method::POST, "/graphql")
            .unwrap()
            .build()
            .unwrap();
        let write = api.builder(Method::POST, &path).unwrap().build().unwrap();
        assert_eq!(
            read.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer client-read-token"
        );
        assert_eq!(
            graphql_read
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer client-read-token"
        );
        assert_eq!(
            write.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer check-write-token"
        );
    }

    #[test]
    fn client_workflow_revision_accepts_default_history_and_exact_pr_merge() {
        use crate::fixtures::{Fixture, Route};
        let snapshots: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native-client-base-snapshots.json"
        ))
        .unwrap();
        let snapshot = snapshots.as_array().unwrap().last().unwrap();
        let revision = snapshot["context_sha"].as_str().unwrap();
        let base = snapshot["base_sha"].as_str().unwrap();
        let head = snapshot["source_sha"].as_str().unwrap();
        let repository = "example/project";
        let compare_path = format!("/repos/{repository}/compare/{revision}...{base}");
        for status in ["ahead", "identical"] {
            let fixture = Fixture::new(vec![Route::get(
                &compare_path,
                serde_json::json!({"status":status}),
            )]);
            require_native_client_workflow_revision(&fixture.api, repository, revision, base, None)
                .unwrap();
            fixture.finish();
        }
        for status in ["ahead", "identical"] {
            let fixture = Fixture::new(vec![
                Route::get(&compare_path, serde_json::json!({"status":"behind"})),
                Route::get(
                    format!("/repos/{repository}/commits/{revision}"),
                    snapshot["workflow_commit"].clone(),
                ),
                Route::get(
                    format!("/repos/{repository}/compare/{base}...{base}"),
                    serde_json::json!({"status":status}),
                ),
            ]);
            require_native_client_workflow_revision(
                &fixture.api,
                repository,
                revision,
                base,
                Some(head),
            )
            .unwrap();
            fixture.finish();
        }
    }

    #[test]
    fn client_workflow_revision_rejects_unbound_and_non_default_pr_merges() {
        use crate::fixtures::{Fixture, Route};
        let revision = "a".repeat(40);
        let base = "b".repeat(40);
        let head = "c".repeat(40);
        let repository = "example/project";
        let compare_path = format!("/repos/{repository}/compare/{revision}...{base}");
        let fixture = Fixture::new(vec![Route::get(
            &compare_path,
            serde_json::json!({"status":"behind"}),
        )]);
        assert!(
            require_native_client_workflow_revision(
                &fixture.api,
                repository,
                &revision,
                &base,
                None,
            )
            .is_err()
        );
        fixture.finish();
        let valid = serde_json::json!({"sha":revision,"parents":[{"sha":base},{"sha":head}]});
        let mut invalid = Vec::new();
        for parents in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!([{"sha":base}]),
            serde_json::json!([{"sha":base},{"sha":head},{"sha":head}]),
            serde_json::json!([{"sha":base},{"sha":base}]),
            serde_json::json!([{"sha":head},{"sha":head}]),
            serde_json::json!([{"sha":"invalid"},{"sha":head}]),
            serde_json::json!([{}, {"sha":head}]),
        ] {
            let mut commit = valid.clone();
            commit["parents"] = parents;
            invalid.push(commit);
        }
        let mut wrong_revision = valid.clone();
        wrong_revision["sha"] = serde_json::json!(base);
        invalid.push(wrong_revision);
        for commit in invalid {
            let fixture = Fixture::new(vec![
                Route::get(&compare_path, serde_json::json!({"status":"diverged"})),
                Route::get(format!("/repos/{repository}/commits/{revision}"), commit),
            ]);
            assert!(
                require_native_client_workflow_revision(
                    &fixture.api,
                    repository,
                    &revision,
                    &base,
                    Some(&head),
                )
                .is_err()
            );
            fixture.finish();
        }
        for status in ["behind", "diverged", "unknown"] {
            let fixture = Fixture::new(vec![
                Route::get(&compare_path, serde_json::json!({"status":"behind"})),
                Route::get(
                    format!("/repos/{repository}/commits/{revision}"),
                    valid.clone(),
                ),
                Route::get(
                    format!("/repos/{repository}/compare/{base}...{base}"),
                    serde_json::json!({"status":status}),
                ),
            ]);
            assert!(
                require_native_client_workflow_revision(
                    &fixture.api,
                    repository,
                    &revision,
                    &base,
                    Some(&head),
                )
                .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn client_workflow_epoch_is_checked_independently_of_server_authority() {
        let captured = "a".repeat(40);
        assert!(require_native_client_workflow_epoch_unchanged(&captured, &captured).is_ok());
        assert!(
            require_native_client_workflow_epoch_unchanged(&captured, &"b".repeat(40)).is_err()
        );
    }

    #[test]
    fn authority_epochs_ignore_unrelated_and_second_parent_changes_but_reject_reverts() {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        let global_config = directory.path().join("global-config");
        let hooks = directory.path().join("empty-hooks");
        std::fs::write(&global_config, []).unwrap();
        std::fs::create_dir(&hooks).unwrap();
        test_git(
            directory.path(),
            &[
                "init",
                "--quiet",
                "--initial-branch=main",
                repository.to_str().unwrap(),
            ],
        );

        let initial_file = repository.join(TEST_CONFIG_PATH);
        std::fs::write(&initial_file, "[instance]\nname = \"old\"\n").unwrap();
        let workflow_file = repository.join(TEST_WORKFLOW_PATH);
        std::fs::create_dir_all(workflow_file.parent().unwrap()).unwrap();
        std::fs::write(&workflow_file, "uses: securefix@old\n").unwrap();
        test_git(&repository, &["add", "."]);
        test_git(
            &repository,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Securefix Test",
                "-c",
                "user.email=securefix-test@example.invalid",
                "commit",
                "-m",
                "initial authority",
            ],
        );
        let initial = String::from_utf8(test_git(&repository, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();

        test_git(&repository, &["checkout", "-b", "second-parent"]);
        let second_parent = test_commit_file(
            &repository,
            TEST_CONFIG_PATH,
            "[instance]\nname = \"second parent\"\n",
            "change config on second parent",
        );
        test_git(&repository, &["checkout", "main"]);
        let workflow_change = test_commit_file(
            &repository,
            TEST_WORKFLOW_PATH,
            "uses: securefix@changed\n",
            "change caller workflow",
        );
        test_git(
            &repository,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Securefix Test",
                "-c",
                "user.email=securefix-test@example.invalid",
                "merge",
                "--no-ff",
                "-s",
                "ours",
                "second-parent",
                "-m",
                "merge second parent without its config tree",
            ],
        );
        let merged = String::from_utf8(test_git(&repository, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        assert_ne!(second_parent, initial);
        let baseline = test_authority_snapshot(&repository, &merged, &global_config, &hooks);
        assert_eq!(baseline.epoch, workflow_change);
        assert_ne!(baseline.epoch, initial);

        test_commit_file(
            &repository,
            "src/main.rs",
            "fn main() {}\n",
            "unrelated source change",
        );
        test_commit_file(
            &repository,
            "docs/README.md",
            "Unrelated documentation.\n",
            "unrelated documentation change",
        );
        let unrelated_head = String::from_utf8(test_git(&repository, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        let after_unrelated =
            test_authority_snapshot(&repository, &unrelated_head, &global_config, &hooks);
        assert_eq!(baseline, after_unrelated);
        assert!(require_native_authority_unchanged(&baseline, &after_unrelated).is_ok());
        assert!(
            git_output(
                &repository,
                &["rev-list", "--first-parent", "--parents", &unrelated_head],
                &global_config,
                &hooks,
                None,
                8,
                Instant::now() + MAX_GIT_OPERATION_TIME,
            )
            .is_err()
        );

        test_commit_file(
            &repository,
            TEST_CONFIG_PATH,
            "[instance]\nname = \"temporary\"\n",
            "change config",
        );
        let config_revert = test_commit_file(
            &repository,
            TEST_CONFIG_PATH,
            "[instance]\nname = \"old\"\n",
            "revert config",
        );
        let after_config_revert =
            test_authority_snapshot(&repository, &config_revert, &global_config, &hooks);
        assert_eq!(baseline.config_sha256, after_config_revert.config_sha256);
        assert_ne!(baseline.epoch, after_config_revert.epoch);
        assert_eq!(
            baseline.workflows[0].sha256,
            after_config_revert.workflows[0].sha256
        );
        assert!(require_native_authority_unchanged(&baseline, &after_config_revert).is_err());

        test_commit_file(
            &repository,
            TEST_WORKFLOW_PATH,
            "uses: securefix@temporary\n",
            "change caller pin",
        );
        let workflow_revert = test_commit_file(
            &repository,
            TEST_WORKFLOW_PATH,
            "uses: securefix@changed\n",
            "revert caller pin",
        );
        let after_workflow_revert =
            test_authority_snapshot(&repository, &workflow_revert, &global_config, &hooks);
        assert_ne!(after_config_revert.epoch, after_workflow_revert.epoch);
        assert_eq!(
            baseline.workflows[0].sha256,
            after_workflow_revert.workflows[0].sha256
        );
        assert!(
            require_native_authority_unchanged(&after_config_revert, &after_workflow_revert)
                .is_err()
        );
    }

    #[test]
    fn native_scratch_check_body_is_bound_to_the_verified_request() {
        let path = format!("/repos/{SCRATCH_REPOSITORY}/check-runs");
        let head_sha = "b".repeat(40);
        let request_sha = "c".repeat(64);
        let body = native_policy_check_body(&head_sha, &request_sha);
        assert!(
            validate_native_scratch_check_body(
                &Method::POST,
                &path,
                SCRATCH_REPOSITORY,
                &head_sha,
                &request_sha,
                &body,
            )
            .is_ok()
        );
        let mut forged = body;
        forged["output"]["summary"] = "a different claim".into();
        assert!(
            validate_native_scratch_check_body(
                &Method::POST,
                &path,
                SCRATCH_REPOSITORY,
                &head_sha,
                &request_sha,
                &forged,
            )
            .is_err()
        );
    }

    #[test]
    fn native_instance_policy_check_id_binds_authority_and_request() {
        let request_sha = "c".repeat(64);
        let authority =
            instance_authority_fixture(include_bytes!("../tests/fixtures/instance-config.toml"))
                .authority;
        let head_sha = "b".repeat(40);
        let id =
            native_instance_policy_check_external_id(&authority, &head_sha, &request_sha).unwrap();
        assert_eq!(
            id,
            format!(
                "native:v1:{head_sha}:{}:{request_sha}",
                native_authority_sha256(&authority).unwrap()
            )
        );
        let parsed = parse_native_instance_policy_check_external_id(&id).unwrap();
        assert_eq!(parsed.head_sha, head_sha);
        assert_eq!(
            parsed.authority_sha256,
            native_authority_sha256(&authority).unwrap()
        );
        assert_eq!(parsed.request_sha256, request_sha);

        let mut changed_authority = authority.clone();
        changed_authority.epoch = "f".repeat(40);
        assert_ne!(
            native_instance_policy_check_external_id(&changed_authority, &head_sha, &request_sha)
                .unwrap(),
            id
        );
        assert_ne!(
            native_instance_policy_check_external_id(&authority, &head_sha, &"d".repeat(64))
                .unwrap(),
            id
        );
        assert!(
            native_instance_policy_check_external_id(&authority, &head_sha, "not-a-digest")
                .is_err()
        );

        let body = native_instance_policy_check_body(&authority, &head_sha, &request_sha).unwrap();
        assert_eq!(body["external_id"], id);
        assert_ne!(
            native_policy_check_body(&head_sha, &request_sha)["external_id"],
            body["external_id"]
        );
        assert!(parse_native_instance_policy_check_external_id("native:v1:bad:bad:bad").is_err());
    }

    #[test]
    fn native_instance_command_must_be_newer_than_its_authority_epoch() {
        let epoch = chrono::DateTime::parse_from_rfc3339("2026-10-22T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let newer = chrono::DateTime::parse_from_rfc3339("2026-10-22T08:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let equal = epoch;
        let older = chrono::DateTime::parse_from_rfc3339("2026-10-22T07:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert!(require_native_instance_command_after_time(newer, epoch).is_ok());
        assert!(require_native_instance_command_after_time(equal, epoch).is_err());
        assert!(require_native_instance_command_after_time(older, epoch).is_err());
    }

    #[test]
    fn server_workflow_roles_record_only_full_sha_remote_pins() {
        let sha = "a".repeat(40);
        let workflow =
            format!("jobs:\n  build:\n    uses: owner/server/.github/workflows/build.yml@{sha}\n");
        let pins = workflow_uses_pins(workflow.as_bytes()).unwrap();
        assert!(pins.contains(&format!("owner/server/.github/workflows/build.yml@{sha}")));
        assert!(
            workflow_uses_pins(b"jobs:\n  build:\n    uses: $/.github/actions/install-cli\n")
                .is_err()
        );
        assert!(
            workflow_uses_pins(
                b"jobs:\n  build:\n    uses: owner/server/.github/workflows/build.yml@main\n"
            )
            .is_err()
        );
    }

    #[test]
    fn bounds_downloads_and_rejects_external_paths() {
        assert!(bounded_read(&b"12345"[..], 4).is_err());
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        for path in [
            "//evil.example/x",
            "https://evil.example",
            "/x\nInjected: x",
        ] {
            assert!(api.url(path).is_err());
        }
    }

    #[test]
    fn isolated_normal_cleanup_only_deletes_the_current_testing_server_label() {
        let mut trusted = crate::config::trusted().unwrap().clone();
        trusted.deployment.workflow_prefix = "testing-".into();
        trusted.deployment.control_repository = Some(trusted.deployment.integration.clone());
        let server = &trusted.deployment.server;
        for (label, run) in [
            ("testing-approve-request-11", "11"),
            ("testing-approve-request-renovate-12", "12"),
            ("testing-merge-request-13", "13"),
            ("testing-policy-request-14", "14"),
            ("testing-release-request-15", "15"),
            ("testing-securefix-16-012345abcdef", "16"),
        ] {
            let payload = serde_json::json!({
                "action":"created",
                "repository":{"id":server.id,"full_name":server.repository},
                "sender":{"id":trusted.client_bot_id,"type":"Bot"},
                "label":{"name":label,"description":format!("{}/{run}", trusted.deployment.integration.repository)}
            });
            let path = format!("/repos/{}/labels/{label}", server.repository);
            assert!(
                testing_label_cleanup_matches(&trusted, &Method::DELETE, &path, &payload).unwrap()
            );
            assert!(
                !testing_label_cleanup_matches(&trusted, &Method::POST, &path, &payload).unwrap()
            );
            assert!(
                !testing_label_cleanup_matches(
                    &trusted,
                    &Method::DELETE,
                    &format!("/repos/other/server/labels/{label}"),
                    &payload,
                )
                .unwrap()
            );
        }

        let other_caller = serde_json::json!({
            "action":"created",
            "repository":{"id":server.id,"full_name":server.repository},
            "sender":{"id":trusted.client_bot_id,"type":"Bot"},
            "label":{"name":"testing-merge-request-13","description":"civitaspo/production/13"}
        });
        assert!(
            !testing_label_cleanup_matches(
                &trusted,
                &Method::DELETE,
                &format!(
                    "/repos/{}/labels/testing-merge-request-13",
                    server.repository
                ),
                &other_caller,
            )
            .unwrap()
        );
        let production_label = serde_json::json!({
            "action":"created",
            "repository":{"id":server.id,"full_name":server.repository},
            "sender":{"id":trusted.client_bot_id,"type":"Bot"},
            "label":{"name":"merge-request-13","description":"civitaspo/example/13"}
        });
        assert!(
            !testing_label_cleanup_matches(
                &trusted,
                &Method::DELETE,
                &format!("/repos/{}/labels/merge-request-13", server.repository),
                &production_label,
            )
            .unwrap()
        );
    }
    #[test]
    fn release_assets_use_binary_accept_and_actions_artifacts_use_json_accept() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::raw(
                "GET",
                "/repos/example/repo/releases/assets/7",
                200,
                vec![0, 255, 1],
            )
            .with_request_header("Accept", "application/octet-stream"),
            Route::raw(
                "GET",
                "/repos/example/repo/actions/artifacts/8/zip",
                200,
                vec![0, 255, 2],
            )
            .with_request_header("Accept", "application/vnd.github+json"),
        ]);
        assert_eq!(
            fixture
                .api
                .download("/repos/example/repo/releases/assets/7", 10)
                .unwrap(),
            vec![0, 255, 1]
        );
        assert_eq!(
            fixture
                .api
                .download("/repos/example/repo/actions/artifacts/8/zip", 10)
                .unwrap(),
            vec![0, 255, 2]
        );
        fixture.finish();
    }
    #[test]
    fn graphql_only_accepts_explicit_read_operations() {
        assert!(read_only_query(
            "query($number:Int!){repository{pullRequest(number:$number){reviewDecision}}}"
        ));
        for query in [
            "mutation { mergePullRequest }",
            "{ viewer { login } }",
            "query {viewer{login}} mutation {mergePullRequest}",
        ] {
            assert!(!read_only_query(query));
        }
    }
    #[test]
    fn scratch_auto_merge_binds_the_graphql_mutation_to_the_accepted_head() {
        use crate::fixtures::{Fixture, Route};
        let head = "b".repeat(40);
        let query = "mutation($input:EnablePullRequestAutoMergeInput!){enablePullRequestAutoMerge(input:$input){pullRequest{id autoMergeRequest{mergeMethod}}}}";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{SCRATCH_REPOSITORY}/pulls/7"),
                serde_json::json!({
                    "number":7,"state":"open","node_id":"PR_fixture",
                    "base":{"repo":{"full_name":SCRATCH_REPOSITORY}},
                    "head":{"repo":{"full_name":SCRATCH_REPOSITORY},"sha":head}
                }),
            ),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({
                    "data":{"enablePullRequestAutoMerge":{"pullRequest":{
                        "id":"PR_fixture","autoMergeRequest":{"mergeMethod":"SQUASH"}
                    }}}
                }),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{
                    "pullRequestId":"PR_fixture","expectedHeadOid":head,"mergeMethod":"SQUASH"
                }}
            })),
        ]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        fixture
            .api
            .enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &head)
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn scratch_auto_merge_rejects_changed_heads_and_other_write_contexts() {
        use crate::fixtures::{Fixture, Route};
        let mut fixture = Fixture::new(vec![Route::get(
            format!("/repos/{SCRATCH_REPOSITORY}/pulls/7"),
            serde_json::json!({
                "number":7,"state":"open","node_id":"PR_fixture",
                "base":{"repo":{"full_name":SCRATCH_REPOSITORY}},
                "head":{"repo":{"full_name":SCRATCH_REPOSITORY},"sha":"c".repeat(40)}
            }),
        )]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        assert!(
            fixture
                .api
                .enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &"b".repeat(40))
                .is_err()
        );
        assert!(
            fixture
                .api
                .enable_scratch_auto_merge("civitaspo/securefix-server", 7, &"b".repeat(40))
                .is_err()
        );
        fixture.finish();
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        assert!(
            api.enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &"b".repeat(40))
                .is_err()
        );
    }

    #[test]
    fn policy_comment_minimization_is_bound_to_the_configured_bot_pr_and_runtime() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let node_id = "IC_fixture";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":node_id,"issue_url":issue_url,
                    "body":format!("{POLICY_FAILURE_COMMENT_MARKER}\nPolicy check failed."),
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            })),
        ]);
        fixture.api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: Some(Fixture::control_revision().identity().unwrap()),
        };
        fixture
            .api
            .minimize_policy_comment(repository, number, comment_id)
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn policy_comment_minimization_rejects_unrelated_or_unowned_comments_before_writing() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let valid_user = serde_json::json!({
            "id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"
        });
        let invalid_comments = [
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,"body":format!("other {POLICY_FAILURE_COMMENT_MARKER}"),"user":valid_user}),
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,"body":POLICY_FAILURE_COMMENT_MARKER,"user":{"id":policy.owner_id,"login":"owner","type":"User"}}),
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":"https://api.github.com/repos/civitaspo/other/issues/17","body":POLICY_FAILURE_COMMENT_MARKER,"user":valid_user}),
        ];
        for comment in invalid_comments {
            let mut fixture = Fixture::new(vec![Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                comment,
            )]);
            fixture.api.writes = WriteContext::Production {
                revision: Some("a".repeat(40)),
                control_id: Some(Fixture::control_revision().identity().unwrap()),
            };
            assert!(
                fixture
                    .api
                    .minimize_policy_comment(repository, number, comment_id)
                    .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn policy_comment_minimization_rejects_stale_runtime_before_graphql_mutation() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,
                    "body":POLICY_FAILURE_COMMENT_MARKER,
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::active_control(&crate::control::ControlRevision {
                source_sha: "b".repeat(40),
                ..Fixture::control_revision()
            }),
        ]);
        fixture.api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: Some(Fixture::control_revision().identity().unwrap()),
        };
        assert!(
            fixture
                .api
                .minimize_policy_comment(repository, number, comment_id)
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn scratch_policy_comment_minimization_is_confined_to_the_scratch_repository() {
        use crate::fixtures::{Fixture, Route};
        let repository = SCRATCH_REPOSITORY;
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let node_id = "IC_scratch";
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":node_id,"issue_url":issue_url,
                    "body":POLICY_FAILURE_COMMENT_MARKER,
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            })),
        ]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        fixture
            .api
            .minimize_policy_comment(repository, number, comment_id)
            .unwrap();
        assert!(
            fixture
                .api
                .minimize_policy_comment("civitaspo/securefix-server", 17, 23)
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn client_can_only_create_request_labels_without_a_server_runtime_epoch() {
        use crate::fixtures::{Fixture, Route};
        let server = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let path = format!("/repos/{server}/labels");
        let body = serde_json::json!({"name":"securefix-fixture","description":"owner/source/123"});
        let mut fixture = Fixture::new(vec![
            Route::request("POST", &path, 201, body.clone()).with_request_body(body.clone()),
        ]);
        fixture.api.writes = WriteContext::ClientLabel {
            server: server.clone(),
        };
        assert_eq!(fixture.api.post::<Value>(&path, &body).unwrap(), body);
        for target in [
            "/graphql",
            "/repos/other/server/labels",
            "/repos/owner/source/pulls",
            "/repos/owner/source/git/refs",
        ] {
            assert!(fixture.api.post::<Value>(target, &body).is_err());
        }
        assert!(fixture.api.patch::<Value>(&path, &body).is_err());
        assert!(fixture.api.delete(&path).is_err());
        assert!(fixture.api.get::<Value>("/user").is_err());
        assert!(
            fixture
                .api
                .post::<Value>(
                    "/graphql",
                    &serde_json::json!({"query":"query { viewer { login } }"})
                )
                .is_err()
        );
        fixture.finish();
    }

    fn native_client_label_authority() -> NativeAuthoritySnapshot {
        NativeAuthoritySnapshot {
            instance_repository: "example-org/server".to_owned(),
            instance_id: 404,
            default_branch: "main".to_owned(),
            config_path: ".securefix/instance.toml".to_owned(),
            config_sha256: "a".repeat(64),
            epoch: "b".repeat(40),
            workflows: vec![NativeWorkflowAuthority {
                role: crate::instance_config::WorkflowRole::PolicyCheck,
                path: ".github/workflows/policy-check.yml".to_owned(),
                sha256: "c".repeat(64),
                pins: Vec::new(),
            }],
        }
    }

    fn native_release_write_fixture() -> NativeReleaseWrite {
        let config_bytes = String::from_utf8(
            include_bytes!("../tests/fixtures/instance-config.toml").to_vec(),
        )
        .unwrap()
        .replace(
            "release = \"github-release\"\nprotect_tags = true",
            "release = \"github-release\"\nnative_binaries = [{ target = \"x86_64-unknown-linux-musl\", runner = \"ubuntu-24.04\" }]\nprotect_tags = true",
        )
        .into_bytes();
        let config = crate::instance_config::InstanceConfig::parse(&config_bytes).unwrap();
        let mut instance = instance_authority_fixture(&config_bytes);
        let server_release_sha = "f".repeat(40);
        let client_release_tag_sha = "1".repeat(40);
        instance.authority.workflows.push(NativeWorkflowAuthority {
            role: crate::instance_config::WorkflowRole::Release,
            path: config.workflow_roles[&crate::instance_config::WorkflowRole::Release].clone(),
            sha256: "e".repeat(64),
            pins: vec![format!(
                "{}/.github/workflows/reusable-server-release.yml@{server_release_sha}",
                config.acceptable_clients.repository
            )],
        });
        let client_package = crate::package::native_client_package_api_test_fixture();
        let client_package = native_client_package_identity(&config, &client_package).unwrap();
        let asset = NativeReleaseAsset {
            name: "project-x86_64-unknown-linux-musl".to_owned(),
            size: 16,
            sha256: "d".repeat(64),
            content_type: "application/octet-stream".to_owned(),
        };
        let release_manifest = crate::release_manifest::ReleaseManifestV2 {
            schema_version: 2,
            repository: "example-org/project".to_owned(),
            source_run_id: crate::release_manifest::RunId(42),
            source_run_sha: crate::release_manifest::CommitSha::parse(&"c".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: crate::release_manifest::CommitSha::parse(&client_release_tag_sha)
                .unwrap(),
            release_pr_number: 88,
            release_pr_sha: crate::release_manifest::CommitSha::parse(&"b".repeat(40)).unwrap(),
            tag: crate::release_manifest::ReleaseTag::parse("v1.2.3").unwrap(),
            package_version: None,
            artifact_id: None,
        };
        let release_manifest_bytes = serde_json::to_vec(&release_manifest).unwrap();
        NativeReleaseWrite {
            instance_repository: config.instance.repository.clone(),
            instance_id: config.instance.id,
            default_branch: config.instance.default_branch.clone(),
            config_path: TEST_CONFIG_PATH.to_owned(),
            config_bytes,
            server_authority: instance.authority,
            target_repository: "example-org/project".to_owned(),
            target_id: 987_654,
            target_default_branch: "main".to_owned(),
            release_pr_number: 88,
            release_pr_head_sha: "a".repeat(40),
            release_pr_merge_sha: "b".repeat(40),
            tag: "v1.2.3".to_owned(),
            release_source_run_id: 42,
            release_source_run_attempt: 1,
            release_source_run_sha: "c".repeat(40),
            release_source_workflow_sha: client_release_tag_sha,
            release_manifest_sha256: crate::hex_encode(sha2::Sha256::digest(
                &release_manifest_bytes,
            )),
            release_manifest,
            release_manifest_bytes,
            client_package,
            assets: vec![asset.clone()],
            native_assets: vec![asset],
            release_id: None,
        }
    }

    #[test]
    fn native_release_target_requires_configured_capability_and_pinned_producer() {
        let write = native_release_write_fixture();
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes).unwrap();
        let instance = NativeServerInstanceAuthority {
            config: config.clone(),
            config_bytes: write.config_bytes.clone(),
            authority: write.server_authority.clone(),
        };
        let client_package = crate::package::native_client_package_api_test_fixture();
        let target = native_release_target(&write, &instance, &client_package);
        assert!(validate_native_release_target(&config, &write.server_authority, &target).is_ok());
        assert!(validate_native_release_saved(&config, &write.server_authority, &write).is_ok());

        let mut changed_manifest_bytes = write.clone();
        changed_manifest_bytes.release_manifest_bytes.push(b' ');
        assert!(
            validate_native_release_saved(
                &config,
                &write.server_authority,
                &changed_manifest_bytes
            )
            .is_err()
        );

        let mut unsupported_manifest = write.clone();
        unsupported_manifest.release_manifest.schema_version = 1;
        unsupported_manifest.release_manifest_bytes =
            serde_json::to_vec(&unsupported_manifest.release_manifest).unwrap();
        unsupported_manifest.release_manifest_sha256 = crate::hex_encode(sha2::Sha256::digest(
            &unsupported_manifest.release_manifest_bytes,
        ));
        assert!(
            validate_native_release_saved(&config, &write.server_authority, &unsupported_manifest)
                .is_err()
        );

        let mut wrong_id = write.clone();
        wrong_id.target_id += 1;
        let target = native_release_target(&wrong_id, &instance, &client_package);
        assert!(validate_native_release_target(&config, &write.server_authority, &target).is_err());

        let mut mismatched_client_revision = write.clone();
        mismatched_client_revision.release_source_workflow_sha = "9".repeat(40);
        let target = native_release_target(&mismatched_client_revision, &instance, &client_package);
        assert!(validate_native_release_target(&config, &write.server_authority, &target).is_err());

        let mut invalid_asset = write.clone();
        invalid_asset.assets[0].sha256 = "not-a-digest".to_owned();
        invalid_asset.native_assets[0].sha256 = "not-a-digest".to_owned();
        let target = native_release_target(&invalid_asset, &instance, &client_package);
        assert!(validate_native_release_target(&config, &write.server_authority, &target).is_err());

        let mut missing_native_target = write.clone();
        missing_native_target.assets.clear();
        missing_native_target.native_assets.clear();
        let target = native_release_target(&missing_native_target, &instance, &client_package);
        assert!(validate_native_release_target(&config, &write.server_authority, &target).is_err());
    }

    #[test]
    fn native_release_scratch_package_keeps_distributor_and_destination_separate() {
        let mut write = native_release_write_fixture();
        let mut config =
            crate::instance_config::InstanceConfig::parse(&write.config_bytes).unwrap();
        let client = crate::package::native_client_package_api_scratch_test_fixture();
        assert!(native_client_package_identity(&config, &client).is_err());
        config.scratch_package_repository = Some(crate::config::Repository {
            repository: "example-org/package-scratch".to_owned(),
            id: 987_655,
            default_branch: "main".to_owned(),
        });
        let identity = native_client_package_identity(&config, &client).unwrap();
        assert_eq!(
            identity.distributor_repository,
            config.acceptable_clients.repository
        );
        assert_eq!(identity.release_repository, "example-org/package-scratch");
        assert_ne!(identity.publisher_branch, identity.producer_branch);
        validate_native_client_package_snapshot(&config, &identity).unwrap();
        write.client_package = identity.clone();
        let mut tampered = identity;
        tampered.release_repository_id += 1;
        assert!(validate_native_client_package_snapshot(&config, &tampered).is_err());
        config.scratch_package_repository = None;
        assert!(validate_native_client_package_snapshot(&config, &write.client_package).is_err());
    }

    #[test]
    fn native_release_draft_reads_use_only_the_isolated_publisher_token() {
        use crate::fixtures::{Fixture, Route};
        let mut write = native_release_write_fixture();
        write.release_id = Some(42);
        let release_path = format!("/repos/{}/releases/42", write.target_repository);
        let tag_path = format!(
            "/repos/{}/releases/tags/{}",
            write.target_repository, write.tag
        );
        let pull_path = format!(
            "/repos/{}/pulls/{}",
            write.target_repository, write.release_pr_number
        );
        let draft = serde_json::json!({"id":42,"draft":true,"tag_name":write.tag,
            "name":write.tag,"target_commitish":write.target_default_branch,"prerelease":false});
        let fixture = Fixture::new(vec![
            Route::get(&release_path, draft)
                .with_request_header("Authorization", "Bearer publisher-token"),
            Route::request(
                "GET",
                &tag_path,
                404,
                serde_json::json!({"message":"Not Found"}),
            )
            .with_request_header("Authorization", "Bearer publisher-token"),
            Route::get(
                &pull_path,
                serde_json::json!({"number":write.release_pr_number}),
            )
            .with_request_header("Authorization", "Bearer reader-token"),
        ]);
        let mut api = GitHub::new(&fixture.base, "reader-token".to_owned()).unwrap();
        api.write_token = Some("publisher-token".to_owned());
        api.writes = WriteContext::NativeRelease(Box::new(write.clone()));
        api.require_native_release_identity_current(&write).unwrap();
        api.get::<Value>(&pull_path).unwrap();
        fixture.finish();
    }

    #[test]
    fn native_release_identity_rejects_missing_replaced_and_unpublished_results_without_writes() {
        use crate::fixtures::{Fixture, Route};
        for case in [
            "missing",
            "wrong_tag",
            "collision",
            "published_missing",
            "published_ok",
        ] {
            let mut write = native_release_write_fixture();
            write.release_id = Some(42);
            let release_path = format!("/repos/{}/releases/42", write.target_repository);
            let tag_path = format!(
                "/repos/{}/releases/tags/{}",
                write.target_repository, write.tag
            );
            let mut release = serde_json::json!({"id":42,"draft":true,"tag_name":write.tag,
                "name":write.tag,"target_commitish":write.target_default_branch,"prerelease":false});
            if case == "wrong_tag" {
                release["tag_name"] = serde_json::json!("v9.9.9");
            }
            if case.starts_with("published_") {
                release["draft"] = serde_json::json!(false);
                release["immutable"] = serde_json::json!(true);
            }
            let mut routes = vec![
                if case == "missing" {
                    Route::request(
                        "GET",
                        &release_path,
                        404,
                        serde_json::json!({"message":"Not Found"}),
                    )
                } else {
                    Route::get(&release_path, release)
                }
                .with_request_header("Authorization", "Bearer publisher-token"),
            ];
            if case == "collision" {
                routes.push(Route::get(
                    &tag_path,
                    serde_json::json!({"id":99,"tag_name":write.tag}),
                ));
            }
            if case == "published_missing" {
                routes.push(Route::request(
                    "GET",
                    &tag_path,
                    404,
                    serde_json::json!({"message":"Not Found"}),
                ));
            }
            if case == "published_ok" {
                routes.push(Route::get(
                    &tag_path,
                    serde_json::json!({"id":42,"tag_name":write.tag}),
                ));
            }
            let fixture = Fixture::new(routes);
            let mut api = GitHub::new(&fixture.base, "reader-token".to_owned()).unwrap();
            api.write_token = Some("publisher-token".to_owned());
            api.writes = WriteContext::NativeRelease(Box::new(write.clone()));
            assert_eq!(
                api.require_native_release_identity_current(&write).is_ok(),
                case == "published_ok",
                "{case}"
            );
            fixture.finish();
        }
    }

    #[test]
    fn native_release_cleanup_is_bound_to_the_exact_authenticated_label() {
        let write = native_release_write_fixture();
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes).unwrap();
        let label = "securefix-native-release-42";
        let event = serde_json::json!({
            "action":"created",
            "repository":{"id":config.instance.id,"full_name":config.instance.repository},
            "sender":{"id":config.identities.client_bot.id,"type":"Bot"},
            "label":{"name":label,"description":"example-org/project/42"}
        });
        validate_native_release_cleanup_event(&config, label, &event).unwrap();
        for pointer in [
            "/action",
            "/repository/full_name",
            "/repository/id",
            "/sender/id",
            "/sender/type",
            "/label/name",
            "/label/description",
        ] {
            let mut changed = event.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::json!("untrusted");
            assert!(
                validate_native_release_cleanup_event(&config, label, &changed).is_err(),
                "{pointer}"
            );
        }
        let instance = NativeServerInstanceAuthority {
            config,
            config_bytes: write.config_bytes,
            authority: write.server_authority,
        };
        let mut api = GitHub::new("https://api.github.com", "unused".to_owned()).unwrap();
        let expected = format!(
            "/repos/{}/labels/{label}",
            instance.config.instance.repository
        );
        api.writes = WriteContext::NativeReleaseCleanup {
            instance: Box::new(instance),
            label: label.to_owned(),
        };
        api.require_write_target(&Method::DELETE, &expected)
            .unwrap();
        assert!(api.require_write_target(&Method::POST, &expected).is_err());
        assert!(
            api.require_write_target(
                &Method::DELETE,
                "/repos/example-org/project/labels/securefix-native-release-42"
            )
            .is_err()
        );
        assert!(
            api.require_write_target(&Method::DELETE, &expected.replace("42", "43"))
                .is_err()
        );
    }

    #[test]
    fn native_release_saved_revalidation_keeps_instance_distributor_and_client_revisions_separate()
    {
        let write = native_release_write_fixture();
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes).unwrap();
        assert_ne!(
            write.instance_repository,
            write.client_package.distributor_repository
        );
        assert_ne!(
            write.target_repository,
            write.client_package.distributor_repository
        );
        assert_ne!(write.instance_repository, write.target_repository);
        assert_ne!(
            native_server_release_pin(&write.server_authority).unwrap(),
            write.release_source_workflow_sha
        );
        assert_eq!(
            write.release_source_workflow_sha,
            write.client_package.implementation_sha
        );
        assert_ne!(
            write.client_package.binary_source_sha,
            write.client_package.implementation_sha
        );
        assert!(validate_native_release_saved(&config, &write.server_authority, &write).is_ok());

        let reference = format!(
            "{}/.github/workflows/reusable-release-tag.yml@{}",
            config.acceptable_clients.repository, write.release_source_workflow_sha
        );
        let source_run = serde_json::json!({
            "id":write.release_source_run_id,
            "run_attempt":write.release_source_run_attempt,
            "status":"completed",
            "conclusion":"success",
            "head_sha":write.release_source_run_sha,
            "repository":{"id":write.target_id,"full_name":write.target_repository},
            "head_repository":{"id":write.target_id,"full_name":write.target_repository},
            "referenced_workflows":[{"path":reference,"sha":write.release_source_workflow_sha}]
        });
        assert!(validate_native_release_source_run(&config, &write, &source_run).is_ok());
        let mut wrong_reference = source_run.clone();
        wrong_reference["referenced_workflows"][0]["path"] = serde_json::json!(format!(
            "{}/.github/workflows/reusable-release-tag.yml@{}",
            write.instance_repository, write.release_source_workflow_sha
        ));
        assert!(validate_native_release_source_run(&config, &write, &wrong_reference).is_err());

        let package = &write.client_package;
        let repository = serde_json::json!({
            "id":package.distributor_id,
            "full_name":package.distributor_repository,
            "default_branch":package.publisher_branch
        });
        let release = serde_json::json!({
            "id":package.release_id,
            "tag_name":package.release_tag,
            "target_commitish":package.binary_source_sha,
            "draft":false,
            "immutable":true,
            "prerelease":false,
            "assets":[{
                "id":package.asset_id,
                "name":package.asset_name,
                "state":"uploaded",
                "size":package.asset_size,
                "digest":format!("sha256:{}",package.asset_sha256)
            }]
        });
        let tag_ref = serde_json::json!({
            "ref":format!("refs/tags/{}",package.release_tag),
            "object":{"type":"commit","sha":package.binary_source_sha}
        });
        let publisher_run = serde_json::json!({
            "id":package.publisher_run_id,
            "run_attempt":package.publisher_run_attempt,
            "repository":{"id":package.distributor_id,"full_name":package.distributor_repository},
            "head_repository":{"id":package.distributor_id},
            "path":package.publisher_workflow,
            "event":"workflow_dispatch",
            "head_branch":package.publisher_branch,
            "head_sha":package.publisher_sha,
            "status":"completed",
            "conclusion":"success"
        });
        let producer_run = serde_json::json!({
            "id":package.producer_run_id,
            "run_attempt":package.producer_run_attempt,
            "repository":{"id":package.distributor_id,"full_name":package.distributor_repository},
            "head_repository":{"id":package.distributor_id},
            "path":package.producer_workflow,
            "event":"workflow_dispatch",
            "head_branch":package.producer_branch,
            "head_sha":package.binary_source_sha,
            "status":"completed",
            "conclusion":"success"
        });
        assert!(
            validate_native_client_package_remote_identity(
                package,
                &repository,
                &release,
                &tag_ref,
                &publisher_run,
                &producer_run,
            )
            .is_ok()
        );
        let mut wrong_package_run = publisher_run.clone();
        wrong_package_run["repository"]["full_name"] = serde_json::json!(write.target_repository);
        assert!(
            validate_native_client_package_remote_identity(
                package,
                &repository,
                &release,
                &tag_ref,
                &wrong_package_run,
                &producer_run,
            )
            .is_err()
        );
    }

    #[test]
    fn native_release_revalidates_distributor_with_server_reader_token() {
        use crate::fixtures::{Fixture, Route};

        let write = native_release_write_fixture();
        let config = crate::instance_config::InstanceConfig::parse(&write.config_bytes).unwrap();
        let package = &write.client_package;
        let authorization = ("Authorization", "Bearer server-reader-token");
        let repository_path = format!("/repos/{}", package.distributor_repository);
        let release_path = format!(
            "/repos/{}/releases/{}",
            package.distributor_repository, package.release_id
        );
        let tag_path = format!(
            "/repos/{}/git/ref/tags/{}",
            package.distributor_repository, package.release_tag
        );
        let run_path = format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            package.distributor_repository, package.publisher_run_id, package.publisher_run_attempt
        );
        let producer_run_path = format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            package.distributor_repository, package.producer_run_id, package.producer_run_attempt
        );
        let fixture = Fixture::new(vec![
            Route::get(
                repository_path,
                serde_json::json!({
                    "id":package.distributor_id,
                    "full_name":package.distributor_repository,
                    "default_branch":package.publisher_branch
                }),
            )
            .with_request_header(authorization.0, authorization.1),
            Route::get(
                release_path,
                serde_json::json!({
                    "id":package.release_id,
                    "tag_name":package.release_tag,
                    "target_commitish":package.binary_source_sha,
                    "draft":false,
                    "immutable":true,
                    "prerelease":false,
                    "assets":[{
                        "id":package.asset_id,
                        "name":package.asset_name,
                        "state":"uploaded",
                        "size":package.asset_size,
                        "digest":format!("sha256:{}", package.asset_sha256)
                    }]
                }),
            )
            .with_request_header(authorization.0, authorization.1),
            Route::get(
                tag_path,
                serde_json::json!({
                    "ref":format!("refs/tags/{}", package.release_tag),
                    "object":{"type":"commit","sha":package.binary_source_sha}
                }),
            )
            .with_request_header(authorization.0, authorization.1),
            Route::get(
                run_path,
                serde_json::json!({
                    "id":package.publisher_run_id,
                    "run_attempt":package.publisher_run_attempt,
                    "repository":{"id":package.distributor_id,"full_name":package.distributor_repository},
                    "head_repository":{"id":package.distributor_id},
                    "path":package.publisher_workflow,
                    "event":"workflow_dispatch",
                    "head_branch":package.publisher_branch,
                    "head_sha":package.publisher_sha,
                    "status":"completed",
                    "conclusion":"success"
                }),
            )
            .with_request_header(authorization.0, authorization.1),
            Route::get(
                producer_run_path,
                serde_json::json!({
                    "id":package.producer_run_id,
                    "run_attempt":package.producer_run_attempt,
                    "repository":{"id":package.distributor_id,"full_name":package.distributor_repository},
                    "head_repository":{"id":package.distributor_id},
                    "path":package.producer_workflow,
                    "event":"workflow_dispatch",
                    "head_branch":package.producer_branch,
                    "head_sha":package.binary_source_sha,
                    "status":"completed",
                    "conclusion":"success"
                }),
            )
            .with_request_header(authorization.0, authorization.1),
            Route::get(
                "/repos/example-org/project",
                serde_json::json!({"id":write.target_id,"full_name":write.target_repository}),
            )
            .with_request_header("Authorization", "Bearer destination-reader-token"),
        ]);
        let server_reader = GitHub::new(&fixture.base, "server-reader-token".to_owned()).unwrap();
        let destination_reader =
            GitHub::new(&fixture.base, "destination-reader-token".to_owned()).unwrap();

        server_reader
            .validate_native_client_package_current(&config, package)
            .unwrap();
        destination_reader
            .get_uncached::<Value>("/repos/example-org/project")
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn native_release_writer_accepts_only_the_exact_draft_lifecycle() {
        let write = native_release_write_fixture();
        let create_path = "/repos/example-org/project/releases";
        let create = serde_json::json!({
            "tag_name":"v1.2.3",
            "name":"v1.2.3",
            "generate_release_notes":true,
            "prerelease":false,
            "draft":true,
            "target_commitish":"main"
        });
        assert!(
            validate_native_release_write_body(&write, &Method::POST, create_path, &create).is_ok()
        );
        let mut changed_create = create.clone();
        changed_create["target_commitish"] = serde_json::json!("other-branch");
        assert!(
            validate_native_release_write_body(&write, &Method::POST, create_path, &changed_create)
                .is_err()
        );

        let mut selected = write.clone();
        selected.release_id = Some(77);
        let release_path = "/repos/example-org/project/releases/77";
        let publish = serde_json::json!({"draft":false});
        assert!(
            validate_native_release_write_body(&selected, &Method::PATCH, release_path, &publish)
                .is_ok()
        );
        assert!(
            validate_native_release_write_body(
                &selected,
                &Method::PATCH,
                "/repos/example-org/project/releases/78",
                &publish
            )
            .is_err()
        );
        assert!(
            validate_native_release_write_body(
                &selected,
                &Method::PATCH,
                release_path,
                &serde_json::json!({"draft":false,"name":"changed"})
            )
            .is_err()
        );
        assert!(
            validate_native_release_write_body(&selected, &Method::POST, create_path, &create)
                .is_err()
        );
    }

    #[test]
    fn native_release_upload_and_asset_inventory_match_the_verified_plan() {
        let mut write = native_release_write_fixture();
        write.release_id = Some(77);
        let upload_url = "https://uploads.github.com/repos/example-org/project/releases/77/assets?name=project-x86_64-unknown-linux-musl";
        assert_eq!(
            native_release_upload_url(&write, upload_url).unwrap(),
            "/repos/example-org/project/releases/77/assets?name=project-x86_64-unknown-linux-musl"
        );
        assert!(native_release_upload_url(
            &write,
            "https://api.github.com/repos/example-org/project/releases/77/assets?name=project-x86_64-unknown-linux-musl"
        )
        .is_err());
        assert!(native_release_upload_url(
            &write,
            "https://uploads.github.com/repos/example-org/project/releases/78/assets?name=project-x86_64-unknown-linux-musl"
        )
        .is_err());
        assert!(native_release_upload_url(
            &write,
            "https://uploads.github.com/repos/example-org/project/releases/77/assets?name=unexpected.zip"
        )
        .is_err());

        let release = serde_json::json!({"id":77,"tag_name":"v1.2.3","draft":true});
        let uploaded = serde_json::json!({
            "id":1,
            "name":"project-x86_64-unknown-linux-musl",
            "state":"uploaded",
            "size":16,
            "digest":format!("sha256:{}", "d".repeat(64)),
            "content_type":"application/octet-stream"
        });
        assert!(
            validate_native_release_inventory(
                &write,
                77,
                &release,
                std::slice::from_ref(&uploaded),
                true
            )
            .is_ok()
        );
        assert!(validate_native_release_inventory(&write, 77, &release, &[], true).is_err());
        assert!(
            validate_native_release_inventory(
                &write,
                77,
                &release,
                &[uploaded.clone(), uploaded.clone()],
                true
            )
            .is_err()
        );
        assert!(
            validate_native_release_inventory(
                &write,
                77,
                &release,
                &[serde_json::json!({"name":"unexpected.zip"})],
                false
            )
            .is_err()
        );
    }

    #[test]
    fn native_client_label_target_binds_server_authority_operation_and_run() {
        let authority = native_client_label_authority();
        let target = NativeClientLabelTarget {
            server_repository: "example-org/server",
            server_authority: &authority,
            client_repository: "example-org/client",
            operation: "merge",
            run_id: 123,
        };
        assert_eq!(
            validate_native_client_label_target(&target).unwrap(),
            (
                "securefix-native-merge-123".to_owned(),
                "example-org/client/123".to_owned()
            )
        );
        assert!(native_client_request_label("unknown", 123).is_err());
        assert!(native_client_request_label("merge", 0).is_err());

        let mismatched_server = NativeClientLabelTarget {
            server_repository: "other-org/server",
            ..target
        };
        assert!(validate_native_client_label_target(&mismatched_server).is_err());

        let unsupported_operation = NativeClientLabelTarget {
            operation: "release",
            ..target
        };
        assert!(validate_native_client_label_target(&unsupported_operation).is_err());
    }

    #[test]
    fn native_client_label_writer_accepts_only_the_exact_manifest_label() {
        use crate::fixtures::{Fixture, Route};
        let server = "example-org/server";
        let body = serde_json::json!({
            "name":"securefix-native-merge-123",
            "color":"1f6feb",
            "description":"example-org/client/123"
        });
        let path = format!("/repos/{server}/labels");
        let mut fixture = Fixture::new(vec![
            Route::request("POST", &path, 201, body.clone()).with_request_body(body.clone()),
        ]);
        fixture.api.writes = WriteContext::NativeClientLabel {
            server: server.to_owned(),
            name: "securefix-native-merge-123".to_owned(),
            description: "example-org/client/123".to_owned(),
        };
        assert_eq!(fixture.api.post::<Value>(&path, &body).unwrap(), body);
        assert!(
            fixture
                .api
                .post::<Value>(
                    &path,
                    &serde_json::json!({
                        "name":"securefix-native-merge-124",
                        "color":"1f6feb",
                        "description":"example-org/client/123"
                    })
                )
                .is_err()
        );
        assert!(fixture.api.patch::<Value>(&path, &body).is_err());
        assert!(
            fixture
                .api
                .post::<Value>("/repos/other-org/server/labels", &body)
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn native_client_release_label_binds_external_server_client_run_and_exact_post() {
        let config_bytes =
            String::from_utf8(include_bytes!("../tests/fixtures/instance-config.toml").to_vec())
                .unwrap()
                .replace(
                    "release_request_label_prefix = \"\"",
                    "release_request_label_prefix = \"testing-\"",
                )
                .into_bytes();
        let instance = instance_authority_fixture(&config_bytes);
        let target = NativeClientReleaseLabelTarget {
            instance: &instance,
            config_path: TEST_CONFIG_PATH,
            release_repository: "example-org/project",
            release_repository_id: 987_654,
            source_run_id: 12_345,
        };
        let write = validate_native_client_release_label_target(&target).unwrap();
        assert_eq!(write.server_repository, "example-org/securefix-server");
        assert_eq!(write.server_repository_id, 404);
        assert_eq!(write.release_repository, "example-org/project");
        assert_eq!(write.release_repository_id, 987_654);
        assert_eq!(
            instance.config.acceptable_clients.repository,
            "example-org/securefix-client"
        );
        assert_eq!(instance.config.acceptable_clients.id, 654_321);
        assert_eq!(write.config_path, TEST_CONFIG_PATH);
        assert_eq!(write.release_request_label_prefix, "testing-");
        assert_eq!(write.source_run_id, 12_345);
        assert_eq!(write.name, "testing-securefix-native-release-12345");
        assert_eq!(write.description, "example-org/project/12345");
        assert!(validate_native_client_release_label_write(&write).is_ok());

        let path = "/repos/example-org/securefix-server/labels";
        let body = serde_json::json!({
            "name":"testing-securefix-native-release-12345",
            "color":"1f6feb",
            "description":"example-org/project/12345"
        });
        assert!(
            validate_native_client_release_label_body(&Method::POST, path, &write, &body).is_ok()
        );
        assert!(
            validate_native_client_release_label_body(&Method::PATCH, path, &write, &body).is_err()
        );
        assert!(
            validate_native_client_release_label_body(
                &Method::POST,
                "/repos/other-org/server/labels",
                &write,
                &body
            )
            .is_err()
        );
        assert!(
            validate_native_client_release_label_body(
                &Method::POST,
                path,
                &write,
                &serde_json::json!({
                    "name":"testing-securefix-native-release-12346",
                    "color":"1f6feb",
                    "description":"example-org/project/12345"
                })
            )
            .is_err()
        );

        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::NativeClientReleaseLabel(Box::new(write.clone()));
        assert!(api.require_write_target(&Method::POST, path).is_ok());
        assert!(api.require_write_target(&Method::PATCH, path).is_err());
        assert!(
            api.require_write_target(&Method::POST, "/repos/other-org/server/labels")
                .is_err()
        );

        let wrong_destination_id = NativeClientReleaseLabelTarget {
            release_repository_id: 999_999,
            ..target
        };
        assert!(validate_native_client_release_label_target(&wrong_destination_id).is_err());
        let distributor_is_not_a_release_destination = NativeClientReleaseLabelTarget {
            release_repository: "example-org/securefix-client",
            release_repository_id: 654_321,
            ..target
        };
        assert!(
            validate_native_client_release_label_target(&distributor_is_not_a_release_destination)
                .is_err()
        );
        let wrong_config_path = NativeClientReleaseLabelTarget {
            config_path: "other.toml",
            ..target
        };
        assert!(validate_native_client_release_label_target(&wrong_config_path).is_err());
        assert!(native_client_release_label_name("testing-", 0).is_err());
        assert!(native_client_release_label_name(&"x".repeat(32), 12_345).is_err());
    }

    #[test]
    fn native_client_label_read_preflight_does_not_require_a_write_payload() {
        use crate::fixtures::{Fixture, Route};
        let instance =
            instance_authority_fixture(include_bytes!("../tests/fixtures/instance-config.toml"));
        let write = validate_native_client_release_label_target(&NativeClientReleaseLabelTarget {
            instance: &instance,
            config_path: TEST_CONFIG_PATH,
            release_repository: "example-org/project",
            release_repository_id: 987_654,
            source_run_id: 12_345,
        })
        .unwrap();
        let path = "/repos/example-org/securefix-server/labels/securefix-native-release-12345";
        let response = serde_json::json!({"name": write.name, "description": write.description});
        let contexts = [
            WriteContext::ClientLabel {
                server: "example-org/securefix-server".into(),
            },
            WriteContext::NativeClientLabel {
                server: "example-org/securefix-server".into(),
                name: write.name.clone(),
                description: write.description.clone(),
            },
            WriteContext::NativeClientReleaseLabel(Box::new(write)),
        ];
        for context in contexts {
            let mut fixture =
                Fixture::new(vec![Route::request("GET", path, 200, response.clone())]);
            fixture.api.writes = context;
            assert_eq!(fixture.api.get::<Value>(path).unwrap(), response);
            assert!(
                fixture
                    .api
                    .patch::<Value>(path, &serde_json::json!({"description":"changed"}))
                    .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn optional_release_branch_reads_current_head_and_only_accepts_404_as_absence() {
        use crate::fixtures::{Fixture, Route};
        let path = "/repos/example-org/project/branches/release%2Fnext";
        let missing: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/native-release-missing-branch.json"
        ))
        .unwrap();
        let fixture = Fixture::new(vec![
            Route::request("GET", path, 404, missing),
            Route::get(path, serde_json::json!({"commit":{"sha":"a".repeat(40)}})),
            Route::get(path, serde_json::json!({"commit":{"sha":"b".repeat(40)}})),
        ]);
        assert_eq!(
            fixture
                .api
                .optional_branch_head("example-org/project", "release/next")
                .unwrap(),
            None
        );
        assert_eq!(
            fixture
                .api
                .optional_branch_head("example-org/project", "release/next")
                .unwrap(),
            Some("a".repeat(40))
        );
        assert_eq!(
            fixture
                .api
                .optional_branch_head("example-org/project", "release/next")
                .unwrap(),
            Some("b".repeat(40))
        );
        fixture.finish();
        for status in [401, 403, 422] {
            let fixture = Fixture::new(vec![Route::request(
                "GET",
                path,
                status,
                serde_json::json!({"message":"failure"}),
            )]);
            assert!(
                fixture
                    .api
                    .optional_branch_head("example-org/project", "release/next")
                    .is_err()
            );
            fixture.finish();
        }
        for response in [
            serde_json::json!({}),
            serde_json::json!({"commit":{"sha":"invalid"}}),
        ] {
            let fixture = Fixture::new(vec![Route::get(path, response)]);
            assert!(
                fixture
                    .api
                    .optional_branch_head("example-org/project", "release/next")
                    .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn native_release_preparation_requires_signed_commit_before_exact_pr_creation() {
        let instance =
            instance_authority_fixture(include_bytes!("../tests/fixtures/instance-config.toml"));
        let package = crate::package::native_client_package_api_test_fixture();
        let target = NativeReleasePreparationTarget {
            instance,
            repository: "example-org/project".into(),
            repository_id: 987654,
            source_sha: "a".repeat(40),
            default_branch: "main".into(),
            release_branch: "release/next".into(),
            expected_head: "a".repeat(40),
            branch_exists: false,
            existing_pull_request: None,
            workflow_path: ".github/workflows/release-pr.yml".into(),
            workflow_sha: "b".repeat(40),
            workflow_epoch: "c".repeat(40),
            run_id: 42,
            run_attempt: 1,
            additions: BTreeMap::from([
                (".release-version".into(), b"1.2.3\n".to_vec()),
                ("CHANGELOG.md".into(), b"Changes".to_vec()),
            ]),
            deletions: vec![],
            commit_message: "chore(release): prepare v1.2.3".into(),
            title: "chore(release): v1.2.3".into(),
            body: "Prepare release v1.2.3".into(),
            client_package: package,
        };
        validate_native_release_preparation_target(&target).unwrap();
        let package =
            native_client_package_identity(&target.instance.config, &target.client_package)
                .unwrap();
        let write = NativeReleasePreparationWrite {
            target: target.clone(),
            package,
            committed_head: Arc::new(Mutex::new(None)),
        };
        let root = "/repos/example-org/project";
        let reference =
            serde_json::json!({"ref":"refs/heads/release/next","sha":target.source_sha});
        let body = serde_json::json!({"title":target.title,"body":target.body,"head":target.release_branch,"base":"main","draft":false});
        validate_native_release_preparation_body(
            &write,
            &Method::POST,
            &format!("{root}/git/refs"),
            &reference,
        )
        .unwrap();
        assert!(
            validate_native_release_preparation_body(
                &write,
                &Method::POST,
                &format!("{root}/pulls"),
                &body
            )
            .is_err()
        );
        *write.committed_head.lock().unwrap() = Some("d".repeat(40));
        validate_native_release_preparation_body(
            &write,
            &Method::POST,
            &format!("{root}/pulls"),
            &body,
        )
        .unwrap();
        assert!(
            validate_native_release_preparation_body(
                &write,
                &Method::POST,
                &format!("{root}/git/refs"),
                &reference
            )
            .is_err()
        );
        let mut altered = body;
        altered["head"] = serde_json::json!("main");
        assert!(
            validate_native_release_preparation_body(
                &write,
                &Method::POST,
                &format!("{root}/pulls"),
                &altered
            )
            .is_err()
        );
        let mut changed = target.clone();
        changed.instance.authority.config_sha256 = "f".repeat(64);
        assert!(validate_native_release_preparation_target(&changed).is_err());
        let mut changed = target.clone();
        changed.additions.insert("src/main.rs".into(), vec![1]);
        assert!(validate_native_release_preparation_target(&changed).is_err());
        let mut changed = target.clone();
        changed.run_attempt = 2;
        assert!(validate_native_release_preparation_target(&changed).is_err());
        let run = serde_json::json!({"id":42,"run_attempt":1,"repository":{"id":987654,"full_name":target.repository},
            "head_repository":{"id":987654},"head_sha":target.source_sha,"head_branch":"main", "event":"push",
            "status":"completed","conclusion":"success","actor":{"id":101,"login":"maintainer","type":"User"}});
        validate_native_release_preparation_run(&target, &run).unwrap();
        for (pointer, value) in [
            ("/head_sha", serde_json::json!("e".repeat(40))),
            ("/actor/id", serde_json::json!(999)),
            ("/conclusion", serde_json::json!("failure")),
            ("/run_attempt", serde_json::json!(2)),
        ] {
            let mut changed = run.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_native_release_preparation_run(&target, &changed).is_err());
        }
    }

    #[test]
    fn release_sync_rejects_a_caller_changed_only_on_the_release_branch() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;
        let protected = "a".repeat(40);
        let release = "b".repeat(40);
        let path = ".github/workflows/release-pr-sync.yml";
        let fixture = Fixture::new(vec![
            Route::get(
                "/repos/example-org/project/commits/main",
                serde_json::json!({"sha":protected}),
            ),
            Route::get(
                format!("/repos/example-org/project/contents/{path}?ref={protected}"),
                serde_json::json!({"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(b"name: protected sync\n")}),
            ),
            Route::get(
                format!("/repos/example-org/project/contents/{path}?ref={release}"),
                serde_json::json!({"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(b"name: unreviewed sync\n")}),
            ),
        ]);
        let error = capture_native_release_sync_workflow_epoch(
            &fixture.api,
            "example-org/project",
            987_654,
            "main",
            path,
            &release,
        )
        .unwrap_err();
        assert!(error.to_string().contains("differs from its protected"));
        fixture.finish();
    }

    #[test]
    fn native_release_metadata_binds_exact_pr_head_authority_and_payload() {
        use crate::fixtures::Fixture;
        let instance =
            instance_authority_fixture(include_bytes!("../tests/fixtures/instance-config.toml"));
        let write = NativeReleasePrMetadataTarget {
            repository: "example-org/project".into(),
            repository_id: 987_654,
            pull_number: 88,
            head_sha: "a".repeat(40),
            default_branch: "main".into(),
            workflow_path: ".github/workflows/release-pr-sync.yml".into(),
            workflow_sha: "a".repeat(40),
            workflow_epoch: "c".repeat(40),
            run_id: 123,
            run_attempt: 1,
            title: "chore(release): v1.2.3".into(),
            body: "Prepare release v1.2.3".into(),
            instance,
        };
        validate_native_release_pr_metadata_target(&write).unwrap();
        let pull = serde_json::json!({
            "number":88,"state":"open",
            "head":{"sha":write.head_sha,"ref":"release/next","repo":{"id":987654,"full_name":write.repository}},
            "base":{"ref":"main","repo":{"id":987654,"full_name":write.repository}},
            "user":{"id":write.instance.config.identities.server_bot.id,
                    "login":write.instance.config.identities.server_bot.login,"type":"Bot"}
        });
        validate_native_release_pr_metadata_pull(&write, &pull).unwrap();
        for (pointer, value) in [
            ("/head/sha", serde_json::json!("d".repeat(40))),
            ("/head/ref", serde_json::json!("another-branch")),
            ("/head/repo/id", serde_json::json!(1)),
            ("/base/ref", serde_json::json!("another-base")),
            ("/user/id", serde_json::json!(1)),
            ("/user/type", serde_json::json!("User")),
            ("/state", serde_json::json!("closed")),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_native_release_pr_metadata_pull(&write, &changed).is_err(),
                "{pointer}"
            );
        }
        let mut changed = write.clone();
        changed.instance.authority.config_sha256 = "d".repeat(64);
        assert!(validate_native_release_pr_metadata_target(&changed).is_err());
        let mut changed = write.clone();
        changed.run_attempt = 2;
        assert!(validate_native_release_pr_metadata_target(&changed).is_err());
        let mut changed = write.clone();
        changed.workflow_sha = "b".repeat(40);
        assert!(validate_native_release_pr_metadata_target(&changed).is_err());
        let mut fixture = Fixture::new(vec![]);
        fixture.api.writes = WriteContext::NativeReleasePrMetadata(Box::new(write));
        let path = "/repos/example-org/project/pulls/88";
        assert!(
            fixture
                .api
                .require_write_target(&Method::PATCH, path)
                .is_ok()
        );
        assert!(
            fixture
                .api
                .require_write_target(&Method::POST, path)
                .is_err()
        );
        assert!(
            fixture
                .api
                .require_write_target(&Method::PATCH, "/repos/example-org/project/pulls/89")
                .is_err()
        );
        assert!(
            fixture
                .api
                .patch::<Value>(path, &serde_json::json!({"title":"unvalidated"}))
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn native_release_tag_writer_binds_application_pr_and_exact_annotated_object() {
        let instance =
            instance_authority_fixture(include_bytes!("../tests/fixtures/instance-config.toml"));
        let target = NativeReleaseTagWriteTarget {
            instance: &instance,
            config_path: TEST_CONFIG_PATH,
            repository: "example-org/project",
            repository_id: 987_654,
            release_pr_number: 88,
            release_pr_head_sha: &"a".repeat(40),
            release_pr_merge_sha: &"b".repeat(40),
            tag: "v1.2.3",
        };
        let write = validate_native_release_tag_target(&target, 42).unwrap();
        assert_eq!(
            write.instance.config.acceptable_clients.repository,
            "example-org/securefix-client"
        );
        assert_eq!(write.repository, "example-org/project");
        assert_eq!(write.source_run_id, 42);

        let tag_path = "/repos/example-org/project/git/tags";
        let tag_body = serde_json::json!({
            "tag": "v1.2.3",
            "message": "Release v1.2.3",
            "object": "b".repeat(40),
            "type": "commit",
        });
        assert!(
            validate_native_release_tag_body(&write, &Method::POST, tag_path, &tag_body).is_ok()
        );
        assert!(
            validate_native_release_tag_body(
                &write,
                &Method::POST,
                tag_path,
                &serde_json::json!({
                    "tag": "v1.2.3",
                    "message": "Release v1.2.3",
                    "object": "a".repeat(40),
                    "type": "commit",
                })
            )
            .is_err()
        );
        assert!(
            validate_native_release_tag_body(
                &write,
                &Method::POST,
                tag_path,
                &serde_json::json!({
                    "tag": "v1.2.3",
                    "message": "Release v1.2.3",
                    "object": "b".repeat(40),
                    "type": "commit",
                    "extra": true,
                })
            )
            .is_err()
        );

        let object_sha = "c".repeat(40);
        let response = serde_json::json!({
            "tag": "v1.2.3",
            "message": "Release v1.2.3",
            "sha": object_sha,
            "object": {"sha": "b".repeat(40), "type": "commit"},
        });
        assert!(record_native_release_tag_created_object(&write, &response).is_ok());
        assert!(record_native_release_tag_created_object(&write, &response).is_err());
        assert!(
            validate_native_release_tag_created_object(
                &write,
                &serde_json::json!({
                    "tag": "v1.2.3",
                    "message": "Release v1.2.3",
                    "sha": object_sha,
                    "object": {"sha": "a".repeat(40), "type": "commit"},
                })
            )
            .is_err()
        );
        let ref_path = "/repos/example-org/project/git/refs";
        let ref_body = serde_json::json!({"ref":"refs/tags/v1.2.3", "sha":object_sha});
        assert!(
            validate_native_release_tag_body(&write, &Method::POST, ref_path, &ref_body).is_ok()
        );
        assert!(
            validate_native_release_tag_body(
                &write,
                &Method::POST,
                ref_path,
                &serde_json::json!({"ref":"refs/tags/v1.2.4", "sha":object_sha})
            )
            .is_err()
        );
        assert!(
            validate_native_release_tag_body(
                &write,
                &Method::POST,
                ref_path,
                &serde_json::json!({"ref":"refs/tags/v1.2.3", "sha":"d".repeat(40)})
            )
            .is_err()
        );

        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::NativeReleaseTag(Box::new(write));
        assert!(api.require_write_target(&Method::POST, tag_path).is_ok());
        assert!(api.require_write_target(&Method::POST, ref_path).is_ok());
        for (method, path) in [
            (&Method::PATCH, tag_path),
            (&Method::POST, "/repos/other-org/project/git/tags"),
            (&Method::POST, "/repos/example-org/project/git/commits"),
            (&Method::PUT, "/repos/example-org/project/git/refs"),
        ] {
            assert!(api.require_write_target(method, path).is_err());
        }

        let accepted_client_is_not_the_release_destination = NativeReleaseTagWriteTarget {
            repository: "example-org/securefix-client",
            repository_id: 654_321,
            ..target
        };
        assert!(
            validate_native_release_tag_target(&accepted_client_is_not_the_release_destination, 42)
                .is_err()
        );
        let wrong_id = NativeReleaseTagWriteTarget {
            repository_id: 999_999,
            ..target
        };
        assert!(validate_native_release_tag_target(&wrong_id, 42).is_err());
        let wrong_config_path = NativeReleaseTagWriteTarget {
            config_path: "other.toml",
            ..target
        };
        assert!(validate_native_release_tag_target(&wrong_config_path, 42).is_err());
        let invalid_merge_sha = NativeReleaseTagWriteTarget {
            release_pr_merge_sha: "not-a-sha",
            ..target
        };
        assert!(validate_native_release_tag_target(&invalid_merge_sha, 42).is_err());
        let invalid_tag = NativeReleaseTagWriteTarget {
            tag: "release/latest",
            ..target
        };
        assert!(validate_native_release_tag_target(&invalid_tag, 42).is_err());
    }

    #[test]
    fn scratch_writes_cannot_escape_the_fixed_repository() {
        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        assert!(
            api.require_write_target(
                &Method::POST,
                &format!("/repos/{SCRATCH_REPOSITORY}/issues/1/comments"),
            )
            .is_ok()
        );
        for path in [
            "/repos/civitaspo/securefix-server/issues/1/comments",
            "/repos/civitaspo/testing-securefix-server-evil/git/refs",
            "/repos/civitaspo/testing-securefix-server/../securefix-server/git/refs",
            "/repos/civitaspo/testing-securefix-server/%2e%2e/git/refs",
            "/graphql",
            "/user/repos",
        ] {
            assert!(
                api.post::<Value>(path, &serde_json::json!({})).is_err(),
                "{path}"
            );
        }
        assert!(
            api.create_commit(
                "civitaspo/securefix-server",
                "main",
                &"a".repeat(40),
                "blocked",
                BTreeMap::from([("fixture.txt".into(), b"test".to_vec())]),
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn signed_commit_rejects_unsafe_changes_before_network_access() {
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        for path in [
            "../outside",
            "/absolute",
            ".git/config",
            "a//b",
            "a\\b",
            "a\nheader",
        ] {
            let result = api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"a".repeat(40),
                "test",
                BTreeMap::from([(path.into(), vec![1])]),
                vec![],
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("invalid commit file path")
            );
        }
    }

    #[test]
    fn commit_response_must_prove_the_signature_and_expected_parent() {
        use crate::fixtures::{Fixture, Route};
        for (signed, parent, expected_ok) in
            [(true, 'a', true), (false, 'a', false), (true, 'c', false)]
        {
            let mut fixture = Fixture::new(vec![Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"createCommitOnBranch":{"commit":{
                    "oid":"b".repeat(40), "parents":{"nodes":[{"oid":parent.to_string().repeat(40)}]},
                    "signature":{"isValid":signed,"state":"VALID"}
                }}}}),
            )]);
            fixture.api.writes = WriteContext::Scratch {
                candidate_sha: "a".repeat(40),
            };
            let result = fixture.api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"a".repeat(40),
                "test",
                BTreeMap::from([("file.txt".into(), b"test".to_vec())]),
                vec![],
            );
            assert_eq!(result.is_ok(), expected_ok);
            if expected_ok {
                assert_eq!(result.unwrap(), "b".repeat(40));
            }
            fixture.finish();
        }
    }
    #[test]
    fn get_retries_one_connection_drop_and_returns_the_second_response() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::disconnect("GET", "/repos/civitaspo/example"),
            Route::get("/repos/civitaspo/example", serde_json::json!({"ok":true})),
        ]);

        let result: Value = fixture.api.get("/repos/civitaspo/example").unwrap();

        assert_eq!(result, serde_json::json!({"ok":true}));
        fixture.finish();
    }
    #[test]
    fn get_retries_a_repeated_connection_drop_only_once() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::disconnect("GET", "/repos/civitaspo/example"),
            Route::disconnect("GET", "/repos/civitaspo/example"),
        ]);

        assert!(
            fixture
                .api
                .get::<Value>("/repos/civitaspo/example")
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn mutation_connection_drop_is_never_retried() {
        use crate::fixtures::{Fixture, Route};
        let path = "/repos/civitaspo/example/issues/7/comments";
        for (method, method_name) in [
            (Method::POST, "POST"),
            (Method::PATCH, "PATCH"),
            (Method::PUT, "PUT"),
            (Method::DELETE, "DELETE"),
        ] {
            let fixture = Fixture::new(vec![
                Route::active_control(&Fixture::control_revision()),
                Route::disconnect(method_name, path),
            ]);

            let empty_body = serde_json::json!({});
            let body = (method != Method::DELETE).then_some(&empty_body);
            assert!(fixture.api.request(method, path, body).is_err());
            fixture.finish();
        }
    }
    #[test]
    fn invalid_json_response_is_not_retried() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![Route::raw(
            "GET",
            "/repos/civitaspo/example",
            200,
            b"{".to_vec(),
        )]);

        assert!(
            fixture
                .api
                .get::<Value>("/repos/civitaspo/example")
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn every_write_rejects_a_stale_runtime_before_sending_the_mutation() {
        use crate::fixtures::{Fixture, Route};
        for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
            let fixture = Fixture::new(vec![Route::active_control(
                &crate::control::ControlRevision {
                    source_sha: "b".repeat(40),
                    ..Fixture::control_revision()
                },
            )]);
            assert!(
                fixture
                    .api
                    .request(
                        method,
                        "/repos/civitaspo/example/labels",
                        Some(&serde_json::json!({"name":"request"}))
                    )
                    .is_err()
            );
            fixture.finish();
        }
    }
    #[test]
    fn testing_control_readback_and_write_fence_use_only_the_fixture_state() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;
        use serde_json::json;
        const CHILD: &str = "SECUREFIX_TEST_CONTROL_STORAGE";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let mut policy: Value =
                serde_json::from_slice(include_bytes!("../tests/fixtures/policy.json")).unwrap();
            policy["deployment"]["workflow_prefix"] = json!("testing-");
            policy["deployment"]["control_repository"] =
                policy["deployment"]["integration"].clone();
            let repository = policy["deployment"]["integration"]["repository"].clone();
            policy["repositories"] = json!([{"repository":repository,"capabilities":["approve","merge","securefix"],"release":null,"protect_tags":false}]);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("policy.json");
            std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "api::tests::testing_control_readback_and_write_fence_use_only_the_fixture_state", "--nocapture"])
                .env(CHILD, "1").env("SECUREFIX_POLICY_PATH", path).status().unwrap().success());
            return;
        }
        let deployment = &crate::config::trusted().unwrap().deployment;
        let state = deployment.control_repository();
        assert_ne!(state, &deployment.server);
        let current = Fixture::control_revision();
        let default_head = "c".repeat(40);
        let content = json!({"encoding":"base64", "content":base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&current).unwrap())});
        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{}", state.repository),
                json!({"id":state.id,"default_branch":state.default_branch}),
            ),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    state.repository, state.default_branch
                ),
                json!({"sha":default_head}),
            ),
            Route::get(
                format!(
                    "/repos/{}/contents/control/active.json?ref={default_head}",
                    state.repository
                ),
                content,
            ),
            Route::active_control(&current),
            Route::request(
                "POST",
                format!("/repos/{}/labels", state.repository),
                201,
                json!({"id":1}),
            ),
        ]);
        assert_eq!(
            crate::control::ControlRevision::load(&fixture.api).unwrap(),
            current
        );
        for path in [
            format!("/repos/{}/labels", deployment.server.repository),
            format!("/repos/{}-other/labels", state.repository),
            format!("/repos/{}/../securefix-server/labels", state.repository),
            format!("/repos/{}/%2e%2e/labels", state.repository),
        ] {
            assert!(
                fixture
                    .api
                    .require_write_target(&Method::POST, &path)
                    .is_err()
            );
        }
        let _: Value = fixture
            .api
            .post(
                &format!("/repos/{}/labels", state.repository),
                &json!({"name":"testing-fixture"}),
            )
            .unwrap();
        fixture.finish();
        let successor = crate::control::ControlRevision {
            generation: 2,
            previous: current.identity().unwrap(),
            source_sha: "b".repeat(40),
            ..current
        };
        let fixture = Fixture::new(vec![Route::active_control(&successor)]);
        assert!(
            fixture
                .api
                .post::<Value>(&format!("/repos/{}/labels", state.repository), &json!({}))
                .unwrap_err()
                .to_string()
                .contains("control revision is no longer current")
        );
        fixture.finish();
    }

    #[test]
    fn unchanged_active_control_allows_write_without_a_main_tip_lookup() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST",
                "/repos/civitaspo/example/labels",
                201,
                serde_json::json!({"id":1}),
            )
            .with_request_body(serde_json::json!({"name":"request"})),
        ]);
        let result: Value = fixture
            .api
            .post(
                "/repos/civitaspo/example/labels",
                &serde_json::json!({"name":"request"}),
            )
            .unwrap();
        assert_eq!(result["id"], 1);
        fixture.finish();
        let read = GitHub::new("https://api.github.com", String::new()).unwrap();
        assert!(
            read.post::<Value>("/repos/civitaspo/example/labels", &serde_json::json!({}))
                .is_err()
        );
    }

    #[test]
    fn same_source_with_a_new_control_generation_is_stale_before_write() {
        use crate::fixtures::{Fixture, Route};
        let captured = Fixture::control_revision();
        let active = crate::control::ControlRevision {
            generation: 2,
            previous: captured.identity().unwrap(),
            ..captured
        };
        let fixture = Fixture::new(vec![Route::active_control(&active)]);
        assert!(
            fixture
                .api
                .post::<Value>(
                    "/repos/civitaspo/example/labels",
                    &serde_json::json!({"name":"request"})
                )
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn retired_descriptor_blocks_every_legacy_write_transport() {
        use crate::fixtures::{Fixture, Route};
        let server = crate::config::trusted()
            .unwrap()
            .deployment
            .control_repository();
        let descriptor = format!(
            "/repos/{}/contents/control/active.json?ref={}",
            server.repository, server.default_branch
        );
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let fixture = Fixture::new(vec![Route::request(
                "GET",
                descriptor.clone(),
                404,
                serde_json::json!({"message":"Not Found"}),
            )]);
            let error = fixture
                .api
                .request(
                    method,
                    "/repos/civitaspo/example/labels",
                    Some(&serde_json::json!({})),
                )
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<ApiError>().unwrap().status,
                StatusCode::NOT_FOUND
            );
            fixture.finish();
        }
        let fixture = Fixture::new(vec![Route::request(
            "GET",
            descriptor.clone(),
            404,
            serde_json::json!({"message":"Not Found"}),
        )]);
        let error = fixture
            .api
            .create_commit(
                "civitaspo/example",
                "fixture",
                &"a".repeat(40),
                "fixture",
                std::collections::BTreeMap::from([("fixture.txt".to_owned(), b"fixture".to_vec())]),
                Vec::new(),
            )
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ApiError>().unwrap().status,
            StatusCode::NOT_FOUND
        );
        fixture.finish();
        let fixture = Fixture::new(vec![Route::request(
            "GET",
            descriptor,
            404,
            serde_json::json!({"message":"Not Found"}),
        )]);
        let error = fixture
            .api
            .upload(
                "https://uploads.github.com/repos/civitaspo/example/releases/1/assets?name=fixture",
                vec![1],
                "application/octet-stream",
            )
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ApiError>().unwrap().status,
            StatusCode::NOT_FOUND
        );
        fixture.finish();
    }

    #[test]
    fn production_write_without_captured_control_identity_fails_closed() {
        let mut api = GitHub::new("http://127.0.0.1:1", "fixture-token".into()).unwrap();
        api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: None,
        };
        assert!(
            api.post::<Value>(
                "/repos/civitaspo/example/labels",
                &serde_json::json!({"name":"request"})
            )
            .is_err()
        );
    }

    #[test]
    fn package_scratch_accepts_only_canonical_prerelease_tags_and_asset_names() {
        for tag in ["v1.2.3-pre.4", "v0.0.1-alpha.1"] {
            validate_package_scratch_tag(tag).unwrap();
        }
        for tag in ["v1.2.3", "1.2.3-pre.4", "v1.2.3+build.1", "v1.2.3-pre.04"] {
            assert!(validate_package_scratch_tag(tag).is_err(), "{tag}");
        }
        validate_package_asset_name("securefix-linux-x86_64").unwrap();
        for name in ["", "../securefix", "securefix/linux", "securefix?name"] {
            assert!(validate_package_asset_name(name).is_err(), "{name}");
        }
    }

    fn package_release_target_fixture(
        channel: PackageReleaseChannel,
    ) -> PackageReleaseWriteTarget<'static> {
        const SOURCE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const PUBLISHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        PackageReleaseWriteTarget {
            channel,
            source_repository: "civitaspo/securefix-server",
            source_repository_id: 1250079425,
            source_owner_id: 4525500,
            source_branch: if channel == PackageReleaseChannel::Stable {
                "main"
            } else {
                "feature/native-package"
            },
            source_default_branch: "main",
            source_sha: SOURCE_SHA,
            source_manifest_sha256: SHA256,
            destination_repository: if channel == PackageReleaseChannel::Stable {
                "civitaspo/securefix-server"
            } else {
                "civitaspo/testing-securefix-server"
            },
            destination_repository_id: if channel == PackageReleaseChannel::Stable {
                1250079425
            } else {
                1410312556
            },
            destination_default_branch: "main",
            destination_branch_sha: PUBLISHER_SHA,
            destination_target_sha: if channel == PackageReleaseChannel::Stable {
                SOURCE_SHA
            } else {
                PUBLISHER_SHA
            },
            version: if channel == PackageReleaseChannel::Stable {
                "1.2.3"
            } else {
                "1.2.3-pre.4"
            },
            tag: if channel == PackageReleaseChannel::Stable {
                "v1.2.3"
            } else {
                "v1.2.3-pre.4"
            },
            asset_name: "securefix-linux-x86_64",
            asset_size: 1024,
            asset_sha256: SHA256,
            max_asset_bytes: 4096,
            producer_workflow: ".github/workflows/native-package-build.yml",
            producer_run_id: 100,
            producer_run_attempt: 1,
            producer_artifact_id: 101,
            producer_artifact_size: 2048,
            producer_artifact_sha256: SHA256,
            publisher_workflow: ".github/workflows/publish-native-package.yml",
            publisher_sha: PUBLISHER_SHA,
            publisher_branch: "main",
            publisher_run_id: 102,
            publisher_run_attempt: 1,
            owner_id: 4525500,
            release_id: None,
        }
    }

    #[test]
    fn package_release_writer_target_is_bound_to_channel_and_source_identity() {
        let stable = package_release_target_fixture(PackageReleaseChannel::Stable);
        validate_package_release_write_target(&stable).unwrap();

        let scratch = package_release_target_fixture(PackageReleaseChannel::Scratch);
        validate_package_release_write_target(&scratch).unwrap();

        let mut invalid_stable = package_release_target_fixture(PackageReleaseChannel::Stable);
        invalid_stable.version = "1.2.3-pre.4";
        invalid_stable.tag = "v1.2.3-pre.4";
        assert!(validate_package_release_write_target(&invalid_stable).is_err());

        let mut invalid_scratch = package_release_target_fixture(PackageReleaseChannel::Scratch);
        invalid_scratch.destination_repository = "civitaspo/securefix-server";
        invalid_scratch.destination_repository_id = invalid_scratch.source_repository_id;
        assert!(validate_package_release_write_target(&invalid_scratch).is_err());

        let mut invalid_digest = package_release_target_fixture(PackageReleaseChannel::Stable);
        invalid_digest.source_manifest_sha256 = "not-a-digest";
        assert!(validate_package_release_write_target(&invalid_digest).is_err());
    }

    fn package_release_write_fixture() -> PackageReleaseWrite {
        package_release_write_fixture_for(PackageReleaseChannel::Stable)
    }

    fn package_release_write_fixture_for(channel: PackageReleaseChannel) -> PackageReleaseWrite {
        let target = package_release_target_fixture(channel);
        PackageReleaseWrite {
            channel: target.channel,
            source_repository: target.source_repository.to_owned(),
            source_repository_id: target.source_repository_id,
            source_owner_id: target.source_owner_id,
            source_branch: target.source_branch.to_owned(),
            source_default_branch: target.source_default_branch.to_owned(),
            source_sha: target.source_sha.to_owned(),
            source_manifest_sha256: target.source_manifest_sha256.to_owned(),
            destination_repository: target.destination_repository.to_owned(),
            destination_repository_id: target.destination_repository_id,
            destination_default_branch: target.destination_default_branch.to_owned(),
            destination_branch_sha: target.destination_branch_sha.to_owned(),
            destination_target_sha: target.destination_target_sha.to_owned(),
            version: target.version.to_owned(),
            tag: target.tag.to_owned(),
            asset_name: target.asset_name.to_owned(),
            asset_size: target.asset_size,
            asset_sha256: target.asset_sha256.to_owned(),
            max_asset_bytes: target.max_asset_bytes,
            producer_workflow: target.producer_workflow.to_owned(),
            producer_run_id: target.producer_run_id,
            producer_run_attempt: target.producer_run_attempt,
            producer_artifact_id: target.producer_artifact_id,
            producer_artifact_size: target.producer_artifact_size,
            producer_artifact_sha256: target.producer_artifact_sha256.to_owned(),
            publisher_workflow: target.publisher_workflow.to_owned(),
            publisher_sha: target.publisher_sha.to_owned(),
            publisher_branch: target.publisher_branch.to_owned(),
            publisher_run_id: target.publisher_run_id,
            publisher_run_attempt: target.publisher_run_attempt,
            owner_id: target.owner_id,
            preflight_state: PackageReleasePreflightState::Create,
            recovery_body_updated: false,
            release_id: Some(103),
        }
    }

    #[test]
    fn package_release_draft_reads_use_only_the_isolated_publisher_token() {
        use crate::fixtures::{Fixture, Route};
        let write = package_release_write_fixture_for(PackageReleaseChannel::Scratch);
        let release_path = format!("/repos/{}/releases/103", write.destination_repository);
        let source_path = format!(
            "/repos/{}/commits/{}",
            write.source_repository, write.source_sha
        );
        let fixture = Fixture::new(vec![
            Route::get(&release_path, serde_json::json!({"id":103,"draft":true}))
                .with_request_header("Authorization", "Bearer publisher-token"),
            Route::get(&source_path, serde_json::json!({"sha":write.source_sha}))
                .with_request_header("Authorization", "Bearer reader-token"),
        ]);
        let mut api = GitHub::new(&fixture.base, "reader-token".to_owned()).unwrap();
        api.write_token = Some("publisher-token".to_owned());
        api.writes = WriteContext::PackageRelease(Box::new(write));
        let draft: Value = api.get_uncached(&release_path).unwrap();
        assert_eq!(draft["draft"], true);
        api.get_uncached::<Value>(&source_path).unwrap();
        fixture.finish();
    }

    #[test]
    fn package_release_publisher_endpoint_uses_the_exact_validated_release_path() {
        let write = package_release_write_fixture();
        let expected_url = "https://uploads.github.com/repos/civitaspo/securefix-server/releases/103/assets?name=securefix-linux-x86_64";
        let expected_path =
            "/repos/civitaspo/securefix-server/releases/103/assets?name=securefix-linux-x86_64";
        let mut api = GitHub::new("https://api.github.com", "test-token".to_owned()).unwrap();
        api.writes = WriteContext::PackageRelease(Box::new(write.clone()));
        let endpoint = api.package_release_asset_upload_endpoint().unwrap();
        assert_eq!(endpoint, expected_url);
        assert_eq!(
            package_release_upload_url(&write, &endpoint).unwrap(),
            expected_path
        );
        assert!(package_release_upload_url(
            &write,
            "https://uploads.github.com/repos/civitaspo/securefix-server/103/assets?name=securefix-linux-x86_64"
        )
        .is_err());
    }

    #[test]
    fn package_release_run_checks_keep_producer_and_publisher_identities_separate() {
        use serde_json::json;

        let write = package_release_write_fixture();
        let producer = json!({
            "id": 100,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_sha": write.source_sha,
            "head_branch": write.source_branch,
            "repository": {"id": write.source_repository_id, "full_name": write.source_repository},
            "head_repository": {"id": write.source_repository_id, "full_name": write.source_repository},
            "path": format!("{}@refs/heads/{}", write.producer_workflow, write.source_branch),
            "actor": {"id": write.owner_id, "type": "User"},
            "triggering_actor": {"id": write.owner_id, "type": "User"}
        });
        validate_package_release_producer_run(&write, &producer).unwrap();

        let publisher = json!({
            "id": 102,
            "run_attempt": 1,
            "status": "in_progress",
            "event": "workflow_dispatch",
            "head_sha": write.publisher_sha,
            "head_branch": write.publisher_branch,
            "repository": {"id": write.source_repository_id, "full_name": write.source_repository},
            "head_repository": {"id": write.source_repository_id, "full_name": write.source_repository},
            "path": format!("{}@refs/heads/{}", write.publisher_workflow, write.publisher_branch),
            "actor": {"id": write.owner_id, "type": "User"},
            "triggering_actor": {"id": write.owner_id, "type": "User"}
        });
        validate_package_release_publisher_run(&write, &publisher).unwrap();

        let mut stale_publisher = publisher.clone();
        stale_publisher["head_sha"] = write.source_sha.clone().into();
        assert!(validate_package_release_publisher_run(&write, &stale_publisher).is_err());
        let mut untrusted_producer = producer;
        untrusted_producer["triggering_actor"]["id"] = json!(write.owner_id + 1);
        assert!(validate_package_release_producer_run(&write, &untrusted_producer).is_err());
    }

    #[test]
    fn package_release_body_and_asset_are_bound_to_verified_publication() {
        use serde_json::json;

        let write = package_release_write_fixture();
        let body = package_release_record_body(&write).unwrap();
        let expected_body = format!(
            "{{\"schema_version\":1,\"source_sha\":\"{}\",\"source_manifest_sha256\":\"{}\",\"producer_workflow\":\".github/workflows/native-package-build.yml\",\"producer_run_id\":100,\"producer_run_attempt\":1,\"publisher_workflow\":\".github/workflows/publish-native-package.yml\",\"publisher_sha\":\"{}\",\"publisher_run_id\":102,\"publisher_run_attempt\":1,\"tag\":\"v1.2.3\",\"asset_name\":\"securefix-linux-x86_64\",\"asset_size\":1024,\"asset_sha256\":\"{}\"}}",
            write.source_sha, write.source_manifest_sha256, write.publisher_sha, write.asset_sha256
        );
        assert_eq!(body, expected_body);
        let draft = json!({
            "id": 103,
            "tag_name": "v1.2.3",
            "name": "v1.2.3",
            "target_commitish": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "draft": true,
            "prerelease": false,
            "immutable": false,
            "body": body,
            "assets": [{
                "name": "securefix-linux-x86_64",
                "size": 1024,
                "digest": format!("sha256:{}", "c".repeat(64)),
                "state": "uploaded"
            }]
        });
        validate_package_release_draft(&write, &draft, 103, true).unwrap();

        let mut published = draft.clone();
        published["draft"] = json!(false);
        published["immutable"] = json!(true);
        published["assets"][0]["id"] = json!(109);
        validate_package_release_published(&write, &published, 103).unwrap();

        let mut changed_published_name = published.clone();
        changed_published_name["name"] = json!("different");
        assert!(validate_package_release_published(&write, &changed_published_name, 103).is_err());
        let mut changed_published_target = published.clone();
        changed_published_target["target_commitish"] = json!("main");
        assert!(
            validate_package_release_published(&write, &changed_published_target, 103).is_err()
        );
        let mut changed_published_channel = published;
        changed_published_channel["prerelease"] = json!(true);
        assert!(
            validate_package_release_published(&write, &changed_published_channel, 103).is_err()
        );

        let mut changed_record = draft.clone();
        changed_record["body"] = body
            .replace("\"publisher_run_id\":102", "\"publisher_run_id\":999")
            .into();
        assert!(validate_package_release_draft(&write, &changed_record, 103, true).is_err());

        let mut changed_asset = draft;
        changed_asset["assets"][0]["size"] = json!(1025);
        assert!(validate_package_release_draft(&write, &changed_asset, 103, true).is_err());
    }

    #[test]
    fn tagless_scratch_draft_must_bind_exact_asset_and_tag_before_publication() {
        use serde_json::json;

        let write = package_release_write_fixture_for(PackageReleaseChannel::Scratch);
        let mut create_write = write.clone();
        create_write.release_id = None;
        let release_path = format!("/repos/{}/releases", write.destination_repository);
        let create_body = json!({
            "tag_name": write.tag,
            "name": write.tag,
            "target_commitish": write.destination_default_branch,
            "draft": true,
            "prerelease": true,
            "generate_release_notes": false,
            "body": package_release_record_body(&write).unwrap(),
        });
        validate_package_release_write_body(
            &create_write,
            &Method::POST,
            &release_path,
            &create_body,
        )
        .unwrap();

        let mut draft = json!({
            "id": 103,
            "tag_name": write.tag,
            "name": write.tag,
            "target_commitish": write.destination_default_branch,
            "draft": true,
            "prerelease": true,
            "immutable": false,
            "body": package_release_record_body(&write).unwrap(),
            "assets": [],
        });
        validate_package_release_draft(&write, &draft, 103, false).unwrap();
        validate_package_release_tag_binding(&write.destination_target_sha, &draft, None).unwrap();

        draft["assets"] = json!([{
            "id": 109,
            "name": write.asset_name,
            "size": write.asset_size,
            "digest": format!("sha256:{}", write.asset_sha256),
            "state": "uploaded",
        }]);
        validate_package_release_draft(&write, &draft, 103, true).unwrap();
        validate_package_release_tag_binding(&write.destination_target_sha, &draft, None).unwrap();

        let tag_path = format!("/repos/{}/git/refs", write.destination_repository);
        let exact_tag_body = json!({
            "ref": format!("refs/tags/{}", write.tag),
            "sha": write.destination_target_sha,
        });
        validate_package_release_write_body(&write, &Method::POST, &tag_path, &exact_tag_body)
            .unwrap();
        validate_package_release_tag_for_publish(
            &write.destination_target_sha,
            Some(&write.destination_target_sha),
        )
        .unwrap();
        assert!(
            validate_package_release_tag_for_publish(&write.destination_target_sha, None).is_err()
        );
        let publish_path = format!("/repos/{}/releases/103", write.destination_repository);
        validate_package_release_write_body(
            &write,
            &Method::PATCH,
            &publish_path,
            &json!({"draft": false}),
        )
        .unwrap();

        let mut published = draft.clone();
        published["draft"] = json!(false);
        published["immutable"] = json!(true);
        validate_package_release_published(&write, &published, 103).unwrap();
        validate_package_release_tag_binding(
            &write.destination_target_sha,
            &published,
            Some(&write.destination_target_sha),
        )
        .unwrap();

        let wrong_tag_body = json!({
            "ref": format!("refs/tags/{}-other", write.tag),
            "sha": write.destination_target_sha,
        });
        assert!(
            validate_package_release_write_body(&write, &Method::POST, &tag_path, &wrong_tag_body,)
                .is_err()
        );
        let wrong_target_body = json!({
            "ref": format!("refs/tags/{}", write.tag),
            "sha": write.source_sha,
        });
        assert!(
            validate_package_release_write_body(
                &write,
                &Method::POST,
                &tag_path,
                &wrong_target_body,
            )
            .is_err()
        );
        assert!(
            validate_package_release_tag_for_publish(
                &write.destination_target_sha,
                Some(&write.source_sha),
            )
            .is_err()
        );
        assert!(
            validate_package_release_tag_binding(&write.destination_target_sha, &published, None)
                .is_err()
        );
        assert!(
            validate_package_release_tag_binding(
                &write.destination_target_sha,
                &draft,
                Some(&write.source_sha),
            )
            .is_err()
        );

        let mut changed_record = draft.clone();
        changed_record["body"] = changed_record["body"]
            .as_str()
            .unwrap()
            .replace("\"producer_run_id\":100", "\"producer_run_id\":999")
            .into();
        assert!(validate_package_release_draft(&write, &changed_record, 103, true).is_err());
        let mut changed_asset = draft;
        changed_asset["assets"][0]["digest"] = json!(format!("sha256:{}", "d".repeat(64)));
        assert!(validate_package_release_draft(&write, &changed_asset, 103, true).is_err());
    }

    #[test]
    fn stable_package_tag_creation_is_bound_to_the_attested_source_commit() {
        use serde_json::json;

        let write = package_release_write_fixture();
        let path = format!("/repos/{}/git/refs", write.destination_repository);
        let exact_body = json!({
            "ref": format!("refs/tags/{}", write.tag),
            "sha": write.source_sha,
        });
        assert_eq!(write.destination_target_sha, write.source_sha);
        validate_package_release_write_body(&write, &Method::POST, &path, &exact_body).unwrap();

        let wrong_body = json!({
            "ref": format!("refs/tags/{}", write.tag),
            "sha": write.destination_branch_sha,
        });
        assert!(
            validate_package_release_write_body(&write, &Method::POST, &path, &wrong_body).is_err()
        );
    }

    #[test]
    fn package_release_recovery_requires_the_exact_terminal_publisher_and_asset() {
        use serde_json::json;

        let write = package_release_write_fixture();
        let target = package_release_target_fixture(PackageReleaseChannel::Stable);
        let mut prior_record = package_release_record(&write);
        prior_record.publisher_run_id = 101;
        let release_body = serde_json::to_string(&prior_record).unwrap();
        let draft = json!({
            "id": 103,
            "tag_name": target.tag,
            "name": target.tag,
            "target_commitish": target.source_sha,
            "draft": true,
            "prerelease": false,
            "immutable": false,
            "body": release_body,
            "assets": []
        });
        validate_package_release_recoverable_draft(&target, &draft, 103).unwrap();

        let publisher = json!({
            "id": 101,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
            "event": "workflow_dispatch",
            "head_sha": target.publisher_sha,
            "head_branch": target.publisher_branch,
            "repository": {"id": target.source_repository_id, "full_name": target.source_repository},
            "head_repository": {"id": target.source_repository_id, "full_name": target.source_repository},
            "path": format!("{}@refs/heads/{}", target.publisher_workflow, target.publisher_branch),
            "actor": {"id": target.owner_id, "type": "User"},
            "triggering_actor": {"id": target.owner_id, "type": "User"}
        });
        validate_package_release_prior_publisher_run(&target, &prior_record, &publisher, true)
            .unwrap();

        let mut active = publisher.clone();
        active["status"] = json!("in_progress");
        active["conclusion"] = json!(null);
        assert!(
            validate_package_release_prior_publisher_run(&target, &prior_record, &active, true)
                .is_err()
        );
        let mut successful_draft_publisher = publisher.clone();
        successful_draft_publisher["conclusion"] = json!("success");
        assert!(
            validate_package_release_prior_publisher_run(
                &target,
                &prior_record,
                &successful_draft_publisher,
                true
            )
            .is_err()
        );
        let mut wrong_owner = publisher.clone();
        wrong_owner["triggering_actor"]["id"] = json!(target.owner_id + 1);
        assert!(
            validate_package_release_prior_publisher_run(
                &target,
                &prior_record,
                &wrong_owner,
                true
            )
            .is_err()
        );

        let no_assets = package_release_recovery_asset_id(&target, &draft, false).unwrap();
        assert_eq!(no_assets, None);
        assert!(package_release_recovery_asset_id(&target, &draft, true).is_err());

        let exact_asset = json!({
            "id": 109,
            "name": target.asset_name,
            "size": target.asset_size,
            "digest": format!("sha256:{}", target.asset_sha256),
            "state": "uploaded"
        });
        let mut uploaded_draft = draft.clone();
        uploaded_draft["assets"] = json!([exact_asset]);
        assert_eq!(
            package_release_recovery_asset_id(&target, &uploaded_draft, false).unwrap(),
            Some(109)
        );
        let mut extra_asset = uploaded_draft.clone();
        extra_asset["assets"] = json!([exact_asset.clone(), exact_asset.clone()]);
        assert!(package_release_recovery_asset_id(&target, &extra_asset, false).is_err());
        let mut changed_asset = uploaded_draft.clone();
        changed_asset["assets"][0]["digest"] = json!(format!("sha256:{}", "d".repeat(64)));
        assert!(package_release_recovery_asset_id(&target, &changed_asset, false).is_err());

        let mut published = uploaded_draft;
        published["draft"] = json!(false);
        published["immutable"] = json!(true);
        validate_package_release_recoverable_published(&target, &published, 103).unwrap();
        let mut successful_publisher = publisher.clone();
        successful_publisher["conclusion"] = json!("success");
        validate_package_release_prior_publisher_run(
            &target,
            &prior_record,
            &successful_publisher,
            false,
        )
        .unwrap();
        let mut failed_publisher = successful_publisher;
        failed_publisher["conclusion"] = json!("failure");
        assert!(
            validate_package_release_prior_publisher_run(
                &target,
                &prior_record,
                &failed_publisher,
                false
            )
            .is_err()
        );
        let mut mutable_published = published;
        mutable_published["immutable"] = json!(false);
        assert!(
            validate_package_release_recoverable_published(&target, &mutable_published, 103)
                .is_err()
        );
    }

    #[test]
    fn package_scratch_upload_is_bound_to_one_release_asset_and_byte_limit() {
        let repository = "civitaspo/testing-securefix-server";
        let asset = "securefix-linux-x86_64";
        let url =
            format!("https://uploads.github.com/repos/{repository}/releases/7/assets?name={asset}");
        assert_eq!(
            validate_package_scratch_upload(
                &url,
                repository,
                7,
                asset,
                10,
                10,
                "application/octet-stream",
            )
            .unwrap(),
            format!("/repos/{repository}/releases/7/assets")
        );

        for (target, target_repository, release_id, target_asset, max_bytes, size, content_type) in [
            (
                url.as_str(),
                repository,
                8,
                asset,
                10,
                1,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                "civitaspo/another-repository",
                7,
                asset,
                10,
                1,
                "application/octet-stream",
            ),
            (
                "https://uploads.github.com/repos/civitaspo/testing-securefix-server/releases/7/assets?name=other",
                repository,
                7,
                asset,
                10,
                1,
                "application/octet-stream",
            ),
            (
                "https://uploads.github.com/repos/civitaspo/testing-securefix-server/releases/7/assets?name=securefix-linux-x86_64&name=other",
                repository,
                7,
                asset,
                10,
                1,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                repository,
                0,
                asset,
                10,
                1,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                repository,
                7,
                asset,
                0,
                1,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                repository,
                7,
                asset,
                10,
                0,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                repository,
                7,
                asset,
                10,
                11,
                "application/octet-stream",
            ),
            (
                url.as_str(),
                repository,
                7,
                asset,
                10,
                1,
                "application/gzip",
            ),
        ] {
            assert!(
                validate_package_scratch_upload(
                    target,
                    target_repository,
                    release_id,
                    target_asset,
                    max_bytes,
                    size,
                    content_type,
                )
                .is_err(),
                "accepted upload target={target} repo={target_repository} release={release_id} asset={target_asset} max={max_bytes} size={size} type={content_type}"
            );
        }
    }

    #[test]
    fn package_scratch_reads_preflight_the_selected_release_before_scoped_writes() {
        use crate::fixtures::{Fixture, Route};
        use serde_json::json;

        let repository = "civitaspo/testing-securefix-server";
        let release_path = format!("/repos/{repository}/releases/7");
        let release = json!({
            "id":7,
            "tag_name":"v0.2.45-pre.7",
            "prerelease":true,
            "draft":true
        });
        let mut fixture = Fixture::new(vec![
            Route::get(release_path.clone(), release.clone()),
            Route::raw("HEAD", release_path.clone(), 200, vec![]),
            Route::get(
                format!("/repos/{repository}"),
                json!({"id":1410312556,"full_name":repository}),
            ),
            Route::request(
                "POST",
                format!("/repos/{repository}/releases"),
                201,
                release.clone(),
            )
            .with_request_body(json!({
                "tag_name":"v0.2.45-pre.7",
                "draft":true,
                "prerelease":true
            })),
            Route::get(release_path.clone(), release.clone()),
            Route::get(
                format!("/repos/{repository}"),
                json!({"id":1410312556,"full_name":repository}),
            ),
            Route::request("PATCH", release_path.clone(), 200, json!({"draft":false}))
                .with_request_body(json!({"draft":false})),
        ]);
        fixture.api.writes = WriteContext::PackageScratch {
            candidate_sha: "a".repeat(40),
            destination_repository: repository.into(),
            destination_repository_id: 1410312556,
            tag: "v0.2.45-pre.7".into(),
            asset_name: "securefix-linux-x86_64".into(),
            max_asset_bytes: 1024,
            release_id: Some(7),
        };

        let selected: Value = fixture.api.get(&release_path).unwrap();
        assert_eq!(selected["id"], 7);
        assert!(
            fixture
                .api
                .request(Method::HEAD, &release_path, None)
                .unwrap()
                .is_null()
        );
        let created: Value = fixture
            .api
            .post(
                &format!("/repos/{repository}/releases"),
                &json!({
                    "tag_name":"v0.2.45-pre.7",
                    "draft":true,
                    "prerelease":true
                }),
            )
            .unwrap();
        assert_eq!(created["id"], 7);
        let published: Value = fixture
            .api
            .request(Method::PATCH, &release_path, Some(&json!({"draft":false})))
            .unwrap();
        assert_eq!(published["draft"], false);

        let error = fixture
            .api
            .post::<Value>(&format!("/repos/{repository}/issues"), &json!({}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("package scratch write target is not the selected release"));
        fixture.finish();
    }
}
