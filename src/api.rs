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
    sync::mpsc,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeScratchMode {
    PolicyCheck,
    Approval,
    Merge,
    Securefix,
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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkflowAuthority {
    pub role: crate::instance_config::WorkflowRole,
    pub path: String,
    pub sha256: String,
    pub pins: Vec<String>,
}

#[derive(Clone)]
enum WriteContext {
    ReadOnly,
    ClientLabel {
        server: String,
    },
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

    pub fn package_release_from_env(
        read_name: &str,
        write_name: &str,
        target: &PackageReleaseWriteTarget<'_>,
    ) -> Result<Self> {
        let preflight_state = Self::package_release_preflight_from_env(read_name, target)?;
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
    /// the job's read token. Call this before minting the scoped App writer.
    pub fn package_release_preflight_from_env(
        read_name: &str,
        target: &PackageReleaseWriteTarget<'_>,
    ) -> Result<PackageReleasePreflightState> {
        validate_package_release_write_target(target)?;
        validate_package_release_publisher_environment(target)?;
        let read_token =
            std::env::var(read_name).with_context(|| format!("missing {read_name}"))?;
        ensure!(!read_token.is_empty(), "{read_name} is empty");
        let api = Self::new("https://api.github.com", read_token)?;

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
            api.get_uncached(&format!("/repos/{}", target.destination_repository))?;
        ensure!(
            destination["id"].as_u64() == Some(target.destination_repository_id)
                && destination["full_name"] == target.destination_repository
                && destination["owner"]["id"].as_u64() == Some(target.source_owner_id)
                && destination["default_branch"] == target.destination_default_branch,
            "package release destination differs from the protected publisher declaration"
        );
        ensure!(
            current_branch_sha(
                &api,
                target.destination_repository,
                target.destination_default_branch
            )? == target.destination_branch_sha,
            "package release destination branch head moved before token issuance"
        );

        let releases: Vec<Value> = api.paginate_uncached(&format!(
            "/repos/{}/releases",
            target.destination_repository
        ))?;
        let matching: Vec<_> = releases
            .iter()
            .filter(|release| release["tag_name"] == target.tag)
            .collect();
        ensure!(matching.len() <= 1, "package release tag is duplicated");
        let refs: Vec<Value> = api.get_uncached(&format!(
            "/repos/{}/git/matching-refs/tags/{}",
            target.destination_repository,
            encode_path_segment(target.tag)
        ))?;
        let tag_exists = refs
            .iter()
            .any(|reference| reference["ref"] == format!("refs/tags/{}", target.tag));
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

        ensure!(
            tag_exists,
            "existing package release has no matching tag ref"
        );
        ensure!(
            current_tag_commit(&api, target.destination_repository, target.tag)?
                == target.destination_target_sha,
            "existing package release tag does not target the exact source commit"
        );

        if draft {
            validate_package_release_recoverable_draft(target, release, release_id)?;
            let asset_uploaded =
                validate_package_release_recovery_asset(target, &api, release, false)?;
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
                validate_package_release_recovery_asset(target, &api, release, true)?;
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
        let path = format!(
            "/repos/{}/releases/{release_id}",
            write.destination_repository
        );
        self.patch(&path, &serde_json::json!({"draft": false}))
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
            "published package tag no longer targets the exact source commit"
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
            ".github/actions/load-package/package.json",
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
        let tag_exists = refs
            .iter()
            .any(|reference| reference["ref"] == format!("refs/tags/{}", write.tag));
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
                matching.len() == 1 && matching[0]["id"].as_u64() == Some(release_id) && tag_exists,
                "selected package draft or tag is no longer unique"
            );
            let tag_commit =
                current_tag_commit(&writer_reader, &write.destination_repository, &write.tag)?;
            ensure!(
                tag_commit == write.destination_target_sha,
                "package release tag no longer targets the exact source commit"
            );
        } else {
            match write.preflight_state {
                PackageReleasePreflightState::Create => ensure!(
                    matching.is_empty() && !tag_exists,
                    "package release tag already exists without an authorized recovery"
                ),
                PackageReleasePreflightState::ResumeDraft { release_id, .. } => {
                    ensure!(
                        matching.len() == 1
                            && matching[0]["id"].as_u64() == Some(release_id)
                            && tag_exists,
                        "recoverable package draft or tag is no longer unique"
                    );
                    let release = matching[0];
                    validate_package_release_draft_recovery_record(write, release, release_id)?;
                    validate_package_release_recovery_asset_for_write(
                        write,
                        &writer_reader,
                        release,
                        false,
                    )?;
                    ensure!(
                        current_tag_commit(
                            &writer_reader,
                            &write.destination_repository,
                            &write.tag
                        )? == write.destination_target_sha,
                        "recoverable package tag no longer targets the exact source commit"
                    );
                }
                PackageReleasePreflightState::AlreadyPublished { .. } => {
                    bail!("an already-published package release cannot be rewritten")
                }
            }
        }
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
        if let WriteContext::ClientLabel { server } = &self.writes {
            ensure!(
                path == format!("/repos/{server}/labels"),
                "client write target is not the configured request-label endpoint"
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
        if let WriteContext::PackageRelease(write) = &self.writes {
            let valid_create = *method == Method::POST
                && path == format!("/repos/{}/releases", write.destination_repository);
            let valid_publish = *method == Method::PATCH
                && write.release_id.is_some_and(|id| {
                    path == format!("/repos/{}/releases/{id}", write.destination_repository)
                });
            let valid_asset =
                *method == Method::POST && package_release_upload_path(write, path).is_ok();
            ensure!(
                valid_create || valid_publish || valid_asset,
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
            WriteContext::PackageRelease(write)
                if (method == Method::POST
                    && path == format!("/repos/{}/releases", write.destination_repository))
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
        if let WriteContext::ClientLabel { server } = &self.writes {
            ensure!(
                method == Method::POST && path == format!("/repos/{server}/labels"),
                "client may only create configured server request labels"
            );
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
        let mut request = self.builder(method.clone(), path)?;
        if no_cache {
            request = request.header(reqwest::header::CACHE_CONTROL, "no-cache");
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .with_context(|| format!("GitHub {method} {path}"))?;
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
        serde_json::from_slice(&bytes).context("invalid GitHub JSON")
    }

    fn require_current_revision(&self) -> Result<()> {
        let (expected, expected_control) = match &self.writes {
            WriteContext::ReadOnly => bail!("read-only API connection cannot write"),
            WriteContext::ClientLabel { .. } => {
                return Ok(());
            }
            WriteContext::Scratch { .. } => return Ok(()),
            WriteContext::PackageScratch { .. } => return Ok(()),
            WriteContext::NativeScratch(_) => {
                return self.require_native_scratch_current();
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
        let WriteContext::NativeScratch(write) = &self.writes else {
            bail!("native scratch merge writer context is missing");
        };
        ensure!(
            write.mode == NativeScratchMode::Merge,
            "native scratch writer is not authorized to merge"
        );
        let path = format!(
            "/repos/{}/pulls/{}/merge",
            write.target_repository, write.pull_number
        );
        let result: Value = self.put(&path, &native_merge_body(&write.head_sha))?;
        ensure!(
            result["merged"] == true,
            "GitHub did not merge the exact native scratch pull request"
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
        if let WriteContext::NativeScratch(write) = &self.writes {
            ensure!(
                write.mode == NativeScratchMode::Securefix
                    && repository == write.target_repository
                    && write.destination_branch.as_deref() == Some(branch)
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
        let upload_token = if matches!(self.writes, WriteContext::PackageRelease(_)) {
            self.write_token
                .as_deref()
                .context("package release write token is missing")?
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

pub fn capture_native_client_workflow_epoch(
    api: &GitHub,
    repository_name: &str,
    repository_id: u64,
    default_branch: &str,
    workflow_path: &str,
    workflow_revision: &str,
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
    let compare: Value = api.get(&format!(
        "/repos/{repository_name}/compare/{workflow_revision}...{snapshot_sha}"
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "caller workflow revision is not on default-branch history"
    );
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

pub fn validate_native_server_execution_workflow(
    snapshot: &NativeAuthoritySnapshot,
    mode: NativeScratchMode,
    workflow_ref: &str,
    workflow_sha: &str,
    workflow_bytes: &[u8],
) -> Result<()> {
    validate_native_authority_snapshot(snapshot)?;
    crate::policy::validate_sha(workflow_sha)?;
    let role = match mode {
        NativeScratchMode::PolicyCheck => crate::instance_config::WorkflowRole::PolicyCheck,
        NativeScratchMode::Approval => crate::instance_config::WorkflowRole::Approve,
        NativeScratchMode::Merge => crate::instance_config::WorkflowRole::Merge,
        NativeScratchMode::Securefix => crate::instance_config::WorkflowRole::Securefix,
    };
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

fn validate_package_release_workflow_path(path: &str) -> Result<()> {
    let name = path
        .strip_prefix(".github/workflows/")
        .context("package workflow path is outside .github/workflows")?;
    ensure!(
        !name.is_empty()
            && name.ends_with(".yml")
            && !name.contains(['\\', '%', '?', '#'])
            && name
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "package workflow path is invalid"
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

fn current_tag_commit(api: &GitHub, repository: &str, tag: &str) -> Result<String> {
    let refs: Vec<Value> = api.get_uncached(&format!(
        "/repos/{repository}/git/matching-refs/tags/{}",
        encode_path_segment(tag)
    ))?;
    let exact: Vec<_> = refs
        .iter()
        .filter(|reference| reference["ref"] == format!("refs/tags/{tag}"))
        .collect();
    ensure!(
        exact.len() == 1,
        "package release tag ref is missing or duplicated"
    );
    let object_sha = exact[0]["object"]["sha"]
        .as_str()
        .context("package release tag object SHA is missing")?;
    crate::policy::validate_sha(object_sha)?;
    match exact[0]["object"]["type"].as_str() {
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
    validate_package_release_workflow_path(target.producer_workflow)?;
    validate_package_release_workflow_path(target.publisher_workflow)?;
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
    bail!("package release write is outside the exact draft, asset, and publish lifecycle")
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
        "native request token must be installed only on the configured Client repository"
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
    let authority_id = crate::hex_encode(sha2::Sha256::digest(serde_json::to_vec(authority)?));
    let marker = format!("<!-- securefix:native-approval:v1:{authority_id}:{request_sha256} -->");
    Ok(serde_json::json!({
        "event": "APPROVE",
        "commit_id": head_sha,
        "body": marker
    }))
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

fn encode_path_segment(value: &str) -> String {
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

    #[test]
    fn git_fetch_uses_basic_token_authorization() {
        assert_eq!(
            git_authorization_header("ghs_test"),
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46Z2hzX3Rlc3Q="
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
        let target = package_release_target_fixture(PackageReleaseChannel::Stable);
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
