//! Read-only resolution of one pinned component's published release metadata.
//!
//! A resolved package and downloaded asset are not execution authority. A host
//! consumer must use `VerifiedPackage`, which adds source/run/signature proof.

use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use semver::{Version, VersionReq};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;

const MAX_CARGO_TOML_BYTES: usize = 64 * 1024;
const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACKAGE_ARTIFACT_BYTES: usize = 160 * 1024 * 1024;
const MAX_PACKAGE_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const PACKAGE_ARTIFACT_NAME: &str = "native-package-attested";
const PACKAGE_BINARY_NAME: &str = "securefix-linux-x86_64";
const PACKAGE_BUNDLE_NAME: &str = "bundle.json";
const MAX_PACKAGE_WORKFLOW_BYTES: usize = 64 * 1024;
pub(crate) const SOURCE_BUILD_MANIFEST_PATH: &str =
    ".github/actions/load-package/source-package.json";
const PACKAGE_PRODUCER_WORKFLOW: &str = ".github/workflows/testing-native-package-build.yml";
const PACKAGE_PUBLISHER_WORKFLOW: &str = ".github/workflows/testing-publish-native-package.yml";
pub(crate) const NATIVE_PACKAGE_PRODUCER_WORKFLOW: &str =
    ".github/workflows/native-package-build.yml";
pub(crate) const NATIVE_PACKAGE_PUBLISHER_WORKFLOW: &str =
    ".github/workflows/publish-native-package.yml";

/// One local package action selected by an authenticated Client workflow's
/// literal `uses: owner/repo/path@<full SHA>` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedPackageAction {
    repository: String,
    path: String,
    sha: String,
}

impl PinnedPackageAction {
    pub fn new(repository: String, path: String, sha: String) -> Result<Self> {
        crate::policy::validate_repository(&repository)?;
        validate_package_action_path(&path)?;
        crate::policy::validate_sha(&sha)?;
        Ok(Self {
            repository,
            path,
            sha,
        })
    }

    pub fn revision(&self) -> &str {
        &self.sha
    }

    fn manifest_path(&self) -> String {
        format!("{}/package.json", self.path)
    }
}

fn validate_package_action_path(path: &str) -> Result<()> {
    validate_repository_relative_path(path)?;
    ensure!(!path.is_empty(), "Client package action path is empty");
    Ok(())
}

fn validate_source_package_manifest_path(path: &str) -> Result<()> {
    validate_repository_relative_path(path)?;
    ensure!(
        path.ends_with(".json"),
        "source package manifest path must name a JSON file"
    );
    Ok(())
}

fn validate_repository_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 200
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path
                .as_bytes()
                .get(..2)
                .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte >= 0x20 && byte != 0x7f && !b"\\?#".contains(&byte))
            }),
        "repository-relative path is invalid"
    );
    Ok(())
}

fn encode_repository_path(path: &str) -> String {
    path.split('/')
        .map(crate::api::encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientPackageChannel {
    Stable,
    Scratch,
}

/// Strict v3 map bundled with the immutable Client package action. It binds
/// that action revision to one binary source revision and its publication.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeClientPackageManifest {
    schema_version: u8,
    channel: ClientPackageChannel,
    component: String,
    protocol: String,
    version: String,
    max_bytes: u64,
    source_repository: String,
    source_repository_id: u64,
    source_sha: String,
    source_branch: String,
    source_default_branch: String,
    source_manifest_path: String,
    source_manifest_sha256: String,
    destination_repository: String,
    destination_repository_id: u64,
    tag: String,
    release_id: u64,
    target_branch: String,
    immutable: bool,
    prerelease: bool,
    asset_id: u64,
    asset_name: String,
    asset_size: u64,
    asset_sha256: String,
    producer_workflow: String,
    producer_run_id: u64,
    producer_run_attempt: u64,
    publisher_workflow: String,
    publisher_sha: String,
    publisher_branch: String,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
}

impl NativeClientPackageManifest {
    fn scratch_publication(&self) -> ScratchPackagePublication {
        ScratchPackagePublication {
            source_repository: self.source_repository.clone(),
            source_repository_id: self.source_repository_id,
            destination_repository: self.destination_repository.clone(),
            destination_repository_id: self.destination_repository_id,
            source_sha: self.source_sha.clone(),
            source_branch: self.source_branch.clone(),
            tag: self.tag.clone(),
            release_id: self.release_id,
            asset_id: self.asset_id,
            asset_sha256: self.asset_sha256.clone(),
            asset_size: self.asset_size,
            producer_run_id: self.producer_run_id,
            producer_run_attempt: self.producer_run_attempt,
            publisher_workflow: self.publisher_workflow.clone(),
            publisher_branch: self.publisher_branch.clone(),
            publisher_sha: self.publisher_sha.clone(),
            publisher_run_id: self.publisher_run_id,
            publisher_run_attempt: self.publisher_run_attempt,
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 16 * 1024,
            "pinned Client package action manifest is empty or exceeds its size limit"
        );
        serde_json::from_slice(bytes).context("parse strict Client package action manifest")
    }

    fn validate(
        &self,
        expected_channel: ClientPackageChannel,
        source: &TrustedPublisher,
        destination: &TrustedPublisher,
        expected_protocol: &str,
        source_default_branch: Option<&str>,
    ) -> Result<String> {
        crate::policy::validate_repository(&self.source_repository)?;
        crate::policy::validate_repository(&self.destination_repository)?;
        crate::policy::validate_sha(&self.source_sha)?;
        crate::policy::validate_sha(&self.publisher_sha)?;
        validate_source_package_manifest_path(&self.source_manifest_path)?;
        validate_package_workflow(&self.producer_workflow)?;
        validate_package_workflow(&self.publisher_workflow)?;
        crate::config::validate_branch(&self.source_branch)?;
        crate::config::validate_branch(&self.source_default_branch)?;
        crate::config::validate_branch(&self.target_branch)?;
        crate::config::validate_branch(&self.publisher_branch)?;

        let version = Version::parse(&self.version).context("Client package version is invalid")?;
        let stable_version = version.pre.is_empty()
            && version.build.is_empty()
            && version.to_string() == self.version;
        let prerelease_version = !version.pre.is_empty() && version.build.is_empty();
        ensure!(
            self.schema_version == 3
                && self.channel == expected_channel
                && self.component == "securefix-server"
                && self.protocol == expected_protocol
                && expected_protocol == NATIVE_CLIENT_PROTOCOL
                && self.source_repository == source.repository
                && self.source_repository_id == source.repository_id
                && self.destination_repository == destination.repository
                && self.destination_repository_id == destination.repository_id
                && source.repository_id > 0
                && destination.repository_id > 0
                && self.immutable
                && self.release_id > 0
                && self.asset_id > 0
                && self.asset_name == PACKAGE_BINARY_NAME
                && self.asset_size > 0
                && self.asset_size <= self.max_bytes
                && self.max_bytes > 0
                && self.max_bytes <= MAX_ASSET_BYTES
                && self.producer_run_id > 0
                && self.producer_run_attempt == 1
                && self.publisher_run_id > 0
                && self.publisher_run_attempt == 1
                && self.source_manifest_sha256.len() == 64
                && self
                    .source_manifest_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && self.asset_sha256.len() == 64
                && self
                    .asset_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && self.tag == format!("v{version}"),
            "Client package action mapping contains an invalid identity or publication claim"
        );
        match expected_channel {
            ClientPackageChannel::Stable => ensure!(
                stable_version
                    && !self.prerelease
                    && self.source_branch == self.source_default_branch
                    && self.target_branch == self.source_default_branch
                    && self.publisher_branch == self.source_default_branch,
                "stable Client package mapping is not a stable default-branch release"
            ),
            ClientPackageChannel::Scratch => ensure!(
                prerelease_version && self.prerelease,
                "scratch Client package mapping is not a prerelease"
            ),
        }
        if let Some(default_branch) = source_default_branch {
            crate::config::validate_branch(default_branch)?;
            ensure!(
                self.source_default_branch == default_branch,
                "Client package mapping source default branch differs from the authenticated repository"
            );
        }
        if expected_channel == ClientPackageChannel::Scratch {
            ensure!(
                self.publisher_workflow == NATIVE_PACKAGE_PUBLISHER_WORKFLOW,
                "scratch Client package mapping names an unexpected publisher workflow"
            );
        }
        Ok(self.source_sha.clone())
    }
}

/// Publisher identity supplied by authenticated deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPublisher {
    pub repository: String,
    pub repository_id: u64,
}

/// One raw executable selected by the trusted caller, not by release metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAsset {
    pub component: String,
    pub platform: String,
    pub name: String,
}

/// GitHub release and source identities checked by [`resolve_release`].
///
/// The `asset` is an API identity and claimed digest only. This type does not
/// mean the asset bytes have been downloaded, attested, or qualified to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRelease {
    pub publisher: TrustedPublisher,
    pub implementation_sha: String,
    pub source_sha: String,
    pub version: Version,
    pub tag: String,
    pub release_id: u64,
    /// Raw GitHub release body. Stable native packages require a canonical
    /// publication record here; generic release resolution does not.
    pub release_body: Option<String>,
    pub asset: ResolvedAsset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsset {
    pub component: String,
    pub platform: String,
    pub id: u64,
    pub name: String,
    pub size: u64,
    /// Canonical lowercase SHA-256 hex claimed by GitHub's release API.
    pub sha256: String,
}

/// Asset bytes whose length and hash match the immutable-release API metadata.
///
/// This is content-integrity data only. It does not establish producer
/// provenance, source-build identity, attestation validity, or permission to
/// execute the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedAsset {
    release: ResolvedRelease,
    bytes: Vec<u8>,
}

impl DownloadedAsset {
    pub fn release(&self) -> &ResolvedRelease {
        &self.release
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A release asset whose bytes and producer/source attestation passed.
/// This type is the only package result a host consumer should use before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    asset: DownloadedAsset,
    producer_run_id: u64,
    producer_run_attempt: u64,
}

impl VerifiedPackage {
    pub fn release(&self) -> &ResolvedRelease {
        self.asset.release()
    }

    pub fn bytes(&self) -> &[u8] {
        self.asset.bytes()
    }

    pub fn producer_run(&self) -> (u64, u64) {
        (self.producer_run_id, self.producer_run_attempt)
    }
}

/// Authenticated identity chain for one fixed Client workflow and its package.
/// The `package` field is the execution-ready result; the other fields explain
/// which implementation, loader mapping, binary source, and protocol it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNativeClientPackage {
    pub implementation_sha: String,
    pub implementation_version: Version,
    pub loader_action_sha: String,
    pub binary_source_sha: String,
    pub binary_version: Version,
    pub protocol: String,
    /// Workflow and branch declared by the fixed loader manifest whose
    /// release publisher record. These are distinct from the producer whose
    /// artifact attestation binds the executable bytes.
    pub package_publisher_workflow: String,
    pub package_publisher_branch: String,
    pub package_publisher_sha: String,
    pub package_publisher_run_id: u64,
    pub package_publisher_run_attempt: u64,
    pub package_producer_workflow: String,
    pub package_producer_branch: String,
    pub package_producer_run_id: u64,
    pub package_producer_run_attempt: u64,
    pub package: VerifiedPackage,
}

#[cfg(test)]
pub(crate) fn native_client_package_api_test_fixture() -> VerifiedNativeClientPackage {
    let publisher = TrustedPublisher {
        repository: "example-org/securefix-client".to_owned(),
        repository_id: 654_321,
    };
    let source_sha = "3".repeat(40);
    let version = Version::parse("1.4.1").unwrap();
    let asset = ResolvedAsset {
        component: "securefix".to_owned(),
        platform: "linux-x86_64".to_owned(),
        id: 8_766,
        name: "securefix-linux-x86_64".to_owned(),
        size: 16,
        sha256: "d".repeat(64),
    };
    let release = ResolvedRelease {
        publisher,
        implementation_sha: source_sha.clone(),
        source_sha: source_sha.clone(),
        version: version.clone(),
        tag: format!("v{version}"),
        release_id: 8_765,
        release_body: None,
        asset,
    };
    VerifiedNativeClientPackage {
        implementation_sha: "1".repeat(40),
        implementation_version: Version::parse("1.4.2").unwrap(),
        loader_action_sha: "2".repeat(40),
        binary_source_sha: source_sha,
        binary_version: version,
        protocol: NATIVE_CLIENT_PROTOCOL.to_owned(),
        package_publisher_workflow: ".github/workflows/publish-native-package.yml".to_owned(),
        package_publisher_branch: "main".to_owned(),
        package_publisher_sha: "4".repeat(40),
        package_publisher_run_id: 8_767,
        package_publisher_run_attempt: 1,
        package_producer_workflow: ".github/workflows/native-package-build.yml".to_owned(),
        package_producer_branch: "main".to_owned(),
        package_producer_run_id: 8_768,
        package_producer_run_attempt: 1,
        package: VerifiedPackage {
            asset: DownloadedAsset {
                release,
                bytes: b"synthetic-test-binary".to_vec(),
            },
            producer_run_id: 8_768,
            producer_run_attempt: 1,
        },
    }
}

/// Verify the configured Client implementation release and the separate
/// binary package selected by the fixed package loader in that implementation.
///
/// The Client implementation version is checked against deployment policy at
/// its authenticated signer SHA. The binary's source revision and version come
/// from the loader manifest pinned by that workflow. This function accepts
/// only stable immutable releases; scratch prereleases remain a separate path.
pub fn verify_native_client_package(
    api: &GitHub,
    acceptable: &crate::instance_config::AcceptableClients,
    signer_sha: &str,
    loader_action: &PinnedPackageAction,
    expected_protocol: &str,
    source_default_branch: &str,
) -> Result<VerifiedNativeClientPackage> {
    crate::policy::validate_repository(&acceptable.repository)?;
    ensure!(acceptable.id > 0, "Client repository ID is invalid");
    crate::policy::validate_sha(signer_sha)?;
    validate_pinned_package_action(loader_action, &acceptable.repository)?;
    crate::config::validate_branch(source_default_branch)?;
    ensure!(
        expected_protocol == NATIVE_CLIENT_PROTOCOL,
        "requested Client protocol is not supported by this Server"
    );
    validate_package_workflow(&acceptable.producer_workflow)?;

    let publisher = TrustedPublisher {
        repository: acceptable.repository.clone(),
        repository_id: acceptable.id,
    };
    let implementation_version = resolve_native_client_implementation(
        api,
        &publisher,
        signer_sha,
        &acceptable.version,
        source_default_branch,
    )?;

    let (_, manifest) = fetch_native_client_action_manifest(api, loader_action)?;
    manifest.validate(
        ClientPackageChannel::Stable,
        &publisher,
        &publisher,
        expected_protocol,
        Some(source_default_branch),
    )?;
    let binary_version = Version::parse(&manifest.version)
        .context("fixed Client package version is invalid SemVer")?;
    ensure!(
        binary_version.build.is_empty()
            && binary_version.pre.is_empty()
            && binary_version.to_string() == manifest.version,
        "fixed Client package version must be canonical stable SemVer"
    );
    let binary_source_sha = manifest.source_sha.clone();
    ensure!(
        manifest.source_branch == source_default_branch
            && manifest.source_default_branch == source_default_branch
            && manifest.target_branch == source_default_branch,
        "stable Client package mapping does not select the protected default branch"
    );

    let source_manifest_bytes = fetch_source_package_manifest(
        api,
        &publisher.repository,
        &binary_source_sha,
        &manifest.source_manifest_path,
    )?;
    let source_manifest: SourcePackageManifest = serde_json::from_slice(&source_manifest_bytes)
        .context("binary source package manifest is invalid JSON")?;
    validate_client_source_package_manifest(
        &manifest,
        &source_manifest,
        &source_manifest_bytes,
        &binary_version,
        expected_protocol,
    )?;

    let asset_name = manifest.asset_name.clone();
    let expected_asset = ExpectedAsset {
        component: manifest.component.clone(),
        platform: "linux-x86_64".to_owned(),
        name: asset_name,
    };
    let exact_binary_version = VersionReq::parse(&format!("={binary_version}"))
        .context("fixed Client package version cannot form an exact version requirement")?;
    let downloaded = download_release_asset_bounded(
        api,
        &publisher,
        &binary_source_sha,
        &expected_asset,
        &exact_binary_version,
        manifest.max_bytes,
    )?;
    ensure!(
        downloaded.release().release_id == manifest.release_id
            && downloaded.release().asset.id == manifest.asset_id
            && downloaded.release().tag == manifest.tag
            && downloaded.release().asset.size == manifest.asset_size
            && downloaded.release().asset.sha256 == manifest.asset_sha256,
        "stable Client package mapping differs from the resolved immutable release"
    );
    let release_record = parse_native_package_release_record(
        downloaded
            .release()
            .release_body
            .as_deref()
            .context("stable Client package release has no publication record")?,
    )?;
    validate_native_package_release_record(
        &release_record,
        downloaded.release(),
        &source_manifest,
        &source_manifest_bytes,
        &binary_source_sha,
        &expected_asset,
    )?;
    validate_client_package_manifest_record(&manifest, &release_record)?;
    let producer_owner_id = package_workflow_owner_id(
        api,
        &publisher.repository,
        &manifest.producer_workflow,
        &binary_source_sha,
    )?;
    let package = verify_downloaded_release_from_with_actor(
        api,
        downloaded,
        &publisher,
        &manifest.producer_workflow,
        source_default_branch,
        Some(producer_owner_id),
    )?;
    ensure!(
        package.producer_run()
            == (
                release_record.producer_run_id,
                release_record.producer_run_attempt
            ),
        "package attestation differs from the exact producer run in its release record"
    );
    let publisher_workflow = manifest.publisher_workflow.as_str();
    let publisher_dispatcher_id = package_workflow_owner_id(
        api,
        &publisher.repository,
        publisher_workflow,
        &manifest.publisher_sha,
    )?;
    let publisher_run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}/attempts/{}",
        publisher.repository, manifest.publisher_run_id, manifest.publisher_run_attempt
    ))?;
    validate_native_package_publisher_run(
        api,
        &publisher,
        source_default_branch,
        &release_record,
        publisher_dispatcher_id,
        &publisher_run,
    )?;

    Ok(VerifiedNativeClientPackage {
        implementation_sha: signer_sha.to_owned(),
        implementation_version,
        loader_action_sha: loader_action.sha.clone(),
        binary_source_sha,
        binary_version,
        protocol: manifest.protocol,
        package_publisher_workflow: publisher_workflow.to_owned(),
        package_publisher_branch: manifest.publisher_branch,
        package_publisher_sha: manifest.publisher_sha,
        package_publisher_run_id: manifest.publisher_run_id,
        package_publisher_run_attempt: manifest.publisher_run_attempt,
        package_producer_workflow: manifest.producer_workflow,
        package_producer_branch: manifest.source_branch,
        package_producer_run_id: manifest.producer_run_id,
        package_producer_run_attempt: manifest.producer_run_attempt,
        package,
    })
}

/// Qualify a scratch package only when the authenticated Server instance
/// explicitly configures its destination. This path also requires the owner
/// selected caller policy. The immutable Action mapping selects the package;
/// dispatch probes may additionally assert an exact publication record.
// Preserve separate authority inputs so each boundary is checked explicitly.
#[allow(clippy::too_many_arguments)]
pub fn verify_native_client_package_scratch(
    api: &GitHub,
    instance: &crate::instance_config::InstanceConfig,
    acceptable: &crate::instance_config::AcceptableClients,
    signer_sha: &str,
    loader_action: &PinnedPackageAction,
    expected_protocol: &str,
    publication: Option<&ScratchPackagePublication>,
) -> Result<VerifiedNativeClientPackage> {
    crate::policy::validate_repository(&acceptable.repository)?;
    ensure!(acceptable.id > 0, "Client repository ID is invalid");
    crate::policy::validate_sha(signer_sha)?;
    validate_pinned_package_action(loader_action, &acceptable.repository)?;
    ensure!(
        expected_protocol == NATIVE_CLIENT_PROTOCOL,
        "requested Client protocol is not supported by this Server"
    );
    let destination_config = configured_scratch_package_repository(instance)?;
    crate::policy::validate_repository(&destination_config.repository)?;
    crate::config::validate_branch(&destination_config.default_branch)?;

    let source = TrustedPublisher {
        repository: acceptable.repository.clone(),
        repository_id: acceptable.id,
    };
    let destination = TrustedPublisher {
        repository: destination_config.repository.clone(),
        repository_id: destination_config.id,
    };
    let (_, manifest) = fetch_native_client_action_manifest(api, loader_action)?;
    let mapped_publication = manifest.scratch_publication();
    let publication = publication.unwrap_or(&mapped_publication);
    validate_scratch_publication_repositories(publication, &source, &destination)?;
    ensure!(
        publication.producer_run_id > 0
            && publication.producer_run_attempt == 1
            && publication.publisher_run_id > 0
            && publication.publisher_run_attempt == 1
            && publication.release_id > 0
            && publication.asset_id > 0
            && publication.asset_size > 0
            && publication.asset_size <= MAX_ASSET_BYTES,
        "scratch publication record has invalid run or release identity"
    );
    crate::config::validate_branch(&publication.source_branch)?;
    crate::policy::validate_sha(&publication.source_sha)?;
    crate::policy::validate_sha(&publication.publisher_sha)?;
    ensure!(
        publication.asset_sha256.len() == 64
            && publication
                .asset_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "scratch publication record has an invalid asset digest"
    );

    let source_repository: Value = api.get(&format!("/repos/{}", source.repository))?;
    validate_remote_repository_identity(&source_repository, &source)?;
    let source_default_branch = source_repository["default_branch"]
        .as_str()
        .context("scratch Client package source has no default branch")?;
    crate::config::validate_branch(source_default_branch)?;
    let source_repository = crate::config::Repository {
        repository: source.repository.clone(),
        id: source.repository_id,
        default_branch: source_default_branch.to_owned(),
    };
    ensure!(
        publication.publisher_workflow == NATIVE_PACKAGE_PUBLISHER_WORKFLOW
            && publication.publisher_branch == source_default_branch,
        "scratch package publisher workflow or branch differs from the configured Client source"
    );
    let publisher_run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}/attempts/{}",
        source.repository, publication.publisher_run_id, publication.publisher_run_attempt
    ))?;
    validate_scratch_package_completed_writer_run(
        &publisher_run,
        &source_repository,
        &publication.publisher_workflow,
        &publication.publisher_sha,
        publication.publisher_run_id,
        publication.publisher_run_attempt,
        instance.identities.owner.id,
    )?;
    let destination_repository: Value = api.get(&format!("/repos/{}", destination.repository))?;
    validate_remote_repository_identity(&destination_repository, &destination)?;
    let destination_default_branch = destination_repository["default_branch"]
        .as_str()
        .context("scratch destination default branch is missing")?;
    ensure!(
        destination_default_branch == destination_config.default_branch
            && destination_repository["owner"]["id"].as_u64()
                == Some(instance.identities.repository_owner.id),
        "scratch destination differs from the authenticated Server instance"
    );

    // The request attestation and configured owner-only scratch caller bind this
    // unreleased implementation SHA. Its version is recorded for diagnostics;
    // stable deployment ranges remain enforced only by the normal verifier.
    let signer_cargo: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={signer_sha}",
        source.repository
    ))?;
    let implementation_version = source_version_with_prerelease(&signer_cargo, true)?;

    let binary_source_sha = manifest.validate(
        ClientPackageChannel::Scratch,
        &source,
        &destination,
        expected_protocol,
        Some(source_default_branch),
    )?;
    ensure!(
        binary_source_sha == publication.source_sha,
        "scratch publication source differs from the pinned action mapping"
    );
    let binary_version =
        Version::parse(&manifest.version).context("scratch package version is invalid SemVer")?;
    ensure!(
        !binary_version.pre.is_empty() && publication.tag == format!("v{binary_version}"),
        "scratch package must use the exact canonical prerelease version and tag"
    );
    ensure!(
        publication.asset_size <= manifest.max_bytes,
        "scratch package asset exceeds its fixed source manifest limit"
    );
    ensure!(
        manifest.source_branch == publication.source_branch
            && manifest.source_default_branch == source_default_branch
            && manifest.target_branch == destination_default_branch
            && manifest.tag == publication.tag
            && manifest.release_id == publication.release_id
            && manifest.asset_id == publication.asset_id
            && manifest.asset_name == PACKAGE_BINARY_NAME
            && manifest.asset_size == publication.asset_size
            && manifest.asset_sha256 == publication.asset_sha256
            && manifest.producer_run_id == publication.producer_run_id
            && manifest.producer_run_attempt == publication.producer_run_attempt
            && manifest.publisher_workflow == publication.publisher_workflow
            && manifest.publisher_sha == publication.publisher_sha
            && manifest.publisher_branch == publication.publisher_branch
            && manifest.publisher_run_id == publication.publisher_run_id
            && manifest.publisher_run_attempt == publication.publisher_run_attempt,
        "scratch package mapping differs from the explicit publication record"
    );
    let source_manifest_bytes = fetch_source_package_manifest(
        api,
        &source.repository,
        &binary_source_sha,
        &manifest.source_manifest_path,
    )?;
    let source_manifest: SourcePackageManifest = serde_json::from_slice(&source_manifest_bytes)
        .context("scratch binary source package manifest is invalid JSON")?;
    validate_client_source_package_manifest(
        &manifest,
        &source_manifest,
        &source_manifest_bytes,
        &binary_version,
        expected_protocol,
    )?;
    let source_cargo: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={binary_source_sha}",
        source.repository
    ))?;
    ensure!(
        source_version_with_prerelease(&source_cargo, true)? == binary_version,
        "scratch package version differs from its source Cargo manifest"
    );

    let asset_name = &manifest.asset_name;
    let release: Value = api.get(&format!(
        "/repos/{}/releases/{}",
        destination.repository, publication.release_id
    ))?;
    let release_record = parse_native_package_release_record(
        release["body"]
            .as_str()
            .context("scratch release publication record is missing")?,
    )?;
    validate_client_package_manifest_record(&manifest, &release_record)?;
    ensure!(
        release["id"].as_u64() == Some(publication.release_id)
            && release["tag_name"].as_str() == Some(publication.tag.as_str())
            && release["target_commitish"].as_str() == Some(destination_default_branch)
            && release["draft"] == false
            && release["prerelease"] == true
            && release["immutable"] == true,
        "scratch package release is not the exact immutable prerelease"
    );
    let assets = release["assets"]
        .as_array()
        .filter(|assets| assets.len() == 1)
        .context("scratch package release must contain exactly one asset")?;
    let asset = &assets[0];
    ensure!(
        asset["id"].as_u64() == Some(publication.asset_id)
            && asset["name"].as_str() == Some(asset_name.as_str())
            && asset["state"] == "uploaded"
            && asset["size"].as_u64() == Some(publication.asset_size)
            && asset["digest"] == format!("sha256:{}", publication.asset_sha256),
        "scratch package release asset differs from the publication record"
    );
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        destination.repository, publication.tag
    ))?;
    ensure!(
        tag_ref["ref"].as_str() == Some(format!("refs/tags/{}", publication.tag).as_str()),
        "scratch package tag ref identity is invalid"
    );
    let tag_commit = match tag_ref["object"]["type"].as_str() {
        Some("commit") => tag_ref["object"]["sha"]
            .as_str()
            .context("scratch package tag commit is missing")?
            .to_owned(),
        Some("tag") => {
            let object_sha = tag_ref["object"]["sha"]
                .as_str()
                .context("scratch package annotated tag object is missing")?;
            crate::policy::validate_sha(object_sha)?;
            let tag_object: Value = api.get(&format!(
                "/repos/{}/git/tags/{object_sha}",
                destination.repository
            ))?;
            ensure!(
                tag_object["object"]["type"] == "commit",
                "scratch package tag does not point directly to a commit"
            );
            tag_object["object"]["sha"]
                .as_str()
                .context("scratch package tag commit is missing")?
                .to_owned()
        }
        _ => anyhow::bail!("scratch package tag object type is invalid"),
    };
    crate::policy::validate_sha(&tag_commit)?;
    let compare: Value = api.get(&format!(
        "/repos/{}/compare/{}...{}",
        destination.repository, tag_commit, destination_default_branch
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical"))
            && compare["base_commit"]["sha"].as_str() == Some(tag_commit.as_str())
            && compare["merge_base_commit"]["sha"].as_str() == Some(tag_commit.as_str())
            && compare["ahead_by"].as_u64().is_some()
            && compare["behind_by"].as_u64() == Some(0),
        "scratch package release tag is not reachable from the integration default branch"
    );

    let resolved = ResolvedRelease {
        publisher: destination.clone(),
        implementation_sha: binary_source_sha.clone(),
        source_sha: binary_source_sha.clone(),
        version: binary_version.clone(),
        tag: publication.tag.clone(),
        release_id: publication.release_id,
        release_body: None,
        asset: ResolvedAsset {
            component: manifest.component.clone(),
            platform: "linux-x86_64".to_owned(),
            id: publication.asset_id,
            name: asset_name.clone(),
            size: publication.asset_size,
            sha256: publication.asset_sha256.clone(),
        },
    };
    let bytes = api.download(
        &format!(
            "/repos/{}/releases/assets/{}",
            destination.repository, publication.asset_id
        ),
        usize::try_from(publication.asset_size)
            .context("scratch asset size does not fit this platform")?,
    )?;
    ensure!(
        bytes.len() as u64 == publication.asset_size
            && crate::hex_encode(Sha256::digest(&bytes)) == publication.asset_sha256,
        "scratch package bytes differ from the publication record"
    );
    let package = verify_downloaded_release_from(
        api,
        DownloadedAsset {
            release: resolved,
            bytes,
        },
        &source,
        &manifest.producer_workflow,
        &manifest.source_branch,
    )?;
    ensure!(
        package.producer_run() == (manifest.producer_run_id, manifest.producer_run_attempt),
        "scratch package attestation differs from the exact producer run mapping"
    );

    Ok(VerifiedNativeClientPackage {
        implementation_sha: signer_sha.to_owned(),
        implementation_version,
        loader_action_sha: loader_action.sha.clone(),
        binary_source_sha,
        binary_version,
        protocol: manifest.protocol,
        package_publisher_workflow: manifest.publisher_workflow,
        package_publisher_branch: manifest.publisher_branch,
        package_publisher_sha: manifest.publisher_sha,
        package_publisher_run_id: manifest.publisher_run_id,
        package_publisher_run_attempt: manifest.publisher_run_attempt,
        package_producer_workflow: manifest.producer_workflow,
        package_producer_branch: manifest.source_branch,
        package_producer_run_id: manifest.producer_run_id,
        package_producer_run_attempt: manifest.producer_run_attempt,
        package,
    })
}

fn validate_remote_repository_identity(
    repository: &Value,
    expected: &TrustedPublisher,
) -> Result<()> {
    let expected_owner = expected
        .repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .context("repository owner is invalid")?;
    ensure!(
        repository["id"].as_u64() == Some(expected.repository_id)
            && repository["full_name"].as_str() == Some(expected.repository.as_str())
            && repository["owner"]["id"].as_u64().is_some_and(|id| id > 0)
            && repository["owner"]["login"].as_str() == Some(expected_owner),
        "repository identity mismatch"
    );
    Ok(())
}

fn validate_scratch_publication_repositories(
    publication: &ScratchPackagePublication,
    source: &TrustedPublisher,
    destination: &TrustedPublisher,
) -> Result<()> {
    ensure!(
        publication.source_repository == source.repository
            && publication.source_repository_id == source.repository_id
            && publication.destination_repository == destination.repository
            && publication.destination_repository_id == destination.repository_id,
        "scratch publication record does not match the configured source and destination"
    );
    Ok(())
}

fn configured_scratch_package_repository(
    instance: &crate::instance_config::InstanceConfig,
) -> Result<&crate::config::Repository> {
    instance
        .scratch_package_repository
        .as_ref()
        .context("scratch package acceptance is not enabled by the Server instance")
}

fn validate_pinned_package_action(
    action: &PinnedPackageAction,
    expected_repository: &str,
) -> Result<()> {
    crate::policy::validate_repository(&action.repository)?;
    validate_package_action_path(&action.path)?;
    crate::policy::validate_sha(&action.sha)?;
    ensure!(
        action.repository == expected_repository,
        "Client package action repository differs from the configured Client repository"
    );
    Ok(())
}

fn fetch_native_client_action_manifest(
    api: &GitHub,
    action: &PinnedPackageAction,
) -> Result<(Vec<u8>, NativeClientPackageManifest)> {
    validate_pinned_package_action(action, &action.repository)?;
    let manifest_path = action.manifest_path();
    let encoded_manifest_path = encode_repository_path(&manifest_path);
    let response: Value = api.get(&format!(
        "/repos/{}/contents/{encoded_manifest_path}?ref={}",
        action.repository, action.sha
    ))?;
    let bytes = source_file_bytes(&response, &manifest_path)?;
    let manifest = NativeClientPackageManifest::parse(&bytes)
        .context("pinned Client package action manifest is invalid")?;
    Ok((bytes, manifest))
}

fn fetch_source_package_manifest(
    api: &GitHub,
    repository: &str,
    source_sha: &str,
    manifest_path: &str,
) -> Result<Vec<u8>> {
    crate::policy::validate_repository(repository)?;
    crate::policy::validate_sha(source_sha)?;
    validate_source_package_manifest_path(manifest_path)?;
    let encoded_manifest_path = encode_repository_path(manifest_path);
    let response: Value = api.get(&format!(
        "/repos/{repository}/contents/{encoded_manifest_path}?ref={source_sha}"
    ))?;
    source_file_bytes(&response, manifest_path)
}

fn validate_client_source_package_manifest(
    action_manifest: &NativeClientPackageManifest,
    source_manifest: &SourcePackageManifest,
    source_manifest_bytes: &[u8],
    version: &Version,
    expected_protocol: &str,
) -> Result<()> {
    source_manifest.validate(version, expected_protocol, &action_manifest.source_sha)?;
    let source_asset = source_manifest
        .assets
        .get("linux-x86_64")
        .context("binary source package manifest has no linux-x86_64 asset")?;
    let publisher_workflow = source_manifest
        .publisher_workflow
        .as_deref()
        .context("binary source package manifest has no publisher workflow")?;
    ensure!(
        source_manifest.schema_version == 2
            && action_manifest.source_manifest_sha256
                == crate::hex_encode(Sha256::digest(source_manifest_bytes))
            && action_manifest.component == source_manifest.component
            && action_manifest.protocol == source_manifest.protocol
            && action_manifest.version == source_manifest.version
            && action_manifest.max_bytes == source_manifest.max_bytes
            && action_manifest.asset_name == *source_asset
            && action_manifest.producer_workflow == source_manifest.producer_workflow
            && action_manifest.publisher_workflow == publisher_workflow,
        "Client package action mapping differs from the exact binary-source manifest"
    );
    Ok(())
}

fn validate_client_package_manifest_record(
    manifest: &NativeClientPackageManifest,
    record: &NativePackageReleaseRecord,
) -> Result<()> {
    crate::policy::validate_sha(&manifest.publisher_sha)?;
    ensure!(
        record.source_sha == manifest.source_sha
            && record.source_manifest_sha256 == manifest.source_manifest_sha256
            && record.producer_workflow == manifest.producer_workflow
            && record.producer_run_id == manifest.producer_run_id
            && record.producer_run_attempt == manifest.producer_run_attempt
            && record.publisher_workflow == manifest.publisher_workflow
            && record.publisher_sha == manifest.publisher_sha
            && record.publisher_run_id == manifest.publisher_run_id
            && record.publisher_run_attempt == manifest.publisher_run_attempt
            && record.tag == manifest.tag
            && record.asset_name == manifest.asset_name
            && record.asset_size == manifest.asset_size
            && record.asset_sha256 == manifest.asset_sha256,
        "Client package action mapping differs from the immutable release publication record"
    );
    Ok(())
}

const NATIVE_CLIENT_PROTOCOL: &str = "securefix-native-request/v1";

fn resolve_native_client_implementation(
    api: &GitHub,
    publisher: &TrustedPublisher,
    signer_sha: &str,
    acceptable_versions: &VersionReq,
    source_default_branch: &str,
) -> Result<Version> {
    crate::policy::validate_repository(&publisher.repository)?;
    ensure!(
        publisher.repository_id > 0,
        "Client repository ID is invalid"
    );
    crate::policy::validate_sha(signer_sha)?;

    let repository: Value = api.get(&format!("/repos/{}", publisher.repository))?;
    let (owner_name, _) = publisher
        .repository
        .split_once('/')
        .context("Client repository owner is invalid")?;
    ensure!(
        repository["id"].as_u64() == Some(publisher.repository_id)
            && repository["full_name"].as_str() == Some(publisher.repository.as_str())
            && repository["owner"]["id"].as_u64().is_some_and(|id| id > 0)
            && repository["owner"]["login"].as_str() == Some(owner_name)
            && repository["default_branch"].as_str() == Some(source_default_branch),
        "Client repository identity mismatch"
    );
    let source: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={signer_sha}",
        publisher.repository
    ))?;
    let version = source_version(&source)?;
    ensure!(
        acceptable_versions.matches(&version),
        "Client implementation version is outside the accepted range"
    );
    let tag = format!("v{version}");
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{tag}",
        publisher.repository
    ))?;
    ensure!(
        tag_ref["ref"].as_str() == Some(format!("refs/tags/{tag}").as_str())
            && tag_ref["object"]["type"] == "commit"
            && tag_ref["object"]["sha"].as_str() == Some(signer_sha),
        "Client implementation tag is not a lightweight ref to the attested signer revision"
    );
    let release: Value = api.get(&format!(
        "/repos/{}/releases/tags/{tag}",
        publisher.repository
    ))?;
    ensure!(
        release["id"].as_u64().is_some_and(|id| id > 0)
            && release["tag_name"].as_str() == Some(tag.as_str())
            && release["target_commitish"].as_str() == Some(signer_sha)
            && release["draft"] == false
            && release["prerelease"] == false
            && release["immutable"] == true,
        "Client implementation release is not published, immutable, and bound to its signer revision"
    );
    Ok(version)
}

fn validate_package_workflow(path: &str) -> Result<()> {
    ensure!(
        path.starts_with(".github/workflows/")
            && path.ends_with(".yml")
            && path.len() <= 200
            && !path.contains("..")
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "Client package producer workflow path is invalid"
    );
    Ok(())
}

fn package_workflow_owner_id(api: &GitHub, repository: &str, path: &str, sha: &str) -> Result<u64> {
    crate::policy::validate_repository(repository)?;
    crate::policy::validate_sha(sha)?;
    validate_package_workflow(path)?;
    let bytes = api.content_uncached(repository, path, sha)?;
    package_workflow_owner_id_from_bytes(&bytes)
}

fn package_workflow_owner_id_from_bytes(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PACKAGE_WORKFLOW_BYTES,
        "package publisher workflow is empty or exceeds its size limit"
    );
    let workflow: serde_yaml::Value =
        serde_yaml::from_slice(bytes).context("package publisher workflow is invalid YAML")?;
    let env_key = serde_yaml::Value::String("env".to_owned());
    let owner_key = serde_yaml::Value::String("SECUREFIX_PACKAGE_OWNER_ID".to_owned());
    let workflow_env = workflow
        .as_mapping()
        .and_then(|mapping| mapping.get(&env_key))
        .and_then(serde_yaml::Value::as_mapping)
        .context("package publisher workflow has no workflow-level env mapping")?;
    let raw_owner = workflow_env
        .get(&owner_key)
        .and_then(serde_yaml::Value::as_str)
        .context("package publisher workflow has no literal owner ID")?;
    let owner_id = parse_positive_decimal(raw_owner)?;
    ensure!(
        owner_id.to_string() == raw_owner,
        "package publisher workflow owner ID is not canonical"
    );

    fn collect_owner_overrides(
        value: &serde_yaml::Value,
        env_key: &serde_yaml::Value,
        owner_key: &serde_yaml::Value,
        declarations: &mut Vec<String>,
    ) -> Result<()> {
        match value {
            serde_yaml::Value::Mapping(mapping) => {
                if let Some(env) = mapping.get(env_key).and_then(serde_yaml::Value::as_mapping)
                    && let Some(owner) = env.get(owner_key)
                {
                    declarations.push(
                        owner
                            .as_str()
                            .context("package publisher workflow overrides its owner ID")?
                            .to_owned(),
                    );
                }
                for child in mapping.values() {
                    collect_owner_overrides(child, env_key, owner_key, declarations)?;
                }
            }
            serde_yaml::Value::Sequence(items) => {
                for child in items {
                    collect_owner_overrides(child, env_key, owner_key, declarations)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut declarations = Vec::new();
    collect_owner_overrides(&workflow, &env_key, &owner_key, &mut declarations)?;
    ensure!(
        declarations.len() == 1 && declarations[0] == raw_owner,
        "package publisher workflow has duplicate or overridden owner ID declarations"
    );
    Ok(owner_id)
}

fn validate_native_package_publisher_run(
    api: &GitHub,
    publisher: &TrustedPublisher,
    default_branch: &str,
    record: &NativePackageReleaseRecord,
    dispatcher_id: u64,
    run: &Value,
) -> Result<()> {
    ensure!(dispatcher_id > 0, "package publisher owner ID is invalid");
    let repository: Value = api.get(&format!("/repos/{}", publisher.repository))?;
    validate_remote_repository_identity(&repository, publisher)?;
    let repository_owner_id = repository["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("package publisher repository owner ID is invalid")?;
    ensure!(
        repository["default_branch"].as_str() == Some(default_branch),
        "package publisher repository default branch changed"
    );
    let (owner_login, _) = publisher
        .repository
        .split_once('/')
        .context("package publisher repository owner is invalid")?;
    ensure!(
        run["id"].as_u64() == Some(record.publisher_run_id)
            && run["run_attempt"].as_u64() == Some(record.publisher_run_attempt)
            && run["run_attempt"].as_u64() == Some(1)
            && run["repository"]["id"].as_u64() == Some(publisher.repository_id)
            && run["repository"]["full_name"].as_str() == Some(publisher.repository.as_str())
            && run["repository"]["owner"]["id"].as_u64() == Some(repository_owner_id)
            && run["repository"]["owner"]["login"].as_str() == Some(owner_login)
            && run["head_repository"]["id"].as_u64() == Some(publisher.repository_id)
            && run["head_repository"]["full_name"].as_str() == Some(publisher.repository.as_str())
            && run["path"].as_str() == Some(record.publisher_workflow.as_str())
            && run["event"] == "workflow_dispatch"
            && run["head_branch"].as_str() == Some(default_branch)
            && run["head_sha"].as_str() == Some(record.publisher_sha.as_str())
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(dispatcher_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(dispatcher_id)
            && run["triggering_actor"]["type"] == "User",
        "package publisher run is not the successful protected owner-dispatched workflow"
    );
    Ok(())
}

/// Resolve the release whose implementation is already selected by a trusted
/// caller's full-SHA pin. This makes exactly four read-only API requests.
///
/// The initial contract requires the defining implementation revision to be
/// the source commit that contains `Cargo.toml`. It accepts one uploaded raw
/// executable asset per release; multi-platform release sets are intentionally
/// not resolved by this API yet.
pub fn resolve_release(
    api: &GitHub,
    publisher: &TrustedPublisher,
    implementation_sha: &str,
    expected_asset: &ExpectedAsset,
    acceptable_versions: &VersionReq,
) -> Result<ResolvedRelease> {
    crate::policy::validate_repository(&publisher.repository)?;
    ensure!(
        publisher.repository_id > 0,
        "publisher repository ID is invalid"
    );
    crate::policy::validate_sha(implementation_sha)?;
    validate_expected_asset(expected_asset)?;

    let repository: Value = api.get(&format!("/repos/{}", publisher.repository))?;
    ensure!(
        repository["id"].as_u64() == Some(publisher.repository_id)
            && repository["full_name"].as_str() == Some(publisher.repository.as_str()),
        "publisher repository identity mismatch"
    );
    let (owner_name, _) = publisher
        .repository
        .split_once('/')
        .context("publisher repository owner is invalid")?;
    ensure!(
        repository["owner"]["id"].as_u64().is_some_and(|id| id > 0)
            && repository["owner"]["login"].as_str() == Some(owner_name),
        "publisher owner identity mismatch"
    );

    // The ref is a complete lowercase commit SHA selected by the trusted pin.
    let manifest: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={implementation_sha}",
        publisher.repository
    ))?;
    let version = source_version(&manifest)?;
    ensure!(
        acceptable_versions.matches(&version),
        "published package version is outside the accepted range"
    );
    let source_sha = implementation_sha.to_owned();
    let tag = format!("v{version}");

    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{tag}",
        publisher.repository
    ))?;
    ensure!(
        tag_ref["ref"].as_str() == Some(format!("refs/tags/{tag}").as_str())
            && tag_ref["object"]["type"] == "commit"
            && tag_ref["object"]["sha"].as_str() == Some(implementation_sha),
        "package tag is not a lightweight ref to the pinned source commit"
    );

    let release: Value = api.get(&format!(
        "/repos/{}/releases/tags/{tag}",
        publisher.repository
    ))?;
    let release_id = release["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("package release ID is missing or invalid")?;
    ensure!(
        release["tag_name"].as_str() == Some(tag.as_str())
            && release["target_commitish"].as_str() == Some(source_sha.as_str()),
        "package release does not identify the pinned source tag"
    );
    ensure!(
        release["draft"] == false && release["immutable"] == true,
        "package release is not published and immutable"
    );
    ensure!(
        release["prerelease"] == false,
        "package release is a prerelease"
    );

    let assets = release["assets"]
        .as_array()
        .context("package release asset list is missing")?;
    ensure!(
        assets.len() == 1,
        "package release must contain exactly one raw executable asset"
    );
    let asset = &assets[0];
    let asset_id = asset["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("package asset ID is missing or invalid")?;
    let name = asset["name"]
        .as_str()
        .context("package asset name is missing")?;
    ensure!(name == expected_asset.name, "package asset name mismatch");
    ensure!(
        asset["state"].as_str() == Some("uploaded"),
        "package asset upload is incomplete"
    );
    let size = asset["size"]
        .as_u64()
        .context("package asset size is missing or invalid")?;
    ensure!(
        size > 0 && size <= MAX_ASSET_BYTES,
        "package asset size is outside the supported bounds"
    );
    let digest = asset["digest"]
        .as_str()
        .context("package asset digest is missing")?;
    let sha256 = canonical_sha256_digest(digest)?;

    Ok(ResolvedRelease {
        publisher: publisher.clone(),
        implementation_sha: implementation_sha.to_owned(),
        source_sha,
        version,
        tag,
        release_id,
        release_body: release["body"].as_str().map(str::to_owned),
        asset: ResolvedAsset {
            component: expected_asset.component.clone(),
            platform: expected_asset.platform.clone(),
            id: asset_id,
            name: name.to_owned(),
            size,
            sha256,
        },
    })
}

/// Fetch the raw asset selected by a fresh metadata resolution and compare its
/// actual size and SHA-256 with GitHub's immutable-release metadata.
///
/// The downloaded bytes remain untrusted data until a host independently
/// verifies producer/source/run/signature evidence before execution.
pub fn download_release_asset(
    api: &GitHub,
    publisher: &TrustedPublisher,
    implementation_sha: &str,
    expected_asset: &ExpectedAsset,
    acceptable_versions: &VersionReq,
) -> Result<DownloadedAsset> {
    download_release_asset_bounded(
        api,
        publisher,
        implementation_sha,
        expected_asset,
        acceptable_versions,
        MAX_ASSET_BYTES,
    )
}

fn download_release_asset_bounded(
    api: &GitHub,
    publisher: &TrustedPublisher,
    implementation_sha: &str,
    expected_asset: &ExpectedAsset,
    acceptable_versions: &VersionReq,
    max_asset_bytes: u64,
) -> Result<DownloadedAsset> {
    ensure!(
        max_asset_bytes > 0 && max_asset_bytes <= MAX_ASSET_BYTES,
        "package asset limit is outside the supported bounds"
    );
    let release = resolve_release(
        api,
        publisher,
        implementation_sha,
        expected_asset,
        acceptable_versions,
    )?;
    ensure!(
        release.asset.size <= max_asset_bytes,
        "package asset exceeds the source manifest limit"
    );
    let max_size = usize::try_from(release.asset.size)
        .context("package asset size does not fit this platform")?;
    let path = format!(
        "/repos/{}/releases/assets/{}",
        release.publisher.repository, release.asset.id
    );
    let bytes = api.download(&path, max_size)?;
    ensure!(
        bytes.len() as u64 == release.asset.size,
        "downloaded package asset size differs from release metadata"
    );
    let actual_digest = crate::hex_encode(Sha256::digest(&bytes));
    ensure!(
        actual_digest == release.asset.sha256,
        "downloaded package asset digest differs from release metadata"
    );
    Ok(DownloadedAsset { release, bytes })
}

/// Resolve, download, and qualify one stable release before returning bytes to a
/// package consumer. The expected workflow and branch must come from trusted
/// deployment/source configuration, never from release metadata.
pub fn download_verified_release(
    api: &GitHub,
    publisher: &TrustedPublisher,
    implementation_sha: &str,
    expected_asset: &ExpectedAsset,
    acceptable_versions: &VersionReq,
    publisher_workflow: &str,
    publisher_branch: &str,
) -> Result<VerifiedPackage> {
    download_verified_release_bounded(
        api,
        publisher,
        implementation_sha,
        expected_asset,
        acceptable_versions,
        publisher_workflow,
        publisher_branch,
        MAX_ASSET_BYTES,
    )
}

// These independent package and publisher constraints are validated at this boundary.
#[allow(clippy::too_many_arguments)]
fn download_verified_release_bounded(
    api: &GitHub,
    publisher: &TrustedPublisher,
    implementation_sha: &str,
    expected_asset: &ExpectedAsset,
    acceptable_versions: &VersionReq,
    publisher_workflow: &str,
    publisher_branch: &str,
    max_asset_bytes: u64,
) -> Result<VerifiedPackage> {
    crate::config::validate_branch(publisher_branch)?;
    let downloaded = download_release_asset_bounded(
        api,
        publisher,
        implementation_sha,
        expected_asset,
        acceptable_versions,
        max_asset_bytes,
    )?;
    verify_downloaded_release(api, downloaded, publisher_workflow, publisher_branch)
}

fn verify_downloaded_release(
    api: &GitHub,
    downloaded: DownloadedAsset,
    publisher_workflow: &str,
    publisher_branch: &str,
) -> Result<VerifiedPackage> {
    let attestation_publisher = downloaded.release().publisher.clone();
    verify_downloaded_release_from(
        api,
        downloaded,
        &attestation_publisher,
        publisher_workflow,
        publisher_branch,
    )
}

fn verify_downloaded_release_from(
    api: &GitHub,
    downloaded: DownloadedAsset,
    attestation_publisher: &TrustedPublisher,
    publisher_workflow: &str,
    publisher_branch: &str,
) -> Result<VerifiedPackage> {
    verify_downloaded_release_from_with_actor(
        api,
        downloaded,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
        None,
    )
}

fn verify_downloaded_release_from_with_actor(
    api: &GitHub,
    downloaded: DownloadedAsset,
    attestation_publisher: &TrustedPublisher,
    publisher_workflow: &str,
    publisher_branch: &str,
    expected_actor_id: Option<u64>,
) -> Result<VerifiedPackage> {
    let release = downloaded.release();
    let repository = &attestation_publisher.repository;
    let digest = &release.asset.sha256;
    let attestation_response: Value = api.get(&format!(
        "/repos/{repository}/attestations/sha256:{digest}?per_page=100"
    ))?;
    let bundle_bytes = crate::attestation::public_bundles(
        &attestation_response,
        attestation_publisher.repository_id,
    )?;
    let mut bundle = tempfile::Builder::new().suffix(".jsonl").tempfile()?;
    std::io::Write::write_all(&mut bundle, &bundle_bytes)?;
    let mut subject = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut subject, downloaded.bytes())?;
    let source_ref = format!("refs/heads/{publisher_branch}");
    let verified = crate::attestation::verify_with_gh(
        subject.path(),
        bundle.path(),
        crate::attestation::VerifyRequest {
            repository,
            signer_repository: repository,
            signer_workflow: publisher_workflow,
            signer_sha: &release.source_sha,
            source: Some((&release.source_sha, &source_ref)),
        },
    )?;
    let (producer_run_id, producer_run_attempt, producer_owner_id) = validate_provenance_result(
        &verified,
        release,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
    )?;
    let run: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{producer_run_id}/attempts/{producer_run_attempt}"
    ))?;
    validate_publisher_run_with_actor(
        &run,
        release,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
        producer_run_id,
        producer_run_attempt,
        producer_owner_id,
        expected_actor_id,
    )?;
    Ok(VerifiedPackage {
        asset: downloaded,
        producer_run_id,
        producer_run_attempt,
    })
}

fn validate_provenance_result(
    verified: &Value,
    release: &ResolvedRelease,
    attestation_publisher: &TrustedPublisher,
    publisher_workflow: &str,
    publisher_branch: &str,
) -> Result<(u64, u64, u64)> {
    let results = verified
        .as_array()
        .filter(|results| results.len() == 1)
        .context("attestation verifier must return exactly one result")?;
    let result = &results[0]["verificationResult"];
    let certificate = &result["signature"]["certificate"];
    let statement = &result["statement"];
    let source_ref = format!("refs/heads/{publisher_branch}");
    let signer = format!(
        "https://github.com/{}/{publisher_workflow}@{source_ref}",
        attestation_publisher.repository
    );
    let owner = attestation_publisher
        .repository
        .split_once('/')
        .context("publisher repository owner is invalid")?
        .0;
    let owner_id = certificate["sourceRepositoryOwnerIdentifier"]
        .as_str()
        .context("attestation publisher owner ID is missing")?
        .parse::<u64>()
        .context("attestation publisher owner ID is invalid")?;
    ensure!(owner_id > 0, "attestation publisher owner ID is invalid");
    ensure!(
        certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["runnerEnvironment"] == "github-hosted"
            && certificate["subjectAlternativeName"] == signer
            && certificate["buildSignerURI"] == signer
            && certificate["buildSignerDigest"] == release.source_sha
            && certificate["githubWorkflowRepository"] == attestation_publisher.repository
            && certificate["githubWorkflowSHA"] == release.source_sha
            && certificate["githubWorkflowRef"] == source_ref
            && certificate["githubWorkflowTrigger"] == "workflow_dispatch"
            && certificate["buildConfigURI"] == signer
            && certificate["buildConfigDigest"] == release.source_sha
            && certificate["buildTrigger"] == "workflow_dispatch"
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", attestation_publisher.repository)
            && certificate["sourceRepositoryDigest"] == release.source_sha
            && certificate["sourceRepositoryRef"] == source_ref
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                == Some(attestation_publisher.repository_id)
            && certificate["sourceRepositoryOwnerURI"] == format!("https://github.com/{owner}"),
        "package attestation certificate does not match the configured publisher workflow and source"
    );
    // The signed certificate is authority for the run identity; SLSA invocation
    // metadata is producer-controlled and is intentionally ignored here.
    let invocation = certificate["runInvocationURI"]
        .as_str()
        .context("package attestation run invocation is missing")?;
    let (run_id, run_attempt) =
        parse_run_invocation(invocation, &attestation_publisher.repository)?;
    let subject = statement["subject"]
        .as_array()
        .filter(|subjects| subjects.len() == 1)
        .context("package attestation must identify exactly one subject")?;
    ensure!(
        statement["predicateType"] == "https://slsa.dev/provenance/v1"
            && subject[0]["name"] == release.asset.name
            && subject[0]["digest"]["sha256"] == release.asset.sha256,
        "package attestation subject differs from the selected release asset"
    );
    Ok((run_id, run_attempt, owner_id))
}

fn parse_run_invocation(value: &str, repository: &str) -> Result<(u64, u64)> {
    let url = reqwest::Url::parse(value).context("package attestation run URI is invalid")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("github.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "package attestation run URI origin is invalid"
    );
    let prefix = format!("/{repository}/actions/runs/");
    let tail = url
        .path()
        .strip_prefix(&prefix)
        .context("package attestation run URI repository or path is invalid")?;
    let mut segments = tail.split('/');
    let run_id = parse_positive_decimal(segments.next().context("attested run ID is missing")?)?;
    ensure!(
        segments.next() == Some("attempts"),
        "attested run attempt path is invalid"
    );
    let run_attempt =
        parse_positive_decimal(segments.next().context("attested run attempt is missing")?)?;
    ensure!(
        segments.next().is_none(),
        "attested run URI has extra path segments"
    );
    Ok((run_id, run_attempt))
}

fn parse_positive_decimal(value: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .context("attested run identity is invalid")?;
    ensure!(
        parsed > 0 && parsed.to_string() == value,
        "attested run identity is not canonical"
    );
    Ok(parsed)
}

// Keep run, repository, workflow, and source identities independently bound.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn validate_publisher_run(
    run: &Value,
    release: &ResolvedRelease,
    attestation_publisher: &TrustedPublisher,
    publisher_workflow: &str,
    publisher_branch: &str,
    run_id: u64,
    run_attempt: u64,
    publisher_owner_id: u64,
) -> Result<()> {
    validate_publisher_run_with_actor(
        run,
        release,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
        run_id,
        run_attempt,
        publisher_owner_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_publisher_run_with_actor(
    run: &Value,
    release: &ResolvedRelease,
    attestation_publisher: &TrustedPublisher,
    publisher_workflow: &str,
    publisher_branch: &str,
    run_id: u64,
    run_attempt: u64,
    publisher_owner_id: u64,
    expected_actor_id: Option<u64>,
) -> Result<()> {
    let expected_owner = attestation_publisher
        .repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .context("publisher repository owner is invalid")?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"].as_u64() == Some(run_attempt)
            && run["repository"]["id"].as_u64() == Some(attestation_publisher.repository_id)
            && run["repository"]["owner"]["id"].as_u64() == Some(publisher_owner_id)
            && run["repository"]["owner"]["login"] == expected_owner
            && run["head_repository"]["id"].as_u64() == Some(attestation_publisher.repository_id)
            && run["path"] == publisher_workflow
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == publisher_branch
            && run["head_sha"] == release.source_sha
            && expected_actor_id
                .is_none_or(|actor_id| run["actor"]["id"].as_u64() == Some(actor_id))
            && expected_actor_id.is_none_or(|_| run["actor"]["type"] == "User")
            && expected_actor_id
                .is_none_or(|actor_id| run["triggering_actor"]["id"].as_u64() == Some(actor_id))
            && expected_actor_id.is_none_or(|_| run["triggering_actor"]["type"] == "User")
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "attested package producer run is not the successful configured source run"
    );
    Ok(())
}

fn validate_expected_asset(asset: &ExpectedAsset) -> Result<()> {
    for (label, value) in [
        ("component", asset.component.as_str()),
        ("platform", asset.platform.as_str()),
    ] {
        ensure!(
            !value.is_empty()
                && value.len() <= 100
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "expected package {label} is invalid"
        );
    }
    ensure!(
        !asset.name.is_empty()
            && asset.name.len() <= 255
            && asset.name != "."
            && asset.name != ".."
            && asset
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "expected package asset name is invalid"
    );
    Ok(())
}

fn source_version(manifest: &Value) -> Result<Version> {
    source_version_with_prerelease(manifest, false)
}

fn source_version_with_prerelease(manifest: &Value, allow_prerelease: bool) -> Result<Version> {
    ensure!(
        manifest["path"].as_str() == Some("Cargo.toml")
            && manifest["type"].as_str() == Some("file"),
        "source Cargo.toml identity is invalid"
    );
    let size = manifest["size"]
        .as_u64()
        .context("source Cargo.toml size is missing or invalid")?;
    ensure!(
        size > 0 && size <= MAX_CARGO_TOML_BYTES as u64,
        "source Cargo.toml size is outside the supported bounds"
    );
    ensure!(
        manifest["encoding"].as_str() == Some("base64"),
        "source Cargo.toml encoding is unsupported"
    );
    let encoded = manifest["content"]
        .as_str()
        .context("source Cargo.toml content is missing")?;
    ensure!(
        encoded.len() <= (MAX_CARGO_TOML_BYTES * 4 / 3) + 4096,
        "encoded source Cargo.toml exceeds size limit"
    );
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace('\n', ""))
        .context("source Cargo.toml content is invalid base64")?;
    ensure!(
        bytes.len() == size as usize,
        "source Cargo.toml size does not match decoded content"
    );
    let text = std::str::from_utf8(&bytes).context("source Cargo.toml is not UTF-8")?;
    let document = text
        .parse::<toml_edit::DocumentMut>()
        .context("source Cargo.toml is invalid TOML")?;
    let package = document
        .as_table()
        .get("package")
        .and_then(|item| item.as_table())
        .context("source Cargo.toml package table is missing or invalid")?;
    ensure!(
        package.get("name").and_then(|item| item.as_str()) == Some("securefix"),
        "source Cargo.toml package name is not securefix"
    );
    let raw_version = package
        .get("version")
        .and_then(|item| item.as_str())
        .context("source Cargo.toml package.version is missing or invalid")?;
    let version =
        Version::parse(raw_version).context("source package version is invalid SemVer")?;
    ensure!(
        version.build.is_empty()
            && version.to_string() == raw_version
            && (allow_prerelease || version.pre.is_empty()),
        "source package version must be canonical SemVer allowed by this release path"
    );
    Ok(version)
}

pub(crate) struct NativePackageReleaseSourceBinding<'a> {
    pub source_sha: &'a str,
    pub version: &'a str,
    pub producer_workflow: &'a str,
    pub publisher_workflow: &'a str,
    pub asset_name: &'a str,
    pub max_asset_bytes: u64,
    pub stable: bool,
}

pub(crate) fn validate_native_package_release_source(
    cargo_bytes: &[u8],
    manifest_bytes: &[u8],
    binding: &NativePackageReleaseSourceBinding<'_>,
) -> Result<()> {
    ensure!(
        cargo_bytes.len() <= MAX_CARGO_TOML_BYTES && manifest_bytes.len() <= 16 * 1024,
        "package source inputs exceed their bounds"
    );
    let cargo = std::str::from_utf8(cargo_bytes).context("source Cargo.toml is not UTF-8")?;
    let document = cargo
        .parse::<toml_edit::DocumentMut>()
        .context("source Cargo.toml is invalid TOML")?;
    let package = document
        .as_table()
        .get("package")
        .and_then(|item| item.as_table())
        .context("source Cargo.toml package table is missing or invalid")?;
    ensure!(
        package.get("name").and_then(|item| item.as_str()) == Some("securefix"),
        "source Cargo.toml package name is not securefix"
    );
    let cargo_version = package
        .get("version")
        .and_then(|item| item.as_str())
        .context("source Cargo.toml package.version is missing or invalid")?;
    let parsed_version =
        Version::parse(cargo_version).context("source package version is invalid")?;
    ensure!(
        parsed_version.to_string() == cargo_version
            && parsed_version.build.is_empty()
            && parsed_version.pre.is_empty() == binding.stable
            && cargo_version == binding.version,
        "source package version differs from the exact release channel or tag"
    );
    let manifest: SourcePackageManifest = serde_json::from_slice(manifest_bytes)
        .context("source package manifest is invalid JSON")?;
    manifest.validate(&parsed_version, NATIVE_CLIENT_PROTOCOL, binding.source_sha)?;
    ensure!(
        manifest.producer_workflow == binding.producer_workflow
            && manifest.producer_workflow == NATIVE_PACKAGE_PRODUCER_WORKFLOW
            && binding.publisher_workflow == NATIVE_PACKAGE_PUBLISHER_WORKFLOW
            && manifest.assets.get("linux-x86_64").map(String::as_str) == Some(binding.asset_name)
            && manifest.max_bytes == binding.max_asset_bytes,
        "source package manifest differs from the selected producer or asset contract"
    );
    ensure!(
        manifest.schema_version == 2
            && manifest
                .source_sha
                .as_deref()
                .is_none_or(|manifest_sha| manifest_sha == binding.source_sha)
            && manifest.publisher_workflow.as_deref() == Some(binding.publisher_workflow),
        "package source manifest does not bind this exact publisher and source"
    );
    Ok(())
}

/// Publish one policy-free raw executable to the configured scratch repository.
/// The source repository and release destination are authenticated independently;
/// the destination token is installation-scoped to the scratch repository.
pub fn publish_scratch_prerelease(
    source_sha: &str,
    producer_run_id: u64,
) -> Result<ScratchPackagePublication> {
    crate::policy::validate_sha(source_sha)?;
    ensure!(
        producer_run_id > 0,
        "scratch package producer run ID is invalid"
    );
    let config = crate::config::trusted()?;
    let deployment = &config.deployment;
    require_scratch_package_deployment(deployment)?;
    let source = &deployment.server;
    let destination = &deployment.integration;
    ensure!(
        source.id != destination.id,
        "package source and destination must differ"
    );
    ensure!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok(source.repository.as_str())
            && std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch")
            && std::env::var("GITHUB_RUN_ATTEMPT").as_deref() == Ok("1"),
        "scratch package publication must run from its first owner-dispatched source-repository attempt"
    );
    let writer_run_id = parse_positive_decimal(&std::env::var("GITHUB_RUN_ID")?)?;
    let writer_sha = std::env::var("GITHUB_SHA")?;
    let asset_name = PACKAGE_BINARY_NAME;
    let read_token = std::env::var("GITHUB_TOKEN").context("missing read-only GITHUB_TOKEN")?;
    ensure!(!read_token.is_empty(), "read-only GITHUB_TOKEN is empty");
    let source_api = GitHub::new("https://api.github.com", read_token)?;
    let source_repository: Value = source_api.get(&format!("/repos/{}", source.repository))?;
    ensure!(
        source_repository["id"].as_u64() == Some(source.id)
            && source_repository["full_name"] == source.repository
            && source_repository["default_branch"] == source.default_branch
            && source_repository["owner"]["id"].as_u64() == Some(deployment.repository_owner.id)
            && source_repository["owner"]["login"] == deployment.repository_owner.login,
        "package source repository identity differs from deployment configuration"
    );
    let cargo_manifest: Value = source_api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={source_sha}",
        source.repository
    ))?;
    let version = source_version_with_prerelease(&cargo_manifest, true)?;
    ensure!(
        !version.pre.is_empty(),
        "scratch package publication requires an explicit prerelease version"
    );
    let tag = format!("v{version}");
    let source_package_manifest: Value = source_api.get(&format!(
        "/repos/{}/contents/{SOURCE_BUILD_MANIFEST_PATH}?ref={source_sha}",
        source.repository,
    ))?;
    let manifest_bytes = source_file_bytes(&source_package_manifest, SOURCE_BUILD_MANIFEST_PATH)?;
    let package_manifest: SourcePackageManifest = serde_json::from_slice(&manifest_bytes)
        .context("source package manifest is invalid JSON")?;
    package_manifest.validate(&version, NATIVE_CLIENT_PROTOCOL, source_sha)?;
    ensure!(
        package_manifest.producer_workflow == PACKAGE_PRODUCER_WORKFLOW
            && package_manifest
                .assets
                .get("linux-x86_64")
                .map(String::as_str)
                == Some(asset_name),
        "source package manifest does not match the scratch publisher contract"
    );
    let producer_run: Value = source_api.get(&format!(
        "/repos/{}/actions/runs/{producer_run_id}/attempts/1",
        source.repository
    ))?;
    let producer_branch = validate_scratch_package_run(
        &producer_run,
        source,
        source_sha,
        PACKAGE_PRODUCER_WORKFLOW,
        producer_run_id,
        1,
        config.owner_id,
    )?;
    let artifact_list: Value = source_api.get(&format!(
        "/repos/{}/actions/runs/{producer_run_id}/artifacts?per_page=100",
        source.repository
    ))?;
    let (artifact_id, artifact_size, artifact_digest) =
        validate_scratch_package_artifact(&artifact_list, source, source_sha, producer_run_id)?;
    let artifact = source_api.download(
        &format!(
            "/repos/{}/actions/artifacts/{artifact_id}/zip",
            source.repository
        ),
        artifact_size,
    )?;
    ensure!(
        artifact.len() == artifact_size
            && crate::hex_encode(Sha256::digest(&artifact)) == artifact_digest,
        "producer artifact bytes differ from the exact run artifact metadata"
    );
    let (bytes, bundle_bytes) =
        parse_scratch_package_artifact(&artifact, asset_name, package_manifest.max_bytes)?;
    ensure!(
        bytes.len() as u64 <= package_manifest.max_bytes,
        "package executable exceeds its source manifest limit"
    );
    let digest = crate::hex_encode(Sha256::digest(&bytes));
    let mut binary_file = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut binary_file, &bytes)?;
    let mut bundle_file = tempfile::Builder::new().suffix(".json").tempfile()?;
    std::io::Write::write_all(&mut bundle_file, &bundle_bytes)?;
    let verified = crate::attestation::verify_with_gh(
        binary_file.path(),
        bundle_file.path(),
        crate::attestation::VerifyRequest {
            repository: &source.repository,
            signer_repository: &source.repository,
            signer_workflow: PACKAGE_PRODUCER_WORKFLOW,
            signer_sha: source_sha,
            source: Some((source_sha, &format!("refs/heads/{producer_branch}"))),
        },
    )?;
    let (run_id, run_attempt, attested_branch) = validate_scratch_package_attestation(
        &verified,
        source,
        deployment.repository_owner.id,
        source_sha,
        PACKAGE_PRODUCER_WORKFLOW,
        asset_name,
        &digest,
    )?;
    ensure!(
        run_id == producer_run_id && run_attempt == 1,
        "verified attestation is not from the explicitly selected first producer attempt"
    );
    ensure!(
        attested_branch == producer_branch,
        "producer attestation branch differs from the exact producer run"
    );
    let branch = producer_branch;
    let current_run: Value = source_api.get(&format!(
        "/repos/{}/actions/runs/{writer_run_id}",
        source.repository
    ))?;
    validate_scratch_package_writer_run(
        &current_run,
        source,
        &deployment.server.default_branch,
        &writer_sha,
        writer_run_id,
        config.owner_id,
    )?;

    let mut destination_api = GitHub::package_scratch_from_env(
        "SECUREFIX_PACKAGE_TOKEN",
        source_sha,
        &tag,
        asset_name,
        package_manifest.max_bytes,
    )?;
    let destination_repository: Value =
        destination_api.get(&format!("/repos/{}", destination.repository))?;
    ensure!(
        destination_repository["id"].as_u64() == Some(destination.id)
            && destination_repository["full_name"] == destination.repository
            && destination_repository["default_branch"] == destination.default_branch,
        "package release destination differs from the configured scratch repository"
    );
    let default_branch = destination_repository["default_branch"]
        .as_str()
        .filter(|branch| crate::config::validate_branch(branch).is_ok())
        .context("scratch release destination has no valid default branch")?;
    let releases: Vec<Value> = destination_api.paginate(&format!(
        "/repos/{}/releases?per_page=100",
        destination.repository
    ))?;
    let mut matching = releases.iter().filter(|release| release["tag_name"] == tag);
    let mut release = matching.next().cloned();
    ensure!(
        matching.next().is_none(),
        "duplicate scratch package release tag"
    );
    if release.is_none() {
        let created: Value = destination_api.post(
            &format!("/repos/{}/releases", destination.repository),
            &serde_json::json!({
                "tag_name": tag,
                "name": tag,
                "target_commitish": default_branch,
                "draft": true,
                "prerelease": true,
                "generate_release_notes": false
            }),
        )?;
        release = Some(created);
    }
    let release = release.context("scratch package release was not resolved")?;
    let release_id = release["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("scratch package release has no ID")?;
    ensure!(
        release["tag_name"] == tag
            && release["target_commitish"] == default_branch
            && release["prerelease"] == true,
        "scratch package release identity or prerelease state changed"
    );
    ensure!(
        release["draft"] == true || release["immutable"] == true,
        "existing scratch package release is neither a draft nor immutable"
    );
    destination_api.package_scratch_allow_release(release_id)?;
    let mut assets: Vec<Value> = destination_api.paginate(&format!(
        "/repos/{}/releases/{release_id}/assets?per_page=100",
        destination.repository
    ))?;
    ensure!(
        assets.len() <= 1,
        "scratch package release has unexpected assets"
    );
    if let Some(asset) = assets.first() {
        ensure!(
            asset["name"] == asset_name
                && asset["size"].as_u64() == Some(bytes.len() as u64)
                && asset["digest"] == format!("sha256:{digest}")
                && asset["state"] == "uploaded",
            "scratch package release already contains different bytes"
        );
        let asset_id = asset["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("scratch package asset has no ID")?;
        let existing = destination_api.download(
            &format!(
                "/repos/{}/releases/assets/{asset_id}",
                destination.repository
            ),
            bytes.len(),
        )?;
        ensure!(
            existing == bytes,
            "scratch package asset bytes differ from the verified producer artifact"
        );
    } else {
        ensure!(
            release["draft"] == true,
            "published scratch package release is missing its asset"
        );
        destination_api.upload(
            &format!(
                "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={asset_name}",
                destination.repository
            ),
            bytes.clone(),
            "application/octet-stream",
        )?;
        assets = destination_api.paginate(&format!(
            "/repos/{}/releases/{release_id}/assets?per_page=100",
            destination.repository
        ))?;
    }
    validate_single_package_asset(&assets, asset_name, bytes.len() as u64, &digest)?;
    if release["draft"] == true {
        let _: Value = destination_api.patch(
            &format!("/repos/{}/releases/{release_id}", destination.repository),
            &serde_json::json!({"draft": false}),
        )?;
    }
    let published: Value = destination_api.get(&format!(
        "/repos/{}/releases/{release_id}",
        destination.repository
    ))?;
    ensure!(
        published["id"].as_u64() == Some(release_id)
            && published["tag_name"] == tag
            && published["draft"] == false
            && published["prerelease"] == true
            && published["immutable"] == true,
        "scratch package release did not become immutable"
    );
    let final_assets: Vec<Value> = destination_api.paginate(&format!(
        "/repos/{}/releases/{release_id}/assets?per_page=100",
        destination.repository
    ))?;
    let asset =
        validate_single_package_asset(&final_assets, asset_name, bytes.len() as u64, &digest)?;
    Ok(ScratchPackagePublication {
        source_repository: source.repository.clone(),
        source_repository_id: source.id,
        destination_repository: destination.repository.clone(),
        destination_repository_id: destination.id,
        source_sha: source_sha.to_owned(),
        source_branch: branch,
        tag,
        release_id,
        asset_id: asset["id"]
            .as_u64()
            .context("scratch package asset ID is missing")?,
        asset_sha256: digest,
        asset_size: bytes.len() as u64,
        producer_run_id: run_id,
        producer_run_attempt: run_attempt,
        publisher_workflow: PACKAGE_PUBLISHER_WORKFLOW.to_owned(),
        publisher_branch: deployment.server.default_branch.clone(),
        publisher_sha: writer_sha,
        publisher_run_id: writer_run_id,
        publisher_run_attempt: 1,
    })
}

fn require_scratch_package_deployment(deployment: &crate::config::Deployment) -> Result<()> {
    ensure!(
        deployment.workflow_prefix == "testing-"
            && deployment.control_repository.as_ref() == Some(&deployment.integration),
        "scratch package publisher requires the isolated testing deployment policy"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScratchPackagePublication {
    pub source_repository: String,
    pub source_repository_id: u64,
    pub destination_repository: String,
    pub destination_repository_id: u64,
    pub source_sha: String,
    pub source_branch: String,
    pub tag: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub asset_sha256: String,
    pub asset_size: u64,
    pub producer_run_id: u64,
    pub producer_run_attempt: u64,
    pub publisher_workflow: String,
    pub publisher_branch: String,
    pub publisher_sha: String,
    pub publisher_run_id: u64,
    pub publisher_run_attempt: u64,
}

fn validate_scratch_package_attestation(
    verified: &Value,
    source: &crate::config::Repository,
    source_owner_id: u64,
    source_sha: &str,
    signer_workflow: &str,
    asset_name: &str,
    asset_digest: &str,
) -> Result<(u64, u64, String)> {
    let results = verified
        .as_array()
        .filter(|results| results.len() == 1)
        .context("package attestation verifier must return exactly one result")?;
    let result = &results[0]["verificationResult"];
    let certificate = &result["signature"]["certificate"];
    let statement = &result["statement"];
    let source_ref = certificate["sourceRepositoryRef"]
        .as_str()
        .context("scratch package source ref is missing")?;
    let branch = source_ref
        .strip_prefix("refs/heads/")
        .context("scratch package source ref is invalid")?;
    crate::config::validate_branch(branch)?;
    let source_ref = format!("refs/heads/{branch}");
    let signer = format!(
        "https://github.com/{}/{signer_workflow}@{source_ref}",
        source.repository
    );
    ensure!(
        certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["runnerEnvironment"] == "github-hosted"
            && certificate["subjectAlternativeName"] == signer
            && certificate["buildSignerURI"] == signer
            && certificate["buildSignerDigest"] == source_sha
            && certificate["githubWorkflowRepository"] == source.repository
            && certificate["githubWorkflowSHA"] == source_sha
            && certificate["githubWorkflowRef"] == source_ref
            && certificate["githubWorkflowTrigger"] == "workflow_dispatch"
            && certificate["buildConfigURI"] == signer
            && certificate["buildConfigDigest"] == source_sha
            && certificate["buildTrigger"] == "workflow_dispatch"
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", source.repository)
            && certificate["sourceRepositoryDigest"] == source_sha
            && certificate["sourceRepositoryRef"] == source_ref
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                == Some(source.id)
            && certificate["sourceRepositoryOwnerIdentifier"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                == Some(source_owner_id),
        "scratch package attestation does not identify the configured source producer"
    );
    ensure!(
        certificate["sourceRepositoryOwnerURI"]
            == format!(
                "https://github.com/{}",
                source.repository.split('/').next().unwrap_or_default()
            ),
        "scratch package attestation owner identity differs from deployment configuration"
    );
    let invocation = certificate["runInvocationURI"]
        .as_str()
        .context("scratch package producer run URI is missing")?;
    let (run_id, run_attempt) = parse_run_invocation(invocation, &source.repository)?;
    let subjects = statement["subject"]
        .as_array()
        .filter(|subjects| subjects.len() == 1)
        .context("scratch package attestation must identify exactly one subject")?;
    ensure!(
        statement["predicateType"] == "https://slsa.dev/provenance/v1"
            && subjects[0]["name"] == asset_name
            && subjects[0]["digest"]["sha256"] == asset_digest,
        "scratch package attestation subject differs from the selected executable"
    );
    Ok((run_id, run_attempt, branch.to_owned()))
}

fn validate_scratch_package_run(
    run: &Value,
    source: &crate::config::Repository,
    source_sha: &str,
    signer_workflow: &str,
    run_id: u64,
    run_attempt: u64,
    owner_id: u64,
) -> Result<String> {
    let expected_path = signer_workflow.to_owned();
    let branch = run["head_branch"]
        .as_str()
        .context("scratch package producer branch is missing")?;
    crate::config::validate_branch(branch)?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"].as_u64() == Some(run_attempt)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["run_attempt"] == 1
            && run["event"] == "workflow_dispatch"
            && run["head_sha"] == source_sha
            && run["repository"]["id"].as_u64() == Some(source.id)
            && run["repository"]["full_name"] == source.repository
            && run["head_repository"]["id"].as_u64() == Some(source.id)
            && run["head_repository"]["full_name"] == source.repository
            && matches!(run["path"].as_str(), Some(path) if path == expected_path || path == format!("{expected_path}@refs/heads/{branch}"))
            && run["actor"]["id"].as_u64() == Some(owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id)
            && run["triggering_actor"]["type"] == "User",
        "scratch package producer run does not match the attested source attempt"
    );
    Ok(branch.to_owned())
}

fn validate_scratch_package_artifact(
    response: &Value,
    source: &crate::config::Repository,
    source_sha: &str,
    run_id: u64,
) -> Result<(u64, usize, String)> {
    let artifacts = response["artifacts"]
        .as_array()
        .context("scratch package producer artifact list is missing")?;
    ensure!(
        response["total_count"].as_u64() == Some(artifacts.len() as u64) && artifacts.len() < 100,
        "scratch package producer artifact list is incomplete"
    );
    let mut matching = artifacts
        .iter()
        .filter(|artifact| artifact["name"] == PACKAGE_ARTIFACT_NAME);
    let artifact = matching
        .next()
        .context("exact scratch package producer artifact is missing")?;
    ensure!(
        matching.next().is_none(),
        "scratch package producer artifact name is duplicated"
    );
    ensure!(
        artifact["expired"] == false
            && artifact["workflow_run"]["id"].as_u64() == Some(run_id)
            && artifact["workflow_run"]["head_sha"] == source_sha
            && artifact["workflow_run"]["head_branch"].is_string()
            && artifact["workflow_run"]["repository_id"].as_u64() == Some(source.id)
            && artifact["workflow_run"]["head_repository_id"].as_u64() == Some(source.id),
        "scratch package artifact is not attached to the selected source run"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("scratch package artifact ID is missing or invalid")?;
    let size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_PACKAGE_ARTIFACT_BYTES as u64)
        .context("scratch package artifact size is outside supported bounds")?;
    let digest = artifact["digest"]
        .as_str()
        .context("scratch package artifact digest is missing")?;
    Ok((
        artifact_id,
        usize::try_from(size)
            .context("scratch package artifact size does not fit this platform")?,
        canonical_sha256_digest(digest)?,
    ))
}

fn parse_scratch_package_artifact(
    bytes: &[u8],
    binary_name: &str,
    max_binary_bytes: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PACKAGE_ARTIFACT_BYTES,
        "scratch package artifact archive is outside supported bounds"
    );
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .context("read scratch package producer artifact ZIP")?;
    ensure!(
        archive.len() == 2,
        "scratch package producer artifact must contain exactly two files"
    );
    let mut binary = None;
    let mut bundle = None;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .context("read scratch package producer artifact entry")?;
        let name = file.name().to_owned();
        ensure!(
            !file.is_dir()
                && file.is_file()
                && !name.contains(['/', '\\'])
                && file
                    .unix_mode()
                    .is_none_or(|mode| matches!(mode & 0o170000, 0 | 0o100000)),
            "scratch package producer artifact contains an unsafe entry"
        );
        let limit = match name.as_str() {
            name if name == binary_name => max_binary_bytes,
            PACKAGE_BUNDLE_NAME => MAX_PACKAGE_BUNDLE_BYTES,
            _ => anyhow::bail!("scratch package producer artifact has an unexpected file"),
        };
        let declared = file.size();
        ensure!(
            declared > 0 && declared <= limit,
            "scratch package producer artifact entry is outside supported bounds"
        );
        let mut contents = Vec::with_capacity(declared as usize);
        std::io::Read::take(&mut file, limit + 1).read_to_end(&mut contents)?;
        ensure!(
            contents.len() as u64 == declared && contents.len() as u64 <= limit,
            "scratch package producer artifact entry size differs from its archive"
        );
        if name == binary_name {
            ensure!(
                binary.replace(contents).is_none(),
                "duplicate package executable entry"
            );
        } else {
            ensure!(
                bundle.replace(contents).is_none(),
                "duplicate package attestation bundle entry"
            );
        }
    }
    let binary = binary.context("scratch package producer artifact lacks its executable")?;
    let bundle =
        bundle.context("scratch package producer artifact lacks its attestation bundle")?;
    let bundle_json: Value = serde_json::from_slice(&bundle)
        .context("scratch package attestation bundle is not JSON")?;
    ensure!(
        bundle_json.is_object(),
        "scratch package attestation bundle must be a JSON object"
    );
    Ok((binary, bundle))
}

fn validate_scratch_package_writer_run(
    run: &Value,
    source: &crate::config::Repository,
    default_branch: &str,
    writer_sha: &str,
    run_id: u64,
    owner_id: u64,
) -> Result<()> {
    let path = PACKAGE_PUBLISHER_WORKFLOW;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"] == 1
            && run["status"] == "in_progress"
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == default_branch
            && run["head_sha"] == writer_sha
            && run["repository"]["id"].as_u64() == Some(source.id)
            && run["repository"]["full_name"] == source.repository
            && run["head_repository"]["id"].as_u64() == Some(source.id)
            && run["head_repository"]["full_name"] == source.repository
            && matches!(run["path"].as_str(), Some(actual) if actual == path || actual == format!("{path}@refs/heads/{default_branch}"))
            && run["actor"]["id"].as_u64() == Some(owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id)
            && run["triggering_actor"]["type"] == "User",
        "scratch package publisher is not the protected owner-dispatched writer workflow"
    );
    Ok(())
}

fn validate_scratch_package_completed_writer_run(
    run: &Value,
    source: &crate::config::Repository,
    workflow: &str,
    writer_sha: &str,
    run_id: u64,
    run_attempt: u64,
    owner_id: u64,
) -> Result<()> {
    let default_branch = source.default_branch.as_str();
    validate_package_workflow(workflow)?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"].as_u64() == Some(run_attempt)
            && run_attempt == 1
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == default_branch
            && run["head_sha"] == writer_sha
            && run["repository"]["id"].as_u64() == Some(source.id)
            && run["repository"]["full_name"] == source.repository
            && run["head_repository"]["id"].as_u64() == Some(source.id)
            && run["head_repository"]["full_name"] == source.repository
            && matches!(run["path"].as_str(), Some(actual) if actual == workflow || actual == format!("{workflow}@refs/heads/{default_branch}"))
            && run["actor"]["id"].as_u64() == Some(owner_id)
            && run["actor"]["type"] == "User"
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id)
            && run["triggering_actor"]["type"] == "User",
        "scratch package publication record is not bound to the successful protected owner-dispatched writer run"
    );
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativePackageReleaseRecord {
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

fn parse_native_package_release_record(body: &str) -> Result<NativePackageReleaseRecord> {
    let record: NativePackageReleaseRecord = serde_json::from_str(body)
        .context("stable Client package release body is not a valid publication record")?;
    ensure!(
        serde_json::to_string(&record)? == body,
        "stable Client package release body is not canonical compact JSON"
    );
    Ok(record)
}

fn validate_native_package_release_record(
    record: &NativePackageReleaseRecord,
    release: &ResolvedRelease,
    manifest: &SourcePackageManifest,
    manifest_bytes: &[u8],
    source_sha: &str,
    expected_asset: &ExpectedAsset,
) -> Result<()> {
    let manifest_digest = crate::hex_encode(Sha256::digest(manifest_bytes));
    let publisher_workflow = manifest
        .publisher_workflow
        .as_deref()
        .context("stable package manifest has no publisher workflow")?;
    crate::policy::validate_sha(&record.source_sha)?;
    crate::policy::validate_sha(&record.publisher_sha)?;
    ensure!(
        record.schema_version == 1
            && record.source_sha == source_sha
            && record.source_sha == release.source_sha
            && record.source_manifest_sha256 == manifest_digest
            && record.producer_workflow == manifest.producer_workflow
            && record.producer_run_id > 0
            && record.producer_run_attempt == 1
            && record.publisher_workflow == publisher_workflow
            && record.publisher_run_id > 0
            && record.publisher_run_attempt == 1
            && record.tag == release.tag
            && record.tag == format!("v{}", release.version)
            && record.asset_name == expected_asset.name
            && record.asset_name == release.asset.name
            && record.asset_size == release.asset.size
            && record.asset_size > 0
            && record.asset_size <= manifest.max_bytes
            && record.asset_sha256 == release.asset.sha256
            && record.asset_sha256.len() == 64
            && record
                .asset_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "stable Client package release record differs from the verified source, workflow, or asset"
    );
    Ok(())
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePackageManifest {
    schema_version: u8,
    component: String,
    protocol: String,
    version: String,
    producer_workflow: String,
    #[serde(default)]
    publisher_workflow: Option<String>,
    max_bytes: u64,
    #[serde(default)]
    source_sha: Option<String>,
    assets: std::collections::BTreeMap<String, String>,
}

impl SourcePackageManifest {
    fn validate(
        &self,
        version: &Version,
        expected_protocol: &str,
        expected_source_sha: &str,
    ) -> Result<()> {
        let asset = self
            .assets
            .get("linux-x86_64")
            .context("source package manifest has no linux-x86_64 asset")?;
        validate_expected_asset(&ExpectedAsset {
            component: self.component.clone(),
            platform: "linux-x86_64".to_owned(),
            name: asset.clone(),
        })?;
        validate_package_workflow(&self.producer_workflow)?;
        match self.schema_version {
            1 => ensure!(
                self.publisher_workflow.is_none(),
                "legacy package manifest unexpectedly declares a publisher workflow"
            ),
            2 => validate_package_workflow(
                self.publisher_workflow
                    .as_deref()
                    .context("package manifest has no publisher workflow")?,
            )?,
            _ => anyhow::bail!("unsupported package manifest schema"),
        }
        if let Some(source_sha) = &self.source_sha {
            crate::policy::validate_sha(source_sha)?;
            ensure!(
                source_sha == expected_source_sha,
                "source package manifest binary source differs from the resolved source revision"
            );
        }
        ensure!(
            matches!(self.schema_version, 1 | 2)
                && self.component == "securefix-server"
                && self.protocol == expected_protocol
                && self.version == version.to_string()
                && self.max_bytes > 0
                && self.max_bytes <= MAX_ASSET_BYTES
                && self.assets.len() == 1
                && !asset.is_empty(),
            "source package manifest does not match the selected executable or Cargo version"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PublishChannel {
    Stable,
    Scratch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativePackageMode {
    Preflight,
    Publish,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Validate the exact attested package without a write token")]
    Preflight {
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long, value_enum)]
        channel: PublishChannel,
    },
    #[command(about = "Publish a source-bound Securefix package release")]
    Publish {
        #[arg(long)]
        producer_run_id: u64,
        #[arg(long, value_enum)]
        channel: PublishChannel,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Preflight {
            producer_run_id,
            channel,
        } => {
            let result =
                publish_native_package(producer_run_id, channel, NativePackageMode::Preflight)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::Publish {
            producer_run_id,
            channel,
        } => {
            let result =
                publish_native_package(producer_run_id, channel, NativePackageMode::Publish)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
pub enum NativePackageCommandResult {
    Preflight(NativePackagePreflight),
    Published(NativePackagePublication),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NativePackagePreflight {
    pub channel: String,
    pub source_repository: String,
    pub source_repository_id: u64,
    pub source_sha: String,
    pub source_branch: String,
    pub source_manifest_sha256: String,
    pub destination_repository: String,
    pub destination_repository_id: u64,
    pub tag: String,
    pub producer_run_id: u64,
    pub producer_run_attempt: u64,
    pub producer_artifact_id: u64,
    pub producer_artifact_size: u64,
    pub producer_artifact_sha256: String,
    pub publisher_workflow: String,
    pub publisher_run_id: u64,
    pub publisher_run_attempt: u64,
    pub publisher_sha: String,
    pub asset_name: String,
    pub asset_size: u64,
    pub asset_sha256: String,
    pub release_state: crate::api::PackageReleasePreflightState,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NativePackagePublication {
    pub channel: String,
    pub source_repository: String,
    pub source_repository_id: u64,
    pub source_sha: String,
    pub source_branch: String,
    pub source_manifest_sha256: String,
    pub tag: String,
    pub producer_run_id: u64,
    pub producer_run_attempt: u64,
    pub producer_artifact_id: u64,
    pub producer_artifact_size: u64,
    pub producer_artifact_sha256: String,
    pub publisher_workflow: String,
    pub publisher_run_id: u64,
    pub publisher_run_attempt: u64,
    pub publisher_sha: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub asset_name: String,
    pub asset_size: u64,
    pub asset_sha256: String,
    pub immutable: bool,
    pub recovered: bool,
    pub recovery_run_id: Option<u64>,
    pub recovery_run_attempt: Option<u64>,
}

fn native_package_owner_id() -> Result<u64> {
    let value = std::env::var("SECUREFIX_PACKAGE_OWNER_ID")
        .context("missing package publisher owner identity")?;
    let owner_id = parse_positive_decimal(&value)?;
    ensure!(
        owner_id.to_string() == value,
        "package owner ID is not canonical"
    );
    Ok(owner_id)
}

fn native_package_scratch_destination() -> Result<crate::config::Repository> {
    let repository = std::env::var("SECUREFIX_PACKAGE_DESTINATION_REPOSITORY")
        .context("missing fixed scratch package destination repository")?;
    let id = std::env::var("SECUREFIX_PACKAGE_DESTINATION_REPOSITORY_ID")
        .context("missing fixed scratch package destination ID")?;
    let default_branch = std::env::var("SECUREFIX_PACKAGE_DESTINATION_DEFAULT_BRANCH")
        .context("missing fixed scratch package destination branch")?;
    crate::policy::validate_repository(&repository)?;
    crate::config::validate_branch(&default_branch)?;
    Ok(crate::config::Repository {
        repository,
        id: parse_positive_decimal(&id)?,
        default_branch,
    })
}

fn validate_package_source_ancestor(
    api: &GitHub,
    repository: &str,
    source_sha: &str,
    publisher_sha: &str,
) -> Result<()> {
    let comparison: Value = api.get_uncached(&format!(
        "/repos/{repository}/compare/{source_sha}...{publisher_sha}"
    ))?;
    validate_package_source_ancestor_comparison(&comparison, source_sha, publisher_sha)
}

pub(crate) fn validate_package_source_ancestor_comparison(
    comparison: &Value,
    source_sha: &str,
    publisher_sha: &str,
) -> Result<()> {
    crate::policy::validate_sha(source_sha)?;
    crate::policy::validate_sha(publisher_sha)?;
    ensure!(
        comparison["base_commit"]["sha"] == source_sha
            && comparison["merge_base_commit"]["sha"] == source_sha
            && comparison["behind_by"].as_u64() == Some(0)
            && matches!(comparison["status"].as_str(), Some("ahead" | "identical")),
        "stable package source is not an ancestor of the current protected publisher"
    );
    Ok(())
}

fn native_package_publisher_identity(repository: &str) -> Result<(String, String, String)> {
    let workflow_ref =
        std::env::var("GITHUB_WORKFLOW_REF").context("missing package publisher workflow ref")?;
    let prefix = format!("{repository}/");
    let workflow_ref = workflow_ref
        .strip_prefix(&prefix)
        .context("package publisher workflow belongs to a different repository")?;
    let (workflow, ref_name) = workflow_ref
        .split_once('@')
        .context("package publisher workflow ref is invalid")?;
    let branch = ref_name
        .strip_prefix("refs/heads/")
        .context("package publisher workflow must run from a branch")?;
    validate_package_workflow(workflow)?;
    crate::config::validate_branch(branch)?;
    Ok((
        workflow.to_owned(),
        branch.to_owned(),
        std::env::var("GITHUB_WORKFLOW_SHA")?,
    ))
}

fn package_workflow_owner_declaration(bytes: &[u8], description: &str) -> Result<u64> {
    ensure!(
        bytes.len() <= 128 * 1024,
        "{description} workflow exceeds its size bound"
    );
    let workflow: serde_yaml::Value =
        serde_yaml::from_slice(bytes).context("package workflow is invalid YAML")?;
    let env = workflow
        .get("env")
        .and_then(serde_yaml::Value::as_mapping)
        .context("package workflow has no workflow-level deployment declarations")?;
    let value = env
        .get(serde_yaml::Value::String(
            "SECUREFIX_PACKAGE_OWNER_ID".to_owned(),
        ))
        .and_then(serde_yaml::Value::as_str)
        .context("package workflow owner declaration is missing or invalid")?;
    let owner_id = parse_positive_decimal(value)?;
    ensure!(
        owner_id.to_string() == value,
        "package workflow owner declaration is not canonical"
    );
    Ok(owner_id)
}

fn validate_native_package_publisher_declaration(
    bytes: &[u8],
    owner_id: u64,
    scratch_destination: &crate::config::Repository,
) -> Result<()> {
    ensure!(
        bytes.len() <= 128 * 1024,
        "package publisher workflow exceeds its size bound"
    );
    let workflow: serde_yaml::Value =
        serde_yaml::from_slice(bytes).context("package publisher workflow is invalid YAML")?;
    let env = workflow
        .get("env")
        .and_then(serde_yaml::Value::as_mapping)
        .context("package publisher workflow has no workflow-level deployment declarations")?;
    let env_string = |name: &str| -> Result<String> {
        env.get(serde_yaml::Value::String(name.to_owned()))
            .and_then(serde_yaml::Value::as_str)
            .map(str::to_owned)
            .with_context(|| format!("package publisher declaration {name} is missing or invalid"))
    };
    ensure!(
        package_workflow_owner_declaration(bytes, "package publisher")? == owner_id,
        "package publisher owner declaration differs from the protected workflow context"
    );
    ensure!(
        env_string("SECUREFIX_PACKAGE_DESTINATION_REPOSITORY")? == scratch_destination.repository
            && env_string("SECUREFIX_PACKAGE_DESTINATION_REPOSITORY_ID")?
                == scratch_destination.id.to_string()
            && env_string("SECUREFIX_PACKAGE_DESTINATION_DEFAULT_BRANCH")?
                == scratch_destination.default_branch,
        "package scratch destination differs from the protected publisher declaration"
    );
    Ok(())
}

fn publish_native_package(
    producer_run_id: u64,
    channel: PublishChannel,
    mode: NativePackageMode,
) -> Result<NativePackageCommandResult> {
    ensure!(producer_run_id > 0, "package producer run ID is invalid");
    let source_repository =
        std::env::var("GITHUB_REPOSITORY").context("missing package publisher repository")?;
    crate::policy::validate_repository(&source_repository)?;
    let package_channel = match channel {
        PublishChannel::Stable => crate::api::PackageReleaseChannel::Stable,
        PublishChannel::Scratch => crate::api::PackageReleaseChannel::Scratch,
    };
    let owner_id = native_package_owner_id()?;
    let read_token = std::env::var("GITHUB_TOKEN").context("missing package read token")?;
    ensure!(!read_token.is_empty(), "package read token is empty");
    let source_api = GitHub::new("https://api.github.com", read_token)?;
    let source_remote: Value = source_api.get_uncached(&format!("/repos/{source_repository}"))?;
    let source_id = source_remote["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("package source repository ID is invalid")?;
    let source_default_branch = source_remote["default_branch"]
        .as_str()
        .context("package source default branch is missing")?
        .to_owned();
    crate::config::validate_branch(&source_default_branch)?;
    let (source_owner_login, _) = source_repository
        .split_once('/')
        .context("package source repository owner is missing")?;
    let source_owner_id = source_remote["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("package source owner ID is invalid")?;
    ensure!(
        source_remote["full_name"] == source_repository
            && source_remote["owner"]["login"] == source_owner_login,
        "package source repository differs from authenticated GitHub context"
    );
    let source = crate::config::Repository {
        repository: source_repository.clone(),
        id: source_id,
        default_branch: source_default_branch,
    };
    let scratch_destination = native_package_scratch_destination()?;
    let destination = match channel {
        PublishChannel::Stable => source.clone(),
        PublishChannel::Scratch => scratch_destination.clone(),
    };
    ensure!(
        matches!(channel, PublishChannel::Stable) || destination.repository != source.repository,
        "scratch package destination must be separate from its source repository"
    );
    let (publisher_workflow, publisher_branch, publisher_sha) =
        native_package_publisher_identity(&source.repository)?;
    ensure!(
        publisher_workflow == NATIVE_PACKAGE_PUBLISHER_WORKFLOW
            && publisher_branch == source.default_branch
            && std::env::var("GITHUB_REF").as_deref()
                == Ok(format!("refs/heads/{}", source.default_branch).as_str())
            && std::env::var("GITHUB_SHA").as_deref() == Ok(publisher_sha.as_str()),
        "package publisher must run from its fixed protected source workflow"
    );
    crate::policy::validate_sha(&publisher_sha)?;
    let publisher_workflow_bytes =
        source_api.content_uncached(&source.repository, &publisher_workflow, &publisher_sha)?;
    validate_native_package_publisher_declaration(
        &publisher_workflow_bytes,
        owner_id,
        &scratch_destination,
    )?;

    let producer: Value = source_api.get_uncached(&format!(
        "/repos/{}/actions/runs/{producer_run_id}/attempts/1",
        source.repository
    ))?;
    let source_sha = producer["head_sha"]
        .as_str()
        .context("package producer source SHA is missing")?
        .to_owned();
    crate::policy::validate_sha(&source_sha)?;
    let source_branch = producer["head_branch"]
        .as_str()
        .context("package producer source branch is missing")?
        .to_owned();
    crate::config::validate_branch(&source_branch)?;
    let producer_workflow_source = source_api.content_uncached(
        &source.repository,
        NATIVE_PACKAGE_PRODUCER_WORKFLOW,
        &source_sha,
    )?;
    ensure!(
        package_workflow_owner_declaration(&producer_workflow_source, "package producer")?
            == owner_id,
        "package producer owner declaration differs from the protected publisher workflow"
    );
    if matches!(channel, PublishChannel::Stable) {
        ensure!(
            source_branch == source.default_branch,
            "stable package producer must build the protected default branch"
        );
        validate_package_source_ancestor(
            &source_api,
            &source.repository,
            &source_sha,
            &publisher_sha,
        )?;
    }

    let cargo_value: Value = source_api.get_uncached(&format!(
        "/repos/{}/contents/Cargo.toml?ref={source_sha}",
        source.repository
    ))?;
    let version =
        source_version_with_prerelease(&cargo_value, matches!(channel, PublishChannel::Scratch))?;
    ensure!(
        !matches!(channel, PublishChannel::Scratch) || !version.pre.is_empty(),
        "scratch package publication requires an explicit prerelease version"
    );
    let manifest_value: Value = source_api.get_uncached(&format!(
        "/repos/{}/contents/{SOURCE_BUILD_MANIFEST_PATH}?ref={source_sha}",
        source.repository,
    ))?;
    let manifest_bytes = source_file_bytes(&manifest_value, SOURCE_BUILD_MANIFEST_PATH)?;
    let manifest: SourcePackageManifest = serde_json::from_slice(&manifest_bytes)
        .context("source package manifest is invalid JSON")?;
    let producer_branch = validate_scratch_package_run(
        &producer,
        &source,
        &source_sha,
        &manifest.producer_workflow,
        producer_run_id,
        1,
        owner_id,
    )?;
    ensure!(
        producer_branch == source_branch,
        "package producer branch changed during validation"
    );
    let cargo_bytes = source_api.content_uncached(&source.repository, "Cargo.toml", &source_sha)?;
    let asset_name = manifest
        .assets
        .get("linux-x86_64")
        .context("package source manifest has no linux-x86_64 asset")?
        .clone();
    ensure!(
        asset_name == PACKAGE_BINARY_NAME,
        "package asset name is not canonical"
    );
    ensure!(
        manifest.publisher_workflow.as_deref() == Some(publisher_workflow.as_str()),
        "package manifest does not select this publisher workflow"
    );
    validate_native_package_release_source(
        &cargo_bytes,
        &manifest_bytes,
        &NativePackageReleaseSourceBinding {
            source_sha: &source_sha,
            version: &version.to_string(),
            producer_workflow: &manifest.producer_workflow,
            publisher_workflow: &publisher_workflow,
            asset_name: &asset_name,
            max_asset_bytes: manifest.max_bytes,
            stable: matches!(channel, PublishChannel::Stable),
        },
    )?;

    let artifact_list: Value = source_api.get_uncached(&format!(
        "/repos/{}/actions/runs/{producer_run_id}/artifacts?per_page=100",
        source.repository
    ))?;
    let (artifact_id, artifact_size, artifact_sha256) =
        validate_scratch_package_artifact(&artifact_list, &source, &source_sha, producer_run_id)?;
    let artifacts = artifact_list["artifacts"]
        .as_array()
        .context("package producer artifacts are missing")?;
    let artifact_entry = artifacts
        .iter()
        .find(|artifact| artifact["id"].as_u64() == Some(artifact_id))
        .context("exact package producer artifact is missing")?;
    ensure!(
        artifact_entry["workflow_run"]["head_branch"] == source_branch,
        "package producer artifact branch differs from its exact run"
    );
    let artifact = source_api.download(
        &format!(
            "/repos/{}/actions/artifacts/{artifact_id}/zip",
            source.repository
        ),
        artifact_size,
    )?;
    ensure!(
        artifact.len() == artifact_size
            && crate::hex_encode(Sha256::digest(&artifact)) == artifact_sha256,
        "package producer archive differs from the exact run artifact digest"
    );
    let (binary, bundle) =
        parse_scratch_package_artifact(&artifact, &asset_name, manifest.max_bytes)?;
    ensure!(
        !binary.is_empty() && binary.len() as u64 <= manifest.max_bytes,
        "package producer executable is outside its manifest bound"
    );
    let asset_sha256 = crate::hex_encode(Sha256::digest(&binary));
    let mut binary_file = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut binary_file, &binary)?;
    let mut bundle_file = tempfile::Builder::new().suffix(".json").tempfile()?;
    std::io::Write::write_all(&mut bundle_file, &bundle)?;
    let attested = crate::attestation::verify_with_gh(
        binary_file.path(),
        bundle_file.path(),
        crate::attestation::VerifyRequest {
            repository: &source.repository,
            signer_repository: &source.repository,
            signer_workflow: &manifest.producer_workflow,
            signer_sha: &source_sha,
            source: Some((&source_sha, &format!("refs/heads/{source_branch}"))),
        },
    )?;
    let (attested_run, attested_attempt, attested_branch) = validate_scratch_package_attestation(
        &attested,
        &source,
        owner_id,
        &source_sha,
        &manifest.producer_workflow,
        &asset_name,
        &asset_sha256,
    )?;
    ensure!(
        attested_run == producer_run_id
            && attested_attempt == 1
            && attested_branch == source_branch,
        "package attestation does not identify the exact successful producer attempt"
    );

    let publisher_run_id = parse_positive_decimal(&std::env::var("GITHUB_RUN_ID")?)?;
    let publisher_run_attempt = parse_positive_decimal(&std::env::var("GITHUB_RUN_ATTEMPT")?)?;
    ensure!(
        publisher_run_attempt == 1,
        "package publisher must run its first attempt"
    );
    let writer_token_name = match channel {
        PublishChannel::Stable => "SECUREFIX_PACKAGE_PUBLISH_TOKEN",
        PublishChannel::Scratch => "SECUREFIX_PACKAGE_TOKEN",
    };
    let destination_remote: Value =
        source_api.get_uncached(&format!("/repos/{}", destination.repository))?;
    ensure!(
        destination_remote["id"].as_u64() == Some(destination.id)
            && destination_remote["full_name"] == destination.repository
            && destination_remote["default_branch"] == destination.default_branch
            && destination_remote["owner"]["id"].as_u64() == Some(source_owner_id),
        "package destination differs from the protected publisher declaration"
    );
    let destination_target_sha = if matches!(channel, PublishChannel::Stable) {
        source_sha.clone()
    } else {
        source_api.branch_head(&destination.repository, &destination.default_branch)?
    };
    let destination_branch_sha = if matches!(channel, PublishChannel::Stable) {
        publisher_sha.clone()
    } else {
        destination_target_sha.clone()
    };
    let tag = format!("v{version}");
    let version_string = version.to_string();
    let source_manifest_sha256 = crate::hex_encode(Sha256::digest(&manifest_bytes));
    let target = crate::api::PackageReleaseWriteTarget {
        channel: package_channel,
        source_repository: &source.repository,
        source_repository_id: source.id,
        source_owner_id,
        source_branch: &source_branch,
        source_default_branch: &source.default_branch,
        source_sha: &source_sha,
        source_manifest_sha256: &source_manifest_sha256,
        destination_repository: &destination.repository,
        destination_repository_id: destination.id,
        destination_default_branch: &destination.default_branch,
        destination_branch_sha: &destination_branch_sha,
        destination_target_sha: &destination_target_sha,
        version: &version_string,
        tag: &tag,
        asset_name: &asset_name,
        asset_size: binary.len() as u64,
        asset_sha256: &asset_sha256,
        max_asset_bytes: manifest.max_bytes,
        producer_workflow: &manifest.producer_workflow,
        producer_run_id,
        producer_run_attempt: 1,
        producer_artifact_id: artifact_id,
        producer_artifact_size: artifact_size as u64,
        producer_artifact_sha256: &artifact_sha256,
        publisher_workflow: &publisher_workflow,
        publisher_sha: &publisher_sha,
        publisher_branch: &publisher_branch,
        publisher_run_id,
        publisher_run_attempt,
        owner_id,
        release_id: None,
    };
    let release_state = GitHub::package_release_preflight_from_env("GITHUB_TOKEN", &target)?;
    let preflight = NativePackagePreflight {
        channel: match channel {
            PublishChannel::Stable => "stable".to_owned(),
            PublishChannel::Scratch => "scratch".to_owned(),
        },
        source_repository: source.repository.clone(),
        source_repository_id: source.id,
        source_sha: source_sha.clone(),
        source_branch: source_branch.clone(),
        source_manifest_sha256: source_manifest_sha256.clone(),
        destination_repository: destination.repository.clone(),
        destination_repository_id: destination.id,
        tag: tag.clone(),
        producer_run_id,
        producer_run_attempt: 1,
        producer_artifact_id: artifact_id,
        producer_artifact_size: artifact_size as u64,
        producer_artifact_sha256: artifact_sha256.clone(),
        publisher_workflow: publisher_workflow.clone(),
        publisher_run_id,
        publisher_run_attempt,
        publisher_sha: publisher_sha.clone(),
        asset_name: asset_name.clone(),
        asset_size: binary.len() as u64,
        asset_sha256: asset_sha256.clone(),
        release_state,
    };
    if mode == NativePackageMode::Preflight {
        return Ok(NativePackageCommandResult::Preflight(preflight));
    }
    if let crate::api::PackageReleasePreflightState::AlreadyPublished {
        release_id,
        asset_id,
        publisher_run_id: recorded_publisher_run_id,
        publisher_run_attempt: recorded_publisher_run_attempt,
    } = release_state
    {
        return Ok(NativePackageCommandResult::Published(
            NativePackagePublication {
                channel: match channel {
                    PublishChannel::Stable => "stable".to_owned(),
                    PublishChannel::Scratch => "scratch".to_owned(),
                },
                source_repository: source.repository.clone(),
                source_repository_id: source.id,
                source_sha,
                source_branch,
                source_manifest_sha256,
                tag,
                producer_run_id,
                producer_run_attempt: 1,
                producer_artifact_id: artifact_id,
                producer_artifact_size: artifact_size as u64,
                producer_artifact_sha256: artifact_sha256,
                publisher_workflow,
                publisher_run_id: recorded_publisher_run_id,
                publisher_run_attempt: recorded_publisher_run_attempt,
                publisher_sha,
                release_id,
                asset_id,
                asset_name,
                asset_size: binary.len() as u64,
                asset_sha256,
                immutable: true,
                recovered: true,
                recovery_run_id: Some(publisher_run_id),
                recovery_run_attempt: Some(publisher_run_attempt),
            },
        ));
    }
    let mut writer = GitHub::package_release_from_env("GITHUB_TOKEN", writer_token_name, &target)?;
    let release_id = writer.package_release_create_draft()?;
    let asset_uploaded = writer.package_release_select(release_id)?;
    if !asset_uploaded {
        writer.upload(
            &writer.package_release_asset_upload_endpoint()?,
            binary.clone(),
            "application/octet-stream",
        )?;
    }
    writer.package_release_publish_draft()?;
    let published = writer.package_release_verify_published()?;
    let assets = published["assets"]
        .as_array()
        .filter(|assets| assets.len() == 1)
        .context("published package release does not have exactly one asset")?;
    let asset = &assets[0];
    let asset_id = asset["id"]
        .as_u64()
        .context("published package asset has no ID")?;
    let downloaded = writer.download(
        &format!(
            "/repos/{}/releases/assets/{asset_id}",
            destination.repository
        ),
        binary.len(),
    )?;
    ensure!(
        downloaded == binary,
        "published package asset bytes differ from the attested producer binary"
    );
    Ok(NativePackageCommandResult::Published(
        NativePackagePublication {
            channel: match channel {
                PublishChannel::Stable => "stable".to_owned(),
                PublishChannel::Scratch => "scratch".to_owned(),
            },
            source_repository: source.repository.clone(),
            source_repository_id: source.id,
            source_sha,
            source_branch,
            source_manifest_sha256,
            tag,
            producer_run_id,
            producer_run_attempt: 1,
            producer_artifact_id: artifact_id,
            producer_artifact_size: artifact_size as u64,
            producer_artifact_sha256: artifact_sha256,
            publisher_workflow,
            publisher_run_id,
            publisher_run_attempt,
            publisher_sha,
            release_id,
            asset_id,
            asset_name,
            asset_size: binary.len() as u64,
            asset_sha256,
            immutable: published["immutable"] == true,
            recovered: matches!(
                release_state,
                crate::api::PackageReleasePreflightState::ResumeDraft { .. }
            ),
            recovery_run_id: None,
            recovery_run_attempt: None,
        },
    ))
}

fn source_file_bytes(manifest: &Value, expected_path: &str) -> Result<Vec<u8>> {
    ensure!(
        manifest["path"].as_str() == Some(expected_path)
            && manifest["type"].as_str() == Some("file")
            && manifest["encoding"].as_str() == Some("base64"),
        "source package manifest identity or encoding is invalid"
    );
    let size = manifest["size"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= 16 * 1024)
        .context("source package manifest size is invalid")?;
    let encoded = manifest["content"]
        .as_str()
        .context("source package manifest contents are missing")?;
    ensure!(
        encoded.len() <= 24 * 1024,
        "source package manifest is too large"
    );
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace('\n', ""))
        .context("source package manifest is invalid base64")?;
    ensure!(
        bytes.len() as u64 == size,
        "source package manifest size changed"
    );
    Ok(bytes)
}

fn validate_single_package_asset(
    assets: &[Value],
    name: &str,
    size: u64,
    sha256: &str,
) -> Result<Value> {
    ensure!(
        assets.len() == 1,
        "scratch package release must contain exactly one asset"
    );
    let asset = &assets[0];
    ensure!(
        asset["id"].as_u64().is_some_and(|id| id > 0)
            && asset["name"] == name
            && asset["state"] == "uploaded"
            && asset["size"].as_u64() == Some(size)
            && asset["digest"] == format!("sha256:{sha256}"),
        "scratch package release asset does not match the verified executable"
    );
    Ok(asset.clone())
}

fn canonical_sha256_digest(value: &str) -> Result<String> {
    let digest = value
        .strip_prefix("sha256:")
        .context("package asset digest must use sha256")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "package asset SHA-256 digest is not canonical lowercase hex"
    );
    Ok(digest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};
    use serde_json::{Value, json};

    const REPOSITORY: &str = "example-org/securefix";
    const SOURCE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CARGO_TOML: &str = "[package]\nname = \"securefix\"\nversion = \"1.2.3\"\n";
    const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn publisher() -> TrustedPublisher {
        TrustedPublisher {
            repository: REPOSITORY.into(),
            repository_id: 42,
        }
    }

    fn expected_asset() -> ExpectedAsset {
        ExpectedAsset {
            component: "server".into(),
            platform: "linux-x86_64".into(),
            name: "securefix-linux-x86_64".into(),
        }
    }

    #[test]
    fn scratch_publisher_requires_the_isolated_testing_policy() {
        let testing =
            crate::policy::Policy::parse(include_bytes!("../.github/testing-policy.json")).unwrap();
        require_scratch_package_deployment(&testing.deployment).unwrap();

        let production = crate::policy::Policy::parse(include_bytes!("../policy.json")).unwrap();
        assert!(require_scratch_package_deployment(&production.deployment).is_err());
    }

    fn source_manifest(toml: &str) -> Value {
        use base64::Engine;
        json!({
            "path":"Cargo.toml",
            "type":"file",
            "size":toml.len(),
            "encoding":"base64",
            "content":base64::engine::general_purpose::STANDARD.encode(toml)
        })
    }

    fn repository() -> Value {
        json!({"id":42,"full_name":REPOSITORY,"default_branch":"main","owner":{"id":84,"login":"example-org"}})
    }

    fn signer_release() -> Value {
        json!({
            "id":11,
            "tag_name":"v1.2.3",
            "target_commitish":SOURCE_SHA,
            "draft":false,
            "immutable":true,
            "prerelease":false
        })
    }

    fn resolve_signer_fixture(
        source_response: Value,
        tag_response: Value,
        release_response: Value,
        range: &str,
        expected_requests: usize,
    ) -> Result<Version> {
        let mut routes = vec![
            Route::get(format!("/repos/{REPOSITORY}"), repository()),
            Route::get(
                format!("/repos/{REPOSITORY}/contents/Cargo.toml?ref={SOURCE_SHA}"),
                source_response,
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/git/ref/tags/v1.2.3"),
                tag_response,
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/releases/tags/v1.2.3"),
                release_response,
            ),
        ];
        routes.truncate(expected_requests);
        let fixture = Fixture::new(routes);
        let requirement = VersionReq::parse(range).unwrap();
        let result = resolve_native_client_implementation(
            &fixture.api,
            &publisher(),
            SOURCE_SHA,
            &requirement,
            "main",
        );
        fixture.finish();
        result
    }

    fn tag_ref() -> Value {
        json!({
            "ref":"refs/tags/v1.2.3",
            "object":{"type":"commit","sha":SOURCE_SHA}
        })
    }

    fn release() -> Value {
        json!({
            "id":7,
            "tag_name":"v1.2.3",
            "name":"v1.2.3",
            "target_commitish":SOURCE_SHA,
            "draft":false,
            "immutable":true,
            "prerelease":false,
            "assets":[{
                "id":9,
                "name":"securefix-linux-x86_64",
                "state":"uploaded",
                "size":1234,
                "digest":format!("sha256:{DIGEST}")
            }]
        })
    }

    fn resolve_fixture(
        repository_response: Value,
        source_response: Value,
        tag_response: Value,
        release_response: Value,
        range: &str,
        expected_requests: usize,
    ) -> Result<ResolvedRelease> {
        let mut routes = vec![
            Route::get(format!("/repos/{REPOSITORY}"), repository_response),
            Route::get(
                format!("/repos/{REPOSITORY}/contents/Cargo.toml?ref={SOURCE_SHA}"),
                source_response,
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/git/ref/tags/v1.2.3"),
                tag_response,
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/releases/tags/v1.2.3"),
                release_response,
            ),
        ];
        routes.truncate(expected_requests);
        let fixture = Fixture::new(routes);
        let requirement = VersionReq::parse(range).unwrap();
        let result = resolve_release(
            &fixture.api,
            &publisher(),
            SOURCE_SHA,
            &expected_asset(),
            &requirement,
        );
        fixture.finish();
        result
    }

    fn download_fixture(
        release_response: Value,
        asset_bytes: Vec<u8>,
        expected_requests: usize,
    ) -> Result<DownloadedAsset> {
        let mut routes = vec![
            Route::get(format!("/repos/{REPOSITORY}"), repository()),
            Route::get(
                format!("/repos/{REPOSITORY}/contents/Cargo.toml?ref={SOURCE_SHA}"),
                source_manifest(CARGO_TOML),
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/git/ref/tags/v1.2.3"),
                tag_ref(),
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/releases/tags/v1.2.3"),
                release_response,
            ),
            Route::raw(
                "GET",
                format!("/repos/{REPOSITORY}/releases/assets/9"),
                200,
                asset_bytes,
            )
            .with_request_header("Accept", "application/octet-stream"),
        ];
        routes.truncate(expected_requests);
        let fixture = Fixture::new(routes);
        let requirement = VersionReq::parse(">=1.0.0").unwrap();
        let result = download_release_asset(
            &fixture.api,
            &publisher(),
            SOURCE_SHA,
            &expected_asset(),
            &requirement,
        );
        fixture.finish();
        result
    }

    fn valid_resolve(range: &str) -> Result<ResolvedRelease> {
        resolve_fixture(
            repository(),
            source_manifest(CARGO_TOML),
            tag_ref(),
            release(),
            range,
            4,
        )
    }

    #[test]
    fn resolves_exact_source_tag_and_single_asset_by_pinned_revision() {
        let resolved = valid_resolve(">=1.2.0").unwrap();
        assert_eq!(resolved.publisher, publisher());
        assert_eq!(resolved.implementation_sha, SOURCE_SHA);
        assert_eq!(resolved.source_sha, SOURCE_SHA);
        assert_eq!(resolved.version, Version::parse("1.2.3").unwrap());
        assert_eq!(resolved.tag, "v1.2.3");
        assert_eq!(resolved.release_id, 7);
        assert_eq!(resolved.asset.component, "server");
        assert_eq!(resolved.asset.platform, "linux-x86_64");
        assert_eq!(resolved.asset.id, 9);
        assert_eq!(resolved.asset.name, "securefix-linux-x86_64");
        assert_eq!(resolved.asset.size, 1234);
        assert_eq!(resolved.asset.sha256, DIGEST);
    }

    #[test]
    fn client_package_asset_is_bounded_by_its_source_manifest_before_download() {
        let fixture = Fixture::new(vec![
            Route::get(format!("/repos/{REPOSITORY}"), repository()),
            Route::get(
                format!("/repos/{REPOSITORY}/contents/Cargo.toml?ref={SOURCE_SHA}"),
                source_manifest(CARGO_TOML),
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/git/ref/tags/v1.2.3"),
                tag_ref(),
            ),
            Route::get(
                format!("/repos/{REPOSITORY}/releases/tags/v1.2.3"),
                release(),
            ),
        ]);
        let result = download_release_asset_bounded(
            &fixture.api,
            &publisher(),
            SOURCE_SHA,
            &expected_asset(),
            &VersionReq::parse(">=1.0.0").unwrap(),
            1233,
        );
        assert!(result.is_err());
        fixture.finish();
    }

    #[test]
    fn client_implementation_must_have_an_accepted_immutable_release_at_signer_sha() {
        assert_eq!(
            resolve_signer_fixture(
                source_manifest(CARGO_TOML),
                tag_ref(),
                signer_release(),
                ">=1.2.0",
                4,
            )
            .unwrap(),
            Version::parse("1.2.3").unwrap()
        );
        assert!(
            resolve_signer_fixture(
                source_manifest(CARGO_TOML),
                tag_ref(),
                signer_release(),
                ">=2.0.0",
                2,
            )
            .is_err()
        );
        assert!(
            resolve_signer_fixture(
                source_manifest("[package]\nname = \"securefix\"\nversion = \"1.2.3-pre.1\"\n"),
                tag_ref(),
                signer_release(),
                ">=1.0.0",
                2,
            )
            .is_err()
        );
        let mut wrong_tag = tag_ref();
        wrong_tag["object"]["sha"] = json!("b".repeat(40));
        assert!(
            resolve_signer_fixture(
                source_manifest(CARGO_TOML),
                wrong_tag,
                signer_release(),
                ">=1.0.0",
                3,
            )
            .is_err()
        );
        let mut mutable_release = signer_release();
        mutable_release["immutable"] = json!(false);
        assert!(
            resolve_signer_fixture(
                source_manifest(CARGO_TOML),
                tag_ref(),
                mutable_release,
                ">=1.0.0",
                4,
            )
            .is_err()
        );
    }

    #[test]
    fn native_client_protocol_mismatch_rejects_before_remote_resolution() {
        let fixture = Fixture::new(vec![]);
        let acceptable = crate::instance_config::AcceptableClients {
            repository: REPOSITORY.into(),
            id: 42,
            producer_workflow: ".github/workflows/request-producer.yml".into(),
            version: VersionReq::parse(">=1.2.0").unwrap(),
        };
        let result = verify_native_client_package(
            &fixture.api,
            &acceptable,
            SOURCE_SHA,
            &PinnedPackageAction::new(
                REPOSITORY.to_owned(),
                ".github/actions/load-package".to_owned(),
                SOURCE_SHA.to_owned(),
            )
            .unwrap(),
            "securefix-native-request/v999",
            "main",
        );
        assert!(result.is_err());
        fixture.finish();
    }

    #[test]
    fn source_package_manifest_paths_are_bounded_and_repository_relative() {
        assert!(validate_package_action_path("actions/packages/Native Client loader").is_ok());
        assert!(
            validate_source_package_manifest_path(".github/actions/load-package/package.json")
                .is_ok()
        );
        assert!(
            validate_source_package_manifest_path(
                ".github/actions/load-package/source-package.json"
            )
            .is_ok()
        );
        assert!(validate_source_package_manifest_path(".github/actions/../package.json").is_err());
        assert!(
            validate_source_package_manifest_path(
                ".github/actions/load-package/package.json?ref=main"
            )
            .is_err()
        );
        assert!(
            validate_source_package_manifest_path("build artifacts/source package.json").is_ok()
        );
        assert!(validate_source_package_manifest_path("C:/absolute/package.json").is_err());
        assert!(validate_source_package_manifest_path("build\\package.json").is_err());
        assert!(validate_source_package_manifest_path("build\n/package.json").is_err());
        assert!(validate_source_package_manifest_path("build/source%20package.json").is_ok());
    }

    #[test]
    fn bundled_v3_action_mapping_binds_the_verified_binary_receipt() {
        const BINARY_SOURCE_SHA: &str = "d84c178ac49ffb21bdc49e816a1285ff873fe259";
        let action_bytes = include_bytes!("../.github/actions/load-package/package.json");
        let manifest = NativeClientPackageManifest::parse(action_bytes).unwrap();
        let source = TrustedPublisher {
            repository: "civitaspo/securefix-server".to_owned(),
            repository_id: 1_250_079_425,
        };
        let destination = TrustedPublisher {
            repository: "civitaspo/testing-securefix-server".to_owned(),
            repository_id: 1_410_312_556,
        };
        assert_eq!(
            manifest
                .validate(
                    ClientPackageChannel::Scratch,
                    &source,
                    &destination,
                    NATIVE_CLIENT_PROTOCOL,
                    Some("main"),
                )
                .unwrap(),
            BINARY_SOURCE_SHA
        );

        let source_manifest_bytes =
            include_bytes!("../tests/fixtures/native-package-source-manifest-v2.json");
        assert_eq!(
            manifest.source_manifest_sha256,
            crate::hex_encode(Sha256::digest(source_manifest_bytes))
        );
        assert_eq!(
            manifest.source_manifest_path,
            ".github/actions/load-package/source-package.json"
        );
        let source_manifest: SourcePackageManifest =
            serde_json::from_slice(source_manifest_bytes).unwrap();
        let binary_version = Version::parse(&manifest.version).unwrap();
        validate_client_source_package_manifest(
            &manifest,
            &source_manifest,
            source_manifest_bytes,
            &binary_version,
            NATIVE_CLIENT_PROTOCOL,
        )
        .unwrap();

        let action = PinnedPackageAction::new(
            source.repository.clone(),
            "actions/package loader/nested".to_owned(),
            "a".repeat(40),
        )
        .unwrap();
        let action_manifest_path = action.manifest_path();
        assert_eq!(
            encode_repository_path(&action_manifest_path),
            "actions/package%20loader/nested/package.json"
        );
        assert_ne!(action.revision(), BINARY_SOURCE_SHA);
        assert_ne!(manifest.source_sha, action.revision());

        use base64::Engine;
        let manifest_path = action.manifest_path();
        let encoded_manifest_path = encode_repository_path(&manifest_path);
        let action_sha = action.revision().to_owned();
        let route = Route::get(
            format!(
                "/repos/{}/contents/{encoded_manifest_path}?ref={action_sha}",
                action.repository
            ),
            json!({
                "path": manifest_path,
                "type": "file",
                "encoding": "base64",
                "size": action_bytes.len(),
                "content": base64::engine::general_purpose::STANDARD.encode(action_bytes)
            }),
        );
        let source_path = manifest.source_manifest_path.clone();
        let source_sha = manifest.source_sha.clone();
        let source_route = Route::get(
            format!(
                "/repos/{}/contents/{source_path}?ref={source_sha}",
                source.repository
            ),
            json!({
                "path": source_path,
                "type": "file",
                "encoding": "base64",
                "size": source_manifest_bytes.len(),
                "content": base64::engine::general_purpose::STANDARD.encode(source_manifest_bytes)
            }),
        );
        let fixture = Fixture::new(vec![route, source_route]);
        let (fetched_bytes, fetched_manifest) =
            fetch_native_client_action_manifest(&fixture.api, &action).unwrap();
        assert_eq!(fetched_bytes, action_bytes);
        assert_eq!(fetched_manifest.source_sha, BINARY_SOURCE_SHA);
        assert_eq!(
            fetch_source_package_manifest(
                &fixture.api,
                &source.repository,
                &manifest.source_sha,
                &manifest.source_manifest_path,
            )
            .unwrap(),
            source_manifest_bytes
        );
        fixture.finish();

        let spaced_source_path = "build artifacts/source package.json";
        let encoded_spaced_source_path = encode_repository_path(spaced_source_path);
        assert_eq!(
            encoded_spaced_source_path,
            "build%20artifacts/source%20package.json"
        );
        let spaced_source_route = Route::get(
            format!(
                "/repos/{}/contents/{encoded_spaced_source_path}?ref={source_sha}",
                source.repository
            ),
            json!({
                "path": spaced_source_path,
                "type": "file",
                "encoding": "base64",
                "size": source_manifest_bytes.len(),
                "content": base64::engine::general_purpose::STANDARD.encode(source_manifest_bytes)
            }),
        );
        let spaced_fixture = Fixture::new(vec![spaced_source_route]);
        assert_eq!(
            fetch_source_package_manifest(
                &spaced_fixture.api,
                &source.repository,
                &manifest.source_sha,
                spaced_source_path,
            )
            .unwrap(),
            source_manifest_bytes
        );
        spaced_fixture.finish();

        let mut unknown = serde_json::from_slice::<Value>(action_bytes).unwrap();
        unknown["unexpected"] = json!(true);
        assert!(
            NativeClientPackageManifest::parse(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );
    }

    #[test]
    fn stable_v3_mapping_and_release_record_must_match_exactly() {
        let manifest = NativeClientPackageManifest {
            schema_version: 3,
            channel: ClientPackageChannel::Stable,
            component: "securefix-server".to_owned(),
            protocol: NATIVE_CLIENT_PROTOCOL.to_owned(),
            version: "1.2.3".to_owned(),
            max_bytes: 128,
            source_repository: REPOSITORY.to_owned(),
            source_repository_id: 42,
            source_sha: SOURCE_SHA.to_owned(),
            source_branch: "main".to_owned(),
            source_default_branch: "main".to_owned(),
            source_manifest_path: ".github/actions/load-package/source-package.json".to_owned(),
            source_manifest_sha256: "a".repeat(64),
            destination_repository: REPOSITORY.to_owned(),
            destination_repository_id: 42,
            tag: "v1.2.3".to_owned(),
            release_id: 7,
            target_branch: "main".to_owned(),
            immutable: true,
            prerelease: false,
            asset_id: 9,
            asset_name: PACKAGE_BINARY_NAME.to_owned(),
            asset_size: 64,
            asset_sha256: DIGEST.to_owned(),
            producer_workflow: ".github/workflows/native-package-build.yml".to_owned(),
            producer_run_id: 3,
            producer_run_attempt: 1,
            publisher_workflow: ".github/workflows/publish-native-package.yml".to_owned(),
            publisher_sha: "b".repeat(40),
            publisher_branch: "main".to_owned(),
            publisher_run_id: 4,
            publisher_run_attempt: 1,
        };
        let record = NativePackageReleaseRecord {
            schema_version: 1,
            source_sha: manifest.source_sha.clone(),
            source_manifest_sha256: manifest.source_manifest_sha256.clone(),
            producer_workflow: manifest.producer_workflow.clone(),
            producer_run_id: manifest.producer_run_id,
            producer_run_attempt: manifest.producer_run_attempt,
            publisher_workflow: manifest.publisher_workflow.clone(),
            publisher_sha: manifest.publisher_sha.clone(),
            publisher_run_id: manifest.publisher_run_id,
            publisher_run_attempt: manifest.publisher_run_attempt,
            tag: manifest.tag.clone(),
            asset_name: manifest.asset_name.clone(),
            asset_size: manifest.asset_size,
            asset_sha256: manifest.asset_sha256.clone(),
        };
        validate_client_package_manifest_record(&manifest, &record).unwrap();
        let mut wrong_run = record.clone();
        wrong_run.publisher_run_id += 1;
        assert!(validate_client_package_manifest_record(&manifest, &wrong_run).is_err());
        let mut wrong_digest = record;
        wrong_digest.asset_sha256 = "d".repeat(64);
        assert!(validate_client_package_manifest_record(&manifest, &wrong_digest).is_err());
    }

    #[test]
    fn stable_package_record_binds_manifest_publisher_and_exact_asset() {
        const PUBLISHER_WORKFLOW: &str = ".github/workflows/publish-native-package.yml";
        const PUBLISHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let manifest_bytes = format!(
            "{{\"schema_version\":2,\"component\":\"securefix\",\"protocol\":\"{}\",\"version\":\"1.2.3-pre.4\",\"producer_workflow\":\".github/workflows/native-package-build.yml\",\"publisher_workflow\":\"{PUBLISHER_WORKFLOW}\",\"max_bytes\":100,\"assets\":{{\"linux-x86_64\":\"securefix-linux-x86_64\"}}}}",
            NATIVE_CLIENT_PROTOCOL
        );
        let manifest: SourcePackageManifest = serde_json::from_str(&manifest_bytes).unwrap();
        let version = Version::parse("1.2.3-pre.4").unwrap();
        let expected_asset = ExpectedAsset {
            component: "securefix".to_owned(),
            platform: "linux-x86_64".to_owned(),
            name: "securefix-linux-x86_64".to_owned(),
        };
        let release = ResolvedRelease {
            publisher: publisher(),
            implementation_sha: SOURCE_SHA.to_owned(),
            source_sha: SOURCE_SHA.to_owned(),
            version: version.clone(),
            tag: format!("v{version}"),
            release_id: 1,
            release_body: None,
            asset: ResolvedAsset {
                component: expected_asset.component.clone(),
                platform: expected_asset.platform.clone(),
                id: 2,
                name: expected_asset.name.clone(),
                size: 7,
                sha256: DIGEST.to_owned(),
            },
        };
        let record = NativePackageReleaseRecord {
            schema_version: 1,
            source_sha: SOURCE_SHA.to_owned(),
            source_manifest_sha256: crate::hex_encode(Sha256::digest(&manifest_bytes)),
            producer_workflow: manifest.producer_workflow.clone(),
            producer_run_id: 3,
            producer_run_attempt: 1,
            publisher_workflow: PUBLISHER_WORKFLOW.to_owned(),
            publisher_sha: PUBLISHER_SHA.to_owned(),
            publisher_run_id: 4,
            publisher_run_attempt: 1,
            tag: release.tag.clone(),
            asset_name: expected_asset.name.clone(),
            asset_size: release.asset.size,
            asset_sha256: DIGEST.to_owned(),
        };
        let encoded = serde_json::to_string(&record).unwrap();
        assert_eq!(
            parse_native_package_release_record(&encoded).unwrap(),
            record
        );
        assert!(parse_native_package_release_record(&format!("{encoded} ")).is_err());
        validate_native_package_release_record(
            &record,
            &release,
            &manifest,
            manifest_bytes.as_bytes(),
            SOURCE_SHA,
            &expected_asset,
        )
        .unwrap();

        let mut wrong_publisher_sha = record.clone();
        wrong_publisher_sha.publisher_sha = "not-a-sha".to_owned();
        let mut wrong_manifest = record.clone();
        wrong_manifest.source_manifest_sha256 = "d".repeat(64);
        let mut wrong_publisher_workflow = record;
        wrong_publisher_workflow.publisher_workflow = ".github/workflows/other.yml".to_owned();
        for invalid in [
            wrong_publisher_sha,
            wrong_manifest,
            wrong_publisher_workflow,
        ] {
            assert!(
                validate_native_package_release_record(
                    &invalid,
                    &release,
                    &manifest,
                    manifest_bytes.as_bytes(),
                    SOURCE_SHA,
                    &expected_asset,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn stable_publisher_run_is_bound_separately_from_binary_source() {
        const PUBLISHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let record = NativePackageReleaseRecord {
            schema_version: 1,
            source_sha: SOURCE_SHA.to_owned(),
            source_manifest_sha256: "d".repeat(64),
            producer_workflow: ".github/workflows/native-package-build.yml".to_owned(),
            producer_run_id: 3,
            producer_run_attempt: 1,
            publisher_workflow: ".github/workflows/publish-native-package.yml".to_owned(),
            publisher_sha: PUBLISHER_SHA.to_owned(),
            publisher_run_id: 4,
            publisher_run_attempt: 1,
            tag: "v1.2.3".to_owned(),
            asset_name: "securefix-linux-x86_64".to_owned(),
            asset_size: 7,
            asset_sha256: DIGEST.to_owned(),
        };
        assert_ne!(record.source_sha, record.publisher_sha);

        let valid = json!({
            "id": 4,
            "run_attempt": 1,
            "repository": {"id":42,"full_name":REPOSITORY,"owner":{"id":84,"login":"example-org"}},
            "head_repository": {"id":42,"full_name":REPOSITORY},
            "path": record.publisher_workflow,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": PUBLISHER_SHA,
            "actor": {"id":84,"type":"User"},
            "triggering_actor": {"id":84,"type":"User"},
            "status": "completed",
            "conclusion": "success"
        });
        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/{REPOSITORY}"),
            repository(),
        )]);
        validate_native_package_publisher_run(
            &fixture.api,
            &publisher(),
            "main",
            &record,
            84,
            &valid,
        )
        .unwrap();
        fixture.finish();

        let mut wrong_actor = valid.clone();
        wrong_actor["actor"]["id"] = json!(85);
        let mut wrong_triggering_actor = valid.clone();
        wrong_triggering_actor["triggering_actor"]["id"] = json!(85);
        let mut invalids = vec![
            ("head_sha", json!(SOURCE_SHA)),
            ("head_branch", json!("release/other")),
            ("event", json!("push")),
            ("run_attempt", json!(2)),
            ("path", json!(".github/workflows/other.yml")),
        ]
        .into_iter()
        .map(|(path, value)| {
            let mut invalid = valid.clone();
            invalid[path] = value;
            (path, invalid)
        })
        .collect::<Vec<_>>();
        invalids.push(("actor.id", wrong_actor));
        invalids.push(("triggering_actor.id", wrong_triggering_actor));
        for (path, invalid) in invalids {
            let fixture = Fixture::new(vec![Route::get(
                format!("/repos/{REPOSITORY}"),
                repository(),
            )]);
            assert!(
                validate_native_package_publisher_run(
                    &fixture.api,
                    &publisher(),
                    "main",
                    &record,
                    84,
                    &invalid,
                )
                .is_err(),
                "publisher run must reject modified {path}"
            );
            fixture.finish();
        }
    }

    #[test]
    fn package_workflow_owner_is_one_protected_literal() {
        let valid = br#"name: publish
env:
  SECUREFIX_PACKAGE_OWNER_ID: "84"
jobs:
  publish:
    runs-on: ubuntu-latest
"#;
        assert_eq!(package_workflow_owner_id_from_bytes(valid).unwrap(), 84);

        let expression = br#"env:
  SECUREFIX_PACKAGE_OWNER_ID: "${{ vars.OWNER_ID }}"
jobs: {}
"#;
        let workflow_override = br#"env:
  SECUREFIX_PACKAGE_OWNER_ID: "84"
jobs:
  publish:
    env:
      SECUREFIX_PACKAGE_OWNER_ID: "85"
"#;
        let duplicate = br#"env:
  SECUREFIX_PACKAGE_OWNER_ID: "84"
jobs:
  publish:
    env:
      SECUREFIX_PACKAGE_OWNER_ID: "84"
"#;
        for invalid in [
            expression.as_slice(),
            workflow_override.as_slice(),
            duplicate.as_slice(),
        ] {
            assert!(package_workflow_owner_id_from_bytes(invalid).is_err());
        }
    }

    #[test]
    fn release_display_name_is_not_part_of_its_identity() {
        for name in [Some("Custom release title"), None] {
            let mut release = release();
            if let Some(name) = name {
                release["name"] = json!(name);
            } else {
                release.as_object_mut().unwrap().remove("name");
            }
            let resolved = resolve_fixture(
                repository(),
                source_manifest(CARGO_TOML),
                tag_ref(),
                release,
                ">=1.0.0",
                4,
            )
            .unwrap();
            assert_eq!(resolved.tag, "v1.2.3");
        }
    }

    #[test]
    fn downloads_exact_asset_and_returns_read_only_metadata_and_bytes() {
        let bytes = vec![0, 255, 1, 128];
        let mut release = release();
        release["assets"][0]["size"] = json!(bytes.len());
        release["assets"][0]["digest"] = json!(format!(
            "sha256:{}",
            crate::hex_encode(Sha256::digest(&bytes))
        ));

        let downloaded = download_fixture(release, bytes.clone(), 5).unwrap();
        assert_eq!(downloaded.bytes(), bytes);
        assert_eq!(downloaded.release().asset.id, 9);
        assert_eq!(downloaded.release().asset.size, bytes.len() as u64);
    }

    #[test]
    fn rejects_short_long_and_digest_mismatched_downloads() {
        let cases = [
            (vec![1, 2, 3], 4, DIGEST),
            (vec![1, 2, 3, 4, 5], 4, DIGEST),
            (
                vec![1, 2, 3, 4],
                4,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
        ];
        for (bytes, metadata_size, digest) in cases {
            let mut release = release();
            release["assets"][0]["size"] = json!(metadata_size);
            release["assets"][0]["digest"] = json!(format!("sha256:{digest}"));
            assert!(download_fixture(release, bytes, 5).is_err());
        }
    }

    #[test]
    fn rejects_oversized_declared_asset_before_download_request() {
        let mut release = release();
        release["assets"][0]["size"] = json!(MAX_ASSET_BYTES + 1);
        assert!(download_fixture(release, vec![1], 4).is_err());
    }

    #[test]
    fn rejects_repository_identity_mismatch() {
        for wrong in [
            json!({"id":43,"full_name":REPOSITORY}),
            json!({"id":42,"full_name":"other/repo"}),
        ] {
            assert!(
                resolve_fixture(
                    wrong,
                    source_manifest(CARGO_TOML),
                    tag_ref(),
                    release(),
                    ">=1.0.0",
                    1
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_incomplete_or_invalid_source_manifest_and_versions() {
        let mut missing = source_manifest(CARGO_TOML);
        missing.as_object_mut().unwrap().remove("content");
        let mut wrong_path = source_manifest(CARGO_TOML);
        wrong_path["path"] = json!("other.toml");
        let mut wrong_size = source_manifest(CARGO_TOML);
        wrong_size["size"] = json!(1);
        for source in [
            missing,
            wrong_path,
            wrong_size,
            source_manifest("[package]\nversion = \"1.2.3-pre.1\"\n"),
            source_manifest("[package]\nversion = \"01.2.3\"\n"),
            source_manifest("[project]\nversion = \"1.2.3\"\n"),
            source_manifest("package = \"not a table\"\n"),
            source_manifest("[package]\nname = \"securefix\"\n"),
        ] {
            assert!(
                resolve_fixture(repository(), source, tag_ref(), release(), ">=1.0.0", 2).is_err()
            );
        }
        assert!(
            resolve_fixture(
                repository(),
                source_manifest(CARGO_TOML),
                tag_ref(),
                release(),
                ">=1.3.0",
                2
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_non_lightweight_or_misdirected_tags() {
        for mut wrong in [
            json!({"ref":"refs/tags/v1.2.3","object":{"type":"tag","sha":SOURCE_SHA}}),
            json!({"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}),
            json!({"ref":"refs/tags/v9.9.9","object":{"type":"commit","sha":SOURCE_SHA}}),
        ] {
            assert!(
                resolve_fixture(
                    repository(),
                    source_manifest(CARGO_TOML),
                    wrong.take(),
                    release(),
                    ">=1.0.0",
                    3
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_unpublished_mutable_prerelease_or_misdirected_release() {
        let mut variants = Vec::new();
        let mut value = release();
        value["draft"] = json!(true);
        variants.push(value);
        let mut value = release();
        value["immutable"] = json!(false);
        variants.push(value);
        let mut value = release();
        value.as_object_mut().unwrap().remove("immutable");
        variants.push(value);
        let mut value = release();
        value["prerelease"] = json!(true);
        variants.push(value);
        let mut value = release();
        value["tag_name"] = json!("v1.2.4");
        variants.push(value);
        let mut value = release();
        value["target_commitish"] = json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        variants.push(value);
        let mut value = release();
        value["id"] = json!(0);
        variants.push(value);
        for wrong in variants {
            assert!(
                resolve_fixture(
                    repository(),
                    source_manifest(CARGO_TOML),
                    tag_ref(),
                    wrong,
                    ">=1.0.0",
                    4
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_missing_ambiguous_or_incomplete_asset_evidence() {
        let mut variants = Vec::new();
        let mut value = release();
        value["assets"] = json!([]);
        variants.push(value);
        let mut value = release();
        let duplicate = value["assets"][0].clone();
        value["assets"].as_array_mut().unwrap().push(duplicate);
        variants.push(value);
        let mut value = release();
        value["assets"][0]["name"] = json!("wrong");
        variants.push(value);
        let mut value = release();
        value["assets"][0]["id"] = json!(0);
        variants.push(value);
        let mut value = release();
        value["assets"][0]["state"] = json!("new");
        variants.push(value);
        let mut value = release();
        value["assets"][0]["size"] = json!(0);
        variants.push(value);
        let mut value = release();
        value["assets"][0]["size"] = json!(MAX_ASSET_BYTES + 1);
        variants.push(value);
        let mut value = release();
        value["assets"][0].as_object_mut().unwrap().remove("digest");
        variants.push(value);
        let mut value = release();
        value["assets"][0]["digest"] = json!(format!("sha256:{}", DIGEST.to_uppercase()));
        variants.push(value);
        for wrong in variants {
            assert!(
                resolve_fixture(
                    repository(),
                    source_manifest(CARGO_TOML),
                    tag_ref(),
                    wrong,
                    ">=1.0.0",
                    4
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_invalid_caller_identity_before_making_requests() {
        assert!(crate::policy::validate_sha(&"A".repeat(40)).is_err());
        assert!(canonical_sha256_digest(&format!("sha256:{}", "G".repeat(64))).is_err());
        assert!(canonical_sha256_digest(&format!("sha256:{}", "a".repeat(63))).is_err());
        assert!(
            validate_expected_asset(&ExpectedAsset {
                component: "server".into(),
                platform: "../secret".into(),
                name: "securefix".into(),
            })
            .is_err()
        );
    }

    fn valid_provenance_result() -> Value {
        let branch = "main";
        let workflow = ".github/workflows/release.yml";
        let source_ref = format!("refs/heads/{branch}");
        let signer = format!("https://github.com/{REPOSITORY}/{workflow}@{source_ref}");
        json!([{"verificationResult": {
            "signature": {"certificate": {
                "issuer":"https://token.actions.githubusercontent.com",
                "runnerEnvironment":"github-hosted",
                "subjectAlternativeName":signer,
                "buildSignerURI":signer,
                "buildSignerDigest":SOURCE_SHA,
                "githubWorkflowRepository":REPOSITORY,
                "githubWorkflowSHA":SOURCE_SHA,
                "githubWorkflowRef":source_ref,
                "githubWorkflowTrigger":"workflow_dispatch",
                "buildConfigURI":signer,
                "buildConfigDigest":SOURCE_SHA,
                "buildTrigger":"workflow_dispatch",
                "sourceRepositoryURI":format!("https://github.com/{REPOSITORY}"),
                "sourceRepositoryDigest":SOURCE_SHA,
                "sourceRepositoryRef":source_ref,
                "sourceRepositoryIdentifier":"42",
                "sourceRepositoryOwnerURI":"https://github.com/example-org",
                "sourceRepositoryOwnerIdentifier":"84",
                "runInvocationURI":format!("https://github.com/{REPOSITORY}/actions/runs/123/attempts/2")
            }},
            "statement": {
                "predicateType":"https://slsa.dev/provenance/v1",
                "subject":[{"name":"securefix-linux-x86_64","digest":{"sha256":DIGEST}}]
            }
        }}])
    }

    #[test]
    fn package_provenance_binds_subject_workflow_source_and_exact_run() {
        let release = valid_resolve(">=1.0.0").unwrap();
        let provenance_publisher = publisher();
        let verified = valid_provenance_result();
        assert_eq!(
            validate_provenance_result(
                &verified,
                &release,
                &provenance_publisher,
                ".github/workflows/release.yml",
                "main"
            )
            .unwrap(),
            (123, 2, 84)
        );
        let run = json!({
            "id":123,
            "run_attempt":2,
            "repository":{"id":42,"owner":{"id":84,"login":"example-org"}},
            "head_repository":{"id":42},
            "path":".github/workflows/release.yml",
            "event":"workflow_dispatch",
            "head_branch":"main",
            "head_sha":SOURCE_SHA,
            "status":"completed",
            "conclusion":"success"
        });
        validate_publisher_run(
            &run,
            &release,
            &provenance_publisher,
            ".github/workflows/release.yml",
            "main",
            123,
            2,
            84,
        )
        .unwrap();

        let mut wrong_subject = verified.clone();
        wrong_subject[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] =
            json!("d".repeat(64));
        let mut wrong_source = verified.clone();
        wrong_source[0]["verificationResult"]["signature"]["certificate"]["githubWorkflowSHA"] =
            json!("b".repeat(40));
        let mut wrong_workflow = verified.clone();
        wrong_workflow[0]["verificationResult"]["signature"]["certificate"]["buildSignerURI"] = json!(
            "https://github.com/example-org/securefix/.github/workflows/other.yml@refs/heads/main"
        );
        let mut wrong_attempt = run.clone();
        wrong_attempt["run_attempt"] = json!(1);
        let mut wrong_event = run.clone();
        wrong_event["event"] = json!("push");
        let mut wrong_owner = run.clone();
        wrong_owner["repository"]["owner"]["id"] = json!(85);
        for result in [
            wrong_subject,
            wrong_source,
            wrong_workflow,
            json!([verified[0].clone(), verified[0].clone()]),
        ] {
            assert!(
                validate_provenance_result(
                    &result,
                    &release,
                    &provenance_publisher,
                    ".github/workflows/release.yml",
                    "main"
                )
                .is_err()
            );
        }
        assert!(
            validate_publisher_run(
                &wrong_attempt,
                &release,
                &provenance_publisher,
                ".github/workflows/release.yml",
                "main",
                123,
                2,
                84
            )
            .is_err()
        );
        for wrong_run in [&wrong_event, &wrong_owner] {
            assert!(
                validate_publisher_run(
                    wrong_run,
                    &release,
                    &provenance_publisher,
                    ".github/workflows/release.yml",
                    "main",
                    123,
                    2,
                    84
                )
                .is_err()
            );
        }
    }

    #[test]
    fn run_invocation_must_be_canonical_github_run_attempt_uri() {
        assert_eq!(
            parse_run_invocation(
                "https://github.com/example-org/securefix/actions/runs/123/attempts/2",
                REPOSITORY
            )
            .unwrap(),
            (123, 2)
        );
        for invalid in [
            "http://github.com/example-org/securefix/actions/runs/123/attempts/2",
            "https://github.com.attacker.invalid/example-org/securefix/actions/runs/123/attempts/2",
            "https://github.com/example-org/other/actions/runs/123/attempts/2",
            "https://github.com/example-org/securefix/actions/runs/0123/attempts/2",
            "https://github.com/example-org/securefix/actions/runs/123/attempts/2/extra",
            "https://github.com/example-org/securefix/actions/runs/123/attempts/2?x=1",
        ] {
            assert!(
                parse_run_invocation(invalid, REPOSITORY).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn prereleases_are_allowed_only_by_the_explicit_scratch_parser() {
        let stable = source_manifest(CARGO_TOML);
        assert_eq!(
            source_version_with_prerelease(&stable, true)
                .unwrap()
                .to_string(),
            "1.2.3"
        );
        let pre = source_manifest("[package]\nname = \"securefix\"\nversion = \"1.2.3-pre.4\"\n");
        assert_eq!(
            source_version_with_prerelease(&pre, true)
                .unwrap()
                .to_string(),
            "1.2.3-pre.4"
        );
        assert!(source_version_with_prerelease(&pre, false).is_err());
        let build =
            source_manifest("[package]\nname = \"securefix\"\nversion = \"1.2.3+build.1\"\n");
        assert!(source_version_with_prerelease(&build, true).is_err());
    }

    #[test]
    fn scratch_package_attestation_separates_source_and_destination_and_binds_run() {
        const SOURCE: &str = "example-org/source";
        const BRANCH: &str = "integration/native-package-proof";
        const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        const WORKFLOW: &str = ".github/workflows/testing-native-package-build.yml";
        let source = crate::config::Repository {
            repository: SOURCE.to_owned(),
            id: 99,
            default_branch: "main".to_owned(),
        };
        let source_ref = format!("refs/heads/{BRANCH}");
        let signer = format!("https://github.com/{SOURCE}/{WORKFLOW}@{source_ref}");
        let valid = json!([{
            "verificationResult": {
                "signature": {"certificate": {
                    "issuer":"https://token.actions.githubusercontent.com",
                    "runnerEnvironment":"github-hosted",
                    "subjectAlternativeName":signer,
                    "buildSignerURI":signer,
                    "buildSignerDigest":SHA,
                    "githubWorkflowRepository":SOURCE,
                    "githubWorkflowSHA":SHA,
                    "githubWorkflowRef":source_ref,
                    "githubWorkflowTrigger":"workflow_dispatch",
                    "buildConfigURI":signer,
                    "buildConfigDigest":SHA,
                    "buildTrigger":"workflow_dispatch",
                    "sourceRepositoryURI":format!("https://github.com/{SOURCE}"),
                    "sourceRepositoryDigest":SHA,
                    "sourceRepositoryRef":source_ref,
                    "sourceRepositoryIdentifier":"99",
                    "sourceRepositoryOwnerURI":"https://github.com/example-org",
                    "sourceRepositoryOwnerIdentifier":"84",
                    "runInvocationURI":format!("https://github.com/{SOURCE}/actions/runs/123/attempts/1")
                }},
                "statement": {
                    "predicateType":"https://slsa.dev/provenance/v1",
                    "subject":[{"name":"securefix-linux-x86_64","digest":{"sha256":DIGEST}}]
                }
            }
        }]);
        assert_eq!(
            validate_scratch_package_attestation(
                &valid,
                &source,
                84,
                SHA,
                WORKFLOW,
                "securefix-linux-x86_64",
                DIGEST
            )
            .unwrap(),
            (123, 1, BRANCH.to_owned())
        );
        let mut wrong_destination_identity = valid.clone();
        wrong_destination_identity[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] =
            json!("100");
        let mut wrong_owner = valid.clone();
        wrong_owner[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryOwnerIdentifier"] =
            json!("85");
        let mut wrong_source = valid.clone();
        wrong_source[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] =
            json!("b".repeat(40));
        let mut wrong_predicate = valid.clone();
        wrong_predicate[0]["verificationResult"]["statement"]["subject"][0]["name"] =
            json!("other");
        for invalid in [
            wrong_destination_identity,
            wrong_owner,
            wrong_source,
            wrong_predicate,
        ] {
            assert!(
                validate_scratch_package_attestation(
                    &invalid,
                    &source,
                    84,
                    SHA,
                    WORKFLOW,
                    "securefix-linux-x86_64",
                    DIGEST
                )
                .is_err()
            );
        }

        let run = json!({
            "id":123,
            "run_attempt":1,
            "status":"completed",
            "conclusion":"success",
            "event":"workflow_dispatch",
            "head_branch":BRANCH,
            "head_sha":SHA,
            "repository":{"id":99,"full_name":SOURCE},
            "head_repository":{"id":99,"full_name":SOURCE},
            "path":WORKFLOW,
            "actor":{"id":84,"type":"User"},
            "triggering_actor":{"id":84,"type":"User"}
        });
        assert_eq!(
            validate_scratch_package_run(&run, &source, SHA, WORKFLOW, 123, 1, 84).unwrap(),
            BRANCH
        );
        let mut wrong_destination = run.clone();
        wrong_destination["repository"]["id"] = json!(100);
        let mut wrong_run_path = run.clone();
        wrong_run_path["path"] = json!(".github/workflows/other.yml");
        for invalid in [&wrong_destination, &wrong_run_path] {
            assert!(
                validate_scratch_package_run(invalid, &source, SHA, WORKFLOW, 123, 1, 84).is_err()
            );
        }
    }

    #[test]
    fn scratch_package_record_requires_the_successful_exact_writer_run() {
        const SOURCE: &str = "example-org/source";
        const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const WORKFLOW: &str = ".github/workflows/publish-native-package.yml";
        let source = crate::config::Repository {
            repository: SOURCE.to_owned(),
            id: 99,
            default_branch: "main".to_owned(),
        };
        let run = json!({
            "id": 456,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": SHA,
            "repository": {"id": 99, "full_name": SOURCE},
            "head_repository": {"id": 99, "full_name": SOURCE},
            "path": WORKFLOW,
            "actor": {"id": 84, "type": "User"},
            "triggering_actor": {"id": 84, "type": "User"}
        });
        validate_scratch_package_completed_writer_run(&run, &source, WORKFLOW, SHA, 456, 1, 84)
            .unwrap();

        let mut wrong_source = run.clone();
        wrong_source["head_sha"] = json!("b".repeat(40));
        let mut wrong_actor = run.clone();
        wrong_actor["triggering_actor"]["id"] = json!(85);
        let mut failed = run.clone();
        failed["conclusion"] = json!("failure");
        let mut wrong_path = run.clone();
        wrong_path["path"] = json!(".github/workflows/other.yml");
        for invalid in [&wrong_source, &wrong_actor, &failed, &wrong_path] {
            assert!(
                validate_scratch_package_completed_writer_run(
                    invalid, &source, WORKFLOW, SHA, 456, 1, 84,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn scratch_publication_must_match_configured_source_and_destination_identities() {
        let source = TrustedPublisher {
            repository: "example-org/client".to_owned(),
            repository_id: 42,
        };
        let destination = TrustedPublisher {
            repository: "example-org/testing-server".to_owned(),
            repository_id: 99,
        };
        let publication = ScratchPackagePublication {
            source_repository: source.repository.clone(),
            source_repository_id: source.repository_id,
            destination_repository: destination.repository.clone(),
            destination_repository_id: destination.repository_id,
            source_sha: "a".repeat(40),
            source_branch: "testing/package".to_owned(),
            tag: "v1.2.3-pre.1".to_owned(),
            release_id: 123,
            asset_id: 456,
            asset_sha256: "b".repeat(64),
            asset_size: 1024,
            producer_run_id: 789,
            producer_run_attempt: 1,
            publisher_workflow: NATIVE_PACKAGE_PUBLISHER_WORKFLOW.to_owned(),
            publisher_branch: "main".to_owned(),
            publisher_sha: "c".repeat(40),
            publisher_run_id: 987,
            publisher_run_attempt: 1,
        };

        validate_scratch_publication_repositories(&publication, &source, &destination).unwrap();

        let mut wrong_destination_name = publication.clone();
        wrong_destination_name.destination_repository = "attacker/other".to_owned();
        let mut wrong_destination_id = publication.clone();
        wrong_destination_id.destination_repository_id += 1;
        let mut wrong_source_name = publication.clone();
        wrong_source_name.source_repository = "attacker/client".to_owned();
        let mut wrong_source_id = publication.clone();
        wrong_source_id.source_repository_id += 1;
        for invalid in [
            wrong_destination_name,
            wrong_destination_id,
            wrong_source_name,
            wrong_source_id,
        ] {
            assert!(
                validate_scratch_publication_repositories(&invalid, &source, &destination).is_err()
            );
        }
    }

    #[test]
    fn scratch_package_acceptance_requires_an_explicit_instance_destination() {
        let mut instance = crate::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        assert!(configured_scratch_package_repository(&instance).is_err());

        instance.scratch_package_repository = Some(crate::config::Repository {
            repository: "example-org/testing-server".to_owned(),
            id: 99,
            default_branch: "main".to_owned(),
        });
        assert_eq!(
            configured_scratch_package_repository(&instance)
                .unwrap()
                .repository,
            "example-org/testing-server"
        );
    }

    #[test]
    fn scratch_package_artifact_is_bound_to_exact_run_source_and_bytes() {
        const SOURCE: &str = "example-org/source";
        const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let source = crate::config::Repository {
            repository: SOURCE.to_owned(),
            id: 99,
            default_branch: "main".to_owned(),
        };
        let response = json!({
            "total_count": 1,
            "artifacts": [{
                "id": 17,
                "name": PACKAGE_ARTIFACT_NAME,
                "size_in_bytes": 1234,
                "digest": format!("sha256:{DIGEST}"),
                "expired": false,
                "workflow_run": {
                    "id": 123,
                    "head_sha": SHA,
                    "head_branch": "integration/native-package-proof",
                    "repository_id": 99,
                    "head_repository_id": 99
                }
            }]
        });
        assert_eq!(
            validate_scratch_package_artifact(&response, &source, SHA, 123).unwrap(),
            (17, 1234, DIGEST.to_owned())
        );
        let mut wrong_sha = response.clone();
        wrong_sha["artifacts"][0]["workflow_run"]["head_sha"] = json!("b".repeat(40));
        let mut wrong_run = response.clone();
        wrong_run["artifacts"][0]["workflow_run"]["id"] = json!(124);
        let mut missing_digest = response.clone();
        missing_digest["artifacts"][0]
            .as_object_mut()
            .unwrap()
            .remove("digest");
        for invalid in [wrong_sha, wrong_run, missing_digest] {
            assert!(validate_scratch_package_artifact(&invalid, &source, SHA, 123).is_err());
        }
        let mut duplicate = response.clone();
        duplicate["total_count"] = json!(2);
        duplicate["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(response["artifacts"][0].clone());
        assert!(validate_scratch_package_artifact(&duplicate, &source, SHA, 123).is_err());
    }

    #[test]
    fn scratch_package_archive_requires_exact_bounded_binary_and_attestation() {
        fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for (name, contents) in entries {
                writer
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut writer, contents).unwrap();
            }
            writer.finish().unwrap().into_inner()
        }

        let good = archive(&[
            (PACKAGE_BINARY_NAME, b"binary"),
            (PACKAGE_BUNDLE_NAME, br#"{"mediaType":"bundle"}"#),
        ]);
        let (binary, bundle) =
            parse_scratch_package_artifact(&good, PACKAGE_BINARY_NAME, 20).unwrap();
        assert_eq!(binary, b"binary");
        assert_eq!(bundle, br#"{"mediaType":"bundle"}"#);
        for invalid in [
            archive(&[(PACKAGE_BINARY_NAME, b"binary"), ("extra", b"x")]),
            archive(&[
                ("../securefix-linux-x86_64", b"binary"),
                (PACKAGE_BUNDLE_NAME, b"{}"),
            ]),
            archive(&[
                (PACKAGE_BINARY_NAME, b"binary"),
                (PACKAGE_BUNDLE_NAME, b"not-json"),
            ]),
        ] {
            assert!(parse_scratch_package_artifact(&invalid, PACKAGE_BINARY_NAME, 20).is_err());
        }
        let too_large = archive(&[
            (PACKAGE_BINARY_NAME, b"binary too large"),
            (PACKAGE_BUNDLE_NAME, b"{}"),
        ]);
        assert!(parse_scratch_package_artifact(&too_large, PACKAGE_BINARY_NAME, 5).is_err());
    }

    #[test]
    fn scratch_package_manifest_and_release_asset_are_exact() {
        let manifest = SourcePackageManifest {
            schema_version: 1,
            component: "securefix-server".to_owned(),
            protocol: "securefix-native-request/v1".to_owned(),
            version: "1.2.3-pre.4".to_owned(),
            producer_workflow: ".github/workflows/testing-native-package-build.yml".to_owned(),
            publisher_workflow: None,
            max_bytes: 134217728,
            source_sha: None,
            assets: [(
                "linux-x86_64".to_owned(),
                "securefix-linux-x86_64".to_owned(),
            )]
            .into_iter()
            .collect(),
        };
        manifest
            .validate(
                &Version::parse("1.2.3-pre.4").unwrap(),
                NATIVE_CLIENT_PROTOCOL,
                SOURCE_SHA,
            )
            .unwrap();
        assert!(
            manifest
                .validate(
                    &Version::parse("1.2.3").unwrap(),
                    NATIVE_CLIENT_PROTOCOL,
                    SOURCE_SHA,
                )
                .is_err()
        );
        let mut wrong_protocol = manifest.clone();
        wrong_protocol.protocol = "other/v1".to_owned();
        assert!(
            wrong_protocol
                .validate(
                    &Version::parse("1.2.3-pre.4").unwrap(),
                    NATIVE_CLIENT_PROTOCOL,
                    SOURCE_SHA,
                )
                .is_err()
        );
        let mut wrong_source = manifest.clone();
        wrong_source.source_sha = Some("b".repeat(40));
        assert!(
            wrong_source
                .validate(
                    &Version::parse("1.2.3-pre.4").unwrap(),
                    NATIVE_CLIENT_PROTOCOL,
                    SOURCE_SHA,
                )
                .is_err()
        );
        let asset = json!({
            "id":7,
            "name":"securefix-linux-x86_64",
            "size":3,
            "state":"uploaded",
            "digest":format!("sha256:{DIGEST}")
        });
        assert!(
            validate_single_package_asset(
                std::slice::from_ref(&asset),
                "securefix-linux-x86_64",
                3,
                DIGEST
            )
            .is_ok()
        );
        assert!(validate_single_package_asset(&[], "securefix-linux-x86_64", 3, DIGEST).is_err());
        assert!(
            validate_single_package_asset(
                &[asset.clone(), asset.clone()],
                "securefix-linux-x86_64",
                3,
                DIGEST
            )
            .is_err()
        );
        assert!(validate_single_package_asset(&[asset], "other", 3, DIGEST).is_err());
    }

    #[test]
    fn source_bound_package_release_requires_schema_two_cargo_and_workflow_binding() {
        let source_sha = SOURCE_SHA;
        let producer = ".github/workflows/native-package-build.yml";
        let publisher = ".github/workflows/publish-native-package.yml";
        let cargo = b"[package]\nname = \"securefix\"\nversion = \"1.2.3\"\n";
        let manifest = serde_json::to_vec(&json!({
            "schema_version": 2,
            "component": "securefix-server",
            "protocol": NATIVE_CLIENT_PROTOCOL,
            "version": "1.2.3",
            "producer_workflow": producer,
            "publisher_workflow": publisher,
            "max_bytes": 1024,
            "assets": {"linux-x86_64": PACKAGE_BINARY_NAME}
        }))
        .unwrap();
        let binding = NativePackageReleaseSourceBinding {
            source_sha,
            version: "1.2.3",
            producer_workflow: producer,
            publisher_workflow: publisher,
            asset_name: PACKAGE_BINARY_NAME,
            max_asset_bytes: 1024,
            stable: true,
        };
        assert!(validate_native_package_release_source(cargo, &manifest, &binding).is_ok());

        for (cargo, source, version, producer, publisher, asset, max_bytes) in [
            (
                cargo.as_slice(),
                source_sha,
                "1.2.4",
                producer,
                publisher,
                PACKAGE_BINARY_NAME,
                1024,
            ),
            (
                cargo.as_slice(),
                source_sha,
                "1.2.3",
                producer,
                ".github/workflows/other.yml",
                PACKAGE_BINARY_NAME,
                1024,
            ),
            (
                cargo.as_slice(),
                source_sha,
                "1.2.3",
                producer,
                publisher,
                "other",
                1024,
            ),
            (
                cargo.as_slice(),
                source_sha,
                "1.2.3",
                producer,
                publisher,
                PACKAGE_BINARY_NAME,
                1023,
            ),
        ] {
            let binding = NativePackageReleaseSourceBinding {
                source_sha: source,
                version,
                producer_workflow: producer,
                publisher_workflow: publisher,
                asset_name: asset,
                max_asset_bytes: max_bytes,
                stable: true,
            };
            assert!(validate_native_package_release_source(cargo, &manifest, &binding).is_err());
        }
        let mut wrong_source_manifest: serde_json::Value =
            serde_json::from_slice(&manifest).unwrap();
        wrong_source_manifest["source_sha"] = serde_json::json!("b".repeat(40));
        let wrong_source_manifest = serde_json::to_vec(&wrong_source_manifest).unwrap();
        let wrong_source_binding = NativePackageReleaseSourceBinding {
            source_sha,
            version: "1.2.3",
            producer_workflow: producer,
            publisher_workflow: publisher,
            asset_name: PACKAGE_BINARY_NAME,
            max_asset_bytes: 1024,
            stable: true,
        };
        assert!(
            validate_native_package_release_source(
                cargo,
                &wrong_source_manifest,
                &wrong_source_binding
            )
            .is_err()
        );
        let prerelease_cargo = b"[package]\nname = \"securefix\"\nversion = \"1.2.3-pre.4\"\n";
        let prerelease_binding = NativePackageReleaseSourceBinding {
            source_sha,
            version: "1.2.3-pre.4",
            producer_workflow: producer,
            publisher_workflow: publisher,
            asset_name: PACKAGE_BINARY_NAME,
            max_asset_bytes: 1024,
            stable: false,
        };
        assert!(
            validate_native_package_release_source(
                prerelease_cargo,
                &manifest,
                &prerelease_binding
            )
            .is_err()
        );
    }

    #[test]
    fn checked_in_package_manifest_passes_the_release_source_validator() {
        let cargo = include_bytes!("../Cargo.toml");
        let manifest = include_bytes!("../.github/actions/load-package/source-package.json");
        let binding = NativePackageReleaseSourceBinding {
            source_sha: SOURCE_SHA,
            version: env!("CARGO_PKG_VERSION"),
            producer_workflow: NATIVE_PACKAGE_PRODUCER_WORKFLOW,
            publisher_workflow: NATIVE_PACKAGE_PUBLISHER_WORKFLOW,
            asset_name: PACKAGE_BINARY_NAME,
            max_asset_bytes: 134217728,
            stable: false,
        };
        validate_native_package_release_source(cargo, manifest, &binding).unwrap();

        let mut explicit_wrong_source: serde_json::Value =
            serde_json::from_slice(manifest).unwrap();
        explicit_wrong_source["source_sha"] = serde_json::json!("b".repeat(40));
        let explicit_wrong_source = serde_json::to_vec(&explicit_wrong_source).unwrap();
        assert!(
            validate_native_package_release_source(cargo, &explicit_wrong_source, &binding)
                .is_err()
        );
    }

    #[test]
    fn package_source_ancestor_accepts_the_github_compare_response_shape() {
        let source_sha = SOURCE_SHA;
        let compare = serde_json::json!({
            "status": "identical",
            "ahead_by": 0,
            "behind_by": 0,
            "base_commit": {"sha": source_sha},
            "merge_base_commit": {"sha": source_sha},
            "head_commit": null
        });
        validate_package_source_ancestor_comparison(&compare, source_sha, source_sha).unwrap();

        let mut stale = compare.clone();
        stale["behind_by"] = serde_json::json!(1);
        assert!(
            validate_package_source_ancestor_comparison(&stale, source_sha, source_sha).is_err()
        );
        let mut divergent = compare;
        divergent["merge_base_commit"]["sha"] = serde_json::json!("b".repeat(40));
        assert!(
            validate_package_source_ancestor_comparison(&divergent, source_sha, source_sha)
                .is_err()
        );
    }

    #[test]
    fn package_publisher_owner_and_scratch_target_come_from_workflow_declaration() {
        let destination = crate::config::Repository {
            repository: "civitaspo/testing-securefix-server".to_owned(),
            id: 1410312556,
            default_branch: "main".to_owned(),
        };
        let workflow = include_bytes!("../.github/workflows/publish-native-package.yml");
        validate_native_package_publisher_declaration(workflow, 4525500, &destination).unwrap();
        assert!(
            validate_native_package_publisher_declaration(workflow, 4525501, &destination).is_err()
        );
        let wrong_destination = crate::config::Repository {
            repository: "civitaspo/other".to_owned(),
            id: 99,
            default_branch: "main".to_owned(),
        };
        assert!(
            validate_native_package_publisher_declaration(workflow, 4525500, &wrong_destination)
                .is_err()
        );
        let producer = include_bytes!("../.github/workflows/native-package-build.yml");
        assert_eq!(
            package_workflow_owner_declaration(producer, "package producer").unwrap(),
            4525500
        );
    }

    #[test]
    fn native_package_workflows_keep_build_attestation_and_publication_credentials_separate() {
        let producer: serde_yaml::Value = serde_yaml::from_slice(include_bytes!(
            "../.github/workflows/native-package-build.yml"
        ))
        .unwrap();
        let producer_build = &producer["jobs"]["build"];
        let producer_attest = &producer["jobs"]["attest"];
        assert_eq!(producer_build["permissions"]["contents"], "read");
        assert_eq!(producer_attest["permissions"]["attestations"], "write");
        assert_eq!(producer_attest["permissions"]["id-token"], "write");
        assert!(producer_build["permissions"]["contents"] != "write");
        let producer_guard = producer_build["if"].as_str().unwrap();
        for required in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.actor_id == '4525500'",
            "github.event_name == 'workflow_dispatch'",
            "github.run_attempt == 1",
            "github.sha == github.workflow_sha",
        ] {
            assert!(producer_guard.contains(required));
        }
        let producer_steps = producer_build["steps"].as_sequence().unwrap();
        let producer_checkout = producer_steps
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/checkout@"))
            })
            .unwrap();
        assert_eq!(producer_checkout["with"]["ref"], "${{ github.sha }}");
        assert_eq!(producer_checkout["with"]["persist-credentials"], false);
        let producer_build_step = producer_steps
            .iter()
            .find(|step| step["name"] == "Test and build the selected source")
            .unwrap();
        assert!(
            producer_build_step["run"]
                .as_str()
                .unwrap()
                .contains("cargo +1.99.0 test --locked")
        );
        assert!(
            producer_build_step["run"]
                .as_str()
                .unwrap()
                .contains("cargo +1.99.0 build --locked --release --bin securefix")
        );
        assert!(
            !serde_json::to_string(producer_build)
                .unwrap()
                .contains("secrets.")
        );
        assert_eq!(producer_attest["needs"], "build");

        let publisher: serde_yaml::Value = serde_yaml::from_slice(include_bytes!(
            "../.github/workflows/publish-native-package.yml"
        ))
        .unwrap();
        let host = &publisher["jobs"]["host-build"];
        let publish = &publisher["jobs"]["publish"];
        assert_eq!(host["permissions"]["contents"], "read");
        assert_eq!(publish["environment"], "main");
        assert_eq!(publish["permissions"]["contents"], "read");
        assert_eq!(publish["permissions"]["actions"], "read");
        assert_eq!(publish["permissions"]["attestations"], "read");
        let host_guard = host["if"].as_str().unwrap();
        for required in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.actor_id == '4525500'",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'workflow_dispatch'",
            "github.run_attempt == 1",
            "github.sha == github.workflow_sha",
        ] {
            assert!(host_guard.contains(required));
        }
        let host_steps = host["steps"].as_sequence().unwrap();
        let host_checkout = host_steps
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("actions/checkout@"))
            })
            .unwrap();
        assert_eq!(host_checkout["with"]["ref"], "${{ github.workflow_sha }}");
        assert_eq!(host_checkout["with"]["persist-credentials"], false);
        let host_build = host_steps
            .iter()
            .find(|step| {
                step["name"] == "Build the publisher host from the protected workflow source"
            })
            .unwrap();
        assert!(
            host_build["run"]
                .as_str()
                .unwrap()
                .contains("cargo +1.99.0 build --locked --release --bin securefix")
        );
        assert!(!serde_json::to_string(host).unwrap().contains("secrets."));
        assert_eq!(
            host["outputs"]["artifact-id"],
            "${{ steps.upload.outputs.artifact-id }}"
        );
        let publish_guard = publish["if"].as_str().unwrap();
        assert!(publish_guard.contains("needs.host-build.result == 'success'"));
        assert!(publish_guard.contains("github.sha == github.workflow_sha"));
        let steps = publish["steps"].as_sequence().unwrap();
        let host_download_index = steps
            .iter()
            .position(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
                    && step["with"]["artifact-ids"] == "${{ needs.host-build.outputs.artifact-id }}"
            })
            .unwrap();
        let step_index = |name: &str| {
            steps
                .iter()
                .position(|step| step["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing package publisher step {name}"))
        };
        let preflight_index = step_index(
            "Qualify the exact producer artifact and attestation before minting a writer token",
        );
        let writer_index = steps
            .iter()
            .position(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
            })
            .unwrap();
        assert_eq!(steps[writer_index]["with"]["permission-contents"], "write");
        assert_eq!(
            steps[writer_index]["with"]["repositories"],
            "${{ inputs.channel == 'stable' && 'securefix-server' || 'testing-securefix-server' }}"
        );
        let package_publish_index = step_index("Publish the exact attested executable");
        assert!(
            host_download_index < preflight_index
                && preflight_index < writer_index
                && writer_index < package_publish_index
        );
        assert_eq!(
            steps[preflight_index]["env"]["GITHUB_TOKEN"],
            "${{ github.token }}"
        );
        assert_eq!(
            steps[preflight_index]["env"]["GITHUB_ACTOR_ID"],
            "${{ github.actor_id }}"
        );
        assert!(steps[preflight_index]["env"]["SECUREFIX_PACKAGE_PUBLISH_TOKEN"].is_null());
        assert!(steps[preflight_index]["env"]["SECUREFIX_PACKAGE_TOKEN"].is_null());
        assert!(
            steps[preflight_index]["run"]
                .as_str()
                .unwrap()
                .contains("package preflight")
        );
        assert!(
            steps[package_publish_index]["run"]
                .as_str()
                .unwrap()
                .contains("package publish")
        );
        let publish_yaml = std::str::from_utf8(include_bytes!(
            "../.github/workflows/publish-native-package.yml"
        ))
        .unwrap();
        assert!(publish_yaml.contains("SECUREFIX_PACKAGE_PUBLISH_TOKEN"));
        assert!(publish_yaml.contains("SECUREFIX_PACKAGE_TOKEN"));
        assert!(publish_yaml.contains("steps.writer.outputs.token"));
        let approval: serde_yaml::Value = serde_yaml::from_slice(include_bytes!(
            "../.github/workflows/testing-native-approve.yml"
        ))
        .unwrap();
        assert!(
            approval["on"]["workflow_dispatch"]["inputs"]
                .get("package_publication_json")
                .is_none()
        );
        for job in ["validate-request", "apply-approval"] {
            let loaders: Vec<_> = approval["jobs"][job]["steps"]
                .as_sequence()
                .unwrap()
                .iter()
                .filter(|step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|uses| uses.contains("/.github/actions/load-package@"))
                })
                .collect();
            assert!(!loaders.is_empty());
            for loader in loaders {
                assert_eq!(
                    serde_json::to_value(&loader["with"]).unwrap(),
                    serde_json::json!({"token":"${{ github.token }}"})
                );
            }
        }
    }
}
