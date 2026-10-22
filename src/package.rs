//! Read-only resolution of one pinned component's published release metadata.
//!
//! A resolved package and downloaded asset are not execution authority. A host
//! consumer must use `VerifiedPackage`, which adds source/run/signature proof.

use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
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
const PACKAGE_PRODUCER_WORKFLOW: &str = ".github/workflows/testing-native-package-build.yml";
const PACKAGE_PUBLISHER_WORKFLOW: &str = ".github/workflows/testing-publish-native-package.yml";

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

/// A release asset whose bytes and exact publisher run/source attestation passed.
/// This type is the only package result a host consumer should use before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    asset: DownloadedAsset,
    publisher_run_id: u64,
    publisher_run_attempt: u64,
}

impl VerifiedPackage {
    pub fn release(&self) -> &ResolvedRelease {
        self.asset.release()
    }

    pub fn bytes(&self) -> &[u8] {
        self.asset.bytes()
    }

    pub fn publisher_run(&self) -> (u64, u64) {
        (self.publisher_run_id, self.publisher_run_attempt)
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
    /// artifact was attested. These are distinct from the Client request
    /// capture workflow configured by the instance.
    pub package_publisher_workflow: String,
    pub package_publisher_branch: String,
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
        package: VerifiedPackage {
            asset: DownloadedAsset {
                release,
                bytes: b"synthetic-test-binary".to_vec(),
            },
            publisher_run_id: 8_767,
            publisher_run_attempt: 1,
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
    loader_action_sha: &str,
    expected_protocol: &str,
    source_default_branch: &str,
) -> Result<VerifiedNativeClientPackage> {
    crate::policy::validate_repository(&acceptable.repository)?;
    ensure!(acceptable.id > 0, "Client repository ID is invalid");
    crate::policy::validate_sha(signer_sha)?;
    crate::policy::validate_sha(loader_action_sha)?;
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

    let loader_manifest_path = ".github/actions/load-package/package.json";
    let loader_manifest_response: Value = api.get(&format!(
        "/repos/{}/contents/{loader_manifest_path}?ref={loader_action_sha}",
        acceptable.repository
    ))?;
    let loader_manifest_bytes = source_file_bytes(&loader_manifest_response, loader_manifest_path)?;
    let manifest: SourcePackageManifest = serde_json::from_slice(&loader_manifest_bytes)
        .context("fixed Client package loader manifest is invalid JSON")?;
    let binary_source_sha = package_source_sha(&manifest, loader_action_sha)?;
    let binary_version = Version::parse(&manifest.version)
        .context("fixed Client package version is invalid SemVer")?;
    ensure!(
        binary_version.build.is_empty()
            && binary_version.pre.is_empty()
            && binary_version.to_string() == manifest.version,
        "fixed Client package version must be canonical stable SemVer"
    );
    manifest.validate(&binary_version, expected_protocol, &binary_source_sha)?;

    let source_manifest_response: Value = api.get(&format!(
        "/repos/{}/contents/{loader_manifest_path}?ref={binary_source_sha}",
        acceptable.repository
    ))?;
    let source_manifest_bytes = source_file_bytes(&source_manifest_response, loader_manifest_path)?;
    ensure!(
        source_manifest_bytes == loader_manifest_bytes,
        "binary source package manifest differs from the fixed loader mapping"
    );

    let asset_name = manifest
        .assets
        .get("linux-x86_64")
        .context("fixed Client package has no linux-x86_64 asset")?
        .clone();
    let expected_asset = ExpectedAsset {
        component: manifest.component.clone(),
        platform: "linux-x86_64".to_owned(),
        name: asset_name,
    };
    let exact_binary_version = VersionReq::parse(&format!("={binary_version}"))
        .context("fixed Client package version cannot form an exact version requirement")?;
    let package = download_verified_release_bounded(
        api,
        &publisher,
        &binary_source_sha,
        &expected_asset,
        &exact_binary_version,
        &manifest.producer_workflow,
        source_default_branch,
        manifest.max_bytes,
    )?;

    Ok(VerifiedNativeClientPackage {
        implementation_sha: signer_sha.to_owned(),
        implementation_version,
        loader_action_sha: loader_action_sha.to_owned(),
        binary_source_sha,
        binary_version,
        protocol: manifest.protocol,
        package_publisher_workflow: manifest.producer_workflow,
        package_publisher_branch: source_default_branch.to_owned(),
        package,
    })
}

/// Qualify the explicitly owner-dispatched development package published to
/// the isolated integration repository. This path is gated by the testing
/// deployment, its configured owner and protected-branch dispatch context, and
/// a complete `ScratchPackagePublication` record. It deliberately performs no
/// fallback to stable release resolution and is not an ordinary operation.
// Preserve separate authority inputs so each boundary is checked explicitly.
#[allow(clippy::too_many_arguments)]
pub fn verify_native_client_package_scratch(
    api: &GitHub,
    instance: &crate::instance_config::InstanceConfig,
    execution_mode: crate::api::NativeScratchMode,
    acceptable: &crate::instance_config::AcceptableClients,
    signer_sha: &str,
    loader_action_sha: &str,
    expected_protocol: &str,
    publication: &ScratchPackagePublication,
) -> Result<VerifiedNativeClientPackage> {
    crate::api::validate_native_test_host_context(instance, execution_mode)?;
    crate::policy::validate_repository(&acceptable.repository)?;
    ensure!(acceptable.id > 0, "Client repository ID is invalid");
    crate::policy::validate_sha(signer_sha)?;
    crate::policy::validate_sha(loader_action_sha)?;
    ensure!(
        expected_protocol == NATIVE_CLIENT_PROTOCOL,
        "requested Client protocol is not supported by this Server"
    );

    let trusted = crate::config::trusted()?;
    let deployment = &trusted.deployment;
    require_scratch_package_deployment(deployment)?;
    ensure!(
        instance.instance.repository == deployment.server.repository
            && instance.instance.id == deployment.server.id
            && acceptable.repository != deployment.integration.repository,
        "scratch package verifier is outside the configured testing deployment"
    );

    let source = TrustedPublisher {
        repository: acceptable.repository.clone(),
        repository_id: acceptable.id,
    };
    let destination = TrustedPublisher {
        repository: deployment.integration.repository.clone(),
        repository_id: deployment.integration.id,
    };
    ensure!(
        publication.source_repository == source.repository
            && publication.source_repository_id == source.repository_id
            && publication.destination_repository == destination.repository
            && publication.destination_repository_id == destination.repository_id,
        "scratch publication record does not match the configured source and destination"
    );
    ensure!(
        publication.producer_run_id > 0
            && publication.producer_run_attempt == 1
            && publication.release_id > 0
            && publication.asset_id > 0
            && publication.asset_size > 0
            && publication.asset_size <= MAX_ASSET_BYTES,
        "scratch publication record has invalid run or release identity"
    );
    crate::config::validate_branch(&publication.source_branch)?;
    crate::policy::validate_sha(&publication.source_sha)?;
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
    let destination_repository: Value = api.get(&format!("/repos/{}", destination.repository))?;
    validate_remote_repository_identity(&destination_repository, &destination)?;
    let destination_default_branch = destination_repository["default_branch"]
        .as_str()
        .context("scratch destination default branch is missing")?;
    ensure!(
        destination_default_branch == deployment.integration.default_branch,
        "scratch destination default branch differs from the testing policy"
    );

    // The request attestation and owner-dispatched test context bind this
    // unreleased implementation SHA. Its version is recorded for diagnostics;
    // stable deployment ranges remain enforced only by the normal verifier.
    let signer_cargo: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={signer_sha}",
        source.repository
    ))?;
    let implementation_version = source_version_with_prerelease(&signer_cargo, true)?;

    let loader_manifest_path = ".github/actions/load-package/package.json";
    let loader_manifest_response: Value = api.get(&format!(
        "/repos/{}/contents/{loader_manifest_path}?ref={loader_action_sha}",
        source.repository
    ))?;
    let loader_manifest_bytes = source_file_bytes(&loader_manifest_response, loader_manifest_path)?;
    let manifest: SourcePackageManifest = serde_json::from_slice(&loader_manifest_bytes)
        .context("fixed Client package loader manifest is invalid JSON")?;
    let binary_source_sha = package_source_sha(&manifest, loader_action_sha)?;
    ensure!(
        binary_source_sha == publication.source_sha,
        "scratch publication source differs from the fixed loader mapping"
    );
    let binary_version =
        Version::parse(&manifest.version).context("scratch package version is invalid SemVer")?;
    ensure!(
        binary_version.build.is_empty()
            && !binary_version.pre.is_empty()
            && binary_version.to_string() == manifest.version
            && publication.tag == format!("v{binary_version}"),
        "scratch package must use the exact canonical prerelease version and tag"
    );
    manifest.validate(&binary_version, expected_protocol, &binary_source_sha)?;
    ensure!(
        publication.asset_size <= manifest.max_bytes,
        "scratch package asset exceeds its fixed source manifest limit"
    );
    let source_manifest_response: Value = api.get(&format!(
        "/repos/{}/contents/{loader_manifest_path}?ref={binary_source_sha}",
        source.repository
    ))?;
    let source_manifest_bytes = source_file_bytes(&source_manifest_response, loader_manifest_path)?;
    ensure!(
        source_manifest_bytes == loader_manifest_bytes,
        "scratch binary source manifest differs from the fixed loader mapping"
    );
    let source_cargo: Value = api.get(&format!(
        "/repos/{}/contents/Cargo.toml?ref={binary_source_sha}",
        source.repository
    ))?;
    ensure!(
        source_version_with_prerelease(&source_cargo, true)? == binary_version,
        "scratch package version differs from its source Cargo manifest"
    );

    let asset_name = manifest
        .assets
        .get("linux-x86_64")
        .context("fixed Client package has no linux-x86_64 asset")?;
    let release: Value = api.get(&format!(
        "/repos/{}/releases/{}",
        destination.repository, publication.release_id
    ))?;
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
        &publication.source_branch,
    )?;
    ensure!(
        package.publisher_run()
            == (
                publication.producer_run_id,
                publication.producer_run_attempt
            ),
        "scratch package attestation differs from the exact producer run record"
    );

    Ok(VerifiedNativeClientPackage {
        implementation_sha: signer_sha.to_owned(),
        implementation_version,
        loader_action_sha: loader_action_sha.to_owned(),
        binary_source_sha,
        binary_version,
        protocol: manifest.protocol,
        package_publisher_workflow: manifest.producer_workflow,
        package_publisher_branch: publication.source_branch.clone(),
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

fn package_source_sha(manifest: &SourcePackageManifest, loader_action_sha: &str) -> Result<String> {
    crate::policy::validate_sha(loader_action_sha)?;
    let source_sha = manifest.source_sha.as_deref().unwrap_or(loader_action_sha);
    crate::policy::validate_sha(source_sha)?;
    Ok(source_sha.to_owned())
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
    let (publisher_run_id, publisher_run_attempt, publisher_owner_id) = validate_provenance_result(
        &verified,
        release,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
    )?;
    let run: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{publisher_run_id}/attempts/{publisher_run_attempt}"
    ))?;
    validate_publisher_run(
        &run,
        release,
        attestation_publisher,
        publisher_workflow,
        publisher_branch,
        publisher_run_id,
        publisher_run_attempt,
        publisher_owner_id,
    )?;
    Ok(VerifiedPackage {
        asset: downloaded,
        publisher_run_id,
        publisher_run_attempt,
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
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "attested package publisher run is not the successful configured source run"
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
        "/repos/{}/contents/.github/actions/load-package/package.json?ref={source_sha}",
        source.repository
    ))?;
    let manifest_bytes = source_file_bytes(
        &source_package_manifest,
        ".github/actions/load-package/package.json",
    )?;
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
        &std::env::var("GITHUB_SHA")?,
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

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePackageManifest {
    schema_version: u8,
    component: String,
    protocol: String,
    version: String,
    producer_workflow: String,
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
        if let Some(source_sha) = &self.source_sha {
            crate::policy::validate_sha(source_sha)?;
            ensure!(
                source_sha == expected_source_sha,
                "source package manifest binary source differs from the resolved source revision"
            );
        }
        ensure!(
            self.schema_version == 1
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
            SOURCE_SHA,
            "securefix-native-request/v999",
            "main",
        );
        assert!(result.is_err());
        fixture.finish();
    }

    #[test]
    fn client_package_source_defaults_to_loader_revision_or_uses_explicit_mapping() {
        const LOADER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const PACKAGE_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";
        let mut manifest: SourcePackageManifest = serde_json::from_value(json!({
            "schema_version":1,
            "component":"securefix-server",
            "protocol":"securefix-native-request/v1",
            "version":"1.2.3",
            "producer_workflow":".github/workflows/testing-native-package-build.yml",
            "max_bytes":134217728,
            "assets":{"linux-x86_64":"securefix-linux-x86_64"}
        }))
        .unwrap();
        assert_eq!(
            package_source_sha(&manifest, LOADER_SHA).unwrap(),
            LOADER_SHA
        );
        manifest.source_sha = Some(PACKAGE_SHA.to_owned());
        assert_eq!(
            package_source_sha(&manifest, LOADER_SHA).unwrap(),
            PACKAGE_SHA
        );
        manifest.source_sha = Some("mutable".to_owned());
        assert!(package_source_sha(&manifest, LOADER_SHA).is_err());
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
}
