//! Read-only resolution of one pinned component's published release metadata.
//!
//! A resolved package is not an attestation or permission to execute bytes. A
//! host loader must separately verify the downloaded asset's exact digest,
//! producer run, source, and signature before it executes anything.

use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use semver::{Version, VersionReq};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_CARGO_TOML_BYTES: usize = 64 * 1024;
const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;

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
    let release = resolve_release(
        api,
        publisher,
        implementation_sha,
        expected_asset,
        acceptable_versions,
    )?;
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
    let raw_version = package
        .get("version")
        .and_then(|item| item.as_str())
        .context("source Cargo.toml package.version is missing or invalid")?;
    let version =
        Version::parse(raw_version).context("source package version is invalid SemVer")?;
    ensure!(
        version.pre.is_empty() && version.build.is_empty() && version.to_string() == raw_version,
        "source package version must be canonical stable SemVer"
    );
    Ok(version)
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
        json!({"id":42,"full_name":REPOSITORY})
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
}
