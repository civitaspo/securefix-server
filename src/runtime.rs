use crate::api::{ApiError, GitHub};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_ARCHIVE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_MANIFEST_SIZE: usize = 65_536;
const ASSET: &str = "securefix-runtime-linux-x86_64.tar.gz";

/// The canonical SemVer identity recorded in the source Cargo manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeVersion(semver::Version);

impl RuntimeVersion {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let version = semver::Version::parse(value).context("invalid runtime SemVer version")?;
        ensure!(
            version.build.is_empty(),
            "runtime version must not contain build metadata"
        );
        ensure!(
            version.to_string() == value,
            "runtime version is not canonical SemVer"
        );
        Ok(Self(version))
    }

    pub(crate) fn as_semver(&self) -> &semver::Version {
        &self.0
    }

    pub(crate) fn tag(&self) -> String {
        format!("v{}", self.0)
    }
}

/// Read the runtime version from Cargo.toml at the exact source commit.
pub(crate) fn version_at_source(api: &GitHub, source_sha: &str) -> Result<RuntimeVersion> {
    crate::policy::validate_sha(source_sha)?;
    let repository = &crate::config::trusted()?.deployment.server.repository;
    let manifest: Value = api.get(&format!(
        "/repos/{repository}/contents/Cargo.toml?ref={source_sha}"
    ))?;
    manifest_source_version(&manifest)
}

fn manifest_source_version(manifest: &Value) -> Result<RuntimeVersion> {
    ensure!(
        manifest["path"] == "Cargo.toml" && manifest["type"] == "file",
        "source manifest identity is invalid"
    );
    let size = manifest["size"]
        .as_u64()
        .context("source Cargo.toml size must be an integer")?;
    ensure!(
        size <= MAX_MANIFEST_SIZE as u64,
        "source Cargo.toml exceeds size limit"
    );
    ensure!(
        manifest["encoding"] == "base64",
        "source Cargo.toml encoding is unsupported"
    );
    let encoded = manifest["content"]
        .as_str()
        .context("source Cargo.toml content missing")?;
    ensure!(
        encoded.len() <= (MAX_MANIFEST_SIZE * 4 / 3) + 4096,
        "encoded Cargo.toml exceeds size limit"
    );
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace('\n', ""))
        .context("invalid source Cargo.toml base64")?;
    ensure!(
        bytes.len() <= MAX_MANIFEST_SIZE,
        "source Cargo.toml exceeds size limit"
    );
    ensure!(
        size == bytes.len() as u64,
        "source Cargo.toml size does not match decoded content"
    );
    parse_source_manifest(&bytes)
}

fn parse_source_manifest(bytes: &[u8]) -> Result<RuntimeVersion> {
    ensure!(
        bytes.len() <= MAX_MANIFEST_SIZE,
        "source Cargo.toml exceeds size limit"
    );
    let text = std::str::from_utf8(bytes).context("source Cargo.toml is not UTF-8")?;
    let document = text
        .parse::<toml_edit::DocumentMut>()
        .context("invalid source Cargo.toml")?;
    let version = document["package"]["version"]
        .as_str()
        .context("source Cargo.toml package.version must be a string")?;
    RuntimeVersion::parse(version)
}

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "Publish the current trusted runtime archive")]
    Publish {
        #[arg(long)]
        archive: PathBuf,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Publish { archive } => {
            let source_sha =
                std::env::var("SECUREFIX_SOURCE_SHA").context("missing SECUREFIX_SOURCE_SHA")?;
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            publish(&api, &source_sha, &archive)
        }
    }
}

fn publish(api: &GitHub, source_sha: &str, archive_path: &Path) -> Result<()> {
    let trusted = crate::config::trusted()?;
    let repository = trusted.deployment.server.repository.as_str();
    let default_branch = trusted.deployment.server.default_branch.as_str();
    crate::policy::validate_sha(source_sha)?;
    let current_main: Value = api.get(&format!("/repos/{repository}/commits/{default_branch}"))?;
    ensure!(
        current_main["sha"] == source_sha,
        "runtime is no longer current; publication denied"
    );
    let version = version_at_source(api, source_sha)?;
    ensure!(
        version.as_semver().to_string() == env!("CARGO_PKG_VERSION"),
        "compiled runtime version differs from source Cargo.toml"
    );
    let (archive, digest) = read_archive(archive_path)?;
    let archive_size = archive.len() as u64;
    let tag = version.tag();
    let ref_path = format!("/repos/{repository}/git/ref/tags/{tag}");

    let release_path = format!("/repos/{repository}/releases/tags/{tag}");
    let prerelease = !version.as_semver().pre.is_empty();
    let existing_release = get_optional(api, &release_path)?;
    if let Some(release) = &existing_release {
        validate_release(release, source_sha, &tag, prerelease)?;
        let assets = release["assets"]
            .as_array()
            .context("release lacks asset list")?;
        validate_assets(assets, &digest, archive_size, release["draft"] == true)?;
    }

    match get_optional(api, &ref_path)? {
        Some(tag_ref) => validate_ref(&tag_ref, source_sha)?,
        None => {
            let created: Value = api.post(
                &format!("/repos/{repository}/git/refs"),
                &json!({"ref": format!("refs/tags/{tag}"), "sha": source_sha}),
            )?;
            validate_ref(&created, source_sha)?;
        }
    }

    let release = match existing_release {
        Some(release) => release,
        None => api.post(
            &format!("/repos/{repository}/releases"),
            &json!({
                "tag_name": tag,
                "name": tag,
                "target_commitish": source_sha,
                "draft": true,
                "prerelease": !version.as_semver().pre.is_empty(),
                "make_latest": "false",
                "generate_release_notes": false
            }),
        )?,
    };
    validate_release(&release, source_sha, &tag, prerelease)?;
    let release_id = release["id"]
        .as_u64()
        .context("release response lacks ID")?;
    let assets = release["assets"]
        .as_array()
        .context("release lacks asset list")?;
    match validate_assets(assets, &digest, archive_size, release["draft"] == true)? {
        AssetState::EmptyDraft => {
            let upload_url = format!(
                "https://uploads.github.com/repos/{repository}/releases/{release_id}/assets?name={ASSET}"
            );
            let _: Value = api.upload(&upload_url, archive, "application/gzip")?;
        }
        AssetState::Matching => {}
    }

    let current: Value = api.get(&format!("/repos/{repository}/releases/{release_id}"))?;
    validate_release(&current, source_sha, &tag, prerelease)?;
    let assets = current["assets"]
        .as_array()
        .context("release lacks asset list")?;
    ensure!(
        validate_assets(assets, &digest, archive_size, current["draft"] == true)?
            == AssetState::Matching,
        "uploaded runtime asset does not match the local archive"
    );
    if current["draft"] == true {
        let _: Value = api.patch(
            &format!("/repos/{repository}/releases/{release_id}"),
            &json!({"draft": false}),
        )?;
    }
    let published: Value = api.get(&format!("/repos/{repository}/releases/{release_id}"))?;
    validate_release(&published, source_sha, &tag, prerelease)?;
    ensure!(
        published["draft"] == false,
        "runtime release did not publish"
    );
    let assets = published["assets"]
        .as_array()
        .context("release lacks asset list")?;
    ensure!(
        validate_assets(assets, &digest, archive_size, false)? == AssetState::Matching,
        "published runtime asset does not match the local archive"
    );
    ensure_version_tag(api, source_sha, &version)
}

pub(crate) fn version_tag(version: &RuntimeVersion) -> String {
    version.tag()
}

fn ensure_version_tag(api: &GitHub, source_sha: &str, version: &RuntimeVersion) -> Result<()> {
    let repository = &crate::config::trusted()?.deployment.server.repository;
    let tag = version_tag(version);
    let current_main: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        crate::config::trusted()?.deployment.server.default_branch
    ))?;
    ensure!(
        current_main["sha"] == source_sha,
        "runtime is no longer current; tag denied"
    );
    match get_optional(api, &format!("/repos/{repository}/git/ref/tags/{tag}"))? {
        Some(reference) => validate_ref(&reference, source_sha),
        None => {
            let reference: Value = api.post(
                &format!("/repos/{repository}/git/refs"),
                &json!({"ref":format!("refs/tags/{tag}"),"sha":source_sha}),
            )?;
            validate_ref(&reference, source_sha)
        }
    }
}

fn read_archive(path: &Path) -> Result<(Vec<u8>, String)> {
    let mut file = File::open(path).context("open runtime archive")?;
    ensure!(
        file.metadata()?.len() <= MAX_ARCHIVE_SIZE,
        "runtime archive exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ARCHIVE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE_SIZE,
        "runtime archive exceeds size limit"
    );
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn get_optional(api: &GitHub, path: &str) -> Result<Option<Value>> {
    match api.get(path) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn validate_ref(tag_ref: &Value, source_sha: &str) -> Result<()> {
    ensure!(
        tag_ref["object"]["type"] == "commit",
        "runtime tag must be a lightweight commit ref"
    );
    ensure!(
        tag_ref["object"]["sha"] == source_sha,
        "runtime tag points at a different commit"
    );
    Ok(())
}

fn validate_release(release: &Value, source_sha: &str, tag: &str, prerelease: bool) -> Result<()> {
    ensure!(release["tag_name"] == tag, "runtime release tag mismatch");
    ensure!(release["name"] == tag, "runtime release name mismatch");
    ensure!(
        release["target_commitish"] == source_sha,
        "runtime release target mismatch"
    );
    ensure!(
        release["draft"].is_boolean(),
        "runtime release draft state missing"
    );
    ensure!(
        release["prerelease"] == prerelease,
        "runtime release prerelease state mismatch"
    );
    ensure!(
        release["id"].as_u64().is_some(),
        "runtime release ID missing"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum AssetState {
    EmptyDraft,
    Matching,
}

fn validate_assets(assets: &[Value], digest: &str, size: u64, draft: bool) -> Result<AssetState> {
    if assets.is_empty() && draft {
        return Ok(AssetState::EmptyDraft);
    }
    ensure!(assets.len() == 1, "runtime release has unexpected assets");
    let asset = &assets[0];
    ensure!(
        asset["name"] == ASSET,
        "runtime release asset name mismatch"
    );
    ensure!(
        asset["state"] == "uploaded",
        "runtime asset upload is incomplete"
    );
    ensure!(
        asset["size"].as_u64() == Some(size),
        "runtime asset size mismatch"
    );
    ensure!(
        asset["digest"] == format!("sha256:{digest}"),
        "runtime asset digest mismatch"
    );
    Ok(AssetState::Matching)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};
    use serde_json::json;
    use tempfile::NamedTempFile;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn version() -> RuntimeVersion {
        RuntimeVersion::parse(env!("CARGO_PKG_VERSION")).unwrap()
    }

    fn tag() -> String {
        version().tag()
    }

    fn manifest() -> Value {
        use base64::Engine;
        let bytes = format!("[package]\nversion = \"{}\"\n", env!("CARGO_PKG_VERSION"));
        json!({"path":"Cargo.toml","type":"file","size":bytes.len(),"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(bytes)})
    }

    fn path(suffix: &str) -> String {
        format!(
            "/repos/{}{suffix}",
            crate::config::trusted()
                .unwrap()
                .deployment
                .server
                .repository
        )
    }

    fn default_branch() -> String {
        crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .default_branch
            .clone()
    }

    fn release(draft: bool, assets: Value) -> Value {
        json!({"id":7,"tag_name":tag(),"name":tag(),"target_commitish":SHA,"draft":draft,"prerelease":!version().as_semver().pre.is_empty(),"assets":assets})
    }

    fn asset(bytes: &[u8]) -> Value {
        let digest = format!("{:x}", Sha256::digest(bytes));
        json!({"name":ASSET,"state":"uploaded","size":bytes.len(),"digest":format!("sha256:{digest}")})
    }

    #[test]
    fn accepts_only_empty_draft_or_exact_single_uploaded_asset() {
        let bytes = b"archive";
        let digest = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(
            validate_assets(&[], &digest, bytes.len() as u64, true).unwrap(),
            AssetState::EmptyDraft
        );
        assert_eq!(
            validate_assets(&[asset(bytes)], &digest, bytes.len() as u64, true).unwrap(),
            AssetState::Matching
        );
        assert_eq!(
            validate_assets(&[asset(bytes)], &digest, bytes.len() as u64, false).unwrap(),
            AssetState::Matching
        );
        assert!(validate_assets(&[], &digest, bytes.len() as u64, false).is_err());
        assert!(validate_assets(&[asset(b"changed")], &digest, bytes.len() as u64, true).is_err());
        assert!(
            validate_assets(
                &[asset(bytes), asset(bytes)],
                &digest,
                bytes.len() as u64,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_annotated_or_moved_runtime_tag_and_wrong_release_identity() {
        assert!(validate_ref(&json!({"object":{"type":"tag","sha":SHA}}), SHA).is_err());
        assert!(validate_ref(&json!({"object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}), SHA).is_err());
        assert!(validate_release(&release(true, json!([])), SHA, "wrong-tag", true).is_err());
        let mut moved = release(true, json!([]));
        moved["target_commitish"] = json!(default_branch());
        assert!(validate_release(&moved, SHA, &tag(), true).is_err());
    }

    #[test]
    fn stale_runtime_stops_before_release_lookup_or_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let main = path(&format!("/commits/{}", default_branch()));
        let fixture = Fixture::new(vec![Route::get(
            main,
            json!({"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}),
        )]);
        assert!(publish(&fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn non_404_lookup_failure_is_not_treated_as_absence() {
        let reference = path(&format!("/git/ref/tags/{}", tag()));
        let fixture = Fixture::new(vec![Route::request(
            "GET",
            reference.clone(),
            403,
            json!({"message":"forbidden"}),
        )]);
        assert!(get_optional(&fixture.api, &reference).is_err());
        fixture.finish();
    }

    #[test]
    fn matching_published_release_is_an_idempotent_read_only_retry() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let main = path(&format!("/commits/{}", default_branch()));
        let reference = path(&format!("/git/ref/tags/{}", tag()));
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let numbered_release = path("/releases/7");
        let existing = release(false, json!([asset(b"archive")]));
        let fixture = Fixture::new(vec![
            Route::get(main, json!({"sha":SHA})),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path, existing.clone()),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(numbered_release.clone(), existing.clone()),
            Route::get(numbered_release, existing),
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::get(reference, json!({"object":{"type":"commit","sha":SHA}})),
        ]);
        publish(&fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn matching_draft_resumes_and_publishes_without_reupload() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let main = path(&format!("/commits/{}", default_branch()));
        let reference = path(&format!("/git/ref/tags/{}", tag()));
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let numbered_release = path("/releases/7");
        let draft = release(true, json!([asset(b"archive")]));
        let published = release(false, json!([asset(b"archive")]));
        let fixture = Fixture::new(vec![
            Route::get(main.clone(), json!({"sha":SHA})),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path, draft.clone()),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(numbered_release.clone(), draft),
            Route::get(main, json!({"sha":SHA})),
            Route::request("PATCH", numbered_release.clone(), 200, published.clone())
                .with_request_body(json!({"draft":false})),
            Route::get(numbered_release, published),
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::get(reference, json!({"object":{"type":"commit","sha":SHA}})),
        ]);
        publish(&fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn asset_mismatch_fails_before_any_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let main = path(&format!("/commits/{}", default_branch()));
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let mismatch = release(true, json!([asset(b"different bytes")]));
        let fixture = Fixture::new(vec![
            Route::get(main, json!({"sha":SHA})),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path, mismatch),
        ]);
        assert!(publish(&fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn canonical_semver_tag_is_created_once_and_never_retargeted() {
        let version = version();
        let tag = version_tag(&version);
        let reference = path(&format!("/git/ref/tags/{tag}"));
        let fixture = Fixture::new(vec![
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::request(
                "GET",
                reference.clone(),
                404,
                json!({"message":"Not Found"}),
            ),
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::request(
                "POST",
                path("/git/refs"),
                201,
                json!({"object":{"type":"commit","sha":SHA}}),
            )
            .with_request_body(json!({"ref":format!("refs/tags/{tag}"),"sha":SHA})),
        ]);
        ensure_version_tag(&fixture.api, SHA, &version).unwrap();
        fixture.finish();
        let fixture = Fixture::new(vec![
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::get(
                reference,
                json!({"object":{"type":"commit","sha":"b".repeat(40)}}),
            ),
        ]);
        assert!(ensure_version_tag(&fixture.api, SHA, &version).is_err());
        fixture.finish();
    }

    #[test]
    fn source_manifest_version_requires_a_bounded_literal_package_version() {
        assert_eq!(
            parse_source_manifest(b"[package]\nversion = \"0.2.0-pre.1\"\n")
                .unwrap()
                .tag(),
            "v0.2.0-pre.1"
        );
        for invalid in [
            &b"[package]\nversion.workspace = true\n"[..],
            &b"[package]\nversion = \"1.2.3+sha\"\n"[..],
            &b"[package]\nversion = \"not-semver\"\n"[..],
            &[0xff][..],
        ] {
            assert!(parse_source_manifest(invalid).is_err());
        }
        assert!(parse_source_manifest(&vec![b' '; MAX_MANIFEST_SIZE + 1]).is_err());
    }

    #[test]
    fn source_manifest_api_response_must_have_exact_identity_and_decoded_size() {
        let valid = manifest();
        assert_eq!(manifest_source_version(&valid).unwrap(), version());

        let mut wrong_path = valid.clone();
        wrong_path["path"] = json!("other.toml");
        assert!(manifest_source_version(&wrong_path).is_err());

        let mut wrong_type = valid.clone();
        wrong_type["type"] = json!("dir");
        assert!(manifest_source_version(&wrong_type).is_err());

        let mut fractional_size = valid.clone();
        fractional_size["size"] = json!(2.5);
        assert!(manifest_source_version(&fractional_size).is_err());

        let mut mismatched_size = valid.clone();
        mismatched_size["size"] = json!(valid["size"].as_u64().unwrap() + 1);
        assert!(manifest_source_version(&mismatched_size).is_err());

        let mut oversized = valid;
        oversized["content"] = json!("A".repeat(MAX_MANIFEST_SIZE * 2));
        assert!(manifest_source_version(&oversized).is_err());
    }

    #[test]
    fn existing_release_prevents_reuse_after_its_tag_was_deleted() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let mut old_release = release(false, json!([asset(b"archive")]));
        old_release["target_commitish"] = json!("b".repeat(40));
        let fixture = Fixture::new(vec![
            Route::get(
                path(&format!("/commits/{}", default_branch())),
                json!({"sha":SHA}),
            ),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(path(&format!("/releases/tags/{}", tag())), old_release),
        ]);
        assert!(publish(&fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }
}
