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
    let repository = &crate::config::trusted()?.deployment.server.repository;
    version_at_repository_source(api, repository, source_sha)
}

fn version_at_repository_source(
    api: &GitHub,
    repository: &str,
    source_sha: &str,
) -> Result<RuntimeVersion> {
    crate::policy::validate_sha(source_sha)?;
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
    #[command(about = "Publish a candidate runtime archive from protected main")]
    Publish {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        archive: PathBuf,
    },
    #[command(about = "Verify an attested published runtime archive")]
    Verify {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        archive: PathBuf,
    },
    #[command(about = "Require a runtime version bump over the pull request base")]
    CheckVersion {
        #[arg(long)]
        base_manifest: PathBuf,
        #[arg(long)]
        changed_files: Option<PathBuf>,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Publish {
            source_sha,
            archive,
        } => {
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            let preflight_api = GitHub::from_env("SECUREFIX_SERVER_APP_TOKEN")?;
            securefix::control::require_runtime(&api)?;
            publish(&api, &preflight_api, &source_sha, &archive).map(|_| ())
        }
        Command::Verify {
            source_sha,
            repository,
            archive,
        } => {
            crate::policy::validate_sha(&source_sha)?;
            crate::policy::validate_repository(&repository)?;
            let api = GitHub::from_env("GH_TOKEN")?;
            verify_published_runtime(&api, &source_sha, &repository, &archive)
        }
        Command::CheckVersion {
            base_manifest,
            changed_files,
        } => {
            let candidate = parse_source_manifest(&std::fs::read("Cargo.toml")?)?;
            let base = parse_source_manifest(&std::fs::read(base_manifest)?)?;
            if let Some(path) = changed_files {
                let bytes = read_changed_files(&path)?;
                if !changed_files_require_runtime(&bytes)? {
                    println!("No runtime input changes; runtime version bump is not required.");
                    return Ok(());
                }
            }
            require_version_bump(&candidate, &base)?;
            let repository = &crate::config::trusted()?.deployment.server.repository;
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            require_unused_version(&api, repository, &candidate)
        }
    }
}

fn verify_published_runtime(
    api: &GitHub,
    source_sha: &str,
    repository: &str,
    archive_path: &Path,
) -> Result<()> {
    verify_publication(api, source_sha, repository, archive_path)?;
    let version = version_at_repository_source(api, repository, source_sha)?;
    ensure!(
        version.as_semver().to_string() == env!("CARGO_PKG_VERSION"),
        "compiled runtime version differs from source Cargo.toml"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Publication {
    pub source_sha: String,
    pub archive_sha256: String,
    pub release_id: u64,
    pub asset_id: u64,
}

/// Verify the immutable release and return the identifiers needed to record its provenance.
pub(crate) fn verify_publication(
    api: &GitHub,
    source_sha: &str,
    repository: &str,
    archive_path: &Path,
) -> Result<Publication> {
    crate::policy::validate_sha(source_sha)?;
    crate::policy::validate_repository(repository)?;
    let version = version_at_repository_source(api, repository, source_sha)?;
    let tag = version.tag();
    let tag_ref: Value = api.get(&format!("/repos/{repository}/git/ref/tags/{tag}"))?;
    validate_ref(&tag_ref, source_sha)?;
    let release: Value = api.get(&format!("/repos/{repository}/releases/tags/{tag}"))?;
    validate_release(
        &release,
        source_sha,
        &tag,
        !version.as_semver().pre.is_empty(),
    )?;
    ensure!(
        release["draft"] == false,
        "runtime release is not published"
    );
    let (archive, digest) = read_archive(archive_path)?;
    let assets = release["assets"]
        .as_array()
        .context("release lacks asset list")?;
    ensure!(
        validate_assets(assets, &digest, archive.len() as u64, false)? == AssetState::Matching,
        "runtime release asset mismatch"
    );
    Ok(Publication {
        source_sha: source_sha.to_owned(),
        archive_sha256: digest,
        release_id: release["id"]
            .as_u64()
            .context("runtime release ID missing")?,
        asset_id: assets[0]["id"]
            .as_u64()
            .context("runtime asset ID missing")?,
    })
}

fn require_version_bump(candidate: &RuntimeVersion, base: &RuntimeVersion) -> Result<()> {
    ensure!(
        candidate.as_semver() > base.as_semver(),
        "runtime package version must increase over the pull request base"
    );
    Ok(())
}

const MAX_CHANGED_FILES: usize = 1024 * 1024;

fn read_changed_files(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path).context("read changed-files metadata")?;
    ensure!(
        metadata.len() <= MAX_CHANGED_FILES as u64,
        "changed-files list exceeds size limit"
    );
    let bytes = std::fs::read(path).context("read changed-files list")?;
    ensure!(
        bytes.len() <= MAX_CHANGED_FILES,
        "changed-files list exceeds size limit"
    );
    Ok(bytes)
}

fn changed_files_require_runtime(bytes: &[u8]) -> Result<bool> {
    ensure!(
        bytes.len() <= MAX_CHANGED_FILES,
        "changed-files list exceeds size limit"
    );
    if bytes.is_empty() {
        return Ok(false);
    }
    ensure!(
        bytes.last() == Some(&0),
        "changed-files list must be NUL terminated"
    );
    let mut requires_runtime = false;
    for raw_path in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        ensure!(
            !raw_path.is_empty(),
            "changed-files list contains an empty path"
        );
        let path = std::str::from_utf8(raw_path).context("changed file path is not UTF-8")?;
        ensure!(
            !path.starts_with('/')
                && !path.contains('\\')
                && path.split('/').all(|component| !component.is_empty()
                    && component != "."
                    && component != ".."),
            "changed-files list contains an invalid repository path"
        );
        requires_runtime |= matches!(
            path,
            "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml" | "policy.json"
        ) || path.starts_with(".cargo/")
            || path.starts_with("src/")
            || path.starts_with("repo-settings/")
            || path.starts_with(".github/actions/setup-cli/")
            || path == ".github/workflows/publish-runtime.yml";
    }
    Ok(requires_runtime)
}

fn require_unused_version(api: &GitHub, repository: &str, version: &RuntimeVersion) -> Result<()> {
    let tag = version.tag();
    for path in ["git/ref/tags", "releases/tags"] {
        ensure!(
            get_optional(api, &format!("/repos/{repository}/{path}/{tag}"))?.is_none(),
            "runtime version {tag} is already reserved"
        );
    }
    Ok(())
}

fn publish(
    api: &GitHub,
    preflight_api: &GitHub,
    source_sha: &str,
    archive_path: &Path,
) -> Result<Publication> {
    crate::settings::require_server_immutable_releases(preflight_api)?;
    let trusted = crate::config::trusted()?;
    let repository = trusted.deployment.server.repository.as_str();
    crate::policy::validate_sha(source_sha)?;
    require_current_candidate(api, source_sha)?;
    verify_candidate_commit(api, repository, source_sha)?;
    let version = version_at_source(api, source_sha)?;
    let (archive, digest) = read_archive(archive_path)?;
    let archive_size = archive.len() as u64;
    let tag = version.tag();
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

    ensure_version_tag(api, source_sha, &version)?;

    let release = match existing_release {
        Some(release) => release,
        None => {
            require_current_candidate(api, source_sha)?;
            api.post(
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
            )?
        }
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
            require_current_candidate(api, source_sha)?;
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
        require_current_candidate(api, source_sha)?;
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
    require_current_candidate(api, source_sha)?;
    verify_publication(api, source_sha, repository, archive_path)
}

fn require_current_candidate(api: &GitHub, source_sha: &str) -> Result<()> {
    ensure!(
        securefix::control::development_revision(api)? == source_sha,
        "candidate source is not the current protected-main revision"
    );
    Ok(())
}

fn verify_candidate_commit(api: &GitHub, repository: &str, source_sha: &str) -> Result<()> {
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{source_sha}"))?;
    ensure!(
        commit["sha"] == source_sha,
        "candidate commit identity mismatch"
    );
    ensure!(
        commit["commit"]["verification"]["verified"] == true,
        "candidate source commit signature is not verified"
    );
    let status: Value = api.get(&format!("/repos/{repository}/commits/{source_sha}/status"))?;
    let status_count = status["total_count"]
        .as_u64()
        .context("candidate combined status count missing")?;
    if status_count > 0 {
        ensure!(
            status["state"] == "success",
            "candidate commit has a failing or pending status context"
        );
    }
    let status_app_id = crate::config::trusted()?.deployment.checks.status_app_id;
    let checks: Value = api.get(&format!(
        "/repos/{repository}/commits/{source_sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id={status_app_id}"
    ))?;
    let matches = checks["check_runs"]
        .as_array()
        .context("candidate check runs malformed")?;
    ensure!(
        matches.len() == 1
            && matches[0]["name"] == "status-check"
            && matches[0]["app"]["id"] == status_app_id
            && matches[0]["status"] == "completed"
            && matches[0]["conclusion"] == "success",
        "candidate CI status-check is not a unique successful check"
    );
    Ok(())
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
    let digest = securefix::hex_encode(Sha256::digest(&bytes));
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
        release["id"].as_u64().is_some_and(|id| id > 0),
        "runtime release ID missing or invalid"
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
        asset["id"].as_u64().is_some_and(|id| id > 0),
        "runtime asset ID missing or invalid"
    );
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
        manifest_for(env!("CARGO_PKG_VERSION"))
    }

    fn manifest_for(version: &str) -> Value {
        use base64::Engine;
        let bytes = format!("[package]\nversion = \"{version}\"\n");
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

    fn repository_route() -> Route {
        let server = &crate::config::trusted().unwrap().deployment.server;
        Route::get(
            format!("/repos/{}", server.repository),
            json!({"id":server.id,"default_branch":server.default_branch}),
        )
    }

    fn main_route(sha: &str) -> Route {
        Route::get(
            path(&format!("/commits/{}", default_branch())),
            json!({"sha":sha}),
        )
    }

    fn immutable_releases_route() -> Route {
        Route::get(path("/immutable-releases"), json!({"enabled":true}))
    }

    fn candidate_checks_routes() -> Vec<Route> {
        let repository = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let status_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .status_app_id;
        vec![
            Route::get(
                format!("/repos/{repository}/commits/{SHA}"),
                json!({"sha":SHA,"commit":{"verification":{"verified":true}}}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{SHA}/status"),
                json!({"state":"success","total_count":0}),
            ),
            Route::get(
                format!(
                    "/repos/{repository}/commits/{SHA}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id={status_app_id}"
                ),
                json!({"check_runs":[{"name":"status-check","app":{"id":status_app_id},"status":"completed","conclusion":"success"}]}),
            ),
        ]
    }

    fn release(draft: bool, assets: Value) -> Value {
        json!({"id":7,"tag_name":tag(),"name":tag(),"target_commitish":SHA,"draft":draft,"prerelease":!version().as_semver().pre.is_empty(),"assets":assets})
    }

    fn release_for(version: &str, draft: bool, assets: Value) -> Value {
        let parsed = RuntimeVersion::parse(version).unwrap();
        json!({"id":7,"tag_name":parsed.tag(),"name":parsed.tag(),"target_commitish":SHA,"draft":draft,"prerelease":!parsed.as_semver().pre.is_empty(),"assets":assets})
    }

    fn asset(bytes: &[u8]) -> Value {
        let digest = securefix::hex_encode(Sha256::digest(bytes));
        json!({"id":8,"name":ASSET,"state":"uploaded","size":bytes.len(),"digest":format!("sha256:{digest}")})
    }

    #[test]
    fn accepts_only_empty_draft_or_exact_single_uploaded_asset() {
        let bytes = b"archive";
        let digest = securefix::hex_encode(Sha256::digest(bytes));
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
    fn version_bump_requires_strictly_newer_semver() {
        let base = RuntimeVersion::parse("0.2.19").unwrap();
        assert!(require_version_bump(&RuntimeVersion::parse("0.2.20").unwrap(), &base).is_ok());
        assert!(require_version_bump(&base, &base).is_err());
        assert!(require_version_bump(&RuntimeVersion::parse("0.2.18").unwrap(), &base).is_err());
    }

    #[test]
    fn changed_files_require_publication_only_for_runtime_inputs() {
        for input in [
            b"README.md\0docs/migration.md\0.github/workflows/ci.yml\0".as_slice(),
            b".github/workflows/release.yml\0docs/testing.md\0",
            b"",
        ] {
            assert!(!changed_files_require_runtime(input).unwrap());
        }
        for input in [
            b"Cargo.toml\0".as_slice(),
            b"Cargo.lock\0",
            b"rust-toolchain.toml\0",
            b".cargo/config.toml\0",
            b"src/main.rs\0",
            b"policy.json\0",
            b"repo-settings/rulesets/base.json\0",
            b".github/actions/setup-cli/action.yml\0",
            b".github/workflows/publish-runtime.yml\0",
        ] {
            assert!(changed_files_require_runtime(input).unwrap());
        }
    }

    #[test]
    fn changed_files_list_requires_bounded_nul_terminated_repository_paths() {
        for invalid in [
            &b"docs/readme.md"[..],
            &b"docs//readme.md\0"[..],
            &b"../Cargo.toml\0"[..],
            &b"/etc/passwd\0"[..],
            &[0xff, 0],
        ] {
            assert!(changed_files_require_runtime(invalid).is_err());
        }
        assert!(changed_files_require_runtime(&vec![b'a'; MAX_CHANGED_FILES + 1]).is_err());
    }

    #[test]
    fn version_reservation_checks_reject_collisions_and_api_errors() {
        let repository = "example/runtime";
        let tag_path = format!("/repos/{repository}/git/ref/tags/{}", tag());
        let release_path = format!("/repos/{repository}/releases/tags/{}", tag());
        let missing = |path: &str| Route::request("GET", path, 404, json!({"message":"missing"}));
        let fixture = Fixture::new(vec![missing(&tag_path), missing(&release_path)]);
        require_unused_version(&fixture.api, repository, &version()).unwrap();
        fixture.finish();
        for routes in [
            vec![Route::get(&tag_path, json!({}))],
            vec![missing(&tag_path), Route::get(&release_path, json!({}))],
            vec![Route::request(
                "GET",
                &tag_path,
                403,
                json!({"message":"forbidden"}),
            )],
        ] {
            let fixture = Fixture::new(routes);
            assert!(require_unused_version(&fixture.api, repository, &version()).is_err());
            fixture.finish();
        }
    }

    #[test]
    fn stale_runtime_stops_before_release_lookup_or_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let fixture = Fixture::new(vec![
            immutable_releases_route(),
            repository_route(),
            main_route("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ]);
        assert!(publish(&fixture.api, &fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn mutable_server_release_setting_stops_publication_before_any_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let fixture = Fixture::new(vec![Route::get(
            path("/immutable-releases"),
            json!({"enabled":false}),
        )]);

        let error = publish(&fixture.api, &fixture.api, SHA, archive.path()).unwrap_err();
        assert!(format!("{error:#}").contains("immutable releases must be enabled"));
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
        let reference = path(&format!("/git/ref/tags/{}", tag()));
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let numbered_release = path("/releases/7");
        let existing = release(false, json!([asset(b"archive")]));
        let mut routes = vec![
            immutable_releases_route(),
            repository_route(),
            main_route(SHA),
        ];
        routes.extend(candidate_checks_routes());
        routes.extend(vec![
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path.clone(), existing.clone()),
            main_route(SHA),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(numbered_release.clone(), existing.clone()),
            Route::get(numbered_release, existing.clone()),
            repository_route(),
            main_route(SHA),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(release_path, existing),
        ]);
        let fixture = Fixture::new(routes);
        publish(&fixture.api, &fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn verify_accepts_only_the_source_bound_published_archive() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let fixture = Fixture::new(vec![
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(
                path(&format!("/git/ref/tags/{}", tag())),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(release_path, release(false, json!([asset(b"archive")]))),
        ]);
        let publication = verify_publication(
            &fixture.api,
            SHA,
            "civitaspo/securefix-server",
            archive.path(),
        )
        .unwrap();
        assert_eq!(publication.source_sha, SHA);
        assert_eq!(
            publication.archive_sha256,
            securefix::hex_encode(Sha256::digest(b"archive"))
        );
        assert_eq!((publication.release_id, publication.asset_id), (7, 8));
        fixture.finish();
    }

    #[test]
    fn candidate_publication_verification_uses_source_version_not_controller_version() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let source_version = "9.8.7";
        let tag = RuntimeVersion::parse(source_version).unwrap().tag();
        let repository = "civitaspo/securefix-server";
        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/contents/Cargo.toml?ref={SHA}"),
                manifest_for(source_version),
            ),
            Route::get(
                format!("/repos/{repository}/git/ref/tags/{tag}"),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(
                format!("/repos/{repository}/releases/tags/{tag}"),
                release_for(source_version, false, json!([asset(b"archive")])),
            ),
        ]);
        let publication =
            verify_publication(&fixture.api, SHA, repository, archive.path()).unwrap();
        assert_eq!(publication.source_sha, SHA);
        assert_eq!(publication.release_id, 7);
        assert_eq!(publication.asset_id, 8);
        fixture.finish();
    }

    #[test]
    fn rejected_candidate_status_stops_before_release_lookup() {
        let repository = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let server = &crate::config::trusted().unwrap().deployment.server;
        let status_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .status_app_id;
        let routes = vec![
            immutable_releases_route(),
            Route::get(
                format!("/repos/{repository}"),
                json!({"id":server.id,"default_branch":server.default_branch}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{}", server.default_branch),
                json!({"sha":SHA}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{SHA}"),
                json!({"sha":SHA,"commit":{"verification":{"verified":true}}}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{SHA}/status"),
                json!({"state":"success","total_count":0}),
            ),
            Route::get(
                format!(
                    "/repos/{repository}/commits/{SHA}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id={status_app_id}"
                ),
                json!({"check_runs":[{"name":"status-check","app":{"id":status_app_id},"status":"completed","conclusion":"failure"}]}),
            ),
        ];
        let fixture = Fixture::new(routes);
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        assert!(publish(&fixture.api, &fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn failed_candidate_publication_does_not_block_repair_with_unchanged_active_runtime() {
        let repository = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let server = &crate::config::trusted().unwrap().deployment.server;
        let status_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .status_app_id;
        let candidate_sha = "b".repeat(40);
        let repair_path = format!("/repos/{repository}/issues/17/comments");
        let repair_body = json!({"body":"repair under the still-active runtime"});
        let fixture = Fixture::new(vec![
            immutable_releases_route(),
            Route::get(
                format!("/repos/{repository}"),
                json!({"id":server.id,"default_branch":server.default_branch}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{}", server.default_branch),
                json!({"sha":candidate_sha}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{candidate_sha}"),
                json!({"sha":candidate_sha,"commit":{"verification":{"verified":true}}}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{candidate_sha}/status"),
                json!({"state":"success","total_count":0}),
            ),
            Route::get(
                format!(
                    "/repos/{repository}/commits/{candidate_sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id={status_app_id}"
                ),
                json!({"check_runs":[{"name":"status-check","app":{"id":status_app_id},"status":"completed","conclusion":"failure"}]}),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST",
                repair_path.clone(),
                201,
                json!({"id":19,"user":{"type":"Bot"}}),
            )
            .with_request_body(repair_body.clone()),
        ]);
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"candidate archive").unwrap();

        let error =
            publish(&fixture.api, &fixture.api, &candidate_sha, archive.path()).unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("candidate CI status-check is not a unique successful check")
        );

        let repair: Value = fixture.api.post(&repair_path, &repair_body).unwrap();
        assert_eq!(repair["id"], 19);
        fixture.finish();
    }

    #[test]
    fn candidate_status_check_suffices_when_commit_statuses_are_absent() {
        let repository = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let status_app_id = crate::config::trusted()
            .unwrap()
            .deployment
            .checks
            .status_app_id;
        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/commits/{SHA}"),
                json!({"sha":SHA,"commit":{"verification":{"verified":true}}}),
            ),
            Route::get(
                format!("/repos/{repository}/commits/{SHA}/status"),
                json!({"state":"pending","total_count":0}),
            ),
            Route::get(
                format!(
                    "/repos/{repository}/commits/{SHA}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id={status_app_id}"
                ),
                json!({"check_runs":[{"name":"status-check","app":{"id":status_app_id},"status":"completed","conclusion":"success"}]}),
            ),
        ]);
        verify_candidate_commit(&fixture.api, repository, SHA).unwrap();
        fixture.finish();
    }

    #[test]
    fn verify_rejects_wrong_tags_unpublished_releases_and_changed_archive_bytes() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let repository = "example/runtime";
        let manifest_route = || {
            Route::get(
                format!("/repos/{repository}/contents/Cargo.toml?ref={SHA}"),
                manifest(),
            )
        };
        let tag_route = |object| {
            Route::get(
                format!("/repos/{repository}/git/ref/tags/{}", tag()),
                object,
            )
        };
        let release_route = |value| {
            Route::get(
                format!("/repos/{repository}/releases/tags/{}", tag()),
                value,
            )
        };
        for object in [
            json!({"object":{"type":"tag","sha":SHA}}),
            json!({"object":{"type":"commit","sha":"b".repeat(40)}}),
        ] {
            let fixture = Fixture::new(vec![manifest_route(), tag_route(object)]);
            assert!(
                verify_published_runtime(&fixture.api, SHA, repository, archive.path()).is_err()
            );
            fixture.finish();
        }
        let mut wrong_target = release(false, json!([asset(b"archive")]));
        wrong_target["target_commitish"] = json!("b".repeat(40));
        for value in [
            release(true, json!([asset(b"archive")])),
            wrong_target,
            release(false, json!([asset(b"tampered")])),
            release(false, json!([])),
            release(false, json!([asset(b"archive"), asset(b"archive")])),
        ] {
            let fixture = Fixture::new(vec![
                manifest_route(),
                tag_route(json!({"object":{"type":"commit","sha":SHA}})),
                release_route(value),
            ]);
            assert!(
                verify_published_runtime(&fixture.api, SHA, repository, archive.path()).is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn matching_draft_resumes_and_publishes_without_reupload() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let reference = path(&format!("/git/ref/tags/{}", tag()));
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let numbered_release = path("/releases/7");
        let draft = release(true, json!([asset(b"archive")]));
        let published = release(false, json!([asset(b"archive")]));
        let mut routes = vec![
            immutable_releases_route(),
            repository_route(),
            main_route(SHA),
        ];
        routes.extend(candidate_checks_routes());
        routes.extend(vec![
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path.clone(), draft.clone()),
            main_route(SHA),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(numbered_release.clone(), draft),
            repository_route(),
            main_route(SHA),
            Route::active_control(&Fixture::control_revision()),
            Route::request("PATCH", numbered_release.clone(), 200, published.clone())
                .with_request_body(json!({"draft":false})),
            Route::get(numbered_release, published.clone()),
            repository_route(),
            main_route(SHA),
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(
                reference.clone(),
                json!({"object":{"type":"commit","sha":SHA}}),
            ),
            Route::get(release_path, published),
        ]);
        let fixture = Fixture::new(routes);
        publish(&fixture.api, &fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn asset_mismatch_fails_before_any_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let release_path = path(&format!("/releases/tags/{}", tag()));
        let mismatch = release(true, json!([asset(b"different bytes")]));
        let mut routes = vec![
            immutable_releases_route(),
            repository_route(),
            main_route(SHA),
        ];
        routes.extend(candidate_checks_routes());
        routes.extend(vec![
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(release_path, mismatch),
        ]);
        let fixture = Fixture::new(routes);
        assert!(publish(&fixture.api, &fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn canonical_semver_tag_is_created_once_and_never_retargeted() {
        let version = version();
        let tag = version_tag(&version);
        let reference = path(&format!("/git/ref/tags/{tag}"));
        let fixture = Fixture::new(vec![
            main_route(SHA),
            Route::request(
                "GET",
                reference.clone(),
                404,
                json!({"message":"Not Found"}),
            ),
            Route::active_control(&Fixture::control_revision()),
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
        let mut routes = vec![
            immutable_releases_route(),
            repository_route(),
            main_route(SHA),
        ];
        routes.extend(candidate_checks_routes());
        routes.extend(vec![
            Route::get(path(&format!("/contents/Cargo.toml?ref={SHA}")), manifest()),
            Route::get(path(&format!("/releases/tags/{}", tag())), old_release),
        ]);
        let fixture = Fixture::new(routes);
        assert!(publish(&fixture.api, &fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }
}
