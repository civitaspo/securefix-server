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

const REPOSITORY: &str = crate::policy::SERVER;
const MAX_ARCHIVE_SIZE: u64 = 128 * 1024 * 1024;
const ASSET: &str = "securefix-runtime-linux-x86_64.tar.gz";

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
    crate::policy::validate_sha(source_sha)?;
    let (archive, digest) = read_archive(archive_path)?;
    let archive_size = archive.len() as u64;
    let tag = format!("securefix-runtime-{source_sha}");
    let ref_path = format!("/repos/{REPOSITORY}/git/ref/tags/{tag}");

    let current_main: Value = api.get(&format!("/repos/{REPOSITORY}/commits/main"))?;
    ensure!(
        current_main["sha"] == source_sha,
        "runtime is no longer current; publication denied"
    );

    match get_optional(api, &ref_path)? {
        Some(tag_ref) => validate_ref(&tag_ref, source_sha)?,
        None => {
            let created: Value = api.post(
                &format!("/repos/{REPOSITORY}/git/refs"),
                &json!({"ref": format!("refs/tags/{tag}"), "sha": source_sha}),
            )?;
            validate_ref(&created, source_sha)?;
        }
    }

    let release_path = format!("/repos/{REPOSITORY}/releases/tags/{tag}");
    let release = match get_optional(api, &release_path)? {
        Some(release) => release,
        None => api.post(
            &format!("/repos/{REPOSITORY}/releases"),
            &json!({
                "tag_name": tag,
                "name": tag,
                "target_commitish": source_sha,
                "draft": true,
                "prerelease": true,
                "make_latest": "false",
                "generate_release_notes": false
            }),
        )?,
    };
    validate_release(&release, source_sha, &tag)?;
    let release_id = release["id"]
        .as_u64()
        .context("release response lacks ID")?;
    let assets = release["assets"]
        .as_array()
        .context("release lacks asset list")?;
    match validate_assets(assets, &digest, archive_size, release["draft"] == true)? {
        AssetState::EmptyDraft => {
            let upload_url = format!(
                "https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?name={ASSET}"
            );
            let _: Value = api.upload(&upload_url, archive, "application/gzip")?;
        }
        AssetState::Matching => {}
    }

    let current: Value = api.get(&format!("/repos/{REPOSITORY}/releases/{release_id}"))?;
    validate_release(&current, source_sha, &tag)?;
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
            &format!("/repos/{REPOSITORY}/releases/{release_id}"),
            &json!({"draft": false}),
        )?;
    }
    let published: Value = api.get(&format!("/repos/{REPOSITORY}/releases/{release_id}"))?;
    validate_release(&published, source_sha, &tag)?;
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
    Ok(())
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

fn validate_release(release: &Value, source_sha: &str, tag: &str) -> Result<()> {
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
        release["prerelease"] == true,
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
    const TAG: &str = "securefix-runtime-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RELEASE: &str = "/repos/civitaspo/securefix-server/releases/tags/securefix-runtime-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REF: &str = "/repos/civitaspo/securefix-server/git/ref/tags/securefix-runtime-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MAIN: &str = "/repos/civitaspo/securefix-server/commits/main";

    fn release(draft: bool, assets: Value) -> Value {
        json!({"id":7,"tag_name":TAG,"name":TAG,"target_commitish":SHA,"draft":draft,"prerelease":true,"assets":assets})
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
        assert!(validate_release(&release(true, json!([])), SHA, "wrong-tag").is_err());
        let mut moved = release(true, json!([]));
        moved["target_commitish"] = json!("main");
        assert!(validate_release(&moved, SHA, TAG).is_err());
    }

    #[test]
    fn stale_runtime_stops_before_release_lookup_or_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let fixture = Fixture::new(vec![Route::get(
            MAIN,
            json!({"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}),
        )]);
        assert!(publish(&fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }

    #[test]
    fn non_404_lookup_failure_is_not_treated_as_absence() {
        let fixture = Fixture::new(vec![Route::request(
            "GET",
            REF,
            403,
            json!({"message":"forbidden"}),
        )]);
        assert!(get_optional(&fixture.api, REF).is_err());
        fixture.finish();
    }

    #[test]
    fn matching_published_release_is_an_idempotent_read_only_retry() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let existing = release(false, json!([asset(b"archive")]));
        let fixture = Fixture::new(vec![
            Route::get(MAIN, json!({"sha":SHA})),
            Route::get(REF, json!({"object":{"type":"commit","sha":SHA}})),
            Route::get(RELEASE, existing.clone()),
            Route::get(
                "/repos/civitaspo/securefix-server/releases/7",
                existing.clone(),
            ),
            Route::get("/repos/civitaspo/securefix-server/releases/7", existing),
        ]);
        publish(&fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn matching_draft_resumes_and_publishes_without_reupload() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let draft = release(true, json!([asset(b"archive")]));
        let published = release(false, json!([asset(b"archive")]));
        let fixture = Fixture::new(vec![
            Route::get(MAIN, json!({"sha":SHA})),
            Route::get(REF, json!({"object":{"type":"commit","sha":SHA}})),
            Route::get(RELEASE, draft.clone()),
            Route::get("/repos/civitaspo/securefix-server/releases/7", draft),
            Route::get(MAIN, json!({"sha":SHA})),
            Route::request(
                "PATCH",
                "/repos/civitaspo/securefix-server/releases/7",
                200,
                published.clone(),
            )
            .with_request_body(json!({"draft":false})),
            Route::get("/repos/civitaspo/securefix-server/releases/7", published),
        ]);
        publish(&fixture.api, SHA, archive.path()).unwrap();
        fixture.finish();
    }

    #[test]
    fn asset_mismatch_fails_before_any_write() {
        let archive = NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"archive").unwrap();
        let mismatch = release(true, json!([asset(b"different bytes")]));
        let fixture = Fixture::new(vec![
            Route::get(MAIN, json!({"sha":SHA})),
            Route::get(REF, json!({"object":{"type":"commit","sha":SHA}})),
            Route::get(RELEASE, mismatch),
        ]);
        assert!(publish(&fixture.api, SHA, archive.path()).is_err());
        fixture.finish();
    }
}
