use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

const MAX_ARCHIVE: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 512;
const MAX_FILE: u64 = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 10 * 1024 * 1024;
const MAX_METADATA: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct FixArtifact {
    pub repository: String,
    pub branch: String,
    pub run_id: u64,
    pub source_sha: String,
    pub commit_message: String,
    pub create_pull_request: Option<String>,
    pub additions: BTreeMap<String, Vec<u8>>,
    pub deletions: Vec<String>,
}

pub fn parse(
    bytes: &[u8],
    name: &str,
    repository: &str,
    run_id: u64,
    source_sha: &str,
    source_branch: &str,
) -> Result<FixArtifact> {
    ensure!(
        bytes.len() <= MAX_ARCHIVE,
        "Securefix artifact exceeds size limit"
    );
    ensure!(
        valid_artifact_name_for_cli(name),
        "invalid Securefix artifact name"
    );
    securefix::policy::validate_repository(repository)?;
    securefix::policy::validate_sha(source_sha)?;
    ensure!(run_id > 0, "invalid source run ID");

    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("read Securefix artifact ZIP")?;
    ensure!(
        zip.len() >= 2 && zip.len() <= MAX_FILES + 2,
        "invalid Securefix artifact entry count"
    );
    let metadata_name = format!("{name}.json");
    let files_name = format!("{name}_files.txt");
    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).context("read Securefix artifact entry")?;
        let path = entry.name().to_owned();
        ensure!(safe_path(&path), "unsafe Securefix artifact path: {path}");
        ensure!(
            entry.is_file(),
            "Securefix artifact contains a non-file entry: {path}"
        );
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "Securefix artifact contains a symbolic link: {path}"
        );
        ensure!(
            entries.insert(path.clone(), Vec::new()).is_none(),
            "duplicate Securefix artifact path: {path}"
        );
        let declared = entry.size();
        let limit = if path == metadata_name {
            MAX_METADATA
        } else if path == files_name {
            MAX_TOTAL
        } else {
            MAX_FILE
        };
        ensure!(
            declared <= limit,
            "Securefix artifact entry exceeds size limit: {path}"
        );
        total = total
            .checked_add(declared)
            .context("Securefix artifact size overflow")?;
        ensure!(
            total <= MAX_TOTAL,
            "Securefix artifact exceeds total size limit"
        );
        let mut contents = Vec::with_capacity(declared as usize);
        (&mut entry).take(limit + 1).read_to_end(&mut contents)?;
        ensure!(
            contents.len() as u64 == declared && contents.len() as u64 <= limit,
            "Securefix artifact entry size mismatch: {path}"
        );
        entries.insert(path, contents);
    }

    let metadata_bytes = entries
        .remove(&metadata_name)
        .context("Securefix artifact lacks metadata")?;
    let file_list = entries
        .remove(&files_name)
        .context("Securefix artifact lacks fixed-file list")?;
    let metadata: Value =
        serde_json::from_slice(&metadata_bytes).context("invalid Securefix artifact metadata")?;
    ensure!(
        metadata["context"]["payload"]["repository"]["full_name"] == repository,
        "artifact repository mismatch"
    );
    ensure!(
        metadata["context"]["runId"].as_u64() == Some(run_id),
        "artifact run ID mismatch"
    );
    ensure!(
        metadata["context"]["sha"] == source_sha
            || metadata["context"]["payload"]["pull_request"]["head"]["sha"] == source_sha
            || metadata["context"]["payload"]["workflow_run"]["head_sha"] == source_sha,
        "artifact source SHA does not match validated workflow run"
    );
    let inputs = metadata["inputs"]
        .as_object()
        .context("artifact inputs missing")?;
    ensure!(
        inputs.get("submodules").is_none_or(Value::is_null),
        "Securefix submodule entries are unsupported"
    );
    let commit_message = inputs
        .get("commit_message")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Securefix")
        .to_owned();
    ensure!(
        commit_message.len() <= 4096 && !commit_message.contains('\0'),
        "invalid Securefix commit message"
    );
    ensure!(
        !commit_message.contains("Securefix-Artifact:"),
        "commit message uses a reserved Securefix receipt marker"
    );
    let destination_repository = inputs
        .get("repository")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(repository)
        .to_owned();
    securefix::policy::validate_repository(&destination_repository)?;
    let branch = inputs
        .get("branch")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(source_branch)
        .to_owned();
    ensure!(
        !branch.is_empty()
            && branch.len() <= 255
            && !branch.starts_with('/')
            && !branch.contains(['\\', '\0']),
        "invalid artifact destination branch"
    );
    let create_pull_request = inputs
        .get("pull_request")
        .filter(|value| !value.is_null())
        .map(serde_json::to_string)
        .transpose()?;

    let text = std::str::from_utf8(&file_list).context("fixed-file list is not UTF-8")?;
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        let path = line.strip_suffix('\r').unwrap_or(line);
        ensure!(
            !path.is_empty() && safe_path(path),
            "unsafe path in fixed-file list"
        );
        ensure!(
            paths.insert(path.to_owned()),
            "duplicate path in fixed-file list: {path}"
        );
    }
    ensure!(
        !paths.is_empty(),
        "Securefix artifact contains no fixed files"
    );
    ensure!(
        paths.len() <= MAX_FILES,
        "Securefix artifact contains too many fixed files"
    );
    ensure!(
        entries.keys().all(|path| paths.contains(path)),
        "artifact contains a file absent from fixed-file list"
    );

    let mut additions = BTreeMap::new();
    let mut deletions = Vec::new();
    for path in paths {
        if let Some(contents) = entries.remove(&path) {
            additions.insert(path, contents);
        } else {
            deletions.push(path);
        }
    }
    ensure!(entries.is_empty(), "artifact contains unexpected files");
    Ok(FixArtifact {
        repository: destination_repository,
        branch,
        run_id,
        source_sha: source_sha.to_owned(),
        commit_message,
        create_pull_request,
        additions,
        deletions,
    })
}

pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0', ':'])
        && !path
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b'%'))
        && path.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.eq_ignore_ascii_case(".git")
        })
}

pub(crate) fn valid_artifact_name_for_cli(name: &str) -> bool {
    name.strip_prefix("securefix-").is_some_and(|suffix| {
        !suffix.is_empty()
            && name.len() <= 50
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(name: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, contents) in files {
            zip.start_file(*path, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(contents).unwrap();
        }
        let _ = name;
        zip.finish().unwrap().into_inner()
    }

    fn metadata() -> Vec<u8> {
        br#"{"context":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","payload":{"repository":{"full_name":"civitaspo/example"}},"runId":42},"inputs":{"commit_message":"Fix it"}}"#.to_vec()
    }

    #[test]
    fn parses_exact_protocol_and_treats_unuploaded_listed_files_as_deletions() {
        let bytes = archive(
            "securefix-test",
            &[
                ("securefix-test.json", &metadata()),
                ("securefix-test_files.txt", b"src/a.rs\nsrc/old.rs\n"),
                ("src/a.rs", b"new"),
            ],
        );
        let fix = parse(
            &bytes,
            "securefix-test",
            "civitaspo/example",
            42,
            &"a".repeat(40),
            "main",
        )
        .unwrap();
        assert_eq!(fix.additions["src/a.rs"], b"new");
        assert_eq!(fix.deletions, ["src/old.rs"]);
        assert_eq!(fix.commit_message, "Fix it");
    }

    #[test]
    fn rejects_traversal_duplicates_unlisted_files_and_identity_mismatch() {
        assert!(!safe_path("../escape"));
        assert!(!safe_path("/absolute"));
        assert!(!safe_path("a\\b"));
        assert!(!safe_path(".git/config"));
        assert!(!safe_path("docs/.GIT/config"));
        assert!(!safe_path("bad?name"));
        assert!(!safe_path("bad%2fname"));
        assert!(!safe_path("bad\nname"));
        let meta = metadata();
        for files in [
            vec![
                ("securefix-test.json", meta.as_slice()),
                ("securefix-test_files.txt", b"../escape\n"),
            ],
            vec![
                ("securefix-test.json", meta.as_slice()),
                ("securefix-test_files.txt", b"a\na\n"),
            ],
            vec![
                ("securefix-test.json", meta.as_slice()),
                ("securefix-test_files.txt", b"a\n"),
                ("b", b"extra"),
            ],
        ] {
            assert!(
                parse(
                    &archive("securefix-test", &files),
                    "securefix-test",
                    "civitaspo/example",
                    42,
                    &"a".repeat(40),
                    "main"
                )
                .is_err()
            );
        }
        let valid = archive(
            "securefix-test",
            &[
                ("securefix-test.json", &meta),
                ("securefix-test_files.txt", b"a\n"),
                ("a", b"x"),
            ],
        );
        assert!(
            parse(
                &valid,
                "securefix-test",
                "civitaspo/example",
                43,
                &"a".repeat(40),
                "main"
            )
            .is_err()
        );
    }
}
