use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const TOOL_VERSION: &str = "v0.2.0";
const LOCK_PATH: &str = ".github/workflows/actions.lock";
const MAX_TREE_ENTRIES: usize = 20_000;
const MAX_INPUT_BYTES: u64 = 50 * 1024 * 1024;

#[cfg(test)]
pub(crate) fn install_fake_runner(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let bin = directory.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let runner = bin.join("gh-actions-lock");
    fs::write(
        &runner,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'actions-lock version v0.2.0'; exit 0; fi\ncd \"$GH_ACTIONS_LOCK_REPO_ROOT\" || exit 7\nif [ \"$1\" = '--verify' ]; then test -s .github/workflows/actions.lock; exit $?; fi\n[ \"$*\" = '--no-narrow --no-interactive --no-migrate-local-actions' ] || exit 8\n{ find .github/workflows -type f ! -name actions.lock -print; find . -type f \\( -name action.yml -o -name action.yaml \\) -print; } | sort > .github/workflows/actions.lock\n",
    )
    .unwrap();
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o700)).unwrap();
    bin
}

pub(crate) fn generate(
    api: &GitHub,
    repository: &str,
    base_sha: &str,
    desired: &BTreeMap<String, Vec<u8>>,
    deletions: &[String],
) -> Result<Vec<u8>> {
    crate::policy::validate_sha(base_sha)?;
    let mut repository_parts = repository.split('/');
    ensure!(
        repository_parts
            .next()
            .is_some_and(valid_repository_component)
            && repository_parts
                .next()
                .is_some_and(valid_repository_component)
            && repository_parts.next().is_none(),
        "invalid caller repository"
    );
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{base_sha}"))?;
    ensure!(commit["sha"] == base_sha, "caller commit identity mismatch");
    let tree_sha = commit["commit"]["tree"]["sha"]
        .as_str()
        .context("caller commit tree SHA missing")?;
    crate::policy::validate_sha(tree_sha)?;
    let tree: Value = api.get(&format!(
        "/repos/{repository}/git/trees/{tree_sha}?recursive=1"
    ))?;
    ensure!(
        tree["sha"] == tree_sha && tree["truncated"] == false,
        "caller repository tree is truncated"
    );
    let entries = tree["tree"]
        .as_array()
        .context("caller repository tree missing")?;
    ensure!(
        entries.len() <= MAX_TREE_ENTRIES,
        "caller repository tree exceeds bounds"
    );

    let mut inputs = BTreeMap::new();
    let mut total_bytes = 0u64;
    for entry in entries {
        let path = entry["path"].as_str().context("tree path missing")?;
        if !is_input(path) && path != LOCK_PATH {
            continue;
        }
        validate_relative_path(path)?;
        ensure!(
            entry["type"] == "blob",
            "lockfile input is not a regular blob: {path}"
        );
        ensure!(
            entry["mode"] == "100644" || entry["mode"] == "100755",
            "lockfile input has unsafe mode: {path}"
        );
        let size = entry["size"]
            .as_u64()
            .context("lockfile input size missing")?;
        total_bytes = total_bytes
            .checked_add(size)
            .context("lockfile input size overflow")?;
        ensure!(
            total_bytes <= MAX_INPUT_BYTES,
            "caller lockfile inputs exceed bounds"
        );
        let bytes = api.content(repository, path, base_sha)?;
        ensure!(
            bytes.len() as u64 == size,
            "lockfile input size mismatch: {path}"
        );
        ensure!(
            inputs.insert(path.to_owned(), bytes).is_none(),
            "duplicate lockfile input: {path}"
        );
    }

    for (path, bytes) in desired {
        validate_relative_path(path)?;
        ensure!(
            is_workflow(path),
            "desired lockfile overlay is not a workflow: {path}"
        );
        inputs.insert(path.clone(), bytes.clone());
    }
    for path in deletions {
        validate_relative_path(path)?;
        ensure!(
            is_workflow(path),
            "deleted lockfile input is not a workflow: {path}"
        );
        ensure!(
            !desired.contains_key(path),
            "workflow cannot be both overlaid and deleted: {path}"
        );
        ensure!(
            inputs.remove(path).is_some(),
            "deleted workflow is missing from the caller snapshot: {path}"
        );
    }
    ensure!(
        inputs.values().map(|bytes| bytes.len() as u64).sum::<u64>() <= MAX_INPUT_BYTES,
        "caller lockfile inputs exceed bounds"
    );
    ensure!(
        inputs.keys().any(|path| is_workflow(path)),
        "caller has no workflow inputs"
    );

    let root = tempfile::tempdir().context("create lockfile workspace")?;
    for (path, bytes) in &inputs {
        let output = safe_join(root.path(), path)?;
        fs::create_dir_all(output.parent().context("lockfile input parent missing")?)?;
        fs::write(output, bytes)?;
    }
    let lock = safe_join(root.path(), LOCK_PATH)?;
    if !inputs.contains_key(LOCK_PATH) {
        fs::create_dir_all(lock.parent().context("lockfile parent missing")?)?;
    }

    let version = run_actions_lock(&["--version"], root.path(), repository)?;
    ensure!(
        version.trim() == format!("actions-lock version {TOOL_VERSION}"),
        "unexpected gh-actions-lock version"
    );
    run_actions_lock(
        &[
            "--no-narrow",
            "--no-interactive",
            "--no-migrate-local-actions",
        ],
        root.path(),
        repository,
    )?;

    ensure_inputs_unchanged(root.path(), &inputs)?;
    run_actions_lock(&["--verify"], root.path(), repository)?;
    read_generated_lock(root.path())
}

fn run_actions_lock(args: &[&str], root: &Path, repository: &str) -> Result<String> {
    run_binary(OsStr::new("gh-actions-lock"), args, root, repository)
}

fn run_binary(binary: &OsStr, args: &[&str], root: &Path, repository: &str) -> Result<String> {
    let mut command = Command::new(binary);
    command.args(args).env_clear();
    for key in ["PATH", "HOME", "GH_CONFIG_DIR", "GH_HOST"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(token) = std::env::var_os("GITHUB_TOKEN") {
        command.env("GH_TOKEN", token);
    }
    let output = command
        .current_dir(root)
        .env("GH_REPO", repository)
        .env("GH_ACTIONS_LOCK_REPO_ROOT", root)
        .output()
        .context("run the pinned gh-actions-lock extension")?;
    ensure!(output.status.success(), "gh-actions-lock failed");
    String::from_utf8(output.stdout).context("gh-actions-lock output is not UTF-8")
}

fn read_generated_lock(root: &Path) -> Result<Vec<u8>> {
    let lockfile = fs::read(safe_join(root, LOCK_PATH)?)
        .context("gh-actions-lock did not create actions.lock")?;
    ensure!(
        !lockfile.is_empty(),
        "gh-actions-lock produced an empty lockfile"
    );
    Ok(lockfile)
}

fn ensure_inputs_unchanged(root: &Path, inputs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for (path, before) in inputs {
        if path != LOCK_PATH {
            ensure!(
                fs::read(safe_join(root, path)?)? == *before,
                "gh-actions-lock modified input file: {path}"
            );
        }
    }
    Ok(())
}

fn safe_join(root: &Path, path: &str) -> Result<PathBuf> {
    validate_relative_path(path)?;
    Ok(root.join(path))
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.contains('\\')
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            }),
        "unsafe repository path"
    );
    Ok(())
}

fn is_workflow(path: &str) -> bool {
    path.starts_with(".github/workflows/")
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
}

fn is_input(path: &str) -> bool {
    is_workflow(path)
        || Path::new(path)
            .file_name()
            .is_some_and(|name| name == "action.yml" || name == "action.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};
    use serde_json::json;

    #[test]
    fn selects_workflows_and_action_definitions_without_other_files() {
        assert!(is_input(".github/workflows/build.yml"));
        assert!(is_input(".github/workflows/reusable.yaml"));
        assert!(is_input("actions/local/action.yml"));
        assert!(is_input("action.yaml"));
        assert!(is_input("src/action.yml"));
        assert!(!is_input("README.md"));
        assert!(!is_input(".github/workflows/actions.lock"));
    }

    #[test]
    fn rejects_unsafe_tree_paths() {
        for path in ["../outside", "/absolute", "a//b", "a/./b", "a\\b"] {
            assert!(validate_relative_path(path).is_err(), "accepted {path}");
        }
        assert!(validate_relative_path(".github/workflows/build.yml").is_ok());
    }

    #[test]
    fn only_workflow_paths_can_be_overlaid() {
        assert!(is_workflow(".github/workflows/approve.yml"));
        assert!(!is_workflow(".github/action.yml"));
        assert!(!is_workflow("actions/local/action.yml"));
    }

    #[test]
    fn input_snapshot_check_rejects_workflow_or_action_mutation() {
        let root = tempfile::tempdir().unwrap();
        let workflow = ".github/workflows/build.yml";
        let action = "actions/local/action.yml";
        let inputs = BTreeMap::from([
            (workflow.to_owned(), b"uses: acme/action@v1".to_vec()),
            (action.to_owned(), b"runs: {using: composite}".to_vec()),
            (LOCK_PATH.to_owned(), b"old lock".to_vec()),
        ]);
        for (path, contents) in &inputs {
            let output = safe_join(root.path(), path).unwrap();
            fs::create_dir_all(output.parent().unwrap()).unwrap();
            fs::write(output, contents).unwrap();
        }
        assert!(ensure_inputs_unchanged(root.path(), &inputs).is_ok());
        fs::write(root.path().join(workflow), b"changed workflow").unwrap();
        assert!(ensure_inputs_unchanged(root.path(), &inputs).is_err());
        fs::write(root.path().join(workflow), &inputs[workflow]).unwrap();
        fs::write(root.path().join(action), b"changed action").unwrap();
        assert!(ensure_inputs_unchanged(root.path(), &inputs).is_err());
    }

    #[test]
    fn snapshot_rejects_identity_truncation_and_symlink_failures() {
        let repository = "owner/repo";
        let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let tree_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let desired = BTreeMap::from([(
            ".github/workflows/build.yml".to_owned(),
            b"name: build\n".to_vec(),
        )]);
        let cases = [
            (
                json!({"sha":"cccccccccccccccccccccccccccccccccccccccc","commit":{"tree":{"sha":tree_sha}}}),
                json!({"sha":tree_sha,"truncated":false,"tree":[]}),
            ),
            (
                json!({"sha":base,"commit":{"tree":{"sha":tree_sha}}}),
                json!({"sha":"cccccccccccccccccccccccccccccccccccccccc","truncated":false,"tree":[]}),
            ),
            (
                json!({"sha":base,"commit":{"tree":{"sha":tree_sha}}}),
                json!({"sha":tree_sha,"truncated":true,"tree":[]}),
            ),
            (
                json!({"sha":base,"commit":{"tree":{"sha":tree_sha}}}),
                json!({"sha":tree_sha,"truncated":false,"tree":[{"path":".github/workflows/untrusted.yml","type":"blob","mode":"120000","size":1}]}),
            ),
        ];
        for (commit, tree) in cases {
            let mut routes = vec![Route::get(
                format!("/repos/{repository}/commits/{base}"),
                commit.clone(),
            )];
            if commit["sha"] == base {
                routes.push(Route::get(
                    format!("/repos/{repository}/git/trees/{tree_sha}?recursive=1"),
                    tree,
                ));
            }
            let fixture = Fixture::new(routes);
            assert!(generate(&fixture.api, repository, base, &desired, &[]).is_err());
            fixture.finish();
        }
    }

    #[cfg(unix)]
    #[test]
    fn pinned_runner_contract_keeps_write_credentials_out_and_returns_lock() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-locker");
        fs::write(
            &script,
            "#!/bin/sh\n[ -z \"${SECUREFIX_SERVER_TOKEN:-}\" ] || exit 9\nif [ \"$1\" = \"--version\" ]; then echo 'actions-lock version v0.2.0'; exit 0; fi\nprintf '%s' 'version: 1\\n' > \"$GH_ACTIONS_LOCK_REPO_ROOT/.github/workflows/actions.lock\"\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&workflows).unwrap();
        let version = run_binary(
            script.as_os_str(),
            &["--version"],
            root.path(),
            "owner/repo",
        )
        .unwrap();
        assert_eq!(version.trim(), "actions-lock version v0.2.0");
        run_binary(
            script.as_os_str(),
            &[
                "--no-narrow",
                "--no-interactive",
                "--no-migrate-local-actions",
            ],
            root.path(),
            "owner/repo",
        )
        .unwrap();
        assert_eq!(read_generated_lock(root.path()).unwrap(), b"version: 1\\n");
    }
}
