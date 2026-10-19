use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn sandboxed_smoke_stage_is_validated_before_upload_and_rejects_extra_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".securefix-client-smoke")).unwrap();
    fs::write(
        dir.path().join(".securefix-client-smoke/request.txt"),
        "Securefix client smoke 123\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("event.json"),
        r#"{"repository":{"full_name":"civitaspo/securefix-server"}}"#,
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_securefix"))
            .current_dir(dir.path())
            .args(args)
            .env_remove("GITHUB_OUTPUT")
            .env("GITHUB_WORKSPACE", dir.path())
            .env("GITHUB_EVENT_PATH", dir.path().join("event.json"))
            .env("GITHUB_REPOSITORY", "civitaspo/securefix-server")
            .env("GITHUB_RUN_ID", "123")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("GITHUB_SHA", "a".repeat(40))
            .env("GITHUB_REF", "refs/heads/main")
            .env("GITHUB_REF_NAME", "main")
            .output()
            .unwrap()
    };
    let prepared = invoke(&[
        "securefix",
        "client-prepare",
        "--files",
        ".securefix-client-smoke/request.txt",
        "--repository",
        "civitaspo/testing-securefix-server",
        "--branch",
        "securefix-client-smoke-123",
        "--output-dir",
        "artifacts",
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let validate = || {
        invoke(&[
            "integration",
            "validate-client-stage",
            "--directory",
            "artifacts",
        ])
    };
    let valid = validate();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    #[cfg(unix)]
    {
        fs::rename(
            dir.path().join("artifacts"),
            dir.path().join("real-artifacts"),
        )
        .unwrap();
        std::os::unix::fs::symlink("real-artifacts", dir.path().join("artifacts")).unwrap();
        let rejected = validate();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("not a regular directory"));
        fs::remove_file(dir.path().join("artifacts")).unwrap();
        fs::rename(
            dir.path().join("real-artifacts"),
            dir.path().join("artifacts"),
        )
        .unwrap();
    }
    let artifact = fs::read_dir(dir.path().join("artifacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let extra = artifact.join("unexpected");
    fs::write(&extra, "unexpected").unwrap();
    assert!(!validate().status.success());
    fs::remove_file(extra).unwrap();
    let file = artifact.join(".securefix-client-smoke/request.txt");
    fs::remove_file(&file).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path().join("event.json"), &file).unwrap();
        assert!(!validate().status.success());
    }
}

fn client(workspace: &std::path::Path, files: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_securefix"))
        .current_dir(workspace)
        .args([
            "securefix",
            "client-prepare",
            "--files",
            files,
            "--branch",
            "feature/fix",
        ])
        .env("GITHUB_WORKSPACE", workspace)
        .env("GITHUB_EVENT_PATH", workspace.join("event.json"))
        .env("GITHUB_REPOSITORY", "civitaspo/testing-securefix-server")
        .env("GITHUB_RUN_ID", "123")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_SHA", "a".repeat(40))
        .env("GITHUB_OUTPUT", workspace.join("outputs"))
        .output()
        .unwrap()
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("event.json"),
        serde_json::to_vec(
            &json!({"repository":{"full_name":"civitaspo/testing-securefix-server"}}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("outputs"), "").unwrap();
    dir
}

#[test]
fn native_client_stages_multiple_files_and_deletion_without_credentials() {
    let dir = workspace();
    fs::write(dir.path().join("one.txt"), "one\n").unwrap();
    fs::write(dir.path().join("two.txt"), "two\n").unwrap();
    let result = client(dir.path(), "one.txt\ntwo.txt\ndeleted.txt");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let outputs = fs::read_to_string(dir.path().join("outputs")).unwrap();
    let name = outputs
        .lines()
        .find_map(|line| line.strip_prefix("artifact_name="))
        .unwrap();
    let stage = dir.path().join(".securefix-artifacts").join(name);
    assert_eq!(fs::read(stage.join("one.txt")).unwrap(), b"one\n");
    assert_eq!(fs::read(stage.join("two.txt")).unwrap(), b"two\n");
    assert!(!stage.join("deleted.txt").exists());
    assert_eq!(
        fs::read_to_string(stage.join(format!("{name}_files.txt"))).unwrap(),
        "deleted.txt\none.txt\ntwo.txt\n"
    );
    let metadata: Value =
        serde_json::from_slice(&fs::read(stage.join(format!("{name}.json"))).unwrap()).unwrap();
    assert_eq!(metadata["context"]["runId"], 123);
    assert_eq!(metadata["context"]["sha"], "a".repeat(40));
    assert_eq!(metadata["inputs"]["branch"], "feature/fix");
    assert!(outputs.contains("changed_files<<securefix_"));
}

#[cfg(unix)]
#[test]
fn native_client_rejects_parent_symlink_and_traversal() {
    let dir = workspace();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("private.txt"), "must not be staged").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
    for file in ["escape/private.txt", "../private.txt", ".git/config"] {
        let result = client(dir.path(), file);
        assert!(
            !result.status.success(),
            "unsafe client path accepted: {file}"
        );
    }
}
