use serde_json::Value;
use std::fs;

fn workflow(path: &str) -> Value {
    let mut yaml: serde_yaml::Value = serde_yaml::from_slice(&fs::read(path).unwrap()).unwrap();
    if let Some(mapping) = yaml.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    serde_json::to_value(yaml).unwrap()
}

#[test]
fn native_client_requests_use_a_fixed_package_across_credential_domains() {
    let value = workflow(".github/workflows/reusable-client-request.yml");
    let inputs = value["on"]["workflow_call"]["inputs"].as_object().unwrap();
    assert!(inputs.keys().all(|key| !key.contains("scratch")));

    for job_name in ["capture", "dispatch"] {
        let steps = value["jobs"][job_name]["steps"].as_array().unwrap();
        let loaders: Vec<_> = steps
            .iter()
            .filter(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.contains("/.github/actions/load-package@"))
            })
            .collect();
        assert_eq!(loaders.len(), 1);
        let package = loaders[0];
        assert_eq!(
            package["uses"],
            "civitaspo/securefix-server/.github/actions/load-package@acbb9eded335037dc7be51d1f49113043153cb2c"
        );
        assert!(package.get("if").is_none());
        assert_eq!(
            package["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
        let cli_step = if job_name == "capture" {
            steps
                .iter()
                .find(|step| {
                    step["name"] == "Capture the exact event and authenticated instance authority"
                })
                .unwrap()
        } else {
            steps
                .iter()
                .find(|step| {
                    step["name"] == "Dispatch the authenticated request with the Client App label"
                })
                .unwrap()
        };
        assert_eq!(
            cli_step["env"]["CLI_BINARY"],
            "${{ steps.package.outputs.binary }}"
        );
    }
}

#[cfg(unix)]
#[test]
fn native_client_capture_passes_the_securefix_artifact_only_to_its_rust_command() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let value = workflow(".github/workflows/reusable-client-request.yml");
    let script = value["jobs"]["capture"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "capture")
        .unwrap()["run"]
        .as_str()
        .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cli = workspace.path().join("stub securefix");
    fs::write(
        &cli,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\n",
    )
    .unwrap();
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
    for (operation, command) in [
        ("securefix", "securefix"),
        ("policy_check", "policy-check"),
        ("approval", "approve"),
        ("merge", "merge"),
    ] {
        let args = workspace.path().join("args");
        let run = Command::new("bash")
            .args(["-euo", "pipefail", "-c", script])
            .env("CLI_BINARY", &cli)
            .env("CAPTURE_ARGS", &args)
            .env("PULL_REQUEST_NUMBER", "42")
            .env("OPERATION", operation)
            .env("SOURCE_ARTIFACT_NAME", "securefix-123-test")
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let mut expected = vec!["new-client", command, "capture"];
        if operation == "securefix" {
            expected.extend(["--artifact-name", "securefix-123-test"]);
        }
        expected.extend([
            "--pull-request-number",
            "42",
            "--output",
            "native-request/manifest.json",
        ]);
        assert_eq!(
            fs::read_to_string(args).unwrap(),
            expected.join("\n") + "\n"
        );
    }
}

#[test]
fn managed_clients_connect_the_generic_signer_to_their_authenticated_instance() {
    const SOURCE: &str = "84f939b68b82de70554f98c429d65e077ef4a771";
    let config = securefix::instance_config::InstanceConfig::parse(
        &fs::read("repo-settings/native-role-events-test-instance.toml").unwrap(),
    )
    .unwrap();
    assert_eq!(
        config.acceptable_clients.producer_workflow,
        ".github/workflows/reusable-client-request.yml"
    );
    for (file, job, operation) in [
        ("policy-check", "check", "policy_check"),
        ("approve-request", "request", "approval"),
        ("merge-request", "request", "merge"),
        ("securefix-request", "request", "securefix"),
    ] {
        let value = workflow(&format!(
            "repo-settings/managed-files/native-settings/{file}.yml"
        ));
        let request = &value["jobs"][job];
        assert_eq!(
            request["uses"],
            format!(
                "civitaspo/securefix-server/.github/workflows/reusable-client-request.yml@{SOURCE}"
            )
        );
        assert_eq!(request["with"]["operation"], operation);
        assert_eq!(
            request["with"]["server_repository"],
            config.instance.repository
        );
        assert_eq!(
            request["with"]["instance_config_path"],
            "repo-settings/native-role-events-test-instance.toml"
        );
        assert!(config.allows_scratch_request_caller(
            "civitaspo/testing-securefix-server",
            1410312556,
            &format!(".github/workflows/{file}.yml"),
            "refs/heads/main",
            if matches!(operation, "approval" | "merge") {
                "issue_comment"
            } else {
                "pull_request_target"
            },
            operation,
        ));
        if operation == "securefix" {
            assert_eq!(request["needs"], "prepare-source");
            assert_eq!(
                request["with"]["artifact_name"],
                "${{ needs.prepare-source.outputs.artifact-name }}"
            );
            let prepare = &value["jobs"]["prepare-source"];
            assert_eq!(
                prepare["permissions"],
                serde_json::json!({"actions":"read", "attestations":"read", "contents":"read"})
            );
            assert!(!serde_json::to_string(prepare).unwrap().contains("secrets."));
            assert_eq!(prepare["if"], request["if"]);
            assert_eq!(
                prepare["outputs"]["artifact-name"],
                "${{ steps.source.outputs.artifact_name }}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn prepare_action_keeps_untrusted_values_in_arguments_and_uploads_only_staged_files() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let action = workflow(".github/actions/prepare-securefix/action.yml");
    assert_eq!(action["runs"]["using"], "composite");
    let steps = action["runs"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(
        steps[0]["with"],
        serde_json::json!({"token":"${{ inputs.token }}"})
    );
    assert_eq!(
        steps[0]["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@f704d9ce91629b0a2094191dbcd3cb0ae591c93a"
    );
    let prepare = &steps[1];
    assert_eq!(prepare["id"], "prepare");
    assert_eq!(
        prepare["env"]["CLI_BINARY"],
        "${{ steps.package.outputs.binary }}"
    );
    let script = prepare["run"].as_str().unwrap();
    assert!(!script.contains("${{"));
    let workspace = tempfile::tempdir().unwrap();
    let cli = workspace.path().join("fixed securefix");
    fs::write(
        &cli,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\nexit \"${CLI_STATUS:-0}\"\n",
    )
    .unwrap();
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
    let args = workspace.path().join("args");
    let values = [
        ("FILES", "path with spaces\nquote'\";$(false).txt"),
        ("ROOT_DIR", "source tree"),
        ("COMMIT_MESSAGE", "fix \"quotes\"; $(false)"),
        ("CUSTOM_JSON", r#"{"message":"$HOME"}"#),
    ];
    for status in ["0", "17"] {
        let result = Command::new("bash")
            .args(["-euo", "pipefail", "-c", script])
            .env("CLI_BINARY", &cli)
            .env("CAPTURE_ARGS", &args)
            .env("CLI_STATUS", status)
            .envs(values)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(status.parse().unwrap()));
        let expected = [
            "new-client",
            "securefix",
            "prepare",
            "--files",
            values[0].1,
            "--root-dir",
            values[1].1,
            "--commit-message",
            values[2].1,
            "--custom-json",
            values[3].1,
            "--output-dir",
            ".securefix-artifacts",
        ];
        assert_eq!(
            fs::read_to_string(&args).unwrap(),
            expected.join("\n") + "\n"
        );
    }
    let upload = &steps[2];
    assert_eq!(upload["if"], "steps.prepare.outputs.artifact_name != ''");
    assert_eq!(
        upload["with"]["name"],
        "${{ steps.prepare.outputs.artifact_name }}"
    );
    assert_eq!(
        upload["with"]["path"],
        "${{ steps.prepare.outputs.artifact_path }}"
    );
    assert_eq!(upload["with"]["include-hidden-files"], true);
    assert_eq!(upload["with"]["if-no-files-found"], "error");
    for output in ["artifact-name", "artifact-id", "changed-files"] {
        assert!(action["outputs"][output]["value"].as_str().is_some());
    }
    assert!(!serde_json::to_string(&action).unwrap().contains("secrets."));
}
