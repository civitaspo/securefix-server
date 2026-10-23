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
            "civitaspo/securefix-server/.github/actions/load-package@f704d9ce91629b0a2094191dbcd3cb0ae591c93a"
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
