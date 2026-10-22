use serde_json::{Value, json};
use std::{fs, process::Command};

fn publisher_workflow() -> Value {
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../.github/workflows/publish-native-package.yml"
    ))
    .unwrap();
    // serde_yaml follows YAML 1.1 and parses GitHub Actions' `on` key as true.
    if let Some(mapping) = yaml.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    serde_json::to_value(yaml).unwrap()
}

#[test]
fn native_package_preflight_outputs_both_release_states_without_skipping_read_only_mode() {
    let publisher = publisher_workflow();
    let steps = publisher["jobs"]["publish"]["steps"].as_array().unwrap();
    let preflight = steps.iter().find(|step| step["id"] == "preflight").unwrap();
    let script = preflight["run"].as_str().unwrap();
    let extraction = script
        .lines()
        .find(|line| line.trim_start().starts_with("already_published="))
        .unwrap()
        .trim();
    let output = script
        .lines()
        .find(|line| {
            line.trim_start()
                .starts_with("printf 'already-published=%s\\n'")
        })
        .unwrap()
        .trim();

    let writer = steps.iter().find(|step| step["id"] == "writer").unwrap();
    let publish = steps
        .iter()
        .find(|step| step["name"] == "Publish the exact attested executable")
        .unwrap();
    let preflight_only_guard =
        "steps.preflight.outputs.already-published != 'true' && inputs.preflight_only != true";
    assert_eq!(writer["if"], preflight_only_guard);
    assert_eq!(publish["if"], preflight_only_guard);

    for (state, expected) in [("create", "false"), ("already_published", "true")] {
        let temp = tempfile::tempdir().unwrap();
        let output_path = temp.path().join("output");
        fs::write(&output_path, "").unwrap();
        let release_state = if state == "create" {
            json!({"state": state})
        } else {
            json!({
                "state": state,
                "release_id": 11,
                "asset_id": 12,
                "publisher_run_id": 13,
                "publisher_run_attempt": 1
            })
        };
        let result = json!({
            "status": "preflight",
            "evidence": {"release_state": release_state}
        });
        let shell = format!("{extraction}\n{output}");
        let execution = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &shell])
            .env("result", result.to_string())
            .env("GITHUB_OUTPUT", &output_path)
            .output()
            .unwrap();
        assert!(
            execution.status.success(),
            "state {state}: {}",
            String::from_utf8_lossy(&execution.stderr)
        );
        assert_eq!(
            fs::read_to_string(output_path).unwrap(),
            format!("already-published={expected}\n")
        );
    }
}
