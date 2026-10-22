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
fn native_client_policy_check_uses_the_exact_pre35_scratch_package() {
    let value = workflow(".github/workflows/reusable-client-request.yml");
    let inputs = value["on"]["workflow_call"]["inputs"].as_object().unwrap();
    assert!(inputs.keys().all(|key| !key.contains("scratch")));

    let scratch_condition = "${{ inputs.operation == 'policy_check' && github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/policy-check.yml@refs/heads/main' && github.event_name == 'pull_request_target' && github.run_attempt == 1 }}";
    let stable_condition = "${{ !(inputs.operation == 'policy_check' && github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/policy-check.yml@refs/heads/main' && github.event_name == 'pull_request_target' && github.run_attempt == 1) }}";
    for job_name in ["capture", "dispatch"] {
        let steps = value["jobs"][job_name]["steps"].as_array().unwrap();
        let stable = steps
            .iter()
            .find(|step| step["name"] == "Load the fixed Securefix Server package")
            .unwrap();
        assert_eq!(stable["if"], stable_condition);
        assert_eq!(
            stable["uses"],
            "civitaspo/securefix-server/.github/actions/load-package@c6aa3110bb31d5ca5bae452d291870066f0147ef"
        );
        assert_eq!(
            stable["with"]["channel"],
            "${{ inputs.operation == 'policy_check' && github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/policy-check.yml@refs/heads/main' && github.event_name == 'pull_request_target' && github.run_attempt == 1 && 'scratch' || 'stable' }}"
        );

        let scratch = steps
            .iter()
            .find(|step| {
                step["name"]
                    == "Load the fixed pre35 package for the immutable policy-check test caller"
            })
            .unwrap();
        assert_eq!(scratch["if"], scratch_condition);
        assert_eq!(
            scratch["uses"],
            "civitaspo/securefix-server/.github/actions/load-package@fa40fc15f4ac79ad97282b83a44d26f6c747311c"
        );
        for (key, expected) in [
            ("action-sha", "fa40fc15f4ac79ad97282b83a44d26f6c747311c"),
            ("source-repository", "civitaspo/securefix-server"),
            ("source-repository-id", "1250079425"),
            (
                "destination-repository",
                "civitaspo/testing-securefix-server",
            ),
            ("destination-repository-id", "1410312556"),
            ("source-default-branch", "main"),
            ("owner-id", "4525500"),
            ("channel", "scratch"),
            (
                "manifest-source-sha",
                "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
            ),
            (
                "publication-source-sha",
                "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
            ),
            (
                "publication-source-branch",
                "integration/native-consumer-pre35-20261023",
            ),
            ("publication-tag", "v0.2.45-pre.35"),
            ("publication-release-id", "421283713"),
            ("publication-asset-id", "667334470"),
            (
                "publication-asset-sha256",
                "589ca95c11671707213b124299d28954bd56957345bbfb637ac2d68d48a9212d",
            ),
            ("publication-asset-size", "12173384"),
            ("publication-producer-run-id", "39866598474"),
            ("publication-producer-run-attempt", "1"),
        ] {
            assert_eq!(
                scratch["with"][key], expected,
                "scratch package {key} changed"
            );
        }

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
            "${{ steps.scratch-package.outputs.binary || steps.package.outputs.binary }}"
        );
    }
}
