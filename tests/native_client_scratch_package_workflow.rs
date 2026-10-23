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
            "civitaspo/securefix-server/.github/actions/load-package@6756eaa1a229b9febd0476023b00ebdc0acd2231"
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
