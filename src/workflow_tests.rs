use serde_json::Value;
use std::fs;

fn workflows() -> Vec<(String, Value)> {
    fs::read_dir(".github/workflows")
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let value: Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
            (path.display().to_string(), value)
        })
        .collect()
}

fn workflow(name: &str) -> Value {
    let mut yaml: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(".github/workflows/{name}"))
            .unwrap_or_else(|error| panic!("cannot read {name}: {error}")),
    )
    .unwrap_or_else(|error| panic!("cannot parse {name}: {error}"));
    // serde_yaml follows YAML 1.1 and parses GitHub Actions' `on` key as true.
    if let Some(mapping) = yaml.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    serde_json::to_value(yaml).unwrap()
}

#[test]
#[cfg(unix)]
fn runtime_loader_stops_before_extraction_or_export_when_a_gate_fails() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    let script = include_str!("../.github/actions/load-runtime/load.sh");
    let source_sha = "a".repeat(40);
    let policy_sha = "b".repeat(64);
    let archive_sha = "c".repeat(64);
    let control_id = "d".repeat(64);
    for scenario in [
        "success",
        "success-no-pin",
        "success-unsuffixed-publisher",
        "success-bootstrap",
        "success-unsuffixed-bootstrap",
        "success-publisher-later-generation",
        "wrong-publisher-source",
        "wrong-publisher-path",
        "wrong-publisher-suffix",
        "wrong-publisher-ref",
        "wrong-publisher-actor",
        "wrong-publisher-repository",
        "bootstrap-rerun",
        "bootstrap-later-generation",
        "missing",
        "wrong-source",
        "malformed-pin",
        "ambiguous",
        "bad-id",
        "api-error",
        "wrong-immutable",
        "oversized",
        "bad-digest",
        "bad-attestation",
        "bad-metadata",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (name, body) in [
            (
                "gh",
                r#"#!/bin/bash
set -euo pipefail
case "$1" in
  api)
    [[ "$SCENARIO" != api-error ]] || exit 1
    case "$2" in
      repos/example/runtime) cat "$REPOSITORY_JSON" ;;
      repos/example/runtime/commits/main) printf '%s\n' "$ACTIVE_SOURCE_SHA" ;;
      repos/example/runtime/contents/control/active.json\?ref=*)
        [[ "$SCENARIO" != missing ]] || exit 1
        cat "$CONTENT_RESPONSE" ;;
      repos/example/runtime/actions/runs/9) cat "$PUBLISHER_RUN_JSON" ;;
      repos/example/runtime/releases/7) cat "$RELEASE_JSON" ;;
      repos/example/runtime/releases/assets/8)
      echo download >> "$TRACE"
        printf archive ;;
      *) exit 1 ;;
    esac ;;
  attestation)
    echo attestation >> "$TRACE"
    printf '%s\n' "$@" > "$ATTESTATION_ARGS"
    [[ "$SCENARIO" != bad-attestation && "$SCENARIO" != wrong-source ]] ;;
  *) exit 1 ;;
esac
"#,
            ),
            (
                "stat",
                r#"#!/bin/bash
if [[ "$SCENARIO" == oversized && "$3" == *runtime-archive* ]]; then echo 134217729; else wc -c < "$3"; fi
"#,
            ),
            (
                "sha256sum",
                r#"#!/bin/bash
if [[ "$1" == *policy.json ]]; then digest="$POLICY_SHA"; else digest="$ARCHIVE_SHA"; fi
printf '%s  %s\n' "$digest" "$1"
"#,
            ),
            (
                "tar",
                r#"#!/bin/bash
set -euo pipefail
echo extraction >> "$TRACE"
cp "$VERIFIER" "$4/securefix"
"#,
            ),
            (
                "securefix-mock",
                r#"#!/bin/bash
set -euo pipefail
if [[ "$1 $2" == "runtime verify" ]]; then
  echo runtime-verify >> "$TRACE"
elif [[ "$1 $2" == "control identify" ]]; then
  echo control-identify >> "$TRACE"
  source_sha="$ACTIVE_SOURCE_SHA"
  [[ "$SCENARIO" != bad-metadata ]] || source_sha="$(printf 'e%.0s' {1..40})"
  generation=1
  [[ "$SCENARIO" != bootstrap-later-generation && "$SCENARIO" != success-publisher-later-generation ]] || generation=2
  printf 'source-sha=%s\ngeneration=%s\npolicy-sha256=%s\narchive-sha256=%s\nrelease-id=7\nasset-id=8\n' "$source_sha" "$generation" "$POLICY_SHA" "$ARCHIVE_SHA"
  printf 'control-id=%s\n' "$CONTROL_ID"
else
  exit 1
fi
"#,
            ),
        ] {
            let path = bin.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut descriptor = serde_json::json!({
            "version": 1,
            "generation": if scenario == "bootstrap-later-generation" || scenario == "success-publisher-later-generation" { 2 } else { 1 },
            "source_sha": source_sha,
            "policy_sha256": policy_sha,
            "archive_sha256": archive_sha,
            "release_id": 7,
            "asset_id": 8,
            "publisher_run_id": 9,
            "verification_run_id": 10,
            "previous": "0".repeat(64)
        });
        if scenario == "bad-id" {
            descriptor["asset_id"] = 0.into();
        }
        let descriptor_bytes = serde_json::to_vec(&descriptor).unwrap();
        use base64::Engine;
        let content_response = serde_json::json!({
            "encoding":"base64",
            "content":base64::engine::general_purpose::STANDARD.encode(descriptor_bytes)
        });
        let content_path = temp.path().join("content.json");
        fs::write(
            &content_path,
            serde_json::to_vec(&content_response).unwrap(),
        )
        .unwrap();
        let repository_path = temp.path().join("repository.json");
        fs::write(
            &repository_path,
            serde_json::to_vec(&serde_json::json!({
                "id":1,"default_branch":"main","owner":{"id":2}
            }))
            .unwrap(),
        )
        .unwrap();
        let publisher_run_path = if scenario == "success-bootstrap"
            || scenario == "success-unsuffixed-bootstrap"
            || scenario == "bootstrap-rerun"
            || scenario == "bootstrap-later-generation"
        {
            if scenario == "success-unsuffixed-bootstrap" {
                ".github/workflows/control-bootstrap.yml"
            } else {
                ".github/workflows/control-bootstrap.yml@refs/heads/main"
            }
        } else if scenario == "wrong-publisher-path" {
            ".github/workflows/other.yml@refs/heads/main"
        } else if scenario == "wrong-publisher-suffix" {
            ".github/workflows/publish-runtime.yml@refs/heads/other"
        } else if scenario == "success-unsuffixed-publisher" {
            ".github/workflows/publish-runtime.yml"
        } else {
            ".github/workflows/publish-runtime.yml@refs/heads/main"
        };
        let publisher_run_path_file = temp.path().join("publisher-run.json");
        fs::write(
            &publisher_run_path_file,
            serde_json::to_vec(&serde_json::json!({
                "id":9,
                "path":publisher_run_path,
                "run_attempt": if scenario == "bootstrap-rerun" { 2 } else { 1 },
                "status":"completed",
                "conclusion":"success",
                "event":"workflow_dispatch",
                "head_branch": if scenario == "wrong-publisher-ref" { "other" } else { "main" },
                "head_sha": if scenario == "wrong-publisher-source" { "f".repeat(40) } else { source_sha.clone() },
                "repository": if scenario == "wrong-publisher-repository" { serde_json::json!({"id":7,"full_name":"example/other"}) } else { serde_json::json!({"id":1,"full_name":"example/runtime"}) },
                "head_repository":{"id":1,"full_name":"example/runtime"},
                "actor":{"id": if scenario == "wrong-publisher-actor" { 3 } else { 4525500 }},
                "triggering_actor":{"id":4525500}
            })).unwrap(),
        ).unwrap();
        let mut release = serde_json::json!({
            "id":7,"draft":false,"immutable":true,
            "assets":[{"id":8,"name":"securefix-runtime-linux-x86_64.tar.gz"}]
        });
        if scenario == "ambiguous" {
            let asset = release["assets"][0].clone();
            release["assets"].as_array_mut().unwrap().push(asset);
        }
        if scenario == "wrong-immutable" {
            release["immutable"] = false.into();
        }
        let release_path = temp.path().join("release.json");
        fs::write(&release_path, serde_json::to_vec(&release).unwrap()).unwrap();
        let trace = temp.path().join("trace");
        let output = temp.path().join("output");
        fs::write(&trace, "").unwrap();
        fs::write(&output, "").unwrap();
        let mut command = Command::new("bash");
        command
            .args(["-euo", "pipefail", "-c", script])
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("RUNNER_TEMP", temp.path())
            .env("GITHUB_OUTPUT", &output)
            .env("ACTIVE_SOURCE_SHA", &source_sha)
            .env("POLICY_SHA", &policy_sha)
            .env(
                "ARCHIVE_SHA",
                if scenario == "bad-digest" {
                    "f".repeat(64)
                } else {
                    archive_sha.clone()
                },
            )
            .env("CONTROL_ID", &control_id)
            .env("REPOSITORY", "example/runtime")
            .env("DEFAULT_BRANCH", "main")
            .env("SCENARIO", scenario)
            .env("CONTENT_RESPONSE", content_path)
            .env("REPOSITORY_JSON", repository_path)
            .env("PUBLISHER_RUN_JSON", publisher_run_path_file)
            .env("RELEASE_JSON", release_path)
            .env("TRACE", &trace)
            .env("ATTESTATION_ARGS", temp.path().join("attestation-args"))
            .env("VERIFIER", bin.join("securefix-mock"));
        match scenario {
            "wrong-source" => {
                command.env("SOURCE_SHA", "f".repeat(40));
            }
            "malformed-pin" => {
                command.env("SOURCE_SHA", "not-a-sha");
            }
            "success-no-pin" => {}
            _ => {
                command.env("SOURCE_SHA", &source_sha);
            }
        }
        let result = command.output().unwrap();
        let should_succeed = matches!(
            scenario,
            "success"
                | "success-no-pin"
                | "success-unsuffixed-publisher"
                | "success-bootstrap"
                | "success-unsuffixed-bootstrap"
                | "success-publisher-later-generation"
                | "bootstrap-later-generation"
        );
        assert_eq!(
            result.status.success(),
            should_succeed,
            "{scenario}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let expected = match scenario {
            "success"
            | "success-no-pin"
            | "success-unsuffixed-publisher"
            | "success-bootstrap"
            | "success-unsuffixed-bootstrap"
            | "success-publisher-later-generation"
            | "bootstrap-later-generation" => {
                "download\nattestation\nextraction\nruntime-verify\ncontrol-identify\n"
            }
            "bad-metadata" => {
                "download\nattestation\nextraction\nruntime-verify\ncontrol-identify\n"
            }
            "bad-attestation" => "download\nattestation\n",
            "wrong-source"
            | "malformed-pin"
            | "wrong-publisher-source"
            | "wrong-publisher-path"
            | "wrong-publisher-suffix"
            | "wrong-publisher-ref"
            | "wrong-publisher-actor"
            | "wrong-publisher-repository"
            | "bootstrap-rerun" => "",
            "oversized" | "bad-digest" => "download\n",
            _ => "",
        };
        assert_eq!(fs::read_to_string(trace).unwrap(), expected, "{scenario}");
        assert_eq!(
            !fs::read(output).unwrap().is_empty(),
            should_succeed,
            "{scenario}"
        );
        if matches!(
            scenario,
            "success"
                | "success-no-pin"
                | "success-unsuffixed-publisher"
                | "success-bootstrap"
                | "success-unsuffixed-bootstrap"
                | "success-publisher-later-generation"
                | "bootstrap-later-generation"
        ) {
            let args = fs::read_to_string(temp.path().join("attestation-args")).unwrap();
            let expected_signer = if scenario == "success-bootstrap"
                || scenario == "success-unsuffixed-bootstrap"
                || scenario == "bootstrap-later-generation"
            {
                "example/runtime/.github/workflows/control-bootstrap.yml"
            } else {
                "example/runtime/.github/workflows/publish-runtime.yml"
            };
            assert!(
                args.lines().any(|line| line == expected_signer),
                "{scenario}: {args}"
            );
        }
    }
}

#[test]
fn workflows_use_pinned_actions_and_immutable_flattened_artifacts() {
    for (path, workflow) in workflows() {
        assert!(
            workflow["permissions"]
                .as_object()
                .is_some_and(|p| p.is_empty()),
            "{path}: top-level permissions must be empty"
        );
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            if let Some(uses) = job["uses"].as_str() {
                let published_probe_loader = path == ".github/workflows/testing-release-pr.yml"
                    && job_id == "trusted-runtime"
                    && uses
                        == "civitaspo/securefix-server/.github/workflows/load-cli.yml@9ec4043ce71f454811ef676b82dcba1314a5f0bb";
                assert!(
                    uses.starts_with("./.github/workflows/") || published_probe_loader,
                    "{path}/{job_id}: local reusable must use the running revision"
                );
                if published_probe_loader {
                    assert_eq!(job["permissions"]["contents"], "read");
                    assert_eq!(job["permissions"]["attestations"], "read");
                }
                assert!(
                    job.get("secrets").is_none() || uses != "./.github/workflows/load-cli.yml",
                    "runtime loader cannot inherit secrets"
                );
                if uses == "./.github/workflows/load-cli.yml" {
                    assert_eq!(
                        job["permissions"]["actions"], "read",
                        "{path}/{job_id}: loader caller needs action run metadata read"
                    );
                    assert_eq!(
                        job["permissions"]["contents"], "read",
                        "{path}/{job_id}: loader caller needs content read"
                    );
                    assert_eq!(
                        job["permissions"]["attestations"], "read",
                        "{path}/{job_id}: loader caller needs attestation read"
                    );
                }
            }
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            for step in steps {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                if !uses.starts_with("./") && !uses.starts_with("$/") {
                    let (_, revision) = uses.rsplit_once('@').unwrap();
                    assert!(
                        securefix::policy::validate_sha(revision).is_ok(),
                        "{path}/{job_id}: {uses}"
                    );
                }
                assert!(
                    !uses.contains("github-script")
                        && !uses.contains("approve-pr-action")
                        && !uses.contains("csm-actions/securefix-action"),
                    "business logic must be in Rust"
                );
                if uses.starts_with("actions/download-artifact@") {
                    let inputs = &step["with"];
                    if path == ".github/workflows/testing-provider-release.yml"
                        && job_id == "assemble-provider"
                    {
                        assert_eq!(
                            inputs["pattern"], "sigma-probe-${{ github.run_id }}-*",
                            "only the current run's provider matrix artifacts may be assembled"
                        );
                        assert_eq!(inputs["path"], "probe/assets");
                        assert_eq!(inputs["merge-multiple"], true);
                        assert!(inputs.get("artifact-ids").is_none());
                        assert!(inputs.get("repository").is_none());
                        assert!(inputs.get("run-id").is_none());
                        continue;
                    }
                    if path == ".github/workflows/testing-securefix-server.yml" && job_id == "reuse"
                    {
                        if inputs["artifact-ids"]
                            == "${{ needs.baseline-build.outputs.artifact-id }}"
                        {
                            assert_eq!(inputs["path"], "trusted-runtime");
                            assert_eq!(inputs["merge-multiple"], true);
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else {
                            assert_eq!(
                                inputs["artifact-ids"],
                                "${{ steps.state.outputs.candidate_artifact_id }}"
                            );
                            assert_eq!(inputs["repository"], "civitaspo/securefix-server");
                            assert_eq!(inputs["run-id"], "${{ inputs.fixture_run_id }}");
                            assert_eq!(inputs["merge-multiple"], true);
                        }
                        continue;
                    }
                    if path == ".github/workflows/testing-release-pr.yml" && job_id == "execute" {
                        assert_eq!(inputs["merge-multiple"], true);
                        let artifact_id = inputs["artifact-ids"].as_str().unwrap();
                        if artifact_id == "${{ needs.trusted-runtime.outputs.artifact-id }}" {
                            assert_eq!(inputs["path"], "trusted-runtime");
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else if artifact_id == "${{ needs.candidate-build.outputs.artifact-id }}"
                        {
                            assert_eq!(step["if"], "inputs.phase == 'prepare'");
                            assert_eq!(inputs["path"], "candidate");
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else {
                            assert!(
                                artifact_id
                                    == "${{ steps.artifacts.outputs.candidate_artifact_id }}"
                                    || artifact_id
                                        == "${{ steps.artifacts.outputs.state_artifact_id }}"
                            );
                            assert_eq!(step["if"], "inputs.phase == 'verify'");
                            assert_eq!(inputs["repository"], "civitaspo/securefix-server");
                            assert_eq!(inputs["run-id"], "${{ inputs.prepare_run_id }}");
                            assert_eq!(inputs["github-token"], "${{ github.token }}");
                            assert_eq!(
                                inputs["path"],
                                if artifact_id.contains("candidate_artifact") {
                                    "candidate"
                                } else {
                                    "fixture-state"
                                }
                            );
                        }
                        continue;
                    }
                    assert!(
                        inputs["artifact-ids"].as_str().is_some_and(|v| {
                            v.starts_with("${{ needs.") || v.starts_with("${{ steps.state.")
                        }),
                        "{path}/{job_id}: immutable artifact ID required"
                    );
                    assert!(inputs.get("name").is_none() && inputs.get("pattern").is_none());
                    assert_eq!(
                        inputs["merge-multiple"], true,
                        "{path}/{job_id}: IDs otherwise extract into named subdirectories"
                    );
                }
                if uses.starts_with("actions/checkout@") {
                    assert_eq!(
                        step["with"]["persist-credentials"], false,
                        "{path}/{job_id}: checkout credentials must not persist"
                    );
                    if step["with"]["repository"] == "civitaspo/securefix-server" {
                        assert_eq!(
                            step["with"]["ref"],
                            if path == ".github/workflows/testing-securefix-server.yml" {
                                if job_id == "baseline-build" {
                                    "${{ steps.resolve.outputs.sha }}"
                                } else if job_id == "build" {
                                    "${{ inputs.candidate_sha || job.workflow_sha }}"
                                } else if job_id == "client-smoke" {
                                    "${{ needs.build.outputs.source-sha }}"
                                } else if job_id == "bootstrap-scratch" {
                                    "${{ github.workflow_sha }}"
                                } else {
                                    "${{ inputs.candidate_sha || job.workflow_sha }}"
                                }
                            } else {
                                if path == ".github/workflows/control-bootstrap.yml" {
                                    "${{ github.workflow_sha }}"
                                } else {
                                    "${{ job.workflow_sha }}"
                                }
                            },
                            "{path}/{job_id}: actual defining workflow revision required"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn verified_runtime_loading_and_publishing_keep_credentials_separate() {
    let loader = workflow("load-cli.yml");
    let load = &loader["jobs"]["load"];
    assert!(loader["on"].get("workflow_dispatch").is_none());
    assert_eq!(
        loader["defaults"]["run"]["shell"], "bash -euo pipefail {0}",
        "failed release fetch or attestation verification must stop the loader"
    );
    assert_eq!(
        load["permissions"],
        serde_json::json!({
            "actions":"read", "contents":"read", "attestations":"read"
        })
    );
    let steps = load["steps"].as_array().unwrap();
    assert_eq!(steps[0]["uses"], "$/.github/actions/load-runtime");
    assert!(steps[0]["with"].get("source-sha").is_none());
    assert_eq!(steps[0]["with"]["repository"], "civitaspo/securefix-server");
    assert_eq!(
        loader["on"]["workflow_call"]["outputs"]["source-sha"]["value"],
        "${{ jobs.load.outputs.source-sha }}"
    );
    assert_eq!(
        load["outputs"]["source-sha"],
        "${{ steps.runtime.outputs.source-sha }}"
    );
    assert_eq!(
        load["outputs"]["control-id"],
        "${{ steps.runtime.outputs.control-id }}"
    );
    assert_eq!(load["outputs"]["workflow-sha"], "${{ job.workflow_sha }}");
    assert_eq!(
        loader["on"]["workflow_call"]["outputs"]["control-id"]["value"],
        "${{ jobs.load.outputs.control-id }}"
    );
    assert_eq!(
        load["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let upload = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/upload-artifact@"))
        })
        .unwrap();
    assert_eq!(
        steps[upload]["with"]["path"],
        "${{ steps.runtime.outputs.directory }}/"
    );
    let action: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/load-runtime/action.yml").unwrap())
            .unwrap();
    let load_text = format!("{load}{action}");
    for forbidden in [
        "secrets.",
        "actions/checkout",
        "setup-cli",
        "cargo ",
        "rustup ",
    ] {
        assert!(
            !load_text.contains(forbidden),
            "loader contains {forbidden}"
        );
    }
    assert_eq!(steps[upload]["with"]["retention-days"], 1);
    assert!(steps[0].get("if").is_none());
    assert_ne!(steps[0]["continue-on-error"], true);
    assert!(action["runs"]["steps"][0].get("if").is_none());
    assert_ne!(action["runs"]["steps"][0]["continue-on-error"], true);
    let script = fs::read_to_string(".github/actions/load-runtime/load.sh").unwrap();
    assert_eq!(
        action["runs"]["steps"][0]["run"],
        "bash \"$ACTION_PATH/load.sh\""
    );
    assert_eq!(
        action["runs"]["steps"][0]["env"]["ACTION_PATH"],
        "${{ github.action_path }}"
    );
    for required in [
        "control/active.json?ref=$main_sha",
        "actions/runs/$publisher_run_id",
        "releases/$release_id",
        "releases/assets/$asset_id",
        ".immutable",
        "archive_sha256",
        "-le 16384",
        "control-id",
        "gh attestation verify",
        "--repo \"$REPOSITORY\"",
        "--source-digest \"$source_sha\"",
        "--source-ref \"refs/heads/$DEFAULT_BRANCH\"",
        "--signer-workflow \"$signer_workflow\"",
        "control-bootstrap.yml@refs/heads/$DEFAULT_BRANCH",
        "publisher_run_id",
        "--signer-digest \"$source_sha\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
        "tar -xzf",
        "runtime verify --source-sha",
    ] {
        assert!(
            script.contains(required),
            "shared runtime loader lacks {required}"
        );
    }
    let attestation = script.find("gh attestation verify").unwrap();
    let extraction = script.find("tar -xzf").unwrap();
    let verify_runtime = script.find("runtime verify --source-sha").unwrap();
    assert!(attestation < extraction && extraction < verify_runtime);
    assert!(
        !script.contains("cargo ")
            && !script.contains("rustup ")
            && !script.contains("actions/checkout")
    );
    let client = fs::read_to_string(".github/actions/client/action.yml").unwrap();
    let client_action: Value = serde_yaml::from_slice(client.as_bytes()).unwrap();
    let client_steps = client_action["runs"]["steps"].as_array().unwrap();
    let published_loader = client_steps
        .iter()
        .find(|step| step["id"] == "published-runtime")
        .unwrap();
    assert_eq!(published_loader["if"], "inputs.runtime-directory == ''");
    assert_eq!(
        published_loader["run"],
        "bash \"$ACTION_PATH/../load-runtime/load.sh\""
    );
    assert_eq!(
        published_loader["env"]["ACTION_PATH"],
        "${{ github.action_path }}"
    );
    assert_eq!(
        published_loader["env"]["SOURCE_SHA"],
        "${{ inputs.runtime-sha }}"
    );
    assert_eq!(
        published_loader["env"]["GH_TOKEN"],
        "${{ inputs.runtime-token || github.token }}"
    );
    let install_runtime = client_steps
        .iter()
        .find(|step| step["id"] == "runtime")
        .unwrap();
    assert_eq!(
        install_runtime["env"]["SECUREFIX_RUNTIME_SHA"],
        "${{ inputs.runtime-sha }}"
    );
    assert_eq!(
        install_runtime["env"]["VERIFIED_CONTROL_ID"],
        "${{ steps.published-runtime.outputs.control-id }}"
    );
    let prepare = client_steps
        .iter()
        .find(|step| step["id"] == "prepare")
        .unwrap();
    let dispatch = client_steps
        .iter()
        .find(|step| step["id"] == "dispatch")
        .unwrap();
    for step in [prepare, dispatch] {
        assert_eq!(
            step["env"]["SECUREFIX_SOURCE_SHA"],
            "${{ steps.runtime.outputs.source-sha }}"
        );
        assert_eq!(
            step["env"]["SECUREFIX_CONTROL_ID"],
            "${{ steps.runtime.outputs.control-id }}"
        );
        let script = step["run"].as_str().unwrap();
        assert!(script.contains("unset SECUREFIX_SOURCE_SHA"));
        assert!(script.contains("unset SECUREFIX_CONTROL_ID"));
    }
    assert_eq!(
        client_action["outputs"]["runtime-control-id"]["value"],
        "${{ steps.runtime.outputs.control-id }}"
    );
    let install_script = install_runtime["run"].as_str().unwrap();
    let candidate_branch = install_script
        .find("runtime_source=prebuilt-candidate")
        .unwrap();
    let published_branch = install_script
        .find("runtime_source=attested-release")
        .unwrap();
    let control_copy = install_script
        .find("install -m 644 \"$runtime_dir/control.json\" \"$bin_dir/control.json\"")
        .unwrap();
    assert!(candidate_branch < published_branch && published_branch < control_copy);
    assert!(install_script.contains("if [[ -n \"$control_id\" ]]; then"));
    assert!(client.contains("INPUT_RUNTIME_DIRECTORY"));
    assert!(client.contains("runtime_source=prebuilt-candidate"));
    assert!(client.contains("runtime_source=attested-release"));
    let ci = workflow("ci.yml");
    let ci_steps = ci["jobs"]["workflows"]["steps"].as_array().unwrap();
    let version_guard = ci_steps
        .iter()
        .position(|step| {
            step["name"] == "Require a runtime version bump over the pull request base"
        })
        .unwrap();
    let version_guard_run = ci_steps[version_guard]["run"].as_str().unwrap();
    assert!(version_guard_run.contains("git diff --name-only -z --no-renames"));
    assert!(version_guard_run.contains("runtime check-version"));
    assert!(version_guard_run.contains("--changed-files \"$changed_files\""));
    let build_cli = ci_steps
        .iter()
        .position(|step| step["id"] == "build-cli")
        .unwrap();
    let install_cli = ci_steps
        .iter()
        .position(|step| step["uses"] == "$/.github/actions/install-cli")
        .unwrap();
    assert!(build_cli < version_guard && version_guard < install_cli);

    let publisher = workflow("publish-runtime.yml");
    assert!(publisher["on"].get("workflow_dispatch").is_some());
    assert!(publisher["on"].get("push").is_none());
    assert_eq!(
        publisher["jobs"]["build"]["if"],
        "github.repository == 'civitaspo/securefix-server' && github.ref == 'refs/heads/main' && github.actor_id == '4525500'"
    );
    let build = &publisher["jobs"]["build"];
    assert_eq!(
        build["permissions"],
        serde_json::json!({
            "contents":"read", "id-token":"write", "attestations":"write"
        })
    );
    assert_eq!(
        build["outputs"]["source-sha"],
        "${{ steps.checkout.outputs.commit }}"
    );
    let build_text = serde_json::to_string(build).unwrap();
    assert!(!build_text.contains("secrets."));
    assert!(build_text.contains("./.github/actions/setup-cli"));
    assert_eq!(
        build["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let build_steps = build["steps"].as_array().unwrap();
    assert!(build_steps.iter().any(|step| {
        step["with"]["repository"] == "civitaspo/securefix-server"
            && step["with"]["ref"] == "${{ job.workflow_sha }}"
            && step["with"]["persist-credentials"] == false
    }));
    let attest_steps = build_steps
        .iter()
        .filter(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/attest@"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        attest_steps.len(),
        1,
        "exactly one archive subject is attested"
    );
    assert_eq!(
        attest_steps[0]["with"]["subject-path"],
        "distribution/securefix-runtime-linux-x86_64.tar.gz"
    );
    assert_eq!(attest_steps[0]["with"]["create-storage-record"], false);
    assert!(
        attest_steps[0]["with"]["subject-path"]
            .as_str()
            .unwrap()
            .ends_with(".tar.gz")
    );

    let controller = &publisher["jobs"]["controller"];
    assert_eq!(controller["uses"], "./.github/workflows/load-cli.yml");
    assert_eq!(controller["if"], build["if"]);
    assert_eq!(
        controller["permissions"],
        serde_json::json!({"actions":"read", "contents":"read", "attestations":"read"})
    );
    let publish = &publisher["jobs"]["publish"];
    assert_eq!(publish["needs"], serde_json::json!(["build", "controller"]));
    assert_eq!(
        publish["permissions"],
        serde_json::json!({"contents":"write", "attestations":"read"})
    );
    let publish_text = serde_json::to_string(publish).unwrap();
    for forbidden in ["id-token", "setup-cli", "actions/checkout"] {
        assert!(
            !publish_text.contains(forbidden),
            "publisher contains {forbidden}"
        );
    }
    assert_eq!(
        publish["env"]["SECUREFIX_SOURCE_SHA"],
        "${{ needs.controller.outputs.source-sha }}"
    );
    assert_eq!(
        publish["env"]["CANDIDATE_SOURCE_SHA"],
        "${{ needs.build.outputs.source-sha }}"
    );
    assert!(publish["steps"].as_array().unwrap().iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
            && step["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
            && step["with"]["path"] == "distribution"
    }));
    let publish_steps = publish["steps"].as_array().unwrap();
    let publish_index = |predicate: &dyn Fn(&Value) -> bool| {
        publish_steps
            .iter()
            .position(predicate)
            .unwrap_or_else(|| panic!("required publisher step is missing"))
    };
    let downloaded = publish_index(&|step| {
        step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/download-artifact@")
                && step["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
        })
    });
    let verified = publish_index(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("gh attestation verify distribution/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let controller_downloaded = publish_index(&|step| {
        step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/download-artifact@")
                && step["with"]["artifact-ids"] == "${{ needs.controller.outputs.artifact-id }}"
                && step["with"]["path"] == "${{ runner.temp }}/controller"
        })
    });
    let invoked = publish_index(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("securefix runtime publish --source-sha \"$CANDIDATE_SOURCE_SHA\" --archive distribution/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let installed = publish_index(&|step| step["uses"] == "$/.github/actions/install-cli");
    assert!(
        downloaded < controller_downloaded
            && controller_downloaded < verified
            && verified < installed
            && installed < invoked
    );
    assert!(publish_steps.iter().all(|step| {
        !step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
    }));
    assert!(publish_steps[invoked]["env"].is_null());
    assert_eq!(
        publish_steps[installed]["with"]["binary"],
        "${{ runner.temp }}/controller/securefix"
    );
    assert!(
        publish_steps.iter().all(|step| !step["run"]
            .as_str()
            .is_some_and(|run| run.contains("tar -xzf"))),
        "credentialed publication must not extract the candidate archive"
    );
    assert!(
        !publish_text.contains("candidate-runtime/securefix")
            && !publish_text.contains("./.github/actions/setup-cli")
    );
    let verification = publish_steps[verified]["run"].as_str().unwrap();
    for required in [
        "--repo civitaspo/securefix-server",
        "--source-digest \"$CANDIDATE_SOURCE_SHA\"",
        "--source-ref refs/heads/main",
        "--signer-workflow civitaspo/securefix-server/.github/workflows/publish-runtime.yml",
        "--signer-digest \"$CANDIDATE_SOURCE_SHA\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ] {
        assert!(
            verification.contains(required),
            "publisher missing attestation constraint: {required}"
        );
    }
    for index in [verified, invoked] {
        assert_ne!(publish_steps[index]["continue-on-error"], true);
        assert!(publish_steps[index].get("if").is_none());
    }
    let ci = workflow("ci.yml");
    let ci_build = &ci["jobs"]["workflows"];
    assert_eq!(
        ci_build["permissions"],
        serde_json::json!({"contents":"read"})
    );
    assert!(
        !serde_json::to_string(ci_build)
            .unwrap()
            .contains("secrets.")
    );
    let mut setup_users = workflows()
        .into_iter()
        .flat_map(|(path, workflow)| {
            workflow["jobs"]
                .as_object()
                .cloned()
                .unwrap_or_default()
                .into_values()
                .filter_map(move |job| {
                    job["steps"].as_array().and_then(|steps| {
                        steps
                            .iter()
                            .any(|step| {
                                step["uses"].as_str().is_some_and(|uses| {
                                    uses.ends_with("/.github/actions/setup-cli")
                                })
                            })
                            .then(|| path.clone())
                    })
                })
        })
        .collect::<Vec<_>>();
    setup_users.sort();
    assert_eq!(
        setup_users,
        [
            ".github/workflows/ci.yml",
            ".github/workflows/control-bootstrap.yml",
            ".github/workflows/publish-runtime.yml",
            ".github/workflows/testing-release-pr.yml",
            ".github/workflows/testing-securefix-server.yml",
            ".github/workflows/testing-securefix-server.yml"
        ],
        "only secret-free CI and runtime producer compile CLI"
    );
    for (path, workflow) in workflows() {
        if matches!(
            path.as_str(),
            ".github/workflows/ci.yml"
                | ".github/workflows/publish-runtime.yml"
                | ".github/workflows/build-bootstrap-host.yml"
        ) {
            continue;
        }
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            if path == ".github/workflows/testing-securefix-server.yml" && job_id == "build" {
                continue;
            }
            if path == ".github/workflows/testing-release-pr.yml" && job_id == "candidate-build" {
                continue;
            }
            if path == ".github/workflows/testing-provider-release.yml"
                && job_id == "compile-harness"
            {
                continue;
            }
            for step in job["steps"].as_array().into_iter().flatten() {
                if let Some(run) = step["run"].as_str() {
                    assert!(
                        !run.contains("cargo ") && !run.contains("rustup "),
                        "{path}/{job_id}: operational jobs must load the published runtime"
                    );
                }
            }
        }
    }
    let setup = fs::read_to_string(".github/actions/setup-cli/action.yml").unwrap();
    assert!(setup.contains("build --locked --release"));
    assert!(!setup.contains("secrets."));
    let installer: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/install-cli/action.yml").unwrap())
            .unwrap();
    let install = installer["runs"]["steps"][0]["run"].as_str().unwrap();
    assert!(install.contains("install -D -m 755"));
    assert!(install.contains("$GITHUB_PATH"));
    assert!(installer["inputs"].get("binary").is_some());
}

#[test]
fn operational_lanes_use_the_active_control_and_keep_distribution_explicit() {
    for (name, loader_job, consumer_jobs) in [
        ("securefix.yml", "runtime", vec!["fix"]),
        ("approve.yml", "build", vec!["approve", "cleanup"]),
        (
            "merge.yml",
            "build",
            vec!["authorize", "wait", "apply", "cleanup"],
        ),
        ("policy-check.yml", "cli", vec!["request"]),
        ("merge-caller-migration.yml", "runtime", vec!["merge"]),
    ] {
        let value = workflow(name);
        let loader = &value["jobs"][loader_job];
        assert_eq!(loader["uses"], "./.github/workflows/load-cli.yml", "{name}");
        assert_eq!(loader["permissions"]["actions"], "read", "{name}");
        assert_eq!(loader["permissions"]["contents"], "read", "{name}");
        assert_eq!(loader["permissions"]["attestations"], "read", "{name}");
        for consumer_id in consumer_jobs {
            let consumer = &value["jobs"][consumer_id];
            assert_eq!(
                consumer["env"]["SECUREFIX_SOURCE_SHA"],
                format!("${{{{ needs.{loader_job}.outputs.source-sha }}}}"),
                "{name}/{consumer_id}: runtime source must come from active descriptor"
            );
            assert_eq!(
                consumer["env"]["SECUREFIX_CONTROL_ID"],
                format!("${{{{ needs.{loader_job}.outputs.control-id }}}}"),
                "{name}/{consumer_id}: control identity must come from active descriptor"
            );
        }
    }

    let merge = workflow("merge.yml");
    let wait = &merge["jobs"]["wait"];
    assert_eq!(wait["runs-on"], "ubuntu-latest");
    assert_eq!(wait["needs"], serde_json::json!(["build", "authorize"]));
    assert_eq!(wait["timeout-minutes"], 70);
    assert_eq!(wait["permissions"]["checks"], "read");
    assert_eq!(wait["permissions"]["statuses"], "read");
    for permission in ["contents", "issues", "pull-requests", "checks", "statuses"] {
        assert_ne!(
            wait["permissions"][permission], "write",
            "merge wait is read-only"
        );
    }
    assert!(
        wait["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| { step["run"] == "securefix merge wait" })
    );
    let apply = &merge["jobs"]["apply"];
    assert!(
        apply["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job == "wait")
    );
    let merge_token = apply["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "merge-token")
        .unwrap();
    assert_eq!(merge_token["if"], "needs.wait.result == 'success'");

    let distribution = workflow("distribute-runtime.yml");
    let dispatch = &distribution["on"]["workflow_dispatch"]["inputs"]["publisher_run_id"];
    assert_eq!(dispatch["required"], true);
    assert!(distribution["on"].get("workflow_run").is_none());
    assert!(distribution["jobs"].get("caller").is_some());
    let publisher = workflow("publish-runtime.yml");
    assert!(publisher["on"].get("workflow_run").is_none());
    assert!(
        !serde_json::to_string(&publisher["jobs"]["publish"])
            .unwrap()
            .contains("distribute-runtime")
    );
}

#[test]
fn caller_migration_requires_read_validation_and_readiness_before_each_write_token() {
    let migration = workflow("merge-caller-migration.yml");
    assert_eq!(
        migration["jobs"]["merge"]["concurrency"]["group"],
        "securefix-control"
    );
    assert_eq!(migration["jobs"]["merge"]["concurrency"]["queue"], "max");
    let steps = migration["jobs"]["merge"]["steps"].as_array().unwrap();
    let target = steps.iter().position(|s| s["id"] == "target").unwrap();
    let read = steps.iter().position(|s| s["id"] == "read-token").unwrap();
    let prepare = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.starts_with("securefix caller-migration prepare "))
        })
        .unwrap();
    let authorize = steps
        .iter()
        .position(|s| s["id"] == "authorization-token")
        .unwrap();
    let ready = steps
        .iter()
        .position(|s| s["run"] == "securefix caller-migration ready")
        .unwrap();
    let merge = steps.iter().position(|s| s["id"] == "merge-token").unwrap();
    assert!(
        target < read
            && read < prepare
            && prepare < authorize
            && authorize < ready
            && ready < merge
    );
    assert_eq!(steps[merge + 1]["run"], "securefix caller-migration merge");
    assert_eq!(steps[read]["with"]["permission-contents"], "read");
    assert!(
        steps[authorize]["with"]
            .get("permission-contents")
            .is_none()
    );
    assert_eq!(
        steps[authorize]["with"]["permission-pull-requests"],
        "write"
    );
    assert_eq!(steps[authorize]["with"]["permission-checks"], "write");
    assert_eq!(steps[authorize]["with"]["permission-issues"], "write");
    assert_eq!(
        steps[authorize]["with"]["repositories"],
        "${{ steps.target.outputs.repository_name }}"
    );
    assert_eq!(
        steps[merge]["with"]["repositories"],
        "${{ steps.target.outputs.repository_name }}"
    );
    assert!(steps.iter().all(|s| s["uses"] != "actions/checkout"));
    let source = fs::read_to_string("src/distribution.rs").unwrap();
    let production = source
        .split("Command::ApplyCaller {")
        .nth(1)
        .unwrap()
        .split("Command::ProbeCaller")
        .next()
        .unwrap();
    assert!(!production.contains("merge_runtime_update"));
}

#[test]
fn bootstrap_workflow_uses_fixed_host_code_and_serialized_main_authority() {
    let bootstrap = workflow("control-bootstrap.yml");
    assert_eq!(
        bootstrap["jobs"]["bootstrap-host"]["uses"],
        "./.github/workflows/build-bootstrap-host.yml"
    );
    let host_build = workflow("build-bootstrap-host.yml");
    let host_build = &host_build["jobs"]["build"];
    assert_eq!(
        host_build["permissions"],
        serde_json::json!({"contents":"read"})
    );
    let host_text = serde_json::to_string(host_build).unwrap();
    for forbidden in [
        "secrets.",
        "environment",
        "id-token",
        "attestations",
        "candidate-runtime",
        "create-github-app-token",
    ] {
        assert!(
            !host_text.contains(forbidden),
            "host build exposes {forbidden}"
        );
    }
    assert!(
        host_build["if"]
            .as_str()
            .unwrap()
            .contains("github.run_attempt == 1")
    );
    let build_steps = host_build["steps"].as_array().unwrap();
    assert_eq!(build_steps[0]["with"]["ref"], "${{ job.workflow_sha }}");
    let compile = build_steps
        .iter()
        .find(|step| step["env"]["SECUREFIX_BOOTSTRAP_SOURCE_SHA"].is_string())
        .unwrap();
    assert_eq!(
        compile["env"]["SECUREFIX_BOOTSTRAP_SOURCE_SHA"],
        "${{ job.workflow_sha }}"
    );
    assert_eq!(
        compile["run"],
        "cargo +1.99.0 build --locked --release --bin securefix-bootstrap"
    );
    for job_id in [
        "validate-proposal",
        "propose",
        "validate-merge",
        "merge",
        "repair-propose",
        "repair-merge",
    ] {
        let job = &bootstrap["jobs"][job_id];
        assert!(
            job["needs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|need| need == "bootstrap-host")
        );
        let steps = job["steps"].as_array().unwrap();
        let download = steps
            .iter()
            .position(|step| {
                step["with"]["artifact-ids"] == "${{ needs.bootstrap-host.outputs.artifact-id }}"
            })
            .unwrap();
        assert_eq!(steps[download]["with"]["path"], "bootstrap-host");
        let install = steps
            .iter()
            .position(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.contains("install -D -m 755 bootstrap-host/securefix-bootstrap")
                })
            })
            .unwrap();
        let invoke = steps
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.starts_with("\"$RUNNER_TEMP/securefix-bootstrap\" "))
            })
            .unwrap();
        assert!(download < install && install < invoke, "{job_id}");
    }
    for path in [
        "scripts/control-bootstrap.py",
        "scripts/test_control_bootstrap.py",
        "scripts/test_control_bootstrap_boundaries.py",
    ] {
        assert!(
            !std::path::Path::new(path).exists(),
            "bootstrap logic must stay in Rust: {path}"
        );
    }
    assert_eq!(
        bootstrap["concurrency"]["group"],
        "securefix-control-bootstrap"
    );
    let build = &bootstrap["jobs"]["build-candidate"];
    assert_eq!(
        build["permissions"],
        serde_json::json!({"contents":"read", "id-token":"write", "attestations":"write"})
    );
    assert_eq!(build["needs"], "baseline");
    assert!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| { step["uses"] == "./.github/actions/setup-cli" })
    );
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    let build_download = "${{ needs.build-candidate.outputs.artifact-id }}";
    for job_id in ["validate-proposal", "propose"] {
        assert!(
            bootstrap["jobs"][job_id]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["with"]["artifact-ids"] == build_download),
            "{job_id} must consume the immutable candidate artifact ID"
        );
    }
    assert!(
        bootstrap["jobs"]["propose"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["with"]["artifact-ids"]
                == "${{ needs.validate-proposal.outputs.artifact-id }}")
    );

    for job_id in ["propose", "merge", "repair-propose", "repair-merge"] {
        let job = &bootstrap["jobs"][job_id];
        assert_eq!(job["environment"], "main", "{job_id}");
        assert_eq!(job["concurrency"]["group"], "securefix-control", "{job_id}");
        assert_eq!(job["concurrency"]["queue"], "max", "{job_id}");
        assert_eq!(job["concurrency"]["cancel-in-progress"], false, "{job_id}");
    }
    for job_id in ["propose", "merge", "repair-propose", "repair-merge"] {
        let job = &bootstrap["jobs"][job_id];
        for step in job["steps"].as_array().unwrap() {
            if step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
            {
                assert_eq!(step["with"]["repositories"], "securefix-server", "{job_id}");
                assert!(
                    step["with"].get("permission-administration").is_none(),
                    "{job_id}"
                );
            }
        }
    }
    let propose = &bootstrap["jobs"]["propose"]["steps"];
    let propose = propose.as_array().unwrap();
    let writer = propose.iter().find(|step| step["id"] == "writer").unwrap();
    assert_eq!(writer["with"]["permission-contents"], "write");
    assert_eq!(writer["with"]["permission-pull-requests"], "write");

    let text = serde_json::to_string(&bootstrap).unwrap();
    assert!(!text.contains("candidate-runtime/securefix"));
    assert!(!text.contains("/candidate/securefix"));
    for (job_id, job) in bootstrap["jobs"].as_object().unwrap() {
        for step in job["steps"].as_array().into_iter().flatten() {
            if let Some(run) = step["run"].as_str() {
                assert!(
                    !run.contains("cargo ") && !run.contains("rustup "),
                    "{job_id}"
                );
            }
        }
    }
}

#[test]
fn initial_bootstrap_scratch_uses_a_fixed_host_for_outputs_and_pinned_legacy_baseline() {
    let testing = workflow("testing-securefix-server.yml");
    assert_eq!(
        testing["on"]["workflow_dispatch"]["inputs"]["phase"]["options"],
        serde_json::json!(["prepare", "verify", "bootstrap", "provider"])
    );
    let legacy = &testing["jobs"]["bootstrap-legacy-runtime"];
    let legacy_if = legacy["if"].as_str().unwrap();
    for guard in [
        "inputs.phase == 'bootstrap'",
        "github.ref == 'refs/heads/main'",
        "github.actor_id == '4525500'",
        "github.run_attempt == 1",
    ] {
        assert!(legacy_if.contains(guard));
    }
    let legacy_script = legacy["steps"][0]["run"].as_str().unwrap();
    for pin in [
        "v0.2.20",
        "414653308",
        "646481902",
        "1f0f991e766e287b1ff55cf8cbda05982c0ddb90295f988081bf5b85a480d96c",
        "gh attestation verify",
    ] {
        assert!(
            legacy_script.contains(pin),
            "bootstrap legacy runtime lacks {pin}"
        );
    }
    let scratch = &testing["jobs"]["bootstrap-scratch"];
    assert!(
        scratch["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|need| need == "bootstrap-legacy-runtime")
    );
    let steps = scratch["steps"].as_array().unwrap();
    let context = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate current main and inactive descriptor before credentials"
        })
        .unwrap();
    let server_token = steps
        .iter()
        .position(|step| step["id"] == "server")
        .unwrap();
    let candidate_probe = steps
        .iter()
        .position(|step| {
            step["name"] == "Probe candidate control generation and CAS before approval"
        })
        .unwrap();
    assert!(context < server_token && server_token < candidate_probe);
    assert_eq!(scratch["environment"], "main");
    assert_eq!(
        steps[context]["run"],
        "\"$RUNNER_TEMP/securefix-bootstrap\" validate-legacy-context --source-sha \"$SOURCE_SHA\""
    );
    let server = steps.iter().find(|step| step["id"] == "server").unwrap();
    assert_eq!(server["with"]["repositories"], "testing-securefix-server");
    assert_eq!(server["with"]["permission-contents"], "write");
    let probe = steps[candidate_probe]["run"].as_str().unwrap();
    assert!(probe.contains("docker run --rm --read-only"));
    assert!(probe.contains("/candidate/securefix integration control-probe"));
    assert!(steps[candidate_probe]["env"].get("GITHUB_TOKEN").is_none());
    assert!(steps[candidate_probe]["env"]["SECUREFIX_SERVER_APP_TOKEN"].is_string());

    let prepare = steps
        .iter()
        .position(|step| step["name"] == "Prepare scratch fixtures with the candidate runtime")
        .unwrap();
    let upload_control_probe = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "control-probe"
        })
        .unwrap();
    let upload_fixture_heads = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "bootstrap-fixture-heads"
        })
        .unwrap();
    let publish_proof = steps
        .iter()
        .position(|step| step["name"] == "Publish pre-approval scratch identities")
        .unwrap();
    let verify = steps
        .iter()
        .position(|step| {
            step["name"] == "Execute candidate verification against isolated scratch fixtures"
        })
        .unwrap();
    let upload_final = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "scratch-fixtures"
        })
        .unwrap();
    let validate_outputs = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate scratch outputs with the fixed Rust bootstrap host"
        })
        .unwrap();
    assert!(verify < validate_outputs && validate_outputs < upload_final);
    let output_command = steps[validate_outputs]["run"].as_str().unwrap();
    assert!(
        output_command
            .starts_with("\"$RUNNER_TEMP/securefix-bootstrap\" validate-scratch-outputs ")
    );
    for argument in [
        "--source-sha \"$SOURCE_SHA\"",
        "--published-runtime-sha e8e2bc77d96a4e359417217f1d1c22f4e1ac4483",
        "--state-directory fixtures",
        "--probe-directory control-probe",
    ] {
        assert!(output_command.contains(argument));
    }
    assert!(!steps.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("securefix integration validate-outputs"))
    }));
    assert!(
        prepare < candidate_probe
            && candidate_probe < upload_control_probe
            && upload_control_probe < upload_fixture_heads
            && upload_fixture_heads < publish_proof
            && publish_proof < verify
            && verify < upload_final,
        "bootstrap proof identities must be available before verification waits for owner approval"
    );
    assert_eq!(
        steps[upload_control_probe]["with"]["path"],
        "control-probe/control-verification.json"
    );
    assert_eq!(
        steps[upload_fixture_heads]["with"]["path"],
        "fixtures/state.json"
    );
    assert_eq!(
        steps[upload_final]["with"]["path"],
        "fixtures/state.json\nfixtures/verification.json\n"
    );
    assert!(
        steps[publish_proof]["run"]
            .as_str()
            .unwrap()
            .contains("$GITHUB_STEP_SUMMARY")
    );
    assert_eq!(
        steps[publish_proof]["run"]
            .as_str()
            .unwrap()
            .matches("$GITHUB_STEP_SUMMARY")
            .count(),
        5
    );
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
}

#[test]
fn workflow_local_actions_have_a_prior_matching_checkout() {
    for (path, value) in workflows() {
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            for (index, step) in steps.iter().enumerate() {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                let Some(local) = uses.strip_prefix("./") else {
                    continue;
                };
                let action_root = if local.starts_with(".github/actions/") {
                    ""
                } else if let Some((root, _)) = local.split_once("/.github/actions/") {
                    root
                } else {
                    continue;
                };
                let has_matching_checkout = steps[..index].iter().any(|prior| {
                    if !prior["uses"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("actions/checkout@"))
                    {
                        return false;
                    }
                    let checkout_path = prior["with"]["path"].as_str().unwrap_or("");
                    checkout_path == action_root
                });
                assert!(
                    has_matching_checkout,
                    "{path}/{job_id}: local action {uses} needs an earlier checkout at its action root"
                );
            }
        }
    }

    let testing = workflow("testing-securefix-server.yml");
    let scratch = &testing["jobs"]["scratch"];
    let steps = scratch["steps"].as_array().unwrap();
    let probe = steps
        .iter()
        .position(|step| step["name"] == "Execute scratch control probe")
        .unwrap();
    let installer = steps
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "candidate-runtime/securefix"
        })
        .unwrap();
    assert!(installer < probe);
}

#[test]
fn control_probe_containers_mount_candidate_policy_beside_the_binary() {
    let testing = workflow("testing-securefix-server.yml");
    for (job_id, step_name) in [
        (
            "bootstrap-scratch",
            "Probe candidate control generation and CAS before approval",
        ),
        ("scratch", "Execute scratch control probe"),
    ] {
        let steps = testing["jobs"][job_id]["steps"].as_array().unwrap();
        let step = steps
            .iter()
            .find(|step| step["name"] == step_name)
            .unwrap_or_else(|| panic!("{job_id}: missing {step_name}"));
        let run = step["run"].as_str().unwrap();
        assert!(
            run.contains(
                "source=$RUNNER_TEMP/securefix-bin/securefix,target=/candidate/securefix,readonly"
            ),
            "{job_id}: candidate executable must be mounted read-only at /candidate/securefix"
        );
        assert!(
            run.contains("source=$RUNNER_TEMP/securefix-bin/policy.json,target=/candidate/policy.json,readonly"),
            "{job_id}: matching candidate policy must be mounted read-only beside the executable"
        );
        assert!(run.contains("/candidate/securefix integration control-probe"));
    }
}

#[test]
fn operational_workflows_have_no_securefix_action_dependency() {
    for (path, value) in workflows() {
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("csm-actions/securefix-action"),
            "{path}"
        );
    }
}

#[test]
fn provider_release_probe_is_a_frozen_no_publish_scratch_test() {
    let provider_workflow = workflow("testing-provider-release.yml");
    assert!(provider_workflow["on"].get("workflow_call").is_some());
    assert_eq!(provider_workflow["permissions"], serde_json::json!({}));
    assert_eq!(
        provider_workflow["env"]["PROBE_REPOSITORY"],
        "civitaspo/testing-securefix-server"
    );
    assert_eq!(
        provider_workflow["env"]["PROBE_PROJECT"],
        "terraform-provider-sigma"
    );
    assert_eq!(
        provider_workflow["env"]["PROBE_EXPECTED_GPG_FINGERPRINT"],
        "12D7B26BEB5394D7AA579FB300F0D373EFFA1DC6"
    );
    assert_eq!(
        provider_workflow["on"]["workflow_call"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": {"required": true},
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": {"required": true},
            "SECUREFIX_SERVER_PRIVATE_KEY": {"required": true}
        })
    );
    let dispatcher = workflow("testing-securefix-server.yml");
    assert_eq!(
        dispatcher["jobs"]["provider-release-probe"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": "${{ secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY }}",
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": "${{ secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE }}",
            "SECUREFIX_SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
        })
    );

    let guard = &provider_workflow["jobs"]["guard"];
    assert!(
        guard["if"]
            .as_str()
            .unwrap()
            .contains("github.actor_id == '4525500'")
    );
    assert!(
        guard["if"]
            .as_str()
            .unwrap()
            .contains("refs/heads/integration/native-")
    );
    assert!(
        guard["steps"][0]["run"]
            .as_str()
            .unwrap()
            .contains("[[ \"$current\" == \"$CANDIDATE_SHA\" ]]")
    );

    let build = &provider_workflow["jobs"]["build-provider"];
    let checkout = build["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        })
        .unwrap();
    assert_eq!(
        checkout["with"]["repository"],
        "civitaspo/terraform-provider-sigma"
    );
    assert_eq!(
        checkout["with"]["ref"],
        "50a03ed7723ff026c0c8f1d567c4ee3f82e39675"
    );
    let matrix = build["strategy"]["matrix"]["include"].as_array().unwrap();
    let targets = matrix
        .iter()
        .filter(|item| item["kind"] == "target")
        .map(|item| {
            format!(
                "{}:{}",
                item["os"].as_str().unwrap(),
                item["arch"].as_str().unwrap()
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let target_count = matrix
        .iter()
        .filter(|item| item["kind"] == "target")
        .count();
    let expected = crate::release::PROVIDER_TARGETS
        .iter()
        .map(|target| format!("{}:{}", target.os, target.arch))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        targets, expected,
        "matrix must build each supported provider target exactly once"
    );
    assert_eq!(target_count, crate::release::PROVIDER_TARGETS.len());
    assert_eq!(
        matrix
            .iter()
            .filter(|item| item["kind"] == "manifest")
            .count(),
        1
    );

    let compile = &provider_workflow["jobs"]["compile-harness"];
    assert!(compile["steps"].as_array().unwrap().iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("cargo +1.99.0 test --locked --bin securefix --no-run"))
    }));
    assert!(compile["steps"].as_array().unwrap().iter().all(|step| {
        !serde_json::to_string(step).unwrap().contains("secrets.")
            && !step["env"].to_string().contains("GPG_")
            && !step["env"].to_string().contains("APP_TOKEN")
    }));

    assert!(build["steps"].as_array().unwrap().iter().any(|step| {
        step["env"]["SECUREFIX_PROVIDER_PROBE_PHASE"]
            == "${{ matrix.kind == 'manifest' && 'build-manifest' || 'build-target' }}"
    }));
    let build_text = serde_json::to_string(build).unwrap();
    for forbidden in [
        "secrets.",
        "TERRAFORM_PROVIDER_GPG",
        "SECUREFIX_SERVER_PRIVATE_KEY",
        "SECUREFIX_SERVER_APP_TOKEN",
    ] {
        assert!(
            !build_text.contains(forbidden),
            "provider build exposes {forbidden}"
        );
    }
    let expected_phases = [
        "fresh-sign",
        "create-draft",
        "stage-draft",
        "recover-download",
        "recover-sign",
        "complete-draft",
        "verify-draft",
        "cleanup-draft",
    ];
    for phase in expected_phases {
        let found = provider_workflow["jobs"]
            .as_object()
            .unwrap()
            .iter()
            .any(|(_, job)| {
                job["steps"].as_array().into_iter().flatten().any(|step| {
                    step["env"]["SECUREFIX_PROVIDER_PROBE_PHASE"] == phase
                        && step["run"].as_str().is_some_and(|run| {
                            run.contains("release::tests::provider_no_publish_probe")
                        })
                })
            });
        assert!(found, "missing test-only probe phase {phase}");
    }
    let text = serde_json::to_string(&provider_workflow).unwrap();
    assert!(
        !text.contains("draft:false"),
        "probe must never publish its release"
    );
    assert!(!text.contains("gh release create") && !text.contains("gh release edit"));

    for job_id in [
        "create-draft",
        "stage-draft",
        "recover-download",
        "complete-draft",
        "verify-draft",
        "cleanup-draft",
    ] {
        let job_text = serde_json::to_string(&provider_workflow["jobs"][job_id]).unwrap();
        assert!(job_text.contains("SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(job_text.contains("testing-securefix-server"));
        assert!(!job_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job_text.contains("GPG_PASSPHRASE"));
        let token = provider_workflow["jobs"][job_id]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["id"] == "scratch-token")
            .unwrap();
        assert_eq!(token["with"]["repositories"], "testing-securefix-server");
        assert_eq!(token["with"]["permission-contents"], "write");
        for permission in [
            "permission-actions",
            "permission-issues",
            "permission-pull-requests",
            "permission-workflows",
        ] {
            assert!(
                token["with"].get(permission).is_none(),
                "{job_id} token should not request {permission}"
            );
        }
    }
    for job_id in ["fresh-sign", "recover-sign"] {
        let job_text = serde_json::to_string(&provider_workflow["jobs"][job_id]).unwrap();
        assert!(job_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job_text.contains("SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job_text.contains("SECUREFIX_SERVER_APP_TOKEN"));
    }
    let aggregate = &provider_workflow["jobs"]["assemble-provider"]["steps"];
    assert!(aggregate.as_array().unwrap().iter().any(|step| {
        step["with"]["pattern"] == "sigma-probe-${{ github.run_id }}-*"
            && step["with"]["merge-multiple"] == true
    }));
}

#[test]
fn candidate_execution_is_separate_from_secret_free_build_and_scoped_to_scratch() {
    let candidate = workflow("testing-securefix-server.yml");
    assert!(candidate["jobs"].get("trusted-runtime-main").is_none());
    let baseline_build = &candidate["jobs"]["baseline-build"];
    assert_eq!(
        baseline_build["permissions"],
        serde_json::json!({"contents":"read"})
    );
    assert!(
        !serde_json::to_string(baseline_build)
            .unwrap()
            .contains("secrets.")
    );
    assert!(
        baseline_build["if"]
            .as_str()
            .unwrap()
            .contains("integration/native-")
    );
    for job_id in ["build", "reuse", "scratch"] {
        let guard = candidate["jobs"][job_id]["if"].as_str().unwrap();
        assert!(guard.contains("github.actor_id == '4525500'"), "{job_id}");
        assert!(guard.contains("github.run_attempt == 1"), "{job_id}");
        assert!(guard.contains("refs/heads/main"), "{job_id}");
        assert!(guard.contains("integration/native-"), "{job_id}");
    }
    let baseline_steps = baseline_build["steps"].as_array().unwrap();
    assert!(
        baseline_build["if"]
            .as_str()
            .unwrap()
            .contains("refs/heads/main")
    );
    for job in ["reuse", "client-smoke", "scratch"] {
        assert_eq!(
            candidate["jobs"][job]["env"]["SECUREFIX_TEST_BASELINE_SHA"],
            "${{ needs.baseline-build.outputs.source-sha }}"
        );
    }
    assert!(
        baseline_steps[0]["run"]
            .as_str()
            .unwrap()
            .contains("commits/main")
    );
    let checkout = baseline_steps
        .iter()
        .find(|step| step["id"] == "checkout")
        .unwrap();
    assert_eq!(checkout["with"]["ref"], "${{ steps.resolve.outputs.sha }}");
    assert_eq!(checkout["with"]["path"], "baseline");
    assert_eq!(checkout["with"]["persist-credentials"], false);
    assert!(
        baseline_steps
            .iter()
            .any(|step| step["uses"] == "./baseline/.github/actions/setup-cli")
    );
    assert!(baseline_steps.iter().any(|step| {
        step["with"]["name"] == "baseline-runtime"
            && step["with"]["path"].as_str().is_some_and(|path| {
                path.lines().eq([
                    "baseline/target/release/securefix",
                    "baseline/target/release/policy.json",
                ])
            })
    }));
    let build = &candidate["jobs"]["build"];
    assert_eq!(build["permissions"], serde_json::json!({"contents":"read"}));
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    let scratch = &candidate["jobs"]["scratch"];
    let steps = scratch["steps"].as_array().unwrap();
    let trusted_fetch = steps
        .iter()
        .position(|step| step["name"] == "Validate fixture state with trusted runtime")
        .unwrap();
    let trusted_install = steps
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "trusted-runtime/securefix"
        })
        .unwrap();
    let candidate_install = steps
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "candidate-runtime/securefix"
        })
        .unwrap();
    let runtime_resolution = steps
        .iter()
        .position(|step| step["id"] == "runtime")
        .unwrap();
    let server_token = steps
        .iter()
        .position(|step| step["id"] == "server")
        .unwrap();
    let candidate_run = steps
        .iter()
        .position(|step| {
            step["name"] == "Execute candidate against the isolated scratch repository"
        })
        .unwrap();
    assert!(trusted_install < trusted_fetch && trusted_fetch < candidate_install);
    let producer_check = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate the defining workflow before minting credentials"
        })
        .unwrap();
    assert!(trusted_install < producer_check && producer_check < candidate_install);
    assert_eq!(
        steps[producer_check]["env"]["GITHUB_TOKEN"],
        "${{ github.token }}"
    );
    assert!(candidate_install < runtime_resolution && runtime_resolution < server_token);
    assert!(server_token < candidate_run);
    assert!(
        steps[trusted_fetch]["run"]
            .as_str()
            .unwrap()
            .starts_with("\"$RUNNER_TEMP/securefix-bin/securefix\" integration fetch-state ")
    );
    assert!(steps[trusted_fetch]["env"].get("GITHUB_TOKEN").is_some());
    assert_eq!(scratch["environment"], "main");
    assert!(steps[candidate_run]["env"].get("GITHUB_TOKEN").is_none());
    assert!(steps[candidate_run]["env"]["SECUREFIX_SERVER_APP_TOKEN"].is_string());
    assert!(steps[candidate_run]["env"]["SECUREFIX_CLIENT_APP_TOKEN"].is_string());
    let isolated_run = steps[candidate_run]["run"].as_str().unwrap();
    for guard in [
        "docker run --rm --read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "--pids-limit",
        "ubuntu@sha256:",
    ] {
        assert!(
            isolated_run.contains(guard),
            "missing candidate isolation: {guard}"
        );
    }
    for forbidden in [
        "docker.sock",
        "--privileged",
        "--pid=host",
        "--network=host",
        "-e GITHUB_TOKEN",
        "-e GITHUB_ENV",
        "-e GITHUB_OUTPUT",
        "target=/home",
        "target=/var/run",
    ] {
        assert!(
            !isolated_run.contains(forbidden),
            "unsafe candidate isolation: {forbidden}"
        );
    }
    let output_validation = steps
        .iter()
        .position(|step| step["id"] == "validate-outputs")
        .unwrap();
    let revalidate_runtime = steps
        .iter()
        .position(|step| step["id"] == "revalidate-runtime")
        .unwrap();
    assert!(candidate_run < revalidate_runtime && revalidate_runtime < output_validation);
    assert!(
        steps[revalidate_runtime]["run"]
            .as_str()
            .unwrap()
            .contains("--expected-tag")
    );
    assert_eq!(
        steps[output_validation]["env"]["GITHUB_TOKEN"],
        "${{ github.token }}"
    );
    assert!(steps[output_validation]["env"]["SECUREFIX_PUBLISHED_RUNTIME_TAG"].is_string());
    let fixture_upload = steps
        .iter()
        .position(|step| step["with"]["name"] == "scratch-fixtures")
        .unwrap();
    assert!(output_validation < fixture_upload);
    assert_eq!(
        steps[fixture_upload]["if"],
        "always() && steps.validate-outputs.outcome == 'success'"
    );
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|value| value.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
    let reuse = &candidate["jobs"]["reuse"]["steps"];
    let reuse = reuse.as_array().unwrap();
    let fetch = reuse.iter().position(|step| step["id"] == "state").unwrap();
    let trusted_installer = reuse
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "trusted-runtime/securefix"
        })
        .unwrap();
    let candidate_download = reuse
        .iter()
        .rposition(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/download-artifact@"))
        })
        .unwrap();
    assert!(trusted_installer < fetch && fetch < candidate_download);
    assert!(
        reuse[fetch]["run"]
            .as_str()
            .unwrap()
            .starts_with("\"$RUNNER_TEMP/securefix-bin/securefix\" integration fetch-state ")
    );
    assert_eq!(reuse[fetch]["env"]["GITHUB_TOKEN"], "${{ github.token }}");
    assert_eq!(reuse[fetch]["uses"], Value::Null);
    assert!(
        !serde_json::to_string(&reuse[fetch])
            .unwrap()
            .contains("candidate-runtime")
    );
    // The provider rehearsal has its own credential-boundary test; the native
    // candidate runner must still receive no provider signing credentials.
    let mut native_candidate = candidate.clone();
    native_candidate["jobs"]
        .as_object_mut()
        .unwrap()
        .remove("provider-release-probe");
    native_candidate["jobs"]
        .as_object_mut()
        .unwrap()
        .remove("bootstrap-legacy-runtime");
    native_candidate["jobs"]
        .as_object_mut()
        .unwrap()
        .remove("bootstrap-scratch");
    let text = serde_json::to_string(&native_candidate).unwrap();
    for forbidden in [
        "CIVITASPO_BOT_PR_APPROVE_TOKEN",
        "TERRAFORM_PROVIDER_GPG",
        "runtime publish",
        "gh release",
    ] {
        assert!(
            !text.contains(forbidden),
            "candidate runner contains {forbidden}"
        );
    }
}

#[test]
fn cli_jobs_install_verified_artifacts_on_path_before_invocation() {
    for (path, workflow) in workflows() {
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            let downloads_cli = path != ".github/workflows/control-bootstrap.yml"
                && steps.iter().any(|step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|u| u.starts_with("actions/download-artifact@"))
                        && step["with"]["artifact-ids"].is_string()
                });
            if path == ".github/workflows/testing-provider-release.yml" {
                continue;
            }
            let installer = steps.iter().position(|step| {
                step["uses"] == "$/.github/actions/install-cli"
                    || step["uses"] == "./.github/actions/install-cli"
            });
            if path == ".github/workflows/testing-release-pr.yml" && job_id == "execute" {
                let trusted_installer = steps
                    .iter()
                    .position(|step| {
                        step["uses"] == "./candidate-source/.github/actions/install-cli"
                            && step["with"]["binary"]
                                == "${{ github.workspace }}/trusted-runtime/securefix"
                    })
                    .unwrap();
                let candidate_installer = steps
                    .iter()
                    .position(|step| {
                        step["uses"] == "./candidate-source/.github/actions/install-cli"
                            && step["with"]["binary"]
                                == "${{ github.workspace }}/candidate/securefix"
                    })
                    .unwrap();
                let producer_check = steps
                    .iter()
                    .position(|step| {
                        step["name"]
                            == "Validate frozen producer before minting scratch credentials"
                    })
                    .unwrap();
                let app_token = steps
                    .iter()
                    .position(|step| step["id"] == "server")
                    .unwrap();
                let mise = steps
                    .iter()
                    .position(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|value| value.starts_with("jdx/mise-action@"))
                    })
                    .unwrap();
                let candidate_run = steps
                    .iter()
                    .position(|step| step["name"] == "Exercise managed release PR refresh")
                    .unwrap();
                let trusted_download = steps
                    .iter()
                    .position(|step| {
                        step["with"]["artifact-ids"]
                            == "${{ needs.trusted-runtime.outputs.artifact-id }}"
                    })
                    .unwrap();
                assert!(trusted_download < trusted_installer);
                assert!(trusted_installer < producer_check && producer_check < app_token);
                let prepare_check = steps
                    .iter()
                    .position(|step| step["name"] == "Validate exact prepare run for verify phase")
                    .unwrap();
                let artifact_lookup = steps
                    .iter()
                    .position(|step| step["id"] == "artifacts")
                    .unwrap();
                assert!(producer_check < prepare_check && prepare_check < artifact_lookup);
                for (index, step) in steps.iter().enumerate() {
                    if step["with"]["artifact-ids"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("${{ steps.artifacts.outputs."))
                    {
                        assert!(artifact_lookup < index && index < app_token);
                    }
                }
                assert!(
                    app_token < mise
                        && mise < candidate_installer
                        && candidate_installer < candidate_run
                );
                continue;
            }
            if downloads_cli {
                assert!(
                    installer.is_some(),
                    "{path}/{job_id}: downloaded CLI must use the installer"
                );
                let download = steps
                    .iter()
                    .position(|step| {
                        step["uses"].as_str().is_some_and(|u| {
                            u.starts_with("actions/download-artifact@")
                                && step["with"]["artifact-ids"].is_string()
                        })
                    })
                    .unwrap();
                assert!(
                    download < installer.unwrap(),
                    "{path}/{job_id}: install follows immutable artifact download"
                );
                let last_path_setup = steps.iter().rposition(|step| {
                    step["uses"].as_str().is_some_and(|uses| {
                        uses.starts_with("jdx/mise-action@")
                            || uses.starts_with("actions/setup-go@")
                            || uses.starts_with("actions/setup-node@")
                            || uses.starts_with("actions/setup-python@")
                            || uses.starts_with("actions/setup-java@")
                    })
                });
                if let Some(setup) = last_path_setup {
                    assert!(
                        setup < installer.unwrap(),
                        "{path}/{job_id}: install follows PATH-changing tool setup"
                    );
                }
            }
            for (index, step) in steps.iter().enumerate() {
                let Some(run) = step["run"].as_str() else {
                    continue;
                };
                assert!(
                    !run.contains("${{ github.event."),
                    "{path}/{job_id}: event data must enter through env or the event file"
                );
                let bounded_baseline_reads = path
                    == ".github/workflows/testing-securefix-server.yml"
                    && job_id == "baseline-build"
                    && run.contains("gh api")
                    && (run.contains("repo=civitaspo/securefix-server")
                        || run.contains(
                            "gh api repos/civitaspo/securefix-server/commits/main --jq .sha",
                        ))
                    && (run.contains("repos/$repo/commits/main")
                        || run.contains("repos/civitaspo/securefix-server/commits/main"))
                    && !run.contains("gh api -X")
                    && !run.contains("--method")
                    && !run.contains("gh release")
                    && !run.contains("jq -e")
                    && !run.contains("jq -r '.content'");
                let bounded_legacy_runtime_reads = path
                    == ".github/workflows/testing-securefix-server.yml"
                    && job_id == "bootstrap-legacy-runtime"
                    && run.contains("repos/$repo/releases/414653308")
                    && run.contains("assets[] | select(.id == 646481902)")
                    && run.contains("gh release download v0.2.20")
                    && run.contains("sha256sum --check")
                    && run.contains("gh attestation verify")
                    && !run.contains("gh api -X")
                    && !run.contains("--method")
                    && !run.contains("gh release upload")
                    && !run.contains("gh release create");
                let bounded_release_artifact_lookup = path
                    == ".github/workflows/testing-release-pr.yml"
                    && job_id == "execute"
                    && ((step["name"] == "Resolve immutable prepare artifacts"
                        && run.contains("actions/runs/$PREPARE_RUN_ID/artifacts?per_page=100")
                        && run.contains("total_count")
                        && run.contains("expired == false"))
                        || (step["name"] == "Validate exact prepare run for verify phase"
                            && run.contains("actions/runs/$PREPARE_RUN_ID")
                            && run.contains("head_sha == $sha")
                            && run.contains("conclusion == \"success\"")))
                    && !run.contains("gh api -X")
                    && !run.contains("--method");
                assert!(
                    !run.contains("python")
                        && !run.contains("ruby")
                        && !run.contains("node ")
                        && (!run.contains("jq ")
                            || bounded_baseline_reads
                            || bounded_legacy_runtime_reads
                            || bounded_release_artifact_lookup)
                        && !run.contains("curl "),
                    "{path}/{job_id}: operation decisions must be in Rust except bounded runtime bootstrap reads"
                );
                assert!(
                    !run.contains("chmod") || !run.contains("securefix"),
                    "{path}/{job_id}: CLI permissions belong in installer action"
                );
                let invokes_cli = run
                    .lines()
                    .any(|line| line.trim().starts_with("securefix "));
                if invokes_cli {
                    if let Some(installer) = installer {
                        assert!(
                            index > installer,
                            "{path}/{job_id}: CLI must run after installer"
                        );
                    }
                    if !run.contains("--help") && !run.contains("policy validate") {
                        assert!(
                            job["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || step["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || (path == ".github/workflows/testing-securefix-server.yml"
                                    && (step["env"]["CANDIDATE_SHA"].is_string()
                                        || job["env"]["CANDIDATE_SHA"].is_string()
                                        || (run.starts_with("securefix integration resolve-test-runtime --published-runtime-sha ")
                                            && step["env"]["PUBLISHED_RUNTIME_SHA"].is_string()
                                            && step["env"]["GITHUB_TOKEN"].is_string()))),
                            "{path}/{job_id}: runtime revision required"
                        );
                    }
                    if run.contains("request capture-") || run.contains("request dispatch") {
                        assert!(
                            job["env"]["GITHUB_TOKEN"].is_string()
                                || step["env"]["GITHUB_TOKEN"].is_string(),
                            "{path}/{job_id}: read token required"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn server_request_callers_pass_the_required_environment_secret_by_name() {
    for operation in ["approve", "merge"] {
        let caller = workflow(&format!("{operation}-request.yml"));
        assert_eq!(
            caller["jobs"]["request"]["secrets"],
            serde_json::json!({
                "SECUREFIX_CLIENT_PRIVATE_KEY": "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
            }),
            "environment-only secrets must be declared explicitly at call time"
        );
        let reusable = workflow(&format!("reusable-{operation}-request.yml"));
        assert_eq!(
            reusable["on"]["workflow_call"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"]["required"],
            true
        );
        let build = &reusable["jobs"]["build"];
        assert!(build.get("secrets").is_none());
        let capture = &reusable["jobs"]["capture"];
        assert_eq!(
            capture["environment"],
            "${{ github.repository == 'civitaspo/securefix-server' && 'main' || null }}"
        );
        let token = capture["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["id"] == "client-token")
            .unwrap();
        assert_eq!(
            token["with"]["private-key"],
            "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
        );
        assert_eq!(token["with"]["owner"], "civitaspo");
        assert_eq!(token["with"]["repositories"], "securefix-server");
        assert_eq!(token["with"]["permission-issues"], "write");
    }
}

#[test]
fn provider_probe_caller_passes_only_the_required_named_secrets() {
    let caller = workflow("testing-securefix-server.yml");
    assert_eq!(
        caller["jobs"]["provider-release-probe"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": "${{ secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY }}",
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": "${{ secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE }}",
            "SECUREFIX_SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
        })
    );

    let reusable = workflow("testing-provider-release.yml");
    for secret in [
        "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY",
        "TERRAFORM_PROVIDER_GPG_PASSPHRASE",
        "SECUREFIX_SERVER_PRIVATE_KEY",
    ] {
        assert!(
            reusable["on"]["workflow_call"]["secrets"][secret]["required"]
                .as_bool()
                .unwrap_or(false),
            "provider workflow must declare {secret} required"
        );
    }

    for job_id in ["fresh-sign", "recover-sign"] {
        let job = serde_json::to_string(&reusable["jobs"][job_id]).unwrap();
        assert!(job.contains("secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(job.contains("secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
        assert!(!job.contains("secrets.SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job.contains("SECUREFIX_SERVER_APP_TOKEN"));
    }
    for job_id in [
        "create-draft",
        "stage-draft",
        "complete-draft",
        "cleanup-draft",
    ] {
        let job = serde_json::to_string(&reusable["jobs"][job_id]).unwrap();
        assert!(job.contains("secrets.SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job.contains("TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
    }
}

#[test]
fn merge_workflow_prefilter_allows_whitespace_for_rust_command_validation() {
    let caller = workflow("merge-request.yml");
    let active_if = caller["jobs"]["request"]["if"].as_str().unwrap();
    let template = fs::read_to_string("src/distribution_templates/merge-request.yml")
        .unwrap()
        .replace(
            "@OWNER_ID@",
            &crate::config::trusted().unwrap().owner_id.to_string(),
        );
    for condition in [active_if, &template] {
        assert!(condition.contains("contains(github.event.comment.body, '/merge')"));
        assert!(condition.contains("github.event.issue.pull_request"));
        assert!(condition.contains("github.event.comment.user.id == 4525500"));
        assert!(condition.contains("github.run_attempt == 1"));
        assert!(!condition.contains("github.event.comment.body == '/merge'"));
    }
}

#[test]
fn approval_caller_prefilters_comments_without_disabling_automatic_approval() {
    let template = fs::read_to_string("src/distribution_templates/approve-request.yml")
        .unwrap()
        .replace("@OWNER_ID@", "4525500");
    let template: Value = serde_yaml::from_str(
        &template
            .replace("@SERVER_REPOSITORY@", "example/server")
            .replace("@SECUREFIX_RUNTIME_SHA@", &"a".repeat(40))
            .replace("@RUNTIME_VERSION@", "v0.2.33"),
    )
    .unwrap();
    let condition = template["jobs"]["approve"]["if"].as_str().unwrap();
    assert_eq!(
        condition,
        workflow("approve-request.yml")["jobs"]["request"]["if"]
    );
    assert!(condition.starts_with("github.event_name != 'issue_comment' ||"));
    assert!(condition.contains("github.event.issue.pull_request"));
    assert!(condition.contains("github.event.comment.user.id == 4525500"));
    assert!(condition.contains("contains(github.event.comment.body, '/approve')"));
}

#[test]
fn self_merge_consumes_its_label_before_apply_and_skips_stale_success_writes() {
    let merge = workflow("merge.yml");
    let authorize = &merge["jobs"]["authorize"];
    let job = &merge["jobs"]["apply"];
    assert_eq!(
        job["outputs"]["self_merged"],
        "${{ needs.authorize.outputs.repository == 'civitaspo/securefix-server' && steps.apply.outcome == 'success' }}"
    );
    let steps = job["steps"].as_array().unwrap();
    let position = |id: &str| {
        steps
            .iter()
            .position(|step| step["id"] == id)
            .unwrap_or_else(|| panic!("missing merge step {id}"))
    };
    let merge_token = position("merge-token");
    let token = position("self-cleanup-token");
    let preclean = position("self-cleanup");
    let apply = position("apply");
    let notify_token = position("notify-token");
    let notify = steps
        .iter()
        .position(|step| step["name"] == "Report the terminal result")
        .unwrap();
    assert!(merge_token < token && token < preclean && preclean < apply);
    assert_eq!(steps[merge_token]["if"], "needs.wait.result == 'success'");
    assert_eq!(
        steps[token]["if"],
        "needs.wait.result == 'success' && needs.authorize.outputs.repository == 'civitaspo/securefix-server'"
    );
    assert_eq!(steps[token]["with"]["repositories"], "securefix-server");
    assert_eq!(steps[token]["with"]["permission-issues"], "write");
    assert!(steps[token]["with"].get("permission-contents").is_none());
    assert!(
        steps[token]["with"]
            .get("permission-pull-requests")
            .is_none()
    );
    assert_eq!(steps[preclean]["run"], "securefix merge cleanup");
    assert_eq!(
        steps[preclean]["env"]["GITHUB_TOKEN"],
        "${{ steps.self-cleanup-token.outputs.token }}"
    );
    assert_eq!(
        steps[apply]["if"],
        "needs.wait.result == 'success' && (needs.authorize.outputs.repository != 'civitaspo/securefix-server' || steps.self-cleanup.outcome == 'success')"
    );
    assert_eq!(
        steps[notify_token]["if"],
        "always() && (needs.authorize.outputs.repository != 'civitaspo/securefix-server' || needs.wait.result != 'success' || steps.apply.outcome != 'success')"
    );
    assert_eq!(
        steps[notify]["if"],
        "always() && steps.notify-token.outcome == 'success'"
    );
    assert_eq!(steps[notify]["run"], "securefix merge notify");
    assert_eq!(
        steps[notify]["env"]["SECUREFIX_MERGE_SHA"],
        "${{ steps.apply.outputs.merge_sha }}"
    );
    assert_eq!(
        steps[notify]["env"]["SECUREFIX_MERGE_RESULT"],
        "${{ needs.wait.result == 'success' && steps.apply.outcome || 'wait-failed' }}"
    );
    assert!(apply < notify_token && notify_token < notify);
    assert_eq!(
        authorize["outputs"]["repository"],
        "${{ steps.validate.outputs.repository }}"
    );
    assert!(
        merge["jobs"]["cleanup"]["if"]
            .as_str()
            .unwrap()
            .contains("needs.apply.outputs.self_merged != 'true'")
    );
}

#[test]
fn native_caller_distribution_mints_only_target_scoped_write_credentials() {
    let distribution = workflow("distribute-runtime.yml");
    let job = &distribution["jobs"]["caller"];
    let steps = job["steps"].as_array().unwrap();
    let token = steps
        .iter()
        .find(|step| step["id"] == "server-write-token")
        .unwrap();
    assert_eq!(
        token["with"]["repositories"],
        "${{ steps.prepare.outputs.repository_name }}"
    );
    assert_eq!(token["with"]["permission-contents"], "write");
    assert_eq!(token["with"]["permission-pull-requests"], "write");
    assert!(steps.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("securefix distribute apply-caller"))
    }));
}

#[test]
fn provider_build_sign_and_publish_have_distinct_credentials() {
    let client: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/reusable-release-tag.yml").unwrap())
            .unwrap();
    let build = &client["jobs"]["build"];
    assert!(build.get("environment").is_none());
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    assert_eq!(
        build["permissions"],
        serde_json::json!({"contents":"read","pull-requests":"read"})
    );
    assert!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["with"]["ref"] == "${{ needs.resolve.outputs.merge_sha }}")
    );
    let server: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/release.yml").unwrap()).unwrap();
    let preflight_steps = server["jobs"]["preflight"]["steps"].as_array().unwrap();
    let preflight_token = preflight_steps
        .iter()
        .find(|step| step["id"] == "client-token")
        .unwrap();
    assert_eq!(
        preflight_token["with"]["repositories"],
        "${{ needs.resolve-request.outputs.repo_name }}"
    );
    assert_eq!(
        preflight_token["with"]["permission-contents"], "write",
        "draft-release inspection requires a push-scoped installation token"
    );
    for (permission, expected) in [
        ("permission-actions", "read"),
        ("permission-pull-requests", "read"),
    ] {
        assert_eq!(preflight_token["with"][permission], expected);
    }
    for permission in [
        "permission-administration",
        "permission-issues",
        "permission-workflows",
    ] {
        assert!(preflight_token["with"].get(permission).is_none());
    }
    let sign = &server["jobs"]["sign"];
    let sign_text = serde_json::to_string(sign).unwrap();
    assert!(sign_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
    for forbidden in [
        "SECUREFIX_SERVER_PRIVATE_KEY",
        "SECUREFIX_CLIENT_PRIVATE_KEY",
        "create-github-app-token",
        "actions/checkout",
        "setup-go",
        "mise-action",
        "goreleaser",
    ] {
        assert!(!sign_text.contains(forbidden), "signer exposes {forbidden}");
    }
    assert_eq!(
        sign["permissions"],
        serde_json::json!({"contents":"read","actions":"read"})
    );
    let publish = serde_json::to_string(&server["jobs"]["publish"]).unwrap();
    assert!(
        publish.contains("permission-contents") && publish.contains("SECUREFIX_SERVER_PRIVATE_KEY")
    );
    for forbidden in ["TERRAFORM_PROVIDER_GPG", "actions/checkout", "goreleaser"] {
        assert!(
            !publish.contains(forbidden),
            "publisher exposes {forbidden}"
        );
    }
}

#[test]
fn policy_feedback_token_can_comment_on_pull_requests_without_contents_write() {
    let policy = workflow("policy-check.yml");
    let steps = policy["jobs"]["process"]["steps"].as_array().unwrap();
    let token = |id| steps.iter().find(|step| step["id"] == id).unwrap();
    let write = &token("write")["with"];
    assert_eq!(write["permission-checks"], "write");
    assert_eq!(write["permission-issues"], "write");
    assert_eq!(write["permission-pull-requests"], "write");
    assert_eq!(
        write["repositories"],
        "${{ steps.locate.outputs.repository_name }}"
    );
    assert!(write.get("permission-contents").is_none());
    assert_eq!(token("read")["with"]["permission-pull-requests"], "read");
}

#[test]
fn integration_testing_documents_the_active_control_review_marker() {
    let docs = fs::read_to_string("docs/integration-testing.md").unwrap();
    assert!(docs.contains("<!-- securefix:control-review:<control-id> -->"));
    assert!(!docs.contains("securefix:v3:approval:"));

    for source in ["src/request.rs", "src/approval.rs"] {
        let source = fs::read_to_string(source).unwrap();
        assert!(
            source.contains("<!-- securefix:control-review:{} -->"),
            "the documented review marker must match the production marker template"
        );
    }
}

#[test]
fn operational_workflows_do_not_request_administration_or_settings_credentials() {
    for (path, value) in workflows() {
        if path.ends_with("/repo-settings.yml") {
            continue;
        }
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            for step in job["steps"].as_array().into_iter().flatten() {
                assert!(
                    step["with"].get("permission-administration").is_none(),
                    "{path} {job_id} requests Administration for an operational step"
                );
            }
        }
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN"),
            "{path} exposes the repository-settings administrator credential"
        );
    }
}

#[test]
fn reusable_callers_grant_the_permissions_requested_by_their_jobs() {
    let mut callers = workflows();
    let server = &crate::config::trusted()
        .unwrap()
        .deployment
        .server
        .repository;
    for (path, bytes) in
        crate::distribution::caller::rendered_files(&"a".repeat(40), "v0.2.22", "main", true)
            .unwrap()
    {
        let mut value: Value = serde_yaml::from_slice(&bytes).unwrap();
        for job in value["jobs"].as_object_mut().unwrap().values_mut() {
            let uses = job["uses"].as_str().unwrap();
            let local = uses
                .strip_prefix(&format!("{server}/"))
                .unwrap()
                .split('@')
                .next()
                .unwrap();
            job["uses"] = Value::String(format!("./{local}"));
        }
        callers.push((format!("generated:{path}"), value));
    }
    for (path, value) in callers {
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            let Some(callee) = job["uses"]
                .as_str()
                .and_then(|uses| uses.strip_prefix("./.github/workflows/"))
            else {
                continue;
            };
            let called = workflow(callee);
            for (nested_id, nested) in called["jobs"].as_object().unwrap() {
                for (permission, required) in nested["permissions"].as_object().unwrap() {
                    let granted = job["permissions"][permission].as_str().unwrap_or("none");
                    assert!(
                        match required.as_str().unwrap() {
                            "none" => true,
                            "read" => matches!(granted, "read" | "write"),
                            "write" => granted == "write",
                            other => panic!("unsupported permission {other}"),
                        },
                        "{path} {job_id} grants {permission}:{granted}, but {callee} {nested_id} needs {required}"
                    );
                }
            }
        }
    }
}
