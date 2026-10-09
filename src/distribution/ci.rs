use anyhow::{Context, Result, ensure};
use serde_yaml::Value;

pub(super) enum Mode {
    Push,
    MinimalCi,
}

pub(super) fn migrate(source: &[u8], mode: Mode, default_branch: &str) -> Result<Vec<u8>> {
    crate::config::validate_branch(default_branch)?;
    let source = std::str::from_utf8(source).context("caller CI workflow is not UTF-8")?;
    let workflow: Value = serde_yaml::from_str(source).context("unsupported caller CI workflow")?;
    match mode {
        Mode::Push => migrate_push(source, &workflow, default_branch),
        Mode::MinimalCi => migrate_minimal_ci(source, &workflow, default_branch),
    }
}

fn migrate_push(source: &str, workflow: &Value, default_branch: &str) -> Result<Vec<u8>> {
    ensure!(
        workflow["name"].as_str() == Some("Push"),
        "unsupported caller push workflow name"
    );
    validate_base_permissions(workflow)?;
    validate_push_triggers(workflow, default_branch)?;
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("push workflow jobs are missing")?;
    let checks = jobs
        .get(Value::String("checks".to_owned()))
        .context("push checks job is missing")?;
    validate_checks_job(checks)?;
    if let Some(status) = jobs.get(Value::String("status-check".to_owned())) {
        validate_status_job(status, &["checks"])?;
        ensure!(jobs.len() == 2, "push workflow has unexpected jobs");
        return Ok(source.as_bytes().to_vec());
    }
    ensure!(
        jobs.len() == 1,
        "push workflow has an ambiguous status-check job layout"
    );
    append_job(source, &push_status_job())
}

fn migrate_minimal_ci(source: &str, workflow: &Value, default_branch: &str) -> Result<Vec<u8>> {
    ensure!(
        workflow["name"].as_str() == Some("CI"),
        "unsupported minimal CI workflow name"
    );
    validate_base_permissions(workflow)?;
    let event_key = Value::Bool(true);
    let on = workflow
        .as_mapping()
        .and_then(|map| map.get("on").or_else(|| map.get(event_key)))
        .and_then(Value::as_mapping)
        .context("minimal CI triggers are missing")?;
    let pull_request = on
        .get(Value::String("pull_request".to_owned()))
        .context("minimal CI pull request trigger is missing")?;
    ensure!(
        pull_request.as_mapping().is_some_and(|map| map.len() == 1)
            && pull_request["types"].as_sequence().is_some_and(|types| {
                types
                    == &[
                        Value::String("opened".to_owned()),
                        Value::String("synchronize".to_owned()),
                        Value::String("reopened".to_owned()),
                    ]
            }),
        "minimal CI pull request trigger is unsupported"
    );
    ensure!(
        (on.len() == 1 && on.contains_key(Value::String("pull_request".to_owned())))
            || (on.len() == 3 && has_push_and_dispatch(workflow, default_branch)),
        "minimal CI triggers are unsupported"
    );
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("minimal CI jobs are missing")?;
    ensure!(jobs.len() == 2, "minimal CI has unexpected jobs");
    let ok = jobs
        .get(Value::String("ok".to_owned()))
        .context("minimal CI ok job is missing")?;
    validate_ok_job(ok)?;
    let status = jobs
        .get(Value::String("status-check".to_owned()))
        .context("minimal CI status-check job is missing")?;
    validate_minimal_status_job(status)?;

    let mut result = source.to_owned();
    if !is_minimal_status_canonical(status) {
        result = migrate_minimal_status_text(&result)?;
    }
    let updated: Value =
        serde_yaml::from_str(&result).context("migrated minimal CI workflow is invalid")?;
    if !has_push_and_dispatch(&updated, default_branch) {
        result = add_minimal_triggers(&result, &updated, default_branch)?;
    }
    Ok(result.into_bytes())
}

fn validate_base_permissions(workflow: &Value) -> Result<()> {
    ensure!(
        workflow["permissions"]
            .as_mapping()
            .is_some_and(|map| map.is_empty()),
        "caller workflow permissions are unsupported"
    );
    Ok(())
}

fn validate_push_triggers(workflow: &Value, default_branch: &str) -> Result<()> {
    let on = triggers(workflow)?;
    ensure!(
        on.len() == 2
            && on.contains_key(Value::String("push".to_owned()))
            && on.contains_key(Value::String("workflow_dispatch".to_owned()))
            && on["workflow_dispatch"].is_null(),
        "caller push workflow triggers are unsupported"
    );
    let push = &on["push"];
    let branches = &push["branches"];
    ensure!(
        push.as_mapping().is_some_and(|map| map.len() == 1)
            && branches.as_sequence().is_some_and(|values| {
                values.len() == 1 && values[0].as_str() == Some(default_branch)
            }),
        "caller push branch trigger is unsupported"
    );
    Ok(())
}

fn validate_checks_job(job: &Value) -> Result<()> {
    ensure!(
        job.as_mapping().is_some_and(|map| {
            map.len() == 2
                && map.contains_key(Value::String("uses".to_owned()))
                && map.contains_key(Value::String("permissions".to_owned()))
        }) && job["uses"].as_str() == Some("./.github/workflows/workflow_call_push.yml")
            && job["permissions"].as_mapping().is_some_and(|map| {
                map.len() == 1
                    && map.get(Value::String("contents".to_owned()))
                        == Some(&Value::String("read".to_owned()))
            }),
        "caller checks job is unsupported"
    );
    Ok(())
}

fn validate_status_job(job: &Value, required_needs: &[&str]) -> Result<()> {
    let needs = job["needs"]
        .as_sequence()
        .context("status-check dependencies are missing")?;
    let expected_needs = required_needs
        .iter()
        .map(|need| Value::String((*need).to_owned()))
        .collect::<Vec<_>>();
    ensure!(
        needs == &expected_needs
            && job.as_mapping().is_some_and(|map| map.len() == 7)
            && job["name"].as_str() == Some("status-check")
            && job["runs-on"].is_string()
            && job["if"].as_str() == Some("always()")
            && job["timeout-minutes"].as_u64() == Some(5)
            && job["permissions"]
                .as_mapping()
                .is_some_and(|map| map.is_empty())
            && job["steps"].as_sequence().is_some_and(|steps| {
                steps.len() == 1 && validate_status_step(&steps[0], required_needs[0])
            }),
        "caller status-check job is unsupported"
    );
    Ok(())
}

fn validate_ok_job(job: &Value) -> Result<()> {
    ensure!(
        job.as_mapping().is_some_and(|map| map.len() == 4)
            && job["runs-on"].as_str().is_some()
            && job["timeout-minutes"].as_u64() == Some(5)
            && job["permissions"]
                .as_mapping()
                .is_some_and(|map| map.is_empty())
            && job["steps"].as_sequence().is_some_and(|steps| {
                steps.len() == 1 && steps[0]["run"].as_str() == Some("exit 0")
            }),
        "minimal CI ok job is unsupported"
    );
    Ok(())
}

fn validate_status_step(step: &Value, needed_job: &str) -> bool {
    let expected_result = format!("${{{{ needs.{needed_job}.result }}}}");
    step.as_mapping().is_some_and(|map| map.len() == 3)
        && step["name"].as_str() == Some("Require successful checks")
        && step["env"].as_mapping().is_some_and(|env| {
            env.len() == 1 && env["JOB_RESULT"].as_str() == Some(expected_result.as_str())
        })
        && step["run"].as_str() == Some("test \"$JOB_RESULT\" = success")
}

fn validate_minimal_status_job(job: &Value) -> Result<()> {
    ensure!(
        job.as_mapping().is_some_and(|map| map.len() == 6)
            && job["needs"]
                .as_sequence()
                .is_some_and(|needs| { needs.len() == 1 && needs[0].as_str() == Some("ok") })
            && job["runs-on"].as_str().is_some()
            && job["timeout-minutes"].as_u64() == Some(5)
            && job["permissions"]
                .as_mapping()
                .is_some_and(|map| map.is_empty())
            && job["steps"]
                .as_sequence()
                .is_some_and(|steps| { steps.len() == 1 }),
        "minimal CI status-check job is unsupported"
    );
    let condition = job["if"]
        .as_str()
        .context("minimal status-check condition is missing")?;
    ensure!(
        condition == MINIMAL_OLD_CONDITION || condition == "always()",
        "minimal status-check condition is unsupported"
    );
    let step = &job["steps"][0];
    if condition == MINIMAL_OLD_CONDITION {
        ensure!(
            step.as_mapping().is_some_and(|map| map.len() == 1)
                && step["run"].as_str() == Some("exit 1"),
            "legacy minimal status-check step is unsupported"
        );
    } else {
        ensure!(
            validate_status_step(step, "ok"),
            "canonical minimal status-check step is unsupported"
        );
    }
    Ok(())
}

const MINIMAL_OLD_CONDITION: &str =
    "always() && (contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled'))";

fn is_minimal_status_canonical(job: &Value) -> bool {
    job["if"].as_str() == Some("always()")
        && job["steps"]
            .as_sequence()
            .is_some_and(|steps| steps.len() == 1 && validate_status_step(&steps[0], "ok"))
}

fn triggers(workflow: &Value) -> Result<&serde_yaml::Mapping> {
    let event_key = Value::Bool(true);
    workflow
        .as_mapping()
        .and_then(|map| map.get("on").or_else(|| map.get(event_key)))
        .and_then(Value::as_mapping)
        .context("caller workflow triggers are missing")
}

fn has_push_and_dispatch(workflow: &Value, default_branch: &str) -> bool {
    let Ok(on) = triggers(workflow) else {
        return false;
    };
    on.len() == 3
        && on.contains_key(Value::String("pull_request".to_owned()))
        && on.contains_key(Value::String("workflow_dispatch".to_owned()))
        && on["workflow_dispatch"].is_null()
        && on["push"].as_mapping().is_some_and(|map| map.len() == 1)
        && on["push"]["branches"]
            .as_sequence()
            .is_some_and(|branches| {
                branches.len() == 1 && branches[0].as_str() == Some(default_branch)
            })
}

fn add_minimal_triggers(source: &str, workflow: &Value, default_branch: &str) -> Result<String> {
    let on = triggers(workflow)?;
    ensure!(
        on.len() == 1 && on.contains_key(Value::String("pull_request".to_owned())),
        "minimal CI triggers are ambiguous"
    );
    let lines = line_offsets(source);
    let permissions = lines
        .iter()
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == "permissions: {}")
        .collect::<Vec<_>>();
    ensure!(
        permissions.len() == 1,
        "minimal CI trigger source anchor is ambiguous"
    );
    let insertion = permissions[0].0;
    let branch = serde_json::to_string(default_branch)?;
    let addition = format!("  push:\n    branches:\n      - {branch}\n  workflow_dispatch:\n\n");
    let mut result = source.to_owned();
    result.insert_str(insertion, &addition);
    Ok(result)
}

fn migrate_minimal_status_text(source: &str) -> Result<String> {
    let lines = line_offsets(source);
    let job_headers = lines
        .iter()
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == "  status-check:")
        .collect::<Vec<_>>();
    ensure!(
        job_headers.len() == 1,
        "minimal status-check source anchor is ambiguous"
    );
    let start = job_headers[0].0;
    let end = lines
        .iter()
        .find(|(offset, line)| {
            *offset > start
                && line.starts_with("  ")
                && !line.starts_with("    ")
                && line.trim().ends_with(':')
        })
        .map(|(offset, _)| *offset)
        .unwrap_or(source.len());
    let block = &source[start..end];
    let old_if = format!("    if: {MINIMAL_OLD_CONDITION}");
    let canonical_if = "    if: always()";
    ensure!(
        block.matches(&old_if).count() == 1 || block.matches(canonical_if).count() == 1,
        "minimal status-check condition anchor is unsupported"
    );
    let old_run = "      - run: exit 1";
    let new_step = "      - name: Require successful checks\n        env:\n          JOB_RESULT: ${{ needs.ok.result }}\n        run: test \"$JOB_RESULT\" = success";
    ensure!(
        block.matches(old_run).count() == 1,
        "minimal status-check step anchor is unsupported"
    );
    let mut changed = block.replace(&old_if, canonical_if);
    changed = changed.replace(old_run, new_step);
    ensure!(
        changed != block,
        "minimal status-check migration made no change"
    );
    Ok(source.replacen(block, &changed, 1))
}

fn push_status_job() -> String {
    "  status-check:\n    name: status-check\n    runs-on: ubuntu-latest\n    if: always()\n    needs:\n      - checks\n    timeout-minutes: 5\n    permissions: {}\n    steps:\n      - name: Require successful checks\n        env:\n          JOB_RESULT: ${{ needs.checks.result }}\n        run: test \"$JOB_RESULT\" = success\n".to_owned()
}

fn append_job(source: &str, block: &str) -> Result<Vec<u8>> {
    let separator = if source.ends_with("\n\n") {
        ""
    } else if source.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let mut result = source.to_owned();
    result.push_str(separator);
    result.push_str(block);
    Ok(result.into_bytes())
}

fn line_offsets(source: &str) -> Vec<(usize, &str)> {
    let mut offsets = Vec::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        offsets.push((offset, line));
        offset += line.len();
    }
    offsets
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUSH: &str = "# keep this comment\nname: Push\n\non:\n  push:\n    branches:\n      - main\n  workflow_dispatch:\n\npermissions: {}\n\njobs:\n  checks:\n    uses: ./.github/workflows/workflow_call_push.yml\n    permissions:\n      contents: read\n";

    const MINIMAL_CI: &str = "# keep this comment\nname: CI\n\non:\n  pull_request:\n    types:\n      - opened\n      - synchronize\n      - reopened\n\npermissions: {}\n\ndefaults:\n  run:\n    shell: bash -euo pipefail {0}\n\njobs:\n  ok:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    permissions: {}\n    steps:\n      - run: exit 0\n\n  status-check:\n    runs-on: ubuntu-latest\n    if: always() && (contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled'))\n    timeout-minutes: 5\n    permissions: {}\n    needs:\n      - ok\n    steps:\n      - run: exit 1\n";

    #[test]
    fn push_workflow_gets_successful_always_run_aggregator() {
        let migrated = migrate(PUSH.as_bytes(), Mode::Push, "main").unwrap();
        let text = std::str::from_utf8(&migrated).unwrap();
        assert!(text.starts_with("# keep this comment\n"));
        assert!(text.contains("  status-check:\n    name: status-check\n"));
        assert!(text.contains("    if: always()\n    needs:\n      - checks\n"));
        assert!(text.contains("JOB_RESULT: ${{ needs.checks.result }}"));
        assert!(text.contains("run: test \"$JOB_RESULT\" = success"));
        assert_eq!(migrate(&migrated, Mode::Push, "main").unwrap(), migrated);
    }

    #[test]
    fn minimal_ci_adds_default_push_and_successful_status_check() {
        let migrated = migrate(MINIMAL_CI.as_bytes(), Mode::MinimalCi, "main").unwrap();
        let text = std::str::from_utf8(&migrated).unwrap();
        assert!(text.starts_with("# keep this comment\n"));
        assert!(text.contains("  push:\n    branches:\n      - \"main\"\n  workflow_dispatch:\n"));
        assert!(text.contains("    if: always()\n"));
        assert!(text.contains(
            "      - name: Require successful checks\n        env:\n          JOB_RESULT: ${{ needs.ok.result }}\n        run: test \"$JOB_RESULT\" = success"
        ));
        assert_eq!(
            migrate(&migrated, Mode::MinimalCi, "main").unwrap(),
            migrated
        );
    }

    #[test]
    fn unknown_push_jobs_and_minimal_status_shapes_fail_closed() {
        let extra_job = PUSH.replace(
            "  checks:\n",
            "  custom:\n    runs-on: ubuntu-latest\n    steps:\n      - run: exit 0\n  checks:\n",
        );
        assert!(migrate(extra_job.as_bytes(), Mode::Push, "main").is_err());
        let changed_run = MINIMAL_CI.replace("      - run: exit 1", "      - run: echo custom");
        assert!(migrate(changed_run.as_bytes(), Mode::MinimalCi, "main").is_err());
    }
}
