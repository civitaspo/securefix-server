use anyhow::{Context, Result, ensure};
use serde_yaml::Value;

const CLIENT_ACTION: &str = "csm-actions/securefix-action";
const CLIENT_ACTION_VERSIONS: [&str; 2] = [
    "1b770a7af0ec5e04517295b4e14c4b451359d550",
    "11b2bfd2f4b7e1e02b63648fbe5d17e6273e515d",
];
const TOKEN_ACTION: &str =
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1";
const TOKEN_ACTION_COMMENT: &str = "# v3.2.0";

pub(super) const AUTOFIX_PATH: &str = ".github/workflows/wc-autofix.yml";
pub(super) const CALLER_PATH: &str = ".github/workflows/workflow_call_pr.yml";
pub(super) const PULL_REQUEST_PATH: &str = ".github/workflows/pull_request.yml";

pub(super) fn validate_previous_generation(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
    runtime_sha: &str,
) -> Result<()> {
    let Some(autofix) = files.get(AUTOFIX_PATH) else {
        ensure!(
            !files.contains_key(CALLER_PATH) && !files.contains_key(PULL_REQUEST_PATH),
            "automation branch has a partial Securefix client workflow generation"
        );
        return Ok(());
    };
    let pull_request = files
        .get(PULL_REQUEST_PATH)
        .context("automation branch client workflow generation is incomplete")?;
    let workflow_call = files
        .get(CALLER_PATH)
        .context("automation branch client workflow generation is incomplete")?;
    let migrated = migrate_autofix(autofix, runtime_sha)?;
    let autofix_is_native = migrated == *autofix;
    if let Some(native_sha) = native_runtime_sha(autofix)? {
        ensure!(
            native_sha == runtime_sha && autofix_is_native,
            "automation branch Securefix client pin does not match its generation"
        );
        let (migrated_pull_request, migrated_workflow_call) =
            migrate_call_chain(pull_request, workflow_call)?;
        ensure!(
            migrated_pull_request == *pull_request && migrated_workflow_call == *workflow_call,
            "automation branch has a partially migrated Securefix client workflow chain"
        );
        return Ok(());
    }
    ensure!(
        !autofix_is_native,
        "automation branch has an unrecognized Securefix client generation"
    );
    migrate_call_chain(pull_request, workflow_call)?;
    Ok(())
}

fn native_runtime_sha(source: &[u8]) -> Result<Option<String>> {
    let workflow: Value = serde_yaml::from_slice(source).context("unsupported autofix workflow")?;
    let steps = workflow["jobs"]["autofix"]["steps"]
        .as_sequence()
        .context("autofix steps are missing")?;
    let native = steps
        .iter()
        .filter_map(|step| step["uses"].as_str())
        .filter_map(|uses| uses.rsplit_once('@'))
        .find(|(name, _)| name.ends_with("/.github/actions/client"));
    Ok(native.map(|(_, sha)| sha.to_owned()))
}

pub(super) fn migrate_autofix(source: &[u8], runtime_sha: &str) -> Result<Vec<u8>> {
    crate::policy::validate_sha(runtime_sha)?;
    let source = std::str::from_utf8(source).context("autofix workflow is not UTF-8")?;
    let workflow: Value = serde_yaml::from_str(source).context("unsupported autofix workflow")?;
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("autofix jobs are missing")?;
    ensure!(
        jobs.len() == 1 && jobs.contains_key("autofix"),
        "unsupported autofix job layout"
    );
    let job = &workflow["jobs"]["autofix"];
    ensure!(job["runs-on"].is_string(), "autofix job has no runner");
    validate_autofix_permissions(&job["permissions"])?;
    let steps = job["steps"]
        .as_sequence()
        .context("autofix steps are missing")?;
    let (detect_index, detect_id) = find_detection_step(steps)?;
    let action_indices = steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| is_securefix_action(step).then_some(index))
        .collect::<Vec<_>>();
    ensure!(
        action_indices.len() == 1,
        "autofix must contain one supported Securefix step"
    );
    let action_index = action_indices[0];
    ensure!(
        action_index > detect_index,
        "Securefix step must follow change detection"
    );
    ensure!(
        steps
            .iter()
            .filter(|step| step["id"].as_str() == Some("securefix-client-token"))
            .count()
            == usize::from(is_native_step_pair(steps, action_index)?),
        "autofix has an unexpected Securefix token step"
    );
    let config = crate::config::trusted()?;
    let server = &config.deployment.server;
    validate_legacy_or_native_action(
        steps,
        action_index,
        &detect_id,
        &server.repository,
        &server.default_branch,
    )?;
    let runtime_version = crate::runtime::version_tag(runtime_sha)?;
    let action_condition = steps[action_index]["if"]
        .as_str()
        .context("Securefix step condition missing")?;
    let action_name = steps[action_index]["name"]
        .as_str()
        .context("Securefix step name missing")?;
    let commit_message = steps[action_index]["with"]["commit_message"]
        .as_str()
        .or_else(|| steps[action_index]["with"]["commit-message"].as_str())
        .context("Securefix commit message is missing")?;
    let replacement = render_native_steps(
        action_name,
        action_condition,
        commit_message,
        config,
        runtime_sha,
        &runtime_version,
    )?;

    let spans = step_spans(source)?;
    ensure!(
        spans.len() == steps.len(),
        "autofix has an unnamed or unsupported step source anchor"
    );
    let mut text = source.to_owned();
    if is_native_step_pair(steps, action_index)? {
        replace_span(
            &mut text,
            spans[action_index - 1].0,
            spans[action_index].1,
            &replacement,
        );
    } else {
        replace_span(
            &mut text,
            spans[action_index].0,
            spans[action_index].1,
            &replacement,
        );
    }
    text = add_capture_step(&text, &detect_id, detect_index)?;
    text = add_permission(&text, "autofix", &workflow, "autofix")?;
    Ok(text.into_bytes())
}

pub(super) fn migrate_call_chain(
    pull_request: &[u8],
    workflow_call: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let outer = add_permission_to_call(
        pull_request,
        "./.github/workflows/workflow_call_pr.yml",
        "pull request workflow",
    )?;
    let inner = add_permission_to_call(
        workflow_call,
        "./.github/workflows/wc-autofix.yml",
        "workflow-call PR workflow",
    )?;
    Ok((outer, inner))
}

pub(super) fn validate_call_file(source: &[u8], path: &str) -> Result<()> {
    let (reusable, description) = match path {
        PULL_REQUEST_PATH => (
            "./.github/workflows/workflow_call_pr.yml",
            "pull request workflow",
        ),
        CALLER_PATH => (
            "./.github/workflows/wc-autofix.yml",
            "workflow-call PR workflow",
        ),
        _ => anyhow::bail!("unsupported caller workflow path"),
    };
    validate_call_permission(source, reusable, description)
}

fn add_permission_to_call(source: &[u8], reusable: &str, description: &str) -> Result<Vec<u8>> {
    validate_call_permission(source, reusable, description)?;
    let text =
        std::str::from_utf8(source).with_context(|| format!("{description} is not UTF-8"))?;
    let workflow: Value =
        serde_yaml::from_str(text).with_context(|| format!("unsupported {description}"))?;
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("caller jobs are missing")?;
    let matches = jobs
        .iter()
        .filter_map(|(name, job)| (job["uses"].as_str() == Some(reusable)).then_some(name.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "{description} must call the expected local workflow exactly once"
    );
    let job_name = matches[0].context("caller job name is invalid")?;
    let job = &workflow["jobs"][job_name];
    validate_read_permissions(&job["permissions"])?;
    add_permission(text, job_name, &workflow, description).map(String::into_bytes)
}

fn validate_call_permission(source: &[u8], reusable: &str, description: &str) -> Result<()> {
    let text =
        std::str::from_utf8(source).with_context(|| format!("{description} is not UTF-8"))?;
    let workflow: Value =
        serde_yaml::from_str(text).with_context(|| format!("unsupported {description}"))?;
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("caller jobs are missing")?;
    let matches = jobs
        .iter()
        .filter_map(|(name, job)| (job["uses"].as_str() == Some(reusable)).then_some(name.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "{description} must call the expected local workflow exactly once"
    );
    let job_name = matches[0].context("caller job name is invalid")?;
    validate_read_permissions(&workflow["jobs"][job_name]["permissions"])
}

fn validate_autofix_permissions(value: &Value) -> Result<()> {
    let permissions = value
        .as_mapping()
        .context("autofix permissions are missing")?;
    ensure!(
        permissions.get("contents").and_then(Value::as_str) == Some("read")
            && permissions
                .keys()
                .all(|key| matches!(key.as_str(), Some("contents" | "attestations")))
            && permissions
                .get("attestations")
                .is_none_or(|value| value.as_str() == Some("read")),
        "autofix permissions are unsupported"
    );
    Ok(())
}

fn validate_read_permissions(value: &Value) -> Result<()> {
    let permissions = value
        .as_mapping()
        .context("reusable caller permissions are missing")?;
    ensure!(
        permissions.get("contents").and_then(Value::as_str) == Some("read")
            && permissions.keys().all(|key| matches!(
                key.as_str(),
                Some("contents" | "attestations" | "pull-requests")
            ))
            && permissions
                .values()
                .all(|value| value.as_str() == Some("read")),
        "reusable caller permissions are unsupported"
    );
    Ok(())
}

fn find_detection_step(steps: &[Value]) -> Result<(usize, String)> {
    let matches = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            matches!(
                step["name"].as_str(),
                Some("Detect workflow fixes" | "Detect automated fixes")
            ) && matches!(step["id"].as_str(), Some("workflow-fixes" | "fixes"))
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "autofix must have one supported file-change detector"
    );
    let (index, step) = matches[0];
    let id = step["id"]
        .as_str()
        .context("file-change detector id missing")?;
    let run = step["run"]
        .as_str()
        .context("file-change detector script missing")?;
    ensure!(
        run.contains("git diff --quiet")
            && run.contains("changed=false")
            && run.contains("changed=true"),
        "file-change detector script is unsupported"
    );
    Ok((index, id.to_owned()))
}

fn is_securefix_action(step: &Value) -> bool {
    step["uses"].as_str().is_some_and(|uses| {
        uses.starts_with("csm-actions/securefix-action@")
            || uses.contains("/.github/actions/client@")
    })
}

fn validate_legacy_or_native_action(
    steps: &[Value],
    index: usize,
    detect_id: &str,
    server_repository: &str,
    default_branch: &str,
) -> Result<()> {
    let step = &steps[index];
    ensure!(step["name"].is_string(), "Securefix step name is missing");
    let step_keys = step
        .as_mapping()
        .context("Securefix step must be a mapping")?;
    ensure!(
        step_keys.len() == 4,
        "Securefix step has unsupported fields"
    );
    let condition = step["if"]
        .as_str()
        .context("Securefix step condition missing")?;
    ensure!(
        condition.contains(&format!("steps.{detect_id}.outputs.changed == 'true'")),
        "Securefix step condition is unsupported"
    );
    let uses = step["uses"]
        .as_str()
        .context("Securefix action reference missing")?;
    if let Some((name, revision)) = uses.rsplit_once('@')
        && name == CLIENT_ACTION
    {
        ensure!(
            CLIENT_ACTION_VERSIONS.contains(&revision),
            "unsupported upstream Securefix action revision"
        );
        let with = step["with"]
            .as_mapping()
            .context("upstream Securefix inputs are missing")?;
        let configured_server_name = server_repository
            .split('/')
            .nth(1)
            .context("server repository name missing")?;
        ensure!(
            with.len() == 5
                && with.get("action").and_then(Value::as_str) == Some("client")
                && with.get("app_id").and_then(Value::as_str)
                    == Some("${{ env.SECUREFIX_CLIENT_APP_ID }}")
                && with.get("app_private_key").and_then(Value::as_str)
                    == Some("${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}")
                && with
                    .get("commit_message")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("ci: apply "))
                && with
                    .get("server_repository")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == "${{ env.SECUREFIX_SERVER_REPOSITORY }}"
                        || value == configured_server_name),
            "upstream Securefix inputs are unsupported"
        );
        return Ok(());
    }
    let (native_action, native_sha) = uses
        .rsplit_once('@')
        .context("native Securefix action pin is missing")?;
    ensure!(
        native_action == format!("{server_repository}/.github/actions/client")
            && crate::policy::validate_sha(native_sha).is_ok(),
        "unsupported Securefix action reference"
    );
    ensure!(
        is_native_step_pair(steps, index)?,
        "native Securefix token step is missing"
    );
    let native = step["with"]
        .as_mapping()
        .context("native Securefix action inputs are missing")?;
    ensure!(
        native.len() == 6
            && native.get("runtime-sha").and_then(Value::as_str) == Some(native_sha)
            && native.get("server-repository").and_then(Value::as_str) == Some(server_repository)
            && native.get("runtime-default-branch").and_then(Value::as_str) == Some(default_branch)
            && native.get("client-token").and_then(Value::as_str)
                == Some("${{ steps.securefix-client-token.outputs.token }}")
            && native.get("files").and_then(Value::as_str)
                == Some("${{ steps.securefix-files.outputs.files }}")
            && native
                .get("commit-message")
                .and_then(Value::as_str)
                .is_some_and(|value| value.starts_with("ci: apply ")),
        "native Securefix action inputs are unsupported"
    );
    Ok(())
}

fn is_native_step_pair(steps: &[Value], action_index: usize) -> Result<bool> {
    if action_index == 0 || steps[action_index - 1]["id"].as_str() != Some("securefix-client-token")
    {
        return Ok(false);
    }
    let token = &steps[action_index - 1];
    ensure!(
        token["name"].as_str() == Some("Create Securefix client token")
            && token["uses"].as_str() == Some(TOKEN_ACTION),
        "native Securefix token step is unsupported"
    );
    let with = token["with"]
        .as_mapping()
        .context("native Securefix token inputs are missing")?;
    let config = crate::config::trusted()?;
    let app_id = config.deployment.client_app_id.to_string();
    let mut repository_parts = config.deployment.server.repository.split('/');
    let owner = repository_parts.next().context("server owner missing")?;
    let repository = repository_parts.next().context("server name missing")?;
    ensure!(
        repository_parts.next().is_none(),
        "server repository is invalid"
    );
    ensure!(
        token.as_mapping().is_some_and(|mapping| mapping.len() == 5),
        "native Securefix token step has unsupported fields"
    );
    ensure!(
        with.len() == 5
            && with.get("app-id").and_then(Value::as_str) == Some(app_id.as_str())
            && with.get("private-key").and_then(Value::as_str)
                == Some("${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}")
            && with.get("owner").and_then(Value::as_str) == Some(owner)
            && with.get("repositories").and_then(Value::as_str) == Some(repository)
            && with.get("permission-issues").and_then(Value::as_str) == Some("write"),
        "native Securefix token inputs are unsupported"
    );
    Ok(true)
}

fn render_native_steps(
    action_name: &str,
    condition: &str,
    commit_message: &str,
    config: &crate::config::TrustedConfig,
    runtime_sha: &str,
    runtime_version: &str,
) -> Result<String> {
    let server_repository = &config.deployment.server.repository;
    let mut repository_parts = server_repository.split('/');
    let server_owner = repository_parts
        .next()
        .context("server repository owner missing")?;
    let server_name = repository_parts
        .next()
        .context("server repository name missing")?;
    ensure!(
        repository_parts.next().is_none(),
        "server repository is invalid"
    );
    let default_branch = &config.deployment.server.default_branch;
    let client_app_id = config.deployment.client_app_id;
    let condition = serde_json::to_string(condition)?;
    let server_repository_yaml = serde_json::to_string(server_repository)?;
    let action_ref = serde_json::to_string(&format!(
        "{server_repository}/.github/actions/client@{runtime_sha}"
    ))?;
    let server_owner = serde_json::to_string(server_owner)?;
    let server_name = serde_json::to_string(server_name)?;
    let default_branch = serde_json::to_string(default_branch)?;
    let client_app_id = serde_json::to_string(&client_app_id.to_string())?;
    let action_name = serde_json::to_string(action_name)?;
    let commit_message = serde_json::to_string(commit_message)?;
    Ok(format!(
        "      - name: Create Securefix client token\n        id: securefix-client-token\n        if: {condition}\n        uses: {TOKEN_ACTION} {TOKEN_ACTION_COMMENT}\n        with:\n          app-id: {client_app_id}\n          private-key: ${{{{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}}}\n          owner: {server_owner}\n          repositories: {server_name}\n          permission-issues: write\n\n      - name: {action_name}\n        if: {condition}\n        uses: {action_ref} # {runtime_version}\n        with:\n          runtime-sha: {runtime_sha}\n          server-repository: {server_repository_yaml}\n          runtime-default-branch: {default_branch}\n          client-token: ${{{{ steps.securefix-client-token.outputs.token }}}}\n          files: ${{{{ steps.securefix-files.outputs.files }}}}\n          commit-message: {commit_message}\n\n"
    ))
}

fn add_capture_step(source: &str, detection_id: &str, detection_index: usize) -> Result<String> {
    let workflow: Value = serde_yaml::from_str(source).context("unsupported autofix workflow")?;
    let steps = workflow["jobs"]["autofix"]["steps"]
        .as_sequence()
        .context("autofix steps are missing")?;
    if let Some(step) = steps
        .iter()
        .find(|step| step["id"].as_str() == Some("securefix-files"))
    {
        let expected_condition = format!("steps.{detection_id}.outputs.changed == 'true'");
        let expected_script = capture_script();
        ensure!(
            step["name"].as_str() == Some("Capture Securefix files")
                && step["if"].as_str() == Some(expected_condition.as_str())
                && step["run"].as_str() == Some(expected_script.as_str())
                && steps
                    .iter()
                    .position(|step| step["id"].as_str() == Some("securefix-files"))
                    .is_some_and(|index| index > detection_index)
                && step.as_mapping().is_some_and(|mapping| mapping.len() == 4),
            "existing Securefix file capture step is unsupported"
        );
        return Ok(source.to_owned());
    }
    let spans = step_spans(source)?;
    ensure!(
        spans.len() == steps.len(),
        "autofix has an unnamed or unsupported step source anchor"
    );
    let insertion = spans
        .get(detection_index)
        .context("file-change detector source missing")?
        .1;
    let capture = format!(
        "      - name: Capture Securefix files\n        id: securefix-files\n        if: steps.{detection_id}.outputs.changed == 'true'\n        run: |\n{}\n\n",
        capture_script()
            .lines()
            .map(|line| format!("          {line}\n"))
            .collect::<String>()
            .trim_end_matches('\n')
    );
    let mut result = source.to_owned();
    result.insert_str(insertion, &capture);
    Ok(result)
}

fn capture_script() -> String {
    "git ls-files --modified --deleted --others --exclude-standard --deduplicate -z > \"$RUNNER_TEMP/securefix-files\"\n\
mapfile -d '' -t files < \"$RUNNER_TEMP/securefix-files\"\n\
((${#files[@]} > 0)) || { echo 'changed files are missing' >&2; exit 1; }\n\
for file in \"${files[@]}\"; do\n\
  [[ \"$file\" != *$'\\n'* && \"$file\" != *$'\\r'* && \"$file\" != ' '* && \"$file\" != *' ' && \"$file\" != $'\\t'* && \"$file\" != *$'\\t' ]] || { echo 'changed file path cannot be represented' >&2; exit 1; }\n\
done\n\
delimiter=securefix-files\n\
while printf '%s\\n' \"${files[@]}\" | grep -Fqx -- \"$delimiter\"; do delimiter=\"${delimiter}x\"; done\n\
{ printf 'files<<%s\\n' \"$delimiter\"; printf '%s\\n' \"${files[@]}\"; printf '%s\\n' \"$delimiter\"; } >> \"$GITHUB_OUTPUT\"\n"
        .to_owned()
}

fn add_permission(
    source: &str,
    job_name: &str,
    workflow: &Value,
    description: &str,
) -> Result<String> {
    let permissions = workflow["jobs"][job_name]["permissions"]
        .as_mapping()
        .with_context(|| format!("{description} permissions are missing"))?;
    if permissions.get("attestations").and_then(Value::as_str) == Some("read") {
        return Ok(source.to_owned());
    }
    ensure!(
        permissions.contains_key("contents"),
        "{description} has no contents permission"
    );
    let job_line = format!("  {job_name}:");
    let lines = line_offsets(source);
    let job_matches = lines
        .iter()
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == job_line)
        .collect::<Vec<_>>();
    ensure!(
        job_matches.len() == 1,
        "{description} job source anchor is ambiguous"
    );
    let job_start = job_matches[0].0;
    let next_job = lines
        .iter()
        .find(|(offset, line)| {
            *offset > job_start
                && line.starts_with("  ")
                && !line.starts_with("    ")
                && line.trim().ends_with(':')
        })
        .map(|(offset, _)| *offset)
        .unwrap_or(source.len());
    let permission_lines = lines
        .iter()
        .filter(|(offset, line)| {
            *offset > job_start
                && *offset < next_job
                && line.trim_end_matches(['\r', '\n']) == "    permissions:"
        })
        .collect::<Vec<_>>();
    ensure!(
        permission_lines.len() == 1,
        "{description} permissions source anchor is ambiguous"
    );
    let permission_start = permission_lines[0].0;
    let contents_line = lines
        .iter()
        .filter(|(offset, line)| {
            *offset > permission_start
                && *offset < next_job
                && line.trim_end_matches(['\r', '\n']) == "      contents: read"
        })
        .collect::<Vec<_>>();
    ensure!(
        contents_line.len() == 1,
        "{description} contents permission source anchor is ambiguous"
    );
    let insert_at = contents_line[0].0 + contents_line[0].1.len();
    let newline = if contents_line[0].1.ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut result = source.to_owned();
    result.insert_str(insert_at, &format!("      attestations: read{newline}"));
    Ok(result)
}

fn step_spans(source: &str) -> Result<Vec<(usize, usize)>> {
    let spans = line_offsets(source)
        .into_iter()
        .filter(|(_, line)| line.starts_with("      - name:"))
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    ensure!(!spans.is_empty(), "autofix step source anchors are missing");
    Ok(spans
        .iter()
        .enumerate()
        .map(|(index, start)| {
            (
                *start,
                spans.get(index + 1).copied().unwrap_or(source.len()),
            )
        })
        .collect())
}

fn replace_span(source: &mut String, start: usize, end: usize, replacement: &str) {
    source.replace_range(start..end, replacement);
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

    fn legacy_autofix() -> String {
        "name: Autofix (workflow_call)\n\npermissions: {}\njobs:\n  autofix:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - name: Check out repository\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - name: Detect workflow fixes\n        id: workflow-fixes\n        run: |\n          git diff --quiet -- .github/workflows\n          echo changed=false\n          echo changed=true\n      - name: Request SecureFix commit\n        if: |\n          steps.workflow-fixes.outputs.changed == 'true' &&\n          env.SECUREFIX_CLIENT_APP_ID != ''\n        uses: csm-actions/securefix-action@1b770a7af0ec5e04517295b4e14c4b451359d550\n        with:\n          action: client\n          app_id: ${{ env.SECUREFIX_CLIENT_APP_ID }}\n          app_private_key: ${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}\n          commit_message: \"ci: apply workflow security fixes\"\n          server_repository: ${{ env.SECUREFIX_SERVER_REPOSITORY }}\n      - name: Require SecureFix configuration\n        if: steps.workflow-fixes.outputs.changed == 'true'\n        run: exit 1\n"
            .to_owned()
    }

    fn caller_chain() -> (Vec<u8>, Vec<u8>) {
        (
            b"jobs:\n  test:\n    uses: ./.github/workflows/workflow_call_pr.yml\n    permissions:\n      contents: read\n      pull-requests: read\n".to_vec(),
            b"jobs:\n  autofix:\n    uses: ./.github/workflows/wc-autofix.yml\n    permissions:\n      contents: read\n".to_vec(),
        )
    }

    #[test]
    fn client_workflow_migration_is_byte_preserving_and_idempotent() {
        let original = legacy_autofix();
        let migrated = migrate_autofix(original.as_bytes(), &"a".repeat(40)).unwrap();
        let migrated = String::from_utf8(migrated).unwrap();
        assert!(migrated.contains("attestations: read"));
        assert!(migrated.contains(
            "git ls-files --modified --deleted --others --exclude-standard --deduplicate"
        ));
        assert!(migrated.contains("files: ${{ steps.securefix-files.outputs.files }}"));
        assert!(migrated.contains("name: Require SecureFix configuration"));
        assert_eq!(
            migrate_autofix(migrated.as_bytes(), &"a".repeat(40)).unwrap(),
            migrated.as_bytes()
        );
    }

    #[test]
    fn client_workflow_chain_migration_adds_only_attestation_read() {
        let (pull_request, workflow_call) = caller_chain();
        let (pull_request, workflow_call) =
            migrate_call_chain(&pull_request, &workflow_call).unwrap();
        assert!(String::from_utf8_lossy(&pull_request).contains("attestations: read"));
        assert!(String::from_utf8_lossy(&pull_request).contains("pull-requests: read"));
        assert!(String::from_utf8_lossy(&workflow_call).contains("attestations: read"));
        assert_eq!(
            migrate_call_chain(&pull_request, &workflow_call).unwrap(),
            (pull_request, workflow_call)
        );
    }

    #[test]
    fn audited_detector_and_upstream_pin_variants_migrate() {
        let original = legacy_autofix()
            .replace("workflow-fixes", "fixes")
            .replace("Detect workflow fixes", "Detect automated fixes")
            .replace(
                "1b770a7af0ec5e04517295b4e14c4b451359d550",
                "11b2bfd2f4b7e1e02b63648fbe5d17e6273e515d",
            )
            .replace(
                "${{ env.SECUREFIX_SERVER_REPOSITORY }}",
                crate::config::trusted()
                    .unwrap()
                    .deployment
                    .server
                    .repository
                    .split('/')
                    .nth(1)
                    .unwrap(),
            );
        let migrated = migrate_autofix(original.as_bytes(), &"a".repeat(40)).unwrap();
        assert!(String::from_utf8_lossy(&migrated).contains("steps.fixes.outputs.changed"));
        assert!(
            !String::from_utf8_lossy(&migrated)
                .contains("11b2bfd2f4b7e1e02b63648fbe5d17e6273e515d")
        );
    }

    #[test]
    fn client_migration_rejects_unnamed_steps_and_custom_inputs_or_permissions() {
        let original = legacy_autofix();
        let unnamed = original.replace(
            "      - name: Require SecureFix configuration",
            "      - run: exit 0\n      - name: Require SecureFix configuration",
        );
        assert!(migrate_autofix(unnamed.as_bytes(), &"a".repeat(40)).is_err());

        let extra_input = original.replace(
            "          action: client",
            "          unsupported: true\n          action: client",
        );
        assert!(migrate_autofix(extra_input.as_bytes(), &"a".repeat(40)).is_err());

        let (pull_request, workflow_call) = caller_chain();
        let extra_permission = String::from_utf8(pull_request).unwrap().replace(
            "      contents: read",
            "      contents: read\n      issues: write",
        );
        assert!(migrate_call_chain(extra_permission.as_bytes(), &workflow_call).is_err());
    }

    #[test]
    fn native_client_generation_is_idempotent_at_its_pinned_sha() {
        let legacy = legacy_autofix();
        let first = migrate_autofix(legacy.as_bytes(), &"a".repeat(40)).unwrap();
        let second = migrate_autofix(&first, &"b".repeat(40)).unwrap();
        let second_text = String::from_utf8(second.clone()).unwrap();
        assert!(second_text.contains(&format!("@{}\" # v", "b".repeat(40))));
        assert_eq!(migrate_autofix(&second, &"b".repeat(40)).unwrap(), second);

        let (pull_request, workflow_call) = caller_chain();
        let (pull_request, workflow_call) =
            migrate_call_chain(&pull_request, &workflow_call).unwrap();
        let mut files = std::collections::BTreeMap::from([
            (AUTOFIX_PATH.to_owned(), first),
            (PULL_REQUEST_PATH.to_owned(), pull_request),
            (CALLER_PATH.to_owned(), workflow_call),
        ]);
        assert!(validate_previous_generation(&files, &"a".repeat(40)).is_ok());
        files.insert(AUTOFIX_PATH.to_owned(), second.clone());
        assert!(validate_previous_generation(&files, &"a".repeat(40)).is_err());
        files.insert(AUTOFIX_PATH.to_owned(), second);
        assert!(validate_previous_generation(&files, &"b".repeat(40)).is_ok());
    }
}
