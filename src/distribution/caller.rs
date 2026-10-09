use super::{CallerMigration, UPDATE_BRANCH, caller_names, validate_branch};
use crate::{
    api::{ApiError, GitHub},
    policy::{Capability, Policy, validate_sha},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

const APPROVE: &str = include_str!("../distribution_templates/approve-request.yml");
const MERGE: &str = include_str!("../distribution_templates/merge-request.yml");
const POLICY_CHECK: &str = include_str!("../distribution_templates/policy-check.yml");
const RELEASE_SYNC: &str = include_str!("../distribution_templates/release-pr-sync.yml");
const RELEASE_PR: &str = include_str!("../distribution_templates/release-pr.yml");
const RELEASE_TAG: &str = include_str!("../distribution_templates/release-tag.yml");

pub(super) fn prepare_caller(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    source_sha: &str,
) -> Result<CallerMigration> {
    let allowed = caller_names(policy)?;
    ensure!(
        allowed.iter().any(|caller| caller == repository),
        "caller is not in the fixed policy registry"
    );
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["full_name"] == repository
            && repo["owner"]["id"] == policy.owner_id
            && repo["owner"]["id"].as_u64().is_some_and(|id| id > 0),
        "caller owner mismatch"
    );
    let default_branch = repo["default_branch"]
        .as_str()
        .context("caller default branch missing")?;
    validate_branch(default_branch)?;
    ensure!(
        default_branch != UPDATE_BRANCH,
        "runtime update branch cannot be the caller default branch"
    );
    let base: Value = api.get(&format!("/repos/{repository}/commits/{default_branch}"))?;
    let base_sha = base["sha"]
        .as_str()
        .context("caller default branch SHA missing")?;
    validate_sha(base_sha)?;
    let release_client = policy
        .repository(repository)?
        .capabilities
        .contains(&Capability::Release);
    let files = rendered_files(source_sha, default_branch, release_client)?;
    let mut default_current = true;
    for (path, expected) in &files {
        match optional_content(api, repository, path, base_sha)? {
            Some(current) => {
                validate_existing(path, &current, default_branch)?;
                default_current &= current == *expected;
            }
            None => {
                default_current = false;
                ensure!(
                    path == ".github/workflows/policy-check.yml",
                    "required managed caller workflow is missing"
                );
            }
        }
    }
    Ok(CallerMigration {
        repository: repository.to_owned(),
        default_branch: default_branch.to_owned(),
        source_sha: source_sha.to_owned(),
        files,
        default_current,
    })
}

pub(crate) fn rendered_files(
    source_sha: &str,
    default_branch: &str,
    releases: bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    validate_sha(source_sha)?;
    validate_branch(default_branch)?;
    let branch = serde_json::to_string(default_branch)?;
    let templates = [
        (".github/workflows/approve-request.yml", APPROVE),
        (".github/workflows/merge-request.yml", MERGE),
        (".github/workflows/policy-check.yml", POLICY_CHECK),
    ];
    let mut files = BTreeMap::new();
    for (path, template) in templates {
        files.insert(
            path.to_owned(),
            render(template, source_sha, &branch)?.into_bytes(),
        );
    }
    if releases {
        for (path, template) in [
            (".github/workflows/release-pr-sync.yml", RELEASE_SYNC),
            (".github/workflows/release-pr.yml", RELEASE_PR),
            (".github/workflows/release-tag.yml", RELEASE_TAG),
        ] {
            files.insert(
                path.to_owned(),
                render(template, source_sha, &branch)?.into_bytes(),
            );
        }
    }
    Ok(files)
}

fn render(template: &str, source_sha: &str, branch: &str) -> Result<String> {
    let rendered = template
        .replace("@SECUREFIX_RUNTIME_SHA@", source_sha)
        .replace("@DEFAULT_BRANCH@", branch);
    ensure!(
        !rendered.contains("@SECUREFIX_RUNTIME_SHA@") && !rendered.contains("@DEFAULT_BRANCH@"),
        "template contains an unresolved placeholder"
    );
    Ok(rendered)
}

pub(super) fn write_migration(directory: &Path, migration: &CallerMigration) -> Result<()> {
    fs::create_dir_all(directory)?;
    for (relative, contents) in &migration.files {
        let path = Path::new(relative);
        ensure!(
            path.components().count() == 3
                && path.starts_with(".github/workflows")
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".yml")),
            "invalid migration path"
        );
        let output_path = directory.join(path);
        fs::create_dir_all(output_path.parent().context("migration parent missing")?)?;
        fs::write(output_path, contents)?;
    }
    Ok(())
}

pub(super) fn validate_migration_files(
    directory: &Path,
    migration: &CallerMigration,
) -> Result<()> {
    for (relative, expected) in &migration.files {
        let path = Path::new(relative);
        ensure!(
            path.components().count() == 3
                && path.starts_with(".github/workflows")
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".yml")),
            "invalid migration path"
        );
        let mut current = directory.to_path_buf();
        for (index, component) in path.components().enumerate() {
            current.push(component.as_os_str());
            let metadata = fs::symlink_metadata(&current)
                .with_context(|| format!("missing prepared migration file {relative}"))?;
            ensure!(
                !metadata.file_type().is_symlink()
                    && (index == path.components().count() - 1 || metadata.is_dir())
                    && (index != path.components().count() - 1 || metadata.is_file()),
                "prepared migration path is not a regular file: {relative}"
            );
        }
        ensure!(
            fs::read(directory.join(path))? == *expected,
            "prepared migration content does not match the reviewed template: {relative}"
        );
    }
    Ok(())
}

pub(super) fn validate_existing(path: &str, contents: &[u8], default_branch: &str) -> Result<()> {
    let value: serde_yaml::Value = serde_yaml::from_slice(contents)
        .with_context(|| format!("unsupported existing workflow {path}"))?;
    let workflow_name = value["name"].as_str().context("workflow name missing")?;
    let expected_name = match path {
        ".github/workflows/approve-request.yml" => "Approve Request",
        ".github/workflows/merge-request.yml" => "Merge Request",
        ".github/workflows/policy-check.yml" => "Policy Check",
        ".github/workflows/release-pr-sync.yml" => "Release PR Sync",
        ".github/workflows/release-pr.yml" => "Release PR",
        ".github/workflows/release-tag.yml" => "Release Tag",
        _ => anyhow::bail!("unexpected managed workflow path"),
    };
    ensure!(
        workflow_name == expected_name,
        "managed workflow name changed: {path}"
    );
    for key in value
        .as_mapping()
        .context("workflow object missing")?
        .keys()
    {
        let key = key
            .as_str()
            .or_else(|| (*key == serde_yaml::Value::Bool(true)).then_some("on"))
            .context("workflow key invalid")?;
        ensure!(
            [
                "name",
                "on",
                "permissions",
                "defaults",
                "concurrency",
                "jobs"
            ]
            .contains(&key),
            "managed workflow contains an unsupported top-level section: {key}"
        );
    }
    let jobs = value["jobs"]
        .as_mapping()
        .context("workflow jobs missing")?;
    ensure!(jobs.len() == 1, "managed workflow has custom jobs: {path}");
    let (job_name, job) = jobs.iter().next().context("managed workflow job missing")?;
    let job_name = job_name.as_str().context("job name missing")?;
    let expected_reusable = match path {
        ".github/workflows/approve-request.yml" => "reusable-approve-request.yml",
        ".github/workflows/merge-request.yml" => "reusable-merge-request.yml",
        ".github/workflows/policy-check.yml" => "reusable-policy-check.yml",
        ".github/workflows/release-pr-sync.yml" => "reusable-release-pr-sync.yml",
        ".github/workflows/release-pr.yml" => "reusable-release-pr.yml",
        ".github/workflows/release-tag.yml" => "reusable-release-tag.yml",
        _ => unreachable!(),
    };
    let uses = job["uses"].as_str();
    if path.ends_with("approve-request.yml") && uses.is_none() {
        return validate_legacy_approval(&value);
    }
    ensure!(
        job_name
            == match path {
                ".github/workflows/approve-request.yml" => "approve",
                ".github/workflows/merge-request.yml" => "request",
                ".github/workflows/policy-check.yml" => "check",
                ".github/workflows/release-pr-sync.yml" => "sync",
                ".github/workflows/release-pr.yml" => "prepare",
                ".github/workflows/release-tag.yml" => "tag",
                _ => unreachable!(),
            },
        "managed workflow job name changed: {path}"
    );
    let expected = format!("civitaspo/securefix-server/.github/workflows/{expected_reusable}");
    let uses = uses.context("managed workflow must call its exact reusable workflow")?;
    let (reusable, sha) = uses
        .rsplit_once('@')
        .context("managed workflow pin is missing")?;
    ensure!(
        reusable == expected,
        "managed workflow calls an unexpected reusable workflow: {path}"
    );
    validate_sha(sha)?;
    let releases = path.starts_with(".github/workflows/release-");
    let canonical = rendered_files(sha, default_branch, releases)?;
    let expected_bytes = canonical
        .get(path)
        .context("managed workflow missing from canonical template set")?;
    let mut expected_yaml: serde_yaml::Value = serde_yaml::from_slice(expected_bytes)?;
    legacy_workflow_shape(path, &value, &mut expected_yaml);
    validate_permission_subset(
        &job["permissions"],
        &expected_yaml["jobs"][job_name]["permissions"],
    )?;
    let mut actual_semantics = value.clone();
    let actual_map = actual_semantics
        .as_mapping_mut()
        .context("workflow object missing")?;
    actual_map.remove(serde_yaml::Value::String("defaults".into()));
    expected_yaml
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("defaults".into()));
    actual_map
        .get_mut("jobs")
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|jobs| jobs.get_mut(job_name))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .context("job object missing")?
        .remove(serde_yaml::Value::String("permissions".into()));
    expected_yaml
        .as_mapping_mut()
        .unwrap()
        .get_mut("jobs")
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|jobs| jobs.get_mut(job_name))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .unwrap()
        .remove(serde_yaml::Value::String("permissions".into()));
    if let Some(defaults) = value.get("defaults") {
        ensure!(
            defaults["run"]["shell"] == "bash -euo pipefail {0}"
                && defaults.as_mapping().is_some_and(|map| map.len() == 1),
            "workflow has unsupported defaults customization"
        );
    }
    ensure!(
        actual_semantics == expected_yaml,
        "managed workflow customization at {path}: actual={actual_semantics:#?}; expected={expected_yaml:#?}"
    );
    for key in job.as_mapping().context("job must be a mapping")?.keys() {
        let key = key.as_str().context("job key invalid")?;
        ensure!(
            ["uses", "permissions", "secrets", "with", "if", "name"].contains(&key),
            "managed workflow job contains custom behavior: {key}"
        );
    }
    ensure!(
        job.get("steps").is_none() && job.get("runs-on").is_none(),
        "managed reusable job has local execution steps"
    );
    Ok(())
}

fn legacy_workflow_shape(path: &str, actual: &serde_yaml::Value, expected: &mut serde_yaml::Value) {
    if path == ".github/workflows/merge-request.yml"
        && let Some(condition) = expected["jobs"]["request"]["if"].as_str()
    {
        let prior = condition.replace(
            "contains(github.event.comment.body, '/merge')",
            "github.event.comment.body == '/merge'",
        );
        if actual["jobs"]["request"]["if"].as_str() == Some(prior.as_str()) {
            expected["jobs"]["request"]["if"] = serde_yaml::Value::String(prior);
        }
    }
    let actual_on = actual
        .as_mapping()
        .and_then(|m| m.get("on").or_else(|| m.get(serde_yaml::Value::Bool(true))))
        .unwrap_or(&serde_yaml::Value::Null);
    match path {
        ".github/workflows/release-pr.yml" => {
            let actual_inputs = actual_on["workflow_dispatch"].get("inputs");
            if let Some(inputs) = actual_inputs {
                let Some(version) = inputs.get("version") else {
                    return;
                };
                let description = version["description"].as_str().unwrap_or_default();
                let known = [
                    "Explicit release version, or empty to compute it",
                    "Explicit release version without the leading v, for example 0.0.1-pre.1 (empty = compute with git-cliff)",
                ];
                if !known.contains(&description)
                    || version["required"] != false
                    || version["type"] != "string"
                    || inputs.as_mapping().is_none_or(|m| m.len() != 1)
                {
                    return;
                }
                if let Some(dispatch) = expected
                    .as_mapping_mut()
                    .and_then(|m| m.get_mut("on"))
                    .and_then(|on| on.get_mut("workflow_dispatch"))
                    .and_then(serde_yaml::Value::as_mapping_mut)
                {
                    dispatch.insert(serde_yaml::Value::String("inputs".into()), inputs.clone());
                }
                let actual_job = actual
                    .get("jobs")
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|jobs| jobs.values().next());
                if actual_job.is_some_and(|job| job.get("with").is_none())
                    && let Some(job) = expected
                        .as_mapping_mut()
                        .and_then(|m| m.get_mut("jobs"))
                        .and_then(serde_yaml::Value::as_mapping_mut)
                        .and_then(|jobs| jobs.values_mut().next())
                        .and_then(serde_yaml::Value::as_mapping_mut)
                {
                    job.remove("with");
                }
            } else {
                if let Some(dispatch) = expected
                    .as_mapping_mut()
                    .and_then(|m| m.get_mut("on"))
                    .and_then(|on| on.get_mut("workflow_dispatch"))
                {
                    *dispatch = serde_yaml::Value::Null;
                }
                if let Some(job) = expected
                    .as_mapping_mut()
                    .and_then(|m| m.get_mut("jobs"))
                    .and_then(serde_yaml::Value::as_mapping_mut)
                    .and_then(|jobs| jobs.values_mut().next())
                    .and_then(serde_yaml::Value::as_mapping_mut)
                {
                    job.remove("with");
                }
            }
        }
        ".github/workflows/release-tag.yml"
            if actual_on["workflow_dispatch"]["inputs"]
                .get("merge_sha")
                .is_some() =>
        {
            if let Some(dispatch) = expected
                .as_mapping_mut()
                .and_then(|m| m.get_mut("on"))
                .and_then(|on| on.get_mut("workflow_dispatch"))
                .and_then(serde_yaml::Value::as_mapping_mut)
            {
                dispatch.insert(serde_yaml::Value::String("inputs".into()), serde_yaml::from_str("{merge_sha: {description: 'Commit SHA to tag (defaults to main HEAD when empty)', required: false, type: string}}").unwrap());
            }
            expected.as_mapping_mut().unwrap().insert(serde_yaml::Value::String("concurrency".into()), serde_yaml::from_str("{group: 'release-tag-${{ github.event.pull_request.number || github.run_id }}', cancel-in-progress: false}").unwrap());
            if let Some(job) = expected
                .as_mapping_mut()
                .and_then(|m| m.get_mut("jobs"))
                .and_then(serde_yaml::Value::as_mapping_mut)
                .and_then(|jobs| jobs.values_mut().next())
                .and_then(serde_yaml::Value::as_mapping_mut)
            {
                job.remove("if");
                job.insert(
                    serde_yaml::Value::String("with".into()),
                    serde_yaml::from_str("{merge_sha: '${{ inputs.merge_sha }}'}").unwrap(),
                );
            }
        }
        _ => {}
    }
}

fn validate_permission_subset(
    actual: &serde_yaml::Value,
    expected: &serde_yaml::Value,
) -> Result<()> {
    let Some(actual) = actual.as_mapping() else {
        return Ok(());
    };
    let expected = expected
        .as_mapping()
        .context("canonical permissions missing")?;
    for (key, level) in actual {
        let maximum = expected
            .get(key)
            .and_then(serde_yaml::Value::as_str)
            .context("workflow requests an unapproved permission")?;
        let requested = level
            .as_str()
            .context("workflow permission level invalid")?;
        let rank = |value: &str| match value {
            "none" => Some(0),
            "read" => Some(1),
            "write" => Some(2),
            _ => None,
        };
        ensure!(
            rank(requested)
                .zip(rank(maximum))
                .is_some_and(|(requested, maximum)| requested <= maximum),
            "workflow requests a broader permission than its canonical template"
        );
    }
    Ok(())
}

fn validate_legacy_approval(workflow: &serde_yaml::Value) -> Result<()> {
    let mut normalized = workflow.clone();
    let action = normalized["jobs"]["approve"]["steps"][1]["uses"]
        .as_str()
        .context("legacy approval action missing")?;
    ensure!(
        action == "csm-actions/approve-pr-action@452271472f121d6d2f8e7a0761488d2fcc29b715"
            || action == "csm-actions/approve-pr-action@a8fdc60ab4d9b446694140534bbcc71c29fb499c",
        "legacy approval action is not an audited version"
    );
    normalized["jobs"]["approve"]["steps"][1]["uses"] = serde_yaml::Value::String(
        "csm-actions/approve-pr-action@a8fdc60ab4d9b446694140534bbcc71c29fb499c".into(),
    );
    for template in [
        include_str!("legacy-approve.yml"),
        include_str!("legacy-approve-infobox.yml"),
    ] {
        let audited: serde_yaml::Value = serde_yaml::from_str(template)?;
        if normalized == audited {
            return Ok(());
        }
    }
    anyhow::bail!("legacy approval workflow contains unsupported customization")
}

fn optional_content(
    api: &GitHub,
    repository: &str,
    path: &str,
    revision: &str,
) -> Result<Option<Vec<u8>>> {
    match api.content(repository, path, revision) {
        Ok(contents) => Ok(Some(contents)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
