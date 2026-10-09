use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use securefix::{
    api::GitHub,
    event, output, output_multiline,
    policy::{Capability, Policy, validate_repository, validate_sha},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[path = "artifact.rs"]
pub(crate) mod artifact;

const LABEL_PREFIX: &str = "securefix-";
const CLIENT_CI_WORKFLOW: &str = ".github/workflows/pull_request.yml";
const RELEASE_PR_WORKFLOW: &str = ".github/workflows/release-pr.yml";
const REUSABLE_RELEASE_PR: &str = ".github/workflows/reusable-release-pr.yml";
const MAX_FIX_ARTIFACT: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct FixPlan {
    pub(crate) version: u8,
    pub(crate) source_repository: String,
    pub(crate) source_run_id: u64,
    pub(crate) source_sha: String,
    pub(crate) artifact_name: String,
    pub(crate) artifact_id: u64,
    pub(crate) destination_repository: String,
    pub(crate) destination_branch: String,
    pub(crate) expected_head: String,
    pub(crate) destination_branch_exists: bool,
    pub(crate) existing_pull_request: Option<u64>,
}

#[derive(Debug)]
struct PreparedFix {
    client_repository: String,
    push_repository: String,
    branch: String,
    workflow_run: String,
    pull_request: Option<String>,
    create_pull_request: Option<String>,
}

#[derive(Debug)]
struct LoadedFix {
    repository: String,
    run_id: u64,
    label: String,
    run: Value,
    artifact_id: u64,
    fix: artifact::FixArtifact,
    pull_request: Option<Value>,
}

#[derive(Clone, Copy)]
pub(crate) struct SourceRequest<'a> {
    pub(crate) repository: &'a str,
    pub(crate) run_id: u64,
    pub(crate) label: &'a str,
    pub(crate) branch: &'a str,
    pub(crate) sha: &'a str,
}

pub(crate) struct ApplyCore<'a> {
    pub(crate) read_api: &'a GitHub,
    pub(crate) write_api: &'a GitHub,
    pub(crate) policy: &'a Policy,
    pub(crate) source: SourceRequest<'a>,
    pub(crate) plan: &'a FixPlan,
    pub(crate) fix: &'a artifact::FixArtifact,
    pub(crate) server_url: &'a str,
    pub(crate) server_repository: &'a str,
    pub(crate) server_run: &'a str,
}

pub(crate) struct ApplyResult {
    pub(crate) commit_sha: String,
    pub(crate) already_applied: bool,
    pub(crate) pull_request_number: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
struct DestinationHead {
    sha: String,
    branch_exists: bool,
    pull_request: Option<u64>,
}

#[derive(Args)]
pub struct ClientPrepareArgs {
    #[arg(long, default_value = "")]
    root_dir: String,
    #[arg(long, default_value = "")]
    files: String,
    #[arg(long, default_value = "")]
    repository: String,
    #[arg(long, default_value = "")]
    branch: String,
    #[arg(long, default_value = "")]
    commit_message: String,
    #[arg(long, default_value = "")]
    pull_request_json: String,
    #[arg(long, default_value = "")]
    pull_request_title: String,
    #[arg(long, default_value = "")]
    pull_request_body: String,
    #[arg(long, default_value = "")]
    pull_request_base: String,
    #[arg(long, default_value = "{}")]
    custom_json: String,
    #[arg(long, default_value = ".securefix-artifacts")]
    output_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum Command {
    ValidateEvent,
    #[command(about = "Validate a Securefix artifact and save an apply plan")]
    Prepare {
        #[arg(long)]
        plan: Option<PathBuf>,
    },
    #[command(about = "Revalidate and apply a prepared Securefix artifact")]
    Apply {
        #[arg(long)]
        plan: Option<PathBuf>,
    },
    #[command(about = "Delete the validated one-time Securefix request label")]
    Cleanup,
    #[command(about = "Stage a legacy-compatible Securefix source artifact")]
    ClientPrepare(Box<ClientPrepareArgs>),
    #[command(about = "Create the Securefix request label after artifact upload")]
    ClientDispatch {
        #[arg(long)]
        artifact_name: String,
        #[arg(long)]
        server_repository: String,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::ValidateEvent => validate_event(),
        Command::Prepare { plan } => prepare(&plan.unwrap_or_else(default_plan_path)),
        Command::Apply { plan } => apply(&plan.unwrap_or_else(default_plan_path)),
        Command::Cleanup => cleanup(),
        Command::ClientPrepare(args) => client_prepare(*args),
        Command::ClientDispatch {
            artifact_name,
            server_repository,
        } => client_dispatch(&artifact_name, &server_repository),
    }
}

fn default_plan_path() -> PathBuf {
    std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("securefix-apply-plan.json")
}

fn client_prepare(args: ClientPrepareArgs) -> Result<()> {
    let ClientPrepareArgs {
        root_dir,
        files: files_arg,
        repository,
        branch,
        commit_message,
        pull_request_json,
        pull_request_title,
        pull_request_body,
        pull_request_base,
        custom_json,
        output_dir,
    } = args;
    let workspace =
        PathBuf::from(std::env::var("GITHUB_WORKSPACE").context("missing GITHUB_WORKSPACE")?);
    let workspace = fs::canonicalize(workspace).context("resolve GitHub workspace")?;
    let root = if root_dir.is_empty() || root_dir == "." {
        PathBuf::new()
    } else {
        ensure!(artifact::safe_path(&root_dir), "invalid Securefix root_dir");
        PathBuf::from(root_dir)
    };
    let root_path = workspace.join(&root);
    ensure_no_symlink_components(&workspace, &root)?;
    let canonical_root = fs::canonicalize(&root_path).context("resolve Securefix root_dir")?;
    ensure!(
        canonical_root.starts_with(&workspace),
        "Securefix root_dir escapes workspace"
    );
    let output_dir_text = output_dir
        .to_str()
        .context("artifact output directory must be UTF-8")?
        .replace('\\', "/");
    ensure!(
        artifact::safe_path(&output_dir_text),
        "artifact output directory must be a relative path"
    );
    let mut files = std::collections::BTreeSet::new();
    for line in files_arg.lines() {
        let file = line.trim();
        if !file.is_empty() {
            ensure!(
                artifact::safe_path(file),
                "unsafe Securefix file path: {file}"
            );
            ensure!(
                files.insert(file.to_owned()),
                "duplicate Securefix file path: {file}"
            );
        }
    }
    ensure!(
        files.len() <= MAX_FILES_FOR_CLIENT,
        "too many Securefix files"
    );
    if files.is_empty() {
        output("artifact_name", "")?;
        output("artifact_path", "")?;
        output("changed_files", "")?;
        output("changed_files_from_root_dir", "")?;
        return Ok(());
    }
    let run_id = std::env::var("GITHUB_RUN_ID")?;
    ensure!(
        !run_id.is_empty() && run_id.bytes().all(|b| b.is_ascii_digit()),
        "invalid GITHUB_RUN_ID"
    );
    let event_path =
        PathBuf::from(std::env::var("GITHUB_EVENT_PATH").context("missing GITHUB_EVENT_PATH")?);
    let event_bytes = fs::read(&event_path).context("read GitHub event payload")?;
    ensure!(
        event_bytes.len() <= MAX_METADATA_FOR_CLIENT,
        "GitHub event payload exceeds size limit"
    );
    let payload: Value =
        serde_json::from_slice(&event_bytes).context("invalid GitHub event payload")?;
    let source_repository = std::env::var("GITHUB_REPOSITORY")?;
    validate_repository(&source_repository)?;
    ensure!(
        payload["repository"]["full_name"] == source_repository,
        "event repository mismatch"
    );
    ensure!(
        pull_request_json.is_empty()
            || (pull_request_title.is_empty()
                && pull_request_body.is_empty()
                && pull_request_base.is_empty()),
        "pass pull request JSON or individual pull request fields, not both"
    );
    let pull_request = if !pull_request_json.is_empty() {
        serde_json::from_str(&pull_request_json).context("invalid pull request JSON")?
    } else if !pull_request_title.is_empty() {
        ensure!(
            !pull_request_base.is_empty(),
            "pull request base is required with a title"
        );
        json!({"title":pull_request_title,"body":pull_request_body,"base":pull_request_base})
    } else {
        Value::Null
    };
    let custom: Value = serde_json::from_str(&custom_json).context("invalid custom JSON")?;
    ensure!(custom.is_object(), "custom metadata must be a JSON object");
    if !repository.is_empty() {
        validate_repository(&repository)?;
    }
    ensure!(
        branch.len() <= 255 && !branch.starts_with('/') && !branch.contains(['\\', '\0']),
        "invalid destination branch"
    );
    ensure!(
        commit_message.len() <= 4096 && !commit_message.contains('\0'),
        "invalid commit message"
    );
    ensure!(
        pull_request.is_null() || pull_request.is_object(),
        "pull request metadata must be a JSON object"
    );
    let root_text = root.to_string_lossy().replace('\\', "/");
    let input_repository = if repository.is_empty() {
        Value::Null
    } else {
        Value::String(repository.to_owned())
    };
    let input_branch = if branch.is_empty() {
        Value::Null
    } else {
        Value::String(branch.to_owned())
    };
    let input_message = if commit_message.is_empty() {
        Value::Null
    } else {
        Value::String(commit_message.to_owned())
    };
    let metadata = json!({
        "context": {
            "serverUrl": std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into()),
            "repo": { "owner": source_repository.split('/').next().unwrap_or_default(), "repo": source_repository.split('/').nth(1).unwrap_or_default() },
            "runId": run_id.parse::<u64>()?,
            "runAttempt": std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".into()).parse::<u64>()?,
            "sha": std::env::var("GITHUB_SHA")?,
            "workflow": std::env::var("GITHUB_WORKFLOW").unwrap_or_default(),
            "ref": std::env::var("GITHUB_REF").unwrap_or_default(),
            "eventName": std::env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
            "actor": std::env::var("GITHUB_ACTOR").unwrap_or_default(),
            "payload": payload
        },
        "inputs": {
            "repository": input_repository,
            "branch": input_branch,
            "commit_message": input_message,
            "root_dir": root_text,
            "pull_request": if pull_request.is_null() { Value::Null } else { pull_request },
            "custom": custom
        }
    });
    let metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
    let file_list = format!("{}\n", files.iter().cloned().collect::<Vec<_>>().join("\n"));
    let digest = Sha256::digest([metadata_bytes.as_slice(), file_list.as_bytes()].concat());
    let suffix = digest
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let artifact_name = format!("securefix-{run_id}-{suffix}");
    let stage = output_dir.join(&artifact_name);
    let cwd = std::env::current_dir()?;
    ensure_no_symlink_components(&cwd, &output_dir)?;
    fs::create_dir_all(&stage)?;
    ensure_no_symlink_components(&cwd, &stage)?;
    let metadata_path = format!("{artifact_name}.json");
    let file_list_path = format!("{artifact_name}_files.txt");
    ensure_no_symlink_components(&cwd, &output_dir.join(&artifact_name).join(&metadata_path))?;
    ensure_no_symlink_components(&cwd, &output_dir.join(&artifact_name).join(&file_list_path))?;
    fs::write(stage.join(metadata_path), &metadata_bytes)?;
    fs::write(stage.join(file_list_path), &file_list)?;
    let mut changed_files = Vec::new();
    let mut changed_from_root = Vec::new();
    let mut total_size = (metadata_bytes.len() + file_list.len()) as u64;
    for file in files {
        let source = canonical_root.join(&file);
        let target = stage.join(&file);
        let source_relative = root.join(&file);
        if ensure_no_symlink_components(&workspace, &source_relative)? {
            let meta = fs::symlink_metadata(&source)?;
            {
                let canonical_source = fs::canonicalize(&source)?;
                ensure!(
                    canonical_source.starts_with(&canonical_root),
                    "Securefix input resolves outside its workspace root: {file}"
                );
                ensure!(
                    meta.file_type().is_file(),
                    "Securefix input is not a regular file: {file}"
                );
                ensure!(
                    meta.len() <= MAX_FILE_FOR_CLIENT,
                    "Securefix input file exceeds size limit: {file}"
                );
                total_size = total_size
                    .checked_add(meta.len())
                    .context("Securefix input size overflow")?;
                ensure!(
                    total_size <= MAX_TOTAL_FOR_CLIENT,
                    "Securefix files exceed total size limit"
                );
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let stage_relative = output_dir.join(&artifact_name).join(&file);
                ensure_no_symlink_components(&cwd, &stage_relative)?;
                fs::copy(&source, &target)?;
            }
        }
        changed_files.push(if root_text.is_empty() {
            file.clone()
        } else {
            format!("{root_text}/{file}")
        });
        changed_from_root.push(file);
    }
    output("artifact_name", &artifact_name)?;
    output(
        "artifact_path",
        format!("{}/{}/**", output_dir.display(), artifact_name),
    )?;
    output_multiline("changed_files", &changed_files.join("\n"))?;
    output_multiline("changed_files_from_root_dir", &changed_from_root.join("\n"))?;
    Ok(())
}

fn ensure_no_symlink_components(base: &Path, relative: &Path) -> Result<bool> {
    ensure!(relative.is_relative(), "path must be relative");
    let mut current = base.to_owned();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("path contains an unsafe component");
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Securefix path contains a symbolic link: {}",
                    current.display()
                );
                if index + 1 < components.len() {
                    ensure!(
                        metadata.is_dir(),
                        "Securefix path parent is not a directory"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn client_dispatch(artifact_name: &str, server_repository: &str) -> Result<()> {
    let trusted = crate::config::trusted()?;
    ensure!(
        server_repository.eq_ignore_ascii_case(&trusted.deployment.server.repository),
        "Securefix labels may only target the server repository"
    );
    ensure!(
        artifact::valid_artifact_name_for_cli(artifact_name),
        "invalid Securefix artifact name"
    );
    let repository = std::env::var("GITHUB_REPOSITORY")?;
    validate_repository(&repository)?;
    let run_id = std::env::var("GITHUB_RUN_ID")?;
    ensure!(
        run_id.bytes().all(|b| b.is_ascii_digit()) && !run_id.is_empty(),
        "invalid GITHUB_RUN_ID"
    );
    let api = GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    let _: Value = api.post(
        &format!("/repos/{}/labels", trusted.deployment.server.repository),
        &json!({
            "name": artifact_name,
            "description": format!("{repository}/{run_id}")
        }),
    )?;
    output("source_label", artifact_name)?;
    Ok(())
}

const MAX_FILES_FOR_CLIENT: usize = 512;
const MAX_METADATA_FOR_CLIENT: usize = 1024 * 1024;
const MAX_FILE_FOR_CLIENT: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_FOR_CLIENT: u64 = 10 * 1024 * 1024;

fn policy(api: &GitHub) -> Result<Policy> {
    let p = Policy::active(api)?;
    let source = std::env::var("SECUREFIX_SOURCE_SHA")?;
    ensure!(source == p.revision, "runtime revision is not current");
    Ok(p)
}

fn validate_event() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let p = policy(&api)?;
    let payload = event()?;
    let repo = std::env::var("GITHUB_REPOSITORY")?;
    let (source_repo, run_id, label) = parse_label_event(&p, &payload, &repo)?;
    output("source_repository", source_repo)?;
    output("source_run_id", run_id.to_string())?;
    output("source_label", label)?;
    Ok(())
}

fn cleanup() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let p = policy(&api)?;
    let payload = event()?;
    let server = std::env::var("GITHUB_REPOSITORY")?;
    let (_, _, label) = parse_label_event(&p, &payload, &server)?;
    let source_repository = payload["label"]["description"]
        .as_str()
        .and_then(|description| description.rsplit_once('/'))
        .map(|(repo, _)| repo)
        .context("missing Securefix label source repository")?;
    let run_id = payload["label"]["description"]
        .as_str()
        .and_then(|description| description.rsplit_once('/'))
        .and_then(|(_, run)| run.parse::<u64>().ok())
        .context("invalid Securefix label source run ID")?;
    require_live_label(&api, &label, source_repository, run_id)?;
    api.delete(&label_definition_path(&label)?)?;
    output("label_deleted", "true")?;
    Ok(())
}

fn parse_label_event(p: &Policy, payload: &Value, repo: &str) -> Result<(String, u64, String)> {
    let trusted = crate::config::trusted()?;
    validate_repository(repo)?;
    ensure!(
        repo.eq_ignore_ascii_case(&trusted.deployment.server.repository)
            && payload["repository"]["full_name"] == repo
            && payload["repository"]["id"].as_u64() == Some(trusted.deployment.server.id)
            && payload["repository"]["owner"]["id"].as_u64()
                == Some(trusted.deployment.repository_owner.id),
        "unexpected event repository"
    );
    ensure!(
        payload["sender"]["id"].as_u64() == Some(trusted.client_bot_id)
            && payload["sender"]["type"] == "Bot",
        "label was not created by Securefix Client"
    );
    let label = payload["label"]["name"].as_str().context("missing label")?;
    ensure!(
        label.starts_with(LABEL_PREFIX) && label.len() <= 50,
        "invalid Securefix label"
    );
    let description = payload["label"]["description"]
        .as_str()
        .context("missing label locator")?;
    let (source_repo, run) = description
        .rsplit_once('/')
        .context("label locator must be owner/repository/run_id")?;
    validate_repository(source_repo)?;
    let run_id: u64 = run.parse().context("invalid source run ID")?;
    ensure!(
        run_id > 0
            && label[LABEL_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid Securefix artifact label"
    );
    p.repository(source_repo)?.require(Capability::Securefix)?;
    Ok((source_repo.to_owned(), run_id, label.to_owned()))
}

fn prepare(plan_path: &Path) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let p = policy(&api)?;
    let loaded = load_fix(&api, &p)?;
    let LoadedFix {
        repository: repo,
        run_id,
        label,
        run,
        artifact_id,
        fix,
        pull_request,
    } = loaded;
    let source_sha = run["head_sha"]
        .as_str()
        .context("source workflow run SHA missing")?;
    let source_branch = run["head_branch"]
        .as_str()
        .context("source workflow branch missing")?;
    let prepared = PreparedFix {
        client_repository: repo.clone(),
        push_repository: fix.repository.clone(),
        branch: fix.branch.clone(),
        workflow_run: run.to_string(),
        pull_request: pull_request.as_ref().map(Value::to_string),
        create_pull_request: fix.create_pull_request.clone(),
    };
    validate_prepared_source(&api, &p, &repo, run_id, &prepared)?;
    let source = SourceRequest {
        repository: &repo,
        run_id,
        label: &label,
        branch: source_branch,
        sha: source_sha,
    };
    let destination = destination_head(&api, &source, &fix, &pull_request, &p)?;
    let plan = FixPlan {
        version: 1,
        source_repository: repo,
        source_run_id: run_id,
        source_sha: source_sha.to_owned(),
        artifact_name: label,
        artifact_id,
        destination_repository: fix.repository,
        destination_branch: fix.branch,
        expected_head: destination.sha,
        destination_branch_exists: destination.branch_exists,
        existing_pull_request: destination.pull_request,
    };
    let bytes = serde_json::to_vec(&plan)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "Securefix plan exceeds size limit"
    );
    if let Some(parent) = plan_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(plan_path, bytes)?;
    output("plan_path", plan_path.display().to_string())?;
    output(
        "repository_name",
        plan.destination_repository
            .split('/')
            .nth(1)
            .context("invalid destination repository")?,
    )?;
    output("repository_full_name", &plan.destination_repository)?;
    output("branch", &plan.destination_branch)?;
    output("source_sha", &plan.source_sha)?;
    output("source_run_id", plan.source_run_id.to_string())?;
    output("artifact_name", &plan.artifact_name)?;
    output("expected_head", &plan.expected_head)?;
    output(
        "pull_request_number",
        plan.existing_pull_request.unwrap_or_default().to_string(),
    )?;
    Ok(())
}

fn apply(plan_path: &Path) -> Result<()> {
    let bytes = fs::read(plan_path).context("read Securefix plan")?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "Securefix plan exceeds size limit"
    );
    let plan: FixPlan = serde_json::from_slice(&bytes).context("invalid Securefix plan")?;
    ensure!(plan.version == 1, "unsupported Securefix plan version");
    let read_api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let p = policy(&read_api)?;
    let loaded = load_fix(&read_api, &p)?;
    let LoadedFix {
        repository: repo,
        run_id,
        label,
        run,
        artifact_id,
        fix,
        pull_request,
    } = loaded;
    ensure!(
        repo == plan.source_repository
            && run_id == plan.source_run_id
            && label == plan.artifact_name
            && artifact_id == plan.artifact_id
            && run["head_sha"] == plan.source_sha,
        "source request changed after Securefix prepare"
    );
    let source_branch = run["head_branch"]
        .as_str()
        .context("source workflow branch missing")?;
    let prepared = PreparedFix {
        client_repository: repo.clone(),
        push_repository: fix.repository.clone(),
        branch: fix.branch.clone(),
        workflow_run: run.to_string(),
        pull_request: pull_request.as_ref().map(Value::to_string),
        create_pull_request: fix.create_pull_request.clone(),
    };
    validate_prepared_source(&read_api, &p, &repo, run_id, &prepared)?;
    let source = SourceRequest {
        repository: &repo,
        run_id,
        label: &label,
        branch: source_branch,
        sha: &plan.source_sha,
    };
    let destination = destination_head(&read_api, &source, &fix, &pull_request, &p)?;
    ensure!(
        fix.repository == plan.destination_repository
            && fix.branch == plan.destination_branch
            && destination.sha == plan.expected_head
            && destination.branch_exists == plan.destination_branch_exists
            && destination.pull_request == plan.existing_pull_request,
        "destination changed after Securefix prepare"
    );

    let write_api = GitHub::from_env("SECUREFIX_WRITE_TOKEN")?;
    let server_url =
        std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
    let server_repository = match std::env::var("GITHUB_REPOSITORY") {
        Ok(repository) => repository,
        Err(_) => crate::config::trusted()?
            .deployment
            .server
            .repository
            .clone(),
    };
    let server_run = std::env::var("GITHUB_RUN_ID").unwrap_or_default();
    let result = apply_core(ApplyCore {
        read_api: &read_api,
        write_api: &write_api,
        policy: &p,
        source,
        plan: &plan,
        fix: &fix,
        server_url: &server_url,
        server_repository: &server_repository,
        server_run: &server_run,
    })?;
    if result.already_applied {
        output("already_applied", "true")?;
    }
    output("commit_sha", &result.commit_sha)?;
    if let Some(number) = result.pull_request_number {
        output("pull_request_number", number.to_string())?;
    }
    Ok(())
}

pub(crate) fn apply_core(input: ApplyCore<'_>) -> Result<ApplyResult> {
    let ApplyCore {
        read_api,
        write_api,
        policy,
        source,
        plan,
        fix,
        server_url,
        server_repository,
        server_run,
    } = input;
    ensure!(
        plan.version == 1
            && plan.source_repository == source.repository
            && plan.source_run_id == source.run_id
            && plan.artifact_name == source.label
            && plan.source_sha == source.sha
            && plan.destination_repository == fix.repository
            && plan.destination_branch == fix.branch
            && fix.run_id == source.run_id
            && fix.source_sha == source.sha,
        "validated apply context does not match the source artifact and destination plan"
    );
    validate_sha(&plan.expected_head)?;
    validate_sha(source.sha)?;
    let message = format!(
        "{}\n{server_url}/{server_repository}/actions/runs/{server_run}\n\nSecurefix-Artifact: {}/{}/{}",
        fix.commit_message, source.repository, source.run_id, source.label,
    );
    let already_applied = has_artifact_receipt(
        read_api,
        &plan.destination_repository,
        &plan.expected_head,
        &source,
        None,
        fix,
        policy.server_bot_id,
    )?;
    if !already_applied && !plan.destination_branch_exists {
        let created: Value = write_api.post(
            &format!("/repos/{}/git/refs", plan.destination_repository),
            &json!({"ref":format!("refs/heads/{}", plan.destination_branch), "sha":plan.expected_head}),
        )?;
        ensure!(
            created["object"]["sha"] == plan.expected_head,
            "new release branch was not created at the validated head"
        );
    }
    let sha = if already_applied {
        plan.expected_head.clone()
    } else {
        write_api.create_commit(
            &plan.destination_repository,
            &plan.destination_branch,
            &plan.expected_head,
            &message,
            fix.additions.clone(),
            fix.deletions.clone(),
        )?
    };
    let mut pull_request_number = plan.existing_pull_request;
    if let Some(options) = &fix.create_pull_request {
        let options: Value = serde_json::from_str(options)?;
        let base = options["base"]
            .as_str()
            .context("release pull request base missing")?;
        if let Some(number) = release_pull_request(
            read_api,
            policy,
            &plan.destination_repository,
            &plan.destination_branch,
            base,
        )? {
            pull_request_number = Some(number);
        } else {
            let created: Value = write_api.post(
                &format!("/repos/{}/pulls", plan.destination_repository),
                &json!({
                    "title": options["title"],
                    "body": options.get("body").cloned().unwrap_or(Value::Null),
                    "head": plan.destination_branch,
                    "base": base,
                    "draft": options.get("draft").cloned().unwrap_or(Value::Bool(false)),
                }),
            )?;
            pull_request_number = Some(
                created["number"]
                    .as_u64()
                    .context("created release pull request has no number")?,
            );
        }
    }
    Ok(ApplyResult {
        commit_sha: sha,
        already_applied,
        pull_request_number,
    })
}

fn load_fix(api: &GitHub, p: &Policy) -> Result<LoadedFix> {
    let payload = event()?;
    let server = std::env::var("GITHUB_REPOSITORY")?;
    let (repository, run_id, label) = parse_label_event(p, &payload, &server)?;
    require_live_label(api, &label, &repository, run_id)?;
    let run: Value = api.get(&format!("/repos/{repository}/actions/runs/{run_id}"))?;
    validate_run_identity(&run, run_id, &repository)?;
    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    let matching: Vec<_> = artifacts["artifacts"]
        .as_array()
        .context("source artifacts missing")?
        .iter()
        .filter(|a| a["name"] == label)
        .collect();
    ensure!(
        matching.len() == 1,
        "Securefix source artifact is missing or duplicated"
    );
    let artifact = matching[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size <= MAX_FIX_ARTIFACT),
        "Securefix source artifact is expired or oversized"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .context("Securefix artifact has no ID")?;
    let zip = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        MAX_FIX_ARTIFACT as usize,
    )?;
    let source_sha = run["head_sha"]
        .as_str()
        .context("source workflow run SHA missing")?;
    let source_branch = run["head_branch"]
        .as_str()
        .context("source workflow run branch missing")?;
    let fix = artifact::parse(&zip, &label, &repository, run_id, source_sha, source_branch)?;
    ensure!(
        fix.run_id == run_id && fix.source_sha == source_sha,
        "artifact run or SHA binding failed"
    );
    let pull_request = if let Some(number) = run["pull_requests"][0]["number"].as_u64() {
        Some(api.get(&format!("/repos/{repository}/pulls/{number}"))?)
    } else {
        None
    };
    Ok(LoadedFix {
        repository,
        run_id,
        label,
        run,
        artifact_id,
        fix,
        pull_request,
    })
}

fn destination_head(
    api: &GitHub,
    source: &SourceRequest<'_>,
    fix: &artifact::FixArtifact,
    source_pr: &Option<Value>,
    p: &Policy,
) -> Result<DestinationHead> {
    let repo: Value = api.get(&format!("/repos/{}", source.repository))?;
    let default_branch = repo["default_branch"]
        .as_str()
        .context("source default branch missing")?;
    if source.branch != default_branch {
        let pr = source_pr
            .as_ref()
            .context("source run has no pull request")?;
        let head = pr["head"]["sha"]
            .as_str()
            .context("source pull request head SHA missing")?;
        if head != source.sha {
            ensure!(
                has_artifact_receipt(
                    api,
                    source.repository,
                    head,
                    source,
                    Some(source.sha),
                    fix,
                    p.server_bot_id,
                )?,
                "source pull request head advanced after the fix run"
            );
        }
        return Ok(DestinationHead {
            sha: head.to_owned(),
            branch_exists: true,
            pull_request: None,
        });
    }

    p.repository(source.repository)?
        .require(Capability::Release)?;
    ensure!(
        fix.repository.eq_ignore_ascii_case(source.repository),
        "release fixes may only update their source repository"
    );
    let branch_path = format!(
        "/repos/{}/branches/{}",
        source.repository,
        path_component(&fix.branch)
    );
    let existing: Option<Value> = match api.get(&branch_path) {
        Ok(value) => Some(value),
        Err(error)
            if error
                .downcast_ref::<securefix::api::ApiError>()
                .is_some_and(|e| e.status.as_u16() == 404) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let Some(existing) = existing else {
        return Ok(DestinationHead {
            sha: source.sha.to_owned(),
            branch_exists: false,
            pull_request: None,
        });
    };
    let head = existing["commit"]["sha"]
        .as_str()
        .context("release branch has no commit SHA")?
        .to_owned();
    validate_sha(&head)?;
    let owner = source
        .repository
        .split('/')
        .next()
        .context("invalid source repository")?;
    let pulls: Vec<Value> = api.get(&format!(
        "/repos/{}/pulls?head={}:{}&base={}&state=open&per_page=100",
        source.repository,
        owner,
        path_component(&fix.branch),
        path_component(default_branch)
    ))?;
    let matching: Vec<_> = pulls
        .iter()
        .filter(|pr| {
            pr["state"] == "open"
                && pr["head"]["repo"]["full_name"] == source.repository
                && pr["head"]["ref"] == fix.branch
                && pr["base"]["repo"]["full_name"] == source.repository
                && pr["base"]["ref"] == default_branch
        })
        .collect();
    ensure!(
        matching.len() <= 1,
        "existing release branch has multiple open same-repository pull requests"
    );
    let touched: std::collections::BTreeSet<&str> = fix
        .additions
        .keys()
        .chain(fix.deletions.iter())
        .map(String::as_str)
        .collect();
    let comparison: Value = api.get(&format!(
        "/repos/{}/compare/{}...{head}",
        source.repository, source.sha
    ))?;
    ensure!(
        comparison["status"] != "diverged",
        "release branch has diverged from source history"
    );
    validate_release_comparison(&comparison, p.server_bot_id)?;
    let changed = comparison["files"]
        .as_array()
        .context("release branch comparison has no changed-file list")?;
    ensure!(
        changed.iter().all(|file| file["filename"]
            .as_str()
            .is_some_and(|path| touched.contains(path))),
        "existing release branch contains changes outside the validated artifact files"
    );
    let artifact_applied = has_artifact_receipt(
        api,
        source.repository,
        &head,
        source,
        None,
        fix,
        p.server_bot_id,
    )?;
    if matching.is_empty() {
        ensure!(
            (head == source.sha && changed.is_empty()) || artifact_applied,
            "existing release branch has no bot-owned pull request or validated artifact commit"
        );
    } else {
        ensure!(
            matching[0]["user"]["id"].as_u64() == Some(p.server_bot_id),
            "existing release pull request is not owned by the Securefix Server bot"
        );
    }
    Ok(DestinationHead {
        sha: head,
        branch_exists: true,
        pull_request: matching.first().and_then(|pr| pr["number"].as_u64()),
    })
}

fn validate_release_comparison(comparison: &Value, server_bot_id: u64) -> Result<()> {
    let changed = comparison["files"]
        .as_array()
        .context("release branch comparison has no changed-file list")?;
    ensure!(
        changed.len() < 300,
        "release branch comparison may have truncated its changed-file list"
    );
    let total = comparison["total_commits"]
        .as_u64()
        .context("release branch comparison has no total commit count")?;
    let commits = comparison["commits"]
        .as_array()
        .context("release branch comparison has no commit list")?;
    ensure!(
        total < 2500 && commits.len() as u64 == total,
        "release branch comparison may have truncated its commit list"
    );
    ensure!(
        commits.iter().all(|commit| {
            commit["author"]["id"].as_u64() == Some(server_bot_id)
                && commit["commit"]["verification"]["verified"] == true
        }),
        "release branch contains a commit not signed by the Securefix Server bot"
    );
    Ok(())
}

fn release_pull_request(
    api: &GitHub,
    policy: &Policy,
    repository: &str,
    branch: &str,
    base: &str,
) -> Result<Option<u64>> {
    let owner = repository.split('/').next().context("invalid repository")?;
    let pulls: Vec<Value> = api.get(&format!(
        "/repos/{repository}/pulls?head={owner}:{}&base={}&state=open&per_page=100",
        path_component(branch),
        path_component(base)
    ))?;
    let matching: Vec<_> = pulls
        .iter()
        .filter(|pr| {
            pr["state"] == "open"
                && pr["head"]["repo"]["full_name"] == repository
                && pr["head"]["ref"] == branch
                && pr["base"]["repo"]["full_name"] == repository
                && pr["base"]["ref"] == base
        })
        .collect();
    ensure!(
        matching.len() <= 1,
        "multiple open Securefix release pull requests exist"
    );
    if let Some(pr) = matching.first() {
        ensure!(
            pr["user"]["id"].as_u64() == Some(policy.server_bot_id),
            "release pull request is not owned by the Securefix Server bot"
        );
        Ok(pr["number"].as_u64())
    } else {
        Ok(None)
    }
}

fn path_component(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn has_artifact_receipt(
    api: &GitHub,
    repository: &str,
    head: &str,
    source: &SourceRequest<'_>,
    expected_parent: Option<&str>,
    fix: &artifact::FixArtifact,
    server_bot_id: u64,
) -> Result<bool> {
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{head}"))?;
    let expected = format!(
        "Securefix-Artifact: {}/{}/{}",
        source.repository, source.run_id, source.label
    );
    if !receipt_matches(&commit, &expected, expected_parent, fix, server_bot_id) {
        return Ok(false);
    }
    for (path, expected) in &fix.additions {
        if api.content(repository, path, head)? != *expected {
            return Ok(false);
        }
    }
    for path in &fix.deletions {
        match api.content(repository, path, head) {
            Err(error)
                if error
                    .downcast_ref::<securefix::api::ApiError>()
                    .is_some_and(|e| e.status.as_u16() == 404) => {}
            Err(error) => return Err(error),
            Ok(_) => return Ok(false),
        }
    }
    Ok(true)
}

fn receipt_matches(
    commit: &Value,
    expected_receipt: &str,
    expected_parent: Option<&str>,
    fix: &artifact::FixArtifact,
    server_bot_id: u64,
) -> bool {
    let Some(parents) = commit["parents"].as_array() else {
        return false;
    };
    if commit["author"]["id"].as_u64() != Some(server_bot_id)
        || commit["author"]["type"] != "Bot"
        || commit["commit"]["verification"]["verified"] != true
        || parents.len() != 1
        || !commit["commit"]["message"]
            .as_str()
            .is_some_and(|message| message.lines().any(|line| line == expected_receipt))
        || expected_parent.is_some_and(|parent| parents[0]["sha"] != parent)
    {
        return false;
    }
    let Some(files) = commit["files"].as_array() else {
        return false;
    };
    let actual: std::collections::BTreeSet<&str> = files
        .iter()
        .filter_map(|file| file["filename"].as_str())
        .collect();
    let expected: std::collections::BTreeSet<&str> = fix
        .additions
        .keys()
        .chain(fix.deletions.iter())
        .map(String::as_str)
        .collect();
    actual == expected && actual.len() == files.len() && files.len() < 300
}

fn label_definition_path(label: &str) -> Result<String> {
    Ok(format!(
        "/repos/{}/labels/{}",
        crate::config::trusted()?.deployment.server.repository,
        path_component(label)
    ))
}

fn require_live_label(api: &GitHub, label: &str, repository: &str, run_id: u64) -> Result<()> {
    let live: Value = api.get(&label_definition_path(label)?)?;
    ensure!(
        live["name"] == label && live["description"] == format!("{repository}/{run_id}"),
        "Securefix event label no longer matches its live request"
    );
    Ok(())
}

fn validate_prepared_source(
    api: &GitHub,
    p: &Policy,
    source_repository: &str,
    source_run_id: u64,
    prepared: &PreparedFix,
) -> Result<(String, String)> {
    let workflow_run: Value = serde_json::from_str(&prepared.workflow_run)
        .context("invalid source workflow run output")?;
    validate_run_identity(&workflow_run, source_run_id, source_repository)?;
    let source_sha = workflow_run["head_sha"]
        .as_str()
        .context("source workflow run SHA missing")?;
    validate_sha(source_sha)?;
    let source_branch = workflow_run["head_branch"]
        .as_str()
        .context("source workflow run branch missing")?;
    ensure!(
        !source_branch.is_empty() && source_branch.len() <= 255,
        "invalid source workflow branch"
    );
    let workflow_path = workflow_run["path"]
        .as_str()
        .context("source workflow path missing")?;
    let workflow_file = normalize_source_workflow(workflow_path)
        .context("source run is not an approved workflow")?;

    let repo: Value = api.get(&format!("/repos/{source_repository}"))?;
    let default_branch = repo["default_branch"]
        .as_str()
        .context("client default branch missing")?;
    let is_release = source_branch == default_branch;
    validate_destination(
        &prepared.client_repository,
        &prepared.push_repository,
        &prepared.branch,
        source_repository,
        source_branch,
        default_branch,
    )?;
    ensure!(
        !is_release || workflow_file == RELEASE_PR_WORKFLOW,
        "default-branch Securefix runs are limited to the release PR workflow"
    );
    if is_release {
        p.repository(source_repository)?
            .require(Capability::Release)?;
        validate_release_provenance(api, p, &workflow_run, source_repository, source_sha)?;
        if let Some(options) = nonempty(prepared.create_pull_request.as_deref()) {
            validate_pull_request_options(options, default_branch)?;
        }
    } else {
        ensure!(
            workflow_file == CLIENT_CI_WORKFLOW && workflow_run["event"] == "pull_request",
            "client PR fixes must come from the pull-request CI workflow"
        );
        ensure!(
            prepared.branch == source_branch,
            "client PR fixes may only update their source branch"
        );
        let number = workflow_run["pull_requests"][0]["number"]
            .as_u64()
            .context("source run has no pull request")?;
        let pr: Value = api.get(&format!("/repos/{source_repository}/pulls/{number}"))?;
        ensure!(
            source_pr_matches(&pr, source_repository, default_branch, source_branch),
            "source workflow no longer belongs to an open same-repository pull request"
        );
        let prepared_pr: Value = serde_json::from_str(
            nonempty(prepared.pull_request.as_deref())
                .context("prepare output lacks pull request")?,
        )
        .context("invalid prepared pull request")?;
        ensure!(
            prepared_pr["number"].as_u64() == Some(number)
                && prepared_pr["head"]["repo"]["full_name"] == source_repository
                && prepared_pr["head"]["ref"] == source_branch
                && prepared_pr["base"]["ref"] == default_branch,
            "prepared pull request does not match the source workflow"
        );
        ensure!(
            nonempty(prepared.create_pull_request.as_deref()).is_none(),
            "client PR fixes cannot create additional pull requests"
        );
    }

    Ok((
        source_sha.to_owned(),
        workflow_run["name"].as_str().unwrap_or_default().to_owned(),
    ))
}

fn validate_release_provenance(
    api: &GitHub,
    policy: &Policy,
    run: &Value,
    repository: &str,
    source_sha: &str,
) -> Result<()> {
    let current: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        run["head_branch"].as_str().unwrap_or_default()
    ))?;
    let current_sha = current["sha"]
        .as_str()
        .context("client default branch has no SHA")?;
    ensure!(
        current_sha == source_sha,
        "release PR caller is not at the current default-branch head"
    );
    let wrapper = api.content(repository, RELEASE_PR_WORKFLOW, source_sha)?;
    securefix::workflow::require_reusable_pin(&wrapper, REUSABLE_RELEASE_PR, &policy.revision)?;
    let referenced: Vec<securefix::workflow::ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("release PR run lacks reusable workflow provenance")?;
    securefix::workflow::referenced_revision(&referenced, REUSABLE_RELEASE_PR, &policy.revision)?;
    Ok(())
}

fn validate_pull_request_options(value: &str, default_branch: &str) -> Result<()> {
    let value: Value =
        serde_json::from_str(value).context("invalid prepared pull request creation options")?;
    let options = value
        .as_object()
        .context("prepared pull request options must be an object")?;
    let allowed = [
        "title",
        "body",
        "base",
        "labels",
        "assignees",
        "reviewers",
        "team_reviewers",
        "draft",
        "automerge_method",
        "comment",
        "project",
        "milestone_number",
    ];
    ensure!(
        options.keys().all(|key| allowed.contains(&key.as_str())),
        "prepared pull request options contain an unknown field"
    );
    let title = options
        .get("title")
        .and_then(Value::as_str)
        .context("release pull request title missing")?;
    let base = options
        .get("base")
        .and_then(Value::as_str)
        .context("release pull request base missing")?;
    ensure!(
        !title.trim().is_empty() && title.len() <= 256,
        "invalid release pull request title"
    );
    ensure!(
        base == default_branch,
        "release pull request must target the default branch"
    );
    ensure!(
        options
            .get("body")
            .is_none_or(|body| body.as_str().is_some_and(|body| body.len() <= 64 * 1024))
            && options.get("draft").is_none_or(Value::is_boolean),
        "invalid release pull request body or draft option"
    );
    ensure!(
        ["labels", "assignees", "reviewers", "team_reviewers"]
            .iter()
            .all(|key| options
                .get(*key)
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)))
            && options
                .get("automerge_method")
                .is_none_or(|value| value.as_str() == Some(""))
            && options
                .get("comment")
                .is_none_or(|value| value.as_str() == Some(""))
            && options.get("project").is_none_or(Value::is_null)
            && options.get("milestone_number").is_none_or(Value::is_null),
        "release pull request options contain unsupported side effects"
    );
    Ok(())
}

fn source_pr_matches(pr: &Value, repository: &str, default_branch: &str, branch: &str) -> bool {
    pr["state"] == "open"
        && pr["base"]["ref"] == default_branch
        && pr["base"]["repo"]["full_name"] == repository
        && pr["head"]["repo"]["full_name"] == repository
        && pr["head"]["ref"] == branch
}

fn normalize_source_workflow(path: &str) -> Option<&str> {
    if path == CLIENT_CI_WORKFLOW || path == RELEASE_PR_WORKFLOW {
        return Some(path);
    }
    let (workflow, reference) = path.split_once('@')?;
    (!reference.is_empty()
        && !reference.contains('@')
        && (workflow == CLIENT_CI_WORKFLOW || workflow == RELEASE_PR_WORKFLOW))
        .then_some(workflow)
}

fn validate_destination(
    client_repository: &str,
    push_repository: &str,
    destination: &str,
    source_repository: &str,
    source_branch: &str,
    default_branch: &str,
) -> Result<()> {
    validate_repository(client_repository)?;
    validate_repository(push_repository)?;
    ensure!(
        client_repository.eq_ignore_ascii_case(source_repository)
            && push_repository.eq_ignore_ascii_case(source_repository),
        "Securefix may only update its source repository"
    );
    ensure!(
        !destination.is_empty()
            && destination.len() <= 255
            && !destination.starts_with('/')
            && !destination.contains(['\\', '\0']),
        "invalid Securefix destination branch"
    );
    ensure!(
        destination != default_branch,
        "Securefix may not directly update a default branch"
    );
    ensure!(
        source_branch == default_branch || destination == source_branch,
        "Securefix destination branch is outside the allowed scope"
    );
    Ok(())
}

fn validate_run_identity(run: &Value, run_id: u64, repository: &str) -> Result<()> {
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == repository
            && run["head_repository"]["full_name"] == repository
            && run["run_attempt"].as_u64() == Some(1),
        "source workflow run identity or repository mismatch"
    );
    Ok(())
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_pull_request_can_advance_after_the_fix_run() {
        let pull_request = json!({
            "state":"open",
            "base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},
            "head":{"ref":"feature","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"civitaspo/example"}}
        });
        assert!(source_pr_matches(
            &pull_request,
            "civitaspo/example",
            "main",
            "feature"
        ));
        assert_eq!(nonempty(Some("")), None);
        assert_eq!(nonempty(Some("{}")), Some("{}"));
    }

    #[test]
    fn source_pull_request_must_be_open_same_repo_and_target_default_branch() {
        let valid = json!({"state":"open","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}});
        assert!(source_pr_matches(
            &valid,
            "civitaspo/example",
            "main",
            "feature"
        ));
        for invalid in [
            json!({"state":"closed","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}}),
            json!({"state":"open","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"attacker/fork"}}}),
            json!({"state":"open","base":{"ref":"other","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}}),
        ] {
            assert!(!source_pr_matches(
                &invalid,
                "civitaspo/example",
                "main",
                "feature"
            ));
        }
    }

    #[test]
    fn workflow_path_accepts_github_ref_suffix_only_for_exact_allowed_files() {
        assert_eq!(
            normalize_source_workflow(CLIENT_CI_WORKFLOW),
            Some(CLIENT_CI_WORKFLOW)
        );
        assert_eq!(
            normalize_source_workflow(".github/workflows/pull_request.yml@refs/heads/feature"),
            Some(CLIENT_CI_WORKFLOW)
        );
        assert_eq!(
            normalize_source_workflow(".github/workflows/release-pr.yml@main"),
            Some(RELEASE_PR_WORKFLOW)
        );
        for invalid in [
            ".github/workflows/other.yml@main",
            ".github/workflows/pull_request.yml@",
            ".github/workflows/pull_request.yml@main@extra",
        ] {
            assert_eq!(normalize_source_workflow(invalid), None);
        }
    }

    #[test]
    fn release_pull_request_options_reject_extra_side_effects() {
        let valid = r#"{"title":"Release","base":"main","body":"release","draft":true}"#;
        assert!(validate_pull_request_options(valid, "main").is_ok());
        let with_label = r#"{"title":"Release","base":"main","labels":["release"]}"#;
        assert!(validate_pull_request_options(with_label, "main").is_err());
        let wrong_base = r#"{"title":"Release","base":"other"}"#;
        assert!(validate_pull_request_options(wrong_base, "main").is_err());
        assert!(
            validate_pull_request_options(r#"{"body":"missing required fields"}"#, "main").is_err()
        );
    }

    #[test]
    fn preparing_a_new_release_branch_records_that_it_must_be_created_at_source_head() {
        use crate::fixtures::{Fixture, Route};

        let repository = "civitaspo/dbt-authorized-models";
        let source_sha = "a".repeat(40);
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let fix = artifact::FixArtifact {
            repository: repository.into(),
            branch: "release/feature/2026-10".into(),
            run_id: 18,
            source_sha: source_sha.clone(),
            commit_message: "release".into(),
            create_pull_request: Some(json!({"title":"Release", "base":"main"}).to_string()),
            additions: std::collections::BTreeMap::from([("README.md".into(), b"x".to_vec())]),
            deletions: vec![],
        };
        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}"),
                json!({"default_branch":"main"}),
            ),
            Route::request(
                "GET",
                format!("/repos/{repository}/branches/release%2Ffeature%2F2026-10"),
                404,
                json!({"message":"Not Found"}),
            ),
        ]);

        assert_eq!(
            destination_head(
                &fixture.api,
                &SourceRequest {
                    repository,
                    run_id: 18,
                    label: "securefix-abc123",
                    branch: "main",
                    sha: &source_sha,
                },
                &fix,
                &None,
                &policy,
            )
            .unwrap(),
            DestinationHead {
                sha: source_sha,
                branch_exists: false,
                pull_request: None,
            }
        );
        fixture.finish();
    }

    #[test]
    fn release_pull_request_retry_reuses_only_the_server_bot_pr() {
        use crate::fixtures::{Fixture, Route};

        let repository = "civitaspo/dbt-authorized-models";
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let route = |id| {
            Route::get(
                format!(
                    "/repos/{repository}/pulls?head=civitaspo:release%2Ffeature&base=main&state=open&per_page=100"
                ),
                json!([{
                    "state":"open",
                    "number":42,
                    "user":{"id":id},
                    "head":{"ref":"release/feature","repo":{"full_name":repository}},
                    "base":{"ref":"main","repo":{"full_name":repository}}
                }]),
            )
        };
        let fixture = Fixture::new(vec![route(policy.server_bot_id)]);
        assert_eq!(
            release_pull_request(&fixture.api, &policy, repository, "release/feature", "main")
                .unwrap(),
            Some(42)
        );
        fixture.finish();

        let fixture = Fixture::new(vec![route(policy.client_bot_id)]);
        assert!(
            release_pull_request(&fixture.api, &policy, repository, "release/feature", "main")
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn release_comparison_rejects_truncated_or_untrusted_commits() {
        let trusted = json!({
            "total_commits": 1,
            "commits": [{
                "author":{"id":288069019},
                "commit":{"verification":{"verified":true}}
            }],
            "files":[{"filename":"README.md"}]
        });
        assert!(validate_release_comparison(&trusted, 288069019).is_ok());

        let mut truncated = trusted.clone();
        truncated["files"] = json!(vec![json!({"filename":"README.md"}); 300]);
        assert!(validate_release_comparison(&truncated, 288069019).is_err());

        let mut untrusted = trusted;
        untrusted["commits"][0]["commit"]["verification"]["verified"] = json!(false);
        assert!(validate_release_comparison(&untrusted, 288069019).is_err());
    }

    #[test]
    fn artifact_receipt_requires_server_authorship_and_exact_final_contents() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;

        let repository = "civitaspo/example";
        let head = "b".repeat(40);
        let source_sha = "a".repeat(40);
        let source = SourceRequest {
            repository,
            run_id: 7,
            label: "securefix-7-abcd",
            branch: "feature",
            sha: &source_sha,
        };
        let fix = artifact::FixArtifact {
            repository: repository.into(),
            branch: "feature".into(),
            run_id: 7,
            source_sha: source_sha.clone(),
            commit_message: "fix".into(),
            create_pull_request: None,
            additions: std::collections::BTreeMap::from([(
                "src/a.rs".into(),
                b"expected".to_vec(),
            )]),
            deletions: vec!["src/old.rs".into()],
        };
        let commit = |author_id| {
            json!({
                "author":{"id":author_id,"type":"Bot"},
                "commit":{
                    "verification":{"verified":true},
                    "message":format!("fix\n\nSecurefix-Artifact: {repository}/7/{}", source.label)
                },
                "parents":[{"sha":source_sha}],
                "files":[
                    {"filename":"src/a.rs","status":"modified"},
                    {"filename":"src/old.rs","status":"removed"}
                ]
            })
        };
        let contents_path = format!("/repos/{repository}/contents/src/a.rs?ref={head}");
        let content = |bytes: &[u8]| {
            json!({
                "encoding":"base64",
                "content":base64::engine::general_purpose::STANDARD.encode(bytes)
            })
        };

        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/{repository}/commits/{head}"),
            commit(288069018),
        )]);
        assert!(
            !has_artifact_receipt(
                &fixture.api,
                repository,
                &head,
                &source,
                Some(&source_sha),
                &fix,
                288069019
            )
            .unwrap()
        );
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/commits/{head}"),
                commit(288069019),
            ),
            Route::get(&contents_path, content(b"different")),
        ]);
        assert!(
            !has_artifact_receipt(
                &fixture.api,
                repository,
                &head,
                &source,
                Some(&source_sha),
                &fix,
                288069019
            )
            .unwrap()
        );
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/commits/{head}"),
                commit(288069019),
            ),
            Route::get(&contents_path, content(b"expected")),
            Route::get(
                format!("/repos/{repository}/contents/src/old.rs?ref={head}"),
                content(b"still present"),
            ),
        ]);
        assert!(
            !has_artifact_receipt(
                &fixture.api,
                repository,
                &head,
                &source,
                Some(&source_sha),
                &fix,
                288069019
            )
            .unwrap()
        );
        fixture.finish();

        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/commits/{head}"),
                commit(288069019),
            ),
            Route::get(&contents_path, content(b"expected")),
            Route::request(
                "GET",
                format!("/repos/{repository}/contents/src/old.rs?ref={head}"),
                404,
                json!({"message":"Not Found"}),
            ),
        ]);
        assert!(
            has_artifact_receipt(
                &fixture.api,
                repository,
                &head,
                &source,
                Some(&source_sha),
                &fix,
                288069019
            )
            .unwrap()
        );
        fixture.finish();
    }

    #[test]
    fn source_run_identity_accepts_running_or_failed_client_ci() {
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":123,
                "repository":{"full_name":"civitaspo/example"},
                "head_repository":{"full_name":"civitaspo/example"},
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion
            });
            assert!(validate_run_identity(&run, 123, "civitaspo/example").is_ok());
        }
        let fork = json!({
            "id":123,
            "repository":{"full_name":"civitaspo/example"},
            "head_repository":{"full_name":"attacker/example"},
            "run_attempt":1
        });
        assert!(validate_run_identity(&fork, 123, "civitaspo/example").is_err());
    }

    #[test]
    fn prepared_ci_run_accepts_in_progress_and_failed_runs_after_pr_head_advances() {
        use crate::fixtures::{Fixture, Route};

        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":17,
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion,
                "repository":{"full_name":"civitaspo/dotfiles"},
                "head_repository":{"full_name":"civitaspo/dotfiles"},
                "head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "head_branch":"ai/fix",
                "path":format!("{CLIENT_CI_WORKFLOW}@refs/heads/ai/fix"),
                "event":"pull_request",
                "pull_requests":[{"number":8}],
                "name":"Pull Request"
            });
            let current_pr = json!({
                "number":8,
                "state":"open",
                "base":{"ref":"main","repo":{"full_name":"civitaspo/dotfiles"}},
                "head":{"ref":"ai/fix","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"civitaspo/dotfiles"}}
            });
            let prepared = PreparedFix {
                client_repository: "civitaspo/dotfiles".into(),
                push_repository: "civitaspo/dotfiles".into(),
                branch: "ai/fix".into(),
                workflow_run: run.to_string(),
                pull_request: Some(current_pr.to_string()),
                create_pull_request: Some(String::new()),
            };
            let fixture = Fixture::new(vec![
                Route::get(
                    "/repos/civitaspo/dotfiles",
                    json!({"default_branch":"main"}),
                ),
                Route::get("/repos/civitaspo/dotfiles/pulls/8", current_pr),
            ]);
            assert_eq!(
                validate_prepared_source(
                    &fixture.api,
                    &policy,
                    "civitaspo/dotfiles",
                    17,
                    &prepared
                )
                .unwrap()
                .0,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            fixture.finish();
        }
    }

    #[test]
    fn prepared_release_run_accepts_pending_or_failed_run_with_pinned_provenance() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;

        let repository = "civitaspo/dbt-authorized-models";
        let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
        policy.revision = "a".repeat(40);
        let server_repository = crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository
            .clone();
        let source_sha = "b".repeat(40);
        let current_sha = source_sha.clone();
        let caller = format!(
            "jobs:\n  release:\n    uses: {server_repository}/{REUSABLE_RELEASE_PR}@{}\n",
            policy.revision
        );
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":18,
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion,
                "repository":{"full_name":repository},
                "head_repository":{"full_name":repository},
                "head_sha":source_sha,
                "head_branch":"main",
                "path":format!("{RELEASE_PR_WORKFLOW}@main"),
                "event":"push",
                "name":"Release PR",
                "referenced_workflows":[{
                    "path":format!("{server_repository}/{REUSABLE_RELEASE_PR}@{}", policy.revision),
                    "sha":policy.revision
                }]
            });
            let prepared = PreparedFix {
                client_repository: repository.into(),
                push_repository: repository.into(),
                branch: "release/feature/2026-10".into(),
                workflow_run: run.to_string(),
                pull_request: Some(String::new()),
                create_pull_request: Some(
                    json!({
                        "title":"chore(release): v1.2.3",
                        "body":"Release notes",
                        "base":"main",
                        "draft":false,
                        "labels":[],"assignees":[],"reviewers":[],"team_reviewers":[],
                        "automerge_method":"","comment":"","project":null
                    })
                    .to_string(),
                ),
            };
            let fixture = Fixture::new(vec![
                Route::get(
                    format!("/repos/{repository}"),
                    json!({"default_branch":"main"}),
                ),
                Route::get(
                    format!("/repos/{repository}/commits/main"),
                    json!({"sha":current_sha}),
                ),
                Route::get(
                    format!("/repos/{repository}/contents/{RELEASE_PR_WORKFLOW}?ref={source_sha}"),
                    json!({
                        "content":base64::engine::general_purpose::STANDARD.encode(&caller),
                        "encoding":"base64"
                    }),
                ),
            ]);
            assert_eq!(
                validate_prepared_source(&fixture.api, &policy, repository, 18, &prepared)
                    .unwrap()
                    .0,
                source_sha
            );
            fixture.finish();
        }
    }

    #[test]
    fn release_provenance_rejects_a_default_branch_advanced_after_the_run() {
        use crate::fixtures::{Fixture, Route};

        let repository = "civitaspo/dbt-authorized-models";
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let run = json!({"head_branch":"main"});
        let fixture = Fixture::new(vec![Route::get(
            format!("/repos/{repository}/commits/main"),
            json!({"sha":"c".repeat(40)}),
        )]);

        assert!(
            validate_release_provenance(&fixture.api, &policy, &run, repository, &"b".repeat(40),)
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn destination_must_be_same_repo_non_default_and_source_branch_for_prs() {
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "feature",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_ok()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "attacker/example",
                "feature",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_err()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "main",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_err()
        );
        for destination in ["feature/ai-fix", "release/next", "release/2026-q4"] {
            assert!(
                validate_destination(
                    "civitaspo/example",
                    "civitaspo/example",
                    destination,
                    "civitaspo/example",
                    "main",
                    "main"
                )
                .is_ok()
            );
        }
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "main",
                "civitaspo/example",
                "main",
                "main"
            )
            .is_err()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "other",
                "civitaspo/example",
                "feature/source",
                "main"
            )
            .is_err()
        );
    }
}
