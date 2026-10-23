use crate::{
    api::{ApiError, GitHub},
    config::{self, Checks},
    policy::{Capability, Policy, RepositoryPolicy, validate_repository},
    workflow::require_current_runtime,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const RULESET_DIR: &str = "repo-settings/rulesets";
const MANAGED_FILES_MANIFEST: &str = "repo-settings/managed-files.json";
const MANAGED_FILES_LIMIT: u64 = 1024 * 1024;
const MANAGED_INSTANCE_CONFIG_TARGET: &str = "securefix-server.toml";
const MANAGED_ACTIONS_LOCK_TARGET: &str = ".github/workflows/actions.lock";
const MANAGED_POLICY_CHECK_INSTANCE_CONFIG_PATH: &str =
    "repo-settings/native-role-events-test-instance.toml";
const MANAGED_POLICY_CHECK_CALLER_CONFIG_PATH: &str = MANAGED_POLICY_CHECK_INSTANCE_CONFIG_PATH;
const MANAGED_SECUREFIX_INSTANCE_CONFIG_PATH: &str =
    "repo-settings/native-securefix-write-test-instance.toml";
const MANAGED_POLICY_CHECK_SIGNER_PATH: &str = ".github/workflows/reusable-client-request.yml";
const MANAGED_POLICY_CHECK_WORKFLOW_PATH: &str = ".github/workflows/reusable-policy-check.yml";
const MANAGED_CLIENT_RELEASE_PR_TARGET: &str = ".github/workflows/release-pr.yml";
const MANAGED_CLIENT_RELEASE_SYNC_TARGET: &str = ".github/workflows/release-pr-sync.yml";
const MANAGED_CLIENT_RELEASE_TAG_TARGET: &str = ".github/workflows/release-tag.yml";
const MANAGED_CLIENT_POLICY_CHECK_TARGET: &str = ".github/workflows/policy-check.yml";
const MANAGED_CLIENT_APPROVE_TARGET: &str = ".github/workflows/approve-request.yml";
const MANAGED_CLIENT_MERGE_TARGET: &str = ".github/workflows/merge-request.yml";
const MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET: &str = ".github/workflows/securefix-request.yml";
const MANAGED_CLIENT_SECUREFIX_SIGNER_PATH: &str =
    ".github/workflows/reusable-client-request-scratch.yml";
const OBSERVED_LEGACY_POLICY_CHECK_SHA256: &str =
    "bc91f9c8993732f17a32ba17e95cdc6bbeba553ecf7fe3eeb7b467bf91086050";
const OBSERVED_PROBE_POLICY_CHECK_SHA256: &str =
    "deab228834396ec569705898264f5d10e0fe3e7fd11ebc3432e01d9c226a6faf";
const CLIENT_WORKFLOWS: &[(&str, &str)] = &[
    (
        ".github/workflows/merge-request.yml",
        "reusable-merge-request.yml",
    ),
    (
        ".github/workflows/approve-request.yml",
        "reusable-approve-request.yml",
    ),
    (
        ".github/workflows/policy-check.yml",
        "reusable-policy-check.yml",
    ),
];
#[derive(Subcommand)]
pub enum Command {
    Prepare,
    Reconcile {
        #[arg(long)]
        repository: String,
    },
    ActivationPreflight,
    ControlledMerges,
    ManagedPrepare {
        #[arg(long)]
        config_path: String,
        #[arg(long)]
        manifest_path: String,
    },
    ManagedReconcile {
        #[arg(long)]
        config_path: String,
        #[arg(long)]
        manifest_path: String,
    },
    ManagedRender {
        #[arg(long)]
        output_dir: PathBuf,
    },
    ManagedReconcileScratch {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        client_repository: Option<String>,
        #[arg(long)]
        client_implementation_sha: Option<String>,
        #[arg(long)]
        client_version: Option<String>,
    },
    ManagedValidateScratch {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        client_repository: Option<String>,
        #[arg(long)]
        client_implementation_sha: Option<String>,
        #[arg(long)]
        client_version: Option<String>,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Prepare => prepare(),
        Command::Reconcile { repository } => reconcile(&repository),
        Command::ActivationPreflight => activation_preflight(),
        Command::ControlledMerges => controlled_merges(),
        Command::ManagedRender { output_dir } => managed_render(&output_dir),
        Command::ManagedPrepare {
            config_path,
            manifest_path,
        } => {
            let prepared = load_managed_deployment(&config_path, &manifest_path)?;
            let (owner, name) = prepared
                .manifest
                .repository
                .split_once('/')
                .context("managed repository has no owner")?;
            crate::output("repository", &prepared.manifest.repository)?;
            crate::output("repo_owner", owner)?;
            crate::output("repo_name", name)?;
            crate::output(
                "server_app_id",
                prepared.instance.config.apps.server_id.to_string(),
            )
        }
        Command::ManagedReconcile {
            config_path,
            manifest_path,
        } => managed_reconcile(&config_path, &manifest_path),
        Command::ManagedReconcileScratch {
            source_sha,
            client_repository,
            client_implementation_sha,
            client_version,
        } => {
            let client_pin =
                client_pin(client_repository, client_implementation_sha, client_version)?;
            managed_reconcile_scratch(&source_sha, client_pin.as_ref())
        }
        Command::ManagedValidateScratch {
            source_sha,
            client_repository,
            client_implementation_sha,
            client_version,
        } => {
            let client_pin =
                client_pin(client_repository, client_implementation_sha, client_version)?;
            managed_validate_scratch(&source_sha, client_pin.as_ref())
        }
    }
}

fn client_pin(
    repository: Option<String>,
    implementation_sha: Option<String>,
    version: Option<String>,
) -> Result<Option<crate::distribution::caller::ClientImplementationPin>> {
    match (repository, implementation_sha, version) {
        (None, None, None) => Ok(None),
        (Some(repository), Some(sha), Some(version)) => Ok(Some(
            crate::distribution::caller::ClientImplementationPin::new(&repository, &sha, &version)?,
        )),
        _ => bail!("Client repository, implementation SHA, and version must be supplied together"),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedFilesManifest {
    repository: String,
    repository_id: u64,
    default_branch: String,
    files: Vec<ManagedFileEntry>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedFileEntry {
    source: String,
    target: String,
}

fn managed_desired_files() -> Result<(ManagedFilesManifest, BTreeMap<String, Vec<u8>>)> {
    let manifest_bytes = read_bounded_regular_file(MANAGED_FILES_MANIFEST)?;
    let manifest = parse_managed_manifest(&manifest_bytes)?;
    let mut desired = BTreeMap::new();
    for file in &manifest.files {
        desired.insert(
            file.target.clone(),
            read_bounded_regular_file(&file.source)?,
        );
    }
    let instance_config = validate_managed_instance_config(&manifest, &desired)?;
    validate_managed_targets(&manifest.files, &instance_config)?;
    validate_managed_removals(&manifest.remove, &instance_config)?;
    let policy_check_instance_config = if expected_managed_targets(&instance_config)
        .contains(MANAGED_CLIENT_POLICY_CHECK_TARGET)
    {
        Some(read_bounded_regular_file(
            MANAGED_POLICY_CHECK_INSTANCE_CONFIG_PATH,
        )?)
    } else {
        None
    };
    validate_managed_policy_check_caller(
        &manifest,
        &desired,
        &instance_config,
        policy_check_instance_config.as_deref(),
    )?;
    validate_managed_command_callers(
        &manifest,
        &desired,
        &instance_config,
        policy_check_instance_config.as_deref(),
    )?;
    let securefix_config = if expected_managed_targets(&instance_config)
        .contains(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET)
    {
        Some(read_bounded_regular_file(
            MANAGED_SECUREFIX_INSTANCE_CONFIG_PATH,
        )?)
    } else {
        None
    };
    validate_managed_securefix_request_caller(
        &manifest,
        &desired,
        &instance_config,
        securefix_config.as_deref(),
    )?;
    Ok((manifest, desired))
}

fn parse_managed_file_manifest(bytes: &[u8]) -> Result<ManagedFilesManifest> {
    ensure!(
        bytes.len() <= 32 * 1024,
        "managed-files manifest exceeds size limit"
    );
    let manifest: ManagedFilesManifest = serde_json::from_slice(bytes)?;
    validate_repository(&manifest.repository)?;
    config::validate_branch(&manifest.default_branch)?;
    ensure!(
        manifest.repository_id > 0 && !manifest.files.is_empty(),
        "managed-file identity or files missing"
    );
    let mut targets = BTreeSet::new();
    for file in &manifest.files {
        ensure!(
            file.source.starts_with("repo-settings/managed-files/")
                && safe_relative_path(&file.source),
            "managed-files manifest contains an unsafe source"
        );
        securefix::api::validate_native_managed_file_path(&file.target)?;
        ensure!(
            targets.insert(&file.target),
            "duplicate managed-file target"
        );
    }
    for path in &manifest.remove {
        securefix::api::validate_native_managed_file_path(path)?;
        ensure!(
            targets.insert(path),
            "duplicate or active managed-file removal"
        );
    }
    ensure!(
        targets.len() <= 1000,
        "managed-file target count exceeds bound"
    );
    Ok(manifest)
}

fn parse_managed_manifest(bytes: &[u8]) -> Result<ManagedFilesManifest> {
    let manifest = parse_managed_file_manifest(bytes)?;
    let scratch = &config::trusted()?.deployment.integration;
    ensure!(
        manifest.repository == scratch.repository && manifest.repository_id == scratch.id,
        "managed-files target differs from the configured scratch repository"
    );
    Ok(manifest)
}

fn validate_managed_instance_config(
    manifest: &ManagedFilesManifest,
    desired: &BTreeMap<String, Vec<u8>>,
) -> Result<securefix::instance_config::InstanceConfig> {
    let parsed_config = securefix::instance_config::InstanceConfig::parse(
        desired
            .get(MANAGED_INSTANCE_CONFIG_TARGET)
            .context("managed instance config missing")?,
    )?;
    ensure!(
        parsed_config.instance.repository == manifest.repository
            && parsed_config.instance.id == manifest.repository_id
            && parsed_config.instance.default_branch == manifest.default_branch,
        "managed instance config does not match its declared scratch target"
    );
    Ok(parsed_config)
}

fn validate_managed_targets(
    files: &[ManagedFileEntry],
    instance_config: &securefix::instance_config::InstanceConfig,
) -> Result<()> {
    let targets = files
        .iter()
        .map(|file| file.target.as_str())
        .collect::<BTreeSet<_>>();
    let expected = expected_managed_targets(instance_config);
    ensure!(
        files.len() == targets.len()
            && targets.len() == expected.len()
            && expected
                .iter()
                .all(|target| targets.contains(target.as_str())),
        "managed-files manifest must contain exactly the instance config, configured workflow roles, and capability-scoped Client callers"
    );
    for (target, source) in [
        (
            MANAGED_CLIENT_APPROVE_TARGET,
            "repo-settings/managed-files/approve-request.yml",
        ),
        (
            MANAGED_CLIENT_MERGE_TARGET,
            "repo-settings/managed-files/merge-request.yml",
        ),
    ] {
        if expected.contains(target) {
            ensure!(
                files
                    .iter()
                    .any(|file| file.target == target && file.source == source),
                "managed command caller must use its canonical desired-state source"
            );
            ensure!(
                !instance_config
                    .workflow_roles
                    .values()
                    .any(|path| path == target),
                "managed command caller collides with a Server role"
            );
        }
    }
    for (target, source) in [
        (
            MANAGED_CLIENT_RELEASE_TAG_TARGET,
            "repo-settings/managed-files/release-tag.yml",
        ),
        (
            MANAGED_CLIENT_RELEASE_PR_TARGET,
            "repo-settings/managed-files/release-pr.yml",
        ),
        (
            MANAGED_CLIENT_RELEASE_SYNC_TARGET,
            "repo-settings/managed-files/release-pr-sync.yml",
        ),
    ] {
        if expected.contains(target) {
            ensure!(
                files
                    .iter()
                    .any(|file| file.target == target && file.source == source),
                "managed Client release caller must use its canonical desired-state source"
            );
            ensure!(
                !instance_config
                    .workflow_roles
                    .values()
                    .any(|role| role == target),
                "managed Client release caller collides with a Server role"
            );
        }
    }
    if expected.contains(MANAGED_CLIENT_POLICY_CHECK_TARGET) {
        ensure!(
            files.iter().any(|file| {
                file.target == MANAGED_CLIENT_POLICY_CHECK_TARGET
                    && file.source == "repo-settings/managed-files/policy-check.yml"
            }),
            "managed Client policy-check caller must use its canonical desired-state source"
        );
        ensure!(
            !instance_config
                .workflow_roles
                .values()
                .any(|path| path == MANAGED_CLIENT_POLICY_CHECK_TARGET),
            "managed Client policy-check caller collides with an instance workflow role"
        );
    }
    if expected.contains(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET) {
        ensure!(
            files.iter().any(|file| {
                file.target == MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET
                    && file.source == "repo-settings/managed-files/securefix-request.yml"
            }),
            "managed Client Securefix request must use its canonical desired-state source"
        );
        ensure!(
            !instance_config
                .workflow_roles
                .values()
                .any(|path| path == MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET),
            "managed Client Securefix request caller collides with an instance workflow role"
        );
    }
    Ok(())
}

fn expected_managed_targets(
    instance_config: &securefix::instance_config::InstanceConfig,
) -> BTreeSet<String> {
    use securefix::policy::Capability;

    let mut expected = [MANAGED_INSTANCE_CONFIG_TARGET, MANAGED_ACTIONS_LOCK_TARGET]
        .into_iter()
        .map(str::to_owned)
        .chain(instance_config.workflow_roles.values().cloned())
        .collect::<BTreeSet<_>>();
    if instance_config
        .repositories
        .iter()
        .any(|repository| repository.capabilities.contains(&Capability::Approve))
    {
        expected.insert(MANAGED_CLIENT_APPROVE_TARGET.to_owned());
    }
    if instance_config
        .repositories
        .iter()
        .any(|repository| repository.capabilities.contains(&Capability::Release))
    {
        expected.extend(
            [
                MANAGED_CLIENT_RELEASE_TAG_TARGET,
                MANAGED_CLIENT_RELEASE_PR_TARGET,
                MANAGED_CLIENT_RELEASE_SYNC_TARGET,
            ]
            .map(str::to_owned),
        );
    }
    if instance_config
        .repositories
        .iter()
        .any(|repository| repository.capabilities.contains(&Capability::Merge))
    {
        expected.insert(MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned());
        expected.insert(MANAGED_CLIENT_MERGE_TARGET.to_owned());
    }
    if instance_config
        .repositories
        .iter()
        .any(|repository| repository.capabilities.contains(&Capability::Securefix))
    {
        expected.insert(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET.to_owned());
    }
    expected
}

fn validate_managed_removals(
    removals: &[String],
    instance_config: &securefix::instance_config::InstanceConfig,
) -> Result<()> {
    let managed_targets = expected_managed_targets(instance_config);
    let mut seen = BTreeSet::new();
    for target in removals {
        let Some(name) = target.strip_prefix(".github/workflows/") else {
            bail!("managed-file removal is not a workflow path: {target}");
        };
        ensure!(
            safe_relative_path(target) && !name.contains('/') && name.ends_with(".yml"),
            "managed-file removal is not a canonical workflow file: {target}"
        );
        ensure!(
            !managed_targets
                .iter()
                .any(|path| path.eq_ignore_ascii_case(target)),
            "managed-file removal targets a currently managed file: {target}"
        );
        ensure!(
            seen.insert(target.to_ascii_lowercase()),
            "managed-files manifest contains duplicate removals"
        );
    }
    Ok(())
}

fn validate_managed_pr_files(files: &[Value], expected_changed: &BTreeSet<String>) -> Result<()> {
    let mut changed = BTreeSet::new();
    for file in files {
        let filename = file["filename"]
            .as_str()
            .context("managed-files PR response has no filename")?;
        ensure!(
            safe_relative_path(filename),
            "managed-files PR response contains an unsafe filename"
        );
        let status = file["status"]
            .as_str()
            .context("managed-files PR response has no status")?;
        ensure!(
            changed.insert(filename.to_owned()),
            "managed-files PR response contains duplicate paths"
        );
        match status {
            "added" | "modified" | "removed" => {
                ensure!(
                    file.get("previous_filename").is_none(),
                    "non-renamed managed file has a previous filename"
                );
            }
            "renamed" => {
                let previous_filename = file["previous_filename"]
                    .as_str()
                    .context("renamed managed file has no previous filename")?;
                ensure!(
                    safe_relative_path(previous_filename)
                        && previous_filename != filename
                        && changed.insert(previous_filename.to_owned()),
                    "managed-files PR response contains an invalid or duplicate rename source"
                );
            }
            _ => bail!("managed-files PR response has an unsupported file status"),
        }
    }
    ensure!(
        &changed == expected_changed,
        "managed-files PR contains files outside the exact desired-state set"
    );
    Ok(())
}

fn workflow_role_slug(role: securefix::instance_config::WorkflowRole) -> &'static str {
    use securefix::instance_config::WorkflowRole;
    match role {
        WorkflowRole::Approve => "approve",
        WorkflowRole::Merge => "merge",
        WorkflowRole::PolicyCheck => "policy-check",
        WorkflowRole::Release => "release",
        WorkflowRole::Securefix => "securefix",
        WorkflowRole::Settings => "settings",
    }
}

fn workflow_role_name(role: securefix::instance_config::WorkflowRole) -> &'static str {
    use securefix::instance_config::WorkflowRole;
    match role {
        WorkflowRole::Approve => "Approve",
        WorkflowRole::Merge => "Merge",
        WorkflowRole::PolicyCheck => "Policy Check",
        WorkflowRole::Release => "Release",
        WorkflowRole::Securefix => "Securefix",
        WorkflowRole::Settings => "Repository settings",
    }
}

fn validate_rendered_managed_role_workflow(
    role: securefix::instance_config::WorkflowRole,
    expected_uses: &str,
    instance_config: &securefix::instance_config::InstanceConfig,
    bytes: &[u8],
) -> Result<()> {
    let role_slug = workflow_role_slug(role);
    let release_prefix = if role == securefix::instance_config::WorkflowRole::Release {
        instance_config.release_request_label_prefix.as_str()
    } else {
        ""
    };
    let mut secrets = json!({
        "SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
    });
    if role == securefix::instance_config::WorkflowRole::Approve {
        secrets["APPROVAL_TOKEN"] = json!("${{ secrets.CIVITASPO_BOT_PR_APPROVE_TOKEN }}");
    }
    let mut expected: serde_yaml::Value = serde_yaml::to_value(json!({
        "name": format!("Securefix server {}", workflow_role_name(role)),
        "on": {"label": {"types": ["created"]}},
        "permissions": {},
        "jobs": {"handler": {
            "if": format!("startsWith(github.event.label.name, '{release_prefix}securefix-native-{role_slug}-')"),
            "permissions": {
                "actions": "read",
                "attestations": "read",
                "checks": "read",
                "contents": "read",
                "issues": "read",
                "pull-requests": "read",
                "statuses": "read"
            },
            "uses": expected_uses,
            "with": {"config_path": "securefix-server.toml"},
            "secrets": secrets
        }}
    }))?;
    if matches!(
        role,
        securefix::instance_config::WorkflowRole::Approve
            | securefix::instance_config::WorkflowRole::Merge
            | securefix::instance_config::WorkflowRole::Securefix
    ) {
        expected["jobs"]["handler"]["concurrency"] = serde_yaml::to_value(json!({
            "group": "securefix-control", "cancel-in-progress": false, "queue": "max"
        }))?;
    }
    if role == securefix::instance_config::WorkflowRole::Release {
        expected["jobs"]["handler"]["if"] = serde_yaml::to_value(format!(
            "startsWith(github.event.label.name, '{release_prefix}securefix-native-release-') || startsWith(github.event.label.name, 'securefix-native-release-prepare-')"
        ))?;
        expected["jobs"]["handler"]["permissions"]["issues"] = serde_yaml::to_value("write")?;
    }
    let actual: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    ensure!(
        actual == expected,
        "managed role workflow has an unexpected trigger, permission, input, secret, or job: {}",
        workflow_role_slug(role)
    );
    Ok(())
}

fn render_managed_role_workflows(
    desired: &mut BTreeMap<String, Vec<u8>>,
    instance_config: &securefix::instance_config::InstanceConfig,
    server_repository: &str,
    source_sha: &str,
    runtime_version: &str,
) -> Result<()> {
    crate::policy::validate_sha(source_sha)?;
    validate_repository(server_repository)?;
    for (role, path) in &instance_config.workflow_roles {
        let bytes = desired
            .get_mut(path)
            .with_context(|| format!("managed role workflow is missing: {path}"))?;
        let template = std::str::from_utf8(bytes)
            .with_context(|| format!("managed role workflow is not UTF-8: {path}"))?;
        for placeholder in [
            "@SERVER_REPOSITORY@",
            "@SECUREFIX_RUNTIME_SHA@",
            "@RUNTIME_VERSION@",
        ] {
            ensure!(
                template.matches(placeholder).count() == 1,
                "managed role workflow must contain exactly one {placeholder}: {path}"
            );
        }
        let release_prefix_placeholder = "@RELEASE_REQUEST_LABEL_PREFIX@";
        if *role == securefix::instance_config::WorkflowRole::Release {
            ensure!(
                template.matches(release_prefix_placeholder).count() == 1,
                "managed release workflow must contain exactly one {release_prefix_placeholder}: {path}"
            );
        } else {
            ensure!(
                !template.contains(release_prefix_placeholder),
                "non-release managed workflow contains {release_prefix_placeholder}: {path}"
            );
        }
        let role_slug = workflow_role_slug(*role);
        let expected_uses = format!(
            "{server_repository}/.github/workflows/reusable-server-{role_slug}.yml@{source_sha}"
        );
        let rendered = template
            .replace("@SERVER_REPOSITORY@", server_repository)
            .replace("@SECUREFIX_RUNTIME_SHA@", source_sha)
            .replace("@RUNTIME_VERSION@", runtime_version)
            .replace(
                release_prefix_placeholder,
                &instance_config.release_request_label_prefix,
            );
        ensure!(
            !rendered.contains("@SERVER_REPOSITORY@")
                && !rendered.contains("@SECUREFIX_RUNTIME_SHA@")
                && !rendered.contains("@RUNTIME_VERSION@")
                && !rendered.contains(release_prefix_placeholder),
            "managed role workflow contains an unresolved placeholder: {path}"
        );
        validate_rendered_managed_role_workflow(
            *role,
            &expected_uses,
            instance_config,
            rendered.as_bytes(),
        )
        .with_context(|| format!("invalid managed role workflow: {path}"))?;
        *bytes = rendered.into_bytes();
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0', '\r', '\n'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn read_bounded_regular_file(path: &str) -> Result<Vec<u8>> {
    ensure!(safe_relative_path(path), "unsafe managed-file path");
    let mut current = PathBuf::new();
    for component in Path::new(path).components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("stat {}", current.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "managed-file path contains a symlink: {path}"
        );
        if current == Path::new(path) {
            ensure!(
                metadata.is_file(),
                "managed-file source is not a regular file: {path}"
            );
            ensure!(
                metadata.len() <= MANAGED_FILES_LIMIT,
                "managed-file source exceeds size limit: {path}"
            );
        }
    }
    let bytes = fs::read(path).with_context(|| format!("read {path}"))?;
    ensure!(
        bytes.len() as u64 <= MANAGED_FILES_LIMIT,
        "managed-file source exceeds size limit: {path}"
    );
    Ok(bytes)
}

fn managed_changes(
    desired: &BTreeMap<String, Vec<u8>>,
    current: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, Vec<u8>> {
    desired
        .iter()
        .filter(|(path, bytes)| current.get(*path) != Some(*bytes))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect()
}

fn workflow_uses(bytes: &[u8]) -> Result<BTreeSet<String>> {
    fn collect(value: &serde_yaml::Value, output: &mut BTreeSet<String>) -> Result<()> {
        match value {
            serde_yaml::Value::Mapping(mapping) => {
                for (key, child) in mapping {
                    if key.as_str() == Some("uses") {
                        output.insert(
                            child
                                .as_str()
                                .context("workflow uses value is not a string")?
                                .to_owned(),
                        );
                    }
                    collect(child, output)?;
                }
            }
            serde_yaml::Value::Sequence(values) => {
                for value in values {
                    collect(value, output)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let workflow: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    let mut uses = BTreeSet::new();
    collect(&workflow, &mut uses)?;
    Ok(uses)
}

fn validate_managed_policy_check_caller(
    manifest: &ManagedFilesManifest,
    desired: &BTreeMap<String, Vec<u8>>,
    instance_config: &securefix::instance_config::InstanceConfig,
    policy_check_instance_config_bytes: Option<&[u8]>,
) -> Result<()> {
    if !expected_managed_targets(instance_config).contains(MANAGED_CLIENT_POLICY_CHECK_TARGET) {
        return Ok(());
    }

    let policy_check_instance_config = securefix::instance_config::InstanceConfig::parse(
        policy_check_instance_config_bytes.context(
            "managed Client policy-check instance config is missing from candidate source",
        )?,
    )?;
    let server = &config::trusted()?.deployment.server;
    ensure!(
        policy_check_instance_config.instance.repository == server.repository
            && policy_check_instance_config.instance.id == server.id
            && policy_check_instance_config.instance.default_branch == server.default_branch,
        "managed Client policy-check instance config does not match the protected Server identity"
    );
    ensure!(
        policy_check_instance_config.acceptable_clients.repository
            == instance_config.acceptable_clients.repository
            && policy_check_instance_config.acceptable_clients.id
                == instance_config.acceptable_clients.id
            && policy_check_instance_config
                .acceptable_clients
                .version
                .to_string()
                == instance_config.acceptable_clients.version.to_string()
            && policy_check_instance_config.identities.owner.id
                == instance_config.identities.owner.id
            && policy_check_instance_config.identities.owner.login
                == instance_config.identities.owner.login,
        "managed Client policy-check test config disagrees with the managed scratch instance"
    );
    ensure!(
        policy_check_instance_config
            .acceptable_clients
            .producer_workflow
            == MANAGED_POLICY_CHECK_SIGNER_PATH,
        "managed Client policy-check test config must select the configured reusable Client signer"
    );
    ensure!(
        policy_check_instance_config
            .repositories
            .iter()
            .any(|repository| {
                repository.repository == manifest.repository
                    && repository.id == manifest.repository_id
                    && repository.capabilities.contains(&Capability::Merge)
            }),
        "managed Client policy-check instance config does not authorize the scratch merge target"
    );

    let bytes = desired
        .get(MANAGED_CLIENT_POLICY_CHECK_TARGET)
        .context("managed Client policy-check caller is missing")?;
    let mut workflow: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    // serde_yaml follows YAML 1.1 and parses GitHub Actions' `on` key as true.
    if let Some(mapping) = workflow.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    let workflow = serde_json::to_value(workflow)?;
    let workflow_keys = workflow
        .as_object()
        .context("managed Client policy-check workflow is not a mapping")?;
    ensure!(
        workflow_keys.len() == 4
            && workflow_keys.contains_key("name")
            && workflow_keys.contains_key("on")
            && workflow_keys.contains_key("permissions")
            && workflow_keys.contains_key("jobs")
            && workflow["name"].as_str().is_some(),
        "managed Client policy-check workflow has unexpected top-level fields"
    );
    let triggers = workflow["on"]
        .as_object()
        .context("managed Client policy-check workflow has no trigger mapping")?;
    ensure!(
        triggers.len() == 1
            && workflow["on"]["pull_request_target"]["types"]
                == json!(["opened", "synchronize", "reopened", "ready_for_review"]),
        "managed Client policy-check workflow must use only the canonical pull_request_target event"
    );
    ensure!(
        workflow["permissions"] == json!({}),
        "managed Client policy-check workflow must default to no permissions"
    );

    let jobs = workflow["jobs"]
        .as_object()
        .context("managed Client policy-check workflow has no jobs mapping")?;
    ensure!(
        jobs.len() == 1,
        "managed Client policy-check workflow has extra jobs"
    );
    let job = &workflow["jobs"]["check"];
    let job_fields = job
        .as_object()
        .context("managed Client policy-check producer is not a mapping")?;
    ensure!(
        job_fields.len() == 5
            && job_fields.contains_key("if")
            && job_fields.contains_key("uses")
            && job_fields.contains_key("with")
            && job_fields.contains_key("permissions")
            && job_fields.contains_key("secrets"),
        "managed Client policy-check producer has unexpected fields"
    );

    let owner_id = policy_check_instance_config.identities.owner.id;
    let expected_condition = format!(
        "github.repository == '{}' && github.event.pull_request.base.repo.id == {} && (github.event.pull_request.user.id == {} || github.event.pull_request.user.id == {}) && github.run_attempt == 1",
        manifest.repository,
        manifest.repository_id,
        owner_id,
        policy_check_instance_config.identities.server_bot.id
    );
    ensure!(
        job["if"].as_str() == Some(expected_condition.as_str()),
        "managed Client policy-check producer must be restricted to configured owner or Server PRs in the scratch repository"
    );
    let reusable_prefix = format!(
        "{}/{}@",
        policy_check_instance_config.acceptable_clients.repository,
        MANAGED_POLICY_CHECK_WORKFLOW_PATH
    );
    let uses = job["uses"]
        .as_str()
        .context("managed Client policy-check producer has no reusable workflow pin")?;
    let reusable_sha = uses
        .strip_prefix(&reusable_prefix)
        .context("managed Client policy-check producer uses an unexpected reusable workflow")?;
    crate::policy::validate_sha(reusable_sha)?;

    let inputs = job["with"]
        .as_object()
        .context("managed Client policy-check producer has no input mapping")?;
    ensure!(
        inputs.len() == 2
            && inputs["server_repository"] == policy_check_instance_config.instance.repository
            && inputs["instance_config_path"] == MANAGED_POLICY_CHECK_CALLER_CONFIG_PATH,
        "managed Client policy-check producer has unexpected request inputs"
    );
    ensure!(
        job["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"]
            == "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}",
        "managed Client policy-check caller must forward only the configured Client App key"
    );
    ensure!(
        job["permissions"]
            == json!({
                "actions": "read",
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
                "issues": "read",
                "pull-requests": "read"
            }),
        "managed Client policy-check producer permissions changed"
    );
    Ok(())
}

fn validate_managed_command_callers(
    manifest: &ManagedFilesManifest,
    desired: &BTreeMap<String, Vec<u8>>,
    instance_config: &securefix::instance_config::InstanceConfig,
    config_bytes: Option<&[u8]>,
) -> Result<()> {
    let targets = expected_managed_targets(instance_config);
    for (role, operation, target) in [
        ("approve", "approval", MANAGED_CLIENT_APPROVE_TARGET),
        ("merge", "merge", MANAGED_CLIENT_MERGE_TARGET),
    ] {
        if !targets.contains(target) {
            continue;
        }
        let config = securefix::instance_config::InstanceConfig::parse(
            config_bytes.context("managed command caller Server config is missing")?,
        )?;
        ensure!(
            config.allows_scratch_request_caller(
                &manifest.repository,
                manifest.repository_id,
                target,
                "refs/heads/main",
                "issue_comment",
                operation,
            ),
            "managed command caller is not authorized by its exact scratch scope"
        );
        let workflow: serde_yaml::Value = serde_yaml::from_slice(
            desired
                .get(target)
                .context("managed command caller is missing")?,
        )?;
        let uses = workflow["jobs"]["request"]["uses"]
            .as_str()
            .context("managed command caller has no implementation pin")?;
        let prefix = format!(
            "{}/.github/workflows/reusable-{role}-request.yml@",
            config.acceptable_clients.repository
        );
        crate::policy::validate_sha(
            uses.strip_prefix(&prefix)
                .context("managed command caller uses an unexpected implementation")?,
        )?;
        let expected: serde_yaml::Value = serde_yaml::to_value(json!({
            "name": format!("testing-{} Request", if role == "approve" { "Approve" } else { "Merge" }),
            "on": {"issue_comment": {"types": ["created"]}},
            "permissions": {},
            "jobs": {"request": {
                "if": format!("github.repository == '{}' && github.event.issue.pull_request && github.event.comment.user.id == {} && github.event.comment.body == '/{role}' && github.run_attempt == 1", manifest.repository, config.identities.owner.id),
                "uses": uses,
                "with": {"server_repository": config.instance.repository, "instance_config_path": MANAGED_POLICY_CHECK_INSTANCE_CONFIG_PATH},
                "permissions": {"actions": "read", "attestations": "write", "contents": "read", "id-token": "write", "issues": "read", "pull-requests": "read"},
                "secrets": {"SECUREFIX_CLIENT_PRIVATE_KEY": "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"}
            }}
        }))?;
        ensure!(
            workflow == expected,
            "managed command caller has an unexpected event, condition, input, credential or permission"
        );
    }
    Ok(())
}

fn validate_managed_securefix_request_caller(
    manifest: &ManagedFilesManifest,
    desired: &BTreeMap<String, Vec<u8>>,
    instance_config: &securefix::instance_config::InstanceConfig,
    securefix_config_bytes: Option<&[u8]>,
) -> Result<()> {
    if !expected_managed_targets(instance_config).contains(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET)
    {
        return Ok(());
    }
    let securefix_config = securefix::instance_config::InstanceConfig::parse(
        securefix_config_bytes.context("managed Securefix Server instance config is missing")?,
    )?;
    let server = &config::trusted()?.deployment.server;
    ensure!(
        securefix_config.instance.repository == server.repository
            && securefix_config.instance.id == server.id
            && securefix_config.instance.default_branch == server.default_branch
            && securefix_config.identities.owner.id == instance_config.identities.owner.id
            && securefix_config.identities.owner.login == instance_config.identities.owner.login
            && securefix_config.acceptable_clients.repository
                == instance_config.acceptable_clients.repository
            && securefix_config.acceptable_clients.id == instance_config.acceptable_clients.id
            && securefix_config.acceptable_clients.version
                == instance_config.acceptable_clients.version,
        "managed Securefix Server config identity or Client acceptance differs"
    );
    ensure!(
        securefix_config
            .repositories
            .iter()
            .any(|repository| repository.repository == manifest.repository
                && repository.id == manifest.repository_id
                && repository.capabilities.contains(&Capability::Securefix)),
        "managed Securefix Server config does not authorize the target"
    );
    ensure!(
        securefix_config.acceptable_clients.producer_workflow
            == MANAGED_CLIENT_SECUREFIX_SIGNER_PATH,
        "managed Client Securefix request must select the dedicated scratch signer"
    );
    ensure!(
        securefix_config.allows_scratch_request_caller(
            &manifest.repository,
            manifest.repository_id,
            MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET,
            "refs/heads/main",
            "pull_request_target",
            "securefix",
        ),
        "managed Client Securefix request is not authorized by the exact scratch caller tuple"
    );
    let bytes = desired
        .get(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET)
        .context("managed Client Securefix request caller is missing")?;
    let workflow: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    let uses = workflow["jobs"]["request"]["uses"]
        .as_str()
        .context("managed Securefix caller has no workflow pin")?;
    let prefix = format!(
        "{}/{}@",
        securefix_config.acceptable_clients.repository, MANAGED_CLIENT_SECUREFIX_SIGNER_PATH
    );
    crate::policy::validate_sha(
        uses.strip_prefix(&prefix)
            .context("managed Securefix caller has an unexpected implementation")?,
    )?;
    let expected_uses = uses.to_owned();
    let mut workflow = workflow;
    if let Some(mapping) = workflow.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    let workflow = serde_json::to_value(workflow)?;
    let owner_id = instance_config.identities.owner.id;
    let expected_condition = format!(
        "github.repository == '{}' && github.event.pull_request.base.repo.id == {} && github.event.pull_request.head.repo.id == {} && github.event.pull_request.user.id == {} && github.event.pull_request.base.ref == '{}' && github.event.pull_request.state == 'open' && github.actor_id == '{}' && github.event.label.name == 'securefix-native-write-probe' && github.run_attempt == 1",
        manifest.repository,
        manifest.repository_id,
        manifest.repository_id,
        owner_id,
        manifest.default_branch,
        owner_id,
    );
    let expected = json!({
        "name": "testing-Native Securefix request",
        "on": {"pull_request_target": {"types": ["labeled"]}},
        "permissions": {},
        "jobs": {"request": {
            "if": expected_condition,
            "uses": expected_uses,
            "with": {
                "server_repository": securefix_config.instance.repository,
                "instance_config_path": MANAGED_SECUREFIX_INSTANCE_CONFIG_PATH,
            },
            "permissions": {
                "actions": "read",
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
                "issues": "read",
                "pull-requests": "read",
            },
            "secrets": {
                "SECUREFIX_CLIENT_PRIVATE_KEY": "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
            }
        }}
    });
    ensure!(
        workflow == expected,
        "managed Client Securefix request has an unexpected trigger, permission, input, secret, or job"
    );
    Ok(())
}

fn validate_supported_pin_state(path: &str, current: &[u8], desired: &[u8]) -> Result<()> {
    if path == MANAGED_CLIENT_POLICY_CHECK_TARGET {
        let current_sha256 = crate::hex_encode(sha2::Sha256::digest(current));
        if current_sha256 == OBSERVED_LEGACY_POLICY_CHECK_SHA256
            || current_sha256 == OBSERVED_PROBE_POLICY_CHECK_SHA256
        {
            return Ok(());
        }
        ensure!(
            workflow_uses(current)? == workflow_uses(desired)?,
            "managed workflow action or reusable-workflow pins changed; refusing to replace them"
        );
    }
    Ok(())
}

fn managed_render(output_dir: &Path) -> Result<()> {
    ensure!(
        !output_dir.exists(),
        "managed render output directory already exists"
    );
    let (_, desired) = managed_desired_files()?;
    let file_count = desired.len();
    for (path, bytes) in desired {
        let output = output_dir.join(&path);
        fs::create_dir_all(output.parent().context("managed output has no parent")?)?;
        fs::write(output, bytes)?;
    }
    println!("rendered {file_count} managed files");
    Ok(())
}

fn managed_desired_files_from_source(
    source_sha: &str,
    client_pin: Option<&crate::distribution::caller::ClientImplementationPin>,
) -> Result<(ManagedFilesManifest, BTreeMap<String, Vec<u8>>)> {
    crate::policy::validate_sha(source_sha)?;
    let trusted = config::trusted()?;
    let source_repository = &trusted.deployment.server.repository;
    let source_api = GitHub::from_env("GITHUB_TOKEN")?;
    let commit: Value =
        source_api.get(&format!("/repos/{source_repository}/commits/{source_sha}"))?;
    ensure!(
        commit["sha"].as_str() == Some(source_sha),
        "managed-files source commit changed"
    );
    let tree_sha = commit["commit"]["tree"]["sha"]
        .as_str()
        .context("candidate source commit has no tree SHA")?;
    crate::policy::validate_sha(tree_sha)?;
    let tree: Value = source_api.get(&format!(
        "/repos/{source_repository}/git/trees/{tree_sha}?recursive=1"
    ))?;
    ensure!(
        tree["truncated"] == false,
        "candidate source tree was truncated"
    );
    let tree_entries = tree["tree"]
        .as_array()
        .context("candidate source tree entries are missing")?;
    let mut entries = BTreeMap::new();
    for entry in tree_entries {
        if let Some(path) = entry["path"].as_str() {
            ensure!(
                entries.insert(path.to_owned(), entry.clone()).is_none(),
                "candidate source tree has duplicate paths"
            );
        }
    }
    let manifest_bytes = read_managed_source_file(
        &source_api,
        source_repository,
        source_sha,
        &entries,
        MANAGED_FILES_MANIFEST,
    )?;
    let manifest = parse_managed_manifest(&manifest_bytes)?;
    let mut desired = BTreeMap::new();
    for file in &manifest.files {
        desired.insert(
            file.target.clone(),
            read_managed_source_file(
                &source_api,
                source_repository,
                source_sha,
                &entries,
                &file.source,
            )?,
        );
    }
    let instance_config = validate_managed_instance_config(&manifest, &desired)?;
    validate_managed_targets(&manifest.files, &instance_config)?;
    validate_managed_removals(&manifest.remove, &instance_config)?;
    let targets = expected_managed_targets(&instance_config);
    let policy_check_instance_config_bytes = if targets.contains(MANAGED_CLIENT_POLICY_CHECK_TARGET)
        || targets.contains(MANAGED_CLIENT_RELEASE_TAG_TARGET)
    {
        Some(read_managed_source_file(
            &source_api,
            source_repository,
            source_sha,
            &entries,
            MANAGED_POLICY_CHECK_INSTANCE_CONFIG_PATH,
        )?)
    } else {
        None
    };
    validate_managed_policy_check_caller(
        &manifest,
        &desired,
        &instance_config,
        policy_check_instance_config_bytes.as_deref(),
    )?;
    validate_managed_command_callers(
        &manifest,
        &desired,
        &instance_config,
        policy_check_instance_config_bytes.as_deref(),
    )?;
    let securefix_config = if expected_managed_targets(&instance_config)
        .contains(MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET)
    {
        Some(read_managed_source_file(
            &source_api,
            source_repository,
            source_sha,
            &entries,
            MANAGED_SECUREFIX_INSTANCE_CONFIG_PATH,
        )?)
    } else {
        None
    };
    validate_managed_securefix_request_caller(
        &manifest,
        &desired,
        &instance_config,
        securefix_config.as_deref(),
    )?;
    for role in instance_config.workflow_roles.keys() {
        let receiver = format!(
            ".github/workflows/reusable-server-{}.yml",
            workflow_role_slug(*role)
        );
        let bytes = read_managed_source_file(
            &source_api,
            source_repository,
            source_sha,
            &entries,
            &receiver,
        )?;
        let yaml = std::str::from_utf8(&bytes)
            .with_context(|| format!("Server role implementation is not UTF-8: {receiver}"))?;
        ensure!(
            yaml.contains("workflow_call:"),
            "Server role implementation is not reusable: {receiver}"
        );
    }
    let runtime_version = format!("v{} (candidate source)", env!("CARGO_PKG_VERSION"));
    render_managed_role_workflows(
        &mut desired,
        &instance_config,
        source_repository,
        source_sha,
        &runtime_version,
    )?;
    let has_client_release_caller =
        expected_managed_targets(&instance_config).contains(MANAGED_CLIENT_RELEASE_TAG_TARGET);
    ensure!(
        has_client_release_caller == client_pin.is_some(),
        "a Client release implementation pin is required exactly when the managed target includes release-tag.yml"
    );
    if let Some(client_pin) = client_pin {
        let server_config = securefix::instance_config::InstanceConfig::parse(
            policy_check_instance_config_bytes
                .as_deref()
                .context("managed Release Tag approval authority config is missing")?,
        )?;
        for target in [
            MANAGED_CLIENT_RELEASE_TAG_TARGET,
            MANAGED_CLIENT_RELEASE_PR_TARGET,
            MANAGED_CLIENT_RELEASE_SYNC_TARGET,
        ] {
            let template = desired
                .get_mut(target)
                .context("managed Client release caller is missing")?;
            *template =
                render_managed_release_tag(&manifest, &server_config, client_pin, template)?;
        }
    }
    Ok((manifest, desired))
}

fn render_managed_release_tag(
    manifest: &ManagedFilesManifest,
    server_config: &securefix::instance_config::InstanceConfig,
    pin: &crate::distribution::caller::ClientImplementationPin,
    template: &[u8],
) -> Result<Vec<u8>> {
    let server = &config::trusted()?.deployment.server;
    ensure!(
        server_config.instance.repository == server.repository
            && server_config.instance.id == server.id
            && server_config.instance.default_branch == server.default_branch,
        "managed Release Tag must use the protected approval Server instance"
    );
    server_config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == manifest.repository && repository.id == manifest.repository_id
        })
        .context("managed Release Tag target is not configured in its approval Server")?
        .policy()
        .require(Capability::Release)?;
    let template = std::str::from_utf8(template)?
        .replace("@DEFAULT_BRANCH@", &manifest.default_branch)
        .replace(
            "@RELEASE_BRANCH@",
            server_config
                .branches
                .release
                .as_deref()
                .context("managed release branch missing")?,
        );
    crate::distribution::caller::render_managed_client_release_tag_from_template(
        &server_config.acceptable_clients,
        pin,
        &server_config.instance.repository,
        MANAGED_POLICY_CHECK_CALLER_CONFIG_PATH,
        template.as_bytes(),
    )
}

fn managed_validate_scratch(
    candidate_sha: &str,
    client_pin: Option<&crate::distribution::caller::ClientImplementationPin>,
) -> Result<()> {
    crate::policy::validate_sha(candidate_sha)?;
    let (manifest, desired) = managed_desired_files_from_source(candidate_sha, client_pin)?;
    println!(
        "validated {} exact managed scratch files for {} at {candidate_sha}",
        desired.len(),
        manifest.repository
    );
    Ok(())
}

fn read_managed_source_file(
    api: &GitHub,
    repository: &str,
    source_sha: &str,
    tree: &BTreeMap<String, Value>,
    path: &str,
) -> Result<Vec<u8>> {
    let entry = tree
        .get(path)
        .with_context(|| format!("managed-file source is absent at {source_sha}: {path}"))?;
    ensure!(
        entry["type"] == "blob" && entry["mode"] == "100644",
        "managed-file source is not a regular non-executable blob: {path}"
    );
    let size = entry["size"]
        .as_u64()
        .context("managed-file source size is missing")?;
    ensure!(
        size <= MANAGED_FILES_LIMIT,
        "managed-file source exceeds size limit: {path}"
    );
    let bytes = api.content(repository, path, source_sha)?;
    ensure!(
        bytes.len() as u64 == size,
        "managed-file source size differs from its candidate tree entry: {path}"
    );
    Ok(bytes)
}

/// Reconcile the exact desired files from protected instance main. Unlike the
/// development probe, this path has no candidate-source or Client pin input.
struct PreparedManagedDeployment {
    instance: securefix::api::NativeServerInstanceAuthority,
    manifest: ManagedFilesManifest,
    source_files: BTreeMap<String, Vec<u8>>,
    desired: BTreeMap<String, Vec<u8>>,
}

fn load_managed_deployment(
    config_path: &str,
    manifest_path: &str,
) -> Result<PreparedManagedDeployment> {
    securefix::api::validate_native_instance_config_path(config_path)?;
    ensure!(
        manifest_path.starts_with("repo-settings/") && safe_relative_path(manifest_path),
        "managed manifest must be root-relative under repo-settings"
    );
    let server = GitHub::from_env("GITHUB_TOKEN")?;
    let instance_repository =
        std::env::var("GITHUB_REPOSITORY").context("missing instance repository")?;
    let instance = server
        .capture_remote_native_server_instance_authority(&instance_repository, config_path)?;
    let reference: Value = server.get_uncached(&format!(
        "/repos/{instance_repository}/git/ref/heads/{}",
        instance.config.instance.default_branch
    ))?;
    let source_sha = reference["object"]["sha"]
        .as_str()
        .context("instance main SHA missing")?;
    crate::policy::validate_sha(source_sha)?;
    let manifest_bytes = server.content(&instance_repository, manifest_path, source_sha)?;
    let manifest = parse_managed_file_manifest(&manifest_bytes)?;
    instance
        .config
        .repositories
        .iter()
        .find(|entry| entry.repository == manifest.repository && entry.id == manifest.repository_id)
        .context("managed destination is not configured")?
        .policy()
        .require(Capability::Settings)?;
    let settings_path = instance
        .config
        .workflow_roles
        .get(&securefix::instance_config::WorkflowRole::Settings)
        .context("managed-file settings workflow role is missing")?;
    let mut source_files = BTreeMap::from([
        (manifest_path.to_owned(), manifest_bytes),
        (
            settings_path.clone(),
            server.content(&instance_repository, settings_path, source_sha)?,
        ),
    ]);
    let mut desired = BTreeMap::new();
    for file in &manifest.files {
        ensure!(
            file.source.starts_with("repo-settings/managed-files/")
                && safe_relative_path(&file.source)
                && safe_relative_path(&file.target),
            "unsafe managed source or target"
        );
        securefix::api::validate_native_managed_file_path(&file.target)?;
        let bytes = server.content(&instance_repository, &file.source, source_sha)?;
        ensure!(
            bytes.len() <= MANAGED_FILES_LIMIT as usize,
            "managed source exceeds size limit"
        );
        ensure!(
            desired.insert(file.target.clone(), bytes.clone()).is_none(),
            "duplicate managed target"
        );
        source_files.insert(file.source.clone(), bytes);
    }
    Ok(PreparedManagedDeployment {
        instance,
        manifest,
        source_files,
        desired,
    })
}

fn managed_reconcile(config_path: &str, manifest_path: &str) -> Result<()> {
    let PreparedManagedDeployment {
        instance,
        manifest,
        source_files,
        desired,
    } = load_managed_deployment(config_path, manifest_path)?;
    // Reads and workflow-PR writes use a repository-scoped installation token;
    // the administrator credential is never accepted by this command.
    let reader = GitHub::from_env("SECUREFIX_SERVER_APP_TOKEN")?;
    let repository: Value = reader.get(&format!("/repos/{}", manifest.repository))?;
    ensure!(
        repository["id"].as_u64() == Some(manifest.repository_id)
            && repository["full_name"] == manifest.repository
            && repository["default_branch"] == manifest.default_branch,
        "managed destination identity changed"
    );
    let reference: Value = reader.get_uncached(&format!(
        "/repos/{}/git/ref/heads/{}",
        manifest.repository, manifest.default_branch
    ))?;
    let base_sha = reference["object"]["sha"]
        .as_str()
        .context("managed destination main SHA missing")?
        .to_owned();
    crate::policy::validate_sha(&base_sha)?;
    let mut current = BTreeMap::new();
    for path in desired.keys() {
        if let Some(bytes) =
            optional_managed_content(&reader, &manifest.repository, path, &base_sha)?
        {
            current.insert(path.clone(), bytes);
        }
    }
    let additions = managed_changes(&desired, &current);
    let mut deletions = Vec::new();
    let mut seen = BTreeSet::new();
    for path in &manifest.remove {
        securefix::api::validate_native_managed_file_path(path)?;
        ensure!(
            !desired.contains_key(path) && seen.insert(path.clone()),
            "duplicate or active managed removal"
        );
        if optional_managed_content(&reader, &manifest.repository, path, &base_sha)?.is_some() {
            deletions.push(path.clone());
        }
    }
    if additions.is_empty() && deletions.is_empty() {
        println!("managed files match protected desired state at {base_sha}; no PR created");
        return Ok(());
    }
    let expected_changed = additions
        .keys()
        .cloned()
        .chain(deletions.iter().cloned())
        .collect::<BTreeSet<_>>();
    let branch = format!(
        "securefix/managed-files/{}-{}",
        env_u64("GITHUB_RUN_ID")?,
        env_u64("GITHUB_RUN_ATTEMPT")?
    );
    let target = securefix::api::NativeManagedFilesTarget {
        instance,
        repository: manifest.repository.clone(),
        repository_id: manifest.repository_id,
        default_branch: manifest.default_branch.clone(),
        base_sha: base_sha.clone(),
        branch: branch.clone(),
        source_files,
        additions: additions.clone(),
        deletions: deletions.clone(),
    };
    let writer = GitHub::native_managed_files_from_env("SECUREFIX_SERVER_APP_TOKEN", target)?;
    writer.post::<Value>(
        &format!("/repos/{}/git/refs", manifest.repository),
        &json!({"ref":format!("refs/heads/{branch}"),"sha":base_sha}),
    )?;
    let head = writer.create_commit(
        &manifest.repository,
        &branch,
        &base_sha,
        "Reconcile managed files",
        additions,
        deletions,
    )?;
    let branch_ref: Value = reader.get_uncached(&format!(
        "/repos/{}/git/ref/heads/{branch}",
        manifest.repository
    ))?;
    ensure!(
        branch_ref["object"]["sha"] == head,
        "managed signed branch changed"
    );
    let pull: Value = writer.post(&format!("/repos/{}/pulls", manifest.repository), &json!({
        "title":"Reconcile managed files","head":branch,"base":manifest.default_branch,
        "body":"Reconcile the protected repo-settings desired files. This PR does not merge automatically."
    }))?;
    let number = pull["number"]
        .as_u64()
        .context("managed PR number missing")?;
    ensure!(
        pull["state"] == "open"
            && pull["head"]["sha"] == head
            && pull["head"]["ref"] == branch
            && pull["head"]["repo"]["id"].as_u64() == Some(manifest.repository_id)
            && pull["base"]["repo"]["id"].as_u64() == Some(manifest.repository_id)
            && pull["base"]["ref"] == manifest.default_branch
            && pull["base"]["sha"] == base_sha,
        "unexpected managed PR identity"
    );
    let files = reader.paginate(&format!(
        "/repos/{}/pulls/{number}/files",
        manifest.repository
    ))?;
    validate_managed_pr_files(&files, &expected_changed)?;
    println!("created reviewable managed-file PR #{number} at {head}");
    Ok(())
}

fn optional_managed_content(
    api: &GitHub,
    repository: &str,
    path: &str,
    revision: &str,
) -> Result<Option<Vec<u8>>> {
    match api.content(repository, path, revision) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn managed_reconcile_scratch(
    candidate_sha: &str,
    client_pin: Option<&crate::distribution::caller::ClientImplementationPin>,
) -> Result<()> {
    crate::policy::validate_sha(candidate_sha)?;
    let (manifest, desired) = managed_desired_files_from_source(candidate_sha, client_pin)?;
    let api = GitHub::scratch_from_env("SECUREFIX_SERVER_APP_TOKEN", candidate_sha)?;
    let repository: Value = api.get(&format!("/repos/{}", manifest.repository))?;
    ensure!(
        repository["id"].as_u64() == Some(manifest.repository_id)
            && repository["full_name"].as_str() == Some(manifest.repository.as_str())
            && repository["default_branch"].as_str() == Some(manifest.default_branch.as_str()),
        "managed-files scratch repository identity or default branch changed"
    );
    let reference: Value = api.get(&format!(
        "/repos/{}/git/ref/heads/{}",
        manifest.repository, manifest.default_branch
    ))?;
    let base_sha = reference["object"]["sha"]
        .as_str()
        .context("scratch main ref has no SHA")?;
    let mut current_files = BTreeMap::new();
    for (path, bytes) in &desired {
        let current = match api.content(&manifest.repository, path, base_sha) {
            Ok(bytes) => Some(bytes),
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(current) = current {
            if current != *bytes {
                validate_supported_pin_state(path, &current, bytes)?;
            }
            current_files.insert(path.clone(), current);
        }
    }
    let additions = managed_changes(&desired, &current_files);
    let mut deletions = Vec::new();
    for path in &manifest.remove {
        match api.content(&manifest.repository, path, base_sha) {
            Ok(_) => deletions.push(path.clone()),
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
            {
                // An already absent exact path is reconciled.
            }
            Err(error) => return Err(error),
        }
    }
    if additions.is_empty() && deletions.is_empty() {
        println!("managed files already match scratch main at {base_sha}; no PR created");
        return Ok(());
    }
    let expected_changed = additions
        .keys()
        .cloned()
        .chain(deletions.iter().cloned())
        .collect::<BTreeSet<_>>();
    let branch = format!(
        "securefix/managed-files/{}-{}",
        env_u64("GITHUB_RUN_ID")?,
        env_u64("GITHUB_RUN_ATTEMPT")?
    );
    let reference_path = format!("/repos/{}/git/refs/heads/{}", manifest.repository, branch);
    let create_ref_path = format!("/repos/{}/git/refs", manifest.repository);
    api.post::<Value>(
        &create_ref_path,
        &json!({"ref":format!("refs/heads/{branch}"),"sha":base_sha}),
    )?;
    let head_sha = api.create_commit(
        &manifest.repository,
        &branch,
        base_sha,
        "Reconcile managed scratch files",
        additions,
        deletions,
    )?;
    let branch_ref: Value = api.get(&reference_path)?;
    ensure!(
        branch_ref["object"]["sha"].as_str() == Some(head_sha.as_str()),
        "managed-files branch does not point at the signed commit"
    );
    let latest_reference: Value = api.get(&format!(
        "/repos/{}/git/ref/heads/{}",
        manifest.repository, manifest.default_branch
    ))?;
    ensure!(
        latest_reference["object"]["sha"].as_str() == Some(base_sha),
        "scratch default branch changed before managed-files PR creation"
    );
    let pull: Value = api.post(
        &format!("/repos/{}/pulls", manifest.repository),
        &json!({"title":"Reconcile managed scratch files","head":branch,"base":manifest.default_branch,"body":"This PR reconciles the exact workflow and configuration files declared in `repo-settings/managed-files.json`."}),
    )?;
    let number = pull["number"]
        .as_u64()
        .context("managed-files PR has no number")?;
    ensure!(
        pull["state"] == "open"
            && pull["base"]["ref"] == manifest.default_branch
            && pull["base"]["sha"] == base_sha
            && pull["base"]["repo"]["id"].as_u64() == Some(manifest.repository_id)
            && pull["head"]["ref"] == branch
            && pull["head"]["repo"]["id"].as_u64() == Some(manifest.repository_id)
            && pull["head"]["sha"] == head_sha,
        "GitHub created an unexpected managed-files PR"
    );
    let files = api.paginate(&format!(
        "/repos/{}/pulls/{number}/files?per_page=100",
        manifest.repository
    ))?;
    validate_managed_pr_files(&files, &expected_changed)?;
    println!("created reviewable managed-files PR #{number} at {head_sha} from base {base_sha}");
    Ok(())
}

fn env_u64(name: &str) -> Result<u64> {
    std::env::var(name)
        .with_context(|| format!("missing {name}"))?
        .parse()
        .with_context(|| format!("invalid {name}"))
}

fn api() -> Result<GitHub> {
    GitHub::from_env("GH_TOKEN")
}

fn prepare() -> Result<()> {
    let trusted = config::trusted()?;
    let deployment = &trusted.deployment;
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let login: Value = api.get("/user")?;
    ensure!(
        login["login"] == deployment.owner_login && login["id"].as_u64() == Some(trusted.owner_id),
        "settings token must authenticate as the configured owner"
    );
    let policy = Policy::active(&api)?;
    validate_desired_settings()?;
    let input_name = env_string("INPUT_REPOSITORY");
    let input_repo = if input_name.trim().is_empty() {
        String::new()
    } else {
        let full_name = format!("{}/{input_name}", deployment.repository_owner.login);
        validate_repository(&full_name)?;
        full_name
    };
    let ready = env_bool("INPUT_MERGE_CONTROLS_READY")?;
    let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let activation = activation_mode(
        &event_name,
        &input_repo,
        ready,
        policy.merge_controls_enabled,
    )?;
    let repositories = if input_repo.trim().is_empty() {
        settings_repositories(&policy)?
    } else {
        policy
            .repository(&input_repo)?
            .require(Capability::Settings)?;
        vec![input_repo]
    };
    if activation == ActivationMode::AttestedFullRollout {
        validate_approval_token_if_present(&api, &repositories)?;
    }
    crate::output("repositories", serde_json::to_string(&repositories)?)?;
    crate::output(
        "repos_list",
        repositories
            .iter()
            .map(|r| r.split_once('/').unwrap().1)
            .collect::<Vec<_>>()
            .join(","),
    )?;
    crate::output(
        "activate_merge_controls",
        matches!(activation, ActivationMode::AttestedFullRollout).to_string(),
    )?;
    crate::output(
        "bot_invite",
        token_present("SECUREFIX_REVIEWER_INVITE_TOKEN").to_string(),
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationMode {
    NoActivation,
    ScheduledReconcile,
    AttestedFullRollout,
}

fn activation_mode(
    event_name: &str,
    repository: &str,
    ready: bool,
    enabled: bool,
) -> Result<ActivationMode> {
    if ready {
        ensure!(
            event_name == "workflow_dispatch",
            "merge controls readiness is only valid for manual dispatch"
        );
        ensure!(
            repository.trim().is_empty(),
            "merge-control activation requires the full repository set"
        );
        ensure!(enabled, "merge controls are disabled by central policy");
        return Ok(ActivationMode::AttestedFullRollout);
    }
    if event_name == "schedule" && enabled {
        return Ok(ActivationMode::ScheduledReconcile);
    }
    Ok(ActivationMode::NoActivation)
}

fn settings_repositories(policy: &Policy) -> Result<Vec<String>> {
    let repositories = policy
        .repositories
        .iter()
        .filter(|repo| repo.capabilities.contains(&Capability::Settings))
        .map(|repo| repo.repository.clone())
        .collect::<Vec<_>>();
    ensure!(
        !repositories.is_empty(),
        "policy has no settings repositories"
    );
    Ok(repositories)
}

fn reconcile(repository: &str) -> Result<()> {
    validate_repository(repository)?;
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    let repo_policy = policy.repository(repository)?;
    repo_policy.require(Capability::Settings)?;
    reconcile_one(&api, repo_policy, env_bool("INPUT_CREATE_IF_MISSING")?)
}

fn reconcile_one(
    api: &GitHub,
    repo_policy: &RepositoryPolicy,
    create_if_missing: bool,
) -> Result<()> {
    let repository = &repo_policy.repository;
    let existing: Option<Value> = match api.get(&format!("/repos/{repository}")) {
        Ok(value) => Some(value),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let is_new_repository = existing.is_none();
    if let Some(existing) = &existing {
        ensure_owner(
            existing,
            repository,
            config::trusted()?.deployment.repository_owner.id,
        )?;
    } else {
        ensure!(create_if_missing, "repository does not exist: {repository}");
        ensure!(
            std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch"),
            "repository creation is manual-dispatch only"
        );
        let trusted = config::trusted()?;
        let repository_owner = &trusted.deployment.repository_owner;
        let account: Value = api.get(&format!("/users/{}", repository_owner.login))?;
        ensure!(
            account["id"].as_u64() == Some(repository_owner.id),
            "configured repository owner identity changed"
        );
        let maintainer = config::Principal {
            login: trusted.deployment.owner_login.clone(),
            id: trusted.owner_id,
        };
        let create_path = repository_creation_path(
            account["type"]
                .as_str()
                .context("repository owner type is missing")?,
            repository_owner,
            &maintainer,
        )?;
        api.post::<Value>(
            &create_path,
            &json!({"name":repository_name(repository)?,"private":false}),
        )?;
    }
    let merge_settings = read_json("repo-settings/repository.json")?;
    api.patch::<Value>(&format!("/repos/{repository}"), &merge_settings)?;

    let default_ruleset = read_json(&format!("{RULESET_DIR}/default-branch.json"))?;
    // New repositories need the non-bypassable baseline before installing the
    // bypassable checks ruleset. Existing repositories already have that baseline,
    // so install the checks ruleset before relaxing their default rules.
    if is_new_repository {
        upsert_ruleset(api, repository, &default_ruleset)?;
    }
    upsert_ruleset(api, repository, &desired_review_and_checks_ruleset()?)?;
    upsert_ruleset(api, repository, &default_ruleset)?;
    if repo_policy.protect_tags {
        let tag_ruleset = read_json(&format!("{RULESET_DIR}/all-tags.json"))?;
        upsert_ruleset(api, repository, &tag_ruleset)?;
        delete_legacy_tag_rulesets(api, repository)?;
    }
    ensure_immutable_releases(api, repo_policy)?;
    let reviewer = &config::trusted()?.deployment.approval_reviewer.login;
    invite_collaborator(api, repository, reviewer)?;
    if token_present("SECUREFIX_REVIEWER_INVITE_TOKEN") {
        accept_invitation(api, repository, reviewer)?;
    }
    Ok(())
}

fn ensure_immutable_releases(api: &GitHub, repo_policy: &RepositoryPolicy) -> Result<()> {
    if repo_policy.repository != config::trusted()?.deployment.server.repository
        && !repo_policy.capabilities.contains(&Capability::Release)
    {
        return Ok(());
    }
    let path = format!("/repos/{}/immutable-releases", repo_policy.repository);
    match api.get::<Value>(&path) {
        Ok(state) if state["enabled"] == true => return Ok(()),
        Ok(state) => ensure!(
            state["enabled"] == false,
            "immutable release status is invalid"
        ),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) => {}
        Err(error) => return Err(error),
    }
    api.request(reqwest::Method::PUT, &path, None)?;
    let state: Value = api.get(&path)?;
    ensure!(
        state["enabled"] == true,
        "immutable releases did not become enabled"
    );
    Ok(())
}

pub(crate) fn require_server_immutable_releases(api: &GitHub) -> Result<()> {
    let server = &config::trusted()?.deployment.server.repository;
    let state: Value = api.get(&format!("/repos/{server}/immutable-releases"))?;
    ensure!(
        state["enabled"] == true,
        "server immutable releases must be enabled before runtime publication or activation"
    );
    Ok(())
}

fn controlled_merges() -> Result<()> {
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let ready = env_bool("INPUT_MERGE_CONTROLS_READY")?;
    let input_repo = env_string("INPUT_REPOSITORY");
    let mode = activation_mode(
        &event_name,
        &input_repo,
        ready,
        policy.merge_controls_enabled,
    )?;
    match mode {
        ActivationMode::AttestedFullRollout => {
            preflight(&api, &policy)?;
            activate_controls(&api, &policy)?;
        }
        ActivationMode::ScheduledReconcile => reconcile_active_controls(&api, &policy)?,
        ActivationMode::NoActivation => {}
    }
    Ok(())
}

fn activation_preflight() -> Result<()> {
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    ensure!(
        activation_mode(
            &std::env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
            &env_string("INPUT_REPOSITORY"),
            env_bool("INPUT_MERGE_CONTROLS_READY")?,
            policy.merge_controls_enabled,
        )? == ActivationMode::AttestedFullRollout,
        "full attested rollout was not requested"
    );
    preflight(&api, &policy)
}

fn preflight(api: &GitHub, policy: &Policy) -> Result<()> {
    require_server_immutable_releases(api)?;
    let trusted = config::trusted()?;
    let deployment = &trusted.deployment;
    let repositories = merge_repositories(policy, &deployment.server.repository)?;
    let expected_sha = &policy.revision;
    ensure!(!expected_sha.is_empty(), "policy revision is missing");
    validate_server_app_installation(&repositories, deployment.repository_owner.id)?;
    for repository in &repositories {
        validate_repo_identity(api, repository)?;
        validate_native_merge_settings(api, repository)?;
        validate_default_branch_ruleset(api, repository)?;
        validate_review_and_checks_ruleset(
            api,
            repository,
            deployment.server_app_id,
            &deployment.checks,
        )?;
        validate_existing_controlled_merges(api, repository, deployment.server_app_id)?;
        validate_current_policy_check(api, repository, &deployment.checks)?;
        validate_collaborator(api, repository, &deployment.approval_reviewer.login)?;
        if repository != &deployment.server.repository {
            for (wrapper, reusable) in CLIENT_WORKFLOWS {
                validate_wrapper_pin(
                    api,
                    repository,
                    wrapper,
                    reusable,
                    expected_sha,
                    &deployment.server.repository,
                )?;
            }
        }
    }
    Ok(())
}

fn merge_repositories(policy: &Policy, server: &str) -> Result<Vec<String>> {
    let mut clients = policy
        .repositories
        .iter()
        .filter(|r| r.capabilities.contains(&Capability::Merge) && r.repository != server)
        .map(|r| r.repository.clone())
        .collect::<Vec<_>>();
    clients.sort();
    ensure!(
        policy
            .repository(server)?
            .capabilities
            .contains(&Capability::Merge),
        "server merge capability is not enabled"
    );
    clients.push(server.to_owned());
    Ok(clients)
}

fn reconcile_existing_controlled_merges(ruleset: &Value) -> bool {
    ruleset["enforcement"] == "active"
}

fn activate_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = desired_controlled_merges_ruleset()?;
    let server = &config::trusted()?.deployment.server.repository;
    for repository in merge_repositories(policy, server)? {
        validate_repo_identity(api, &repository)?;
        validate_native_merge_settings(api, &repository)?;
        upsert_ruleset(api, &repository, &ruleset)?;
        validate_existing_controlled_merges(
            api,
            &repository,
            config::trusted()?.deployment.server_app_id,
        )?;
    }
    Ok(())
}

fn reconcile_active_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = desired_controlled_merges_ruleset()?;
    let server = &config::trusted()?.deployment.server.repository;
    for repository in merge_repositories(policy, server)? {
        validate_native_merge_settings(api, &repository)?;
        let matches = repository_rulesets(api, &repository, "controlled-merges")?;
        ensure!(
            matches.len() <= 1,
            "multiple controlled-merges rulesets on {repository}"
        );
        let Some(existing) = matches.first() else {
            continue;
        };
        if !reconcile_existing_controlled_merges(existing) {
            continue;
        }
        let id = existing["id"].as_u64().context("ruleset ID missing")?;
        api.put::<Value>(&format!("/repos/{repository}/rulesets/{id}"), &ruleset)?;
        validate_existing_controlled_merges(
            api,
            &repository,
            config::trusted()?.deployment.server_app_id,
        )?;
    }
    Ok(())
}

fn validate_repo_identity(api: &GitHub, repository: &str) -> Result<()> {
    let value: Value = api.get(&format!("/repos/{repository}"))?;
    let trusted = config::trusted()?;
    ensure_owner(&value, repository, trusted.deployment.repository_owner.id)?;
    let server = &trusted.deployment.server;
    if repository == server.repository {
        ensure!(
            value["id"].as_u64() == Some(server.id)
                && value["default_branch"] == server.default_branch,
            "configured server repository identity or default branch changed"
        );
    }
    Ok(())
}

fn validate_native_merge_settings(api: &GitHub, repository: &str) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    validate_repository_merge_settings(&repo, repository)?;
    let pull_requests = api.paginate(&format!("/repos/{repository}/pulls?state=open"))?;
    ensure!(
        pull_requests
            .iter()
            .all(|pull| pull["auto_merge"].is_null()),
        "{repository} has an outstanding native auto-merge request"
    );
    Ok(())
}

fn validate_repository_merge_settings(repo: &Value, repository: &str) -> Result<()> {
    ensure!(
        repo["allow_auto_merge"] == false
            && repo["allow_squash_merge"] == true
            && repo["allow_merge_commit"] == false
            && repo["allow_rebase_merge"] == false,
        "{repository} native auto-merge or merge methods are not controlled"
    );
    Ok(())
}

fn desired_controlled_merges_ruleset() -> Result<Value> {
    let mut ruleset = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    let server_app_id = config::trusted()?.deployment.server_app_id;
    let actors = ruleset["bypass_actors"]
        .as_array_mut()
        .context("controlled-merges bypass actors missing")?;
    ensure!(
        actors.len() == 1,
        "controlled-merges must name one bypass actor"
    );
    actors[0]["actor_id"] = json!(server_app_id);
    validate_controlled_merges(&ruleset, "configured repository", server_app_id)?;
    Ok(ruleset)
}

fn validate_controlled_merges(ruleset: &Value, repository: &str, server_app_id: u64) -> Result<()> {
    validate_ruleset_scope(ruleset, repository, "controlled-merges")?;
    ensure!(
        ruleset["bypass_actors"]
            == json!([{"actor_id":server_app_id,"actor_type":"Integration","bypass_mode":"pull_request"}]),
        "{repository} controlled-merges must have only the configured Server App PR bypass"
    );
    let rules = ruleset["rules"]
        .as_array()
        .context("controlled-merges rules missing")?;
    ensure!(
        rules.len() == 1
            && (rules[0] == json!({"type":"update"})
                || rules[0]
                    == json!({"type":"update","parameters":{"update_allows_fetch_and_merge":false}})),
        "{repository} controlled-merges rule set is not exact"
    );
    Ok(())
}

fn validate_existing_controlled_merges(
    api: &GitHub,
    repository: &str,
    server_app_id: u64,
) -> Result<bool> {
    let matches = repository_rulesets(api, repository, "controlled-merges")?;
    ensure!(
        matches.len() <= 1,
        "multiple controlled-merges rulesets on {repository}"
    );
    let Some(listed) = matches.first() else {
        return Ok(false);
    };
    let id = listed["id"].as_u64().context("ruleset ID missing")?;
    let detail: Value = api.get(&format!("/repos/{repository}/rulesets/{id}"))?;
    ensure!(
        detail["id"].as_u64() == Some(id)
            && detail["source_type"] == "Repository"
            && detail["source"] == repository
            && detail["name"] == "controlled-merges"
            && detail["target"] == "branch",
        "{repository} controlled-merges ruleset identity changed"
    );
    validate_controlled_merges(&detail, repository, server_app_id)?;
    Ok(true)
}

fn ensure_owner(repo: &Value, expected: &str, owner_id: u64) -> Result<()> {
    ensure!(
        repo["full_name"] == expected,
        "repository identity mismatch"
    );
    ensure!(
        repo["owner"]["id"].as_u64() == Some(owner_id),
        "repository is not owned by the configured organization"
    );
    Ok(())
}

fn validate_wrapper_pin(
    api: &GitHub,
    repository: &str,
    path: &str,
    reusable: &str,
    expected_sha: &str,
    server_repository: &str,
) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let bytes = api.content(repository, &crate::config::workflow_path(path)?, branch)?;
    let yaml: Value = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("invalid workflow {repository}/{path}"))?;
    let uses = find_uses(&yaml);
    let expected = wrapper_pin(server_repository, reusable, expected_sha)?;
    ensure!(
        uses.iter().filter(|value| **value == expected).count() == 1 && uses.len() == 1,
        "{repository}/{path} must call {reusable} at the current server revision"
    );
    Ok(())
}

fn wrapper_pin(server_repository: &str, reusable: &str, expected_sha: &str) -> Result<String> {
    let path = crate::config::workflow_path(&format!(".github/workflows/{reusable}"))?;
    Ok(format!("{server_repository}/{path}@{expected_sha}"))
}

fn find_uses(value: &Value) -> Vec<&str> {
    let mut found = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "uses"
                    && let Some(value) = child.as_str()
                {
                    found.push(value);
                }
                found.extend(find_uses(child));
            }
        }
        Value::Array(items) => {
            for item in items {
                found.extend(find_uses(item));
            }
        }
        _ => {}
    }
    found
}

fn validate_current_policy_check(api: &GitHub, repository: &str, checks: &Checks) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let reference: Value = api.get(&format!("/repos/{repository}/git/ref/heads/{branch}"))?;
    let sha = reference["object"]["sha"]
        .as_str()
        .context("default branch SHA missing")?;
    for (name, app_id) in [
        ("status-check", checks.status_app_id),
        ("securefix-policy-check", checks.policy_app_id),
    ] {
        let response: Value = api.get(&format!(
            "/repos/{repository}/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={name}&app_id={app_id}"
        ))?;
        let check_runs = response["check_runs"]
            .as_array()
            .context("check-runs missing")?;
        ensure!(
            response["total_count"].as_u64() == Some(check_runs.len() as u64),
            "{repository} named check response is incomplete"
        );
        let latest = check_runs
            .iter()
            .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
            .max_by_key(|check| check["id"].as_u64().unwrap_or_default());
        ensure!(
            latest.is_some_and(
                |check| check["status"] == "completed" && check["conclusion"] == "success"
            ),
            "{repository} default-branch head lacks successful {name} from app {app_id}"
        );
    }
    Ok(())
}

fn validate_default_branch_ruleset(api: &GitHub, repository: &str) -> Result<()> {
    let detail = repository_ruleset(api, repository, "default-branch")?;
    validate_default_ruleset(&detail, repository)
}

fn validate_review_and_checks_ruleset(
    api: &GitHub,
    repository: &str,
    server_app_id: u64,
    checks: &Checks,
) -> Result<()> {
    let detail = repository_ruleset(api, repository, "review-and-checks")?;
    validate_review_and_checks(&detail, repository, server_app_id, checks)
}

fn repository_ruleset(api: &GitHub, repository: &str, name: &str) -> Result<Value> {
    let matches = repository_rulesets(api, repository, name)?;
    ensure!(
        matches.len() == 1,
        "{repository} must have exactly one {name} ruleset"
    );
    let listed = &matches[0];
    let id = listed["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .with_context(|| format!("{name} ruleset list entry has no valid ID"))?;
    ensure!(
        listed["source_type"] == "Repository"
            && listed["name"] == name
            && listed["target"] == "branch",
        "{repository} {name} ruleset list identity is invalid"
    );
    let detail: Value = api.get(&format!("/repos/{repository}/rulesets/{id}"))?;
    ensure!(
        detail["id"].as_u64() == Some(id)
            && detail["source_type"] == "Repository"
            && detail["source"] == repository
            && detail["name"] == name
            && detail["target"] == "branch",
        "{repository} {name} ruleset detail identity changed"
    );
    Ok(detail)
}

fn validate_ruleset_scope(ruleset: &Value, repository: &str, name: &str) -> Result<()> {
    ensure!(
        ruleset["enforcement"] == "active"
            && ruleset["target"] == "branch"
            && ruleset["conditions"]["ref_name"]["include"] == json!(["~DEFAULT_BRANCH"])
            && ruleset["conditions"]["ref_name"]["exclude"] == json!([]),
        "{repository} {name} protections are not active on exactly the default branch"
    );
    Ok(())
}

fn validate_default_ruleset(ruleset: &Value, repository: &str) -> Result<()> {
    validate_ruleset_scope(ruleset, repository, "default-branch")?;
    ensure!(
        ruleset["bypass_actors"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "{repository} default-branch rules must be bypass-free"
    );
    let rules = ruleset["rules"]
        .as_array()
        .context("default-branch rules missing")?;
    ensure!(
        rules.len() == 5,
        "{repository} default-branch rule set is not exact"
    );
    for rule_type in [
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "required_signatures",
    ] {
        ensure!(
            rules.iter().any(|rule| rule["type"] == rule_type),
            "{repository} default-branch protections lack {rule_type}"
        );
    }
    let pull_rules: Vec<_> = rules
        .iter()
        .filter(|rule| rule["type"] == "pull_request")
        .collect();
    ensure!(
        pull_rules.len() == 1,
        "{repository} must have one pull-request rule"
    );
    let pull_request = pull_rules[0];
    ensure!(
        pull_request["parameters"]["required_approving_review_count"] == 0
            && pull_request["parameters"]["allowed_merge_methods"] == json!(["squash"]),
        "{repository} default-branch must require PRs and squash-only merges, without reviews"
    );
    ensure!(
        !rules
            .iter()
            .any(|rule| rule["type"] == "required_status_checks"),
        "{repository} required checks must live in the separately bypassable ruleset"
    );
    Ok(())
}

fn validate_review_and_checks(
    ruleset: &Value,
    repository: &str,
    server_app_id: u64,
    checks: &Checks,
) -> Result<()> {
    validate_ruleset_scope(ruleset, repository, "review-and-checks")?;
    ensure!(
        ruleset["bypass_actors"]
            == json!([{"actor_id":server_app_id,"actor_type":"Integration","bypass_mode":"pull_request"}]),
        "{repository} review-and-checks ruleset must have only the configured Server App PR bypass"
    );
    let rules = ruleset["rules"]
        .as_array()
        .context("review-and-checks rules missing")?;
    ensure!(
        rules.len() == 2,
        "{repository} review-and-checks rule set is not exact"
    );
    let pull_rules: Vec<_> = rules
        .iter()
        .filter(|rule| rule["type"] == "pull_request")
        .collect();
    ensure!(
        pull_rules.len() == 1,
        "{repository} must have one review rule"
    );
    let pull_request = pull_rules[0];
    ensure!(
        pull_request["parameters"]["required_approving_review_count"] == 1
            && pull_request["parameters"]["dismiss_stale_reviews_on_push"] == true
            && pull_request["parameters"]["allowed_merge_methods"] == json!(["squash"]),
        "{repository} review-and-checks must require one current approval"
    );
    let status_rules: Vec<_> = rules
        .iter()
        .filter(|rule| rule["type"] == "required_status_checks")
        .collect();
    ensure!(
        status_rules.len() == 1,
        "{repository} must have one status-check rule"
    );
    let required_checks = status_rules[0];
    ensure!(
        required_checks["parameters"]["strict_required_status_checks_policy"] == false
            && required_checks["parameters"]["do_not_enforce_on_create"] == false,
        "{repository} status-check rule parameters are not exact"
    );
    let statuses = required_checks["parameters"]["required_status_checks"]
        .as_array()
        .context("required status checks missing")?;
    ensure!(
        statuses.len() == 2,
        "{repository} required status-check set is not exact"
    );
    for (name, integration_id) in [
        ("status-check", checks.status_app_id),
        ("securefix-policy-check", checks.policy_app_id),
    ] {
        ensure!(
            statuses.iter().any(|check| check["context"] == name
                && check["integration_id"].as_u64() == Some(integration_id)),
            "{repository} ruleset does not bind {name} to app {integration_id}"
        );
    }
    Ok(())
}

fn validate_server_app_installation(repositories: &[String], owner_id: u64) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_APP_TOKEN")?;
    // App identity comes from the trusted workflow minting this token. Installation
    // tokens expose repository scope, but not the App identity that minted them.
    validate_installation_scope(&api, repositories, owner_id)
}

pub(crate) fn validate_installation_scope(
    api: &GitHub,
    repositories: &[String],
    owner_id: u64,
) -> Result<()> {
    let expected = repositories.iter().collect::<BTreeSet<_>>();
    ensure!(
        expected.len() == repositories.len(),
        "configured installation repository set contains duplicates"
    );
    let mut installed = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut total_count = None;
    for page in 1..=100 {
        let response: Value = api.get(&format!(
            "/installation/repositories?per_page=100&page={page}"
        ))?;
        let page_total = response["total_count"]
            .as_u64()
            .context("installation repository total_count missing or malformed")?;
        ensure!(
            total_count.is_none_or(|count| count == page_total),
            "installation repository total_count changed during pagination"
        );
        total_count = Some(page_total);
        let values = response["repositories"]
            .as_array()
            .context("installation repositories missing")?;
        ensure!(
            values.len() <= 100,
            "installation repository page exceeds limit"
        );
        for repository in values {
            ensure!(
                repository["owner"]["id"].as_u64() == Some(owner_id),
                "Securefix Server App installation contains a repository outside the configured owner"
            );
            let name = repository["full_name"]
                .as_str()
                .context("installation repository full_name missing or malformed")?;
            let (owner, repository_name) = name
                .split_once('/')
                .context("installation repository full_name malformed")?;
            ensure!(
                !owner.is_empty() && !repository_name.is_empty() && !repository_name.contains('/'),
                "installation repository full_name malformed"
            );
            let id = repository["id"]
                .as_u64()
                .context("installation repository id missing or malformed")?;
            ensure!(ids.insert(id), "duplicate repository in installation scope");
            ensure!(
                installed.insert(name.to_string()),
                "duplicate repository in installation scope"
            );
        }
        let installed_count = u64::try_from(installed.len())?;
        ensure!(
            installed_count <= page_total,
            "installation repository pages exceed total_count"
        );
        if installed_count == page_total {
            break;
        }
        ensure!(
            page < 100 && !values.is_empty(),
            "Securefix Server App installation repository list exceeded limit"
        );
    }
    ensure!(
        installed == expected.into_iter().cloned().collect(),
        "Securefix Server App token scope differs from the full configured repository set"
    );
    Ok(())
}

fn validate_approval_token_if_present(owner_api: &GitHub, repositories: &[String]) -> Result<()> {
    let reviewer = &config::trusted()?.deployment.approval_reviewer;
    ensure!(
        token_present("SECUREFIX_APPROVAL_REVIEWER_TOKEN"),
        "SECUREFIX_APPROVAL_REVIEWER_TOKEN is required for full activation readiness"
    );
    let api = GitHub::from_env("SECUREFIX_APPROVAL_REVIEWER_TOKEN")?;
    validate_reviewer_access(owner_api, &api, repositories, reviewer)
}

fn validate_reviewer_access(
    owner_api: &GitHub,
    reviewer_api: &GitHub,
    repositories: &[String],
    reviewer: &config::Principal,
) -> Result<()> {
    let user: Value = reviewer_api.get("/user")?;
    validate_reviewer_identity(&user, reviewer)?;
    for repository in repositories {
        validate_collaborator(owner_api, repository, &reviewer.login)?;
    }
    Ok(())
}

fn validate_collaborator(api: &GitHub, repository: &str, reviewer: &str) -> Result<()> {
    let collaborator: Value = api.get(&format!(
        "/repos/{repository}/collaborators/{reviewer}/permission"
    ))?;
    ensure!(
        matches!(collaborator["permission"].as_str(), Some("write" | "admin")),
        "configured approval reviewer lacks effective write permission on {repository}"
    );
    Ok(())
}

fn validate_reviewer_identity(identity: &Value, reviewer: &config::Principal) -> Result<()> {
    ensure!(
        identity["login"] == reviewer.login && identity["id"].as_u64() == Some(reviewer.id),
        "token must authenticate as the configured approval reviewer"
    );
    Ok(())
}

fn repository_creation_path(
    account_type: &str,
    repository_owner: &config::Principal,
    maintainer: &config::Principal,
) -> Result<String> {
    match account_type {
        "Organization" => Ok(format!("/orgs/{}/repos", repository_owner.login)),
        "User" => {
            ensure!(
                repository_owner.id == maintainer.id && repository_owner.login == maintainer.login,
                "the configured human settings token cannot create a repository for a different user"
            );
            Ok("/user/repos".to_owned())
        }
        _ => anyhow::bail!("configured repository owner has an unknown account type"),
    }
}

fn repository_rulesets(api: &GitHub, repository: &str, name: &str) -> Result<Vec<Value>> {
    Ok(api
        .paginate(&format!(
            "/repos/{repository}/rulesets?includes_parents=false"
        ))?
        .into_iter()
        .filter(|value| value["name"] == name && value["source_type"] == "Repository")
        .collect())
}

fn upsert_ruleset(api: &GitHub, repository: &str, body: &Value) -> Result<()> {
    let name = body["name"].as_str().context("ruleset name missing")?;
    let matches = repository_rulesets(api, repository, name)?;
    ensure!(
        matches.len() <= 1,
        "multiple {name} rulesets on {repository}"
    );
    if let Some(existing) = matches.first() {
        let id = existing["id"].as_u64().context("ruleset ID missing")?;
        api.put::<Value>(&format!("/repos/{repository}/rulesets/{id}"), body)?;
    } else {
        api.post::<Value>(&format!("/repos/{repository}/rulesets"), body)?;
    }
    Ok(())
}

fn delete_legacy_tag_rulesets(api: &GitHub, repository: &str) -> Result<()> {
    let existing = api.paginate(&format!(
        "/repos/{repository}/rulesets?includes_parents=false"
    ))?;
    for ruleset in existing.into_iter().filter(|value| {
        value["name"] == "Protect tags"
            && value["source_type"] == "Repository"
            && value["target"] == "tag"
    }) {
        let id = ruleset["id"]
            .as_u64()
            .context("legacy ruleset ID missing")?;
        api.delete(&format!("/repos/{repository}/rulesets/{id}"))?;
    }
    Ok(())
}

fn invite_collaborator(api: &GitHub, repository: &str, username: &str) -> Result<()> {
    let collaborator = read_json("repo-settings/collaborator.json")?;
    let permission = collaborator["permission"]
        .as_str()
        .context("collaborator permission missing")?;
    api.put::<Value>(
        &format!("/repos/{repository}/collaborators/{username}"),
        &json!({"permission":permission}),
    )?;
    Ok(())
}

fn accept_invitation(owner_api: &GitHub, repository: &str, username: &str) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_REVIEWER_INVITE_TOKEN")?;
    let trusted = config::trusted()?;
    ensure!(
        username == trusted.deployment.approval_reviewer.login,
        "invitation target differs from the configured approval reviewer"
    );
    accept_reviewer_invitation(
        owner_api,
        &api,
        repository,
        &trusted.deployment.approval_reviewer,
    )
}

fn accept_reviewer_invitation(
    owner_api: &GitHub,
    invitation_api: &GitHub,
    repository: &str,
    reviewer: &config::Principal,
) -> Result<()> {
    let identity: Value = invitation_api.get("/user")?;
    validate_reviewer_identity(&identity, reviewer)?;
    let invitations: Vec<Value> = invitation_api.paginate("/user/repository_invitations")?;
    let full_name = repository.to_lowercase();
    if let Some(invitation) = invitations.iter().find(|item| {
        item["repository"]["full_name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&full_name))
    }) {
        let id = invitation["id"].as_u64().context("invitation ID missing")?;
        invitation_api.patch::<Value>(&format!("/user/repository_invitations/{id}"), &json!({}))?;
    }
    validate_collaborator(owner_api, repository, &reviewer.login)
}

fn validate_desired_settings() -> Result<()> {
    let repository = read_json("repo-settings/repository.json")?;
    validate_repository_merge_settings(&repository, "repository.json")?;
    let collaborator = read_json("repo-settings/collaborator.json")?;
    ensure!(
        collaborator["permission"] == "push",
        "collaborator.json must grant push access"
    );
    let default = read_json(&format!("{RULESET_DIR}/default-branch.json"))?;
    validate_default_ruleset(&default, "configured repository")?;
    let review_and_checks = desired_review_and_checks_ruleset()?;
    let trusted = config::trusted()?;
    validate_review_and_checks(
        &review_and_checks,
        "configured repository",
        trusted.deployment.server_app_id,
        &trusted.deployment.checks,
    )?;
    ensure!(
        default["name"] == "default-branch"
            && default["target"] == "branch"
            && default["bypass_actors"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "invalid default-branch ruleset"
    );
    desired_controlled_merges_ruleset()?;
    let tags = read_json(&format!("{RULESET_DIR}/all-tags.json"))?;
    ensure!(
        tags["name"] == "all-tags"
            && tags["target"] == "tag"
            && tags["bypass_actors"].as_array().is_some_and(Vec::is_empty),
        "invalid all-tags ruleset"
    );
    Ok(())
}

fn desired_review_and_checks_ruleset() -> Result<Value> {
    let mut ruleset = read_json(&format!("{RULESET_DIR}/review-and-checks.json"))?;
    let trusted = config::trusted()?;
    ruleset["bypass_actors"][0]["actor_id"] = json!(trusted.deployment.server_app_id);
    let statuses = ruleset["rules"]
        .as_array_mut()
        .and_then(|rules| {
            rules
                .iter_mut()
                .find(|rule| rule["type"] == "required_status_checks")
        })
        .and_then(|rule| rule["parameters"]["required_status_checks"].as_array_mut())
        .context("review-and-checks status template missing")?;
    for (name, app_id) in [
        ("status-check", trusted.deployment.checks.status_app_id),
        (
            "securefix-policy-check",
            trusted.deployment.checks.policy_app_id,
        ),
    ] {
        let mut matching = statuses.iter_mut().filter(|check| check["context"] == name);
        let check = matching
            .next()
            .with_context(|| format!("review-and-checks template missing {name}"))?;
        ensure!(
            matching.next().is_none(),
            "review-and-checks template must contain one {name}"
        );
        check["integration_id"] = json!(app_id);
    }
    Ok(ruleset)
}

fn read_json(path: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {path}"))?;
    ensure!(bytes.len() <= 256 * 1024, "{path} exceeds size limit");
    serde_json::from_slice(&bytes).with_context(|| format!("parse {path}"))
}

fn repository_name(repository: &str) -> Result<&str> {
    repository
        .split_once('/')
        .map(|(_, name)| name)
        .context("invalid repository name")
}

fn env_string(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}
fn token_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}
fn env_bool(name: &str) -> Result<bool> {
    match env_string(name).as_str() {
        "" | "false" | "0" => Ok(false),
        "true" | "1" => Ok(true),
        _ => bail!("{name} must be true or false"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_settings_deployment_matches_its_protected_desired_manifest() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-settings-test-instance.toml"
        ))
        .unwrap();
        let manifest = parse_managed_file_manifest(include_bytes!(
            "../repo-settings/native-settings-test-managed-files.json"
        ))
        .unwrap();
        assert_eq!(
            config.workflow_roles[&securefix::instance_config::WorkflowRole::Settings],
            ".github/workflows/testing-native-settings.yml"
        );
        config
            .repositories
            .iter()
            .find(|entry| {
                entry.repository == manifest.repository && entry.id == manifest.repository_id
            })
            .unwrap()
            .policy()
            .require(Capability::Settings)
            .unwrap();
        assert_eq!(manifest.files.len(), 14);
        for file in &manifest.files {
            let bytes = fs::read(&file.source).unwrap();
            assert!(!bytes.is_empty(), "{}", file.source);
            if file.target.ends_with(".yml") {
                let _: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
                assert!(!String::from_utf8_lossy(&bytes).contains("@CLIENT_"));
                assert!(!String::from_utf8_lossy(&bytes).contains("@SERVER_"));
            } else if file.target == "securefix-server.toml" {
                securefix::instance_config::InstanceConfig::parse(&bytes).unwrap();
            } else {
                assert_eq!(file.target, MANAGED_ACTIONS_LOCK_TARGET);
                let lock: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
                assert_eq!(lock["version"].as_str(), Some("v0.0.3"));
                assert!(lock["workflows"].as_mapping().is_some());
            }
        }
    }

    use super::*;
    use crate::fixtures::{Fixture, Route};

    fn managed_entry(target: &str) -> ManagedFileEntry {
        ManagedFileEntry {
            source: format!(
                "repo-settings/managed-files/{}",
                target.rsplit('/').next().unwrap()
            ),
            target: target.to_owned(),
        }
    }

    fn managed_instance_config() -> securefix::instance_config::InstanceConfig {
        securefix::instance_config::InstanceConfig::parse(
            include_str!("../repo-settings/managed-files/securefix-server.toml").as_bytes(),
        )
        .unwrap()
    }

    fn managed_role_entries() -> Vec<ManagedFileEntry> {
        let instance_config = managed_instance_config();
        expected_managed_targets(&instance_config)
            .iter()
            .map(|path| managed_entry(path))
            .collect()
    }

    fn canonical_managed_policy_check_caller() -> Vec<u8> {
        include_bytes!("../repo-settings/managed-files/policy-check.yml").to_vec()
    }

    fn canonical_managed_securefix_request_caller() -> Vec<u8> {
        include_bytes!("../repo-settings/managed-files/securefix-request.yml").to_vec()
    }

    #[test]
    fn managed_securefix_request_preserves_the_verified_cross_repository_caller() {
        let manifest =
            parse_managed_manifest(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        let instance_config = managed_instance_config();
        let config = include_bytes!("../repo-settings/native-securefix-write-test-instance.toml");
        let desired = BTreeMap::from([(
            MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET.to_owned(),
            canonical_managed_securefix_request_caller(),
        )]);
        validate_managed_securefix_request_caller(
            &manifest,
            &desired,
            &instance_config,
            Some(config),
        )
        .unwrap();
        assert!(
            validate_managed_securefix_request_caller(&manifest, &desired, &instance_config, None)
                .is_err()
        );
        let caller =
            std::str::from_utf8(&desired[MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET]).unwrap();
        for (from, to) in [
            ("github.actor_id == '4525500'", "github.actor_id == '1'"),
            (
                "server_repository: civitaspo/securefix-server",
                "server_repository: civitaspo/testing-securefix-server",
            ),
            (
                "repo-settings/native-securefix-write-test-instance.toml",
                "securefix-server.toml",
            ),
            ("2179c5566b1cc84bd7d53082f028f00f5f046b60", "main"),
        ] {
            assert!(caller.contains(from));
            let changed = BTreeMap::from([(
                MANAGED_CLIENT_SECUREFIX_REQUEST_TARGET.to_owned(),
                caller.replace(from, to).into_bytes(),
            )]);
            assert!(
                validate_managed_securefix_request_caller(
                    &manifest,
                    &changed,
                    &instance_config,
                    Some(config)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn protected_managed_manifest_uses_declared_identity_without_scratch_defaults() {
        let mut value: Value =
            serde_json::from_slice(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        value["repository"] = json!("example-org/project");
        value["repository_id"] = json!(987654);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            parse_managed_file_manifest(&bytes).unwrap().repository,
            "example-org/project"
        );
        assert!(
            parse_managed_manifest(&bytes).is_err(),
            "the scratch-only contract stays bounded"
        );
        for target in [
            "Cargo.toml",
            "control/active.json",
            ".github/workflows/../policy.json",
        ] {
            let mut changed = value.clone();
            changed["files"][0]["target"] = json!(target);
            assert!(parse_managed_file_manifest(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let duplicate = value["files"][0].clone();
        value["files"].as_array_mut().unwrap().push(duplicate);
        assert!(parse_managed_file_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn managed_planner_changes_only_the_drifted_file() {
        let desired = BTreeMap::from([
            (
                ".github/workflows/policy-check.yml".into(),
                b"workflow".to_vec(),
            ),
            ("securefix-server.toml".into(), b"config".to_vec()),
        ]);
        let current = BTreeMap::from([
            (
                ".github/workflows/policy-check.yml".into(),
                b"old workflow".to_vec(),
            ),
            ("securefix-server.toml".into(), b"config".to_vec()),
            ("unmanaged.txt".into(), b"leave alone".to_vec()),
        ]);
        let changes = managed_changes(&desired, &current);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes.get(".github/workflows/policy-check.yml"),
            Some(&b"workflow".to_vec())
        );
        assert!(!changes.contains_key("unmanaged.txt"));
        assert!(managed_changes(&desired, &desired).is_empty());
    }

    #[test]
    fn managed_planner_adds_a_missing_file_without_deleting_unmanaged_files() {
        let desired = BTreeMap::from([
            (
                ".github/workflows/policy-check.yml".into(),
                b"workflow".to_vec(),
            ),
            ("securefix-server.toml".into(), b"config".to_vec()),
        ]);
        let current = BTreeMap::from([
            (
                ".github/workflows/policy-check.yml".into(),
                b"workflow".to_vec(),
            ),
            ("unmanaged.txt".into(), b"leave alone".to_vec()),
        ]);
        let changes = managed_changes(&desired, &current);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes.get("securefix-server.toml"),
            Some(&b"config".to_vec())
        );
        assert!(!changes.contains_key("unmanaged.txt"));
    }

    #[test]
    fn managed_workflow_rejects_a_different_immutable_pin() {
        let expected = b"jobs:\n  call:\n    uses: owner/repo/.github/workflows/check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let changed = b"jobs:\n  call:\n    uses: owner/repo/.github/workflows/check.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
        assert!(
            validate_supported_pin_state(".github/workflows/policy-check.yml", changed, expected)
                .is_err()
        );
        assert!(
            validate_supported_pin_state(".github/workflows/policy-check.yml", expected, expected)
                .is_ok()
        );
    }

    #[test]
    fn managed_policy_check_migrates_only_observed_prior_callers() {
        let manifest =
            parse_managed_manifest(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        let desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                canonical_managed_policy_check_caller(),
            ),
        ]);
        let instance_config = validate_managed_instance_config(&manifest, &desired).unwrap();

        let caller = &desired[MANAGED_CLIENT_POLICY_CHECK_TARGET];
        let policy_check_instance_config =
            include_bytes!("../repo-settings/native-role-events-test-instance.toml");
        assert!(
            validate_managed_policy_check_caller(&manifest, &desired, &instance_config, None)
                .is_err()
        );
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &desired,
                &instance_config,
                Some(include_bytes!(
                    "../repo-settings/managed-files/securefix-server.toml"
                )),
            )
            .is_err()
        );
        validate_managed_policy_check_caller(
            &manifest,
            &desired,
            &instance_config,
            Some(policy_check_instance_config),
        )
        .unwrap();
        let legacy = include_bytes!("../tests/fixtures/managed-legacy-policy-check.yml");
        assert_eq!(
            crate::hex_encode(sha2::Sha256::digest(legacy)),
            OBSERVED_LEGACY_POLICY_CHECK_SHA256
        );
        assert!(
            validate_supported_pin_state(MANAGED_CLIENT_POLICY_CHECK_TARGET, legacy, caller)
                .is_ok()
        );

        let probe = include_bytes!("../tests/fixtures/managed-policy-check-probe.yml");
        assert_eq!(
            crate::hex_encode(sha2::Sha256::digest(probe)),
            OBSERVED_PROBE_POLICY_CHECK_SHA256
        );
        assert!(
            validate_supported_pin_state(MANAGED_CLIENT_POLICY_CHECK_TARGET, probe, caller).is_ok()
        );

        let mut changed_legacy = legacy.to_vec();
        changed_legacy.extend_from_slice(b"\n# changed\n");
        assert!(
            validate_supported_pin_state(
                MANAGED_CLIENT_POLICY_CHECK_TARGET,
                &changed_legacy,
                caller
            )
            .is_err()
        );

        let mut changed_probe = probe.to_vec();
        changed_probe.extend_from_slice(b"\n# changed\n");
        assert!(
            validate_supported_pin_state(
                MANAGED_CLIENT_POLICY_CHECK_TARGET,
                &changed_probe,
                caller
            )
            .is_err()
        );

        let wrong_pin = String::from_utf8(caller.clone())
            .unwrap()
            .replace("2719567ddd2cb9e13294e12cb9537780c6643263", "main");
        let wrong_pin_desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                wrong_pin.into_bytes(),
            ),
        ]);
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &wrong_pin_desired,
                &instance_config,
                Some(policy_check_instance_config),
            )
            .is_err()
        );

        let wrong_secret = String::from_utf8(caller.clone()).unwrap().replace(
            "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}",
            "${{ secrets.UNEXPECTED_KEY }}",
        );
        let wrong_secret_desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                wrong_secret.into_bytes(),
            ),
        ]);
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &wrong_secret_desired,
                &instance_config,
                Some(policy_check_instance_config),
            )
            .is_err()
        );

        let mut wrong_event = String::from_utf8(caller.clone()).unwrap();
        wrong_event = wrong_event.replace("pull_request_target:", "workflow_dispatch:");
        let invalid_desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                wrong_event.into_bytes(),
            ),
        ]);
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &invalid_desired,
                &instance_config,
                Some(policy_check_instance_config),
            )
            .is_err()
        );

        let wrong_config_path = String::from_utf8(caller.clone()).unwrap().replace(
            "instance_config_path: repo-settings/native-role-events-test-instance.toml",
            "instance_config_path: securefix-server.toml",
        );
        let wrong_config_path_desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                wrong_config_path.into_bytes(),
            ),
        ]);
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &wrong_config_path_desired,
                &instance_config,
                Some(policy_check_instance_config),
            )
            .is_err()
        );

        let wrong_signer_config = String::from_utf8(policy_check_instance_config.to_vec())
            .unwrap()
            .replace(
                MANAGED_POLICY_CHECK_SIGNER_PATH,
                ".github/workflows/request-producer-probe.yml",
            );
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &desired,
                &instance_config,
                Some(wrong_signer_config.as_bytes()),
            )
            .is_err()
        );

        let wrong_server = String::from_utf8(caller.clone()).unwrap().replace(
            "server_repository: civitaspo/securefix-server",
            "server_repository: civitaspo/testing-securefix-server",
        );
        let wrong_server_desired = BTreeMap::from([
            (
                MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
            ),
            (
                MANAGED_CLIENT_POLICY_CHECK_TARGET.to_owned(),
                wrong_server.into_bytes(),
            ),
        ]);
        assert!(
            validate_managed_policy_check_caller(
                &manifest,
                &wrong_server_desired,
                &instance_config,
                Some(policy_check_instance_config),
            )
            .is_err()
        );
    }

    #[test]
    fn managed_command_callers_preserve_exact_owner_scope_and_credentials() {
        let manifest =
            parse_managed_manifest(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        let config = managed_instance_config();
        let server_config =
            include_bytes!("../repo-settings/native-role-events-test-instance.toml");
        let callers = BTreeMap::from([
            (
                MANAGED_CLIENT_APPROVE_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/approve-request.yml").to_vec(),
            ),
            (
                MANAGED_CLIENT_MERGE_TARGET.to_owned(),
                include_bytes!("../repo-settings/managed-files/merge-request.yml").to_vec(),
            ),
        ]);
        validate_managed_command_callers(&manifest, &callers, &config, Some(server_config))
            .unwrap();
        assert!(validate_managed_command_callers(&manifest, &callers, &config, None).is_err());
        for target in [MANAGED_CLIENT_APPROVE_TARGET, MANAGED_CLIENT_MERGE_TARGET] {
            for (from, to) in [
                ("2719567ddd2cb9e13294e12cb9537780c6643263", "main"),
                ("comment.user.id == 4525500", "comment.user.id == 1"),
                (
                    "SECUREFIX_CLIENT_PRIVATE_KEY",
                    "SECUREFIX_SERVER_PRIVATE_KEY",
                ),
                (
                    "instance_config_path: repo-settings/native-role-events-test-instance.toml",
                    "instance_config_path: securefix-server.toml",
                ),
                ("attestations: write", "attestations: read"),
            ] {
                let mut changed = callers.clone();
                let caller = std::str::from_utf8(&callers[target]).unwrap();
                assert!(caller.contains(from));
                changed.insert(target.to_owned(), caller.replace(from, to).into_bytes());
                assert!(
                    validate_managed_command_callers(
                        &manifest,
                        &changed,
                        &config,
                        Some(server_config)
                    )
                    .is_err(),
                    "{target}: {from}"
                );
            }
        }
        let unscoped = std::str::from_utf8(server_config).unwrap().replace(
            "event = \"issue_comment\"",
            "event = \"pull_request_target\"",
        );
        assert!(
            validate_managed_command_callers(
                &manifest,
                &callers,
                &config,
                Some(unscoped.as_bytes())
            )
            .is_err()
        );
    }

    #[test]
    fn managed_manifest_requires_exactly_the_configured_role_files() {
        let instance_config = managed_instance_config();
        let files = managed_role_entries();
        assert!(validate_managed_targets(&files, &instance_config).is_ok());
        assert!(
            files
                .iter()
                .any(|file| file.target == MANAGED_CLIENT_RELEASE_TAG_TARGET)
        );

        let omitted_role = instance_config
            .workflow_roles
            .values()
            .next()
            .expect("fixture must configure at least one workflow role");
        let missing_role = files
            .iter()
            .filter(|file| file.target.as_str() != omitted_role.as_str())
            .cloned()
            .collect::<Vec<_>>();
        assert!(validate_managed_targets(&missing_role, &instance_config).is_err());

        let mut duplicate = files;
        duplicate.push(managed_entry(".github/workflows/policy-check.yml"));
        assert!(validate_managed_targets(&duplicate, &instance_config).is_err());

        let mut unexpected = managed_role_entries();
        unexpected.push(managed_entry(".github/workflows/unmanaged.yml"));
        assert!(validate_managed_targets(&unexpected, &instance_config).is_err());
    }

    #[test]
    fn managed_pr_file_validation_accounts_for_github_rename_rows() {
        let previous = ".github/workflows/testing-release-tag.yml".to_owned();
        let current = ".github/workflows/release-tag.yml".to_owned();
        let expected = BTreeSet::from([previous.clone(), current.clone()]);
        let files = vec![json!({
            "filename": current,
            "previous_filename": previous,
            "status": "renamed"
        })];

        assert!(validate_managed_pr_files(&files, &expected).is_ok());

        let unexpected_rename = vec![json!({
            "filename": ".github/workflows/release-tag.yml",
            "previous_filename": ".github/workflows/unmanaged.yml",
            "status": "renamed"
        })];
        assert!(validate_managed_pr_files(&unexpected_rename, &expected).is_err());
    }

    #[test]
    fn managed_role_templates_render_full_candidate_source_pins() {
        let instance_config = securefix::instance_config::InstanceConfig::parse(
            include_str!("../repo-settings/managed-files/securefix-server.toml").as_bytes(),
        )
        .unwrap();
        let mut desired = BTreeMap::from([
            (
                ".github/workflows/server-approve.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-approve.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-merge.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-merge.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-policy-check.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-policy-check.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-release.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-release.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-securefix.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-securefix.yml")
                    .as_bytes()
                    .to_vec(),
            ),
        ]);
        let source_sha = "a".repeat(40);
        render_managed_role_workflows(
            &mut desired,
            &instance_config,
            "civitaspo/securefix-server",
            &source_sha,
            "v0.2.45-pre.23 (candidate source)",
        )
        .unwrap();

        for (role, path) in &instance_config.workflow_roles {
            let rendered = desired.get(path).unwrap();
            assert!(!String::from_utf8_lossy(rendered).contains("@SECUREFIX_RUNTIME_SHA@"));
            let role_slug = workflow_role_slug(*role);
            let expected_label_prefix =
                if *role == securefix::instance_config::WorkflowRole::Release {
                    "testing-securefix-native-release-".to_owned()
                } else {
                    format!("securefix-native-{role_slug}-")
                };
            let parsed: serde_yaml::Value = serde_yaml::from_slice(rendered).unwrap();
            let condition = if *role == securefix::instance_config::WorkflowRole::Release {
                format!(
                    "startsWith(github.event.label.name, '{expected_label_prefix}') || startsWith(github.event.label.name, 'securefix-native-release-prepare-')"
                )
            } else {
                format!("startsWith(github.event.label.name, '{expected_label_prefix}')")
            };
            assert_eq!(
                parsed["jobs"]["handler"]["if"].as_str(),
                Some(condition.as_str())
            );
            assert_eq!(
                workflow_uses(rendered).unwrap(),
                BTreeSet::from([format!(
                    "civitaspo/securefix-server/.github/workflows/reusable-server-{}.yml@{source_sha}",
                    workflow_role_slug(*role)
                )])
            );
        }

        let path = instance_config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::Release)
            .unwrap();
        let broken = desired.get_mut(path).unwrap();
        *broken = include_str!("../repo-settings/managed-files/server-release.yml")
            .replace("@RUNTIME_VERSION@", "")
            .into_bytes();
        assert!(
            render_managed_role_workflows(
                &mut desired,
                &instance_config,
                "civitaspo/securefix-server",
                &source_sha,
                "v0.2.45-pre.23 (candidate source)",
            )
            .is_err()
        );
    }

    #[test]
    fn managed_role_templates_reject_broader_permissions_or_secret_sources() {
        let instance_config = securefix::instance_config::InstanceConfig::parse(
            include_str!("../repo-settings/managed-files/securefix-server.toml").as_bytes(),
        )
        .unwrap();
        let mut desired = BTreeMap::from([
            (
                ".github/workflows/server-approve.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-approve.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-merge.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-merge.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-policy-check.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-policy-check.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-release.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-release.yml")
                    .as_bytes()
                    .to_vec(),
            ),
            (
                ".github/workflows/server-securefix.yml".to_owned(),
                include_str!("../repo-settings/managed-files/server-securefix.yml")
                    .as_bytes()
                    .to_vec(),
            ),
        ]);
        let source_sha = "b".repeat(40);
        render_managed_role_workflows(
            &mut desired,
            &instance_config,
            "civitaspo/securefix-server",
            &source_sha,
            "v0.2.45-pre.23 (candidate source)",
        )
        .unwrap();

        let role = securefix::instance_config::WorkflowRole::Approve;
        let path = instance_config.workflow_roles.get(&role).unwrap();
        let uses = workflow_uses(desired.get(path).unwrap()).unwrap();
        let expected_uses = uses.iter().next().unwrap();
        let mut workflow: serde_yaml::Value =
            serde_yaml::from_slice(desired.get(path).unwrap()).unwrap();
        for group in [
            serde_yaml::Value::Null,
            serde_yaml::Value::String("other".to_owned()),
        ] {
            let mut altered = workflow.clone();
            altered["jobs"]["handler"]["concurrency"]["group"] = group;
            assert!(
                validate_rendered_managed_role_workflow(
                    role,
                    expected_uses,
                    &instance_config,
                    serde_yaml::to_string(&altered).unwrap().as_bytes()
                )
                .is_err()
            );
        }
        workflow["jobs"]["handler"]["permissions"]["contents"] =
            serde_yaml::Value::String("write".to_owned());
        assert!(
            validate_rendered_managed_role_workflow(
                role,
                expected_uses,
                &instance_config,
                serde_yaml::to_string(&workflow).unwrap().as_bytes(),
            )
            .is_err()
        );

        workflow["jobs"]["handler"]["permissions"]["contents"] =
            serde_yaml::Value::String("read".to_owned());
        workflow["jobs"]["handler"]["secrets"]["APPROVAL_TOKEN"] =
            serde_yaml::Value::String("${{ secrets.OTHER_TOKEN }}".to_owned());
        assert!(
            validate_rendered_managed_role_workflow(
                role,
                expected_uses,
                &instance_config,
                serde_yaml::to_string(&workflow).unwrap().as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn managed_client_release_tag_uses_its_own_accepted_full_sha_pin() {
        let manifest: ManagedFilesManifest =
            serde_json::from_slice(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        let instance_config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../repo-settings/native-role-events-test-instance.toml"
        ))
        .unwrap();
        let pin_sha = "c".repeat(40);
        let pin = crate::distribution::caller::ClientImplementationPin::new(
            "civitaspo/securefix-server",
            &pin_sha,
            "0.2.45",
        )
        .unwrap();
        let template = include_bytes!("../repo-settings/managed-files/release-tag.yml");
        assert_eq!(
            template.as_slice(),
            include_bytes!("distribution_templates/managed-client-release-tag.yml")
        );
        let rendered =
            render_managed_release_tag(&manifest, &instance_config, &pin, template).unwrap();
        let workflow: serde_yaml::Value = serde_yaml::from_slice(&rendered).unwrap();
        assert_eq!(
            workflow["permissions"],
            serde_yaml::Value::Mapping(Default::default())
        );
        assert_eq!(
            workflow["jobs"]["tag"]["uses"].as_str(),
            Some(
                format!(
                    "civitaspo/securefix-server/.github/workflows/reusable-release-tag.yml@{pin_sha}"
                )
                .as_str()
            )
        );
        assert_eq!(
            workflow["jobs"]["tag"]["with"].as_mapping().unwrap().len(),
            3,
            "managed caller passes only the release PR and protected instance locator"
        );
        assert_eq!(
            workflow["jobs"]["tag"]["with"]["release_pr_number"],
            r"${{ fromJSON(format('{0}', inputs.release_pr_number || github.event.pull_request.number || 0)) }}"
        );
        assert_eq!(
            workflow["jobs"]["tag"]["with"]["server_repository"],
            "civitaspo/securefix-server"
        );
        assert_eq!(
            workflow["jobs"]["tag"]["with"]["instance_config_path"],
            MANAGED_POLICY_CHECK_CALLER_CONFIG_PATH
        );
        assert!(String::from_utf8_lossy(&rendered).contains("# v0.2.45"));
        assert_eq!(
            workflow["jobs"]["tag"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"],
            "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
        );

        let wrong_repository = crate::distribution::caller::ClientImplementationPin::new(
            "civitaspo/other-client",
            &pin_sha,
            "0.2.45",
        )
        .unwrap();
        assert!(
            render_managed_release_tag(&manifest, &instance_config, &wrong_repository, template,)
                .is_err()
        );
        let wrong_version = crate::distribution::caller::ClientImplementationPin::new(
            "civitaspo/securefix-server",
            &pin_sha,
            "0.0.9",
        )
        .unwrap();
        assert!(
            render_managed_release_tag(&manifest, &instance_config, &wrong_version, template,)
                .is_err()
        );

        let mut wrong_authority = instance_config.clone();
        wrong_authority.instance.repository = manifest.repository.clone();
        wrong_authority.instance.id = manifest.repository_id;
        assert!(render_managed_release_tag(&manifest, &wrong_authority, &pin, template).is_err());
    }

    #[test]
    fn managed_removals_are_exact_inactive_workflow_paths() {
        let instance_config = managed_instance_config();
        let retired = vec![".github/workflows/old-server-approve.yml".to_owned()];
        assert!(validate_managed_removals(&retired, &instance_config).is_ok());

        let active_role = instance_config
            .workflow_roles
            .values()
            .next()
            .expect("fixture must configure at least one workflow role")
            .clone();
        assert!(validate_managed_removals(&[active_role], &instance_config).is_err());
        assert!(
            validate_managed_removals(&["securefix-server.toml".to_owned()], &instance_config)
                .is_err()
        );
        assert!(
            validate_managed_removals(
                &[MANAGED_CLIENT_RELEASE_TAG_TARGET.to_owned()],
                &instance_config
            )
            .is_err()
        );
        assert!(
            validate_managed_removals(
                &[
                    ".github/workflows/old-server-approve.yml".to_owned(),
                    ".github/workflows/OLD-SERVER-APPROVE.yml".to_owned(),
                ],
                &instance_config
            )
            .is_err()
        );
        assert!(
            validate_managed_removals(
                &[".github/workflows/nested/old.yml".to_owned()],
                &instance_config
            )
            .is_err()
        );
    }

    #[test]
    fn adopted_manifest_retires_only_the_observed_legacy_test_callers() {
        let manifest =
            parse_managed_manifest(include_bytes!("../repo-settings/managed-files.json")).unwrap();
        let desired = BTreeMap::from([(
            MANAGED_INSTANCE_CONFIG_TARGET.to_owned(),
            include_bytes!("../repo-settings/managed-files/securefix-server.toml").to_vec(),
        )]);
        let instance_config = validate_managed_instance_config(&manifest, &desired).unwrap();
        assert!(validate_managed_targets(&manifest.files, &instance_config).is_ok());
        assert!(validate_managed_removals(&manifest.remove, &instance_config).is_ok());

        let actual = manifest.remove.into_iter().collect::<BTreeSet<_>>();
        let expected = [
            ".github/workflows/native-securefix-producer.yml",
            ".github/workflows/native-approval-producer.yml",
            ".github/workflows/native-merge-producer.yml",
            ".github/workflows/testing-approve-request.yml",
            ".github/workflows/testing-merge-request.yml",
            ".github/workflows/testing-policy-check.yml",
            ".github/workflows/testing-release-pr-sync.yml",
            ".github/workflows/testing-release-pr.yml",
            ".github/workflows/testing-release-tag.yml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.target.clone())
                .collect::<BTreeSet<_>>(),
            expected_managed_targets(&instance_config)
        );
    }

    fn installation_repository(id: u64, full_name: &str, owner_id: u64) -> Value {
        json!({"id":id,"full_name":full_name,"owner":{"id":owner_id}})
    }

    fn installation_page(total_count: u64, repositories: Vec<Value>) -> Value {
        json!({"total_count":total_count,"repositories":repositories})
    }

    #[test]
    fn installation_scope_accepts_exact_paginated_repository_set() {
        let expected = vec!["forge/one".into(), "forge/two".into()];
        let fixture = Fixture::new(vec![
            Route::get(
                "/installation/repositories?per_page=100&page=1",
                installation_page(2, vec![installation_repository(1, "forge/one", 10)]),
            ),
            Route::get(
                "/installation/repositories?per_page=100&page=2",
                installation_page(2, vec![installation_repository(2, "forge/two", 10)]),
            ),
        ]);
        validate_installation_scope(&fixture.api, &expected, 10).unwrap();
        fixture.finish();
    }

    #[test]
    fn installation_scope_rejects_wrong_owner_extra_missing_and_malformed_entries() {
        let expected = vec!["forge/one".into()];
        for (repositories, total_count) in [
            (vec![installation_repository(1, "forge/one", 11)], 1),
            (
                vec![
                    installation_repository(1, "forge/one", 10),
                    installation_repository(2, "forge/two", 10),
                ],
                2,
            ),
            (vec![], 0),
            (vec![json!({"id":1,"full_name":"forge/one"})], 1),
            (vec![installation_repository(1, "malformed", 10)], 1),
            (
                vec![json!({"id":"1","full_name":"forge/one","owner":{"id":10}})],
                1,
            ),
        ] {
            let fixture = Fixture::new(vec![Route::get(
                "/installation/repositories?per_page=100&page=1",
                installation_page(total_count, repositories),
            )]);
            assert!(validate_installation_scope(&fixture.api, &expected, 10).is_err());
            fixture.finish();
        }
    }

    #[test]
    fn installation_scope_rejects_incomplete_pagination_and_http_errors() {
        let expected = vec!["forge/one".into(), "forge/two".into()];
        let incomplete = Fixture::new(vec![
            Route::get(
                "/installation/repositories?per_page=100&page=1",
                installation_page(2, vec![installation_repository(1, "forge/one", 10)]),
            ),
            Route::get(
                "/installation/repositories?per_page=100&page=2",
                installation_page(2, vec![]),
            ),
        ]);
        assert!(validate_installation_scope(&incomplete.api, &expected, 10).is_err());
        incomplete.finish();

        let failed = Fixture::new(vec![Route::request(
            "GET",
            "/installation/repositories?per_page=100&page=1",
            404,
            json!({"message":"Not Found"}),
        )]);
        assert!(validate_installation_scope(&failed.api, &expected, 10).is_err());
        failed.finish();
    }

    #[test]
    fn activation_tokens_are_minted_from_trusted_workflow_provenance() {
        let workflow: Value =
            serde_yaml::from_str(include_str!("../.github/workflows/repo-settings.yml")).unwrap();
        let deployment = &config::trusted().unwrap().deployment;
        for (job_name, repository_expression, consumer_name) in [
            (
                "prepare",
                "${{ steps.cli.outputs.repos_list }}",
                "Attested activation preflight",
            ),
            (
                "controlled-merges",
                "${{ needs.prepare.outputs.repos_list }}",
                "Reconcile controlled merge rulesets",
            ),
        ] {
            let job = &workflow["jobs"][job_name];
            assert_eq!(job["environment"], "main");
            let steps = job["steps"].as_array().unwrap();
            let mint = steps.iter().find(|step| step["id"] == "app-token").unwrap();
            let action = mint["uses"].as_str().unwrap();
            let (action_name, revision) = action.split_once('@').unwrap();
            assert_eq!(action_name, "actions/create-github-app-token");
            assert_eq!(revision.len(), 40);
            assert!(revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert_eq!(
                mint["with"]["app-id"].as_u64(),
                Some(deployment.server_app_id)
            );
            assert_eq!(
                mint["with"]["private-key"],
                "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
            );
            assert_eq!(mint["with"]["owner"], deployment.repository_owner.login);
            assert_eq!(mint["with"]["repositories"], repository_expression);
            for (permission, level) in [
                ("permission-actions", "read"),
                ("permission-checks", "write"),
                ("permission-contents", "write"),
                ("permission-pull-requests", "write"),
            ] {
                assert_eq!(mint["with"][permission], level);
            }
            let consumer = steps
                .iter()
                .find(|step| step["name"] == consumer_name)
                .unwrap();
            assert_eq!(
                consumer["env"]["SECUREFIX_SERVER_APP_TOKEN"],
                "${{ steps.app-token.outputs.token }}"
            );
        }
    }

    #[test]
    fn collaborator_readback_uses_github_effective_roles() {
        for (permission, accepted) in [
            ("write", true),
            ("admin", true),
            ("read", false),
            ("none", false),
            ("push", false),
            ("maintain", false),
        ] {
            let fixture = Fixture::new(vec![Route::get(
                "/repos/forge/example/collaborators/reviewer/permission",
                json!({"permission":permission}),
            )]);
            assert_eq!(
                validate_collaborator(&fixture.api, "forge/example", "reviewer").is_ok(),
                accepted
            );
            fixture.finish();
        }
    }

    #[test]
    fn reviewer_token_authenticates_identity_and_owner_checks_access() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        let owner = Fixture::new(vec![Route::get(
            "/repos/forge/example/collaborators/reviewer/permission",
            json!({"permission":"write"}),
        )]);
        let token = Fixture::new(vec![Route::get(
            "/user",
            json!({"login":"reviewer","id":100}),
        )]);
        validate_reviewer_access(&owner.api, &token.api, &["forge/example".into()], &reviewer)
            .unwrap();
        token.finish();
        owner.finish();
    }

    #[test]
    fn invitation_only_token_does_not_query_repository_permissions() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        for (permission, accepted) in [("write", true), ("read", false)] {
            let owner = Fixture::new(vec![Route::get(
                "/repos/forge/example/collaborators/reviewer/permission",
                json!({"permission":permission}),
            )]);
            let token = Fixture::new(vec![
                Route::get("/user", json!({"login":"reviewer","id":100})),
                Route::get(
                    "/user/repository_invitations?per_page=100&page=1",
                    json!([]),
                ),
            ]);
            assert_eq!(
                accept_reviewer_invitation(&owner.api, &token.api, "forge/example", &reviewer)
                    .is_ok(),
                accepted
            );
            token.finish();
            owner.finish();
        }
    }

    #[test]
    fn matching_invitation_is_accepted_before_owner_access_readback() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        let owner = Fixture::new(vec![Route::get(
            "/repos/forge/example/collaborators/reviewer/permission",
            json!({"permission":"write"}),
        )]);
        let token = Fixture::new(vec![
            Route::get("/user", json!({"login":"reviewer","id":100})),
            Route::get(
                "/user/repository_invitations?per_page=100&page=1",
                json!([
                    {"id":1,"repository":{"full_name":"forge/other"}},
                    {"id":2,"repository":{"full_name":"forge/example"}}
                ]),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request("PATCH", "/user/repository_invitations/2", 204, Value::Null),
        ]);
        accept_reviewer_invitation(&owner.api, &token.api, "forge/example", &reviewer).unwrap();
        token.finish();
        owner.finish();
    }

    #[test]
    fn default_readiness_uses_named_checks_and_rejects_newer_failure() {
        let sha = "a".repeat(40);
        let checks = Checks {
            status_app_id: 11,
            policy_app_id: 22,
        };
        for (latest_app, conclusion, accepted) in [
            (11, "success", true),
            (11, "failure", false),
            (99, "success", false),
            (11, "skipped", false),
        ] {
            let mut routes = vec![
                Route::get("/repos/forge/example", json!({"default_branch":"main"})),
                Route::get(
                    "/repos/forge/example/git/ref/heads/main",
                    json!({"object":{"sha":sha}}),
                ),
                Route::get(
                    format!(
                        "/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id=11"
                    ),
                    json!({"total_count":2,"check_runs":[
                        {"id":1,"name":"status-check","status":"completed","conclusion":"success","app":{"id":latest_app}},
                        {"id":2,"name":"status-check","status":"completed","conclusion":conclusion,"app":{"id":latest_app}}
                    ]}),
                ),
            ];
            if accepted {
                routes.push(Route::get(format!("/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=securefix-policy-check&app_id=22"),
                    json!({"total_count":1,"check_runs":[{"id":3,"name":"securefix-policy-check","status":"completed","conclusion":"success","app":{"id":22}}]})));
            }
            let fixture = Fixture::new(routes);
            assert_eq!(
                validate_current_policy_check(&fixture.api, "forge/example", &checks).is_ok(),
                accepted
            );
            fixture.finish();
        }
    }

    #[test]
    fn default_readiness_rejects_incomplete_named_response() {
        let sha = "a".repeat(40);
        let fixture = Fixture::new(vec![
            Route::get("/repos/forge/example", json!({"default_branch":"main"})),
            Route::get(
                "/repos/forge/example/git/ref/heads/main",
                json!({"object":{"sha":sha}}),
            ),
            Route::get(
                format!(
                    "/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id=11"
                ),
                json!({"total_count":101,"check_runs":[{"id":1,"name":"status-check","status":"completed","conclusion":"success","app":{"id":11}}]}),
            ),
        ]);
        assert!(
            validate_current_policy_check(
                &fixture.api,
                "forge/example",
                &Checks {
                    status_app_id: 11,
                    policy_app_id: 22
                }
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn scheduled_runs_reconcile_without_activating() {
        assert_eq!(
            activation_mode("schedule", "", false, true).unwrap(),
            ActivationMode::ScheduledReconcile
        );
        assert_eq!(
            activation_mode("workflow_dispatch", "", false, true).unwrap(),
            ActivationMode::NoActivation
        );
        assert_eq!(
            activation_mode("workflow_dispatch", "", true, true).unwrap(),
            ActivationMode::AttestedFullRollout
        );
        assert!(activation_mode("workflow_dispatch", "civitaspo/repo", true, true).is_err());
        assert!(activation_mode("workflow_dispatch", "", true, false).is_err());
        assert!(reconcile_existing_controlled_merges(
            &json!({"enforcement":"active"})
        ));
        assert!(!reconcile_existing_controlled_merges(
            &json!({"enforcement":"disabled"})
        ));
        assert!(!reconcile_existing_controlled_merges(
            &json!({"enforcement":"evaluate"})
        ));
    }

    #[test]
    fn controlled_merges_requires_exact_server_app_pr_bypass() {
        let valid = json!({
            "name":"controlled-merges",
            "target":"branch",
            "enforcement":"active",
            "bypass_actors":[{"actor_id":29,"actor_type":"Integration","bypass_mode":"pull_request"}],
            "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
            "rules":[{"type":"update","parameters":{"update_allows_fetch_and_merge":false}}]
        });
        assert!(validate_controlled_merges(&valid, "forge/example", 29).is_ok());

        let mut omitted_default = valid.clone();
        omitted_default["rules"] = json!([{"type":"update"}]);
        assert!(validate_controlled_merges(&omitted_default, "forge/example", 29).is_ok());
        for rules in [
            json!([{"type":"update","parameters":{"update_allows_fetch_and_merge":true}}]),
            json!([{"type":"update","parameters":{"update_allows_fetch_and_merge":0}}]),
            json!([{"type":"update","parameters":null}]),
            json!([{"type":"update","parameters":{}}]),
            json!([{"type":"update","unexpected":false}]),
        ] {
            let mut invalid = valid.clone();
            invalid["rules"] = rules;
            assert!(validate_controlled_merges(&invalid, "forge/example", 29).is_err());
        }

        let mut extra_bypass = valid.clone();
        extra_bypass["bypass_actors"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "actor_id":2740,"actor_type":"Integration","bypass_mode":"pull_request"
            }));
        assert!(validate_controlled_merges(&extra_bypass, "forge/example", 29).is_err());
        let mut always = valid.clone();
        always["bypass_actors"][0]["bypass_mode"] = json!("always");
        assert!(validate_controlled_merges(&always, "forge/example", 29).is_err());
        let mut extra_rule = valid;
        extra_rule["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"deletion"}));
        assert!(validate_controlled_merges(&extra_rule, "forge/example", 29).is_err());
    }

    #[test]
    fn native_auto_merge_and_alternate_merge_methods_are_rejected() {
        let settings = json!({
            "allow_auto_merge":false,
            "allow_squash_merge":true,
            "allow_merge_commit":false,
            "allow_rebase_merge":false
        });
        assert!(validate_repository_merge_settings(&settings, "forge/example").is_ok());
        for (field, value) in [
            ("allow_auto_merge", json!(true)),
            ("allow_merge_commit", json!(true)),
            ("allow_rebase_merge", json!(true)),
            ("allow_squash_merge", json!(false)),
        ] {
            let mut unsafe_settings = settings.clone();
            unsafe_settings[field] = value;
            assert!(validate_repository_merge_settings(&unsafe_settings, "forge/example").is_err());
        }
    }

    #[test]
    fn repository_creation_uses_org_endpoint_and_only_creates_user_repos_for_maintainer() {
        let org = config::Principal {
            login: "forge-org".into(),
            id: 200,
        };
        let maintainer = config::Principal {
            login: "alice".into(),
            id: 100,
        };
        assert_eq!(
            repository_creation_path("Organization", &org, &maintainer).unwrap(),
            "/orgs/forge-org/repos"
        );
        assert_eq!(
            repository_creation_path("User", &maintainer, &maintainer).unwrap(),
            "/user/repos"
        );
        assert!(repository_creation_path("User", &org, &maintainer).is_err());
    }

    #[test]
    fn reviewer_invitation_identity_is_not_the_client_app_bot() {
        let reviewer = config::Principal {
            login: "approval-reviewer".into(),
            id: 100,
        };
        assert!(
            validate_reviewer_identity(&json!({"login":"approval-reviewer","id":100}), &reviewer)
                .is_ok()
        );
        assert!(
            validate_reviewer_identity(&json!({"login":"client-bot[bot]","id":200}), &reviewer)
                .is_err()
        );
    }

    #[test]
    fn activation_readiness_covers_the_full_merge_set_and_keeps_server_last() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let expected = policy
            .repositories
            .iter()
            .filter(|repo| repo.capabilities.contains(&Capability::Merge))
            .map(|repo| repo.repository.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let activation = merge_repositories(
            &policy,
            &config::trusted().unwrap().deployment.server.repository,
        )
        .unwrap();
        let actual = activation
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            activation.last().map(String::as_str),
            Some(
                config::trusted()
                    .unwrap()
                    .deployment
                    .server
                    .repository
                    .as_str()
            )
        );
        assert!(
            activation[..activation.len() - 1]
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn default_ruleset_keeps_unbypassable_pr_integrity_without_reviews_or_checks() {
        let valid = json!({
            "target":"branch",
            "enforcement":"active",
            "bypass_actors":[],
            "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
            "rules":[
                {"type":"deletion"},
                {"type":"non_fast_forward"},
                {"type":"required_linear_history"},
                {"type":"required_signatures"},
                {"type":"pull_request","parameters":{"required_approving_review_count":0,"allowed_merge_methods":["squash"]}}
            ]
        });
        assert!(validate_default_ruleset(&valid, "forge/example").is_ok());
        let mut bypass = valid.clone();
        bypass["bypass_actors"] = json!([{"actor_id":23}]);
        assert!(validate_default_ruleset(&bypass, "forge/example").is_err());
        let mut review = valid.clone();
        review["rules"][4]["parameters"]["required_approving_review_count"] = json!(1);
        assert!(validate_default_ruleset(&review, "forge/example").is_err());
        let mut checks = valid.clone();
        checks["rules"].as_array_mut().unwrap().push(json!({
            "type":"required_status_checks",
            "parameters":{"required_status_checks":[]}
        }));
        assert!(validate_default_ruleset(&checks, "forge/example").is_err());
        let mut missing_signature = valid.clone();
        missing_signature["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|rule| rule["type"] != "required_signatures");
        assert!(validate_default_ruleset(&missing_signature, "forge/example").is_err());
        let mut other_branch = valid.clone();
        other_branch["conditions"]["ref_name"]["include"] = json!(["refs/heads/release"]);
        assert!(validate_default_ruleset(&other_branch, "forge/example").is_err());
    }

    #[test]
    fn review_and_checks_ruleset_requires_exact_server_app_bypass_and_configured_checks() {
        let checks = Checks {
            status_app_id: 17,
            policy_app_id: 23,
        };
        let valid = json!({
            "target":"branch",
            "enforcement":"active",
            "bypass_actors":[{"actor_id":29,"actor_type":"Integration","bypass_mode":"pull_request"}],
            "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
            "rules":[
                {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"allowed_merge_methods":["squash"]}},
                {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,"do_not_enforce_on_create":false,"required_status_checks":[
                    {"context":"status-check","integration_id":17},
                    {"context":"securefix-policy-check","integration_id":23}
                ]}}
            ]
        });
        assert!(validate_review_and_checks(&valid, "forge/example", 29, &checks).is_ok());

        let mut wrong_app = valid.clone();
        wrong_app["bypass_actors"][0]["actor_id"] = json!(30);
        assert!(validate_review_and_checks(&wrong_app, "forge/example", 29, &checks).is_err());
        let mut extra_bypass = valid.clone();
        extra_bypass["bypass_actors"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "actor_id":100,"actor_type":"RepositoryRole","bypass_mode":"always"
            }));
        assert!(validate_review_and_checks(&extra_bypass, "forge/example", 29, &checks).is_err());
        let mut direct_bypass = valid.clone();
        direct_bypass["bypass_actors"][0]["bypass_mode"] = json!("always");
        assert!(validate_review_and_checks(&direct_bypass, "forge/example", 29, &checks).is_err());
        let mut wrong_check_source = valid.clone();
        wrong_check_source["rules"][1]["parameters"]["required_status_checks"][1]["integration_id"] =
            json!(15368);
        assert!(
            validate_review_and_checks(&wrong_check_source, "forge/example", 29, &checks).is_err()
        );
        let mut stale_reviews = valid.clone();
        stale_reviews["rules"][0]["parameters"]["dismiss_stale_reviews_on_push"] = json!(false);
        assert!(validate_review_and_checks(&stale_reviews, "forge/example", 29, &checks).is_err());
        let mut other_branch = valid;
        other_branch["conditions"]["ref_name"]["include"] = json!(["refs/heads/release"]);
        assert!(validate_review_and_checks(&other_branch, "forge/example", 29, &checks).is_err());
    }

    #[test]
    fn current_default_ruleset_is_fetched_by_id_before_validating_protections() {
        let list_path = "/repos/forge/example/rulesets?includes_parents=false&per_page=100&page=1";
        let detail_path = "/repos/forge/example/rulesets/41";
        // The list endpoint returns summary metadata only. Protection data must
        // come from the per-ID detail endpoint, where bypass actors and rules live.
        let listed = json!([{
            "id":41,
            "name":"default-branch",
            "target":"branch",
            "source_type":"Repository"
        }]);
        let detail = json!({
            "id":41,
            "name":"default-branch",
            "target":"branch",
            "source":"forge/example",
            "source_type":"Repository",
            "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
            "enforcement":"active",
            "bypass_actors":[],
            "rules":[
                {"type":"deletion"},
                {"type":"non_fast_forward"},
                {"type":"required_linear_history"},
                {"type":"required_signatures"},
                {"type":"pull_request","parameters":{"required_approving_review_count":0,"allowed_merge_methods":["squash"]}}
            ]
        });
        let fixture = Fixture::new(vec![
            Route::get(list_path, listed.clone()),
            Route::get(detail_path, detail.clone()),
        ]);
        validate_default_branch_ruleset(&fixture.api, "forge/example").unwrap();
        fixture.finish();

        for (pointer, replacement) in [
            ("/id", json!(42)),
            ("/name", json!("other")),
            ("/source_type", json!("Organization")),
            ("/source", json!("forge/other")),
        ] {
            let mut malformed = detail.clone();
            malformed
                .pointer_mut(pointer)
                .unwrap()
                .clone_from(&replacement);
            let fixture = Fixture::new(vec![
                Route::get(list_path, listed.clone()),
                Route::get(detail_path, malformed),
            ]);
            assert!(
                validate_default_branch_ruleset(&fixture.api, "forge/example").is_err(),
                "mismatched detail identity {pointer} passed validation"
            );
            fixture.finish();
        }

        for (pointer, replacement) in [
            ("/name", json!("other")),
            ("/source_type", json!("Organization")),
        ] {
            let mut malformed = listed.clone();
            malformed[0]
                .pointer_mut(pointer)
                .unwrap()
                .clone_from(&replacement);
            let fixture = Fixture::new(vec![Route::get(list_path, malformed)]);
            assert!(
                validate_default_branch_ruleset(&fixture.api, "forge/example").is_err(),
                "mismatched list identity {pointer} passed validation"
            );
            fixture.finish();
        }
    }

    #[test]
    fn server_wrapper_pin_uses_the_trusted_deployment_repository() {
        assert_eq!(
            wrapper_pin(
                "forge/securefix",
                "reusable-approve-request.yml",
                &"a".repeat(40)
            )
            .unwrap(),
            format!(
                "forge/securefix/.github/workflows/reusable-approve-request.yml@{}",
                "a".repeat(40)
            )
        );
    }

    #[test]
    fn workflow_pin_parser_rejects_unexpected_callers() {
        let workflow: Value = serde_yaml::from_str("on: workflow_dispatch\njobs:\n  call:\n    uses: civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").unwrap();
        assert_eq!(
            find_uses(&workflow),
            vec![
                "civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]
        );
        let additional: Value = serde_yaml::from_str("jobs:\n  call:\n    uses: civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  extra:\n    uses: attacker/workflow@main\n").unwrap();
        assert_eq!(find_uses(&additional).len(), 2);
    }

    #[test]
    fn immutable_release_reconciliation_is_release_scoped_and_non_disabling() {
        let repository = RepositoryPolicy {
            repository: "civitaspo/example".into(),
            capabilities: vec![Capability::Settings],
            release: None,
            native_binaries: Vec::new(),
            sensitive_paths: vec![".github/**".into()],
            protect_tags: false,
        };
        let fixture = Fixture::new(vec![]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();

        let repository = RepositoryPolicy {
            capabilities: vec![Capability::Settings, Capability::Release],
            release: Some(crate::policy::ReleaseStrategy::GithubRelease),
            ..repository
        };
        let path = "/repos/civitaspo/example/immutable-releases";
        let fixture = Fixture::new(vec![Route::get(
            path,
            json!({"enabled":true,"enforced_by_owner":false}),
        )]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();

        let server = RepositoryPolicy {
            repository: config::trusted()
                .unwrap()
                .deployment
                .server
                .repository
                .clone(),
            capabilities: vec![Capability::Settings],
            release: None,
            native_binaries: Vec::new(),
            sensitive_paths: vec![".github/**".into()],
            protect_tags: false,
        };
        let path = format!("/repos/{}/immutable-releases", server.repository);
        let fixture = Fixture::new(vec![Route::get(
            path,
            json!({"enabled":true,"enforced_by_owner":false}),
        )]);
        ensure_immutable_releases(&fixture.api, &server).unwrap();
        fixture.finish();
    }

    #[test]
    fn runtime_publication_requires_server_immutable_releases() {
        let server = &config::trusted().unwrap().deployment.server.repository;
        let path = format!("/repos/{server}/immutable-releases");
        let enabled = Fixture::new(vec![Route::get(
            &path,
            json!({"enabled":true,"enforced_by_owner":false}),
        )]);
        require_server_immutable_releases(&enabled.api).unwrap();
        enabled.finish();

        let disabled = Fixture::new(vec![Route::get(
            path,
            json!({"enabled":false,"enforced_by_owner":false}),
        )]);
        assert!(require_server_immutable_releases(&disabled.api).is_err());
        disabled.finish();
    }

    #[test]
    fn disabled_immutable_releases_are_enabled_then_verified() {
        let repository = RepositoryPolicy {
            repository: "civitaspo/example".into(),
            capabilities: vec![Capability::Release],
            release: Some(crate::policy::ReleaseStrategy::GithubRelease),
            native_binaries: Vec::new(),
            sensitive_paths: vec![".github/**".into()],
            protect_tags: false,
        };
        let path = "/repos/civitaspo/example/immutable-releases";
        let fixture = Fixture::new(vec![
            Route::request("GET", path, 404, json!({"message":"Not Found"})),
            Route::active_control(&Fixture::control_revision()),
            Route::request("PUT", path, 204, Value::Null),
            Route::get(path, json!({"enabled":true,"enforced_by_owner":false})),
        ]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();
    }
}
