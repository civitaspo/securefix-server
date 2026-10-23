use super::*;
use crate::native_client::{ProducerIdentity, RepositoryIdentity, SecurefixArtifactIdentity};
use crate::securefix_gate::{self, SourceRequest};
use std::fs;

const SIGNER: &str = ".github/workflows/reusable-release-pr.yml";
const PROTOCOL: &str = "securefix-native-request/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationManifest {
    protocol: String,
    operation: String,
    repository: RepositoryIdentity,
    producer: ProducerIdentity,
    artifact: SecurefixArtifactIdentity,
    default_branch: String,
    release_branch: String,
    destination_head: String,
    destination_branch_exists: bool,
    client_workflow_epoch: String,
    server_authority: NativeAuthoritySnapshot,
}

impl PreparationManifest {
    fn validate(&self) -> Result<()> {
        validate_repository(&self.repository.full_name)?;
        crate::policy::validate_sha(&self.producer.context_sha)?;
        crate::policy::validate_sha(&self.producer.source_sha)?;
        crate::policy::validate_sha(&self.producer.workflow_sha)?;
        crate::policy::validate_sha(&self.destination_head)?;
        crate::policy::validate_sha(&self.client_workflow_epoch)?;
        crate::config::validate_branch(&self.default_branch)?;
        crate::config::validate_branch(&self.release_branch)?;
        ensure!(
            self.protocol == PROTOCOL
                && self.operation == "release_prepare"
                && self.server_authority.instance_id > 0
                && self.repository.id > 0
                && self.producer.run_id > 0
                && self.producer.run_attempt == 1
                && self.producer.context_sha == self.producer.source_sha
                && self.default_branch != self.release_branch
                && (!self.destination_branch_exists || !self.destination_head.is_empty())
                && (self.destination_branch_exists
                    || self.destination_head == self.producer.source_sha)
                && matches!(self.producer.event.as_str(), "push" | "workflow_dispatch")
                && self.producer.workflow_ref == format!("refs/heads/{}", self.default_branch)
                && self
                    .producer
                    .workflow_path
                    .starts_with(".github/workflows/")
                && self.producer.workflow_path.ends_with(".yml")
                && !self.producer.workflow_path.contains("..")
                && self.artifact.id > 0
                && self.artifact.name.starts_with("securefix-")
                && securefix_gate::artifact::valid_artifact_name_for_cli(&self.artifact.name)
                && self
                    .artifact
                    .digest
                    .strip_prefix("sha256:")
                    .is_some_and(|s| s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
            "invalid native release preparation manifest"
        );
        Ok(())
    }
}

pub(super) fn prepare(input_version: &str) -> Result<()> {
    let api = api()?;
    let instance = native_release_instance_for(
        &api,
        &env("SECUREFIX_SERVER_REPOSITORY")?,
        &env("SECUREFIX_INSTANCE_CONFIG_PATH")?,
    )?;
    let repo = current_repository()?;
    configured_release_destination(&instance.config, &repo)?;
    let metadata: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = metadata["default_branch"]
        .as_str()
        .context("release default branch missing")?;
    ensure!(
        env("GITHUB_REF")? == format!("refs/heads/{default_branch}")
            && git_output(&["rev-parse", "HEAD"])? == env("GITHUB_SHA")?
            && api.branch_head(repo.as_str(), default_branch)? == env("GITHUB_SHA")?,
        "release preparation requires the current protected default-branch checkout"
    );
    crate::output(
        "release_branch",
        instance
            .config
            .branches
            .release
            .as_deref()
            .context("release branch missing")?,
    )?;
    crate::output("default_branch", default_branch)?;
    prepare_metadata(input_version)
}

pub(super) fn capture(artifact_name: &str, output: &Path) -> Result<()> {
    let api = api()?;
    let instance = native_release_instance_for(
        &api,
        &env("SECUREFIX_SERVER_REPOSITORY")?,
        &env("SECUREFIX_INSTANCE_CONFIG_PATH")?,
    )?;
    let repo = current_repository()?;
    let id = configured_release_destination(&instance.config, &repo)?;
    let metadata: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = metadata["default_branch"]
        .as_str()
        .context("default branch missing")?
        .to_owned();
    ensure!(
        metadata["id"].as_u64() == Some(id),
        "release repository ID mismatch"
    );
    let run_id = env("GITHUB_RUN_ID")?.parse::<u64>()?;
    let run: Value = api.get(&format!("/repos/{}/actions/runs/{run_id}", repo.as_str()))?;
    let sha = env("GITHUB_SHA")?;
    let workflow_sha = env("SECUREFIX_CALLER_WORKFLOW_SHA")?;
    let workflow_path = crate::native_client::canonical_workflow_path(
        run["path"].as_str().context("release caller missing")?,
    )?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"] == 1
            && run["repository"]["id"].as_u64() == Some(id)
            && run["head_repository"]["id"].as_u64() == Some(id)
            && run["head_sha"] == sha
            && run["head_branch"] == default_branch
            && run["status"] == "in_progress"
            && matches!(run["event"].as_str(), Some("push" | "workflow_dispatch"))
            && api.branch_head(repo.as_str(), &default_branch)? == sha,
        "release preparation run is not the current default-branch source"
    );
    let branch = instance
        .config
        .branches
        .release
        .as_deref()
        .context("release branch missing")?
        .to_owned();
    let destination = api.optional_branch_head(repo.as_str(), &branch)?;
    let manifest = PreparationManifest {
        protocol: PROTOCOL.into(),
        operation: "release_prepare".into(),
        repository: RepositoryIdentity {
            id,
            full_name: repo.as_str().into(),
        },
        producer: ProducerIdentity {
            run_id,
            run_attempt: env("GITHUB_RUN_ATTEMPT")?.parse()?,
            event: run["event"].as_str().context("run event missing")?.into(),
            context_sha: sha.clone(),
            source_sha: sha.clone(),
            workflow_path: workflow_path.clone(),
            workflow_ref: crate::native_client::capture_workflow_ref(
                repo.as_str(),
                &workflow_path,
            )?,
            workflow_sha: workflow_sha.clone(),
            actor_id: run["actor"]["id"].as_u64().context("actor missing")?,
            actor_login: run["actor"]["login"]
                .as_str()
                .context("actor login missing")?
                .into(),
        },
        artifact: crate::native_client::capture_artifact_identity(
            &api,
            repo.as_str(),
            run_id,
            id,
            &sha,
            artifact_name,
        )?,
        default_branch: default_branch.clone(),
        release_branch: branch,
        destination_head: destination.clone().unwrap_or(sha),
        destination_branch_exists: destination.is_some(),
        client_workflow_epoch: securefix::api::capture_native_client_workflow_epoch(
            &api,
            repo.as_str(),
            id,
            &default_branch,
            &workflow_path,
            &workflow_sha,
            None,
        )?,
        server_authority: instance.authority,
    };
    manifest.validate()?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec(&manifest)?)?;
    crate::output(
        "server_owner",
        manifest
            .server_authority
            .instance_repository
            .split('/')
            .next()
            .context("Server owner missing")?,
    )?;
    crate::output(
        "server_repository_name",
        manifest
            .server_authority
            .instance_repository
            .split('/')
            .nth(1)
            .context("Server name missing")?,
    )?;
    crate::output("client_app_id", instance.config.apps.client_id.to_string())?;
    Ok(())
}

pub(super) fn dispatch(path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "release preparation manifest oversized"
    );
    let m: PreparationManifest = serde_json::from_slice(&bytes)?;
    m.validate()?;
    ensure!(
        env("GITHUB_REPOSITORY")? == m.repository.full_name
            && env("GITHUB_RUN_ID")?.parse::<u64>()? == m.producer.run_id
            && env("GITHUB_RUN_ATTEMPT")?.parse::<u32>()? == m.producer.run_attempt
            && env("SECUREFIX_SERVER_REPOSITORY")? == m.server_authority.instance_repository,
        "release preparation dispatch differs from the captured run"
    );
    let label = securefix::api::native_client_request_label("release_prepare", m.producer.run_id)?;
    let target = crate::api::NativeClientLabelTarget {
        server_repository: &m.server_authority.instance_repository,
        server_authority: &m.server_authority,
        client_repository: &m.repository.full_name,
        operation: "release_prepare",
        run_id: m.producer.run_id,
    };
    let writer = GitHub::native_client_label_from_env("SECUREFIX_CLIENT_TOKEN", &target)?;
    let _: Value = writer.post(&format!("/repos/{}/labels", m.server_authority.instance_repository),
        &json!({"name":label,"color":"1f6feb","description":format!("{}/{}",m.repository.full_name,m.producer.run_id)}))?;
    Ok(())
}

fn locator(instance: &NativeServerInstanceAuthority) -> Result<(String, u64)> {
    ensure!(
        env("GITHUB_EVENT_NAME")? == "label",
        "release preparation requires a label event"
    );
    let event = crate::event()?;
    let bot = &instance.config.identities.client_bot;
    ensure!(
        event["action"] == "created"
            && event["repository"]["id"].as_u64() == Some(instance.config.instance.id)
            && event["repository"]["full_name"] == instance.config.instance.repository
            && crate::request::matches_principal(&event["sender"], bot.id, &bot.login, "Bot"),
        "release preparation label is not from the configured Client App"
    );
    let (repo, run) =
        crate::native_server::native_request_event_locator(&event, "release-prepare")?;
    let repository = Repository::parse(&repo)?;
    configured_release_destination(&instance.config, &repository)?;
    Ok((repo, run))
}

pub(super) fn locate() -> Result<()> {
    let api = api()?;
    let instance = native_release_instance(&api)?;
    validate_host(&api, &instance)?;
    let (repository, run) = locator(&instance)?;
    let (owner, name) = repository.split_once('/').context("invalid repository")?;
    crate::output("repository", &repository)?;
    crate::output("repo_owner", owner)?;
    crate::output("repo_name", name)?;
    crate::output("run_id", run.to_string())?;
    crate::output("server_app_id", instance.config.apps.server_id.to_string())
}

fn validate_host(api: &GitHub, instance: &NativeServerInstanceAuthority) -> Result<()> {
    ensure!(
        env("GITHUB_REPOSITORY")? == instance.config.instance.repository
            && env("GITHUB_REF")?
                == format!("refs/heads/{}", instance.config.instance.default_branch),
        "release preparation is outside the protected Server"
    );
    let role = securefix::instance_config::WorkflowRole::Release;
    let path = instance
        .config
        .workflow_roles
        .get(&role)
        .context("Release role missing")?;
    let sha = env("GITHUB_WORKFLOW_SHA")?;
    let bytes = api.content(&instance.config.instance.repository, path, &sha)?;
    securefix::api::validate_native_server_execution_workflow_role(
        &instance.authority,
        role,
        &env("GITHUB_WORKFLOW_REF")?,
        &sha,
        &bytes,
    )
}

pub(super) fn apply(apply: bool) -> Result<()> {
    let server = api()?;
    let instance = native_release_instance(&server)?;
    validate_host(&server, &instance)?;
    let (repository, run_id) = locator(&instance)?;
    let client = GitHub::from_env("SECUREFIX_CLIENT_TOKEN")?;
    let (bytes, bundle) = crate::native_server::download_request_proof_for_instance(
        &server,
        &client,
        &instance,
        &repository,
        run_id,
        Capability::Release,
    )?;
    let m: PreparationManifest = serde_json::from_slice(&bytes)?;
    m.validate()?;
    ensure!(
        m.repository.full_name == repository
            && m.producer.run_id == run_id
            && m.repository.id
                == configured_release_destination(
                    &instance.config,
                    &Repository::parse(&repository)?
                )?,
        "release preparation locator mismatch"
    );
    securefix::api::require_native_authority_unchanged(&m.server_authority, &instance.authority)?;
    let run: Value = client.get(&format!("/repos/{repository}/actions/runs/{run_id}"))?;
    let owner = &instance.config.identities.owner;
    let bot = &instance.config.identities.server_bot;
    ensure!(
        run["run_attempt"].as_u64() == Some(u64::from(m.producer.run_attempt))
            && run["head_sha"] == m.producer.source_sha
            && run["head_branch"] == m.default_branch
            && run["event"] == m.producer.event
            && run["actor"]["id"].as_u64() == Some(m.producer.actor_id)
            && run["actor"]["login"] == m.producer.actor_login
            && (crate::request::matches_principal(&run["actor"], owner.id, &owner.login, "User")
                || crate::request::matches_principal(&run["actor"], bot.id, &bot.login, "Bot")),
        "release preparation producer identity mismatch"
    );
    let references: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())?;
    let signer_sha = crate::native_server::unique_referenced_workflow_sha(
        &references,
        &instance.config.acceptable_clients.repository,
        SIGNER,
    )?;
    let signer_bytes = server.content(
        &instance.config.acceptable_clients.repository,
        SIGNER,
        &signer_sha,
    )?;
    let action = crate::native_server::native_client_package_action(
        &signer_bytes,
        &instance.config.acceptable_clients.repository,
    )?;
    let package = crate::native_server::verify_configured_client_package(
        &server,
        &instance.config,
        &signer_sha,
        &action,
    )?;
    let directory = tempfile::tempdir()?;
    let subject = directory.path().join("manifest.json");
    let bundle_path = directory.path().join("bundle.json");
    fs::write(&subject, &bytes)?;
    fs::write(&bundle_path, bundle)?;
    let verified = securefix::attestation::verify_with_gh(
        &subject,
        &bundle_path,
        securefix::attestation::VerifyRequest {
            repository: &repository,
            signer_repository: &instance.config.acceptable_clients.repository,
            signer_workflow: SIGNER,
            signer_sha: &signer_sha,
            source: Some((&m.producer.context_sha, &m.producer.workflow_ref)),
        },
    )?;
    crate::native_server::verify_native_certificate(
        &verified,
        &m.repository,
        &m.producer,
        &run,
        &instance.config.acceptable_clients.repository,
        SIGNER,
        &signer_sha,
        &bytes,
    )?;
    let metadata: Value = client.get(&format!("/repos/{repository}"))?;
    ensure!(
        metadata["default_branch"] == m.default_branch
            && client.branch_head(&repository, &m.default_branch)? == m.producer.source_sha,
        "release preparation default branch advanced"
    );
    let epoch = securefix::api::capture_native_client_workflow_epoch(
        &client,
        &repository,
        m.repository.id,
        &m.default_branch,
        &m.producer.workflow_path,
        &m.producer.workflow_sha,
        None,
    )?;
    securefix::api::require_native_client_workflow_epoch_unchanged(
        &m.client_workflow_epoch,
        &epoch,
    )?;
    ensure!(
        Some(m.release_branch.as_str()) == instance.config.branches.release.as_deref(),
        "release branch differs from protected config"
    );
    let actual_branch = client.optional_branch_head(&repository, &m.release_branch)?;
    ensure!(
        actual_branch.is_some() == m.destination_branch_exists
            && actual_branch.as_deref().unwrap_or(&m.producer.source_sha) == m.destination_head,
        "release preparation destination head is stale or replayed"
    );
    let artifact = crate::native_client::capture_artifact_identity(
        &client,
        &repository,
        run_id,
        m.repository.id,
        &m.producer.source_sha,
        &m.artifact.name,
    )?;
    ensure!(
        artifact == m.artifact,
        "release preparation artifact identity changed"
    );
    let zip = client.download(
        &format!("/repos/{repository}/actions/artifacts/{}/zip", artifact.id),
        16 * 1024 * 1024,
    )?;
    ensure!(
        format!("sha256:{}", crate::hex_encode(Sha256::digest(&zip))) == artifact.digest,
        "release preparation artifact digest mismatch"
    );
    let fix = securefix_gate::artifact::parse(
        &zip,
        &artifact.name,
        &repository,
        run_id,
        &m.producer.source_sha,
        &m.default_branch,
    )?;
    let (title, body) = validate_metadata(&client, &m, &fix)?;
    let source = SourceRequest {
        repository: &repository,
        run_id,
        label: &artifact.name,
        branch: &m.default_branch,
        sha: &m.producer.source_sha,
    };
    let destination = securefix_gate::release_destination_head(
        &client,
        &source,
        &fix,
        &m.default_branch,
        bot.id,
    )?;
    ensure!(
        destination.sha == m.destination_head
            && destination.branch_exists == m.destination_branch_exists,
        "release preparation destination changed"
    );
    if !apply {
        return Ok(());
    }
    let server_url = env("GITHUB_SERVER_URL")?;
    let server_run = env("GITHUB_RUN_ID")?;
    let message = format!(
        "{}\n{server_url}/{}/actions/runs/{server_run}\n\nSecurefix-Artifact: {repository}/{run_id}/{}",
        fix.commit_message, instance.config.instance.repository, artifact.name
    );
    let writer = GitHub::native_release_preparation_from_env(
        "SECUREFIX_CLIENT_TOKEN",
        "SECUREFIX_WRITE_TOKEN",
        crate::api::NativeReleasePreparationTarget {
            instance: instance.clone(),
            repository: repository.clone(),
            repository_id: m.repository.id,
            source_sha: m.producer.source_sha.clone(),
            default_branch: m.default_branch.clone(),
            release_branch: m.release_branch.clone(),
            expected_head: destination.sha.clone(),
            branch_exists: destination.branch_exists,
            existing_pull_request: destination.pull_request,
            workflow_path: m.producer.workflow_path.clone(),
            workflow_sha: m.producer.workflow_sha.clone(),
            workflow_epoch: m.client_workflow_epoch.clone(),
            run_id,
            run_attempt: u64::from(m.producer.run_attempt),
            additions: fix.additions.clone(),
            deletions: fix.deletions.clone(),
            commit_message: message,
            title,
            body,
            client_package: package,
        },
    )?;
    let plan = securefix_gate::FixPlan {
        version: 1,
        source_repository: repository.clone(),
        source_run_id: run_id,
        source_sha: m.producer.source_sha.clone(),
        artifact_name: artifact.name.clone(),
        artifact_id: artifact.id,
        destination_repository: repository.clone(),
        destination_branch: m.release_branch.clone(),
        expected_head: destination.sha,
        destination_branch_exists: destination.branch_exists,
        existing_pull_request: destination.pull_request,
    };
    let result = securefix_gate::apply_core(securefix_gate::ApplyCore {
        read_api: &client,
        write_api: &writer,
        server_bot_id: bot.id,
        source,
        plan: &plan,
        fix: &fix,
        server_url: &server_url,
        server_repository: &instance.config.instance.repository,
        server_run: &server_run,
    })?;
    crate::output("commit_sha", &result.commit_sha)?;
    crate::output(
        "pull_request_number",
        result
            .pull_request_number
            .context("release PR was not created")?
            .to_string(),
    )
}

fn validate_metadata(
    api: &GitHub,
    m: &PreparationManifest,
    fix: &securefix_gate::artifact::FixArtifact,
) -> Result<(String, String)> {
    ensure!(
        fix.repository == m.repository.full_name
            && fix.branch == m.release_branch
            && fix.event_name == m.producer.event
            && fix.pull_request_context.is_none()
            && fix.deletions.is_empty()
            && fix.additions.contains_key(".release-version")
            && fix.additions.contains_key("CHANGELOG.md")
            && fix.additions.keys().all(|p| [
                ".release-version",
                "CHANGELOG.md",
                "Cargo.toml",
                "Cargo.lock",
                "dbt_project.yml",
                "pyproject.toml"
            ]
            .contains(&p.as_str())),
        "release preparation artifact contains non-release changes"
    );
    let version = std::str::from_utf8(&fix.additions[".release-version"])?.trim();
    let parsed = Version::parse(version)?;
    ensure!(
        parsed.build.is_empty(),
        "release version contains build metadata"
    );
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "dbt_project.yml",
    ] {
        if let Some(changed) = fix.additions.get(path) {
            let source = api.content(&m.repository.full_name, path, &m.producer.source_sha)?;
            let root_name = if path == "Cargo.lock" {
                let manifest = api.content(
                    &m.repository.full_name,
                    "Cargo.toml",
                    &m.producer.source_sha,
                )?;
                let manifest: toml_edit::DocumentMut = std::str::from_utf8(&manifest)?.parse()?;
                Some(
                    manifest["package"]["name"]
                        .as_str()
                        .context("root Cargo package name missing")?
                        .to_owned(),
                )
            } else {
                None
            };
            validate_version_only_change(path, &source, changed, version, root_name.as_deref())?;
        }
    }
    let metadata = if fix.additions.contains_key("dbt_project.yml")
        || fix.additions.contains_key("pyproject.toml")
        || fix.additions.contains_key("Cargo.toml")
    {
        "package version metadata"
    } else {
        "release metadata"
    };
    let title = format!("chore(release): v{version}");
    let body = format!(
        "## Summary\n- Prepare release v{version}\n- Update the changelog and {metadata}\n\nThis pull request is managed by the Release PR workflow."
    );
    let options: Value = serde_json::from_str(
        fix.create_pull_request
            .as_deref()
            .context("release PR options missing")?,
    )?;
    ensure!(
        options == json!({"title":title,"body":body,"base":m.default_branch})
            && fix.commit_message == format!("chore(release): prepare v{version}"),
        "release PR metadata differs from the version"
    );
    Ok((title, body))
}

fn validate_version_only_change(
    path: &str,
    source: &[u8],
    changed: &[u8],
    version: &str,
    root_name: Option<&str>,
) -> Result<()> {
    if path == "dbt_project.yml" {
        let mut before: serde_yaml::Value = serde_yaml::from_slice(source)?;
        let after: serde_yaml::Value = serde_yaml::from_slice(changed)?;
        before["version"] = serde_yaml::Value::String(version.to_owned());
        ensure!(
            before == after,
            "release YAML changes fields other than version"
        );
    } else {
        let mut before: toml_edit::DocumentMut = std::str::from_utf8(source)?.parse()?;
        let after: toml_edit::DocumentMut = std::str::from_utf8(changed)?.parse()?;
        if path == "Cargo.lock" {
            let before_packages = before["package"]
                .as_array_of_tables_mut()
                .context("Cargo.lock packages missing")?;
            let after_packages = after["package"]
                .as_array_of_tables()
                .context("Cargo.lock packages missing")?;
            ensure!(
                before_packages.len() == after_packages.len(),
                "release lock adds or removes packages"
            );
            let mut edits = 0;
            for (old, new) in before_packages.iter_mut().zip(after_packages.iter()) {
                if old["version"].as_str() != new["version"].as_str() {
                    ensure!(
                        root_name.is_some()
                            && old["name"].as_str() == root_name
                            && old.get("source").is_none()
                            && new["version"].as_str() == Some(version),
                        "release lock changes a dependency"
                    );
                    old["version"] = toml_edit::value(version);
                    edits += 1;
                }
            }
            ensure!(
                edits == 1,
                "release lock must change exactly one root package version"
            );
        } else {
            let table = if path == "Cargo.toml" {
                "package"
            } else {
                "project"
            };
            ensure!(
                before[table]["version"].is_str(),
                "release manifest version must be explicit"
            );
            before[table]["version"] = toml_edit::value(version);
        }
        let before: serde_json::Value = toml_edit::de::from_str(&before.to_string())?;
        let after: serde_json::Value = toml_edit::de::from_str(&after.to_string())?;
        ensure!(
            before == after,
            "release manifest changes fields other than version"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_metadata_allows_only_the_root_version_change() {
        let before =
            b"[package]\nname = 'example'\nversion = '1.0.0'\n[dependencies]\nserde = '1'\n";
        let after =
            b"[package]\nname = 'example'\nversion = '1.1.0'\n[dependencies]\nserde = '1'\n";
        validate_version_only_change("Cargo.toml", before, after, "1.1.0", None).unwrap();
        let changed = std::str::from_utf8(after)
            .unwrap()
            .replace("serde = '1'", "serde = '2'");
        assert!(
            validate_version_only_change("Cargo.toml", before, changed.as_bytes(), "1.1.0", None)
                .is_err()
        );
        assert!(validate_version_only_change("Cargo.toml", before, after, "2.0.0", None).is_err());
        let lock = b"version = 4\n[[package]]\nname = 'example'\nversion = '1.0.0'\n[[package]]\nname = 'member'\nversion = '1.0.0'\n";
        let changed = std::str::from_utf8(lock).unwrap().replacen(
            "version = '1.0.0'",
            "version = '1.1.0'",
            1,
        );
        validate_version_only_change(
            "Cargo.lock",
            lock,
            changed.as_bytes(),
            "1.1.0",
            Some("example"),
        )
        .unwrap();
        assert!(
            validate_version_only_change(
                "Cargo.lock",
                lock,
                changed.as_bytes(),
                "1.1.0",
                Some("member")
            )
            .is_err()
        );
        assert!(
            validate_version_only_change("Cargo.lock", lock, changed.as_bytes(), "1.1.0", None)
                .is_err()
        );
    }

    #[test]
    fn release_artifact_rejects_non_metadata_before_any_api_write() {
        use crate::fixtures::Fixture;
        let fixture = Fixture::new(vec![]);
        let m: PreparationManifest = serde_json::from_value(json!({
            "protocol":PROTOCOL,"operation":"release_prepare",
            "repository":{"id":987654,"full_name":"example-org/project"},
            "producer":{"run_id":42,"run_attempt":1,"event":"workflow_dispatch",
                "context_sha":"a".repeat(40),"source_sha":"a".repeat(40),
                "workflow_path":".github/workflows/release-pr.yml","workflow_ref":"refs/heads/main",
                "workflow_sha":"b".repeat(40),"actor_id":101,"actor_login":"maintainer"},
            "artifact":{"id":123,"name":"securefix-42-abcd","digest":format!("sha256:{}","c".repeat(64))},
            "default_branch":"main","release_branch":"release/next","destination_head":"a".repeat(40),
            "destination_branch_exists":false,"client_workflow_epoch":"d".repeat(40),
            "server_authority":{"instance_repository":"example-org/securefix-server","instance_id":404,
                "default_branch":"main","config_path":"instance.toml","config_sha256":"e".repeat(64),
                "epoch":"f".repeat(40),"workflows":[{"role":"release","path":".github/workflows/release.yml","sha256":"1".repeat(64),"pins":[]}]}
        })).unwrap();
        m.validate().unwrap();
        let version = "1.1.0";
        let title = format!("chore(release): v{version}");
        let body = format!(
            "## Summary\n- Prepare release v{version}\n- Update the changelog and release metadata\n\nThis pull request is managed by the Release PR workflow."
        );
        let mut fix = securefix_gate::artifact::FixArtifact {
            repository: m.repository.full_name.clone(),
            branch: m.release_branch.clone(),
            run_id: 42,
            source_sha: m.producer.source_sha.clone(),
            event_name: m.producer.event.clone(),
            pull_request_context: None,
            commit_message: format!("chore(release): prepare v{version}"),
            create_pull_request: Some(json!({"title":title,"body":body,"base":"main"}).to_string()),
            additions: std::collections::BTreeMap::from([
                (".release-version".into(), b"1.1.0\n".to_vec()),
                ("CHANGELOG.md".into(), b"Changes".to_vec()),
            ]),
            deletions: vec![],
        };
        assert_eq!(
            validate_metadata(&fixture.api, &m, &fix).unwrap(),
            (title, body)
        );
        fix.additions
            .insert("src/main.rs".into(), b"fn main() {}".to_vec());
        assert!(validate_metadata(&fixture.api, &m, &fix).is_err());
        fix.additions.remove("src/main.rs");
        fix.deletions.push("Cargo.toml".into());
        assert!(validate_metadata(&fixture.api, &m, &fix).is_err());
        let mut changed = m.clone();
        changed.producer.run_attempt = 2;
        assert!(changed.validate().is_err());
        let mut changed = m.clone();
        changed.destination_head = "2".repeat(40);
        assert!(changed.validate().is_err());
        let mut changed = m;
        changed.protocol = "unknown/v2".into();
        assert!(changed.validate().is_err());
        fixture.finish();
    }

    #[test]
    fn cargo_metadata_updates_root_and_lock_without_changing_dependencies() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("Cargo.toml");
        let lock = temporary.path().join("Cargo.lock");
        fs::write(&manifest, "[package]\nname='example'\nversion='1.0.0'\n").unwrap();
        fs::write(&lock,"version=4\n[[package]]\nname='example'\nversion='1.0.0'\n[[package]]\nname='serde'\nversion='1.0.0'\nsource='registry+https://example.invalid'\n").unwrap();
        let before_manifest = fs::read(&manifest).unwrap();
        let before_lock = fs::read(&lock).unwrap();
        update_cargo_version(&manifest, &lock, "1.1.0").unwrap();
        validate_version_only_change(
            "Cargo.toml",
            &before_manifest,
            &fs::read(&manifest).unwrap(),
            "1.1.0",
            None,
        )
        .unwrap();
        validate_version_only_change(
            "Cargo.lock",
            &before_lock,
            &fs::read(&lock).unwrap(),
            "1.1.0",
            Some("example"),
        )
        .unwrap();
    }
}
