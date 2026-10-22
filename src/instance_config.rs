//! Strict parsing for an external Server instance's declared configuration.
//!
//! Parsed IDs and names are configuration claims. This module checks syntax
//! and internal consistency; it does not authenticate them against GitHub.
use anyhow::{Context, Result, ensure};
use globset::Glob;
use semver::VersionReq;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    pub schema_version: u32,
    pub release_request_label_prefix: String,
    pub instance: crate::config::Repository,
    pub identities: Identities,
    pub apps: Apps,
    #[serde(default)]
    pub branches: Branches,
    pub policy: InstancePolicy,
    pub repositories: Vec<ConfiguredRepository>,
    pub workflow_roles: BTreeMap<WorkflowRole, String>,
    pub acceptable_clients: AcceptableClients,
}

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRole {
    Approve,
    Merge,
    PolicyCheck,
    Release,
    Securefix,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identities {
    pub owner: crate::config::Principal,
    pub repository_owner: crate::config::Principal,
    pub client_bot: crate::config::Principal,
    pub server_bot: crate::config::Principal,
    pub approval_reviewer: crate::config::Principal,
    #[serde(default)]
    pub renovate_merge_bot: Option<crate::config::Principal>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apps {
    pub client_id: u64,
    pub server_id: u64,
    pub status_check_id: u64,
    pub policy_check_id: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branches {
    #[serde(default)]
    pub release: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstancePolicy {
    pub trusted_committers: Vec<String>,
    pub default_sensitive_paths: Vec<String>,
    pub merge_controls_enabled: bool,
    #[serde(default)]
    pub sensitive_path_approval_exemptions: crate::policy::SensitivePathApprovalExemptions,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredRepository {
    pub repository: String,
    pub id: u64,
    pub capabilities: Vec<crate::policy::Capability>,
    #[serde(default)]
    pub release: Option<crate::policy::ReleaseStrategy>,
    #[serde(default)]
    pub native_binaries: Vec<crate::policy::NativeBinaryTarget>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    pub protect_tags: bool,
}

impl ConfiguredRepository {
    pub fn policy(&self) -> crate::policy::RepositoryPolicy {
        crate::policy::RepositoryPolicy {
            repository: self.repository.clone(),
            capabilities: self.capabilities.clone(),
            release: self.release,
            native_binaries: self.native_binaries.clone(),
            sensitive_paths: self.sensitive_paths.clone(),
            protect_tags: self.protect_tags,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptableClients {
    pub repository: String,
    pub id: u64,
    pub producer_workflow: String,
    #[serde(deserialize_with = "deserialize_version_req")]
    pub version: VersionReq,
}

fn deserialize_version_req<'de, D>(deserializer: D) -> std::result::Result<VersionReq, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    VersionReq::parse(&value).map_err(serde::de::Error::custom)
}

impl InstanceConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CONFIG_BYTES,
            "instance config exceeds size limit"
        );
        let source = std::str::from_utf8(bytes).context("instance config is not UTF-8")?;
        let mut config: Self = toml_edit::de::from_str(source).context("parse instance TOML")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported instance schema version"
        );
        validate_release_request_label_prefix(&self.release_request_label_prefix)?;
        crate::policy::validate_repository(&self.instance.repository)?;
        ensure!(
            self.instance.id > 0,
            "instance repository ID must be nonzero"
        );
        crate::config::validate_branch(&self.instance.default_branch)?;

        validate_principal(&self.identities.owner)?;
        validate_principal(&self.identities.repository_owner)?;
        validate_principal(&self.identities.client_bot)?;
        validate_principal(&self.identities.server_bot)?;
        validate_principal(&self.identities.approval_reviewer)?;
        validate_principal_consistency(
            &self.identities,
            &self.policy.sensitive_path_approval_exemptions,
        )?;
        ensure!(
            self.identities.owner.id != self.identities.client_bot.id
                && self.identities.owner.id != self.identities.server_bot.id
                && self.identities.client_bot.id != self.identities.server_bot.id,
            "invalid security principals"
        );
        ensure!(
            self.instance.repository.split('/').next()
                == Some(self.identities.repository_owner.login.as_str()),
            "instance repository owner differs from configured account"
        );
        if let Some(bot) = &self.identities.renovate_merge_bot {
            validate_principal(bot)?;
            ensure!(
                ![
                    self.identities.owner.id,
                    self.identities.client_bot.id,
                    self.identities.server_bot.id,
                    self.identities.approval_reviewer.id,
                ]
                .contains(&bot.id)
                    && bot.login.ends_with("[bot]")
                    && self
                        .policy
                        .trusted_committers
                        .iter()
                        .any(|login| login.eq_ignore_ascii_case(&bot.login)),
                "invalid Renovate merge bot"
            );
        }

        ensure!(
            self.apps.client_id > 0
                && self.apps.server_id > 0
                && self.apps.status_check_id > 0
                && self.apps.policy_check_id > 0
                && self.apps.client_id != self.apps.server_id,
            "invalid App identities"
        );
        ensure!(
            !self.policy.trusted_committers.is_empty(),
            "no trusted committers"
        );
        let mut trusted = HashSet::new();
        for login in &self.policy.trusted_committers {
            ensure!(
                crate::config::is_valid_login(login),
                "invalid trusted committer login"
            );
            ensure!(
                trusted.insert(login.to_ascii_lowercase()),
                "duplicate trusted committer"
            );
        }
        crate::policy::validate_sensitive_path_approval_exemptions(
            &self.policy.sensitive_path_approval_exemptions,
            &self.policy.trusted_committers,
        )?;
        validate_sensitive_paths(&self.policy.default_sensitive_paths)?;

        let owner = self.identities.repository_owner.login.as_str();
        let mut repository_names = HashSet::new();
        let mut repository_ids = HashSet::new();
        let has_release_capability = self.repositories.iter().any(|repository| {
            repository
                .capabilities
                .contains(&crate::policy::Capability::Release)
        });
        for repository in &mut self.repositories {
            crate::policy::validate_repository(&repository.repository)?;
            ensure!(repository.id > 0, "repository ID must be nonzero");
            ensure!(
                repository.repository.split('/').next() == Some(owner),
                "repository must belong to the configured account"
            );
            ensure!(
                repository_names.insert(repository.repository.to_ascii_lowercase()),
                "duplicate repository policy"
            );
            ensure!(
                repository_ids.insert(repository.id),
                "duplicate repository ID"
            );
            let capabilities: HashSet<_> = repository.capabilities.iter().collect();
            ensure!(
                !repository.capabilities.is_empty()
                    && capabilities.len() == repository.capabilities.len(),
                "invalid capabilities"
            );
            ensure!(
                repository.release.is_some()
                    == repository
                        .capabilities
                        .contains(&crate::policy::Capability::Release),
                "release strategy/capability mismatch"
            );
            crate::policy::validate_native_binary_targets(
                repository.release,
                &repository.native_binaries,
            )?;
            if repository.sensitive_paths.is_empty() {
                repository
                    .sensitive_paths
                    .clone_from(&self.policy.default_sensitive_paths);
            }
            validate_sensitive_paths(&repository.sensitive_paths)?;
        }

        let mut normalized_workflow_paths = HashSet::new();
        for path in self.workflow_roles.values() {
            validate_workflow_path(path)?;
            ensure!(
                normalized_workflow_paths.insert(path.to_ascii_lowercase()),
                "duplicate workflow role path"
            );
        }

        for (role, capability) in [
            (WorkflowRole::Approve, crate::policy::Capability::Approve),
            (WorkflowRole::Merge, crate::policy::Capability::Merge),
            (WorkflowRole::PolicyCheck, crate::policy::Capability::Merge),
            (WorkflowRole::Release, crate::policy::Capability::Release),
            (
                WorkflowRole::Securefix,
                crate::policy::Capability::Securefix,
            ),
        ] {
            if self
                .repositories
                .iter()
                .any(|repository| repository.capabilities.contains(&capability))
            {
                ensure!(
                    self.workflow_roles.contains_key(&role),
                    "required workflow role is missing: {role:?}"
                );
            }
        }

        if has_release_capability {
            ensure!(
                self.branches.release.is_some(),
                "release branch is required"
            );
        }
        if let Some(branch) = &self.branches.release {
            crate::config::validate_branch(branch)?;
            ensure!(
                branch != &self.instance.default_branch,
                "release branch cannot be the instance default branch"
            );
        }

        crate::policy::validate_repository(&self.acceptable_clients.repository)?;
        ensure!(
            self.acceptable_clients.id > 0,
            "acceptable Client repository ID must be nonzero"
        );
        validate_workflow_path(&self.acceptable_clients.producer_workflow)?;
        validate_repository_identity_consistency(
            &self.instance,
            &self.repositories,
            &self.acceptable_clients,
        )?;
        Ok(())
    }
}

fn validate_release_request_label_prefix(prefix: &str) -> Result<()> {
    ensure!(
        prefix.is_empty()
            || (prefix.len() <= 32
                && prefix.ends_with('-')
                && prefix.as_bytes()[0].is_ascii_lowercase()
                && prefix[..prefix.len() - 1].bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })),
        "release request label prefix is invalid"
    );
    Ok(())
}

fn validate_workflow_path(path: &str) -> Result<()> {
    let filename = path
        .strip_prefix(".github/workflows/")
        .and_then(|path| path.strip_suffix(".yml"));
    ensure!(
        filename.is_some_and(|filename| {
            !filename.is_empty()
                && filename
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        }),
        "invalid workflow path"
    );
    Ok(())
}

fn validate_repository_identity_consistency(
    instance: &crate::config::Repository,
    repositories: &[ConfiguredRepository],
    acceptable_clients: &AcceptableClients,
) -> Result<()> {
    let mut ids_by_name = HashMap::new();
    let mut names_by_id = HashMap::new();
    let mut add = |repository: &str, id: u64| -> Result<()> {
        let repository = repository.to_ascii_lowercase();
        if let Some(previous_id) = ids_by_name.insert(repository.clone(), id) {
            ensure!(
                previous_id == id,
                "conflicting configured repository identity claims"
            );
        }
        if let Some(previous_repository) = names_by_id.insert(id, repository.clone()) {
            ensure!(
                previous_repository == repository,
                "conflicting configured repository identity claims"
            );
        }
        Ok(())
    };

    add(&instance.repository, instance.id)?;
    for configured in repositories {
        add(&configured.repository, configured.id)?;
    }
    add(&acceptable_clients.repository, acceptable_clients.id)?;
    Ok(())
}

fn validate_principal(principal: &crate::config::Principal) -> Result<()> {
    ensure!(principal.id > 0, "configured principal ID must be nonzero");
    ensure!(
        crate::config::is_valid_login(&principal.login),
        "invalid configured login"
    );
    Ok(())
}

fn validate_principal_consistency(
    identities: &Identities,
    exemptions: &crate::policy::SensitivePathApprovalExemptions,
) -> Result<()> {
    let mut ids_by_login = HashMap::new();
    let mut logins_by_id = HashMap::new();
    let mut add = |login: &str, id: u64| -> Result<()> {
        let login = login.to_ascii_lowercase();
        if let Some(previous_id) = ids_by_login.insert(login.clone(), id) {
            ensure!(previous_id == id, "conflicting configured principal claims");
        }
        if let Some(previous_login) = logins_by_id.insert(id, login.clone()) {
            ensure!(
                previous_login == login,
                "conflicting configured principal claims"
            );
        }
        Ok(())
    };

    for principal in [
        &identities.owner,
        &identities.repository_owner,
        &identities.client_bot,
        &identities.server_bot,
        &identities.approval_reviewer,
    ] {
        add(&principal.login, principal.id)?;
    }
    if let Some(principal) = &identities.renovate_merge_bot {
        add(&principal.login, principal.id)?;
    }
    for user in &exemptions.users {
        add(&user.login, user.id)?;
    }
    for app in &exemptions.github_apps {
        add(&app.bot_login, app.bot_id)?;
    }
    Ok(())
}

fn validate_sensitive_paths(paths: &[String]) -> Result<()> {
    ensure!(!paths.is_empty(), "missing sensitive paths");
    for pattern in paths {
        Glob::new(pattern).with_context(|| format!("invalid sensitive path glob {pattern:?}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/instance-config.toml");
    const ALL_WORKFLOW_ROLES: &str = "[workflow_roles]\napprove = \".github/workflows/approve.yml\"\nmerge = \".github/workflows/merge.yml\"\npolicy_check = \".github/workflows/policy-check.yml\"\nrelease = \".github/workflows/release.yml\"\nsecurefix = \".github/workflows/securefix.yml\"\n\n";

    fn changed(source: &str, before: &str, after: &str) -> String {
        assert!(source.contains(before), "missing test input {before:?}");
        source.replacen(before, after, 1)
    }

    fn fixture_text() -> String {
        String::from_utf8(FIXTURE.to_vec()).unwrap()
    }

    fn rejects(source: &str) {
        assert!(
            InstanceConfig::parse(source.as_bytes()).is_err(),
            "{source}"
        );
    }

    #[test]
    fn parses_synthetic_configuration_without_defaulting_optional_authority() {
        let config = InstanceConfig::parse(FIXTURE).unwrap();
        assert_eq!(config.schema_version, 1);
        assert_eq!(config.release_request_label_prefix, "");
        assert_eq!(config.instance.repository, "example-org/securefix-server");
        assert_eq!(config.identities.owner.login, "maintainer");
        assert_eq!(
            config.workflow_roles.keys().copied().collect::<Vec<_>>(),
            vec![
                WorkflowRole::Approve,
                WorkflowRole::Merge,
                WorkflowRole::PolicyCheck,
                WorkflowRole::Release,
                WorkflowRole::Securefix,
            ]
        );
        assert_eq!(
            config.identities.renovate_merge_bot.as_ref().unwrap().id,
            607
        );
        assert!(config.policy.merge_controls_enabled);
        assert_eq!(config.repositories.len(), 1);
        assert_eq!(
            config.repositories[0].sensitive_paths,
            config.policy.default_sensitive_paths
        );
        assert!(
            config
                .acceptable_clients
                .version
                .matches(&semver::Version::parse("99.0.0").unwrap())
        );

        let without_bot = changed(
            &fixture_text(),
            "[identities.renovate_merge_bot]\nlogin = \"renovate[bot]\"\nid = 607\n\n",
            "",
        );
        assert!(
            InstanceConfig::parse(without_bot.as_bytes())
                .unwrap()
                .identities
                .renovate_merge_bot
                .is_none()
        );

        let same_owner = changed(
            &changed(
                &fixture_text(),
                "login = \"maintainer\"",
                "login = \"example-org\"",
            ),
            "id = 101",
            "id = 406",
        );
        let same_owner = InstanceConfig::parse(same_owner.as_bytes()).unwrap();
        assert_eq!(
            same_owner.identities.owner,
            same_owner.identities.repository_owner
        );
    }

    #[test]
    fn release_request_label_prefix_is_explicit_bounded_and_namespaced() {
        rejects(&changed(
            &fixture_text(),
            "release_request_label_prefix = \"\"\n",
            "",
        ));
        let testing = changed(
            &fixture_text(),
            "release_request_label_prefix = \"\"",
            "release_request_label_prefix = \"testing-\"",
        );
        assert_eq!(
            InstanceConfig::parse(testing.as_bytes())
                .unwrap()
                .release_request_label_prefix,
            "testing-"
        );
        let too_long = "x".repeat(33);
        for invalid in ["Testing-", "testing", "../", too_long.as_str()] {
            let source = changed(
                &fixture_text(),
                "release_request_label_prefix = \"\"",
                &format!("release_request_label_prefix = {invalid:?}"),
            );
            rejects(&source);
        }
    }

    #[test]
    fn requires_a_closed_workflow_role_table_and_enabled_roles() {
        let fixture = fixture_text();
        rejects(&changed(&fixture, ALL_WORKFLOW_ROLES, ""));
        rejects(&changed(
            &fixture,
            "approve = \".github/workflows/approve.yml\"",
            "approver = \".github/workflows/approve.yml\"",
        ));
        rejects(&changed(
            &fixture,
            "approve = \".github/workflows/approve.yml\"",
            "settings = \".github/workflows/approve.yml\"",
        ));
        rejects(&changed(
            &fixture,
            "approve = \".github/workflows/approve.yml\"\n",
            "",
        ));
        rejects(&changed(
            &fixture,
            "policy_check = \".github/workflows/policy-check.yml\"\n",
            "",
        ));
    }

    #[test]
    fn workflow_role_paths_are_shallow_ascii_yml_and_case_insensitively_unique() {
        let fixture = fixture_text();
        for path in [
            ".github/workflows/nested/approve.yml",
            ".github/workflows/../approve.yml",
            ".github/workflows/approve.yaml",
            ".github/workflows/é.yml",
            ".github/workflows/has space.yml",
            ".github/workflows/.yml",
        ] {
            rejects(&changed(&fixture, ".github/workflows/approve.yml", path));
        }

        rejects(&changed(
            &fixture,
            ".github/workflows/merge.yml",
            ".github/workflows/approve.yml",
        ));
        rejects(&changed(
            &fixture,
            ".github/workflows/merge.yml",
            ".github/workflows/APPROVE.yml",
        ));
    }

    #[test]
    fn request_producer_path_is_required_and_canonical() {
        let fixture = fixture_text();
        rejects(&changed(
            &fixture,
            "producer_workflow = \".github/workflows/request-producer.yml\"\n",
            "",
        ));
        for path in [
            ".github/workflows/nested/request-producer.yml",
            ".github/workflows/../request-producer.yml",
            ".github/workflows/request-producer.yaml",
            ".github/workflows/.yml",
        ] {
            rejects(&changed(
                &fixture,
                ".github/workflows/request-producer.yml",
                path,
            ));
        }
    }

    #[test]
    fn allows_an_empty_workflow_role_table_without_ordinary_capabilities() {
        let fixture = fixture_text();
        let source = changed(&fixture, ALL_WORKFLOW_ROLES, "[workflow_roles]\n\n");
        let source = changed(
            &source,
            "schema_version = 1\n",
            "schema_version = 1\nrepositories = []\n",
        );
        let source = changed(
            &source,
            "[[repositories]]\nrepository = \"example-org/project\"\nid = 987654\ncapabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]\nrelease = \"github-release\"\nprotect_tags = true\n\n",
            "",
        );
        let empty = InstanceConfig::parse(source.as_bytes()).unwrap();
        assert!(empty.repositories.is_empty());
        assert!(empty.workflow_roles.is_empty());

        let settings_only = changed(
            &fixture,
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
            "capabilities = [\"settings\"]",
        );
        let settings_only = changed(&settings_only, "release = \"github-release\"\n", "");
        let settings_only = changed(&settings_only, ALL_WORKFLOW_ROLES, "[workflow_roles]\n\n");
        let settings_only = InstanceConfig::parse(settings_only.as_bytes()).unwrap();
        assert!(settings_only.workflow_roles.is_empty());
        assert_eq!(
            settings_only.repositories[0].capabilities,
            vec![crate::policy::Capability::Settings]
        );
    }

    #[test]
    fn permits_only_the_enabled_role_and_allows_configured_disabled_roles() {
        let fixture = fixture_text();
        let approve_only = changed(
            &fixture,
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
            "capabilities = [\"approve\"]",
        );
        let approve_only = changed(&approve_only, "release = \"github-release\"\n", "");
        let configured_disabled_roles = InstanceConfig::parse(approve_only.as_bytes()).unwrap();
        assert_eq!(configured_disabled_roles.workflow_roles.len(), 5);

        let approve_role = "[workflow_roles]\napprove = \".github/workflows/approve.yml\"\n\n";
        let approve_only = changed(&approve_only, ALL_WORKFLOW_ROLES, approve_role);
        let parsed = InstanceConfig::parse(approve_only.as_bytes()).unwrap();
        assert_eq!(parsed.workflow_roles.len(), 1);
        assert_eq!(
            parsed.workflow_roles.get(&WorkflowRole::Approve).unwrap(),
            ".github/workflows/approve.yml"
        );
    }

    #[test]
    fn preserves_existing_capability_and_sensitive_path_decisions() {
        let old =
            crate::policy::Policy::parse(include_bytes!("../docs/policy.example.json")).unwrap();
        let old_repository = old.repository("example-org/project").unwrap();
        let config = InstanceConfig::parse(FIXTURE).unwrap();
        let new_repository = &config.repositories[0];
        assert_eq!(new_repository.capabilities, old_repository.capabilities);
        assert_eq!(new_repository.release, old_repository.release);
        assert_eq!(new_repository.protect_tags, old_repository.protect_tags);

        let parsed_repository = new_repository.policy();
        for capability in [
            crate::policy::Capability::Approve,
            crate::policy::Capability::Merge,
            crate::policy::Capability::Securefix,
            crate::policy::Capability::Release,
            crate::policy::Capability::Settings,
        ] {
            assert_eq!(
                old_repository.require(capability).is_ok(),
                parsed_repository.require(capability).is_ok()
            );
        }
        for paths in [
            vec![".github/workflows/approve.yml"],
            vec!["Cargo.lock"],
            vec!["README.md"],
            vec!["models/example.sql"],
        ] {
            assert_eq!(
                old_repository.sensitive(paths.iter().copied()).unwrap(),
                parsed_repository.sensitive(paths.iter().copied()).unwrap(),
                "{paths:?}"
            );
        }
    }

    #[test]
    fn converted_configuration_preserves_legacy_policy_fields_and_decisions() {
        let legacy =
            crate::policy::Policy::parse(include_bytes!("../docs/policy.example.json")).unwrap();
        let renovate: serde_json::Value =
            serde_json::from_slice(include_bytes!("../docs/renovate-merge-policy.example.json"))
                .unwrap();
        let legacy = legacy
            .with_renovate_merge_bot(Some(
                serde_json::from_value(renovate["renovate_merge_bot"].clone()).unwrap(),
            ))
            .unwrap();
        let config = InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config-policy-parity.toml"
        ))
        .unwrap();

        assert_eq!(config.identities.owner.login, legacy.deployment.owner_login);
        assert_eq!(config.identities.owner.id, legacy.owner_id);
        assert_eq!(
            config.identities.repository_owner,
            legacy.deployment.repository_owner
        );
        assert_eq!(
            config.identities.client_bot.login,
            legacy.deployment.client_bot_login
        );
        assert_eq!(config.identities.client_bot.id, legacy.client_bot_id);
        assert_eq!(
            config.identities.server_bot.login,
            legacy.deployment.server_bot_login
        );
        assert_eq!(config.identities.server_bot.id, legacy.server_bot_id);
        assert_eq!(
            config.identities.approval_reviewer,
            legacy.deployment.approval_reviewer
        );
        assert_eq!(
            config.identities.renovate_merge_bot,
            legacy.renovate_merge_bot
        );
        assert_eq!(config.instance, legacy.deployment.server);
        assert_eq!(config.apps.client_id, legacy.deployment.client_app_id);
        assert_eq!(config.apps.server_id, legacy.deployment.server_app_id);
        assert_eq!(
            config.apps.status_check_id,
            legacy.deployment.checks.status_app_id
        );
        assert_eq!(
            config.apps.policy_check_id,
            legacy.deployment.checks.policy_app_id
        );
        assert_eq!(
            config.branches.release.as_deref(),
            Some(legacy.deployment.release_branch.as_str())
        );
        assert_eq!(config.policy.trusted_committers, legacy.trusted_committers);
        assert_eq!(
            config.policy.default_sensitive_paths,
            legacy.default_sensitive_paths
        );
        assert_eq!(
            config.policy.merge_controls_enabled,
            legacy.merge_controls_enabled
        );
        assert_eq!(
            serde_json::to_value(&config.policy.sensitive_path_approval_exemptions).unwrap(),
            serde_json::to_value(&legacy.sensitive_path_approval_exemptions).unwrap()
        );

        assert_eq!(config.repositories.len(), legacy.repositories.len());
        let new_repository = &config.repositories[0];
        let old_repository = &legacy.repositories[0];
        assert_eq!(new_repository.repository, old_repository.repository);
        assert_eq!(new_repository.capabilities, old_repository.capabilities);
        assert_eq!(new_repository.release, old_repository.release);
        assert_eq!(new_repository.protect_tags, old_repository.protect_tags);
        assert_eq!(
            new_repository.sensitive_paths,
            old_repository.sensitive_paths
        );

        let converted_repository = new_repository.policy();
        for capability in [
            crate::policy::Capability::Approve,
            crate::policy::Capability::Merge,
            crate::policy::Capability::Securefix,
            crate::policy::Capability::Release,
            crate::policy::Capability::Settings,
        ] {
            assert_eq!(
                old_repository.require(capability).is_ok(),
                converted_repository.require(capability).is_ok()
            );
        }
        for paths in [
            vec![".github/workflows/approve.yml"],
            vec!["Cargo.lock"],
            vec!["README.md"],
            vec!["models/example.sql"],
        ] {
            assert_eq!(
                old_repository
                    .matching_sensitive_paths(paths.iter().copied())
                    .unwrap(),
                converted_repository
                    .matching_sensitive_paths(paths.iter().copied())
                    .unwrap(),
                "{paths:?}"
            );
        }

        crate::policy::validate_sensitive_path_approval_exemptions(
            &config.policy.sensitive_path_approval_exemptions,
            &config.policy.trusted_committers,
        )
        .unwrap();
    }

    #[test]
    fn accepts_unbounded_and_bounded_semver_requirements() {
        let unbounded = InstanceConfig::parse(FIXTURE).unwrap();
        assert!(
            unbounded
                .acceptable_clients
                .version
                .matches(&semver::Version::parse("7.8.9").unwrap())
        );

        let bounded = changed(
            &fixture_text(),
            "version = \">=1.4.0\"",
            "version = \">=1.4.0, <2.0.0\"",
        );
        let bounded = InstanceConfig::parse(bounded.as_bytes()).unwrap();
        assert!(
            bounded
                .acceptable_clients
                .version
                .matches(&semver::Version::parse("1.9.9").unwrap())
        );
        assert!(
            !bounded
                .acceptable_clients
                .version
                .matches(&semver::Version::parse("2.0.0").unwrap())
        );
    }

    #[test]
    fn native_binaries_are_optional_and_release_strategy_is_checked() {
        assert!(
            InstanceConfig::parse(FIXTURE).unwrap().repositories[0]
                .native_binaries
                .is_empty()
        );

        let with_native_targets = changed(
            &fixture_text(),
            "release = \"github-release\"\nprotect_tags = true",
            "release = \"github-release\"\nnative_binaries = [{ target = \"x86_64-unknown-linux-musl\", runner = \"ubuntu-24.04\" }]\nprotect_tags = true",
        );
        let parsed = InstanceConfig::parse(with_native_targets.as_bytes()).unwrap();
        assert_eq!(
            parsed.repositories[0].native_binaries[0].target,
            "x86_64-unknown-linux-musl"
        );

        let missing_release = changed(
            &with_native_targets,
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"settings\"]",
        );
        let missing_release = changed(&missing_release, "release = \"github-release\"\n", "");
        rejects(&missing_release);

        let mismatched_runner = changed(
            &with_native_targets,
            "runner = \"ubuntu-24.04\"",
            "runner = \"macos-15\"",
        );
        rejects(&mismatched_runner);
    }

    #[test]
    fn release_branch_is_optional_when_no_repository_enables_release() {
        let source = changed(
            &fixture_text(),
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
            "capabilities = [\"approve\", \"merge\", \"securefix\", \"settings\"]",
        );
        let source = changed(&source, "release = \"github-release\"\n", "");
        let source = changed(&source, "[branches]\nrelease = \"release/next\"\n\n", "");

        let config = InstanceConfig::parse(source.as_bytes()).unwrap();
        assert!(config.branches.release.is_none());
    }

    #[test]
    fn accepts_case_insensitive_repeated_principal_claims() {
        let source = changed(
            &fixture_text(),
            "[identities.renovate_merge_bot]\nlogin = \"renovate[bot]\"\nid = 607",
            "[identities.renovate_merge_bot]\nlogin = \"Renovate[bot]\"\nid = 607",
        );
        let source = changed(
            &source,
            "users = [{ id = 601, login = \"automation-reviewer\" }]",
            "users = [{ id = 601, login = \"Automation-Reviewer\" }]",
        );

        InstanceConfig::parse(source.as_bytes()).unwrap();

        let app_id_matches_principal_number =
            changed(&fixture_text(), "client_id = 501", "client_id = 101");
        InstanceConfig::parse(app_id_matches_principal_number.as_bytes()).unwrap();
    }

    #[test]
    fn accepts_matching_repeated_repository_identity_claims() {
        let source = changed(
            &fixture_text(),
            "repository = \"example-org/project\"\nid = 987654",
            "repository = \"example-org/SECUREFIX-SERVER\"\nid = 404",
        );
        let source = changed(
            &source,
            "repository = \"example-org/securefix-client\"\nid = 654321",
            "repository = \"EXAMPLE-ORG/securefix-server\"\nid = 404",
        );

        InstanceConfig::parse(source.as_bytes()).unwrap();
    }

    #[test]
    fn rejects_conflicting_repeated_repository_identity_claims() {
        let wrong_id_for_instance_row = changed(
            &fixture_text(),
            "repository = \"example-org/project\"\nid = 987654",
            "repository = \"example-org/securefix-server\"\nid = 987654",
        );
        let reused_instance_id_for_other_repository = changed(
            &fixture_text(),
            "repository = \"example-org/project\"\nid = 987654",
            "repository = \"example-org/project\"\nid = 404",
        );
        let conflicting_acceptable_client = changed(
            &fixture_text(),
            "repository = \"example-org/securefix-client\"\nid = 654321",
            "repository = \"example-org/securefix-server\"\nid = 654321",
        );

        for source in [
            wrong_id_for_instance_row,
            reused_instance_id_for_other_repository,
            conflicting_acceptable_client,
        ] {
            rejects(&source);
        }
    }

    #[test]
    fn accepts_empty_repository_policy_array() {
        let source = changed(
            &fixture_text(),
            "schema_version = 1\n",
            "schema_version = 1\nrepositories = []\n",
        );
        let source = changed(
            &source,
            "[[repositories]]\nrepository = \"example-org/project\"\nid = 987654\ncapabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]\nrelease = \"github-release\"\nprotect_tags = true\n\n",
            "",
        );
        let source = changed(&source, "[branches]\nrelease = \"release/next\"\n\n", "");

        assert!(
            InstanceConfig::parse(source.as_bytes())
                .unwrap()
                .repositories
                .is_empty()
        );
    }

    #[test]
    fn accepts_distinct_policy_check_and_server_apps() {
        let source = changed(
            &fixture_text(),
            "policy_check_id = 502\n",
            "policy_check_id = 702\n",
        );
        let config = InstanceConfig::parse(source.as_bytes()).unwrap();
        assert_eq!(config.apps.server_id, 502);
        assert_eq!(config.apps.status_check_id, 701);
        assert_eq!(config.apps.policy_check_id, 702);
    }

    #[test]
    fn rejects_oversized_missing_unknown_or_unsupported_configuration() {
        let oversized = vec![b' '; MAX_CONFIG_BYTES + 1];
        assert!(InstanceConfig::parse(&oversized).is_err());
        assert!(InstanceConfig::parse(&[0xff]).is_err());

        for source in [
            changed(&fixture_text(), "schema_version = 1\n", ""),
            changed(&fixture_text(), "id = 404\n", ""),
            changed(&fixture_text(), "policy_check_id = 502\n", ""),
            changed(
                &fixture_text(),
                "schema_version = 1\n",
                "schema_version = 2\n",
            ),
            changed(
                &fixture_text(),
                "version = \">=1.4.0\"",
                "version = \">=invalid\"",
            ),
            changed(
                &fixture_text(),
                "id = 101\n",
                "id = 101\nunexpected = true\n",
            ),
            changed(
                &fixture_text(),
                "merge_controls_enabled = true\n",
                "merge_controls_enabled = true\nunexpected = true\n",
            ),
            changed(
                &fixture_text(),
                "client_id = 501\n",
                "client_id = 501\nunexpected = true\n",
            ),
            changed(
                &fixture_text(),
                "release = \"release/next\"\n",
                "release = \"release/next\"\nunexpected = true\n",
            ),
            changed(
                &fixture_text(),
                "users = [{ id = 601, login = \"automation-reviewer\" }]",
                "users = [{ id = 601, login = \"automation-reviewer\", unexpected = true }]",
            ),
            changed(
                &fixture_text(),
                "protect_tags = true\n",
                "protect_tags = true\nunexpected = true\n",
            ),
            changed(
                &fixture_text(),
                "version = \">=1.4.0\"",
                "version = \">=1.4.0\"\nunexpected = true",
            ),
            changed(
                &fixture_text(),
                "schema_version = 1\n",
                "schema_version = 1\nruntime = {}\n",
            ),
        ] {
            rejects(&source);
        }
    }

    #[test]
    fn rejects_invalid_logins_branches_globs_and_repository_ownership() {
        for source in [
            changed(
                &fixture_text(),
                "login = \"maintainer\"",
                "login = \"maintainer!\"",
            ),
            changed(
                &fixture_text(),
                "release = \"release/next\"",
                "release = \"bad^branch\"",
            ),
            changed(
                &fixture_text(),
                "default_branch = \"main\"",
                "default_branch = \"bad^branch\"",
            ),
            changed(
                &fixture_text(),
                "repository = \"example-org/project\"",
                "repository = \"other-org/project\"",
            ),
            changed(
                &fixture_text(),
                "repository = \"example-org/securefix-server\"",
                "repository = \"other-org/securefix-server\"",
            ),
            changed(
                &fixture_text(),
                "default_sensitive_paths = [\n",
                "default_sensitive_paths = [\".github/[\",\n",
            ),
        ] {
            rejects(&source);
        }
    }

    #[test]
    fn rejects_duplicate_names_or_ids_and_identity_or_capability_mismatches() {
        let duplicate_name = format!(
            "{}\n[[repositories]]\nrepository = \"example-org/project\"\nid = 987655\ncapabilities = [\"approve\"]\nprotect_tags = false\n",
            fixture_text()
        );
        let duplicate_id = format!(
            "{}\n[[repositories]]\nrepository = \"example-org/another\"\nid = 987654\ncapabilities = [\"approve\"]\nprotect_tags = false\n",
            fixture_text()
        );
        for source in [
            duplicate_name,
            duplicate_id,
            changed(&fixture_text(), "id = 202\n", "id = 101\n"),
            changed(&fixture_text(), "client_id = 501\n", "client_id = 502\n"),
            changed(
                &fixture_text(),
                "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
                "capabilities = [\"approve\", \"merge\", \"securefix\", \"settings\"]",
            ),
            changed(
                &fixture_text(),
                "capabilities = [\"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
                "capabilities = [\"approve\", \"approve\", \"merge\", \"securefix\", \"release\", \"settings\"]",
            ),
            changed(&fixture_text(), "release = \"release/next\"\n", ""),
        ] {
            rejects(&source);
        }
    }

    #[test]
    fn rejects_untrusted_or_duplicate_sensitive_exemptions_and_untrusted_renovate_bot() {
        for source in [
            changed(&fixture_text(), "  \"automation-reviewer\",\n", ""),
            changed(&fixture_text(), "bot_id = 607", "bot_id = 601"),
            changed(&fixture_text(), "id = 607\n\n[apps]", "id = 608\n\n[apps]"),
            changed(
                &fixture_text(),
                "login = \"maintainer\"",
                "login = \"example-org\"",
            ),
            changed(&fixture_text(), "id = 101", "id = 406"),
            changed(
                &fixture_text(),
                "users = [{ id = 601, login = \"automation-reviewer\" }]",
                "users = [{ id = 601, login = \"maintainer\" }]",
            ),
        ] {
            rejects(&source);
        }

        let no_exemptions = changed(
            &fixture_text(),
            "[policy.sensitive_path_approval_exemptions]\nusers = [{ id = 601, login = \"automation-reviewer\" }]\ngithub_apps = [{ bot_id = 607, bot_login = \"renovate[bot]\" }]\n\n",
            "",
        );
        let config = InstanceConfig::parse(no_exemptions.as_bytes()).unwrap();
        assert!(
            config
                .policy
                .sensitive_path_approval_exemptions
                .users
                .is_empty()
        );
        assert!(
            config
                .policy
                .sensitive_path_approval_exemptions
                .github_apps
                .is_empty()
        );
    }
}
