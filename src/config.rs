//! Deployment identities come only from the trusted runtime's policy files.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::OnceLock};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub repository: String,
    pub id: u64,
    pub default_branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub login: String,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    pub status_app_id: u64,
    pub policy_app_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub server: Repository,
    pub owner_login: String,
    pub repository_owner: Principal,
    pub client_app_id: u64,
    pub server_app_id: u64,
    pub client_bot_login: String,
    pub server_bot_login: String,
    pub approval_reviewer: Principal,
    pub checks: Checks,
    pub integration: Repository,
    pub release_branch: String,
    pub runtime_update_branch: String,
}

impl Deployment {
    pub fn validate(&self) -> Result<()> {
        for repository in [&self.server, &self.integration] {
            crate::policy::validate_repository(&repository.repository)?;
            ensure!(repository.id > 0, "repository ID must be nonzero");
            validate_branch(&repository.default_branch)?;
            ensure!(
                repository.repository.split('/').next()
                    == Some(self.repository_owner.login.as_str()),
                "repository owner differs from configured account"
            );
        }
        ensure!(
            self.server.id != self.integration.id
                && self.server.repository != self.integration.repository,
            "integration repository must differ from production server"
        );
        ensure!(
            self.client_app_id > 0
                && self.server_app_id > 0
                && self.client_app_id != self.server_app_id,
            "invalid App identities"
        );
        ensure!(
            self.checks.status_app_id > 0 && self.checks.policy_app_id == self.server_app_id,
            "required check App does not match the server App"
        );
        ensure!(
            self.repository_owner.id > 0 && self.approval_reviewer.id > 0,
            "configured principal IDs must be nonzero"
        );
        for login in [
            &self.owner_login,
            &self.repository_owner.login,
            &self.client_bot_login,
            &self.server_bot_login,
            &self.approval_reviewer.login,
        ] {
            ensure!(
                !login.is_empty()
                    && login.len() <= 100
                    && login
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_[].".contains(&b)),
                "invalid configured login"
            );
        }
        validate_branch(&self.release_branch)?;
        validate_branch(&self.runtime_update_branch)?;
        ensure!(
            self.release_branch != self.server.default_branch
                && self.runtime_update_branch != self.server.default_branch,
            "automation branch cannot be the server default branch"
        );
        Ok(())
    }
}

pub fn validate_branch(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains(['\\', ':', '?', '#', '%', '@', '~', '^', '*', '['])
            && !value.bytes().any(|b| b.is_ascii_control() || b == b' ')
            && !value.contains("..")
            && value.split('/').all(|p| !p.is_empty()
                && !p.starts_with('.')
                && !p.ends_with('.')
                && !p.ends_with(".lock")),
        "invalid configured branch"
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TrustedConfig {
    pub owner_id: u64,
    pub client_bot_id: u64,
    pub server_bot_id: u64,
    pub renovate_merge_bot: Option<Principal>,
    pub deployment: Deployment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenovateMergePolicy {
    #[serde(default)]
    renovate_merge_bot: Option<Principal>,
}

fn renovate_merge_policy(bytes: &[u8]) -> Result<Option<Principal>> {
    ensure!(bytes.len() <= 1024, "Renovate merge policy is oversized");
    Ok(serde_json::from_slice::<RenovateMergePolicy>(bytes)?.renovate_merge_bot)
}

static TRUSTED: OnceLock<std::result::Result<(TrustedConfig, Vec<u8>), String>> = OnceLock::new();

fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SECUREFIX_POLICY_PATH") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(test)]
    return Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy.json"));
    #[cfg(not(test))]
    Ok(std::env::current_exe()?
        .parent()
        .context("runtime executable has no directory")?
        .join("policy.json"))
}

fn loaded() -> Result<&'static (TrustedConfig, Vec<u8>)> {
    TRUSTED
        .get_or_init(|| {
            (|| {
                let path = path()?;
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read trusted policy {}", path.display()))?;
                // This source-bound policy is embedded in the attested binary.
                // Keep policy.json readable by the predecessor controller that
                // validates a successor before activating its new authority.
                let policy = crate::policy::Policy::parse(&bytes)?.with_renovate_merge_bot(
                    renovate_merge_policy(include_bytes!("renovate_merge_policy.json"))?,
                )?;
                Ok((
                    TrustedConfig {
                        owner_id: policy.owner_id,
                        client_bot_id: policy.client_bot_id,
                        server_bot_id: policy.server_bot_id,
                        renovate_merge_bot: policy.renovate_merge_bot,
                        deployment: policy.deployment,
                    },
                    bytes,
                ))
            })()
            .map_err(|error: anyhow::Error| format!("{error:#}"))
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

pub fn trusted() -> Result<&'static TrustedConfig> {
    Ok(&loaded()?.0)
}
pub fn trusted_policy_bytes() -> Result<Vec<u8>> {
    Ok(loaded()?.1.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_renovate_policy_is_optional_strict_and_separate_from_base_policy() {
        assert!(renovate_merge_policy(b"{}").unwrap().is_none());
        assert!(
            renovate_merge_policy(br#"{"renovate_merge_bot":null}"#)
                .unwrap()
                .is_none()
        );
        for invalid in [
            br#"{"extra":true}"#.as_slice(),
            br#"{"renovate_merge_bot":{"id":43,"login":"updater[bot]","extra":true}}"#,
            &[b' '; 1025],
        ] {
            assert!(renovate_merge_policy(invalid).is_err());
        }
        let policy = crate::policy::Policy::parse(include_bytes!("../policy.json")).unwrap();
        assert!(policy.renovate_merge_bot.is_none());
        let bot = renovate_merge_policy(include_bytes!("renovate_merge_policy.json")).unwrap();
        let configured = policy.with_renovate_merge_bot(bot.clone()).unwrap();
        assert_eq!(configured.renovate_merge_bot, bot);
        assert!(
            serde_json::to_value(configured)
                .unwrap()
                .get("renovate_merge_bot")
                .is_none()
        );
    }
}
