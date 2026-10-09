//! Deployment identities come only from the trusted runtime's policy file.
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
    pub deployment: Deployment,
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
                let policy = crate::policy::Policy::parse(&bytes)?;
                Ok((
                    TrustedConfig {
                        owner_id: policy.owner_id,
                        client_bot_id: policy.client_bot_id,
                        server_bot_id: policy.server_bot_id,
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
