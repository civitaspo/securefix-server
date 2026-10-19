use crate::{api::GitHub, config};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ACTIVE_PATH: &str = "control/active.json";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlRevision {
    pub version: u32,
    pub generation: u64,
    pub source_sha: String,
    pub policy_sha256: String,
    pub archive_sha256: String,
    pub release_id: u64,
    pub asset_id: u64,
    pub publisher_run_id: u64,
    pub verification_run_id: u64,
    pub previous: String,
}

impl ControlRevision {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported control revision version");
        ensure!(self.generation > 0, "control generation must be nonzero");
        crate::policy::validate_sha(&self.source_sha)?;
        validate_digest(&self.policy_sha256)?;
        validate_digest(&self.archive_sha256)?;
        validate_digest(&self.previous)?;
        ensure!(
            self.release_id > 0
                && self.asset_id > 0
                && self.publisher_run_id > 0
                && self.verification_run_id > 0,
            "control provenance IDs must be nonzero"
        );
        ensure!(
            self.generation != 1 || self.previous == "0".repeat(64),
            "first control revision must have a zero predecessor"
        );
        Ok(())
    }

    pub fn identity(&self) -> Result<String> {
        self.validate()?;
        Ok(crate::hex_encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn validate_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        ensure!(
            self.generation.checked_add(1) == Some(next.generation),
            "control generation is not the next generation"
        );
        ensure!(
            next.previous == self.identity()?,
            "control predecessor mismatch"
        );
        ensure!(
            self.payload() != next.payload(),
            "control successor repeats the same revision tuple"
        );
        Ok(())
    }

    fn payload(&self) -> (&str, &str, &str, u64, u64, u64, u64) {
        (
            &self.source_sha,
            &self.policy_sha256,
            &self.archive_sha256,
            self.release_id,
            self.asset_id,
            self.publisher_run_id,
            self.verification_run_id,
        )
    }

    pub fn load(api: &GitHub) -> Result<Self> {
        let trusted = config::trusted()?;
        Self::load_from_repository(api, trusted.deployment.control_repository())
    }

    /// Read-only descriptor lookup with an identity selected by a trusted host policy.
    pub fn load_from_repository(api: &GitHub, server: &config::Repository) -> Result<Self> {
        crate::policy::validate_repository(&server.repository)?;
        config::validate_branch(&server.default_branch)?;
        ensure!(server.id > 0, "control repository identity is missing");
        let repository: serde_json::Value = api.get(&format!("/repos/{}", server.repository))?;
        ensure!(
            repository["default_branch"] == server.default_branch
                && repository["id"].as_u64() == Some(server.id),
            "unexpected server default branch or repository identity"
        );
        let main: serde_json::Value = api.get(&format!(
            "/repos/{}/commits/{}",
            server.repository, server.default_branch
        ))?;
        let main_sha = main["sha"].as_str().context("missing server revision")?;
        crate::policy::validate_sha(main_sha)?;
        let bytes = api.content(&server.repository, ACTIVE_PATH, main_sha)?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "control descriptor exceeds size limit"
        );
        let descriptor: Self =
            serde_json::from_slice(&bytes).context("invalid control descriptor")?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn require_current(api: &GitHub, expected: &Self) -> Result<()> {
        ensure!(
            Self::load(api)? == *expected,
            "control revision is no longer current"
        );
        Ok(())
    }

    pub fn require_runtime(api: &GitHub) -> Result<Self> {
        let control = Self::load(api)?;
        let source =
            std::env::var("SECUREFIX_SOURCE_SHA").context("missing trusted runtime revision")?;
        crate::policy::validate_sha(&source)?;
        ensure!(
            source == control.source_sha,
            "runtime source differs from active control revision"
        );
        let policy_sha = crate::hex_encode(Sha256::digest(config::trusted_policy_bytes()?));
        ensure!(
            policy_sha == control.policy_sha256,
            "bundled policy differs from active control revision"
        );
        if let Ok(identity) = std::env::var("SECUREFIX_CONTROL_ID") {
            ensure!(
                identity == control.identity()?,
                "runtime control identity differs from active descriptor"
            );
        }
        Ok(control)
    }
}

pub fn development_revision(api: &GitHub) -> Result<String> {
    crate::policy::latest_revision(api, ".github/workflows/ci.yml")
}

pub fn load(api: &GitHub) -> Result<ControlRevision> {
    ControlRevision::load(api)
}

pub fn require_current(api: &GitHub, expected: &ControlRevision) -> Result<()> {
    ControlRevision::require_current(api, expected)
}

pub fn require_runtime(api: &GitHub) -> Result<ControlRevision> {
    ControlRevision::require_runtime(api)
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid SHA-256 digest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(generation: u64, previous: String, source: &str) -> ControlRevision {
        ControlRevision {
            version: 1,
            generation,
            source_sha: source.into(),
            policy_sha256: "1".repeat(64),
            archive_sha256: "2".repeat(64),
            release_id: 3,
            asset_id: 4,
            publisher_run_id: 5,
            verification_run_id: 6,
            previous,
        }
    }

    #[test]
    fn descriptor_identity_is_stable_and_bound_to_every_field() {
        let first = descriptor(1, "0".repeat(64), &"a".repeat(40));
        let encoded = serde_json::to_vec(&first).unwrap();
        let decoded: ControlRevision = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(first.identity().unwrap(), decoded.identity().unwrap());
        let mut changed = decoded;
        changed.asset_id += 1;
        assert_ne!(first.identity().unwrap(), changed.identity().unwrap());
    }

    #[test]
    fn successor_chain_rejects_replay_and_accepts_new_generation_rollback() {
        let first = descriptor(1, "0".repeat(64), &"a".repeat(40));
        let second = descriptor(2, first.identity().unwrap(), &"b".repeat(40));
        first.validate_successor(&second).unwrap();
        let replay = descriptor(2, first.identity().unwrap(), &"a".repeat(40));
        assert!(first.validate_successor(&replay).is_err());
        let rollback = descriptor(3, second.identity().unwrap(), &"a".repeat(40));
        second.validate_successor(&rollback).unwrap();
    }

    #[test]
    fn malformed_and_conflicting_descriptors_fail_validation() {
        let mut invalid = descriptor(1, "0".repeat(64), &"a".repeat(40));
        invalid.previous = "A".repeat(64);
        assert!(invalid.validate().is_err());
        let bytes = br#"{"version":1,"generation":1,"source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"1111111111111111111111111111111111111111111111111111111111111111","archive_sha256":"2222222222222222222222222222222222222222222222222222222222222222","release_id":3,"asset_id":4,"publisher_run_id":5,"verification_run_id":6,"previous":"0000000000000000000000000000000000000000000000000000000000000000","extra":true}"#;
        assert!(serde_json::from_slice::<ControlRevision>(bytes).is_err());
    }
}
