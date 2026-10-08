# Distribute one verified runtime per server revision

The previous reusable builder compiled Rust for every operation, then passed a same-run artifact to execution jobs.
We retain that artifact boundary while moving compilation into a dedicated producer.

`publish-runtime.yml` runs only on pushes to protected server `main`.
It checks out `job.workflow_sha`, builds with the locked toolchain and dependencies, and archives the executable, `policy.json`, `securefix-config.yaml`, and `repo-settings` together.
The build job has contents-read, OIDC, and attestation permissions, but no release-write token or custom secrets.
The pinned official attestation action signs that exact archive.
A separate contents-write job downloads the producer's immutable artifact ID, verifies the same archive before extracting its executable, and calls Rust to publish a draft-first Release.

The release tag is `securefix-runtime-<full-SHA>` and its single asset is `securefix-runtime-linux-x86_64.tar.gz`.
An existing release must have the exact tag commit, target SHA, asset name, uploaded state, and SHA256 digest.
An empty draft may resume an upload, and a matching draft may be published.
Different bytes or extra assets fail; published assets are never overwritten.
Every publication write uses the current-main guard.

`load-cli.yml` has no checkout, compilation, or custom secrets.
The runner's native `gh` downloads the exact SHA-based release and verifies the archive before extraction.
Verification fixes the repository, signer workflow path, signer digest, source digest, main ref, GitHub OIDC issuer, SLSA predicate type, and hosted-runner requirement.
Source and signer digests must both equal the actual reusable job's `job.workflow_sha`.
The CLI checks these identities against the signed certificate and matches the archive's digest to the attestation subject.
See [GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify) and [trusted-builder guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating).
No downloaded executable participates in verifying its own trust.

The verified archive is extracted in a read-only loader job, then uploaded as an immutable artifact ID for this caller run.
Execution jobs use only that ID and retain the existing exact-current runtime/policy checks before effects.
All callers grant `attestations: read` alongside their existing contents permission.
Public Releases avoid a cross-repository Actions artifact download token, and do not expire with Actions artifact retention.
No server immutable-release setting is required for runtime integrity: tags and assets locate bytes, while the attestation establishes their source.
Deletion or replacement may deny service, but unverified replacement bytes cannot be executed.
This does not change the immutable-release requirement for client product releases.

Missing or unverified Releases stop operations without compiling a fallback or selecting another SHA.
After each server merge, wait for `Publish Runtime` to succeed before updating client pins or resuming processing.
Recover failed production by rerunning that same main-push workflow; an obsolete runtime cannot publish after main advances.
Publication may rebuild during an explicit retry; normal operations reuse the published archive.
This relies on protected main, the pinned producer actions, GitHub's hosted runner, OIDC/attestation service, and its preinstalled `gh` verifier.
