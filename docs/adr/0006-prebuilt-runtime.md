# Promote a verified runtime after staging

The previous reusable builder compiled Rust for every operation, then passed a same-run artifact to execution jobs.
Normal operations now load a prebuilt runtime; candidate validation uses a separate scratch CI artifact and creates no Release.

`publish-runtime.yml` runs only when the owner manually dispatches it on protected server `main` after staging.
It checks out `job.workflow_sha`, builds with the locked toolchain and dependencies, and archives the executable, `policy.json`, and `repo-settings` together.
The build job has contents-read, OIDC, and attestation permissions, but no release-write token or custom secrets.
The pinned official attestation action signs that exact archive.
A separate contents-write job downloads the producer's immutable artifact ID, verifies the same archive before extraction, installs the executable, and calls Rust to publish a draft-first Release.
Pushes and intermediate test revisions do not publish runtime Releases.

The release tag is `securefix-runtime-<full-SHA>` and its single asset is `securefix-runtime-linux-x86_64.tar.gz`.
The SHA identifies a deliberately promoted production revision; it does not schedule publication for every commit.
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
Execution jobs download only that ID under `runner.temp`, then call the shared `install-cli` composite action.
The action installs the fixed binary with mode `755` and adds its directory to `GITHUB_PATH`; subsequent steps invoke `securefix` by name.
Policy, configuration, and settings files remain outside the client checkout and artifact extraction workspace.
The native `uses: $/.github/actions/install-cli` reference resolves to the defining workflow's repository at its running commit, including when a client calls a server reusable workflow.
It requires no server checkout, bundled action, or separately maintained action SHA.
See the [GitHub action self-reference syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-using-an-action-in-the-same-repository-as-the-workflow-at-the-running-commit-recommended).

Execution jobs retain the existing exact-current runtime/policy checks before effects.
All callers grant `attestations: read` alongside their existing contents permission.
Public Releases avoid a cross-repository Actions artifact download token, and do not expire with Actions artifact retention.
No server immutable-release setting is required for runtime integrity: tags and assets locate bytes, while the attestation establishes their source.
Deletion or replacement may deny service, but unverified replacement bytes cannot be executed.
This does not change the immutable-release requirement for client product releases.

The [scratch testing workflow](../testing.md) builds a reviewed server revision in a secret-free job and transfers the runtime and API probe by immutable same-run artifact ID.
Its separate probe job checks the installed executable and a metadata-only Client App token limited to the scratch repository.
It neither publishes a Release nor bypasses production authorization for a candidate SHA.

Missing or unverified Releases stop operations without compiling a fallback or selecting another SHA.
After server main advances, the previous runtime becomes stale immediately.
Multiple changes can be staged together; manually promote the final stable main revision before resuming operations.
Successful publication starts the [caller PR rollout and default-head Policy Check](0007-published-runtime-rollout.md).
Review and merge the caller PRs through the existing upgrade maintenance procedure.
Recover a failed publication by rerunning that dispatch while its revision remains current.
An obsolete runtime cannot publish after main advances.
Publication may rebuild during an explicit retry; normal operations reuse the published archive.
This relies on protected main, the pinned producer actions, GitHub's hosted runner, OIDC/attestation service, and its preinstalled `gh` verifier.
