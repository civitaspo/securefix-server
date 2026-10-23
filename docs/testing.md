# Candidate integration tests

The workflow-level migration environment is being implemented in
[the Phase B plan](testing-workflows-plan.md). The owner-defined trusted-server threat model and credential boundary are recorded
in [the isolation review](testing-workflows-isolation-review.md). The Environment
move and per-job approvals were rejected; keep the existing client repository key.
The owner-selected development CLI runs as one source-bound process on the runner
under the securefix-server change-management boundary. Scratch credentials remain
repository-scoped and test-only. The following commands describe the direct scratch
harness.

Use `testing-Candidate Runtime` on the server's trusted main workflow with a full reviewed candidate SHA. The candidate does not need a merged production revision or a Runtime Release.

Use `phase=candidate-artifact` when a source-bound `candidate-runtime` artifact is
needed for a read-only event/provenance probe. This phase runs the baseline and
credential-free build jobs only; the credentialed scratch job runs only for
`prepare` and `verify`, while bootstrap, provider, and managed-file jobs require
their own explicit phase. The artifact records both its candidate source SHA and
the defining workflow SHA.

```sh
gh workflow run testing-securefix-server.yml --repo civitaspo/securefix-server --ref main -f candidate_sha="$CANDIDATE_SHA" -f phase=prepare
```

The prepare job builds and tests without credentials. Its execution job receives only Server and Client App installation tokens restricted to `civitaspo/testing-securefix-server`. The repository ID and token installation scope are checked in Rust before creating fixtures. No personal approval token, administration token or release signing key is passed to the candidate.

The prepare run records three scratch PRs in `scratch-fixtures/state.json`. An authenticated owner controller posts `/approve` and `/merge` to the positive PR, posts `/merge` to the stale-head PR, and approves the positive PR's current commit. These commands can be posted by the coding agent using its existing owner GitHub session. The test does not require the human to post them.

```sh
gh workflow run testing-securefix-server.yml --repo civitaspo/securefix-server --ref main -f candidate_sha="$CANDIDATE_SHA" -f phase=verify -f fixture_run_id="$PREPARE_RUN_ID"
```

Verification reuses the prepare run's candidate binary. Before minting write credentials it checks the successful owner-triggered producer run, the defining workflow revision, the candidate SHA and the bounded immutable state artifact. It verifies actual signatures, owner authorization, current-head approval, required checks, signed workflow migration files, a successful squash merge, stale-head rejection and replay rejection. Remaining PRs and branches are cleaned up.

The native release-asset bridge uses a separate source-bound rehearsal. Dispatch it
from the exact frozen candidate branch `integration/native-<candidate SHA prefix>`
and pass the same full SHA:

```sh
gh workflow run testing-securefix-server.yml --repo civitaspo/securefix-server --ref "integration/native-${CANDIDATE_SHA:0:12}" -f candidate_sha="$CANDIDATE_SHA" -f phase=release-assets
```

It builds the four configured targets from Client commit
`ccdaada3efa78ebdef58f2db38aaf6ec5a8c8e00` on their matching GitHub-hosted
runners, without credentials. A read-only job verifies the current run and attempt,
the signed Client commit and merged source PR, `.release-version` at that commit,
each target's runner/version evidence, and the exact artifact IDs, digests, names,
and bytes. Before minting its scratch-only token, the writer repeats that check.
It then publishes those same binaries as one unique prerelease to
`civitaspo/testing-securefix-server`, records the release and asset digests, and
retains the immutable evidence. An incomplete target set must remain unpublished;
its separate draft and tag are cleaned up.

The scratch main branch requires a non-author approving review, signed commits, `status-check` from GitHub Actions and `securefix-policy-check` from the Server App. A policy success is published only after the shared production PR validator accepts the current head.

See [the harness contract](integration-testing.md) for the boundary between live functional tests and source-provenance fixtures. Stable runtime publication is a separate protected-main operation after candidate verification and review.

The same source-bound CLI prepares fixtures, runs the scratch operations and validates output bindings on the runner. It does not receive production credentials or signing keys. The CLI rejects symlinks, unexpected files, oversized data and invalid output bindings before fixture artifacts are uploaded.

The former PAT-based live merge test has been replaced by the candidate integration workflow. Live writes use only repository-scoped installation tokens and clean up their fixtures. The optional known signed-commit regression remains read-only.

## Native release-asset scratch verification

`testing-native-release-assets-publish.yml` consumes one previously successful
four-target build and verifier run when its producer cannot enter the protected
`main` environment. Dispatch it on Server `main` with distinct `harness_sha` and
`producer_source_sha` values plus the exact producer run ID and attempt. The
harness SHA must be the current signed head of an open owner PR containing the
producer-tuple-aware Rust probe; the producer SHA remains bound to the frozen
source branch and original build run. The qualifier checks that the harness
descends from that producer source, both revisions carry the same policy, their
active control matches current main, and the producer's expected jobs and artifact
IDs, digests, and sizes are unchanged. The workflow rebuilds the harness without write credentials, checks
the artifacts before token creation, then uses a Server App token scoped only to
`testing-securefix-server` and records the scratch release and immutable asset
digests. The release probe reads its active operational policy from the source
revision named by `control/active.json` and verifies that policy against the
descriptor digest. The candidate policy supplies only the four native target
definitions used to validate the preserved build artifacts; it is not used as
control or write authority. It does not publish a Client release.

## Development pre-release publication

`testing-publish-runtime.yml` publishes the exact reviewed protected-main source
with `.github/testing-policy.json` bundled as `policy.json`. The captured trusted
validator requires a `vX.Y.Z-pre.N` version and verifies the publisher, source and
policy before the stable active controller publishes the attested archive. The
candidate archive remains data in that credentialed job. No production control is
activated, and no caller is automatically distributed. The development runtime
loader and native capture/host relay now have local implementations described in
`integration-testing.md`. Fixture-control initialization, reviewed successor
activation and hosted migration scenarios remain unfinished. Publication alone
does not establish a working testing deployment.

The separate `testing-native-approve.yml` workflow is a test-only owner-dispatched
probe for applying an approval to one configured scratch PR. It loads the fixed
attested scratch package through `.github/actions/load-package` in both its
validation and apply jobs. The workflow pins the current mapping directly:
Server source `c6aa3110bb31d5ca5bae452d291870066f0147ef`, package build run
`39710467717`, publisher run `39710779361`, immutable scratch release `420243090`,
asset `664424003`, and SHA-256
`a01165f2204b51f99f1cc37d922858d7941475b4193e9e066d6352e575c28083` for
`v0.2.45-pre.12`. The loader rechecks the release, asset, digest, source
attestation, signer, producer run and publication record before installing the
binary. The workflow then validates the captured producer run, request
attestation, Server authority, owner identity and exact open PR head with a
scratch-scoped read token, and exposes the existing Bot User token only to the
protected apply job after the independent validation succeeds. A bounded no-cache
readback follows; readback failure does not submit a second review. This probe
does not replace the production `/approve` command or authorize production PRs.
Hosted scratch approval qualification remains pending.

The separate `testing-native-merge.yml` workflow is a test-only owner-dispatched
probe for one configured scratch PR. It requires independently attested merge and
approval requests that bind the same exact PR head and captured Server authority.
Before writing, the source-built host revalidates the policy check against the
active control descriptor of the configured scratch repository, the required
`status-check`, and the latest configured User approval carrying the full marker
derived from the approval manifest. The Server execution authority remains bound
separately by both producer proofs. Its scratch-only Server App
writer is restricted to GitHub's squash merge endpoint with the expected head SHA;
the workflow uses the existing scratch Contents and pull-request write permissions
and performs an independent merged-state readback. It does not replace the
production `/merge` command or authorize production PRs. Hosted scratch
qualification remains pending.

## Host self-update probes

The `testing-native-self-client-{approve,merge,policy-check}.yml` callers use the
existing Server-hosted native event roles and test-only
`repo-settings/native-role-events-test-instance.toml`. No separate Server
repository, environment or secret placement is required. The Client dispatch
uses the Host's existing protected `main` environment.

Fixtures are owner-authored PRs titled `[testing native self] ...` from
`testing/native-self-...` branches. Approval and merge require fresh unedited
owner commands, exact-head review, signatures, checks and current authority. The
test instance grants the Host only approval and merge. Its main mutations share
`securefix-control` with the existing operational lane. Production workflows,
active descriptor and bundled policy remain unchanged during these probes.
