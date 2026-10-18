# Candidate scratch integration

The native integration command runs the candidate CLI against only
`civitaspo/testing-securefix-server`. It does not publish a runtime release or
write to another repository. The scratch Server App token is checked against
the installation repository list and each mutation is restricted by the API
client to the fixed scratch repository. The Client App token is checked the
same way. Do not pass a user token or a production installation token to the
candidate process.

The trusted workflow builds the candidate without credentials, then runs the
artifact in an isolated job. On main or an integration branch, it separately captures
the exact signed protected server default-branch SHA, builds that read-only test validator with locked
dependencies, and uploads a distinct immutable artifact. Baseline commands
validate the producer and retrieve fixture state; candidate commands prepare
client input, exercise the isolated mutations, and verify the client result.
The validator's baseline SHA must remain current throughout the test. Read-only
producer, fixture-state and client-verification commands require
`SECUREFIX_TEST_BASELINE_SHA` to match signed current main at entry. This test-only
build receives no production credentials and does not select an operational runtime.
The published test runtime is selected independently from `control/active.json`:
its source, immutable release/asset IDs, archive digest and canonical tag must
match. An ordinary main advance does not require a new runtime release.
Run `securefix integration run --phase prepare`
with the candidate SHA and a state-file path. The workflow producer SHA is
recorded separately from the candidate SHA, so a candidate commit does not
need to contain the workflow that produced its fixture artifact. The workflow
sets `SECUREFIX_TEST_WORKFLOW_SHA` to its own source SHA. The command creates three signed,
disposable PRs in the scratch repository: one for the approval/merge path, one
for stale-head rejection, and one containing the managed workflow files rendered
from the current published stable runtime SHA. Before minting App tokens, the host validates the published baseline source
and Release metadata and resolves its source-bound version tag. It passes
`SECUREFIX_PUBLISHED_RUNTIME_SHA` and `SECUREFIX_PUBLISHED_RUNTIME_TAG` to the
candidate, then independently rechecks both after candidate execution.
The test-only tag resolver permits the legacy exact-SHA annotation during the
first SemVer cutover; production consumers require canonical `v<version>` tags.
The baseline build does not download or attest the published Release asset.
Production loading and the separate published-client test verify archive bytes
and attestation. This test creates no candidate Release.
The prepare run uploads `fixtures/state.json` as `scratch-fixtures` and uploads
`control-probe/control-verification.json` separately as `control-probe`. Download both
artifacts from the completed prepare run:

```sh
gh run download <prepare-run-id> --name scratch-fixtures --dir fixtures
gh run download <prepare-run-id> --name control-probe --dir control-probe
```

Read the generation-one control ID from `control-probe/control-verification.json` at
`.generation_one`. Read the positive and stale PR numbers and exact heads from
`fixtures/state.json` at `.positive.number`, `.positive.head_sha`, `.stale.number`, and
`.stale.head_sha`. The configured repository owner (`deployment.owner_login`) must
submit an `APPROVED` review on the positive PR at its current head. The scratch
harness uses that owner as its User reviewer. Its body must include this exact marker line, replacing the placeholder
with `.generation_one` from the control-probe artifact:

```text
<!-- securefix:control-review:<control-id> -->
```

The PR review's `commit_id` binds that approval to the current head; the marker binds it
to the control generation. A plain UI approval without the marker is rejected. Then post
exact owner `/approve` and `/merge` comments on the positive PR, plus exact owner `/merge` on the stale-head
PR. Run the workflow's verify phase with the successful prepare run ID. A validator
built from the captured current default-branch source fetches state
only from that exact successful owner-run `workflow_dispatch`, validates the
server repository ID, owner actor, workflow path, producer SHA, the configured default branch or
SHA-named frozen integration branch, and single bounded artifact. Prepare also
checks that the named producer branch currently resolves to the recorded
producer SHA; keep a frozen integration branch protected against updates while
it is used. The validator selects the candidate binary by its immutable artifact ID.
Only the validator receives the server repository read token; the candidate receives
only installation tokens scoped to the scratch repository. The candidate
SHA remains an independent state binding. It then checks commit signatures, current-head
authorization, merge readiness, rejection of native GitHub auto-merge, stale-head rejection, replay
rejection, and exact distribution workflow bytes. The distribution PR runs actual
`pinact run --verify-comment` and must have a successful Actions `status-check`.
The positive PR first proves it is not merge-ready while its required policy check is
absent. After publishing the check and confirming all merge gates, the harness requires
GitHub to reject a native auto-merge request and verifies that no request was queued.
The scratch Server App then merges the ready PR directly with the accepted head SHA.
For stale-head rejection, the other PR advances after its head was accepted; a direct
Server App merge using that old SHA must fail and leave the PR open and unmerged.
The harness closes any remaining test
PRs and deletes all three test branches after collecting evidence.

After candidate output validation succeeds, both the prepare and verify workflows run
the separate `control-probe` and upload an artifact containing only
`control-verification.json`. A prepare run's `scratch-fixtures` artifact contains only
`state.json`; a successful verify run also contains `verification.json`. The probe
creates three scratch control generations,
checks that an unrelated source advance leaves the active descriptor bytes unchanged,
and confirms that a stale expected-head update is rejected without changing the
branch tip or descriptor. It then changes the source identity and restores the first
source identity in generation three, proving that the resulting control identity is
new rather than replayed. The strict schema contains `version`, `repository`,
`candidate_sha`, `branch`, `base_sha`, the three generation commit SHAs, the three
generation identities, and booleans `source_advance_kept_descriptor`,
`expected_head_conflict_rejected`, and `stale_identity_rejected_after_aba`. Its
`production_publication_verified`, `production_activation_verified`, and
`distribution_verified` fields are all `false`: this scratch-only probe does not
publish or activate a production runtime and does not exercise distribution.

For the initial descriptor rehearsal, dispatch `testing-securefix-server.yml` with
`phase=bootstrap` from protected `main`. This mode cannot use the usual current-main
`validate-producer` baseline because that would make the proposed runtime validate its
own initial trust chain. It instead downloads the pinned v0.2.20 baseline (release ID
`414653308`, asset ID `646481902`, size `3964894`, archive SHA-256
`1f0f991e766e287b1ff55cf8cbda05982c0ddb90295f988081bf5b85a480d96c`) and checks its
GitHub attestation and runtime identity against source
`e8e2bc77d96a4e359417217f1d1c22f4e1ac4483`. Before minting scratch App tokens, the
fixed bootstrap helper checks the owner dispatch, current main SHA, and absent active
descriptor. The candidate runtime prepares and verifies the integration fixtures; the
pinned runtime remains an independently verified baseline. The fixed, source-pinned
Rust bootstrap host validates the exact bounded regular output files, rejects symlinks
and unexpected fields, and checks source, baseline, fixture, and control-generation
bindings. It repeats the owner dispatch, current main, policy, and absent descriptor
checks. The legacy runtime's ordinary `validate-outputs` command requires its source
to remain on main, so it cannot validate this post-merge rehearsal. The candidate also runs the scratch-only
`control-probe`. This test mode does not publish or activate production control, and a
green result does not establish production distribution or the published client loader.
The initial bootstrap proposal's archive qualification separately treats the candidate
archive as data and never executes it.

In `phase=bootstrap`, the same instructions apply while the run is in progress: the
workflow uploads `control-probe` and the state-only `bootstrap-fixture-heads` artifact,
then prints both JSON files in the run summary before candidate verification waits for
the review and owner commands. Download them from that run into explicit directories:
`gh run download <run-id> --name control-probe --dir control-probe` and
`gh run download <run-id> --name bootstrap-fixture-heads --dir fixtures`. The paths
and fields are then `control-probe/control-verification.json` `.generation_one` and
`fixtures/state.json` fixture PR numbers/heads. The required review marker and owner
comments are scratch fixture controls, not production activation approval.

The harness also posts an actual scratch App `/merge` comment and assigns that
App as the merge bot in an explicit in-memory test policy. It validates the bot's
own PR, signed effective committers, disabled-authority rejection, current-head
checks and review, and rejection after merge. Production policy rejects aliasing
the Server App and Renovate identities. This tests the merge-bot validation core;
it does not establish that the hosted Renovate service sent a production request.

Before the positive fixture PR is merged, the harness also calls the production
rebase-request core with the scratch Server App as the explicitly configured
Renovate principal. It verifies that an owner command and disabled bot authority
are rejected, the first eligible bot request writes the Server App retry marker
and adds GitHub's standard `rebase` label, and another failure does not request
another rebase. To prove the marker, rather than the still-present label, enforces
the budget, the harness removes the label from the disposable PR before making
the second call. It does not delete the repository's label definition. This is
direct core coverage under an isolated scratch policy. It does not exercise a
hosted Renovate installation or prove that Renovate processed the label.

The harness invokes production PR authorization, merge-state, readiness, and
distribution rendering/validation functions. It does not claim that a scratch
workflow is a production request source: the source-run and reusable-workflow
artifact provenance chain is tested by its own fixtures because the scratch
caller is not the production caller workflow. The direct merge mutation binds the
accepted head SHA and uses squash merge, but does not publish a runtime tag/release.
The native repair apply core runs against GitHub with a verified signed commit,
exact contents and an idempotent retry. Release tagging uses the production annotated-tag
helper and verifies retries and target mismatch before deleting the disposable tag.
Attested stable runtime publication remains a separate protected-main operation.

To exercise review creation as well, prepare an owner-authored PR in the configured
scratch repository before dispatching the prepare phase. Its branch must be
`securefix-integration-approval-<first 12 characters of candidate SHA>`. It must
contain one owner-authored, verified signed commit whose sole parent is the current
scratch default head. The only added file must be
`.securefix-integration/approval-<full candidate SHA>.txt`, containing exactly
`candidate=<full candidate SHA>\nscenario=approval\n`. Post one owner `/approve`
comment, then pass its PR number and exact head SHA as `approval_fixture_pr` and
`approval_fixture_head` workflow inputs. Both inputs are required together.

The candidate verifies the fixture's author, repository IDs, base, branch, signed
head and exact file bytes before writing. The scratch-scoped Server App then runs
the shared review creation core as a different identity from the PR author. The
test verifies an `APPROVED` review with that App's exact configured identity and
commit SHA. Production still authenticates the configured User reviewer before
calling the same core. No production reviewer token enters the candidate. Close
the owner-created fixture and remove its branch after collecting the review and
CI evidence; it is separate from the three harness-owned fixtures.

This probe covers review mutation and current-head readback. The production
source-run artifact and label-event pipeline remains covered separately; the
scratch probe does not claim to execute that full workflow. Prepare also runs the
repository-settings installation scope validator against the real singleton
scratch App token before it creates the harness-owned fixtures.

The candidate policy used by the harness is constructed in memory from the
trusted runtime policy, narrowed to the scratch repository, and assigned the candidate
SHA. This is an explicit test context; production `Policy::active` and
default-branch revision write checks remain unchanged.

The candidate executes in a digest-pinned Ubuntu container with an unprivileged user, read-only root filesystem, dropped capabilities and private process namespace. Only its executable, read-only deployment policy, CA certificates and fixture directory are mounted; the runner filesystem, Docker socket and workflow command files are unavailable. Only scratch tokens and explicit non-secret workflow metadata enter the container. App keys and the server read token stay in the trusted host steps. The trusted CLI rejects symlinks, unexpected files, oversized data and invalid output bindings before fixture artifacts are uploaded.

The separate `client-smoke` job exercises the actual composite client Action. Its
action checkout and candidate binary are bound to the successful credential-free
build's source SHA and immutable artifact ID. A trusted controller generates a
scratch deployment policy and one fixed input file.
Client-only policies omit approval exemptions and the optional Renovate merge
principal, so the published baseline can parse the fixture before a schema update
is activated. These fixtures grant only the scratch `securefix` capability.
The Action receives only a
Client App token restricted to scratch `issues:write`, uploads the real envelope,
and creates its request label in scratch. The trusted verifier independently reads
the source artifact and scratch label, checks exact metadata and file bytes, and
uploads `client-verification.json`.

Candidate testing uses `client_runtime: candidate-artifact`; that path skips published descriptor and release loading. The live `published-release` loader path cannot be verified until the initial active descriptor exists. After bootstrap, run a published-release prepare and verify to cover descriptor selection, publisher-run validation, Release download, attestation verification, preparation, upload, and dispatch. Record that run separately; candidate-artifact smoke results do not stand in for it. The bootstrap and published-loader end-to-end gate remain unverified.

The distribution fixture also migrates the three-file autofix workflow call chain.
Its scratch-only job deliberately changes a tracked workflow, requires the native
client Action to produce an artifact and request label using the attested published
runtime, and verifies the label before deleting it. Its token and deployment policy
target only the scratch repository. The required `status-check` fails if this chain
fails or is skipped, and separately verifies every generated action pin with pinact.

## Provider release rehearsal without publication

The `provider` phase of `testing-securefix-server.yml` calls
`testing-provider-release.yml` at a reviewed, frozen integration revision with
an owner-only dispatch. It compiles a test executable once, then uses the same
fixed production Go build helper in a parallel target matrix against an exact
provider source commit. Source builds receive no signing key or installation
token. The resulting archives and Registry manifest are validated before signing.

Fresh signing and retry signing run in separate jobs that reference only the
protected provider GPG key and passphrase. They execute the prebuilt test artifact;
they do not check out or execute client source. Draft upload and recovery download
run separately with a Server App installation token restricted to the configured
integration repository. A unique SemVer prerelease draft receives the checksums
and signature first, simulating an interrupted upload. The retry verifies and
reuses the uploaded signature, uploads the remaining assets, and checks that an
additional retry leaves their identities and digests unchanged.

The test never finalizes a draft or creates a production release. Its always-run
cleanup removes only the recorded integration draft and any matching rehearsal
tag, then checks that neither remains. The protected environment allowance applies only to the exact frozen
branch during the rehearsal and is removed afterward. The ignored Rust probe is
compiled only for tests; the installed runtime retains its normal authorization
and provenance requirements. This verifies build, signing, and draft recovery;
Terraform Registry ingestion still requires a published release.

The candidate verify phase exercises receipt reactions on both owner commands and the configured scratch bot's `/merge`. After the scratch merge, it checks the completion comment's squash SHA and Server run URL. The policy feedback probe publishes two failure results, verifies only the latest failure comment is visible, then publishes success and verifies both failure comments are hidden. The comment bodies identify the server CI and target commit. These probes use scratch-scoped Server App credentials.

Prepare also exercises the shared policy feedback probe: wrapping multiline failure comments, superseding an older failure, and hiding failures after success. It preserves the server run and commit references and leaves no visible probe failure comment.
