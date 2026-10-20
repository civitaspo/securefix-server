# Candidate scratch integration

## Independent workflow-fixture readback

The workflow-level migration harness is being implemented separately from the
direct scratch probes below. Its plan and deployment prerequisites are recorded
in `testing-workflows-plan.md` and `testing-workflows-isolation-review.md`.
The following read-only commands capture and compare the configured integration
repository's protected state:

```sh
securefix integration workflow-snapshot --pull-request <number> --state-file evidence/before.json
# Trigger the recorded scenario, then wait for its exact run and attempt.
securefix integration workflow-snapshot --pull-request <number> --state-file evidence/after.json
securefix integration compare-workflow-snapshots --before evidence/before.json --after evidence/after.json --protect all
```

Run these commands with the owner-selected source-bound CLI and a test-repository
read token in `GITHUB_TOKEN`. Keep the evidence directory separate from scratch
fixtures so the before/after API snapshots remain available for comparison. The
repository identity comes from the CLI's deployment policy, not a command-line
repository argument. Paths must be relative without traversal.

Each bounded snapshot records the default head, PR head/state/merged flag, and
fingerprints of every review, issue comment, commit status and check run on that
head. Missing fields, duplicate IDs, incomplete check pagination or a branch/PR
move during capture fail the command. Snapshot files larger than 16 KiB fail
rather than being truncated. Comparison requires the same initially open,
unmerged fixture and unchanged default head and PR state. `--protect all` also
requires identical review, comment, status and check fingerprints; use it for
non-owner dispatch. `--protect branch-and-pull` allows those auxiliary records to
change, for scenarios whose intended rejection emits checks or feedback.

These commands do not certify a rejection. The parent harness must separately
bind the snapshot artifacts to the exact scenario, prepare producer, candidate,
source revision, control identity, event chronology and workflow run/attempt,
and require the expected rejection reason. A passing comparison after an API,
setup, artifact or runner failure is not a passing scenario.

## Approved development runtime and native processing

The owner trusts reviewed server source and verified pre-release binaries bound to
it. Testing uses the production execution locations and the normal CLI commands.
Caller capture, release preparation/build/tag and sync stay on the caller; approval,
merge, policy results, CSM writes and signing/publication stay on the server.
Testing reusables differ in names/references, qualified runtime selection,
test-only operation scopes and the independent testing control/policy.

The same approved development CLI runs `securefix approve validate` and
`securefix approve apply`, using the existing civitaspo-bot User PAT to post the
actual control-bound review. There is no separate review revision or candidate
continuation command. The prior split commands and aggregate processor were
removed after the owner corrected the trust interpretation on 2026-10-19.

The existing Client App secret still creates server labels. Server App tokens and
all actual mutations are limited to the test repository. Unreviewed code and
unqualified artifacts remain outside this trust grant; existing scratch sandbox
validation remains applicable to those cases. Production active control/settings
are never fixtures. No new App, issuer or Environment approval is introduced.

The test loader qualifies full source/workflow/runtime/control bindings each run.
`setup-cli` may reuse a source- and build-condition-bound successful main CI
artifact after checking its exact producer run and digest; this never skips active
control, authorization, accepted-head or readiness checks. See
[the current plan](testing-workflows-plan.md#current-direction--supersedes-historical-routing-and-credential-restrictions-2026-10-19).

## Historical development runtime and native capture

The following records the earlier container/relay implementation. It is superseded
for normal approved-development operations by the section above; previous successful
runs do not validate the corrected execution path.


`testing-load-cli.yml` builds a credential-free validator from captured current
server main. With the caller's test-repository read token, it reads only that
client's isolated `control/active.json`. Public server metadata, source, immutable
release and attestation retrieval use an anonymous API client. It requires a
signed current validator baseline, signed candidate ancestor and successful CI,
an exact `pre.N` publisher/source/main run, and equality of source, release/asset
IDs and archive/policy digests with the test descriptor. The defining reusable
revision must equal the selected test runtime source; there is no fallback to
the production runtime or acceptance of an old caller.

Attestation verification passes repository-bound inline bundles to
[`gh attestation verify --bundle`](https://cli.github.com/manual/gh_attestation_verify)
with exact signer workflow, source digest/ref, issuer and hosted-runner checks.
It removes token variables and uses empty GitHub configuration and a temporary
cache. Missing inline bundles, absent or truncated lists, wrong repository IDs
and verification errors fail closed. This avoids giving a candidate a production
repository token. The bounded Rust archive reader selects only the binary and
policy as data; it never extracts arbitrary archive paths or executes the binary
on the host. A final control/main read detects movement before outputs.

`testing-reusable-approve-request.yml`, `testing-reusable-merge-request.yml` and
`testing-reusable-policy-check.yml` retain the existing named
`SECUREFIX_CLIENT_PRIVATE_KEY` contract and call that loader. Only a separate
trusted dispatch job uses the key. It downloads the exact
uploaded manifest and trusted validator by immutable artifact IDs, revalidates
the manifest, and invokes the pinned token action. No candidate executable or
Action runs in that job. It mints a Client App token limited to
`securefix-server` and `issues:write`. The trusted host's
`integration dispatch-testing-request` checks the current isolated control and
creates the native request label. The candidate never gets that key or token.
The caller's repository secret remains required; reusable placement does not
supply the server repository's secrets to caller jobs.

The source-bound CLI receives the native event file and the test caller's
read-only token on the runner. Approval/merge capture needs only issues and pull
request reads; the server adds the validated command reaction using its existing
operation-scoped token. `integration validate-testing-capture` checks a single regular
manifest of at most 16 KiB, rejects symlinks and extra files, and binds repository,
run/attempt, request kind, source and full control identity before uploading it.

The labels are `testing-approve-request-{run}`, `testing-merge-request-{run}` and
`testing-policy-request-{run}`. Renovate merge requests also send
`testing-approve-request-renovate-{run}` to renew the configured User review.
Production label handlers do not match these names. The server-hosted
`testing-process-request.yml` is triggered by `label:created`, not owner dispatch.
Before App issuance, its trusted host checks the exact Client App sender, server
repository, label/locator, current signed main, workflow path and first attempt.
It independently retrieves the original successful caller run and artifact,
including its exact reusable/source/control provenance. The existing source-run
poller handles label arrival before the caller completes.

The configured User PAT stays in trusted host review; candidate continuation gets
only operation-specific test-client tokens. Only merge shares `securefix-control`;
review/policy jobs can complete while a merge waits for them. Cleanup uses the
host's server `GITHUB_TOKEN` with `issues:write` and an API fence that permits only
DELETE of this exact validated testing label. It runs after failure as well when
preflight succeeded. No server token is forwarded to the candidate.

These definitions remain undeployed until fixture control and the indirect
client-secret exposure during candidate workflow mutation are resolved. Keeping
the native key contract does not resolve that GitHub-side exposure. Local checks
do not establish the new testing publisher or any of the ten live scenarios.

## Development dedicated caller migration

`testing-merge-caller-migration.yml` stays on `securefix-server` and reuses the
existing `caller-migration` Rust commands. Its inputs retain the exact client,
PR/head, full control identity, separate owner command IDs and selected publisher
run. The trusted host checks first-attempt owner dispatch, exact defining workflow
and current signed main before minting a singleton test-client read token. It
qualifies the isolated runtime as data, then runs `target` and `prepare` with the
reviewed host executable and isolated policy. The candidate does not supply its
own plan or trusted executable.

The candidate's `authorize`, `ready` and `merge` commands run in the same restricted
container with read-only plan, policy, binary and dispatch event mounts. Host
credentials and workflow command files are excluded. The authorization token is
limited to test checks/issues/PRs; the contents/PR merge token is minted only after
readiness. Each command reuses the existing canonical-file, owner review, command,
signature, control, replay and expected-head checks. Both privileged jobs have
owner/main/first-attempt guards, and the mutation job shares `securefix-control`.

This workflow is local and undeployed. No Client-key cutover is required under
the owner's threat model. Independent fixture initialization and reviewed
successors, parent prepare/verify evidence, exact rejection reasons and all ten
hosted scenarios remain required. No production control or settings are fixtures.

## Reviewed isolated control fixture

`testing-control-fixture.yml` lives on `securefix-server`. It builds its trusted
host from the exact protected-main workflow source in a secret-free job. The
credentialed job executes only that trusted host and treats the qualified runtime
archive as data. It mints a singleton `testing-securefix-server` token; there is
no candidate process or production write token in this controller.

`integration testing-control propose` validates current signed server main,
first-attempt owner dispatch/run provenance, source ancestry/signature/CI, exact
`testing-publish-runtime.yml` evidence, immutable release/archive/attestation,
source-bound testing policy and successful scratch verification artifacts using
the existing validators. It proposes only `control/active.json` in a signed
Server App PR on the test client. Expected test main and control are rechecked
before writes. A missing descriptor permits initialization only if its path has
no history on that main; deletion cannot reopen initialization.

`integration testing-control merge` repeats evidence qualification, requires the
exact one-file PR, expected main/head, Server App author/branch/repository,
verified commit signatures, owner review bound to the accepted control and
successful required `status-check`. Initial generation has no preceding active
test runtime, so its dedicated initial merge requires owner review bound to the
proposed descriptor; both command IDs must be zero. This follows the existing
reviewed bootstrap distinction, without changing production bootstrap authority.
Successors require review after the current fixture generation's activation and
fresh, separate, unedited `/approve` and `/merge` comments after that review.
Consumed IDs are rejected. The trusted controller publishes its exact-head,
control-bound policy result, rechecks state, and uses expected-head squash merge;
the activated descriptor is independently read back. A rollback is a new reviewed
generation, never a direct descriptor write.

This implementation does not certify a hosted fixture or migration. The parent
prepare/verify evidence and all ten scenarios still need actual Actions runs.
The existing Client repository secret stays in place under the owner's explicit
trusted-server threat model; no Environment move or per-job approval is required.

After initialization, `testing-control-fixture.yml` phase `propose-callers`
requalifies the active test descriptor and proposes the initial caller setup.
It reuses the existing strict production wrapper/minimal-CI validator and canonical
testing renderer. The signed Server App PR adds the three `testing-*` native
callers and `testing-ci.yml`, and deletes only the three old production caller
wrappers so owner commands cannot enter both deployments. The existing `ci.yml`
and other direct-harness workflows remain. This phase receives a separate
singleton test token with contents/PR/workflow write, without check or issue write.
Review and merge this initial setup through the existing production caller lane;
it is setup, not proof of migration from an unavailable caller.

`testing-distribute-runtime.yml` subsequently qualifies the isolated active
runtime with the trusted protected-main host. The candidate runs the existing
`distribute validate-promotion`, `prepare-caller` and `apply-caller` only in the
restricted container. Preparation gets a test read token; signed PR creation gets
only test contents/PR/workflow write after successful preparation. The workflow
opens the canonical migration PR and never merges it. Use the separate reviewed
testing migration lane. Owner/main/first-attempt guards and `securefix-control`
serialization apply before credential issuance or mutation.

## Retired legacy client smoke

The old `client-smoke`/`client-baseline` jobs and `client_runtime` selector were
removed. They split candidate CLI preparation in Docker from trusted-host label
dispatch, duplicating the approved-development native path under an obsolete
credential restriction. Their dedicated prepare/stage/dispatch/verify CLI commands
were removed as well. Normal client artifact preparation and Client App server
label creation remain in the production-shared testing callers; actual native
acceptance is recorded in [the workflow inventory](testing-workflows-client-inventory.md).
The direct scratch/bootstrap probes now run the owner-selected development CLI on the runner; their former candidate container boundary is retired. Provider build/signing separation has a separate role and remains unchanged.

## Existing direct scratch probes

The owner rejected the historical Client-key cutover proposal recorded in
`testing-workflows-isolation-review.md`. Keep the existing repository secret.
The legacy client smoke is retired. Owner-dispatched development code is trusted under the securefix-server change-management boundary.

The native integration command runs the candidate CLI against only
`civitaspo/testing-securefix-server`. It does not publish a runtime release or
write to another repository. The scratch Server App token is checked against
the installation repository list and each mutation is restricted by the API
client to the fixed scratch repository. The Client App token is checked the
same way. These scratch probes require only test-scoped installation tokens; ordinary approved-development workflows continue to use the existing User reviewer PAT where required.

The workflow builds or reuses one source-bound development CLI without secrets and installs it on the runner PATH. The same CLI validates provenance, retrieves fixture state, runs scratch operations/control probes and validates the resulting files. There is no separate trusted-baseline binary, candidate Docker container or verify-run artifact relay. The existing setup-cli main CI artifact reuse still checks source/build identity, producer and digest; control/authority/fixture checks run afresh. A metadata-only baseline job captures signed current main for `SECUREFIX_TEST_BASELINE_SHA`; it does not build another executable. That revision must remain current throughout the test.
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
from the current published stable runtime SHA, together with a generated
`.github/workflows/actions.lock`. The lock generator reads the exact recorded
scratch base SHA, overlays the rendered caller workflows, and removes only the
obsolete workflow paths recorded as present at that base. Verify regenerates the
lock from that same immutable base and requires the obsolete set and lock bytes
to match the prepared PR exactly. This keeps the disposable fixture aligned with
the normal caller lock maintenance path even when the published baseline predates
lockfile enforcement. Before minting App tokens, the host validates the published baseline source
and Release metadata and resolves its source-bound version tag. It passes
`SECUREFIX_PUBLISHED_RUNTIME_SHA` and `SECUREFIX_PUBLISHED_RUNTIME_TAG` to the
candidate, then independently rechecks both after candidate execution.

The direct readiness probe binds its policy check to the exact fixture head and
full structural control identity. A check emitted concurrently by the native
testing controller for another control does not satisfy that probe. The verifier
still rejects readiness before its own control publishes a policy result, then
requires that exact result and the current-head review.

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
to the control generation. A plain UI approval without the marker is rejected.
While the positive and stale PRs are drafts, post the exact owner `/approve` and
`/merge` comments on the positive PR, then the exact owner `/merge` on the
stale-head PR, one comment at a time. Wait for each matching caller workflow to
fail closed on the draft and for the opposite command workflow to skip. Confirm
that no request label or corresponding server request run was created. Then mark
both PRs ready, let their ready-event caller and server label-consumer runs finish,
and confirm the transient request labels are gone before dispatching verify.
The verifier re-reads the fresh, unedited owner comments after the PRs are ready
and records acceptance at that point. Later merge-state validation requires the
PRs to be ready and rejects changes to the review, head, or PR state after
acceptance. The comments exercise the production request and merge core. Their
original caller events failed closed while the PRs were drafts, so this does not
claim to test end-to-end caller event delivery.

The workflow validates producer metadata before minting scratch tokens and uses
one source-bound candidate CLI to retrieve state from the exact successful
owner-run `workflow_dispatch`, validate the server repository ID, owner actor,
workflow path, producer SHA, configured default branch or SHA-named frozen
integration branch, and bounded artifact, then run the probe and validate its
outputs. Prepare also checks that the named producer branch currently resolves
to the recorded producer SHA; keep a frozen integration branch protected against
updates while it is used. The candidate SHA remains an independent state binding.
The CLI uses the server-repository read token to fetch fixture artifacts; the
Server and Client App tokens are scoped to the scratch repository. Direct
owner-selected scratch probes use no separate trusted or candidate executable
or container. The probe then checks commit signatures, current-head
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

The owner-selected development CLI executes directly on the GitHub runner. The same CLI checks output bounds, symlinks and fixture/provenance bindings before artifacts are uploaded. Repository/token scope and independent protected-state checks remain required. This is not isolation against an attacker who controls the owner account or approved server code; those threats are outside this test environment's agreed scope.

The former standalone client smoke and published-baseline selector are retired;
they are not part of runtime qualification. Native testing callers exercise the
qualified development runtime and original Client App/server-label transport.
The distribution fixture below still reuses the scratch client policy and the
normal client Action; those shared helpers remain in use.

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

## Migration rejection fixtures

`testing-migration-fixture.yml` is a narrow trusted-host fixture writer on the
server. It builds the captured protected-main source without credentials and
validates its exact owner/main/first-attempt provenance before issuing credentials.
It accepts only an open Server App PR on the isolated policy's fixed automation
branch in the existing test client, with explicit expected head, protected main
and control identity. The host rechecks those fences before writes and independently
reads back the resulting head. It never merges or changes a descriptor.

The supported mutations add one unmanaged file or append a comment to the managed
merge wrapper. The latter supplies either non-canonical bytes or a head advance
*after* owner acceptance. These commits need the Server App identity so that the
real migration lane reaches the intended validation instead of an unrelated
commit-author rejection. Tokens remain singleton test-client tokens: ordinary
file changes and cleanup omit workflow permission; managed workflow mutations
request it explicitly. Cleanup closes only the accepted PR and deletes only its
still-matching automation ref. Candidate code is not executed by this host.

The non-owner case is different: it makes no test-client mutation. Trusted host
code verifies the existing reviewer User PAT's identity, prepares only the fixed
migration dispatch with the active publisher/control, and the trusted `gh` CLI
sends it as that User. The PAT is never passed to a candidate. The resulting run
must independently show both migration jobs skipped before token issuance and
unchanged protected test state. A dispatch permission failure is a failed setup,
not evidence that the migration guard rejected the request.

These fixture operations do not certify a rejection. Capture the independent
before state after fixture preparation; trigger the real migration workflow; then
verify its exact failure reason and a fresh after state. Revoked owner reviews
and edited commands are made by the owner controller outside candidate execution.
The consumed-command case must retain an open PR after accepted authorization
and failing required CI, then reject the same IDs in a new first-attempt run.
