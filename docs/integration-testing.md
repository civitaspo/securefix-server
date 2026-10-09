# Candidate scratch integration

The native integration command runs the candidate CLI against only
`civitaspo/testing-securefix-server`. It does not publish a runtime release or
write to another repository. The scratch Server App token is checked against
the installation repository list and each mutation is restricted by the API
client to the fixed scratch repository. The Client App token is checked the
same way. Do not pass a user token or a production installation token to the
candidate process.

The trusted workflow builds the candidate without credentials, then runs the
artifact in an isolated job. Run `securefix integration run --phase prepare`
with the candidate SHA and a state-file path. The workflow producer SHA is
recorded separately from the candidate SHA, so a candidate commit does not
need to contain the workflow that produced its fixture artifact. The workflow
sets `SECUREFIX_TEST_WORKFLOW_SHA` to its own source SHA. The command creates three signed,
disposable PRs in the scratch repository: one for the approval/merge path, one
for stale-head rejection, and one containing the managed workflow files rendered
from the current published stable runtime SHA. The host verifies that stable release
and its exact SemVer annotation tag before passing `SECUREFIX_PUBLISHED_RUNTIME_SHA`
to the candidate. This reuses an existing stable release and creates no candidate release.
The prepare run uploads its `state.json` as the
`scratch-fixtures` artifact.

Post an exact owner `/approve` and `/merge` comment to the positive PR, plus an
exact owner `/merge` comment to the stale-head PR. The positive PR also needs a
current non-author review approval and the required checks. Run the workflow's
verify phase with the successful prepare run ID. A validator compiled from the trusted defining workflow revision fetches state
only from that exact successful owner-run `workflow_dispatch`, validates the
server repository ID, owner actor, workflow path, producer SHA, the configured default branch or
SHA-named frozen integration branch, and single bounded artifact. Prepare also
checks that the named producer branch currently resolves to the recorded
producer SHA; keep a frozen integration branch protected against updates while
it is used. The validator selects the candidate binary by its immutable artifact ID.
Only the validator receives the server repository read token; the candidate receives
only installation tokens scoped to the scratch repository. The candidate
SHA remains an independent state binding. It then checks commit signatures, current-head
authorization, merge readiness, native GitHub auto-merge, stale-head rejection, replay
rejection, and exact distribution workflow bytes. The distribution PR runs actual
`pinact run --verify-comment` and must have a successful Actions `status-check`.
The positive PR queues auto-merge while its required policy check is absent, proves
it remains open, publishes that check, and waits for GitHub to merge it. The stale
PR advances after auto-merge is queued and must reject the old accepted head.
The harness closes any remaining test
PRs and deletes all three test branches after collecting evidence.

The harness invokes production PR authorization, merge-state, readiness, and
distribution rendering/validation functions. It does not claim that a scratch
workflow is a production request source: the source-run and reusable-workflow
artifact provenance chain is tested by its own fixtures because the scratch
caller is not the production caller workflow. The auto-merge mutation binds the
accepted head SHA and uses squash merge, but does not publish a runtime tag/release.
The native repair apply core runs against GitHub with a verified signed commit,
exact contents and an idempotent retry. Release tagging uses the production annotated-tag
helper and verifies retries and target mismatch before deleting the disposable tag.
Immutable release publication remains a separate protected-main operation.

The candidate policy used by the harness is constructed in memory from the
trusted runtime policy, narrowed to the scratch repository, and assigned the candidate
SHA. This is an explicit test context; production `Policy::active` and
default-branch revision write checks remain unchanged.

The candidate executes in a digest-pinned Ubuntu container with an unprivileged user, read-only root filesystem, dropped capabilities and private process namespace. Only its executable, read-only deployment policy, CA certificates and fixture directory are mounted; the runner filesystem, Docker socket and workflow command files are unavailable. Only scratch tokens and explicit non-secret workflow metadata enter the container. App keys and the server read token stay in the trusted host steps. The trusted CLI rejects symlinks, unexpected files, oversized data and invalid output bindings before fixture artifacts are uploaded.

The separate `client-smoke` job exercises the actual composite client Action. Its
action checkout and candidate binary are bound to the successful credential-free
build's source SHA and immutable artifact ID. A trusted controller generates a
scratch deployment policy and one fixed input file. The Action receives only a
Client App token restricted to scratch `issues:write`, uploads the real envelope,
and creates its request label in scratch. The trusted verifier independently reads
the source artifact and scratch label, checks exact metadata and file bytes, and
uploads `client-verification.json`.

Candidate testing uses `client_runtime: candidate-artifact`. After stable publication,
repeat prepare and verify with `client_runtime: published-release`; that leaves the
Action's candidate-directory override empty and exercises Release download,
attestation verification, preparation, upload and dispatch. Completion requires this
published-runtime client test, successful consumer pinact CI and actual scratch
auto-merge. Fixture preparation and distribution success alone are insufficient.
