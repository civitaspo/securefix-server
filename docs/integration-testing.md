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
from the candidate SHA. The prepare run uploads its `state.json` as the
`scratch-fixtures` artifact.

Post an exact owner `/approve` and `/merge` comment to the positive PR, plus an
exact owner `/merge` comment to the stale-head PR. The positive PR also needs a
current non-author review approval and the required checks. Run the workflow's
verify phase with the successful prepare run ID. A validator compiled from the trusted defining workflow revision fetches state
only from that exact successful owner-run `workflow_dispatch`, validates the
server repository ID, owner actor, workflow path, producer SHA, main or
SHA-named frozen integration branch, and single bounded artifact. Prepare also
checks that the named producer branch currently resolves to the recorded
producer SHA; keep a frozen integration branch protected against updates while
it is used. The validator selects the candidate binary by its immutable artifact ID.
Only the validator receives the server repository read token; the candidate receives
only installation tokens scoped to the scratch repository. The candidate
SHA remains an independent state binding. It then checks commit signatures, current-head
authorization, merge readiness, squash merge, stale-head rejection, replay
rejection, and exact distribution workflow bytes. It closes any remaining test
PRs and deletes all three test branches after collecting evidence.

The harness invokes production PR authorization, merge-state, readiness, and
distribution rendering/validation functions. It does not claim that a scratch
workflow is a production request source: the source-run and reusable-workflow
artifact provenance chain is tested by its own fixtures because the scratch
caller is not the production caller workflow. The merge uses the same accepted
head SHA and squash API contract but does not publish a runtime tag/release.
The native repair apply core runs against GitHub with a verified signed commit,
exact contents and an idempotent retry. Release tagging uses the production annotated-tag
helper and verifies retries and target mismatch before deleting the disposable tag.
Immutable release publication remains a separate protected-main operation.

The candidate policy used by the harness is constructed in memory from the
bundled policy, narrowed to the scratch repository, and assigned the candidate
SHA. This is an explicit test context; production `Policy::active` and
main-revision write checks remain unchanged.
