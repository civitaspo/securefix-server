# Workflow integration test implementation plan

## Completion criteria

Run a caller migration through real GitHub Actions in isolated test repositories.
After activating a successor control, prove that the old caller fails, the reviewed
canonical caller PR can still merge through the dedicated lane, and normal caller
operations recover. Security cases must prove a specific rejection and unchanged
protected state. A timeout or infrastructure failure is a failed test.

Use the existing GitHub Apps. Candidate installation tokens are restricted to
the test repositories; trusted native label dispatch uses server `issues:write`. The owner confirmed this shared-App arrangement on 2026-10-19;
dedicated test Apps are not a completion criterion. Never give candidate code
production credentials or owner credentials.
Every test workflow file and display name starts with `testing-`.

## Owner decision: trusted server and unchanged Client secret (2026-10-19)

The owner trusts change management and code approved in `securefix-server`.
Compromise of that server, or an attacker able to introduce malicious approved
code there, is outside this test environment's threat model. Deliberate use by
that code of a test workflow-writing token to obtain a repository secret is
therefore not a completion criterion. This does not authorize direct credential
access by candidate code.

The owner rejected the proposed `testing-client-dispatch` Environment, moving or
deleting the existing `testing-securefix-server` repository secret
`SECUREFIX_CLIENT_PRIVATE_KEY`, and per-job owner approvals. The decision is final;
the Environment proposal is historical and no longer pending. No seven-consumer
secret cutover or replacement authentication platform is required for this concern.

Retain the existing host/container boundary: only trusted code handles App keys,
bot PAT and owner credentials; candidate containers receive only tokens restricted
to the necessary test repositories and operation permissions. Never pass candidate
code production-directed tokens. Reuse the existing restricted Docker harness.
Retain Client App server-label creation and automatic processing, exact
provenance/source/runtime/control qualification, reviewed migration and normal
recovery, and all ten rejection scenarios with exact reasons and independent
unchanged-state readback. Production active control/settings remain untouched.

This decision supersedes the indirect repository-secret exposure deployment fence
and pending Environment/credential-cutover wording in historical sections below.
The host-executed candidate smoke path is replaced locally as described below.
Hosted control initialization and successors, scenario orchestration and hosted
verification still require work.

## Native request protocol correction (2026-10-19)

The owner's label-path question exposed an omitted requirement. The existing
client uploads request artifacts, obtains a Client App installation token scoped
to `securefix-server` with `issues:write`, and creates a server request label.
The server's label event starts request processing. This is also the upstream
[csm-actions protocol](https://github.com/csm-actions/securefix-action#architecture).
See `reusable-approve-request.yml`, `reusable-merge-request.yml`,
`reusable-policy-check.yml`, `src/request.rs::dispatch` and
`src/policy_check.rs` for this deployment's implementation.

At the time of the correction, the local secret-free testing reusables only
captured/uploaded artifacts and `testing-process-request.yml` substituted an owner
dispatch. The implementation following that correction is described below. These are reusable
implementation parts, but this alternate trigger does not prove recovery of the
normal label-driven caller path. Retain label ingress in that acceptance test.
Do not count manual processing as successful normal automatic recovery.

The earlier claim that the client repository secret can be removed is withdrawn
for the existing protocol. Current callers require
`SECUREFIX_CLIENT_PRIVATE_KEY` to obtain the label-writing token. Neither
cross-repository reusable placement nor the caller's `GITHUB_TOKEN` supplies
that server authority. The Client App label-writing credential is distinct from
the Server App's commit/merge authority; sharing the existing Apps remains decided.
No secret has been deleted or copied.

Keep credentials and server-directed tokens out of candidate execution. A trusted
label-writing operation still needs its narrowly scoped server token; inspect
how to preserve this native path with the existing host/container boundary before
changing client secret configuration. The previous seven-consumers-versus-new-client
scope question was premature and is withdrawn. Subsequent remediation proposals
below are inspection history, not an approved cutover or evidence that a
label-preserving replacement exists. This correction supersedes conflicting
key-removal and normal-flow claims below and in earlier ledger entries.

### Native ingress implementation following the correction

Local testing reusables and canonical callers now retain the named Client key
forwarding contract. Candidate capture stays inside the existing sandbox. After
bounded host validation and upload, a separate trusted dispatch job downloads the
immutable manifest and validator artifacts and revalidates them. Its pinned token
action mints only a server `issues:write` Client App token. Trusted Rust code rechecks the isolated
control and creates a `testing-approve-request-*`, `testing-merge-request-*` or
`testing-policy-request-*` label. Renovate review refresh has its own testing
approval label. No candidate code executes with that key or server token.

`testing-process-request.yml` now receives `label:created` automatically. Its host
validates the exact Client App sender, fixed server/client/run locator, source,
workflow and first attempt before test-token issuance, then independently loads
the successful caller artifact with existing provenance/control checks. The
trusted User review and candidate test-token continuation are reused. Review and
policy runs can finish while the serialized merge lane waits for them. Trusted
cleanup can delete only its exact validated testing label, including on failure
after successful preflight. Production label handlers do not match this namespace.

This supersedes the owner-dispatch and secret-free caller descriptions in the
historical status below. It is local implementation, not hosted proof. The
existing client repository secret is retained. Indirect access through intentionally
secret-reading workflows is outside the owner-defined threat model above; direct
credential exclusion from candidate execution remains required.

The concrete proposed GitHub configuration change and seven-consumer rollout are
in [Client key protection proposal](testing-client-secret-protection-proposal.md).
It is retained as proposal history. The owner rejected its Environment move and
per-job approvals; no secret or setting change is required for that proposal.

## Hosted direct-harness qualification: caller interference (2026-10-19)

Prepare [39206238831](https://github.com/civitaspo/securefix-server/actions/runs/39206238831)
succeeded at source `f0a8090a66b05d3c0e048a75e80d2e5fb6374edd`. It proved the
restricted candidate execution, credential-free client capture, trusted Client App
label dispatch and immutable artifact readback. The virtual control probe recorded
three distinct generations, expected-head conflict rejection and stale identity
rejection after ABA. These are direct-harness results, not the ten native workflow
acceptance cases.

Verify [39206649129](https://github.com/civitaspo/securefix-server/actions/runs/39206649129)
reused that exact immutable candidate/state after owner review `5567425033` and
separate commands `6260633467`, `6260634047`, `6260634245`. It failed with
`positive policy check was published before the native auto-merge probe`.
Existing production-pinned caller workflows had also processed these direct core
fixtures and created production-control reviews/checks and owner markers. The
assertion is retained. Fixture PRs #241–243 were closed by cleanup; independent
readback confirmed test main stayed `0851bea96e07756a8ee52c5721dba99b8527d13f`.
The two outstanding competing fixture merge runs `39206677319` and `39206684422`
were cancelled; approval run `39206678642` had already completed. This failed
qualification is not publication or migration evidence.

[Test PR #244](https://github.com/civitaspo/testing-securefix-server/pull/244)
merged temporary job guards on the three existing legacy callers as
`bb15209a8844e29abb7f45ba9ee0628649e14e02`, through the normal server merge
lane `39207118408` after the exact-head `civitaspo-bot` APPROVED review,
owner approve `6260676111` and separate merge `6260693810`. Only direct
`securefix-integration-*` PR branches and `test: Securefix ` issue titles are
excluded before entering the reusable workflow/minting credentials. Ordinary PRs
and native migration scenarios on the canonical automation branch retain the
Client App path. The exact original files are saved in
`/private/tmp/securefix-phaseb-direct-fence/`; restore them by reviewed PR after
all direct candidate qualification and before initial canonical testing-caller
setup. No secret, Environment, App, production control or setting is changed.
This is a test fixture configuration repair, not a relaxed verification gate.
Fresh prepare `39207258822` passed using the same candidate source. Legacy
approve/policy jobs were skipped and the positive head had no premature review
or policy check. Owner review `5567499478` and separate commands
`6260775361`, `6260777158`, `6260777386` precede verify `39207675252`, which
is in progress.

## Execution checklist

- [x] Read the Principles section of poteto-mode.
- [x] Phase A: Frame.
- [ ] Phase B: Design the workflow.
- [ ] Phase C: Run the loop.
- [ ] Phase D: Keep the audit trail.
- [ ] Phase E: Verify and hand back.

The side conversation forbids delegation. Design exploration and review run
sequentially. They do not constitute independent review.

## Units and verification

1. Trace the existing deployment, runtime loader, distribution and migration lane.
   Capture current main and reuse the existing Rust integration commands.
2. Keep production and development `testing-*` definitions, including reusable
   workflows, on `civitaspo/securefix-server`. Test clients pin its development
   reusable workflows. Separate test control state from workflow/source identity;
   use an additional state repository only if the existing test client cannot
   supply that fixture. Preserve exact workflow provenance checks.
3. Extend prepare/verify evidence with workflow runs, PR heads, active controls and
   expected outcomes. Keep owner review and commands outside candidate execution.
4. Exercise the real distribution and dedicated migration workflow. Verify the
   resulting caller bytes and a recovered normal request.
5. Exercise non-owner dispatch, unmanaged files, managed-file tampering, stale head,
   changed control, failing CI, revoked review, edited comments and consumed commands.
   Use separate fixtures and prove no forbidden mutation for each rejection.
6. Validate Rust and workflow changes. Run the isolated integration scenario if the
   test repository and App installation are available. Record external prerequisites
   explicitly if they prevent a live run.

## Throughput checkpoint

The highest-risk unknown is exact provenance across development runtime selection
and independent control state. Resolve that before adding scenario orchestration.
Reuse the existing harness, policy types and canonical workflow renderer.
Do not add a second implementation language or a generic test framework.
Do not disable existing scratch workflows. Separate direct-harness fixture branches
from event-driven fixtures.

## Credential decision before deployment

Sharing an App also shares its private key's authority. Restricting a token's
`repositories` input limits that token, but does not limit what another workflow
holding the same key can mint. A protected test branch still adds another place
whose workflow changes must be trusted with the App's production installations.

Do not copy production App keys into candidate-controlled workflow definitions.
The existing harness keeps the keys in trusted host steps and executes the candidate
in a container with singleton scratch tokens. Preserve that boundary.

Earlier exploration considered dedicated test Apps or a separate trusted issuer.
That credential choice is now resolved: reuse the existing production Apps and
the existing Actions host/container boundary. Keep token issuance in reviewed
`securefix-server` testing workflow definitions; reusable caller jobs retain
caller context for the existing Client key contract. No external token service
or general credential platform is planned. Do not ask for dedicated Apps again on
the basis of shared-key authority alone.

Server App keys and the bot PAT stay in trusted server operations. The existing
Client key stays available to trusted caller dispatch operations. Candidate
execution receives only explicitly scoped, operation-specific test tokens; their
repository lists exclude `civitaspo/securefix-server` and all other production
repositories. No key is copied into candidate execution or a new test repository.
Ask for a specific decision only if an actual required operation cannot preserve these
boundaries with the existing arrangement. Historical pending-choice rows remain
in the TSV; the owner's later decision supersedes them.

### Workflow placement and runtime selection (owner clarification)

| Role | Placement | Credential boundary |
| --- | --- | --- |
| Production workflows and runtime selection | `civitaspo/securefix-server` | Existing released and activated stable runtime; production control is not a fixture |
| Development controller, reusable workflows and trusted credential operations | `civitaspo/securefix-server`, reviewed `testing-*` definitions under existing protection | Keys and bot PAT stay in trusted operations; candidate execution is container-only with test-only tokens |
| Candidate runtime | Explicit source-revision build artifact, or provenance-verified pre-release | Exact source/artifact/publisher bindings; candidate binary/Action/scripts never execute in PAT/key operations |
| Canonical caller files, migration PRs, rejected fixtures and recovered client requests | Existing `civitaspo/testing-securefix-server`; callers pin development reusables on `securefix-server` | Test-only tokens; separate fixture identities from the existing direct harness |
| Independent development control state | Isolated test fixture, preferably in the existing test repository | Exact repository/path/revision/control binding; reviewed successors and new-generation rollback; never production active control |

The earlier proposal to deploy a second workflow server to
`civitaspo/testing-securefix-control` is superseded by the owner's clarification.
Do not create it as a development workflow host. Independent control generations
require independent state, not a second workflow or publisher identity. The
existing client tree at `0851bea96e07756a8ee52c5721dba99b8527d13f` has no
top-level `control` directory. Check whether its fixture storage can serve this
purpose before proposing another repository. If another state repository is
necessary, specify only its descriptor/PR/state role and the concrete reason the
existing test client is insufficient; no dedicated App follows from that choice.

Native client jobs still need test-only tokens. A cross-repository reusable runs
in its caller's context and does not gain the callee repository's secrets. Keep
production-directed dispatch and PAT operations in the trusted host; do not solve
the client boundary by passing a production-repository token or key to candidate
code. Audit the existing artifact/capture/dispatch split before selecting a
bounded transfer mechanism. No new issuer service or generic authentication
platform has been adopted.

### Isolation inspection and concrete prerequisites

The existing scratch container command has a pinned image, non-root UID, read-only
root filesystem, dropped capabilities, no-new-privileges, PID/memory/CPU limits,
private PID namespace and bounded tmpfs. Its bind mounts expose only the executable,
policy, fixture output directory and CA certificates. There is no host home,
credential directory, Actions command-file directory or Docker socket mount.
The explicit environment list excludes App keys, owner credentials and the host's
GitHub token. Reuse these settings rather than adding an isolation framework.

This is code inspection, not a proof of the complete existing workflow. The
baseline scratch job installs the candidate on host PATH and invokes
`integration resolve-test-runtime` before token issuance and again afterward;
the client-smoke job also executes the candidate Action on the host. These host
execution paths must not be copied into the new key-holding testing controller.
Keep the captured trusted validator on host PATH, use explicit candidate mounts
only inside the sandbox, and validate outputs as data before any host operation.

### Historical repository-secret concern (resolved by owner)

Read-only inspection found the existing client repository secret and no
Environments. Workflow-writing test tokens could intentionally create workflows
that read that secret; Docker alone does not prevent such remote actions. No
exploit or secret read was performed. This led to the Environment proposal and
seven-consumer cutover exploration, which the owner rejected under the explicit
trusted-server threat model above. Preserve the repository secret and its normal
Client App label-dispatch consumers; no additional job approval or credential
cutover is pending. Continue excluding credentials and production-directed tokens
from candidate processes, using trusted dispatch and restricted containers.

## Scenario contract

Keep the automatic reviewer as `civitaspo-bot` (`User`). The owner rejected the
proposed Client App reviewer adaptation. The existing PAT may be used by trusted
host code; it may not enter candidate execution. `approval::apply` currently
combines candidate-capable policy logic and PAT review mutation, so split those
operations using the existing review core rather than changing reviewer identity.
The candidate must independently read back the exact-head, control-bound User
review before continuing with its limited test token. Local commands now separate
`approve review-for-testing` (trusted host User review) from
`approve apply-reviewed-for-testing` (test-token-only continuation); both revalidate
the request and require the isolated testing policy. The local development workflow
now wires them together; it has not been deployed or run. Keep the owner User review and separate
commands in every case. This credential split has not yet established a working
native Actions flow.

Each row uses a distinct fixture and separate owner commands. Record the exact
client default head, PR head, control identity, review ID, command IDs, workflow
source, run ID and attempt before execution.

| Case | Required observation | Protected state after execution |
| --- | --- | --- |
| Canonical migration | Old caller fails, canonical migration merges, new caller request succeeds | Default contains exactly the generated caller files |
| Non-owner dispatch | Privileged jobs are skipped before token issuance | Default, PR, reviews, policy checks and authorization comments unchanged |
| Unmanaged file | Canonical file validation rejects the extra path | PR unmerged and default unchanged |
| Changed managed file | Exact generated-byte validation rejects the altered file | PR unmerged and default unchanged |
| Changed head | Accepted review and command head no longer match | PR unmerged and default unchanged |
| Changed control | Accepted control no longer equals the active descriptor | PR unmerged and default unchanged |
| Failed CI | Readiness rejects the required failed check | PR unmerged and default unchanged |
| Revoked review | Effective owner review no longer authorizes the accepted head | PR unmerged and default unchanged |
| Edited comment | The command's update time invalidates the accepted unedited command | PR unmerged and default unchanged |
| Consumed commands | A new first-attempt dispatch rejects already consumed command IDs | PR unmerged and default unchanged |

Capture snapshots before the scenario's triggering event and read GitHub state
again afterward. Include every privileged job's conclusion and the exact failed
step or skipped-job guard. For a rejected operation, require its expected validation
reason as well as unchanged state. An API, setup, artifact, timeout or runner error
fails the parent test even if the PR remains open.

The consumed-command fixture must stay open after the first accepted attempt.
Use a failed required CI check after authorization, then submit another first-attempt
dispatch with the same comment IDs. A merged PR alone cannot prove replay rejection.

Changed control requires a real reviewed successor descriptor. Restoring the old
runtime source must still use a new descriptor generation and identity.
Never edit `control/active.json` directly to manufacture the scenario.

Preparation may complete without owner review. Verification must retrieve the exact
successful prepare artifact and immutable candidate artifact, and reject missing or
additional cases. Cleanup uses only recorded fixture identities and expected heads.

## Current status

The foundation is deployed through the ordinary source-code PR lane:
[PR #120](https://github.com/civitaspo/securefix-server/pull/120), reviewed head
`f6cba8dcef4d16bf1eaa176110203ded153eee4b`, `civitaspo-bot` APPROVED review
`5567379748`, owner approve comment `6260523221`, separate merge comment
`6260555280`, and successful
[CI](https://github.com/civitaspo/securefix-server/actions/runs/39205833004).
The server merge lane is
[run 39206111198](https://github.com/civitaspo/securefix-server/actions/runs/39206111198);
main is `f0a8090a66b05d3c0e048a75e80d2e5fb6374edd`.
Production active control remains generation five selecting v0.2.33/source
`1e2866cbab65c5ef4e218fa6853300c2731e73c0`; no activation/settings/secret change.
The automatic PR-target approval attempt rejected reusable provenance; a fresh
ordinary owner `/approve` comment succeeded with the exact-head User review and
policy result. No provenance condition was relaxed.

[Scratch prepare 39206238831](https://github.com/civitaspo/securefix-server/actions/runs/39206238831)
passed the deployed candidate artifact at that exact main source. Follow-up verify
`39206649129` failed because the old native callers also processed the direct
fixtures; see the hosted qualification section above and repair PR #244. No testing
pre-release, descriptor or canonical testing-caller deployment has been created,
and the ten hosted workflow cases remain unverified.

The following paragraphs record implementation progress before that deployment;
their earlier local-only/undeployed statements are historical.

The latest local increment adds `testing-control-fixture.yml` and trusted Rust
propose/merge operations for initial and successor test descriptors, reusing
publication/scratch/signature/review/comment/CI checks. Initial activation uses
a proposed-control-bound owner review with zero command IDs; successors require
the full existing separate-command contract. Only reviewed PR merges change the
test descriptor. Production bootstrap/activation remain separate and unchanged.
The legacy smoke host Action execution is replaced with credential-free sandboxed
CLI artifact preparation, bounded host validation and trusted label dispatch.
These additions have not yet been deployed or verified by hosted scenarios.
See [the integration contract](integration-testing.md#reviewed-isolated-control-fixture).

The next local increment adds `propose-callers` to that trusted controller:
requalify the test descriptor, validate existing native wrappers/minimal CI,
propose the canonical testing wrappers and testing CI, and remove only the old
three production wrappers. Keep the existing direct-harness CI/workflows and
repository secret. Initial setup merges through the existing production caller
lane and does not count as the unavailable-old-caller migration scenario.
`testing-distribute-runtime.yml` reuses existing distribution in the candidate
container with test-only tokens and never merges its PR. Its trusted source and
runtime qualification, first-attempt owner guard and shared mutation queue reuse
the existing test processor boundary. Hosted acceptance remains pending.

Draft implementation PR: https://github.com/civitaspo/securefix-server/pull/120.
Its first source `6f994a4b213261e08153d0e3112ef54d23561806` is GitHub-signed.
The [initial CI run](https://github.com/civitaspo/securefix-server/actions/runs/39205242258)
passed format/tests/Clippy/version/actionlint and `status-check`. This certifies
CI for that source only. The ordinary request capture rejected the draft PR as
not ready; the production policy check correctly requires exact-head owner
authorization for sensitive code. Neither is a testing migration scenario result.


After the fixture controller and smoke isolation increment, local assembled
checks pass: 354 tests (42 library, 287 CLI, 22 bootstrap, 3 client), 2 existing
ignored, documentation tests, fmt, clippy and actionlint. The full test log is
`/private/tmp/securefix-phaseb-distribution-verified.log`; Clippy output is in
`/private/tmp/securefix-phaseb-distribution-verified-clippy.log`. Earlier assembled failures exposed
obsolete workflow expectations; the implementation and exact assertions were
corrected before the successful rerun. No hosted scenario,
publication, deployment or control activation has occurred. The owner has resolved
the Environment tradeoff by rejecting it under the explicit trusted-server threat
model above. Fixture initialization/successors and all ten live scenarios remain
unfinished.

Phase B has resumed from the recorded baseline. The owner confirmed shared Apps
and the protected production-repository test controller. Local implementation of
the trusted `testing-` namespace covers the canonical caller renderer, exact
publisher/bootstrap/migration/request/reusable validators, runtime loader and
scratch fixture paths. Focused tests pass, including a separate process with the
test policy and loader rejection cases in both namespaces. Release provenance
and automation-branch detection use the same exact selected namespace.
This is a local provenance unit, not a deployed test environment.

The concrete `.github/testing-policy.json` keeps the production workflow host,
App identities and `civitaspo-bot` User, while selecting only the existing test
repository for mutation and independent descriptor state. Isolated approval,
merge, policy and release caller rendering now retains named Client key forwarding
where required; exact canonical validation rejects missing or substituted keys. The namespace regression
now uses this actual policy and the production workflow host. The legacy client
Action/autofix fixture has a separate credential migration prerequisite and is
not evidence of a key-free native client path.

`testing-publish-runtime.yml` implements the permitted pre-release route without
production activation. It builds and attests the candidate with its source-bound
testing policy, then passes the archive as data to the captured, protected-main
validator. The read-only `integration validate-testing-publication` gate requires
the exact current signed source, first-attempt owner dispatch, testing publisher
path, unchanged App/User/workflow identities, a `pre.N` version and the exact
archived testing policy. Archive inspection reuses the existing bootstrap's
bounded Rust parser, now shared with normal control qualification. It rejects
traversal, duplicate paths, links, special entries, expansion excess and invalid
trailing data; it never extracts or executes the candidate. The publication step
then restores the stable active controller on PATH and uses the existing runtime
publisher. It does not propose or activate a production descriptor. This route
currently selects the exact reviewed protected-main source, not arbitrary branches.
Development loading now has a local implementation; fixture activation remains
unfinished. The loader reads the isolated descriptor with a test-client token,
uses anonymous public source/release/attestation metadata, and checks the exact
testing publisher, source, CI, policy and full release/archive tuple. It passes
repository-bound inline bundles to GitHub CLI's token-free bundle verifier with
empty GitHub configuration and a temporary cache. The archive stays data on the
host. Control and current signed validator main are re-read before export.

The three testing request reusables now preserve native label dispatch through
trusted host code while candidate capture remains container-only. See the native
ingress implementation section above for the current contract. The previous
owner-dispatch relay description is superseded; no hosted recovery is claimed.

`testing-merge-caller-migration.yml` now connects the existing dedicated Rust
migration lane to the same trusted-host/candidate-container split. Every job is
guarded by owner, first attempt and protected main. The host validates its exact
workflow and current signed source before token issuance, qualifies the active
test runtime as data and prepares the canonical reviewed plan. Candidate
authorization, readiness and merge run in separate restricted containers with
read-only plan/event mounts. The merge token is issued after readiness. Every App
token targets only the test client; no key, PAT, host token or socket is forwarded.
The processor and migration host validators accept only their own exact workflow
paths. This definition remains undeployed; the owner has removed the client-key cutover
fence. It does not itself initialize or advance the independent control fixture.

Read-only attestation qualification on 2026-10-19T02:10Z used existing v0.2.33
archive `b2c044b989ae12e0fae28f8ac7f69d1adeaab87af709d84a1e3a0c62df1c7dcb`
as data. With no token variables and empty GitHub configuration, the exact
production signer/source verification returned zero. Changing only the signer
to `testing-publish-runtime.yml` returned nonzero. An initial attempt failed to
initialize Sigstore's cache under the local sandbox; supplying a writable
temporary XDG cache resolved that tooling error without altering verification.
This verifies the credential-free bundle route, not a testing publication.

The local package advances to `0.2.34-pre.1`. Read-only GitHub lookups returned
404 for both its exact tag and release on 2026-10-19T01:57Z. This is an availability
observation, not a reservation or publication; CI must check again before merge.
The testing policy is included in runtime-version input classification.

The scratch workflow no longer installs or executes the candidate on the trusted
host PATH. Its downloaded candidate binary/policy are mounted directly into the
existing containers. The separate client-smoke host Action path was subsequently replaced by the
container/trusted-dispatch increment described above.

Independent host-side readback commands now capture and compare a fixed client
PR's protected branch/PR state and review/check/status/comment fingerprints.
They fail on missing fields, duplicate IDs, incomplete check pagination, oversized
files or movement during capture. Their contract is in `integration-testing.md`.
They are only a readback primitive: scenario chronology, exact artifact producer,
source/control bindings and the expected rejection reason still require parent
orchestration. Keep their output outside candidate-writable mounts.

Assembled local checks at 2026-10-19T01:41Z pass: formatting, actionlint v1.7.12,
Clippy with warnings denied, and 328 executable tests (38 library, 266 CLI,
22 bootstrap, 2 client; 2 existing tests ignored). Documentation tests pass
(zero tests) with the installed pinned 1.99.0 `rustdoc`. Earlier checks exposed
a missing temporary-toolchain `rustdoc`, then four workflow assertions that still
expected candidate host installation. The tool path and assertions were corrected;
the final complete check passed. These are local checks; none establishes a live
Actions result.

The assembled check at 2026-10-19T02:24Z passes formatting, actionlint,
Clippy with warnings denied, and 345 executable tests (41 library, 280 CLI,
22 bootstrap and 2 client; 2 existing ignored). Documentation tests pass with
zero cases. The preceding full run caught a workflow assertion against `chmod`
in the newly added launcher step. The launcher now uses the existing `install`
convention; the assertion was retained unchanged and the full suite rerun.
The decision ledger has six columns throughout, testing policy parses as JSON,
documentation file links resolve and `git diff --check` passes.

Remaining Phase B work includes complete generated test deployment definitions
and trigger/fixture separation. The proposed client credential cutover is rejected.
Workflow/source authority remains on `securefix-server`; local
`deployment.control_repository` now selects only the exact existing integration
repository for descriptor reads, activation timestamps and per-write checks.
Its policy and API write guards exclude production mutation and settings
authority. Production activation explicitly rejects that split configuration:
development evidence qualification and initial/reviewed successor fixture
activation now have the local trusted controller described above. No hosted fixture
descriptor was created.
The existing namespace work is reusable, but it is not a second-server deployment.
Keep the stable production loader separate from explicit candidate/pre-release
selection in testing workflows. The local User review/native relay split still
requires hosted verification.
Then implement the exact prepare/verify evidence and all ten live scenarios.
Repeat the existing publication/version availability check before proposing these
runtime changes; no tag or release has been reserved by this local implementation.
The owner-defined threat model resolves the historical repository-key fence;
credential movement and additional per-job approvals are not prerequisites. No live integration run, deployment, repository
creation, secret copy, settings mutation or production activation has occurred.
Read-only inspection found no environments on the existing scratch client and found
the Client App key as a repository secret. This is an observed configuration, not
evidence that the new test-server isolation already exists.

The earlier seven-consumers-versus-new-client scope question is withdrawn by the
native request protocol correction above. First preserve and inspect the actual
label-dispatch path and its trusted credential boundary. Shared Apps, the User
reviewer and server-side workflow placement remain resolved. The indirect-access concern is resolved by the owner-defined scope above; direct
credential exclusion remains required. The owner-dispatch relay is not a replacement
for native request ingress.

### Phase B provenance trace

The following production contracts must stay exact in the generated deployment.

| Boundary | Existing implementation | Test deployment requirement |
| --- | --- | --- |
| Runtime loader and attestation | `.github/actions/load-runtime/load.sh`, `src/runtime.rs`, `src/control_commands.rs` | Bind the test repository, exact publisher path, source, immutable release and descriptor; do not accept a production publisher as a substitute |
| Distribution | `src/distribution.rs`, `src/distribution/caller.rs` | Generate the canonical test caller from the selected test runtime and revalidate its exact bytes |
| Dedicated migration | `src/distribution/reviewed.rs` | Keep owner actor, first attempt, protected default head, defining workflow path, current control, review and separate command checks |
| Recovered request | `src/request.rs`, `src/workflow.rs`, `src/policy_check.rs` | Require the exact test wrapper and reusable paths at the accepted source revisions, rather than accepting either namespace |
| Independent control state | `src/config.rs`, `src/control.rs`, `src/api.rs`, `src/request.rs` | Keep the test descriptor repository and revision distinct from workflow/source provenance; initialize and advance only reviewed fixtures, never production's retired bootstrap |

Naming must be bound to trusted deployment configuration because workflow paths
are part of authorization, not just display labels. Use a single optional
`deployment.workflow_prefix`, restricted to empty or `testing-`, for canonical
workflow paths. Existing production policy omits the field and retains its exact
paths and serialized representation. A test deployment selects only the prefixed
paths; it must not also accept unprefixed production paths. Existing `testing-`
paths remain singly prefixed. The workflow generator and runtime validators must
use the same mapping. Test repository/App IDs still come from verified deployment
configuration, never from a prefix or caller input. The workflow host remains
`civitaspo/securefix-server` for both development and production. This naming unit
does not relocate development workflows to another server.

Implement this naming/provenance unit before scenario orchestration. Keep the
recorded ten scenarios, artifact bindings, owner controls, fixture separation and
credential gate unchanged. No repository provisioning, secret copying, settings
change or new token issuer has occurred.

## Decision record

See `testing-workflows-decisions.tsv`. Record verified results separately from
implementation and unverified live behavior.

## Baseline

Work starts from protected main `7d94766dccf7231408c3aa7b6137315e5fcd7728` in
an isolated clone. The shared worktree is untouched.
The proposed `civitaspo/testing-securefix-control` repository was not found during
the initial read-only GitHub lookup. No external test setup has been changed.

### Next reviewed increment: rejection fixture operations

Local `testing-migration-fixture.yml` and the narrow Rust fixture command provide
only the missing signed test inputs and exact cleanup. Existing canonical
migration, provenance, owner review/commands and snapshot comparison remain the
validators. A separate trusted-host branch can dispatch the actual migration
workflow using the existing configured non-owner User PAT after identity checking;
it does not pass that PAT to a candidate. No new authentication service, App,
review identity, Environment approval or production fixture is introduced.
See [the fixture contract](integration-testing.md#migration-rejection-fixtures).
This increment advances the next candidate to `0.2.34-pre.2`; it is local and
unpublished. Source one remains frozen while its direct qualification runs.
The client stage validator also rejects a symlinked output directory before
reading it and bounds enumeration to two entries. The focused regression passed.
Hosted scenario results are still required.

Local assembled verification of this increment passed 356 tests (42 library,
289 CLI, 22 bootstrap, 3 client; 2 existing ignored), fmt, actionlint and Clippy.
The first assembled run found a sort-order mismatch in the exact secret-free
build-job inventory; the expected list was ordered correctly and all assertions
were retained. Logs: `/private/tmp/securefix-phaseb-fixture-verified.log` and
`/private/tmp/securefix-phaseb-fixture-clippy.log`. No native hosted acceptance
case is certified by these local results.
