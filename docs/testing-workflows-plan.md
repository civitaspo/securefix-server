# Workflow integration test implementation plan

## Current direction — supersedes historical routing and credential restrictions (2026-10-19)

The owner withdrew **server-wide execution centralization**. Testing follows the
production execution locations and existing commands: caller capture, release
preparation/build/tag and sync remain on the caller; server approval/merge/policy,
CSM writes and release signing/publication remain on the server. The six testing
reusables are production counterparts with testing names/references, qualified
development runtime, test-only targets/permissions and isolated control/policy.
Existing caller distribution generates all six testing callers, including release.

Reviewed server source and verified pre-release binaries bound to it are trusted.
Normal `securefix approve apply` uses the existing civitaspo-bot User PAT in the
same development CLI. Earlier blanket bans covering approved development code,
review-only/continuation CLI splits and server-wide routing are **historical and
not current policy**. Unreviewed code and unqualified artifacts remain untrusted.
Shared Apps, existing Client secret, normal Client App server labels and no extra
Environment approval remain final decisions. Production active control/settings
are not fixtures. Test installation tokens and actual mutations stay test-scoped.

Reuse identical-source/identical-build CLI artifacts with source, digest and exact
producer workflow/run verification. Rebuild only if no qualified reusable artifact
exists or source/build conditions differ. Runtime/control/PR/permission checks
still run on each operation. Prove reuse across multiple real Actions runs.

Current implementation removes the server-only metadata notification/release
adapter and dedicated aggregate processor, as well as review split commands and
its containers/transfers. Qualification and negative-case fixtures remain where
they serve independent provenance or scenario validation. Earlier split-route
successes are retained as historical evidence, not validation of this correction.
All reviewed-migration, native recovery and recorded refusal requirements remain.

Parallel work is now explicitly permitted by the owner; the primary agent owns
integration and final design decisions. Independent agents edit disjoint caller,
server, namespace and build-reuse areas; no duplicate investigation is requested.

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
`6260775361`, `6260777158`, `6260777386` preceded successful verify
`39207675252`. Its immutable `scratch-fixtures` artifact `12166706073` has digest
`7b4827600173d0d34ba75678ca8884a71781771d87c8e00ea44c6857f4378ce1`.
The Server App merged positive PR #245 as `ee182e58e7afdf2a432144fb3ddbca88f3ea0f1d`;
stale #246 and distribution #247 were independently read back closed/unmerged.
The direct assertions and failed earlier run remain recorded.

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
passed the deployed candidate artifact at that exact main source. The first verify
`39206649129` failed on competing legacy callers; reviewed test PR #244 repaired
only that fixture configuration. Fresh prepare `39207258822` and verify
`39207675252` then passed with unchanged assertions. Testing publication
`39208311685` produced immutable `v0.2.34-pre.1` at source one. No isolated
descriptor or canonical testing-caller deployment exists yet; the ten native
hosted workflow cases remain unverified. The second source is advancing through
ordinary server PR #121. See the newer execution sections for exact evidence.

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

### First immutable test publication and second source

Testing publisher [39208311685](https://github.com/civitaspo/securefix-server/actions/runs/39208311685)
succeeded from exact signed source `f0a8090a66b05d3c0e048a75e80d2e5fb6374edd`.
Release [v0.2.34-pre.1](https://github.com/civitaspo/securefix-server/releases/tag/v0.2.34-pre.1)
is a published immutable pre-release: release ID `416960439`, asset `655408620`,
size `4266388`, archive SHA-256
`814b28ceaf487b7331916aff258b09af634c1010be734c3e70b59cdb16701943`.
The trusted validator qualified the testing policy/archive, exact publisher
attestation passed, and the stable active controller published it. No production
activation occurred. This qualifies source one for an isolated descriptor;
it does not certify the ten native workflow cases.

[Server PR #121](https://github.com/civitaspo/securefix-server/pull/121) stages the
second source at signed head `425a854fddb5ab1fad51b5eecd6ff17156c2b278`.
Its actual CI `39207754316` passed, and fresh owner approve `6260870452` produced
exact-head User review `5567558891` and policy success. The normal separate merge
command was sent only after source-one publication finished. Source two still
needs merged-source direct qualification/publication. Keep the temporary legacy
caller fixture fence until both direct candidates are qualified, then restore
saved exact wrappers before proposing canonical testing callers.

### Second source deployed (2026-10-19T06:16:06Z)

PR #121 merged through normal server run `39208651493`, separate owner merge
comment `6260908348`, as signed main `10334dcb2b5f2e119f1b8724660df29c6a2f0f2a`.
Second-source prepare is `39208842850`; initial isolated descriptor proposal for
qualified source one is `39208912143`. Both are pending execution evidence.
Production active control is unchanged; no native acceptance result is claimed.

### Second direct qualification (2026-10-19T06:29:57Z)

Prepare `39208842850` and verify `39209719785` passed at exact source
`10334dcb2b5f2e119f1b8724660df29c6a2f0f2a`. Positive #248 merged as
`a31799aa572f63002e165451648bc23631364e5e`; stale #249 and distribution #250
were closed unmerged. Verify artifact `12166927282` has digest
`9bb650122a5e5e169f253b553a54a77b70bd7878f16f4378a1cfe76634ba739b`.
Testing publisher `39210164274` is running. The failed initial descriptor
proposal `39208912143` stopped at public attestation verification before a write;
local token-free verification of the exact archive/bundles succeeds. Fresh proposal
`39210117405` retains identical verification conditions and is pending.

Test PR #251 restores the exact three saved legacy wrappers after both direct
qualifications and adds a credential-free target required-CI fixture. It is held
unmerged until the initial descriptor operation has finished, to preserve its
expected-main fence. This is setup, not native acceptance.

### Source two published; attestation diagnostic follow-up (2026-10-19T06:33:34Z)

Testing publisher `39210164274` succeeded at source
`10334dcb2b5f2e119f1b8724660df29c6a2f0f2a`. `v0.2.34-pre.2` is published,
pre-release and immutable: release `416977455`, asset `655448383`, size `4276372`,
archive SHA-256 `b802142b8b77b05d7ff15f990b0ac48484143c59329b672b68e506d979bf2d73`.
Both distinct sources now have direct qualification and immutable publications.
Production generation five is unchanged.

Initial descriptor retry `39210117405` again stopped before any write with
`public testing runtime attestation verification failed`. The same public bundle,
archive, full source/workflow/digest constraints and CLI 2.102.0 pass locally with
no token and an empty config/cache. Hosted root cause is not established. A minimal
follow-up inherits stderr for this already token-free public verifier; credentials
remain removed and every verification argument remains exact. This is diagnostic
visibility, not an attestation bypass or a passed native case. No further runtime
publication is needed for that trusted-host-only diagnostic increment.

Test PR #251 has exact-head civitaspo-bot review `5567692803`, successful required
CI/policy, owner approve `6261142759` and separate merge `6261202402`. Its normal
merge was requested only after both direct qualifications completed and the
descriptor retry failed without writing. A fresh expected-main read is required
for the next initial descriptor proposal.

### Attestation cause identified (2026-10-19T06:43:15Z)

Reproducing the Rust verifier’s extensionless temporary filenames locally gives
`bundle file extension not supported, must be json or jsonl`. Earlier local
commands used `bundles.jsonl`, which explains their success. The minimum fix
creates the same bounded public bundle bytes using a `.jsonl` temporary file; all
cryptographic/provenance constraints remain unchanged. PR #122 includes this fix
and stderr visibility. Its prior merge request must not authorize the changed
head; obtain a fresh exact-head review and commands. Reuse both qualified runtimes
and run the actual initial control proposal after this corrected source merges.

PR #122 had already merged as `45672d80f0572556f909a926ec747a6ca18bccb7`
before the suffix commit reached its old branch. Therefore the suffix fix uses
a new PR based on that main, fresh version `0.2.34-pre.4` for the unchanged
version gate, and fresh head-bound commands. The merged diagnostic source has
not been dispatched for another failing proposal. Neither pre.3 nor pre.4 needs
publication: these are trusted host fixes, while the existing two qualified
runtime payloads remain selected for the planned test.

### Attestation fix verified on Actions (2026-10-19T06:54:28Z)

PR #123 merged as `2b0616521197329cf9281f607cea89c94831ac9c` after exact-head
review `5567802405`, approve `6261366626`, merge `6261423882` and successful
CI `39211634197`. Fixed control proposal `39212336684` succeeded with the same
source-one archive and all original checks. Earlier failed runs `39208912143` and
`39210117405` remain separate failed setup evidence. The `.jsonl` filename fixes
the reproduced CLI protocol error; attestation was not bypassed.

Descriptor-only test PR #252 selects qualified pre.1 at generation one, proposed
control `bb0f6bb9427ff257097a7d7f85369beb504494644f5ffb8036c0005628878d8f`,
head `b3192bf85c38df427ccd45bc1aa5ecf9382e4f9c`. Its file bytes and required CI
were checked; exact proposed-control owner review `5567890660` was submitted.
Initialization dispatch `39212605755` uses both command IDs zero as required;
no legacy `/approve` or `/merge` was posted for this descriptor. No production
activation, App, secret, settings or Environment change. Native acceptance remains
pending until actual caller setup, successor, rejection/migration/recovery runs.

### Canonical caller setup and successor proposal (2026-10-19T07:03:48Z)

Initial caller proposal `39212881045` created test PR #253 at signed head
`3b098e3ef0b8281de09fa589ee8de6533dbce5dd`. The generated diff renames only the
three legacy native wrappers to `testing-*`, pins development reusables at pre.1
source `f0a8090a66b05d3c0e048a75e80d2e5fb6374edd`, forwards the same existing
Client secret and adds `testing-ci.yml`. Required CI/policy and User review
`5567976815` passed; owner commands are `6261601217` and `6261637782`.

In parallel, read-only qualification and proposal `39213284245` produced
descriptor-only test PR #254 for generation two at head
`981607c9167a942625dd5f3165fee0a0489f00b1`. Its exact diff selects qualified
pre.2 and links previous control bb0f6bb9…; proposed full identity is
`317fbf25a73f6db161f76205f154c4c44de79c9009fb1e6669871af94999196f`.
Caller setup must merge before this successor; no native acceptance result is
claimed from either proposal or passing setup CI.

### Successor fixture base mismatch (2026-10-19T07:12:33Z)

Run `39213929302` refused PR #254 with `fixture PR ownership, branch, base or
accepted head changed` before mutation. The API still reported PR base
`3184f6280f16f6fdf334ff1c188d8b425801e7d1`, while caller setup had advanced main
to `0a898efe3e745fc7c8bb2c3088504aeeb739078b`. A PR base SHA is not implicitly
refreshed when main advances. Parallel proposal before that main write was a
fixture ordering error. Do not relax the exact base check or repeat the same
merge. PR #254 was closed unmerged and its exact branch head checked before
deletion; fresh proposal `39214453159` is bound to current main. No acceptance
case is certified by this setup refusal. Keep main frozen from each proposal
until its reviewed merge; after intentional control-change tests, create a fresh
canonical caller proposal for the new main before testing successful migration.

### Successor control activated (2026-10-19)

Correct-base PR #255 merged through reviewed fixture run `39214829376` at
`588ab2b354642bf0cc3b41c0b2e248a55a7766fa`. Independent descriptor readback and
Rust identity validation confirmed generation 2, control
`317fbf25a73f6db161f76205f154c4c44de79c9009fb1e6669871af94999196f`,
source `10334dcb2b5f2e119f1b8724660df29c6a2f0f2a` and the previously qualified
pre.2 archive. Review `5568115345` and distinct commands `6261816667` /
`6261816918` bind this fresh PR. Native acceptance remains pending; next is
canonical distribution and actual old-pin rejection, then the recorded guards,
reviewed migration and native Client-label recovery. No production activation.

### Native old-pin rejection confirmed (2026-10-19)

Distribution `39215317164` created canonical test PR #256 at head
`03312ce768f00707c6f4d99de41e4062ea3c55fb`. Actual client Approve
`39215616778` and Policy `39215616789` both failed at runtime qualification with
`testing caller workflow source differs from active test control`. Independent
trusted snapshots `old-pin-before.json` / `old-pin-after.json` show identical
default head, PR head/state/merged, reviews, comments and statuses; only Actions
check completion changed. Branch-and-pull comparison passed. This satisfies the
old-pin portion only; migration and native recovery remain pending. Evidence is
in `/private/tmp/securefix-phaseb-native-evidence/`.

### First native migration guards confirmed (2026-10-19)

Non-owner fixture `39216014326` dispatched actual migration run `39216179219`
as `civitaspo-bot` (User); both host and merge jobs were skipped with no steps.
Independent `nonowner-before/after.json` all-state comparison passed. After a
current-head CHANGES_REQUESTED review `5568242180`, owner migration run
`39216345180` refused with `current-head owner review for the active control is
missing`; independent `revoked-before/after.json` all-state comparison passed.
Both cases use canonical PR #256 and active control generation 2.

### Edited commands and failing required CI confirmed (2026-10-19)

Edited-command run `39216705755` refused the restored `/approve` body with
`owner command is edited, expired, pre-review or bound to another owner/PR`;
`edited-before/after.json` all-state comparison passed. Required CI fixture
`39217049218` first bound the exact head successfully and then deliberately
failed `status-check` (GitHub Actions App 15368, check 117943238727). Actual
migration `39217085370` recorded authorization, then refused Ready with
`required CI, control-bound policy check and current-head owner review are not ready`.
`failing-ci-before/after.json` confirms protected main and PR head/state/merged
unchanged. Separate owner consumption markers are `6262181003` / `6262181204`;
replay is being tested with a new first-attempt run, not a merged-PR shortcut.

### Consumed command replay confirmed (2026-10-19)

New first-attempt migration `39217540417` reused only the already consumed
command IDs on still-open PR #256. It refused with `owner approval or merge
command was already consumed; issue new commands`. Independent
`consumed-before/after.json` all-state comparison passed. The earlier failing
CI run and this replay remain separate evidence. A descriptor-only generation-3
rollback proposal (#257, run `39217337408`) is reviewed but remains unmerged;
test main/control stay frozen while file/head guards are exercised.

### Unmanaged fixture post-write readback failure (2026-10-19)

Fixture `39217927273` created signed Server App commit
`416e52f9cfd76cb255bec9e53a2c8670eb0f509b` (parent canonical `03312ce7…`),
then failed the immediate post-write PR predicate with `fixture is not the exact
open Server App migration PR on the fixed test repository`. The failed response
does not expose which predicate field differed; do not claim a proven API-lag
cause. Independent later PR readback satisfies every predicate, and the verified
commit adds only `.securefix-testing/migration-unmanaged.txt`; main/control are
unchanged. Do not repeat mutation. Use this independently verified invalid head
for the actual migration guard, keeping fixture failure and guard result distinct.

### Native unmanaged-file guard confirmed (2026-10-19)

Actual migration `39218387811` refused PR #256 head `416e52f9…` with
`automation branch contains an unmanaged or deleted file: .securefix-testing/migration-unmanaged.txt`.
Independent `unmanaged-before/after.json` all-state comparison passed. The
fixture-controller failure `39217927273` remains distinct from this successful
guard verification. Trusted owner cleanup independently fenced current main,
control, exact open Server App PR/head and branch, closed PR #256 unmerged,
verified its closed/unmerged head, then deleted only the matching branch and
read back unchanged main. This avoids rebuilding the cleanup controller; it
does not count as acceptance. Next canonical proposal is `39218758709`.

### Routing correction takes priority (2026-10-19)

User correction: the three migrated approve/merge/policy callers are not a complete
test deployment. Release PR/sync/tag still select production reusable workflows,
and the current testing reusables execute candidate capture in the consumer repo.
A reusable file on securefix-server does not make that run a server run.

| Consumer workflow / trigger | Existing call and runtime | Actual execution | Required correction |
| --- | --- | --- | --- |
| testing-approve-request / PR, owner command | testing reusable / pre.1 | consumer capture, server continuation | notification only in consumer; candidate entirely on server |
| testing-merge-request / owner or Renovate command | testing reusable / pre.1 | consumer capture, server continuation | same; preserve User review and Client label |
| testing-policy-check / PR, main push | testing reusable / pre.1 | consumer capture, server continuation | same; retain exact target/control checks |
| release-pr / main push, manual version | production reusable / v0.2.33 | consumer prepare, production server | testing caller and server processing |
| release-pr-sync / manual | production reusable / v0.2.33 | consumer | testing caller and server processing |
| release-tag / merged release PR, manual retry | production reusable / v0.2.33 | consumer build/tag, production server | testing caller and server processing |
| client-app-smoke / manual | source 678e10c6 probe | consumer | consolidate into real Client label ingress evidence |
| runtime-smoke / manual, workflow push | synthetic archive | consumer | remove obsolete substitute; verify selected real runtime on server |
| verify-server / manual | old 97269f5f testing reusable | consumer | remove obsolete entry; use server native verification |
| verify-published-runtime / manual | old 7819d4ab stable loader | consumer | consolidate into server qualification/isolated runtime verification |
| ci, fixture-validation, testing-ci, testing-required-ci-fixture | credential-free CI | consumer | preserve; intentional CI fixture remains |

Reuse existing label processor, isolated runtime qualification, restricted Docker,
release implementation and caller distributor. Enable Release capability only in
the single-repository testing policy; production policy/control stay unchanged.
All new caller files/display names and server entrypoints use testing-. Remove
old consumer release/smoke/verify files as part of the exact reviewed setup change,
not by leaving duplicate active routes. Notification data remains untrusted and
requires exact successful first-attempt run, reusable pin/source, caller source,
current control and native event/authorization checks on server. Keys/PAT remain
in approved host code; no extra Environment approvals or authentication system.

Preserve Phase B evidence. No runs are currently in progress. Fixture run
39219142815 failed after a signed managed-bytes mutation of PR #258 with the
same undiagnosed immediate PR-predicate failure as 39217927273. Independent
readback is saved as managed-fixture-independent-pr.json; do not repeat mutation.
Add field-level diagnostic context without relaxing predicates. PR #258 and the
reviewed, unmerged control proposal #257 are unfinished fixtures, not acceptance.

Order: correct routing implementation and exact caller generation; review/merge
server source; qualify its explicit development runtime; install isolated control
and all testing callers through reviewed changes; prove actual Client label route
and selected runtime per feature (including release); then resume canonical
migration, native recovery and remaining negative scenarios with independent
protected-state snapshots. Existing successful/failed evidence is retained.

### Approved development runtime trust correction (2026-10-19)

The previous implementation incorrectly treated every development binary as
untrusted even after reviewed-source and publication qualification. That was not
the user's intended boundary. This entry supersedes the earlier blanket PAT/key
prohibition and split-review design, while retaining its history. Approved server
source and a verified runtime bound to that source are trusted in server testing
workflows. Unreviewed PR code and unqualified artifacts remain untrusted.

Use the same qualified development CLI for normal validate/apply operations.
In particular, `securefix approve apply` uses the existing civitaspo-bot User PAT
and posts the actual review. App token actions still issue explicit test-only
repository and operation permissions. No new key delivery mechanism, issuer,
App, Environment approval or production fixture is introduced.

Delete split approval modes, review-for-testing/apply-reviewed-for-testing,
relayed policy apply and prepare/continue testing-request commands. Remove
consumer candidate execution, its loader, split-only Docker and host/candidate
manifest transfers. Retain qualification as a prerequisite to executing approved
development code; it is not a split of the tested business operation. Existing
qualification and migration scratch containers remain only where they exercise
unreviewed source or protect disposable fixture operations. Reassess them by
actual role instead of imposing them on approved normal processing.

Verification starts anew for changed execution paths. Earlier split-path successes
remain historical evidence and cannot prove corrected native processing.

Implementation checklist and throughput checkpoint:

Historical checkpoint: the server-wide routing and sequential/no-agent statements
below were superseded by the current direction at the top of this document.

- [x] `how` over affected ingress, approval, policy and release call sites.
- [x] `architect` skipped: user fixed the design and forbids redesign/delegation.
- [x] Blocking first steps: record corrected trust and preserve previous evidence.
- [x] Independent workstreams: sequential source/workflow/caller edits; no agents.
- [x] Shared mutable state: preserve production control; serialize test main/control changes.
- [x] Smallest safe decomposition: one owner reuses normal commands and exact existing manifests.
- [ ] Remove split code and route client notifications to server development commands.
- [ ] Complete release routes and remove obsolete consumer smoke/verify entries.
- [ ] Verify changed source, review/merge, qualify runtime and install reviewed test callers/control.
- [ ] Verify real Actions routes and rerun affected acceptance cases.

Model the Domain keeps the existing RequestManifest and ControlRevision as the
authority data shapes. Subtract Before You Add removes the split modes before
extending release routing. The implementation and checks are sequential; no
independent agent review is claimed.

### Native path implementation checkpoint (2026-10-19)

The six testing reusable workflows now share the production job/command sequence
and execution locations, with the qualified testing loader and testing release
branch. The five server testing entrypoints retain normal approve, merge, policy,
CSM and release processing. Normal `approve apply` owns the complete User review;
split commands, aggregate notification/release adapters, aggregate processor and
approved-runtime migration/distribution Docker launchers have been removed.
The existing unreviewed-source scratch harness remains separate.

Canonical distribution now renders all six testing callers, including release;
the isolated policy enables release only for testing-securefix-server. Client
capture/release preparation/build/tag/sync stay on the client. Removal of old
consumer release/smoke/verify routes still requires a reviewed consumer change.

The existing setup-cli action can reuse a source/build-bound main CI artifact.
It checks the producer repository, workflow, successful first attempt, exact SHA,
artifact SHA-256, fixed archive members and matching policy bytes before reuse.
Missing or mismatched artifacts fall back to the existing locked Cargo build.
Each business operation keeps its own current control and authorization checks.
The local functional test covers reuse and source/digest rejection; real multi-run
reuse and corrected native-path acceptance remain pending.

Local checks for this checkpoint: `cargo test --locked` passed 42 library, 288
CLI, 22 bootstrap and 3 integration tests (2 CLI tests ignored). Clippy with
`-D warnings`, formatting, shell syntax and actionlint passed. Evidence:
`/private/tmp/securefix-phaseb-native-final-tests-2.log`,
`/private/tmp/securefix-phaseb-native-final-clippy-3.log`, and
`/private/tmp/securefix-phaseb-native-final-actionlint.log`. The earlier failed
full run and focused corrections remain separate logs; its stale permission
assertion was fixed before this successful full run. Production `control/active.json`
and `policy.json` have no local changes. Hosted acceptance remains pending.

### Reviewed source and runtime milestone (2026-10-19)

PR #124 merged through the normal User bot approval and `/merge` path to
`a0725a954715c840fedfb841c0edcd9612636056`. PR CI 39228547288 and main CI
39229307199 passed. Initial automatic pull_request_target approval 39228606592
failed with the exact reusable-source revision reason; the separate owner-command
approval 39228636479 succeeded. Both remain distinct evidence. Production control
blob remains `ef2dcc1ed591fc6c4e7815f5e5d40794933b254f`.

Main CI published artifact 12175922566, SHA-256
`e164a2114e3cf0242a457b1890c21351544d3c1fe1a7a2fa452179426134a7b7`.
Publisher 39229862034 and fixture cleanup 39229864332 independently reused it;
their setup logs contain the same source/producer/digest and no compile commands.
This satisfies multi-run identical-source CLI reuse. Prepare 39229859747 passed
and the qualified pre-release v0.2.34-pre.5 was published by 39229862034.
These successes are prerequisites, not native recovery or migration acceptance.

Cleanup closed invalid disposable PR #258 unmerged and deleted only its exact
accepted automation branch. Independent readback confirmed test main
`588ab2b354642bf0cc3b41c0b2e248a55a7766fa` and control blob
`887d2ed6278df1df79074a286460b8d42c568001` unchanged.
Corrected-path evidence lives separately in
`/private/tmp/securefix-phaseb-native-corrected-evidence`; all prior path results
remain historical. All ten acceptance scenario entries start pending there.

Corrected-source verify 39230155449 passed, reusing prepare 39229859747.
The owner independently reviewed signed positive PR #259 at
`14d2e01794e395a191bd3c02547ed3a7bd2114ed` with structural scratch control
`44b321613fcdd86999e6e23502112b81c15bc16dffe3b3c62237c91398da7a96`
(review 5569467291), then posted separate commands 6264051787/6264052159;
stale PR #260 had command 6264052473. The scratch harness merged only the
positive fixture and cleaned the stale/distribution fixtures. Test main is now
`aa7acebe537b6f2ca401bb70848b80fcd2301f74`; the isolated active descriptor
remains generation two until its separately reviewed successor merges. This is
qualification evidence, not the native caller recovery result.

### Additive release-caller migration failure (2026-10-19)

Reviewed control PR #262 merged via 39230946790 after review 5569518100 and
commands 6264133296/6264133702. Independent descriptor readback identifies
generation three `65629f1ab698348cebe378fe80f0d6d369f885d828bde34f42d0727ee2df956c`,
source a0725a9, with test main `98abbe820338c9960e076a2a1262877d72cb6329`.

Distributor 39231133319 then failed in “Validate publisher and prepare canonical
test caller files” with `required managed caller workflow is missing`. The old
testing deployment has three feature callers and CI; release is newly enabled,
so its three exact generated release callers must be added. Existing prepare_caller
permits a missing policy-check workflow only. Failure preceded write-token issuance
and PR creation; no migration PR exists. Do not repeat this run unchanged.

The minimum correction is to admit the three exact canonical release paths as
additions when rendered for a release-enabled policy. Existing caller and CI
requirements, validation of present files, canonical bytes, source/control, owner
review and ready/merge checks remain. This is a normal distributor feature addition
and uses the same implementation in production/testing. No new fixture/auth/build
framework is introduced. A changed CLI source requires a new pre.6 qualification;
pre.5 results are preserved and are not acceptance of the fixed distributor.

The pre.6 correction passed all 32 distribution tests, including a release-enabled
migration from the existing three feature callers plus CI and explicit rejection
when approve is missing. Formatting and whitespace checks passed. The signed
source change proceeds through the ordinary owner-command review/merge path.
