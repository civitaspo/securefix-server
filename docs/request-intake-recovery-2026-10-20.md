# Request intake recovery, 2026-10-20

Status: corrected bounded recovery merged and temporary authorization removed; normal-path verification and deployment remain pending.

## Failure and bounded repair

Protected main `dd1f4ec650587e7d491f38df77708f0a1d9b65af` lowered request-capture
permissions before activating the runtime that moves receipt reactions to the
server. Generation six still selects immutable v0.2.36, source
`f80196051161fe4161c42cd9cb7530cc7db79882`, full control identity
`ab2b5b473767f6a3e58022dce677ae94a344c54fd1c12c8714a4deb6a74bd444`.
The owner command on [PR #142](https://github.com/civitaspo/securefix-server/pull/142)
failed before Client App dispatch in [run 39428623212](https://github.com/civitaspo/securefix-server/actions/runs/39428623212):
posting its reaction returned 403. A green code CI does not establish successful
owner authorization or satisfy the failed policy check.

The repair temporarily pins only the server's two request wrappers to the active
v0.2.36 reusable workflows and grants both Issues and Pull requests write to match
their declarations. The reaction API itself requires only Pull requests write,
but GitHub validates the entire nested permission declaration before starting jobs. Current reusable workflows and generated client templates
remain read-only. It does not change active control, repository policy, App
permissions or rulesets. The bridge must remain until a compatible successor is
verified and activated; remove it in a subsequent reviewed change.

## Permission evidence

The disposable [scratch PR #331](https://github.com/civitaspo/testing-securefix-server/pull/331)
and [probe 39432135670](https://github.com/civitaspo/testing-securefix-server/actions/runs/39432135670)
use source `611fde1dd08df445e351f63348638e39d31d2fbe`, based on scratch main
`7594ee5f7586d4f126639c5458faeb095c6994fa`. Three secret-free jobs use only their
own GITHUB_TOKEN against the same disposable PR comment:

| Issues | Pull requests | Result |
| --- | --- | --- |
| write | read | 403, expected rejection |
| read | write | 200, existing reaction accepted |
| write | write | 201, reaction created |

The overall run is marked failed because the negative job deliberately exposes
the 403. The two positive jobs succeeded. This reproduces the earlier
[PR #74 diagnosis](https://github.com/civitaspo/securefix-server/pull/74).
The probe establishes this API's token requirement; it does not establish a
successful production request, merge, publication or activation. The disposable PR
was closed without merging and its matching branch was deleted. Scratch main
remained at the recorded base.

## Separate recovery authority

Use the separately reviewed source-pinned Rust host pattern recorded in the
[successor recovery report](control-successor-verification-2026-10-17.md#first-corrected-successor-recovery-2026-10-18-jst).
The legacy bootstrap and bounded repair commands remain retired. A request-intake
repair requires its own explicit authority: the old successor executor cannot be
reused unchanged, because its descriptor-only target and successful ordinary
policy/approval prerequisites do not describe this failure.

Prepare an unmerged, one-use executor whose compiled record fixes the repository,
expected main, full active descriptor, PR number, exact target head and complete
allowed file hashes. Bind owner authorization to that record and the exact signed
executor source. Review the executor and repair before authorizing production
credentials. Successful independent required CI and read-only qualification are
mandatory before the writer can run. Do not manufacture a successful ordinary
policy check or describe the failed intake as an accepted command.

Qualification checks first-attempt owner dispatch, exact workflow/run/source and
repository identities, signed source ancestry, unchanged main and active control,
exact PR author/base/head/state, complete signed commit and changed-file lists,
exact file bytes, required code CI, and explicit exact-target owner authorization.
The recovery contract must state how it obtains the configured non-author review
and substitutes independent authorization for the unavailable intake. A successful
ordinary policy check cannot be assumed when intake itself is broken.

Build the executor without production credentials. Its read-only job must work
before environment admission. A separate writer repeats qualification, validates
the singleton Server App installation, and uses the protected main environment,
shared `securefix-control` queue and expected-head PR Merge API. Recheck expected
main immediately before the write; this is an application fence, not an atomic
base-SHA CAS. It may merge only the compiled target. Keep administrator credentials
in the separate settings context; the executor receives none.

Only after exact-source owner approval, temporarily admit the locked executor
branch to the main environment and set a repository-level exact-source approval
variable. Restrict every other privileged entrypoint on that branch so this
admission cannot enable settings, publication, distribution or other writes.
Do not add a ruleset bypass actor, enable native auto-merge or write main directly.
Always remove the approval variable and newly created environment admission after
an attempt, verify original admission is preserved, and retain the locked unmerged
source and run evidence. A changed fence or ambiguous outcome requires read-only
inspection; do not blindly retry or broaden the target.

## Prove normal operation and close recovery

Verify the merge commit's signature, sole expected parent, complete reviewed tree
and unchanged active descriptor. Then exercise fresh normal owner commands and
Bot approval through the repaired request path on a reviewed exact head. Complete
the affected scratch candidate prepare/verify cycle, normal immutable publication
and owner-reviewed activation before distributing client changes. A recovery merge
alone proves none of these later stages.

Record source and candidate SHAs, exact-head reviews/checks, run URLs and artifact
or release identities. Close disposable scratch PRs and remove only their still-
matching branches. Keep the permission probe's expected rejection in the evidence.

For future changes, preserve predecessor-compatible intake permissions until the
successor runtime is active. Rehearse recovery from intake, runtime-validation and
loader failures separately before claiming a reusable recovery capability exists.
This document does not establish that such a permanent executor is deployed.

## First bounded recovery and corrected compatibility requirement

The first independently reviewed executor source was
`e6214109711dfc504c7202012f15d8bdff92404a`, with
[successful code CI](https://github.com/civitaspo/securefix-server/actions/runs/39437467080)
and [read-only qualification](https://github.com/civitaspo/securefix-server/actions/runs/39437991365).
The [scratch fixed-core rehearsal](https://github.com/civitaspo/securefix-server/actions/runs/39438859972)
verified a signed exact-tree merge, stale-head rejection, unchanged scratch main
and complete fixture cleanup. The separate
[Bot review](https://github.com/civitaspo/securefix-server/actions/runs/39439292730)
approved PR #142 head `cdaebbcf51306dea3a2acc6dd8b1a010d381d989`.
The [Server App merge](https://github.com/civitaspo/securefix-server/actions/runs/39439800062)
produced signed main `041268a86feec5eed7c9514cf2c7c56089ca79dd`, sole parent
`dd1f4ec650587e7d491f38df77708f0a1d9b65af`, exact reviewed tree
`3566877425c63fccf92c454aa48e23f8047791cb` and unchanged active descriptor.
Readback confirmed the temporary source-approval variable and environment admission
`63718732` were removed, the original main admission `50334840` remained, and the
unmerged executor stayed locked at the approved source.

That successful bounded merge did not restore ordinary intake.
[Normal PR #141 intake 39440786077](https://github.com/civitaspo/securefix-server/actions/runs/39440786077)
failed before any job started. GitHub's annotation states that nested `capture`
requests Issues write while its caller allows only Issues read. The API permission
probe did not test workflow expansion; using its narrower permission for the
legacy reusable caller was an implementation error.

Two disposable scratch dispatches bind this diagnosis to the exact v0.2.36 approve
and merge reusables. Their jobs deliberately use `if: false`, so validation expands
the references without running a capture or exposing a secret to a job:

- [Both declared writes, 39441257574](https://github.com/civitaspo/testing-securefix-server/actions/runs/39441257574),
  signed source `72bcb9cea307ca6e89b23fd6389559bf49f39c01` on `testing/legacy-workflow-scope-positive-20261020`:
  valid workflow, both jobs skipped as intended.
- [Issues read, 39441404600](https://github.com/civitaspo/testing-securefix-server/actions/runs/39441404600),
  signed source `bee95d379a23add514928c0b2e73681b1689642b` on `testing/legacy-workflow-scope-negative-20261020`:
  startup failure with no jobs, reproducing the declaration mismatch.

These probes establish workflow validation behavior, not successful command
capture or Server processing. The corrected bridge must pass an independently
reviewed new exact-source recovery before ordinary owner commands can be proved.
The earlier executor cannot be reused: its fixed expected main and target are
already consumed. Bootstrap and repair remain retired.

## Corrected recovery execution and cleanup

The owner authorized remaining corrective work and deployment without further
conversational approval waits. The first corrected executor rehearsal
[39445902029](https://github.com/civitaspo/securefix-server/actions/runs/39445902029)
failed before writes because a test fixture prefix guard was stale. The next
[39449157853](https://github.com/civitaspo/securefix-server/actions/runs/39449157853)
exercised the merge and stale-head rejection but failed cleanup when the merged
branch was already absent. Neither failed rehearsal enabled production review
or merge; their temporary authorizations were removed. These failures are harness
defects, not passing rejection scenarios.

The frozen signed successor source
`0e33d30d70c14aa8dcfdc0d44134583b66aa75cd` corrected cleanup and added offline
regressions for already absent refs, exact-head deletion, concurrent 404/422
removal, authorization failures, changed heads and surviving refs. Its
[required code CI](https://github.com/civitaspo/securefix-server/actions/runs/39450313335)
and [read-only qualification](https://github.com/civitaspo/securefix-server/actions/runs/39450791204)
passed. Downloaded plan artifact `12278901305` matched the complete fixed record,
including authorization digest
`4e562713809db4f9f9db8ca2724032c406755cba8c43d48a6a89b19a7d23606c`.
The [exact source-bound owner authorization](https://github.com/civitaspo/securefix-server/pull/143#issuecomment-6294878324)
fixed PR #143 head `17de6fdb1fe4846acdc34d469662e1bab635de94`.

[Fresh rehearsal 39451205606](https://github.com/civitaspo/securefix-server/actions/runs/39451205606)
passed. Downloaded artifact `12277872667` and independent API reads confirmed
scratch PR #336 merged as signed `828d4b6e35ad22a38bcfd9e0c4cd826898f2e6fa`,
sole parent `fe75d490cecc5c26c2daeff371297d3d043ce656`, exact tree
`4f0471c8deee35130e844a74bb0e0610209320e7`; stale PR #337 closed unmerged.
All fixture refs were absent and scratch main remained
`7594ee5f7586d4f126639c5458faeb095c6994fa`.

The separate [Bot review 39451616538](https://github.com/civitaspo/securefix-server/actions/runs/39451616538)
created exact-head approval `5587704704`. The separate
[Server App merge 39451952259](https://github.com/civitaspo/securefix-server/actions/runs/39451952259)
merged only PR #143 as signed main
`84fa5d889c1b7f204a6e7bc5ce08d5bdd0606f99`, sole parent
`041268a86feec5eed7c9514cf2c7c56089ca79dd`, exact reviewed tree
`35c2a86ec23cb52f3b8fdb3779f3cbcdb116f532`. Independent reads confirmed the
complete generation-six descriptor was unchanged.

The repository source-approval variable and new environment admission `63728725`
were deleted. Readback confirmed only original main admission `50334840`, no
approval variable in either scope, and the unmerged executor locked at its signed
source with administrator enforcement and force pushes/deletion disabled.
No ruleset bypass or native merge settings were changed. Normal request intake,
candidate qualification, publication, activation and rollout require their own
subsequent evidence.
