# One-use successor activation recovery, 2026-10-17

Status: prepared for separate owner review. Execution requires approval of the
exact signed executor source and its fixed target, successful required CI, and
successful read-only qualification. This executor branch must never merge to main.

## Cause and fixed target

The active immutable v0.2.23 runtime checks `pull.head.user` as the PR author.
For the real same-repository activation PR, that field identifies the repository
owner; the actual Server App author is `pull.user`. Normal v0.2.24 activation
therefore stopped before its merge API call. Source correction
[PR #103](https://github.com/civitaspo/securefix-server/pull/103) merged through the
ordinary controller as signed main `2f7bd311be7c6bca92666dbcd9252991b8c8214a`.
Generation one remains active until a separately reviewed successor is merged.

The normally proposed target is [PR #104](https://github.com/civitaspo/securefix-server/pull/104),
head `1cb05b25b6ba0837e06890b2bf2f4d234d6e7be9`, selecting generation two with full
identity `1d259a21246696b0792be649d85caad702da271c417c441bd8dace786126cb42`.
Normal publication run `39041250830` and scratch verification run `39040925267`
succeeded. Required PR checks and owner/Bot review remain separate gates.

The [embedded authorization record](../control/successor-recovery.json) fixes the
expected main, current generation-one descriptor, single generation-two descriptor
PR and exact head, complete proposed descriptor, source, release/asset identities,
archive/policy digests, publisher and scratch-verification runs. It is compiled into
the fixed host; dispatch inputs cannot substitute another target. The candidate is
the normally published immutable v0.2.25 correction. The executor's own source SHA
is a separate identity, embedded by the source-pinned build and supplied again by
the owner dispatch and repository-level approval variable.

## Qualification and writer

The existing `control-activation.yml` path has recovery jobs only on
`codex/recover-successor-025-20261017`. Its ordinary main jobs retain their normal
published-controller contract. The branch builds the fixed Rust host from exact
`job.workflow_sha` without production credentials, then passes its immutable
artifact ID to a read-only qualifier. The candidate archive is data; its executable
is never invoked by the recovery host.

Qualification requires first-attempt owner dispatch; exact repository, branch,
workflow, compiled source, run and source-bound CI; unchanged protected main and
full current descriptor; signed source ancestry; the canonical Server App PR author,
repository IDs, branch, base and head; one signed descriptor-only commit; latest
exact-head owner and configured Bot approvals carrying the full current-control
marker; required CI, the unique exact-control policy check and GitHub approval
decision; normal publisher provenance; immutable release and asset identities;
archive size/digest, exact-source policy and normal publisher attestation; and the
complete scratch proof against the current published baseline.

Environment branch admission applies to all jobs using that environment. On this
unmerged branch, the repository-settings workflow's build and privileged jobs are
explicitly restricted to `refs/heads/main`; admitting the recovery branch cannot
enable its administrator-token lane. The distribution workflow's loader and caller
jobs also require main and the owner, independently of guards in the older active
runtime. Other dispatch entrypoints remain unreachable from this recovery ref,
including through `always()` jobs.

`successor-qualify` never enters the production environment or mints an App token.
Only `successor-merge` can enter the separate writer job, after successful
qualification and exact-source approval. That job uses the protected `main`
environment and shared `securefix-control` queue. Its App token is scoped to
`securefix-server`, with Contents and Pull requests write only. The host repeats
qualification, verifies installation scope, then re-reads main, active descriptor
and PR head before the sole PR Merge API write with the fixed expected head SHA.
The expected-main check is an application fence; GitHub's atomic CAS covers the PR
head. This procedure does not claim an atomic base-SHA CAS.

## Separately approved settings and execution

After the owner approves the exact signed executor and fixed target together:

1. Confirm the target and evidence are unchanged, required source CI and read-only
   qualification passed, and the one-use approval variable is absent.
2. Lock the executor branch with administrator enforcement, force pushes and
   deletion disabled. Confirm its head still equals the approved source SHA.
3. Temporarily admit only that exact branch to the existing `main` environment.
   Preserve the existing main admission, policy ID `50334840`, and record the
   newly returned admission ID for cleanup.
4. Create the **repository-level Actions variable**
   `SECUREFIX_SUCCESSOR_RECOVERY_SOURCE_SHA` using
   `POST /repos/civitaspo/securefix-server/actions/variables`, with its value equal
   to the approved executor SHA. Do not create an environment-scoped variable or
   shadow it in the `main` environment. Repository scope is required because the
   job condition and no-environment qualifier must both read it.
5. Dispatch `successor-merge` on that locked branch with the exact executor SHA
   and the four target inputs matching the embedded record. Inspect the actual
   writer result; do not treat dispatch acceptance or read-only success as a merge.
6. Verify the resulting signed main commit, one-file descriptor change, exact
   reviewed descriptor bytes and full identity, generation, runtime source and
   predecessor. Confirm ordinary runtime loading selects the immutable correction.

Only the existing separate administrator context performs these narrowly scoped
settings changes. It is never passed to the host or App job. No repository ruleset,
bypass actor, App permission, native auto-merge or direct Contents API write is added.
Bootstrap and bounded repair remain retired after generation one.

## Cleanup and stop conditions

Always remove the repository approval variable and only the newly created
environment admission after the attempt, including failure. Confirm the prior main
policy remains the sole admission, the variable is absent, and the executor still
has its reviewed SHA and remains locked. Retain the unmerged branch and evidence
for audit. A successful merge advances main and permanently invalidates this
executor's fixed-main fence.

On changed source, main, descriptor, head, review, CI, publication or scratch
evidence, stop before writing and clean up. On an ambiguous runner result, inspect
the run, PR and resulting main read-only. Do not replay a consumed authority or
re-enable its variable; a new recovery attempt requires a newly reviewed exact
source, fixed target and explicit authorization.

## Completion after recovery

The recovery merge does not prove the corrected normal activation path. Complete
an ordinary follow-up candidate cycle through source review/merge, scratch
prepare/verify, normal publication, exact descriptor review and separate normal
`/approve` and `/merge` commands before claiming that path works. After that normal
activation succeeds, explicitly distribute the verified publisher. First exercise
the complete owner-reviewed migration workflow on the configured scratch caller,
then review and merge the other eight caller PRs through that same narrow lane.
Verify actual default-branch pins and workflow results. Preserve failures in the
dated verification report and clean up disposable scratch fixtures.
