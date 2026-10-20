# One-use request-intake executor, 2026-10-20

Status: prepared for exact-source owner review. This branch must never merge to
main, publish a runtime, or be distributed to callers. Production write
qualification, scratch rehearsal and repair merge remain pending.

## Fixed repair and authority

[PR #142](https://github.com/civitaspo/securefix-server/pull/142) repairs only the
server-local legacy request compatibility bridge, its structural tests, package
version and recovery documentation. The [compiled authorization record](../control/request-recovery.json)
fixes head `cdaebbcf51306dea3a2acc6dd8b1a010d381d989`, expected main
`dd1f4ec650587e7d491f38df77708f0a1d9b65af`, complete generation-six descriptor,
reviewed tree, three signed owner commits and SHA-256 hashes for all eight changed
files. Dispatch inputs cannot substitute another repair. The source-pinned Rust
host extends neither the retired bootstrap nor its bounded repair contract; its
three new commands are explicitly separate authority on this unmerged branch.

The owner reviews this exact executor source, the fixed target and this procedure
together. Authorization of the general recovery procedure does not replace this
exact-source review. The read-only plan prints the exact unedited owner comment
required on the target PR. That comment binds source, target, expected main, full
control and the compiled authorization record. It expires after 24 hours; changed
or edited comments and later source/head/control changes are rejected. PR head,
base and lifecycle transitions at or after authorization also invalidate it.

## Independent gates

The fixed host builds from `job.workflow_sha` without credentials and is passed
by immutable artifact ID. The qualifier runs without a production environment or
App token. It validates owner/run/workflow/source and branch identity, successful
source-bound code CI for executor and repair, signed owner ancestry, unchanged
main/policy/control, exact same-repository PR identity and state, complete signed
owner commit chain, full changed-file set and bytes, fixed tree and scope probe.

All unrelated PR checks must be completed and successful, neutral or skipped.
The only substituted ordinary policy failure is the exact-control Server App
check whose reported reason is missing owner authorization. The executor never
publishes a substitute green `securefix-policy-check`. It repeats these independent
gates before privileged writes. Administrative configuration is not read by this
host, and no administrator credential enters any of its jobs.

The production review and merge additionally require a successful rehearsal run
from this same signed executor source and first-attempt owner dispatch. The host
verifies its bounded, digest-checked artifact and independently reads scratch PRs,
merge signature/tree/sole parent, unchanged protected scratch main and deleted
fixture refs. A successful fixture setup or read-only plan is insufficient.

## Scratch rehearsal scope

The [compiled fixture record](../control/request-recovery-rehearsal.json) identifies
owner-signed scratch PRs #332 and #333 against the disposable non-default base
`testing/recovery-base-20261020`. It does not change either repository's main.
The source-bound test harness is compiled in the secret-free build job and receives
only a singleton scratch installation token, never the production installation
or configured reviewer PAT. The shared token-scope guard rejects other installations.

The test exercises the actual fixed merge core after target/fence validation,
rejects the advanced stale head before writing, verifies the successful signed
merge's exact tree and parent, rechecks scratch main and cleans recorded fixtures.
It does not exercise production owner intake or the configured User reviewer
credential. Their exact-target validation and mutation/readback are separate
production recovery gates. Unit fixtures cover changed owner/source/head/control,
signatures and effective committers, altered files, main fences and the exact
expected-head Merge API payload. No test is represented as proof of ordinary
production recovery.

## Exact-source approval and execution

After reviewing the immutable executor source and fixed repair together:

1. Confirm successful executor and repair CI and the read-only `request-recovery-plan`
   run; retain its artifact and the exact source SHA. Inspect all remaining gates.
2. Through the separate administrator context, lock only the executor branch with
   administrator enforcement, no force pushes or deletion, and confirm its SHA.
   Preserve main protection, rulesets, sole Server App PR bypass, native merge
   settings and all existing environment admissions.
3. Temporarily admit only this branch to the existing `main` environment. Record
   the new admission ID for cleanup. Set the repository-level Actions variable
   `SECUREFIX_REQUEST_RECOVERY_SOURCE_SHA` to the approved source SHA. Confirm no
   same-named environment variable shadows it. No App permissions change.
4. Post the plan's exact owner authorization comment on PR #142 after source review.
   Dispatch `request-recovery-rehearsal` with exact `authority_sha` and that
   `authorization_comment_id`. Inspect the actual result and independent scratch
   state. Any failure stops production work and requires cleanup and investigation.
5. Dispatch `request-recovery-review` with the same source and comment plus the
   successful `rehearsal_run_id`. Only this job receives the existing configured
   User reviewer PAT. Rust verifies its identity and non-author status, repeats
   qualification and posts APPROVED for the exact `commit_id`. It checks the
   resulting review and GitHub review decision.
6. In a separate dispatch, run `request-recovery-merge` with those same bindings.
   Its read-only qualifier also checks the latest exact-source/head/control Bot
   review. The writer alone mints a server-repository Contents/Pull requests token,
   verifies singleton installation scope and repeats qualification, authorization,
   review and check validation. It rechecks head, main and full active descriptor
   immediately before the fixed PR squash Merge API call with expected-head CAS.
   The main fence is an application check, not an atomic base-SHA CAS.
7. Verify the resulting signed main's sole parent and exact reviewed tree, unchanged
   active descriptor and completed target PR. Restore and prove ordinary intake
   with fresh exact-head commands, then complete candidate qualification and the
   ordinary publication/activation sequence before caller distribution.

The protected writer jobs share `securefix-control` with `queue: max`. Temporary
branch admission cannot enable this branch's settings or distribution workflows:
their entry and privileged jobs explicitly require main. Other manual privileged
entrypoints are guarded by main or the separate integration branch prefix, or
depend on such guarded jobs without `always()`. The fixed recovery jobs alone
admit the exact recovery branch, owner, source and first attempt.

## Cleanup and failures

After completion or any failed attempt, remove the repository approval variable
and only the newly created environment admission using the separate administrator
context. Confirm earlier admissions remain unchanged, no environment variable
shadows the removed repository variable, and the unmerged executor remains locked
at its reviewed SHA. Do not relax rulesets, enable auto-merge, push main directly,
reuse bootstrap, fabricate policy checks or broaden this authority.

Inspect an ambiguous result read-only before taking another action. A successful
merge changes the fixed expected main and prevents another successful use. A
failed or abandoned operation requires fresh explicit review before re-enabling
source approval. Preserve source, exact-head reviews/checks, run and artifact
identities, resulting commit and cleanup evidence. The general recovery contract
and later reusable mechanism must be reviewed separately; this one-use executor
is not a permanent alternative merge service.

## Source preparation evidence

The fixed repair head passed [code CI 39435333243](https://github.com/civitaspo/securefix-server/actions/runs/39435333243),
including the required `status-check`. Its ordinary policy result is still the
exact-head/control missing-owner failure, as expected before separate recovery
authorization.

Before freezing this executor source, local `cargo +1.99.0 fmt --all -- --check`,
`cargo +1.99.0 test --locked`, `cargo +1.99.0 clippy --locked --all-targets -- -D warnings`,
and CI-pinned actionlint v1.7.12 passed. The full suite passed 42 library, 303 CLI,
32 fixed-host, two native-client and one testing-runtime tests; two existing CLI
live tests and the new scratch rehearsal remained ignored locally. Cargo JSON
selection independently identified the exact test executable. Independent source
and read-only live review found no remaining blocker after the permission,
policy-check completeness, stale-rejection, timeline-restoration and harness
selection fixes. These checks do not establish a successful live rehearsal or
production recovery.

The initial executor [CI 39436152460](https://github.com/civitaspo/securefix-server/actions/runs/39436152460)
at source `868cc8d68acb07954b60361a38cb1dd4b2e90368` stopped before Rust checks:
the new control-activation artifact upload was missing its workflow lockfile
association. The official gh-actions-lock v0.2.0 regenerated that single entry;
its frozen check then validated all 42 workflows and the relevant Rust lockfile
contract test passed. No production operation ran during the failed CI. The
corrected source needs its own successful code CI and read-only plan.
