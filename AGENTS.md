# Agent instructions

## Unmerged recovery executor branch

This branch contains a proposed one-use recovery executor for the exact PR #98
target recorded in `control/bootstrap-recovery.json`. Never merge this executor
branch into main. Its production use requires separate explicit owner approval
of the final executor SHA and the settings changes in
`docs/bootstrap-recovery-2026-10-17.md`. Before that approval, only source review,
CI, and `recovery-qualify` (without production credentials) are authorized.
The normal repair guard and main rulesets remain in force. After approval,
the executor branch must be locked before its exact environment admission and
out-of-band SHA variable are configured; remove admission and the variable after
the attempt. Do not give settings credentials to the executor.

## Purpose and architecture

This repository is a privileged GitHub automation server. Preserve its security
boundaries when changing approval, merge, repair, release, or repository settings.
The Rust `securefix` CLI owns validation and business logic. Workflows orchestrate
events, verified runtime loading, credential isolation, and CLI invocation; keep
shell steps limited to this orchestration. Do not restore upstream Securefix
Actions or implement policy decisions in Bash, Python, or github-script. Introducing
another implementation language requires an explicit owner decision. The fixed
`control-bootstrap.yml` workflow invokes the `securefix-bootstrap` Rust binary,
built from its exact protected-main source in a separate job without production
credentials. It independently qualifies the
bootstrap source, publisher run, archive, attestation, policy, scratch proof, and
reviewed PR because no verified active Rust runtime exists for the first migration.
The candidate archive is data during this qualification; the candidate executable is
never run. Repair is split into `repair-propose` and `repair-merge`; both validate the
bounded repair PR contract. Repair cannot change the bootstrap authority or its
build inputs. Bootstrap permanently stops once the active descriptor exists.

Keep Rust suitable for reuse outside this deployment. Account names, repository
identities, GitHub App identities, branch names, capabilities, trusted actors, and
sensitive-path exceptions belong in deployment configuration (`policy.json` and
`repo-settings/`), not Rust defaults. See `docs/configuration.md` and
`docs/policy.example.json`.

## Repository settings ownership and least privilege

`repo-settings.yml` owns repository configuration and periodically reconciles it
with the desired settings using its existing dedicated administrator credential.
This includes protection rulesets and bypass actors, native merge settings, and
immutable-release enablement.

Do not add repository-settings preflights to PR creation, approval, merge, runtime
publication, control activation, or bootstrap/repair operations. Do not request
Server App `Administration: read` or `Administration: write`, broaden token scope,
or inject administrator credentials into these operations to inspect those
settings. Possible configuration drift between reconciliation runs does not
justify expanding their privileges. This rule also applies to shared helpers and
new workflows. If an operation fails because such a settings read lacks
permission, remove the unnecessary dependency rather than asking for more access.

Keep settings inspection and repair in the repository-settings management flow;
separate manual settings changes require explicit user authorization. Preserve
operation-specific validation of actor identity, owner approval, exact PR head,
required CI, provenance, and the actual published release's immutable state. These
checks do not justify querying administrative configuration in normal operations.

## Read before changing a flow

- `README.md` describes current operation and credentials.
- `CONTEXT.md` defines domain terms.
- `docs/merging.md`, `docs/client-releases.md`, and `docs/repo-settings.md`
  define the approval/merge, release, and settings contracts.
- `docs/client-action.md` documents the client Action and request protocol.
- `docs/migration.md` and `docs/adr/` explain runtime promotion and rollout.
- `docs/testing.md` and `docs/integration-testing.md` define candidate testing.
- `docs/deployment-verification-2026-10-11.md` records dated deployment evidence;
  historical reports do not certify later changes.

Update the corresponding contract when behavior changes. Reuse existing Rust
helpers and keep the change focused; do not add speculative abstractions.

## Security invariants

- Fail closed at trust boundaries. Validate repository and actor identities,
  capabilities, source workflow/run provenance, artifact identity and contents,
  signatures, and the active control identity before privileged writes.
- Bind owner commands, reviews, policy results, and mutations to the accepted PR
  head and full active control identity. Reject stale heads, changed control
  revisions, and replayed requests; preserve expected-head checks.
- `trusted_committers` alone does not exempt sensitive paths. Exemptions require
  the configured author and every effective committer to match; retain all other
  signature, provenance, approval, and required-check conditions.
- Treat client source, artifacts, configuration, and hooks as untrusted inputs.
  Preserve archive bounds and rejection of traversal, symlinks, and duplicates.
- Isolate build, signing, and publication credentials. Never execute client build
  hooks in jobs with signing or publishing credentials. Never log secret values.
- Keep repository-scoped installation tokens and the candidate sandbox. Never
  give a candidate production write tokens, personal approval tokens, or keys.
- Ordinary operations read `control/active.json` from protected main, load the
  source-bound, attested published runtime named by that descriptor, and use
  `.github/actions/install-cli` to put it on PATH. The descriptor's policy
  digest is checked against the policy bundled with that runtime; ordinary
  operations do not substitute the live `policy.json` from main. A missing or
  invalid descriptor or release must stop execution; do not introduce a build
  fallback or unverified binary.
- Treat a control activation as a new protected-main revision. The descriptor
  records its generation, source SHA, policy and archive digests, immutable
  release and asset IDs, publisher and scratch-verification run IDs, and the
  previous descriptor identity. Its identity is the SHA-256 of its canonical
  serialized fields. Candidate publication alone never changes active control.
- Publish normal candidates through the currently active published controller. The
  candidate executable and build artifact never receive production write
  credentials. Keep any release-writing token in the trusted host publisher
  step and never expose it to candidate code. The one-time initial publication
  uses only the separately reviewed fixed `control-bootstrap.yml` authority. Its
  host-side qualification is read-only, and its separate writer does not execute the
  candidate binary.
  After publication and scratch verification, propose a signed descriptor PR, then
  merge it only through the separately dispatched owner, expected-main, exact-head,
  descriptor-identity, and required-CI fence.
- Protected-main mutation workflows use the shared `securefix-control`
  concurrency group with `queue: max`. Do not add a ruleset bypass actor or
  mode beyond the exact Server App pull-request bypass required by the
  controlled merge rulesets. Do not use that ruleset entry outside the
  validated server Actions lane or add direct Contents API writes, native
  auto-merge, or another path that avoids the lane. Every accepted owner
  command and completion marker carries both the exact PR head and full control
  identity.
- Caller migration is restricted to exact generated workflows in a reviewable
  server-owned PR. Preserve ownership, exact-file, expected-head, and resulting
  default-branch checks. Distribution must not merge caller PRs automatically.
- Release publication requires immutable releases and validates final immutable
  state. Preserve merged-release-PR identity and idempotent recovery checks.

## Validation and evidence

Run the tests relevant to a change first. Run the standard checks once after the
changes are assembled; avoid repeating successful checks without a new change or
unresolved concern:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Use the repository's pinned toolchain and the CI workflow's actionlint command.
Workflow pins need full SHAs and verifiable version comments. Preserve the
existing actionlint exceptions for supported GitHub workflow syntax.
Documentation-only changes need link and accuracy checks plus required CI, not
new test suites or a repeat of unchanged live scenarios.

For behavioral changes, verify a reviewed candidate in the configured
`testing-securefix-server` scratch repository before promotion. Candidate binaries
come from immutable build artifacts; candidate tests do not need a runtime
release. Follow the documented prepare/verify phases and reuse their exact
candidate and fixture artifacts. Exercise affected success and rejection paths.
For release changes, use the release-PR/provider rehearsal workflows and inspect
checks and uploaded assets. Do not use production merges as experiments.

Save the candidate/source SHA, run URLs, exact-head review/check results, and
relevant artifact or release evidence. Distinguish tested behavior from code
inspection and from unverified behavior. Never claim success based only on
fixture creation, PR creation, or a passing unrelated check. If a test fails,
inspect the cause before retrying or modifying production state. Do not hide a
failed normal flow behind a manual alternative publication.

## Promotion and maintenance

After review and candidate verification where relevant, use the normal approval
and merge flow. `/approve` and `/merge` must be posted only within existing user
authorization; they are exact-head commands, not arbitrary bypasses. Existing
authorization permits an agent to post them without asking the user to do it.

Ordinary protected-main changes do not activate a new runtime. The active
published runtime and its bundled policy digest remain in force until a reviewed
activation PR advances `control/active.json`. Runtime publication is a separate
step and does not automatically distribute callers. After activation, explicitly
dispatch distribution for the verified publisher run and review the resulting
caller PRs. Use SemVer tags `vX.Y.Z`; prereleases use `vX.Y.Z-pre.N`. Never
overwrite a published version or fabricate release provenance.

The first protected-main code PR has an explicit permanent-settings gate. Before it
merges, an owner must approve and complete removal of Renovate bypass from all nine
controlled-merge rulesets (retaining only the Server App `pull_request` bypass),
disable native auto-merge and confirm no queued requests, and enable immutable
releases for the server. The deployed v0.2.20 runtime cannot apply these changes;
use the repository administrator UI or API. Do not use a temporary exception.

The one-time bootstrap is handled only by the reviewed fixed `control-bootstrap.yml`
workflow. Its source-pinned `securefix-bootstrap` Rust binary performs host-side
qualification before a verified active runtime exists for the first migration. It treats the
candidate archive as data and never executes its binary. It publishes only the verified
initial archive and never runs again after generation one. A later normal successor may select that same archive for rollback
using its recorded bootstrap publisher run and fixed signer path; other generations
use the normal publisher. There is no fallback runtime.
After generation one is required, a missing or invalid descriptor disables operations
until a valid control revision is restored. Publish and propose first, obtain owner
review of the exact descriptor PR, then separately dispatch merge with owner,
expected-main SHA, exact PR head, full descriptor identity, and required CI checks.
Every job that mints a Server App token uses the protected `main` environment. The
bootstrap scratch rehearsal uses a pinned v0.2.20 read baseline because the current
main runtime cannot validate its own initial bootstrap producer. In that rehearsal the
candidate prepares and verifies scratch fixtures, while the source-pinned fixed Rust
bootstrap host validates the bounded output files and their source, fixture, and
control-generation bindings. The legacy runtime's ordinary output validator requires
its own source on main and cannot validate the post-merge bootstrap rehearsal.
This baseline does not replace the fixed helper's qualification or establish
production publication.

While `control/active.json` is absent, dispatch the `CI` workflow on a signed repair
branch and wait for its required `status-check` before `repair-propose`; arbitrary
repair branches do not receive CI automatically. `repair-propose` checks the exact
expected main, signed repair head, successful required checks, and allowed paths before
the Server App opens a PR. Owner review happens after PR creation. `repair-merge`
requires the latest owner review on that exact PR head, repeats the checks, and merges
with expected-head CAS. The repair lane rejects changes to `control/active.json`,
all `.github/` workflow/action definitions, Rust authority modules and their dependency/build inputs.
Only package-version advances are permitted in `Cargo.toml` and `Cargo.lock`; all
other contents must remain identical. A defect
in the bootstrap authority needs a separately reviewed recovery; the bounded
repair lane cannot rewrite its own trust root. Repair does not restore old-runtime
availability and permanently stops once generation one exists.

The bootstrap workflow, initial activation and failure handling remain unverified.
Before merging the first code PR, compile the implementation, pass the normal candidate
scratch verification on a frozen integration branch, review the fixed bootstrap path and
operator procedure, and explicitly approve and complete the permanent live-settings
rollout. The protected-main `phase=bootstrap` scratch gate cannot run before that merge;
after the first code PR merges, it must pass during the finite pause before bootstrap
publication or descriptor activation is proposed. The old v0.2.20 runtime is only
expected to remain available before the first protected-main advance; no availability
claim applies after the first code PR merges. No production settings changes are
authorized by the proposal.

Renovate remains a PR author. Native Renovate auto-merge is incompatible with
the sole-controller model and is removed. Non-major and lockfile PRs now require
an explicit owner `/merge` command after required checks; major updates also
remain explicit. Do not add overlapping Dependabot version-update
configuration.

Keep completion reports precise: what changed, what passed, and any remaining
unverified condition. Reuse saved evidence and clean up disposable test fixtures.
