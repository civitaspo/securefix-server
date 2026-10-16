# Agent instructions

## Purpose and architecture

This repository is a privileged GitHub automation server. Preserve its security
boundaries when changing approval, merge, repair, release, or repository settings.
The Rust `securefix` CLI owns validation and business logic. Workflows orchestrate
events, verified runtime loading, credential isolation, and CLI invocation; keep
shell steps limited to this orchestration. Do not restore upstream Securefix
Actions or implement policy decisions in Bash, Python, or github-script.

Keep Rust suitable for reuse outside this deployment. Account names, repository
identities, GitHub App identities, branch names, capabilities, trusted actors, and
sensitive-path exceptions belong in deployment configuration (`policy.json` and
`repo-settings/`), not Rust defaults. See `docs/configuration.md` and
`docs/policy.example.json`.

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
- Publish candidates through the currently active published controller. The
  candidate executable and build artifact never receive production write
  credentials. Keep any release-writing token in the trusted host publisher
  step and never expose it to candidate code. After publication and scratch
  verification, an owner-dispatched active-controller command may open a signed
  activation PR. The owner reviews and merges that PR through the normal server
  Actions lane.
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

The first activation is a bootstrap boundary. The currently deployed v0.2.20
loader accepts only its exact pinned workflow provenance and policy, and it
cannot publish a different version. The current publisher uses a production
contents-write token that can also update repository content. A proposed main
revision is therefore not a safe migration path by itself: do not merge it as
though the old runtime can remain operative, and do not treat a post-merge
recovery as a completed safe transition. Keep the proposal unmerged until a
separately trusted bootstrap publication path is established and reviewed.

Renovate remains a PR author. Native Renovate auto-merge is incompatible with
the sole-controller model and is removed. Non-major and lockfile PRs now require
an explicit owner `/merge` command after required checks; major updates also
remain explicit. Do not add overlapping Dependabot version-update
configuration.

Keep completion reports precise: what changed, what passed, and any remaining
unverified condition. Reuse saved evidence and clean up disposable test fixtures.
