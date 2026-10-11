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
  signatures, and current runtime revision before privileged writes.
- Bind owner commands, reviews, policy results, and mutations to the accepted PR
  head. Reject stale heads and replayed requests; preserve expected-head checks.
- `trusted_committers` alone does not exempt sensitive paths. Exemptions require
  the configured author and every effective committer to match; retain all other
  signature, provenance, approval, and required-check conditions.
- Treat client source, artifacts, configuration, and hooks as untrusted inputs.
  Preserve archive bounds and rejection of traversal, symlinks, and duplicates.
- Isolate build, signing, and publication credentials. Never execute client build
  hooks in jobs with signing or publishing credentials. Never log secret values.
- Keep repository-scoped installation tokens and the candidate sandbox. Never
  give a candidate production write tokens, personal approval tokens, or keys.
- Ordinary operations load the source-bound, attested published runtime and use
  `.github/actions/install-cli` to put it on PATH. A missing or invalid release
  must stop execution; do not introduce a build fallback or unverified binary.
- Automatic caller migration is restricted to exact generated workflows in the
  validated server-owned PR. Preserve ownership, exact-file, expected-head, and
  resulting-default-branch checks; do not extend this bypass to ordinary PRs.
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

Every protected-main revision, including documentation-only revisions, needs a
matching source-bound runtime release before ordinary operations resume. Update
`Cargo.toml` and the package entry in `Cargo.lock` consistently when preparing a
new publication. Use SemVer tags `vX.Y.Z`; prereleases use `vX.Y.Z-pre.N`. Do not
publish a release for each test candidate or intermediate SHA.

Run `Publish Runtime` on protected main only after its revision is ready for
promotion. A successful publication automatically triggers `Distribute Runtime`
for callers configured in policy. Confirm publication and all caller jobs rather
than manually merging generated caller updates or weakening required checks.
For recovery, follow `docs/migration.md` and retry the successful publisher run;
never fabricate release provenance or repoint an existing version tag.

Renovate manages dependency updates. Keep signed platform commits, non-major
updates and lockfile maintenance eligible for checked automerge, and major
updates manual. Do not add overlapping Dependabot version-update configuration.

Keep completion reports precise: what changed, what passed, and any remaining
unverified condition. Reuse saved evidence and clean up disposable test fixtures.
