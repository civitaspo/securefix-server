# securefix-server

Privileged OSS automation for civitaspo repositories, based on the client/server trust model of [csm-actions/securefix-action](https://github.com/csm-actions/securefix-action).
The Rust `securefix` executable owns approval, merge, release, settings, and request validation.
GitHub Actions workflows route events, load the verified prebuilt executable, isolate credentials, and call its commands.

Protected-main commits do not activate a runtime. `control/active.json` selects the published runtime and policy snapshot used by ordinary operations; its descriptor records `version`, `generation`, `source_sha`, `policy_sha256`, `archive_sha256`, `release_id`, `asset_id`, `publisher_run_id`, `verification_run_id`, and `previous`.
The full control identity is the SHA-256 digest of the canonical serialized descriptor.
The active runtime checks its source and bundled policy against this descriptor. It does not load the live `policy.json` from main.
The proposed activation workflow takes the candidate source SHA, publisher run ID, scratch-verification run ID, and expected full active control identity. Normal activations verify publication and scratch evidence before opening a signed descriptor PR. An owner reviews it, then a separate dispatch merges only after rechecking the expected main SHA, exact PR head, descriptor identity, and required CI through the Actions lane. Publication alone does not activate or distribute the candidate.
After activation, the owner explicitly dispatches `Distribute Runtime` for the verified publisher run and reviews the caller PRs.
Callers with the previous pin pause until their generated migration is merged; server-side distribution can complete those migrations without invoking the old caller workflows.
Ordinary operations load the attested release named by the active descriptor and fail closed if verification fails.
See [ADR 0009](docs/adr/0009-active-control-revision.md) for the lifecycle and bootstrap constraint.
Execution jobs use one `install-cli` composite action to install the executable with mode `755` on `PATH`; trusted runtime data stays under `runner.temp`.

## Policy and trust

[`policy.json`](policy.json) grants named operations to exact repositories and defines sensitive paths.
Approval, merge, and release requests must originate from the configured Client App and a successful first-attempt workflow run; the active control revision validates the request and its full control identity.
Client wrappers pin the active runtime source SHA, and older runtime sources are rejected.
Ordinary server commits do not change caller pins; activation and the explicit distribution that follows update them.

Owner commands `/approve` and `/merge` bind authorization to the PR head observed at intake and the full active control identity.
All source commits need verified signatures and an allowed committer.
Sensitive changes need owner authorization for that exact head unless the author and every effective committer satisfy a configured `sensitive_path_approval_exemptions` entry.
The current policy exempts the Renovate App; membership in `trusted_committers` alone does not grant that exemption.
Signature, source, current-head approval, and merge checks still apply.
The server publishes `securefix-policy-check` from the Server App; an approval for an earlier head cannot satisfy it for an updated head.
The sole-controller model disables native Renovate automerge. Non-major and lockfile Renovate PRs require an explicit owner `/merge` command after the normal checks; major updates also remain explicit.

Rust owns the client artifact protocol, source validation, signed commits and pull requests.
Repository capabilities in policy.json are the only Securefix allowlist.
Client CI fixes its own non-default branch. A pinned release workflow can update a non-default release branch in the same repository.
Artifact extraction rejects unsafe paths, symlinks, duplicate files and oversized content.
Every repair uses a verified GitHub-signed commit and an expected-head comparison before updating its destination. A newer head invalidates a same-branch fix.
Caller distribution commits generated workflows on the configured update branch and opens or updates reviewable PRs after an explicit dispatch for an activated runtime.
This managed-workflow path does not grant ordinary PRs an exemption from approval or required checks.
The [native protocol decision](docs/adr/0008-native-securefix.md) replaces the upstream implementation decision.

## Operations

| Operation | CLI | Contract |
| --- | --- | --- |
| Approve | `request`, `approve` | [Approval and merge](docs/merging.md) |
| Merge | `request`, `merge`, `check` | [Approval and merge](docs/merging.md) |
| Release | `release` | [Client releases](docs/client-releases.md) |
| Settings | `settings` | [Settings and activation](docs/repo-settings.md) |
| Signed fixes | `securefix` | [Migration](docs/migration.md) |
| Runtime control | `runtime`, `distribute`, `control` | [Active control revision](docs/adr/0009-active-control-revision.md) |

Provider releases use a secret-free fixed build, a GPG-only signer, and a publisher with a repository-scoped contents token.
Publication requires immutable releases to be enabled and verifies the published release's immutable state.
Client release configuration and hooks never run in signing or publishing jobs.
Manual release retries identify a verified merged release PR, rather than an arbitrary commit SHA.
Scheduled settings reconciliation cannot create or reactivate merge restrictions.

## Credentials

The existing `main` environment holds these secrets:

| Secret | Use |
| --- | --- |
| `SECUREFIX_SERVER_PRIVATE_KEY` | Narrow Server App tokens for reads, checks, commits, merges, publication, and activation |
| `SECUREFIX_CLIENT_PRIVATE_KEY` | This repository's client request labels |
| `CIVITASPO_BOT_PR_APPROVE_TOKEN` | Reviews as `civitaspo-bot`; its identity and non-author status are checked |
| `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` | Dedicated administrator credential for `repo-settings.yml` reconciliation only |
| `CIVITASPO_BOT_REPO_INVITE_TOKEN` | Optional acceptance of the bot's collaborator invitation |
| `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY` | Provider checksum signing only |
| `TERRAFORM_PROVIDER_GPG_PASSPHRASE` | Provider checksum signing only |

The Server App ID is `3872533`; the Client App ID is `3872492`.
Clients provide only `SECUREFIX_CLIENT_PRIVATE_KEY` to the reusables.
The server's approve and merge callers also pass that secret by name.
The capture job receives its value from the protected `main` environment; the explicit mapping satisfies the reusable workflow's required-secret contract before that job starts.
`civitaspo-bot` must retain write collaborator access for its reviews to count.
The operation documents list the required App permissions.

## Dependency updates

[`renovate.json`](renovate.json) manages dependency updates using signed platform commits.
Non-major updates and lockfile maintenance require an explicit owner `/merge` command after required checks; major updates also remain explicit.
Renovate does not merge its own PRs, and native Renovate auto-merge is not enabled.
Dependabot version-update configuration has been removed. Dependabot vulnerability alerts are a separate repository setting.

## Development and rollout

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

CI also runs pinned actionlint and structural workflow tests.
The [candidate integration harness](docs/integration-testing.md) builds a reviewed candidate without secrets and exercises its writes only against `testing-securefix-server`, without publishing a runtime Release.
The active-control implementation merged in [PR #94](https://github.com/civitaspo/securefix-server/pull/94), after candidate scratch verification and the approved permanent settings rollout. The Server App is the sole pull-request bypass actor, native auto-merge is disabled, and server immutable releases are enabled. The first protected-main `phase=bootstrap` scratch gate failed; bootstrap publication and descriptor activation remain unverified. While `control/active.json` is absent, ordinary operations and scheduled settings reconciliation stop at the runtime loader. The bounded repair attempt also failed before opening a qualified PR. Its bootstrap workflow and helper need separately reviewed recovery; the repair lane cannot rewrite either authority file. The current repair removes unnecessary Administration settings reads and separates scratch probe phases. See the [dated verification report](docs/control-revision-verification-2026-10-16.md) for exact runs and remaining conditions, and [ADR 0009](docs/adr/0009-active-control-revision.md) for the bootstrap gates. No temporary ruleset exception or direct protected-main write is part of this repair.
The [initial Rust GitHub verification](docs/github-verification-2026-10-08.md) records the earlier pre-deployment API probes.
See [migration and rollout](docs/migration.md), the [domain glossary](CONTEXT.md), and [architecture decisions](docs/adr/).
The [previous GitHub verification](docs/archive/merge-verification-2026-10-08.md) is historical evidence for the former implementation.

Deployment identities and branch names are configured in [policy.json](policy.json); see [deployment configuration](docs/configuration.md) and the [organization example](docs/policy.example.json). The Rust runtime has no account or GitHub App defaults.
