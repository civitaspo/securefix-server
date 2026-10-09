# securefix-server

Privileged OSS automation for civitaspo repositories, based on the client/server trust model of [csm-actions/securefix-action](https://github.com/csm-actions/securefix-action).
The Rust `securefix` executable owns approval, merge, release, settings, and request validation.
GitHub Actions workflows route events, load the verified prebuilt executable, isolate credentials, and call its commands.

After staging succeeds, the owner manually runs `Publish Runtime` on protected `main` to publish `securefix-runtime-<full-SHA>`.
Successful publication starts the server default-head Policy Check and opens or updates signed runtime migration PRs in the configured callers.
Review and merge those PRs through the [upgrade maintenance procedure](docs/migration.md#subsequent-server-upgrades).
Intermediate commits and test candidates do not create Releases.
`Load CLI` downloads that exact release and verifies its archive against the server SHA and publishing workflow's GitHub attestation before extraction.
It transfers the verified runtime to execution jobs using an immutable same-run artifact ID.
Normal operations never compile Rust; a missing release or failed verification stops the operation.
See the [runtime distribution decision](docs/adr/0006-prebuilt-runtime.md) for provenance and retry behavior.
Execution jobs use one `install-cli` composite action to install the executable with mode `755` on `PATH`; trusted runtime data stays under `runner.temp`.

## Policy and trust

[`policy.json`](policy.json) grants named operations to exact repositories and defines sensitive paths.
Approval, merge, and release requests must originate from the configured Client App, a successful first-attempt workflow run, and the current server revision.
Client wrappers pin a full server commit SHA; older ancestors are rejected.
Every server commit therefore requires client pin updates.

Owner commands `/approve` and `/merge` bind authorization to the PR head observed at intake.
All source commits need verified signatures and an allowed committer.
Sensitive changes need owner authorization for that exact head.
The server publishes `securefix-policy-check` from the Server App; an approval for an earlier head cannot satisfy it for an updated head.
Ordinary Renovate automerge remains possible under the same required checks and stale-review dismissal.

Securefix uses pinned upstream `prepare`, `commit`, and `notify` actions for its artifact protocol and repair commits.
Rust validates the Client App event, exact repository capabilities, source workflow provenance, and destination scope between preparation and commit.
It accepts client `CI` and `Release PR` workflows and denies direct default-branch pushes.
The trusted [`securefix-config.yaml`](securefix-config.yaml) permits the fixed release-capable clients on any branch name; it travels with the attested runtime outside the client artifact workspace.
PR CI fixes its own branch, and a trusted release-PR source can target any non-default branch in the same repository.
Securefix requests may come from a running or failed CI run because the client deliberately fails after dispatching a same-branch fix.
The separate runtime distribution route requires a successful server distribution run for a published current-main runtime.
It permits only generated caller workflows on `automation/securefix-runtime` and reuses one review PR per caller.
See the [runtime rollout decision](docs/adr/0007-published-runtime-rollout.md).
The [upstream integration decision](docs/adr/0005-upstream-securefix-protocol.md) records the accepted stale-artifact limitation and why approval remains in Rust.

## Operations

| Operation | CLI | Contract |
| --- | --- | --- |
| Approve | `request`, `approve` | [Approval and merge](docs/merging.md) |
| Merge | `request`, `merge`, `check` | [Approval and merge](docs/merging.md) |
| Release | `release` | [Client releases](docs/client-releases.md) |
| Settings | `settings` | [Settings and activation](docs/repo-settings.md) |
| Signed fixes | `securefix` | [Migration](docs/migration.md) |
| Runtime rollout | `runtime` | [Published runtime rollout](docs/adr/0007-published-runtime-rollout.md) |

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
| `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` | Repository administration as civitaspo |
| `CIVITASPO_BOT_REPO_INVITE_TOKEN` | Optional acceptance of the bot's collaborator invitation |
| `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY` | Provider checksum signing only |
| `TERRAFORM_PROVIDER_GPG_PASSPHRASE` | Provider checksum signing only |

The Server App ID is `3872533`; the Client App ID is `3872492`.
Clients provide only `SECUREFIX_CLIENT_PRIVATE_KEY` to the reusables.
The server's approve and merge callers also pass that secret by name.
The capture job receives its value from the protected `main` environment; the explicit mapping satisfies the reusable workflow's required-secret contract before that job starts.
`civitaspo-bot` must retain write collaborator access for its reviews to count.
The operation documents list the required App permissions.

## Development and rollout

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

CI also runs pinned actionlint and structural workflow tests.
The [scratch verification CI](docs/testing.md) builds a reviewed server revision in `testing-securefix-server` and transfers its executable by immutable same-run artifact ID, without publishing a Release.
The [Rust GitHub verification](docs/github-verification-2026-10-08.md) records PR CI, isolated live API checks, and the remaining deployment tests.
See [migration and rollout](docs/migration.md), the [domain glossary](CONTEXT.md), and [architecture decisions](docs/adr/).
The [previous GitHub verification](docs/archive/merge-verification-2026-10-08.md) is historical evidence; the Rust implementation still needs deployment validation before activation.
