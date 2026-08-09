# securefix-server

Securefix Action server repository for `civitaspo` repositories.

This repository is built around [`csm-actions/securefix-action`](https://github.com/csm-actions/securefix-action). Thank you to the maintainers for providing the client/server workflow used here.

The server workflow receives Securefix client requests through `securefix-*` label events and creates signed fix commits with the server GitHub App.

## Required configuration

Create a GitHub App for the server and install it into this repository and the client repositories.

Repository variables and secrets:

- Variable `SECUREFIX_SERVER_APP_ID`
- Secret `SECUREFIX_SERVER_PRIVATE_KEY`

The server app needs these permissions:

- `contents: write`
- `actions: read`
- `pull_requests: write`
- `workflows: write`

`workflows: write` is required because the current client use case fixes files under `.github/workflows`.

## Repository hardening

The repository intentionally keeps only the features needed by Securefix:

- Issues: enabled, because Securefix uses repository labels.
- Pull requests: enabled for repository maintenance.
- Projects, wiki, discussions, and downloads: disabled.
- Main branch: protected by ruleset, requiring signed commits, linear history, pull requests, status checks, and blocking deletion and force pushes.
- Security features: secret scanning, push protection, private vulnerability reporting, and Dependabot security updates are enabled.

## Pull request approval

Pull requests **to this repository** are auto-requested for approval by the `Approve Request` workflow (same CSM client pattern as other civitaspo repos). It creates an `approve-pr-*` label; the `Approve Pull Request` workflow then approves with the machine-user PAT.

Trusted authors / committers (single policy, shared with client reusables): `civitaspo`, `cursoragent`, `civitaspo-securefix-server[bot]`, `renovate[bot]`, `dependabot[bot]`. You can also comment `/approve` as `civitaspo`.

Client configuration on this repository:

- `main` environment secret `SECUREFIX_CLIENT_PRIVATE_KEY` (this repository's Approve Request stays inline with `environment: main`; client repos call `reusable-approve-request.yml` with a repository secret instead)

Server-side approval still needs `PR_APPROVE_GITHUB_ACCESS_TOKEN` on the `main` environment, plus `SECUREFIX_SERVER_APP_ID` / `SECUREFIX_SERVER_PRIVATE_KEY`. `civitaspo-bot` must remain a write collaborator so its approvals count toward the ruleset.

## Securefix client workflows

The Securefix server accepts requests only from the `Lint` and `Release PR` client workflows. Requests from other workflow names are denied before a commit is created.

Clients may request an allowed destination branch, including `release/next`, within `civitaspo/*` repositories. The server validates these requests with `securefix-config.yaml`. Commit messages supplied by clients are honored; the server does not override them.

## Client releases

Privileged publish runs only in this repository (`environment: main`). Clients call reusable workflows defined here, create an annotated tag, and open a `release-request-*` label; the server validates against [`release-clients.yaml`](release-clients.yaml) and publishes.

**Full specification:** [docs/client-releases.md](docs/client-releases.md) (architecture, label contract, allowlist, reusables, onboarding, approval policy).

Quick facts:

- Allowlist gate: exact `owner/repo` entries in `release-clients.yaml` (no wildcards); add via PR to this repo
- Label: `release-request-<run_id>-<tag>` with description `owner/repo/run_id/tag/sha`
- Clients pin `reusable-release-*.yml` / `reusable-approve-request.yml` by commit SHA (Renovate bumps)
- Client secret required: `SECUREFIX_CLIENT_PRIVATE_KEY` only (App ID and server name are hardcoded in the reusables)
- Caller jobs must grant the `permissions` scopes the reusable jobs request (see the doc)
