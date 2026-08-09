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

Privileged publish runs only in this repository (`environment: main`). Clients create an annotated tag and open a `release-request-*` label; the server validates and publishes.

### Label contract

- Label name: `release-request-<run-id>-<tag>` (for example `release-request-123-v1.2.3`)
- Description: `owner/repo/run_id/tag/sha` (preferred), or without the trailing merge SHA when the description would exceed GitHub's 100-character limit
- Referenced run must be a `Release Tag` workflow that is queued, in progress, or completed successfully
- Tag must be a semantic version such as `v1.2.3`, point at the expected merge commit, and be an ancestor of `main`

### Publish allowlist

[`release-clients.yaml`](release-clients.yaml) is the only gate for which repositories may publish. Each entry has:

- `repository`: exact `owner/repo` (no wildcards)
- `publish`: `github-release` or `goreleaser`

Repositories not listed are denied and the request label is deleted. Go / GoReleaser versions are workflow constants (pinned; not floating `latest`).

For `goreleaser`, the `main` environment must provide `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY` and `TERRAFORM_PROVIDER_GPG_PASSPHRASE`. The server GitHub App needs `actions: read`, `contents: write`, and `pull_requests: read` on each allowlisted client.

### Reusable client workflows

Client repositories should call these reusables with a **commit SHA pin** (bump via Renovate):

| Workflow | Purpose |
| --- | --- |
| `reusable-release-pr.yml` | git-cliff bump; sync `dbt_project.yml` / `pyproject.toml` when present; open `release/next` via Securefix |
| `reusable-release-tag.yml` | annotated tag + `release-request-*` label (fork PRs rejected) |
| `reusable-release-pr-sync.yml` | keep open `release/next` PR title/body in sync |
| `reusable-approve-request.yml` | request server-side PR approval |

App ID and server repository name are hardcoded in the reusables (`3872492`, `securefix-server`). Clients only need the repository secret `SECUREFIX_CLIENT_PRIVATE_KEY`.

Thin wrapper example:

```yaml
name: Release Tag

on:
  pull_request:
    types:
      - closed
  workflow_dispatch:
    inputs:
      merge_sha:
        description: Commit SHA to tag (defaults to main HEAD when empty)
        required: false
        type: string

permissions: {}

concurrency:
  group: release-tag-${{ github.event.pull_request.number || github.run_id }}
  cancel-in-progress: false

jobs:
  tag:
    uses: civitaspo/securefix-server/.github/workflows/reusable-release-tag.yml@<sha>
    with:
      merge_sha: ${{ inputs.merge_sha }}
    secrets:
      SECUREFIX_CLIENT_PRIVATE_KEY: ${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}
```

mise **CLI** is pinned inside the reusable; tool versions come from each client's `mise.lock`.

### Onboarding a new client

1. Add an explicit entry to [`release-clients.yaml`](release-clients.yaml) (`repository` + `publish`) and merge that PR.
2. Install the Securefix **server** and **client** GitHub Apps on the client repository.
3. Add thin wrappers that call the four reusables above, pinned to a securefix-server commit SHA.
4. Configure repository secret `SECUREFIX_CLIENT_PRIVATE_KEY` only (no `SECUREFIX_CLIENT_APP_ID` / `SECUREFIX_SERVER_REPOSITORY` / approve policy vars).
5. Enable Renovate (or equivalent) so the reusable SHA pins stay current.
