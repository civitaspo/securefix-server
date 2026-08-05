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

Trusted authors: `civitaspo`, `civitaspo-securefix-server[bot]`, `renovate[bot]`, `dependabot[bot]`. You can also comment `/approve` as `civitaspo`.

Client configuration on this repository:

- Repository variable `SECUREFIX_CLIENT_APP_ID` (shared Securefix client app)
- `main` environment secret `SECUREFIX_CLIENT_PRIVATE_KEY` (Approve Request selects `environment: main`)

Server-side approval still needs `PR_APPROVE_GITHUB_ACCESS_TOKEN` on the `main` environment, plus `SECUREFIX_SERVER_APP_ID` / `SECUREFIX_SERVER_PRIVATE_KEY`. `civitaspo-bot` must remain a write collaborator so its approvals count toward the ruleset.

## Securefix client workflows

The Securefix server accepts requests only from the `Lint` and `Release PR` client workflows. Requests from other workflow names are denied before a commit is created.

Clients may request an allowed destination branch, including `release/next`, within `civitaspo/*` repositories. The server validates these requests with `securefix-config.yaml`. Commit messages supplied by clients are honored; the server does not override them.

## Terraform provider releases

The `Release Terraform Provider` workflow handles `release-tf-provider-*` labels whose description is `civitaspo/terraform-provider-sigma/<workflow-run-id>/<tag>/<merge-sha>`. The referenced run must be a successful (or still in-progress) `Release Tag` workflow run, and its tag must be a semantic version such as `v1.2.3`.

The server validates the workflow run through the GitHub API, checks out the requested tag with a short-lived server GitHub App installation token, verifies that the tag matches the expected merge commit and is contained in `main`, imports the provider signing key, and runs GoReleaser v2.17.0.

`Release Tag` runs on `pull_request` closed events tag the squash-merge commit on `main`, while `workflow_run.head_sha` is the PR head (`release/next`). The preferred label description therefore includes the tagged merge commit SHA. When the SHA is omitted, the server resolves it from the merged `release/next` → `main` pull request associated with the run's head commit (for `pull_request` events) or uses `head_sha` (for `workflow_dispatch`).

The `main` environment must provide `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY` and `TERRAFORM_PROVIDER_GPG_PASSPHRASE`. The Securefix server app variable and private-key secret must also be available to this workflow. The server GitHub App needs `actions: read`, `contents: write`, and `pull_requests: read` access to `civitaspo/terraform-provider-sigma`.

The release request label description must be `owner/repo/run_id/tag/sha` (for example `civitaspo/terraform-provider-sigma/123/v0.1.0/<40-char-sha>`). The server accepts in-progress `Release Tag` workflow runs so the client can request a release before its own job finishes.
