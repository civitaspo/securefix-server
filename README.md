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

The `Approve Pull Request` workflow handles `approve-pr-*` label requests for pull requests whose committer is `civitaspo`, `renovate[bot]`, or `dependabot[bot]`.

Add the machine-user personal access token as the `PR_APPROVE_GITHUB_ACCESS_TOKEN` secret on the `main` environment. The workflow is expected to fail until that secret is configured; this repository does not create or store the token.

## Securefix client workflows

The Securefix server accepts requests only from the `Lint` and `Release PR` client workflows. Requests from other workflow names are denied before a commit is created.

Clients may request an allowed destination branch, including `release/next`, within `civitaspo/*` repositories. The server validates these requests with `securefix-config.yaml`. Commit messages supplied by clients are honored; the server does not override them.
