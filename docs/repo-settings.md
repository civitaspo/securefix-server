# Repository settings reconcile

Thin GitHub Actions workflow that applies shared repository settings to `civitaspo` OSS repos with `gh`.

- Workflow: [`.github/workflows/repo-settings.yml`](../.github/workflows/repo-settings.yml)
- Desired state: [`repo-settings/`](../repo-settings/)

## What is reconciled

| File | API |
| --- | --- |
| [`repository.json`](../repo-settings/repository.json) | `PATCH /repos/{owner}/{repo}` (merge options) |
| [`rulesets/default-branch.json`](../repo-settings/rulesets/default-branch.json) | Upsert repository ruleset by fixed `.name` (`PUT` if present, else `POST`). Full body replace — include anything you want kept (for example `bypass_actors`) |
| [`collaborator.json`](../repo-settings/collaborator.json) | Invite collaborator (`push`); optional Accept via bot PAT (token must authenticate as that user) |

Not managed here: Securefix Apps, secret values, Renovate, client workflow wrappers, `release-clients.yaml`. Other rulesets under different names (for example legacy `Protect main` or per-repo status checks) are left alone — delete or rename them manually if you want a single ruleset.

The shared ruleset requires 1 approving review. Solo merges rely on a second actor (typically `civitaspo-bot` via Securefix). Add `bypass_actors` in the JSON if you need an explicit human/admin bypass.

## Allowlist

Exact repository names under `civitaspo` live in [`repo-settings/allowlist.json`](../repo-settings/allowlist.json). Names must match `^[a-zA-Z0-9._-]{1,100}$` and be unique. Adding a name there makes the daily schedule keep reconciling it (one matrix job per repo).

## Triggers

| Trigger | Behavior |
| --- | --- |
| `schedule` (daily) | Reconcile every allowlisted name (matrix) |
| `workflow_dispatch` with empty `repository` | Same as schedule |
| `workflow_dispatch` with `repository` | Configure that one repo; only if `create_if_missing` is explicitly true and the repo is absent, `gh repo create civitaspo/<name> --public` first |

`create_if_missing` defaults to **false** so a typo does not create a public repo. Dispatch does **not** edit the allowlist for you. After creating a new OSS, add the name to `allowlist.json` in a PR if schedule should cover it.

## Secrets (`main` environment)

Checked once in the `prepare` job before the matrix runs.

| Secret | Required | Purpose |
| --- | --- | --- |
| `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` | yes | classic PAT as **civitaspo** with `public_repo` (create / administer public target repos) |
| `CIVITASPO_BOT_REPO_INVITE_TOKEN` | no | classic PAT as **civitaspo-bot** with `repo:invite` only, to accept invitations |

Bot-owned PATs use the `CIVITASPO_BOT_*` prefix (the Securefix approver is `CIVITASPO_BOT_PR_APPROVE_TOKEN` on the same environment).

Actions `GITHUB_TOKEN` cannot configure other repositories, so a PAT (or equivalent) is required.

Protect the `main` environment: required reviewers and deployment branches limited to the default branch, so `workflow_dispatch` from a fork/feature branch cannot use these secrets with a rewritten workflow.

## New OSS setup

1. Run **Repo settings** → `workflow_dispatch` with the new repository name and `create_if_missing: true` (explicit).
2. PR: add the name to [`repo-settings/allowlist.json`](../repo-settings/allowlist.json) (for schedule).
3. If the repo will publish: add [`release-clients.yaml`](../release-clients.yaml) (`repository` + `publish`).
4. Install Securefix server/client Apps, set `SECUREFIX_CLIENT_PRIVATE_KEY`, add client wrappers, enable Renovate — see [client-releases.md](client-releases.md).

Settings-only repos (for example `dotfiles`) need steps 1–2 (and App/bot as needed), not release allowlist.

## Manual checklist

- [ ] `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` on `main`
- [ ] `main` environment: required reviewers + default-branch-only deployments
- [ ] Optional bot invite Accept token
- [ ] Securefix Apps + client secret + wrappers + Renovate
- [ ] If invite stays pending, accept as the collaborator user once
