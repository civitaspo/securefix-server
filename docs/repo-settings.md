# Repository settings reconcile

Thin GitHub Actions workflow that applies shared repository settings to `civitaspo` OSS repos with `gh`.

- Workflow: [`.github/workflows/repo-settings.yml`](../.github/workflows/repo-settings.yml)
- Desired state: [`repo-settings/`](../repo-settings/)

## What is reconciled

| File | API |
| --- | --- |
| [`repository.json`](../repo-settings/repository.json) | `PATCH /repos/{owner}/{repo}` (merge options, including Always suggest updating pull request branches via `allow_update_branch`) |
| [`merge-controls.json`](../repo-settings/merge-controls.json) | Opt-in switch for disabling GitHub native auto-merge and enabling the controlled merge ruleset. It starts disabled. |
| [`rulesets/default-branch.json`](../repo-settings/rulesets/default-branch.json) | Upsert branch ruleset by fixed `.name` (`PUT` if present, else `POST`). Full body replace — include anything you want kept (for example `bypass_actors`). Requires the single CI job context `status-check` (clients collapse PR workflows into that gate) |
| [`rulesets/controlled-merges.json`](../repo-settings/rulesets/controlled-merges.json) | Upsert `controlled-merges` by fixed name when merge controls are enabled. It restricts updates to the default branch, with PR-only bypass for the Securefix Server and Renovate Apps. |
| [`rulesets/all-tags.json`](../repo-settings/rulesets/all-tags.json) | Upsert tag ruleset `all-tags` (`~ALL`, block deletion / force-push) for names in [`tags-allowlist.json`](../repo-settings/tags-allowlist.json). Also deletes legacy `Protect tags` if present |
| [`collaborator.json`](../repo-settings/collaborator.json) | Invite collaborator (`push`); optional Accept via bot PAT (token must authenticate as that user) |

Not managed here: Securefix App installation or permissions, secret values, Renovate update rules, client workflow contents, and `release-clients.yaml`. Other branch rulesets under different names (for example legacy `Protect main` or per-repo status checks) are left alone.

The shared `default-branch` ruleset requires one approving review and does not grant bypass. `controlled-merges` is separate because a bypass applies to every rule in a ruleset. Its only rule restricts updates, so Securefix and Renovate can merge pull requests without bypassing the existing CI, review, signature, or squash requirements.

Merge controls remain off while [`merge-controls.json`](../repo-settings/merge-controls.json) has `"enabled": false`. In that state, the workflow omits `allow_auto_merge` and creates no `controlled-merges` ruleset. If a prior rollout left that ruleset active, the workflow disables it. Before enabling the switch, validate both App installations and their permissions, including `actions: read` for the Securefix Server App. Also validate the real merge behavior, install the pinned merge-request workflow in every allowlisted repository, and clear all queued native auto-merge requests. The activation preflight checks every wrapper pin, required Actions variables, and client-key secret metadata. It rejects any missing value or queued request before the matrix changes settings. It never reads a secret value. GitHub's user-authenticated API cannot confirm the App installations or permissions, and the workflow cannot prove the result of a live merge test. The readiness input is an explicit human attestation of those checks.

To enable the controls, change `enabled` to `true` in a reviewed PR after completing the checks above. Then run **Repo settings** with an empty `repository` and `merge_controls_ready: true`. The workflow requires the full allowlist for this dispatch. It applies the restriction to each client repository in sequence and applies it to securefix-server last. Later scheduled runs keep reconciling the enabled state. To roll back, set `enabled` to `false` and run the workflow for all repositories. This disables the new ruleset. Restore `allow_auto_merge` separately only if the previous policy is needed.

## Allowlist

Exact repository names under `civitaspo` live in [`repo-settings/allowlist.json`](../repo-settings/allowlist.json). Names must match `^[a-zA-Z0-9._-]{1,100}$` and be unique. Adding a name there makes the daily schedule keep reconciling it (one matrix job per repo).

Tag immutability (`all-tags`) is limited to [`tags-allowlist.json`](../repo-settings/tags-allowlist.json) (must be a subset of the main allowlist — typically release-capable repos + this server).

## Triggers

| Trigger | Behavior |
| --- | --- |
| `schedule` (daily) | Reconcile every allowlisted name (matrix) |
| `workflow_dispatch` with empty `repository` | Same as schedule. When merge controls are enabled, set `merge_controls_ready: true` to run the activation preflight and apply the full rollout. |
| `workflow_dispatch` with `repository` | Configure that one repo; only if `create_if_missing` is explicitly true and the repo is absent, `gh repo create civitaspo/<name> --public` first |

`create_if_missing` defaults to **false** so a typo does not create a public repo. Dispatch does **not** edit the allowlist for you. After creating a new OSS, add the name to `allowlist.json` in a PR if schedule should cover it.

## Secrets (`main` environment)

Checked once in the `prepare` job before the matrix runs.

| Secret | Required | Purpose |
| --- | --- | --- |
| `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` | yes | classic PAT as **civitaspo** with `public_repo` (create / administer public target repos) |
| `CIVITASPO_BOT_REPO_INVITE_TOKEN` | no | classic PAT as **civitaspo-bot** with `repo:invite` only, to accept invitations |

Bot-owned PATs use the `CIVITASPO_BOT_*` prefix (the SecureFix approver is `CIVITASPO_BOT_PR_APPROVE_TOKEN` on the same environment).

Actions `GITHUB_TOKEN` cannot configure other repositories, so a PAT (or equivalent) is required.

Protect the `main` environment: required reviewers and deployment branches limited to the default branch, so `workflow_dispatch` from a fork/feature branch cannot use these secrets with a rewritten workflow.

## New OSS setup

1. Run **Repo settings** → `workflow_dispatch` with the new repository name and `create_if_missing: true` (explicit).
2. PR: add the name to [`repo-settings/allowlist.json`](../repo-settings/allowlist.json) (for schedule). If it publishes releases/tags, also add it to [`tags-allowlist.json`](../repo-settings/tags-allowlist.json).
3. If the repo will publish: add [`release-clients.yaml`](../release-clients.yaml) (`repository` + `publish`).
4. Install SecureFix server/client Apps, set `SECUREFIX_CLIENT_PRIVATE_KEY`, add client wrappers, enable Renovate — see [client-releases.md](client-releases.md).

Settings-only repos (for example `dotfiles`) need steps 1–2 (and App/bot as needed), not release / tags allowlists.

## Manual checklist

- [ ] `CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN` on `main`
- [ ] `main` environment: required reviewers + default-branch-only deployments
- [ ] Optional bot invite Accept token
- [ ] Securefix and Renovate Apps installed with the permissions required for controlled PR merges
- [ ] Pinned merge-request wrapper installed on every allowlisted repository
- [ ] No queued GitHub native auto-merge requests remain before rollout
- [ ] If invite stays pending, accept as the collaborator user once
