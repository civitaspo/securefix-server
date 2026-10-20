# Maintain workflow dependency lockfiles

Run the official GitHub generator from the repository root after changing a workflow or an action definition.
Keep the workflow changes and `.github/workflows/actions.lock` in the same reviewed commit.

```sh
gh extension install github/gh-actions-lock --pin v0.2.0
gh actions-lock --no-narrow --no-interactive
gh actions-lock --verify
```

`--no-narrow` preserves the repository's full SHA references.
The generator converts supported local action references from `./` to `$/`.
Review those changes too.
Do not edit `actions.lock` by hand.
Use `--relock` only after reviewing why an upstream reference moved.
Do not automatically accept moved or unreachable commits.

The server installs the official v0.2.0 binary by its release asset ID and SHA-256 digest.
CI runs its frozen `--verify` check.
The workflow structure test also requires an entry for every server workflow, including testing workflows and workflows without external actions.

## Distribute callers with their lockfile

Caller distribution generates the desired managed workflows over an immutable snapshot of all caller workflows and local action definitions.
The official generator updates the complete lockfile, including dependencies of workflows outside the managed caller set.
Only the managed caller files and generated lockfile enter the signed migration PR.
Generation fails if the tool changes a workflow or action definition.
Convert any unsupported local action reference in a separately reviewed source change before distribution.

The reviewed migration lane regenerates the expected file set against the current default branch.
The lockfile is part of the exact file comparison and expected-head merge check.
Initial testing caller deployment also updates the shared lockfile after removing retired caller workflows.
A later distribution must preserve entries for other workflows.

Reusable workflows use the lockfile in their defining repository at their referenced commit.
Adding a lockfile to current main cannot repair an old commit.
Publish and activate a lockfile-bearing runtime source through the normal control lifecycle before distributing its caller pins.
A production runtime change is required here because the caller generator and reviewed migration validator are embedded in the published executable.

## Keep Renovate updates consistent

Renovate's GitHub Actions manager supports the official `actions.lock` format in version 44.24.0 and later.
For onboarded workflows it regenerates the lockfile after dependency edits with `--no-narrow` and `--no-migrate-local-actions`.
Retain the existing Renovate configuration and signed server merge lane.
Do not add overlapping Dependabot version updates.
Check the deployed Renovate version and its PR diff before relying on this maintenance behavior.
New workflows still need onboarding with the official generator.

## Enforce through repository settings

Actions policy changes belong only in `repo-settings.yml` with its dedicated administrator credential.
Keep approval, merge, publication, activation, and distribution free of administrator reads and credentials.
Enable Require lockfile only after all targeted workflows and pinned reusable workflow revisions have valid lockfiles.

As of the 2026-10-18 official REST OpenAPI revision, repository Actions policy rules document actor and event restrictions but no Require lockfile payload.
The Actions permissions API exposes `sha_pinning_required`, which is a separate setting.
Do not send an invented lockfile rule or treat SHA pinning as lockfile enforcement.
Automated repository-settings enforcement remains unimplemented until a supported API is established.

## Sources

- [GitHub lockfile generation](https://docs.github.com/en/actions/how-tos/secure-your-work/lock-workflow-dependencies).
- [GitHub lockfile enforcement](https://docs.github.com/en/actions/how-tos/administer/enforce-workflow-lockfiles).
- [Official generator v0.2.0](https://github.com/github/gh-actions-lock/releases/tag/v0.2.0).
- [Renovate GitHub Actions manager](https://github.com/renovatebot/renovate/blob/b28f4eb4b7d738b9c5664bf91e533e297ab366a4/lib/modules/manager/github-actions/readme.md).
- [GitHub REST OpenAPI snapshot](https://github.com/github/rest-api-description/blob/755ee33b4a81d51f6f07a902cce26cbec3b822f2/descriptions/api.github.com/api.github.com.json).
