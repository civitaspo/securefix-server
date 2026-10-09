# Rust runtime migration

This migration changes the request contract and accepted runtime revision.
There is one execution path for each operation; old inline scripts and legacy allowlists are removed.
[`policy.json`](../policy.json) grants exact repository capabilities for release, settings, approval, merge, and Securefix.
[`securefix-config.yaml`](../securefix-config.yaml) configures upstream Securefix branch overrides for the fixed release-capable clients.

## Contract changes

| Previous contract | New contract |
| --- | --- |
| Reviewed server ancestors remain usable | Only the current server `main` SHA is accepted |
| Approval delegates policy to an upstream action | Rust verifies source signatures, paths, exact-head owner authorization, and review identity |
| A green review/check can survive a new sensitive head | App-bound `securefix-policy-check` is required on that head; stale reviews are dismissed |
| Release label carries tag/SHA data | Label carries repository/run locator; the v2 artifact manifest carries verified identity |
| Manual release accepts an arbitrary SHA | Retry identifies a merged, authorized `release/next` PR |
| Client GoReleaser executes with signing/publishing credentials | Fixed secret-free build, isolated checksum signer, isolated publisher |
| Scheduled reconcile can distribute merge restrictions | Scheduled runs update only existing active restrictions; activation is manual and full-set |
| Verification repo environment variable bypasses policy | A scratch repo needs an explicit reviewed capability entry |

Securefix's client and server use upstream v0.6.3, pinned to its full commit SHA.
The server delegates artifact preparation, commits, notifications, and post-action cleanup to upstream actions.
`CI` uses `.github/workflows/pull_request.yml`; `Release PR` uses `.github/workflows/release-pr.yml`.
PR CI fixes stay on their source branch, and trusted release-PR sources can target any non-default branch in the same repository.
Direct default-branch pushes remain forbidden; `release/next` is the release product workflow's convention, not a Securefix branch-name restriction.
Rust validates the Client App locator before preparation and checks repository capabilities, source workflow provenance, and destination scope before commit.
The executable and config come from the attested runtime and remain outside the workspace where upstream extracts client files.
The Securefix client may dispatch a request from a running CI run that will deliberately conclude failure, so this path does not require a successful run.
It does not weaken the separate successful-run and exact-head authorization checks for approval, merge, or release publication.

Upstream resolves the artifact name to an immutable ID but creates its commit on the destination head observed at write time.
An artifact made at A can therefore replace newer file content on B if B was present before that lookup.
We accept that limitation pending an upstream fix and remove the private artifact parser and expected-head commit engine.
The [integration decision](adr/0005-upstream-securefix-protocol.md) records the verified behavior and the reason `approve-pr-action` cannot safely replace head-bound owner approval.

## Deployment sequence

1. Run the [scratch verification CI](testing.md) on the reviewed candidate without publishing a Release. Review and land this runtime while privileged processing is stopped. Disable the schedule and controlled-merges activation during staging; the automatic schedule cannot reactivate a disabled restriction. Once the current main revision is stable, manually dispatch `Publish Runtime` on main to build, attest, and publish that SHA before privileged lifecycle testing or updating client pins. Confirm `Load CLI` verifies the resulting Release without compilation. No operational fallback build is available.
2. Configure the existing secrets and confirm both Apps' repository installations and requested permissions. The Server App needs Administration read for immutable-release preflight. Enable immutable releases for every release-capable repository through settings reconciliation before staging publication. Provider signing uses the existing GPG secrets in `main`; the signing job references no Server App key and receives no client write token.
3. Add a public scratch repository to a reviewed temporary policy and wait for that SHA's runtime publication. Successful publication starts caller distribution and the server default-head Policy Check. Review the generated caller PRs before merging them under the maintenance procedure below. The PRs add `policy-check.yml` with PR-target and default-branch push triggers, minimum caller permissions, the full runtime SHA, and the release PR-number retry contract. Confirm `SECUREFIX_CLIENT_PRIVATE_KEY` is present in each caller.
4. Exercise the runtime on scratch before making checks mandatory. Verify valid signed approval/merge, unauthorized and edited commands, reruns/replays, changed heads, force-push-and-return, wrong source workflow/pin, malformed artifacts, unsigned parents, failed/pending CI, and natural fixed-deadline timeout. For the requested scenario, authorize head A, update to sensitive B, and verify that a Renovate direct merge is rejected until B gets new owner authorization.
5. Stage both release strategies. Confirm a merged release PR produces the expected annotated tag and release. For Sigma, compare all 13 ZIP names and four archive entries, Terraform manifest, checksum names, GPG signature and Registry import. Test a matching partial draft retry and rejection of different bytes or extra assets. Confirm client hooks never run in sign/publish.
6. Reconcile default protections and read back the App-bound check sources, stale-review dismissal, signed commits, linear history, squash settings, bot collaborator access, and tag protection. Obtain successful default-head checks for every configured repository at the current wrapper pins.
7. Dispatch settings with an empty repository input and `merge_controls_ready: true` only after those staging checks. The CLI checks the entire capability set and current operational state, applies clients first, and applies the server last. Read back each resulting ruleset and test ordinary Renovate automerge without widening its existing exclusions.
8. Remove the temporary scratch policy entry through review, promote the stable revision, review its generated caller updates, and resume processing. Each subsequent server commit also requires new client pins.

GitHub deployment, token issuance, real merges, signing, publication, and fleet activation are not performed by local implementation checks.
The readiness input records operator attestation; API preflight does not prove those lifecycle tests occurred.

## Subsequent server upgrades

Merge the server change while the old current runtime can still authorize its PR.
After that merge, old client wrappers deliberately fail closed.
After staging the stable main revision, manually dispatch `Publish Runtime` on main and wait for it to succeed before resuming operations.
Rerun a failed dispatch at that same current revision; main pushes do not create runtime Releases automatically.
Successful publication starts `Distribute Runtime` and a new server default-head `Policy Check`.
Distribution uses Securefix Action to create signed commits on `automation/securefix-runtime` and opens or updates one PR per configured caller.
Review the caller PRs; distribution does not merge them or alter protections.
PR-target workflows use the wrapper on the default branch, so a client pin-update PR cannot produce the new policy check by changing its own workflow file.

Use a coordinated maintenance window for that transition.
Stop privileged processors and scheduled settings reconciliation, and pause Renovate automerge.
Manually disable controlled-merges and temporarily remove only `securefix-policy-check` from required checks while merging the reviewed client pin updates.
Retain signed commits, reviews, `status-check`, and the other default-branch protections.
Then resume current-runtime processing, obtain current default-head checks, restore the App-bound policy requirement, and repeat full-set activation readiness before resuming automerge and schedules.
The temporary rule changes are manual recovery operations; the CLI has no stale-runtime exception or activation bypass.

See [the runtime rollout decision](adr/0007-published-runtime-rollout.md) for the source and destination checks and the upstream commit limitation.

## Emergency stop and retry

Disable the relevant processing workflows and controlled-merges restrictions manually if a server change needs immediate containment.
An already-successful check on an unchanged head is not automatically revoked when policy changes.
Scheduled reconciliation preserves a disabled restriction and retains tag protection when a policy entry stops requesting it.
Retry pending work from the latest runtime and current client pins; incompatible or stale manifests fail closed.
Existing published releases and assets are never overwritten.

## Verification tooling

Run locked Rust tests, formatting, Clippy, and pinned actionlint as in CI.
`job.workflow_sha` identifies the actual workflow defining a reusable job, introduced in the [September 2026 GitHub Actions update](https://github.blog/changelog/2026-09-03-github-actions-early-september-2026-updates/).
Actionlint v1.7.12 does not yet recognize this field or GitHub's native `$/` action self-reference; CI ignores only those specific diagnostics for the supported field and installer path.
Rust workflow tests independently require that exact producer checkout expression and consumer verification SHA, empty top-level permissions, immutable artifact IDs, verification before extraction, and release credential separation.
Remove those narrow exceptions when actionlint supports them.
Version comments on SHA-pinned actions remain because [Renovate uses them to follow action tags](https://docs.renovatebot.com/modules/manager/github-actions/); bare SHA references are disabled by its default update policy.
The [previous live verification](archive/merge-verification-2026-10-08.md) is historical and does not certify this implementation.
