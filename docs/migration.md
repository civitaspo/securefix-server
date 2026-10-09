# Rust runtime migration

This migration changes the request contract and accepted runtime revision.
There is one execution path for each operation; old inline scripts and legacy allowlists are removed.
[`policy.json`](../policy.json) grants exact repository capabilities for release, settings, approval, merge, and Securefix.
Rust applies branch and source-provenance validation directly; there is no second allowlist or upstream runtime configuration.

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
| Verification repo environment variable bypasses policy | A separate typed scratch API context permits only the fixed test repository |

The native Rust client produces the bounded metadata and fixed-file artifact envelope. The server validates its immutable artifact ID, paths, exact source head and destination before applying a GitHub-signed expected-head commit. It reconciles release PRs and removes consumed request labels in Rust.

PR CI repairs stay on their source non-default branch. A pinned release-PR source may target any non-default branch in its own repository. Direct default-branch repairs remain forbidden; `release/next` is the release product workflow's convention. A newer source head invalidates a same-branch repair. Idempotent retries require the Server App's verified signature, expected parent, receipt, changed paths and exact resulting contents.

The Securefix client may dispatch a request from a CI run that will deliberately conclude failure. Approval, merge and release publication retain their separate successful-source-run requirement. See the [native protocol decision](adr/0008-native-securefix.md).

## Deployment sequence

1. Run the [scratch verification CI](testing.md) on the reviewed candidate without publishing a Release. Review and land this runtime while privileged processing is stopped. Disable the schedule and controlled-merges activation during staging; the automatic schedule cannot reactivate a disabled restriction. Once the current main revision is stable, manually dispatch `Publish Runtime` on main to build, attest, and publish that SHA before privileged lifecycle testing or updating client pins. Confirm `Load CLI` verifies the resulting Release without compilation. No operational fallback build is available.
2. Configure the existing secrets and confirm both Apps' repository installations and requested permissions. The Server App needs Administration read for immutable-release preflight. Enable immutable releases for every release-capable repository through settings reconciliation before staging publication. Provider signing uses the existing GPG secrets in `main`; the signing job references no Server App key and receives no client write token.
3. Run candidate integration against the fixed scratch repository using its scoped test context before production merge. No policy edit or candidate Release is required. Stable runtime publication starts caller distribution and the server default-head Policy Check. Review the generated caller PRs before merging them under the maintenance procedure below. The PRs add `policy-check.yml` with PR-target and default-branch push triggers, minimum caller permissions, the full runtime SHA, and the release PR-number retry contract. Confirm `SECUREFIX_CLIENT_PRIVATE_KEY` is present in each caller.
4. Exercise the runtime on scratch before making checks mandatory. Verify valid signed approval/merge, unauthorized and edited commands, reruns/replays, changed heads, force-push-and-return, wrong source workflow/pin, malformed artifacts, unsigned parents, failed/pending CI, and natural fixed-deadline timeout. For the requested scenario, authorize head A, update to sensitive B, and verify that a Renovate direct merge is rejected until B gets new owner authorization.
5. Stage both release strategies. Confirm a merged release PR produces the expected annotated tag and release. For Sigma, compare all 13 ZIP names and four archive entries, Terraform manifest, checksum names, GPG signature and Registry import. Test a matching partial draft retry and rejection of different bytes or extra assets. Confirm client hooks never run in sign/publish.
6. Reconcile default protections and read back the App-bound check sources, stale-review dismissal, signed commits, linear history, squash settings, bot collaborator access, and tag protection. Obtain successful default-head checks for every configured repository at the current wrapper pins.
7. Dispatch settings with an empty repository input and `merge_controls_ready: true` only after those staging checks. The CLI checks the entire capability set and current operational state, applies clients first, and applies the server last. Read back each resulting ruleset and test ordinary Renovate automerge without widening its existing exclusions.
8. Clean up test fixtures and any one-time frozen bootstrap branch/environment allowance, promote the stable revision, review its generated caller updates, and resume processing. Each subsequent server commit also requires new client pins.

GitHub deployment, token issuance, real merges, signing, publication, and fleet activation are not performed by local implementation checks.
The readiness input records operator attestation; API preflight does not prove those lifecycle tests occurred.

## Subsequent server upgrades

Merge the server change while the old current runtime can still authorize its PR.
After that merge, old client wrappers deliberately fail closed.
After staging the stable main revision, manually dispatch `Publish Runtime` on main and wait for it to succeed before resuming operations.
Rerun a failed dispatch at that same current revision; main pushes do not create runtime Releases automatically.
Successful publication starts `Distribute Runtime` and a new server default-head `Policy Check`.
Distribution uses the Rust expected-head commit API to create signed commits on `automation/securefix-runtime` and opens or updates one PR per configured caller.
Review the caller PRs; distribution does not merge them or alter protections.
PR-target workflows use the wrapper on the default branch, so a client pin-update PR cannot produce the new policy check by changing its own workflow file.

Use a coordinated maintenance window for that transition.
Stop privileged processors and scheduled settings reconciliation, and pause Renovate automerge.
Manually disable controlled-merges and temporarily remove only `securefix-policy-check` from required checks while merging the reviewed client pin updates.
Retain signed commits, reviews, `status-check`, and the other default-branch protections.
Then resume current-runtime processing, obtain current default-head checks, restore the App-bound policy requirement, and repeat full-set activation readiness before resuming automerge and schedules.
The temporary rule changes are manual recovery operations; the CLI has no stale-runtime exception or activation bypass.

See [the runtime rollout decision](adr/0007-published-runtime-rollout.md) for the source and destination checks; the native implementation replaces the historical upstream commit limitation.

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
