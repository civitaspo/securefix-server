# Rust runtime migration

This migration changes the request contract and accepted runtime revision.
There is one execution path for each operation; old inline scripts and legacy allowlists are removed.
[`policy.json`](../policy.json) replaces release, settings, tag, and wildcard Securefix allowlists.
The former `securefix-config.yaml` is removed because the native Rust server uses this policy directly.

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

Securefix's upstream v0.6.0 client artifact contract remains in use; the server-side upstream `prepare`, `commit`, and `notify` actions are removed.
`CI` uses `.github/workflows/pull_request.yml`; `Release PR` uses `.github/workflows/release-pr.yml`.
Fixes stay on the source branch or `release/next`, and cannot push directly to a default branch.
The native server permits the existing release-PR metadata without running client-provided scripts.
It reads the selected immutable artifact ID once, validates the manifest and metadata, and stages those exact ZIP bytes outside the runner workspace; no artifact is resolved again by name or extracted.
Every payload must belong to the manifest, which may list absent paths only to represent deletions. Unsafe paths, including `.git`, are rejected whether or not a payload is present.
Immediately before applying, the server rechecks the successful source run, live PR head, current policy/runtime, artifact ID, and captured destination branch head.
Signed writes use GitHub's `createCommitOnBranch` with the captured head as `expectedHeadOid`; concurrent branch movement fails instead of applying stale CI fixes to newer content.
For a new `release/next`, Rust creates the ref at the validated default-branch run SHA and then performs the same expected-head check.
PR creation is limited to the validated title/body/base/draft options; client-provided labels, reviewers, comments, automerge, projects, and scripts are not executed.
After Rust validates the bot-created locator, an `always()` workflow step consumes that request label through the current-runtime guard, including when source validation or application fails. Per-PR failure comments from the former server notifier are not retained; operators track failures from the Securefix Actions run and its logs.

## Deployment sequence

1. Review and land this runtime while privileged processing is stopped. Disable the schedule and controlled-merges activation during staging; the automatic schedule cannot reactivate a disabled restriction. Wait for `Publish Runtime` to build, attest, and publish the new main SHA before testing or updating client pins. Confirm `Load CLI` verifies the resulting Release without compilation. No operational fallback build is available.
2. Configure the existing secrets and confirm both Apps' repository installations and requested permissions. The Server App needs Administration read for immutable-release preflight. Enable immutable releases for every release-capable repository through settings reconciliation before staging publication. Provider signing uses the existing GPG secrets in `main`; the signing job references no Server App key and receives no client write token.
3. Add a public scratch repository to a reviewed temporary policy, wait for that SHA's runtime publication, then update every client wrapper to the resulting full server SHA. Add `policy-check.yml` with PR-target and default-branch push triggers, read-only caller permissions, and `SECUREFIX_CLIENT_PRIVATE_KEY`. All reusable callers need `attestations: read` as well as their documented contents permission. Update release wrappers to the documented PR-number retry contract.
4. Exercise the runtime on scratch before making checks mandatory. Verify valid signed approval/merge, unauthorized and edited commands, reruns/replays, changed heads, force-push-and-return, wrong source workflow/pin, malformed artifacts, unsigned parents, failed/pending CI, and natural fixed-deadline timeout. For the requested scenario, authorize head A, update to sensitive B, and verify that a Renovate direct merge is rejected until B gets new owner authorization.
5. Stage both release strategies. Confirm a merged release PR produces the expected annotated tag and release. For Sigma, compare all 13 ZIP names and four archive entries, Terraform manifest, checksum names, GPG signature and Registry import. Test a matching partial draft retry and rejection of different bytes or extra assets. Confirm client hooks never run in sign/publish.
6. Reconcile default protections and read back the App-bound check sources, stale-review dismissal, signed commits, linear history, squash settings, bot collaborator access, and tag protection. Obtain successful default-head checks for every configured repository at the current wrapper pins.
7. Dispatch settings with an empty repository input and `merge_controls_ready: true` only after those staging checks. The CLI checks the entire capability set and current operational state, applies clients first, and applies the server last. Read back each resulting ruleset and test ordinary Renovate automerge without widening its existing exclusions.
8. Remove the temporary scratch policy entry through review, update every pin again, and resume processing. Each subsequent server commit also requires new client pins.

GitHub deployment, token issuance, real merges, signing, publication, and fleet activation are not performed by local implementation checks.
The readiness input records operator attestation; API preflight does not prove those lifecycle tests occurred.

## Subsequent server upgrades

Prepare and review all client pin updates before merging a new server revision.
Merge the server change while the old current runtime can still authorize its PR.
After that merge, old client wrappers deliberately fail closed.
Wait for the new SHA's `Publish Runtime` run to succeed; rerun a failed main-push producer before resuming operations.
PR-target workflows use the wrapper on the default branch, so a client pin-update PR cannot produce the new policy check by changing its own workflow file.

Use a coordinated maintenance window for that transition.
Stop privileged processors and scheduled settings reconciliation, and pause Renovate automerge.
Manually disable controlled-merges and temporarily remove only `securefix-policy-check` from required checks while merging the reviewed client pin updates.
Retain signed commits, reviews, `status-check`, and the other default-branch protections.
Then resume current-runtime processing, obtain current default-head checks, restore the App-bound policy requirement, and repeat full-set activation readiness before resuming automerge and schedules.
The temporary rule changes are manual recovery operations; the CLI has no stale-runtime exception or activation bypass.

## Emergency stop and retry

Disable the relevant processing workflows and controlled-merges restrictions manually if a server change needs immediate containment.
An already-successful check on an unchanged head is not automatically revoked when policy changes.
Scheduled reconciliation preserves a disabled restriction and retains tag protection when a policy entry stops requesting it.
Retry pending work from the latest runtime and current client pins; incompatible or stale manifests fail closed.
Existing published releases and assets are never overwritten.

## Verification tooling

Run locked Rust tests, formatting, Clippy, and pinned actionlint as in CI.
`job.workflow_sha` identifies the actual workflow defining a reusable job, introduced in the [September 2026 GitHub Actions update](https://github.blog/changelog/2026-09-03-github-actions-early-september-2026-updates/).
Actionlint v1.7.12 does not yet recognize this field; CI ignores only its specific unknown-property diagnostic.
Rust workflow tests independently require that exact producer checkout expression and consumer verification SHA, empty top-level permissions, immutable artifact IDs, verification before extraction, and release credential separation.
Remove that narrow exception when actionlint supports the field.
Version comments on SHA-pinned actions remain because [Renovate uses them to follow action tags](https://docs.renovatebot.com/modules/manager/github-actions/); bare SHA references are disabled by its default update policy.
The [previous live verification](archive/merge-verification-2026-10-08.md) is historical and does not certify this implementation.
