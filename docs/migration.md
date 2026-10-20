# Rust runtime migration

This migration changes the request contract and accepted runtime revision.
There is one execution path for each operation; old inline scripts and legacy allowlists are removed.
[`policy.json`](../policy.json) grants exact repository capabilities for release, settings, approval, merge, and Securefix.
Rust applies branch and source-provenance validation directly; there is no second allowlist or upstream runtime configuration.

The contract table below records the earlier Rust migration. Its current-main runtime selection was superseded by the active-control design in [ADR 0009](adr/0009-active-control-revision.md); the operational sequence below describes the current lifecycle. Deployment evidence is recorded in the dated verification report.

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

## Active control lifecycle

Active control separates the protected-main source tree from the runtime currently authorized to perform privileged work. `control/active.json` identifies the source SHA and bundled policy digest, the published archive digest and immutable release and asset IDs, the publisher and scratch-verification run IDs, its generation, and the previous control identity. Ordinary main commits leave this descriptor unchanged. The runtime uses the policy snapshot in its attested archive and does not fetch live `policy.json` from main.

The activation sequence is:

1. Merge ordinary changes through the normal protected-main checks. They do not activate or publish a runtime automatically.
2. Build, attest, and publish a candidate runtime from protected main using the trusted publisher path. Candidate code and artifacts receive no production write credentials.
3. Verify the candidate against the fixed scratch repository and retain the successful publisher and verification run IDs.
4. Dispatch the active published controller with those run IDs and the expected full active control identity. It revalidates the current protected-main source, successful CI, source signature, immutable release, archive attestation, policy digest, and scratch evidence before opening a signed activation PR.
5. Review and merge the activation PR through the server Actions lane. It changes only the active descriptor, uses the exact PR head and control identity, and advances the generation with the prior control identity as predecessor.
6. After activation, explicitly dispatch caller distribution using the successful publisher run ID. Review each resulting caller PR. Publication alone does not trigger caller updates.

Callers with the previous source pin are unavailable between activation and their migration merge. Treat completion of every caller migration as part of the rollout. Distribution creates PRs only. The separately owner-dispatched server [reviewed caller migration](client-releases.md#reviewing-a-caller-migration) can merge these PRs without invoking the old caller workflow, after a fresh exact-head, control-bound owner review, separate owner commands, signatures and required CI. A failed or delayed distribution leaves affected callers paused and requires a retry of that verified publisher run.

Protected-main mutation workflows share `securefix-control` concurrency with `queue: max`. The controlled-merge rulesets retain only the configured Server App pull-request bypass, which does not replace the server Actions lane's authorization, exact-head, approval, check, and expected-head validation. Activation adds no new bypass actor or mode. Native Renovate auto-merge is disabled under this sole-controller model. After activating a runtime with the separately configured `renovate_merge_bot` and distributing its callers, eligible non-major and lockfile updates request `/merge` through Renovate's `pr-comment` mode. Major updates remain manual. See `docs/merging.md` for authorization and expired-request recovery.

Activation fails closed when the active control identity changes, the candidate is not an ancestor of current protected main, source signature or required CI fails, publication is mutable or unverifiable, the archive or bundled policy digest differs, publisher or scratch evidence is invalid, or prepared activation metadata and PR head no longer match. Those failures leave the active descriptor unchanged. A missing descriptor, release, attestation, or policy match also stops ordinary operations rather than selecting a runtime from live main.

After activation, a later main commit does not select its own runtime or policy. The previous published control remains usable if the descriptor and trusted workflow path remain available. To repair a later failing runtime, publish and verify a repair candidate and activate it as the next generation. Rollback also creates a new generation whose payload may identify an earlier verified runtime; it records the current descriptor as its predecessor rather than rewinding history.

### One-time bootstrap and first activation

The first protected-main revision needs a separate trusted bootstrap route. Before
the first code pull request merged, the owner explicitly approved and completed the
permanent settings rollout through the repository administrator flow: removing the
Renovate bypass from all nine controlled-merge rulesets while retaining the sole
Server App `pull_request` bypass, disabling native auto-merge, confirming no queued
requests, and enabling immutable releases for `civitaspo/securefix-server`. The former
v0.2.20 runtime could not make those changes. These settings remain in force without
a temporary ruleset exception.

The one-time `control-bootstrap.yml` path is an explicitly reviewed protected-main
authority. Its `securefix-bootstrap` Rust binary is compiled from the exact workflow
SHA by `build-bootstrap-host.yml` in a separate job without production credentials.
The binary embeds that source SHA and rejects a mismatched dispatch. It independently checks the source and workflow runs,
candidate artifact ID, attestation, archive and bundled policy, scratch proof, current
main, absent descriptor, and pull request before a write. Qualification treats the
candidate archive as data and never executes its binary. App-token jobs use the
protected `main` environment. The workflow has separate `propose` and `merge` phases:
the first revalidates and publishes the verified initial archive, then opens a
descriptor PR; the second requires a separate owner-reviewed dispatch and rechecks the
expected main SHA, exact PR head, descriptor identity, and required CI before merging
with expected-head CAS. If publication succeeded but a later step failed, a retry may
reuse the reserved release only when it is already immutable and published and the
host re-downloads the bounded asset, verifies its GitHub size and digest, checks the
archive policy against the exact source, and verifies the fixed bootstrap attestation.
A draft with mismatched asset metadata fails closed. This fixed producer never runs
again after generation one. A later rollback can select the same archive in a new normal
successor descriptor, using the recorded bootstrap publisher run and fixed trusted signer
path. Other generations use the regular runtime publication path. There is no fallback
loader. Once generation one is required, a missing or invalid active descriptor
permanently disables operations until an authorized control revision is restored.

Bootstrap publication and activation are separate phases. First, the bootstrap path
publishes and proposes an exact descriptor change. An owner reviews the resulting
activation PR. A separate dispatch then merges only after it rechecks the owner,
expected protected-main SHA, exact PR head SHA, full proposed descriptor identity,
and required CI through the serialized server Actions lane. Normal candidate
publication and scratch verification do not alter active control. After bootstrap,
normal activations and later rollbacks require exact-head owner review, `/approve`,
successful Bot approval and required checks, then a separate `/merge` through the
ordinary server lane. These commands bind to the exact head and full current control
identity. The merge revalidates the successor descriptor and uses expected-head CAS.
An unrelated main advance with an unchanged descriptor does not select a new runtime
or invalidate that control identity.

The bootstrap scratch rehearsal has its own `phase=bootstrap` in
`testing-securefix-server.yml`. It verifies the pinned v0.2.20 legacy runtime by
release ID `414653308`, asset ID `646481902`, archive digest, GitHub attestation, and
runtime verification against source `e8e2bc77d96a4e359417217f1d1c22f4e1ac4483`.
Before minting scratch App tokens, the fixed Rust host checks that the dispatch came from
current protected main and that `control/active.json` is absent. The pinned runtime
provides the read baseline. The source-pinned fixed Rust host validates the bounded
fixture output files. The candidate runtime prepares and verifies the
scratch integration fixtures and runs the scratch-only control probe. This avoids using
the current-main `validate-producer` path as its own initial trust baseline. It verifies
the bootstrap test path, not production publication, activation, or distribution.

Generation four is active at immutable runtime v0.2.32, source
`673dd9254150a3271b09798481f616900c56191a`. Final-source scratch qualification,
normal publication, descriptor review, required CI, Bot approval and separate owner
commands passed through the ordinary controller. Descriptor
[PR #116](https://github.com/civitaspo/securefix-server/pull/116) activated this generation.
All nine canonical caller migrations, their post-merge CI, and the nine configured
Renovate settings are deployed. An actual Renovate comment request completed through
the existing approval job and Server App merge lane. Bootstrap and bounded repair
remain retired. See the [dated verification report](renovate-merge-verification-2026-10-18.md)
for exact activation, rollout, policy and hosted-service evidence, including recovery limits.
If the active descriptor becomes missing or invalid, ordinary operations fail closed;
the settings administrator credential does not supply a replacement runtime.

Repository settings remain owned by the periodic `repo-settings.yml` management flow and its existing dedicated administrator credential. Normal PR creation, approval, merge, runtime publication, control activation, and bootstrap/repair do not read administrative settings or receive that credential or Server App Administration read permission. This boundary does not remove required source provenance, owner and exact-head checks, CI, immutable-release verification, signature/attestation, archive verification, or activation CAS.

Earlier deployment and verification reports certify only the revisions and paths they actually tested. Use the current dated successor report for active-control activation and caller rollout evidence.

## Emergency stop and retry

Disable the relevant processing workflows for immediate containment while retaining
controlled-merges restrictions. Recover through the verified active runtime.
Bootstrap and bounded repair are retired after generation one; a defect that prevents
normal activation needs a separately reviewed recovery authority. Any change to enforcement authority or rulesets
requires separate explicit administrator review. The [request-intake recovery procedure](request-intake-recovery-2026-10-20.md) records the bounded workflow-repair case and its independent gates. An already-successful check on an
unchanged head is not automatically revoked when policy changes.
Scheduled reconciliation preserves a disabled restriction and retains tag protection when a policy entry stops requesting it.
Retry pending work from the latest runtime and current client pins; incompatible or stale manifests fail closed.
Existing published releases and assets are never overwritten.

## Verification tooling

Run locked Rust tests, formatting, Clippy, and pinned actionlint as in CI.
`job.workflow_sha` identifies the actual workflow defining a reusable job, introduced in the [September 2026 GitHub Actions update](https://github.blog/changelog/2026-09-03-github-actions-early-september-2026-updates/).
Actionlint v1.7.12 does not yet recognize this field, GitHub's native `$/` action self-reference, or queued concurrency. CI ignores only those specific diagnostics; structural tests require `queue: max` and `cancel-in-progress: false` on each shared mutation lane.
Rust workflow tests independently require that exact producer checkout expression and consumer verification SHA, empty top-level permissions, immutable artifact IDs, verification before extraction, and release credential separation.
Remove those narrow exceptions when actionlint supports them.
Version comments on SHA-pinned actions remain because [Renovate uses them to follow action tags](https://docs.renovatebot.com/modules/manager/github-actions/); bare SHA references are disabled by its default update policy.
The [previous live verification](archive/merge-verification-2026-10-08.md) is historical and does not certify this implementation.

The managed client token step accepts the audited SHA pins for `actions/create-github-app-token` v3.2.0 and v3.3.0 and emits v3.3.0. Unknown revisions, other action repositories, and changed token inputs remain unsupported; a Renovate token-action upgrade outside this set requires an audited server update before caller migration.
