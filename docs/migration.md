# Rust runtime migration

This migration changes the request contract and accepted runtime revision.
There is one execution path for each operation; old inline scripts and legacy allowlists are removed.
[`policy.json`](../policy.json) grants exact repository capabilities for release, settings, approval, merge, and Securefix.
Rust applies branch and source-provenance validation directly; there is no second allowlist or upstream runtime configuration.

The contract table below records the earlier Rust migration. Its current-main runtime selection was superseded by the active-control proposal in [ADR 0009](adr/0009-active-control-revision.md); the operational sequence later in this document is the proposed lifecycle and is not evidence of deployment.

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

The active control proposal separates the protected-main source tree from the runtime currently authorized to perform privileged work. `control/active.json` identifies the source SHA and bundled policy digest, the published archive digest and immutable release and asset IDs, the publisher and scratch-verification run IDs, its generation, and the previous control identity. Ordinary main commits leave this descriptor unchanged. The runtime uses the policy snapshot in its attested archive and does not fetch live `policy.json` from main.

The proposed activation sequence is:

1. Merge ordinary changes through the normal protected-main checks. They do not activate or publish a runtime automatically.
2. Build, attest, and publish a candidate runtime from protected main using the trusted publisher path. Candidate code and artifacts receive no production write credentials.
3. Verify the candidate against the fixed scratch repository and retain the successful publisher and verification run IDs.
4. Dispatch the active published controller with those run IDs and the expected full active control identity. It revalidates the current protected-main source, successful CI, source signature, immutable release, archive attestation, policy digest, and scratch evidence before opening a signed activation PR.
5. Review and merge the activation PR through the server Actions lane. It changes only the active descriptor, uses the exact PR head and control identity, and advances the generation with the prior control identity as predecessor.
6. After activation, explicitly dispatch caller distribution using the successful publisher run ID. Review each resulting caller PR. Publication alone does not trigger caller updates.

Callers with the previous source pin are unavailable between activation and their migration merge. Treat completion of every caller migration as part of the rollout. The server's exact generated-workflow migration path can merge these PRs without invoking the old caller workflow; the server's own repair path remains available. A failed or delayed distribution leaves affected callers paused and requires a retry of that verified publisher run.

Protected-main mutation workflows share `securefix-control` concurrency with `queue: max`. The controlled-merge rulesets retain only the configured Server App pull-request bypass, which does not replace the server Actions lane's owner, exact-head, approval, check, and expected-head validation. Activation adds no new bypass actor or mode. Native Renovate auto-merge is disabled under this sole-controller model; non-major, lockfile, and major Renovate PRs all need an explicit owner `/merge` command after checks.

Activation fails closed when the active control identity changes, the candidate is not an ancestor of current protected main, source signature or required CI fails, publication is mutable or unverifiable, the archive or bundled policy digest differs, publisher or scratch evidence is invalid, or prepared activation metadata and PR head no longer match. Those failures leave the active descriptor unchanged. A missing descriptor, release, attestation, or policy match also stops ordinary operations rather than selecting a runtime from live main.

After activation, a later main commit does not select its own runtime or policy. The previous published control remains usable if the descriptor and trusted workflow path remain available. To repair a later failing runtime, publish and verify a repair candidate and activate it as the next generation. Rollback also creates a new generation whose payload may identify an earlier verified runtime; it records the current descriptor as its predecessor rather than rewinding history.

### One-time bootstrap and first activation

The first protected-main revision needs a separate trusted bootstrap route. Before its
first code pull request is merged, an owner must explicitly approve and complete the
permanent live-settings rollout: remove the Renovate bypass from all nine controlled-
merge rulesets while retaining the sole Server App `pull_request` bypass, disable
native auto-merge and confirm that no requests remain queued, and enable immutable
releases for `civitaspo/securefix-server`. The currently deployed v0.2.20 runtime
cannot make those changes. They require the existing repository administrator UI or
API. No temporary ruleset exception is part of this migration, and no production
settings change has been made as part of this proposal.

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
publication and scratch verification do not alter active control; after this bootstrap,
normal activations and later rollbacks use the same reviewed descriptor-PR fence.

The bootstrap scratch rehearsal has its own `phase=bootstrap` in
`testing-securefix-server.yml`. It verifies the pinned v0.2.20 legacy runtime by
release ID `414653308`, asset ID `646481902`, archive digest, GitHub attestation, and
runtime verification against source `e8e2bc77d96a4e359417217f1d1c22f4e1ac4483`.
Before minting scratch App tokens, the fixed Rust host checks that the dispatch came from
current protected main and that `control/active.json` is absent. The pinned runtime
validates the fixture output files. The candidate runtime prepares and verifies the
scratch integration fixtures and runs the scratch-only control probe. This avoids using
the current-main `validate-producer` path as its own initial trust baseline. It verifies
the bootstrap test path, not production publication, activation, or distribution.

While `control/active.json` is absent, the current proposal does not provide a proven recovery route. Ordinary Policy Check and repository-settings loads fail closed when the descriptor lookup returns 404. The proposed `repair-propose` path has not passed prequalification: a failed prequalification opens no PR, so its paired `repair-merge` phase cannot recover the control path. A scheduled settings run also fails at descriptor loading; the dedicated settings administrator credential does not make a missing runtime descriptor valid.

Do not describe this pause as recoverable through those phases until a separately reviewed recovery route has passed its end-to-end checks. Any route that changes the bootstrap workflow or fixed helper needs independent review. It must preserve the self-repair guard, signed source and owner-head CI checks, exact-head compare-and-swap, and must not use a temporary ruleset exception or direct main API write. No route may infer a runtime from main or use an unverified archive. The dated deployment report records prior runtime evidence only; it is not proof that bootstrap or repair works.

Repository settings remain owned by the periodic `repo-settings.yml` management flow and its existing dedicated administrator credential. Normal PR creation, approval, merge, runtime publication, control activation, and bootstrap/repair do not read administrative settings or receive that credential or Server App Administration read permission. This boundary does not remove required source provenance, owner and exact-head checks, CI, immutable-release verification, signature/attestation, archive verification, or activation CAS.

The deployment and verification reports dated before this proposal document evidence for the earlier runtime contract only. They do not establish that this lifecycle, bootstrap path, or proposed code has been deployed or verified.

## Emergency stop and retry

Disable the relevant processing workflows for immediate containment while retaining
controlled-merges restrictions. Recover through the active runtime or the bounded
reviewed repair path as applicable; any change to enforcement authority or rulesets
requires separate explicit administrator review. An already-successful check on an
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
