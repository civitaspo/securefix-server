# Active control revision

Status: proposed.

Protected main needs a stable authority for privileged operations while ordinary changes continue to merge. The proposal makes `control/active.json` on protected main that authority: it selects a published runtime and its bundled policy snapshot, and advances only through a reviewed activation pull request. `ControlRevision` records `version`, `generation`, `source_sha`, `policy_sha256`, `archive_sha256`, `release_id`, `asset_id`, `publisher_run_id`, `verification_run_id`, and `previous`. Its control identity is the SHA-256 digest of all serialized fields.

## Decision

Use one descriptor in protected main rather than a separate activation ledger or an additional runtime pointer. A separate ledger would create another mutable authority and require a consistency rule between the ledger and the runtime selector. The descriptor keeps selection, evidence, and history in the same protected-main change, so existing branch review and required checks fence activation. Generation starts at 1 with a zero-filled predecessor digest; each successor increments it and names the full identity of its predecessor. Reverting to an earlier runtime creates a new successor generation; it does not rewind or reuse a prior descriptor.

An ordinary main commit does not change the active control revision. The active runtime loads the descriptor from main and verifies that its source SHA and bundled policy digest match the descriptor. It uses the policy bundled in that runtime; it does not fetch live `policy.json` from main. Runtime publication and caller distribution are separate operations. Publication creates evidence for a candidate but does not activate it. After activation, an owner explicitly dispatches caller distribution for the verified publisher run.

The active controller validates a candidate publisher run and scratch-verification run before preparing an activation. It revalidates both when proposing the signed activation pull request. Candidate build and publication credentials cannot write `control/active.json`. The owner merges the resulting PR through the serialized server Actions lane. The current active control identity and the proposed successor identity are included in the request metadata, while owner commands, reviews, checks, and completion markers bind to both the exact PR head and full active control identity.

The proposed protected-main mutation workflows use the `securefix-control` concurrency group with `queue: max`. The rulesets retain the exact Server App pull-request bypass required by the controlled merge lane; repository-settings management validates that identity and mode. Approval, merge, publication, activation, and bootstrap or repair do not query administrative settings or receive the dedicated repository-settings administrator credential or Server App Administration read permission. That separation does not relax owner, review, required CI, exact-head, control-identity, source provenance, signature, attestation, archive, or immutable-release checks. No additional bypass actor or mode is added, and native Renovate auto-merge is disabled. The signed activation PR follows the same server Actions lane as other controlled mutations.

## Failure and recovery

Activation stops if the active descriptor changes, the candidate source is not an ancestor of current protected main, the source signature or required CI is invalid, the release is missing or mutable, the archive attestation or policy digest differs, the publisher or scratch run is not a successful first-attempt owner dispatch, or the scratch evidence does not match the candidate. The activation PR must also stop if its prepared metadata, expected control identity, base head, or proposed descriptor changes. These failures leave the active descriptor unchanged.

After a successful activation, a later main commit does not by itself replace the active runtime or policy snapshot. If a later runtime revision fails, operations can continue through the prior published control as long as the descriptor and trusted loader workflow remain available. Recovery publishes and verifies a repair candidate, then activates it as the next generation. A rollback similarly publishes or selects a previously verified runtime and policy as a new generation with the current descriptor as predecessor. Missing or invalid active descriptor, runtime release, attestation, or policy match fails closed; the system must not infer a replacement from live main state.

## One-time bootstrap

Before the first code pull request is merged, the owner must explicitly approve and
complete the permanent live-settings rollout: remove Renovate bypass from all nine
controlled-merge rulesets while retaining only the Server App `pull_request` bypass,
disable native auto-merge and verify no pending native merge requests, and enable
immutable releases on the server repository. The currently deployed v0.2.20 runtime
cannot apply those settings; an existing repository administrator must use the GitHub
UI or API. This is a required rollout prerequisite, not a temporary exception. No live
production change has been authorized by this proposal.

The proposed `control-bootstrap.yml` supplies a one-time, reviewed protected-main
authority for the initial publication and descriptor proposal. Its `securefix-bootstrap`
Rust binary is compiled from the exact workflow SHA in a separate job without
production credentials and embeds that source identity. The binary
independently qualifies the source and workflow runs, candidate artifact ID, attestation,
archive and policy, scratch proof, current main, absent descriptor, and reviewed PR.
Qualification is read-only and does not run the candidate executable; the archive is
data. App-token jobs use the protected `main` environment, and candidate code receives
no write token. The workflow separates `propose` from `merge`: the first revalidates
and publishes the initial archive and proposes the descriptor PR; the second is a
separate owner-reviewed dispatch that rechecks expected main, exact PR head, descriptor
identity, and required CI before expected-head CAS merge. If publication succeeded but a
later step failed, retry may reuse the reserved release only after re-downloading its
bounded immutable asset and rechecking GitHub size/digest, exact-source bundled policy,
and fixed bootstrap attestation; a mismatched draft asset fails closed. The trusted
bootstrap producer publishes only the verified initial archive and never runs again
after generation one. A later normal successor may select that same archive for
rollback, with the original bootstrap publisher run and fixed signer path recorded in
the descriptor. Other generations use the regular runtime publisher.
There is no fallback runtime selection. After generation one is required, a missing or
invalid descriptor disables operations until a valid control revision is restored.

Publication and activation remain distinct. The workflow proposes an exact descriptor
PR; an owner reviews it; a separate serialized dispatch merges only after checking the
owner, expected protected-main SHA, exact PR head SHA, full descriptor identity, and
required CI. The first bootstrap sequence and its failure behavior remain unverified.
The `testing-securefix-server.yml` `phase=bootstrap` rehearsal uses the pinned v0.2.20
read baseline (release ID `414653308`, asset ID `646481902`, verified archive digest
and attestation for source `e8e2bc77d96a4e359417217f1d1c22f4e1ac4483`) because the
current-main producer cannot validate its own initial trust chain. It checks current
main and descriptor absence before minting scratch tokens, uses v0.2.20 for scratch
output validation, and runs the candidate runtime's fixture preparation, verification,
and control probe only against scratch. This establishes a bootstrap test mode; it does
not verify production publication, activation, or distribution.

The proposal is not deployable until its code is compiled, the required bootstrap verification gate passes, and operators review the procedure. The bootstrap scratch rehearsal validates fixtures; it does not establish production publication, activation, or recovery. While the descriptor is absent, Policy Check and settings loads fail closed on descriptor lookup. The proposed `repair-propose` and `repair-merge` sequence has not demonstrated a recovery: failed prequalification creates no PR for the merge phase, and scheduled settings reconciliation also stops at the missing descriptor. Do not claim a proven recovery path or that v0.2.20 remains operative after main advances. A separately reviewed recovery may change the bootstrap trust root only with independent qualification; it must not weaken self-repair restrictions, bypass rulesets, or write directly to main. Preserve exact-head CI, review, provenance, immutable-release postconditions, signed attestation, archive verification, and CAS. Historical deployment reports cover the earlier runtime contract only. The protected-main `phase=bootstrap` scratch gate is post-merge by design; it must pass before proposing bootstrap publication or descriptor activation.

The pull-request version check in this proposal is scoped to runtime inputs: Cargo manifests and lockfile, Rust sources, toolchain, policy, repository settings, CLI setup, and the runtime publisher workflow. Documentation-only changes do not require a package version increase. The bootstrap path and overall control lifecycle remain unverified, so this ADR describes a proposal rather than deployed behavior. Before the first code PR merges, compile the implementation, pass normal candidate scratch verification on a frozen integration branch, review the fixed bootstrap path and operator procedure, and explicitly approve and complete the permanent live-settings rollout. The protected-main `phase=bootstrap` scratch gate is post-merge by design: run it during the finite pause, and require it to pass before bootstrap publication or descriptor activation is proposed.
