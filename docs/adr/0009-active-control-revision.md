# Active control revision

Status: proposed.

Protected main needs a stable authority for privileged operations while ordinary changes continue to merge. The proposal makes `control/active.json` on protected main that authority: it selects a published runtime and its bundled policy snapshot, and advances only through a reviewed activation pull request. `ControlRevision` records `version`, `generation`, `source_sha`, `policy_sha256`, `archive_sha256`, `release_id`, `asset_id`, `publisher_run_id`, `verification_run_id`, and `previous`. Its control identity is the SHA-256 digest of all serialized fields.

## Decision

Use one descriptor in protected main rather than a separate activation ledger or an additional runtime pointer. A separate ledger would create another mutable authority and require a consistency rule between the ledger and the runtime selector. The descriptor keeps selection, evidence, and history in the same protected-main change, so existing branch review and required checks fence activation. Generation starts at 1 with a zero-filled predecessor digest; each successor increments it and names the full identity of its predecessor. Reverting to an earlier runtime creates a new successor generation; it does not rewind or reuse a prior descriptor.

An ordinary main commit does not change the active control revision. The active runtime loads the descriptor from main and verifies that its source SHA and bundled policy digest match the descriptor. It uses the policy bundled in that runtime; it does not fetch live `policy.json` from main. Runtime publication and caller distribution are separate operations. Publication creates evidence for a candidate but does not activate it. After activation, an owner explicitly dispatches caller distribution for the verified publisher run.

The active controller validates a candidate publisher run and scratch-verification run before preparing an activation. It revalidates both when proposing the signed activation pull request. Candidate build and publication credentials cannot write `control/active.json`. The owner merges the resulting PR through the serialized server Actions lane. The current active control identity and the proposed successor identity are included in the request metadata, while owner commands, reviews, checks, and completion markers bind to both the exact PR head and full active control identity.

All protected-main mutation workflows use the `securefix-control` concurrency group with `queue: max`. The rulesets retain the exact Server App pull-request bypass required by the controlled merge lane; settings preflight validates that identity and mode, and the bypass does not replace Rust owner, review, check, exact-head, or control-identity validation. No additional bypass actor or mode is added, and native Renovate auto-merge is disabled. The signed activation PR follows the same server Actions lane as other controlled mutations.

## Failure and recovery

Activation stops if the active descriptor changes, the candidate source is not an ancestor of current protected main, the source signature or required CI is invalid, the release is missing or mutable, the archive attestation or policy digest differs, the publisher or scratch run is not a successful first-attempt owner dispatch, or the scratch evidence does not match the candidate. The activation PR must also stop if its prepared metadata, expected control identity, base head, or proposed descriptor changes. These failures leave the active descriptor unchanged.

After a successful activation, a later main commit does not by itself replace the active runtime or policy snapshot. If a later runtime revision fails, operations can continue through the prior published control as long as the descriptor and trusted loader workflow remain available. Recovery publishes and verifies a repair candidate, then activates it as the next generation. A rollback similarly publishes or selects a previously verified runtime and policy as a new generation with the current descriptor as predecessor. Missing or invalid active descriptor, runtime release, attestation, or policy match fails closed; the system must not infer a replacement from live main state.

## Bootstrap constraint

This proposal is not yet a safe deployment path. The currently deployed v0.2.20 loader requires its exact workflow SHA and runtime policy, and its publisher cannot publish a different runtime version. The current publisher uses a production contents-write token that can update repository content as well as create a release. The new main revision is an unmerged, reviewable proposal; merging it and relying on a failure discovered afterward would not preserve the old runtime as an operative control. Activation remains blocked until a separately trusted bootstrap publication path is established and reviewed. No additional ruleset bypass or bootstrap exception is part of this decision.

The pull-request version check in this proposal is scoped to runtime inputs: Cargo manifests and lockfile, Rust sources, toolchain, policy, repository settings, CLI setup, and the runtime publisher workflow. Documentation-only changes do not require a package version increase. The bootstrap path and overall control lifecycle remain unverified, so this ADR describes a proposal rather than deployed behavior.
