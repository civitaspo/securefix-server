# Active control revision: verification record (2026-10-16)

## Decision rationale

Protected `main` supplies reviewed code; `control/active.json` separately selects the
runtime and bundled policy authorized to perform privileged operations. An ordinary
main advance leaves that selection unchanged. The descriptor binds an exact source,
immutable release asset, policy/archive digests, publisher and verification runs, and
an activation generation linked to its predecessor. Keeping it on protected main
reuses the existing review and required-check boundary. A separate mutable Git ref
would add another authority and consistency rule. See [ADR 0009](adr/0009-active-control-revision.md).

Activation uses an owner-dispatched, exact-head and expected-main merge under the
shared mutation queue. Reusable approvals, policy results, and mutations carry the
full control identity. The fixed bootstrap workflow/helper qualifies initial archive
bytes without executing candidate code; its separate writer never executes the
candidate binary. This narrow initial authority is explicitly documented and reviewed.

## Local verification

The assembled suite passed: **32 library, 233 binary, and 2 native integration tests**;
2 binary tests were ignored. All **16 Python bootstrap tests**, formatting, Clippy,
and pinned actionlint passed. The local suite covers all five requested scenarios at
the boundaries below. Fixtures and workflow assertions do not establish live production
publication or activation.

## Five requested scenarios

| Scenario | Evidence and result | Limit |
| --- | --- | --- |
| 1. Failed candidate publication leaves repair available | `runtime::tests::failed_candidate_publication_does_not_block_repair_with_unchanged_active_runtime` rejects candidate B after failed CI, then allows a repair POST under unchanged active descriptor A. `api::tests::unchanged_active_control_allows_write_without_a_main_tip_lookup` checks that ordinary main advancement is irrelevant. | Sequential component fixtures; no live failed-publication repair rehearsal. |
| 2. Unpublished/unverified candidates cannot activate | `control_commands::tests::prepare_and_propose_validation_rejects_unpublished_candidates_before_mutation` exercises shared `validate_request`, rejecting missing and mutable releases before descriptor output or PR creation. Publisher, archive, attestation, signer, policy, and verification-run gates have separate negative tests. | Component boundaries, not a real production activation attempt or the CLI environment wrapper. |
| 3. Failed/conflicting activation leaves consistent state | `api::tests::same_source_with_a_new_control_generation_is_stale_before_write` and control successor tests cover generation fencing. The scratch control probe passed expected-head conflict rejection, unchanged-descriptor source advancement, and generation 1→2→3. | Real scratch Git CAS; no production activation merge or simultaneous activation/mutation race rehearsal. |
| 4. Old approval cannot cross a control switch | Scratch verify recorded a real exact-head review and policy check, accepted the current generation, then rejected that evidence with a synthetic successor on the same head. `request::tests::control_approval_is_bound_to_the_supplied_bot_and_generation` covers reviewer identity. The separate scratch probe rejected the old identity after A→B→A. | The synthetic successor and probe are not a production activation PR merge. |
| 5. Normal publication, activation validation, and distribution | `distribution::tests::verified_publication_can_be_carried_into_promotion_validation` carries one verified publication result into a successor descriptor and the real promotion-validation boundary. Publication retry/immutable-release and activation-evidence tests cover positive paths. Scratch verify passed generated caller-file equality, signed PR checks, and required CI. | The composed test uses mock API routes and archive bytes. No single live path published, merged a production descriptor, and distributed that publication to callers. |

## Scratch evidence

The executed source and workflow revision was
`f540cd7dd5854298ff30c8b54356936e05a21ae7`. The first documentation/test-only successor was
`681a44a94e04a714fcc719cf1374929e14065b84`, whose production files were unchanged
from that tested revision. The pre-merge compatibility correction described below
subsequently changes the Rust and fixed bootstrap settings validators; the corrected runtime source is
`5f2997bd59f2f06a260dfe353310d4fbc1d43a55`. Later documentation-only clarifications
leave that production code unchanged; run identities and results are recorded in the
PR description.

- [Prepare 38881231411](https://github.com/civitaspo/securefix-server/actions/runs/38881231411): **success**. `scratch-fixtures` artifact **12037104874** and `control-probe` artifact **12038230883**.
- [Verify 38881750974](https://github.com/civitaspo/securefix-server/actions/runs/38881750974): **success**, reusing that prepare state. `scratch-fixtures` artifact **12037723314** contains `state.json` and `verification.json`; `control-probe` artifact **12037783176** contains `control-verification.json`.
- Both runs' artifact ZIP digests were checked against GitHub API metadata before their JSON was inspected. Candidate SHA and workflow SHA matched the frozen revision.
- Positive PR **176**, exact head `b149e90306ef62f0c972d75458f6a380b525a026`, merged as `34ede6d75f400e5055e5f626c83b4423d9d64678`. Stale PR **178** was rejected after its head changed. Distribution fixture PR **179** passed generated-file and CI validation.
- The probe recorded `source_advance_kept_descriptor`, `expected_head_conflict_rejected`, and `stale_identity_rejected_after_aba` as true. Its production publication, production activation, and distribution flags are explicitly false.
- Native auto-merge was rejected in the scratch verification. Disposable fixture branches, owner fixture PR **171**, run labels, the frozen source branch and its environment branch policy were removed. The four preexisting active handlers and `allow_auto_merge=true` were restored; preexisting release-sync remained disabled and PR **105** remained open.

An earlier prepare failed because the new local installer step lacked checkout. The
installer now uses the existing pinned-action form, and both control probes mount the
adjacent policy file; regression tests cover both. An earlier verify run
[38880655146](https://github.com/civitaspo/securefix-server/actions/runs/38880655146)
failed closed because the operator followed an incorrect marker in the draft guide.
The guide and a regression test now require
`<!-- securefix:control-review:<control-id> -->`. The successful fresh runs above
supersede those failed rehearsals. See the [integration guide](integration-testing.md)
for artifact download paths and the owner commands.

During the original unmerged proposal, production main remained
`e8e2bc77d96a4e359417217f1d1c22f4e1ac4483`; no production merge, publication,
activation, permanent settings rollout, or ruleset exception was performed. The
existing completed nine-repository distribution was preserved.

## Pre-merge API compatibility correction

After the owner authorized merge, live rollout preflight found that GitHub REST omits
`parameters` from an update restriction even after writing an explicit
`update_allows_fetch_and_merge=false`. An independent GraphQL read of that same rule
reported `updateAllowsFetchAndMerge=false`. Both the Rust validator and the fixed
bootstrap helper now accept exactly the omitted-default form or the explicit-false
form. Regression cases reject true, numeric zero, null, empty parameters, unknown
fields, extra rules, and alternate bypass actors or modes.

This correction keeps the update restriction and the exact sole Server App PR bypass.
The permanent merge prerequisites cover all ten policy repositories, including scratch;
the nine existing production controlled-merges rulesets lose Renovate bypass, while
scratch receives the same restriction. Native auto-merge is disabled, merge/rebase
methods are disabled, queued native requests are absent, and server immutable releases
are enabled. These are the reviewed migration settings applied under the owner's new
merge authorization; they are not temporary exceptions. The earlier scratch cleanup
record describes its original restored state before this permanent rollout.

## Review and remaining conditions

Code and evidence reviews used the same model family; they do not provide independent
human security assurance. The owner subsequently authorized merge; the normal exact-
head approval and required checks still apply.

The permanent settings rollout described above is complete. Every operational lane
checks this configuration before performing mutations.

The protected-main `phase=bootstrap` scratch gate is necessarily post-merge and remains
unexecuted. It must pass during the finite bootstrap pause before initial publication
or descriptor activation is proposed. The old v0.2.20 runtime is not claimed to remain
available after that first main advance. The bounded repair lane excludes
`control-bootstrap.yml` and `scripts/control-bootstrap.py`; a defect in that authority
needs separately reviewed recovery. Invalid/missing active descriptors, missing release
assets, failed attestation, and unavailable required GitHub services still fail closed.

Production bootstrap publication, descriptor activation, concurrent switch/merge races,
and the full publication→activation→caller-distribution chain remain **unverified**.
After activation, callers still need reviewed pin-migration PRs; unmigrated callers may
remain paused. No temporary ruleset exception is part of the proposed routine recovery.
