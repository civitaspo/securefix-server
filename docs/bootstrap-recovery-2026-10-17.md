# Proposed one-use bootstrap recovery

Status: implementation prepared for review; production use and settings changes
require separate owner approval of the final executor commit. This branch must
never be merged into main. The previous approved recovery completed PR #97 and
removed its temporary admission and source variable. This new source fixes a
separate failure found in the required post-merge bootstrap scratch gate.

## Fixed target

| Identity | Required value |
| --- | --- |
| Repository | `civitaspo/securefix-server` (policy IDs also checked) |
| Current main | `51eba48c73fce56b1c7dcc7acd53bc58da6cc099` |
| Source PR | [#98](https://github.com/civitaspo/securefix-server/pull/98), open, owner-authored |
| Target head | `82cedf43e3a8ea285290f795197bf70fda1c5191` |
| Target tree | `3719e4ef351778c326335beccb01e1533033e2a6` |
| Executor branch | `codex/recover-bootstrap-82cedf4-20261017` |
| Server App proposal branch | `securefix-bootstrap-recovery-82cedf43e3a8` |
| Executor SHA | Exact signed commit on the executor branch, recorded in the approval request |

The existing repair route rejects changes to its own authority. Ordinary loaders
also stop because the active descriptor is absent. This separate, unmerged
executor can propose and merge only the target above, after qualification and
exact-head owner review. It does not publish, activate, or distribute a runtime.

## Previous completed recovery and new correction

The separately approved executor `fcb447c4fabf48023dab26079e6d2e8cb0ece37a`
[merged PR #97](https://github.com/civitaspo/securefix-server/actions/runs/39014362215)
as `51eba48c73fce56b1c7dcc7acd53bc58da6cc099`. The resulting tree and signature
were verified, its temporary environment admission and approval variable were
removed, and its executor branch remains locked. Superseded PRs #95 and #96 closed.

The exact-main [scratch run 39014510834](https://github.com/civitaspo/securefix-server/actions/runs/39014510834)
passed candidate verification, then its final v0.2.20 output validator rejected
the newer main SHA. The legacy validator requires its own old source on main.
PR #98 uses the fixed Rust bootstrap host for final bounded output validation,
retaining the owner/current-main/inactive-descriptor fence, strict schemas,
fixture and control-generation bindings, and independent legacy archive verification.
All fixtures were cleaned and all scratch handlers restored. Production publication,
activation and distribution have not occurred. This new executor SHA requires renewed
approval under the original exact-source gate; the former approval was source-specific.

## Evidence required before production authorization

1. Review the executor delta from the target head, including its workflow, Rust
   module, and fixed authorization JSON. Retain the final signed commit SHA.
2. Complete required CI on that exact executor SHA and retain the run URL.
3. Dispatch `control-bootstrap.yml` on the executor branch with
   `phase=recovery-qualify` and `authority_sha=<exact executor SHA>`. This phase
   compiles the host without production credentials, transfers only its immutable
   artifact ID, and checks current main, absent descriptor, owner dispatch/run
   provenance, branch head, both signed CI sources, target tree, and signed ancestry.
   Its writer job is skipped. Retain the run URL and qualification result.
4. Obtain explicit owner approval of that exact executor SHA, fixed target,
   settings changes below, bot PR proposal, exact-head review, and recovery merge.
   A passing qualification run does not grant production authority.

## Separately authorized settings and execution

Use the existing repository administrator context only for these settings.
The Server App and executor do not receive Administration permission or credentials.

1. Re-read the executor branch and expected main; stop if either SHA changed.
2. Lock only the executor branch with branch protection: `lock_branch=true`,
   `enforce_admins=true`, `allow_force_pushes=false`, `allow_deletions=false`,
   `allow_fork_syncing=false`; leave required checks/reviews and restrictions
   null for this new read-only branch. Check the returned protection and exact SHA.
   [GitHub's branch protection API](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection)
   defines this read-only lock. Do not alter main protection or any ruleset.
3. Add one branch deployment policy to the existing `main` environment, naming
   only the executor branch above. Preserve the existing `main` policy, secrets,
   and protection settings. Record the new deployment-policy ID for cleanup.
4. Create repository Actions variable `SECUREFIX_RECOVERY_SOURCE_SHA` with the
   approved full executor SHA. Stop if a variable with that name already exists.
   Both the writer job guard and Rust entry points require this out-of-band pin.
5. Dispatch `phase=recovery-propose`, `authority_sha=<approved executor SHA>`.
   The read-only job must succeed before the `main`-environment writer starts.
   The writer revalidates all inputs and its server-only App token, creates or
   reuses only the fixed target branch, and opens a Server App-authored PR with
   the identical target head/tree. It never executes target code.
6. Verify that proposal's target head, base, author, and required CI. Under the
   explicit owner authorization, submit an owner approval on that exact head.
   PR #98 itself cannot receive its author's approval, which is why the identical
   Server App proposal is needed. Do not transfer an approval to a changed head.
7. Separately dispatch `phase=recovery-merge`, the same `authority_sha`, and the
   proposal's `pull_request` number. It repeats qualification and requires the
   latest owner review to approve the exact target head. The App performs only a
   squash PR merge with that head SHA, serialized by `securefix-control`.
   The writer rechecks expected main and absent descriptor immediately before
   each write. The existing merge API has PR-head CAS; expected main is an
   application fence under the shared lane, not an atomic GitHub base-SHA CAS.
8. Verify the resulting main tree equals the fixed target tree and its commit
   signature is valid. The changed main permanently stops this executor. Close
   PR #98 as superseded only after that verification.

Always remove the new environment deployment-policy ID and Actions variable
after the attempt, including a failed attempt. Re-read environment policies to
confirm only the prior `main` admission remains. Retain the locked executor branch
for audit; it has no production admission or approval variable. Do not remove an
existing policy or overwrite an existing variable. A failed attempt needs renewed
approval after its cause is understood; do not broaden any fence to force it through.

After recovery, rerun the corrected protected-main bootstrap scratch verification,
publication/proposal, exact-head review, and activation before describing normal
Actions as restored. Recovery merge alone leaves the descriptor absent.

## Optional continuation scope for the owner to authorize explicitly

To avoid splitting the remaining rollout into repeated authorization requests, the
owner may authorize the following sequence together with the exact recovery above.
These steps do not inherit authority from the prior recovery-only approval.

1. On the resulting signed main with the exact target tree above, run the corrected
   protected-main `phase=bootstrap` scratch gate. Restore its isolated handlers and
   clean fixtures whether it succeeds or fails. Stop publication if it fails.
2. If it succeeds and required main CI is successful, dispatch the existing protected-main
   `control-bootstrap.yml` `phase=propose` with that exact successful verification run.
   Independently qualify archive/attestation/policy and publish only the new immutable
   `v0.2.22` release from that signed source. Never overwrite a published version.
3. Verify the resulting signed generation-one PR changes only `control/active.json`,
   source and policy/archive digests match the verified candidate, release/asset and
   publisher/verification IDs match their evidence, previous identity is zero, and all
   required CI passes. Under explicit authorization for this sequence, submit owner
   review of only that exact head. Separately dispatch `phase=merge` with the expected
   main SHA, exact head, PR number and full descriptor identity. Stop on any mismatch.
4. Verify the signed activated descriptor and the actual published-release client loader
   through the documented scratch prepare/verify phases. Verify ordinary Policy Check
   and repository-settings workflows through their existing runtime-loading lanes.
5. Explicitly dispatch `distribute-runtime.yml` for that verified bootstrap publisher
   run and inspect all nine configured caller migration PRs, exact generated files and
   required checks. Review each exact head, submit the required owner approval and
   separate `/approve` and `/merge` commands through the normal server lane, and
   verify each resulting default branch pins the activated source. The distributor
   itself still only creates reviewable PRs; these separately authorized reviews and
   merges are subsequent owner operations. Stop any PR with extra files or stale evidence.

No Server App permission expansion, administrator credential in operational lanes,
temporary ruleset exception, runtime fallback, or direct main write is permitted.
Publication, activation and caller migrations must be reported as separate results.
