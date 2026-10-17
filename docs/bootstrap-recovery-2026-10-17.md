# Proposed one-use bootstrap recovery

Status: implementation prepared for review; production use and settings changes
require separate owner approval of the final executor commit. This branch must
never be merged into main. The previous executor proposed a PR but stopped before
owner review or merge; no protected-main recovery has completed.

## Fixed target

| Identity | Required value |
| --- | --- |
| Repository | `civitaspo/securefix-server` (policy IDs also checked) |
| Current main | `5851ec5f7713357c0edd97355952aae03bdd0051` |
| Source PR | [#95](https://github.com/civitaspo/securefix-server/pull/95), open, owner-authored |
| Target head | `5e6b2e5bb4c9ef38eeb921c700cdca49bccc0524` |
| Target tree | `076564f46be31ae806b609a6f25b766a468b1c0c` |
| Executor branch | `codex/recover-bootstrap-5e6b2e5-20261017` |
| Server App proposal branch | `securefix-bootstrap-recovery-5e6b2e5bb4c9` |
| Executor SHA | Exact signed commit on the executor branch, recorded in the approval request |

The existing repair route rejects changes to its own authority. Ordinary loaders
also stop because the active descriptor is absent. This separate, unmerged
executor can propose and merge only the target above, after qualification and
exact-head owner review. It does not publish, activate, or distribute a runtime.

## Previous stopped attempt and correction

The separately approved executor `ae97fa9e552b9de52413541600659a4622ca090c`
[proposed PR #96](https://github.com/civitaspo/securefix-server/actions/runs/39011910085)
at the former PR #95 head. Both PRs' required CI succeeded. The API returned a
latest `status-check` for each PR suite, and an incorrect uniqueness guard stopped
the operator before review or merge. The temporary branch admission and approval
variable were removed. That executor remains locked without production admission.

The updated target and this executor require at least one trusted matching check,
with every matching latest check completed successfully. Missing, pending, or
failing evidence remains rejected. Normal publication and activation have the same
correction. This new executor SHA requires renewed approval under the original
exact-source gate; the former approval does not cover the changed source.

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
   PR #95 itself cannot receive its author's approval, which is why the identical
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
   PR #95 as superseded only after that verification.

Always remove the new environment deployment-policy ID and Actions variable
after the attempt, including a failed attempt. Re-read environment policies to
confirm only the prior `main` admission remains. Retain the locked executor branch
for audit; it has no production admission or approval variable. Do not remove an
existing policy or overwrite an existing variable. A failed attempt needs renewed
approval after its cause is understood; do not broaden any fence to force it through.

After recovery, rerun the corrected protected-main bootstrap scratch verification,
publication/proposal, exact-head review, and activation before describing normal
Actions as restored. Recovery merge alone leaves the descriptor absent.
