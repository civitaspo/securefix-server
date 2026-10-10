# Approval and merging

Post the complete comment `/approve` or `/merge` on an open, non-draft PR targeting its repository's default branch.
Only owner user ID `4525500` can authorize these commands.
The accepted head is the SHA observed by the intake workflow, which can run after the comment was posted.
If that head changes, resolve the failure and post a new command.
When automatic approval rejects a sensitive change, post `/approve` before `/merge` to obtain the bot review for that head; `/merge` still waits for a counted approval.

Automatic approval remains available to configured trusted actors for ordinary changes.
The server checks every source commit's verified signature and committer identity.
GitHub web commits additionally require the exact commit's GraphQL proof of a valid GitHub signature and a trusted author; a missing committer identity is rejected.
Fork PRs are rejected.
Missing, truncated, unsigned, or mismatched commit lists fail closed.
Sensitive paths in [`policy.json`](../policy.json), including dependency manifests and workflow/build configuration, require an owner command for the same head.
Renames inspect both the current and previous path.
Every change in the server repository is sensitive.

## Request proof

Client wrappers are `.github/workflows/approve-request.yml` and `.github/workflows/merge-request.yml`.
They call the corresponding reusable at a full current server SHA.
The caller grants `contents: read`, `attestations: read`, `issues: read`, and `pull-requests: read`, and passes `SECUREFIX_CLIENT_PRIVATE_KEY`.
The Client App creates a server label whose description is only `civitaspo/<repository>/<run ID>`.
The versioned manifest travels as an immutable source-run artifact.

The Rust processor verifies the Client App sender ID/type, repository capability and ID, successful first attempt, event/path, default-branch ancestry, wrapper pin and Actions `referenced_workflows`, artifact identity, and manifest fields.
An older server revision is rejected even if it remains an ancestor of `main`.
Edited or deleted command comments, reruns, expired requests, terminal receipts, head/base changes, and later force-push, close/reopen, or draft/ready transitions invalidate merge requests.
Timeline events within the acceptance second are treated conservatively.

## Exact-head protection

Owner commands create a Server App receipt identifying the accepted head and command comment.
Approval uses the machine-user PAT only after validation and explicitly sends the accepted `commit_id` to GitHub.
The machine user's identity must be `civitaspo-bot`, and it cannot approve its own PR.
Only a non-author approval for the current head counts; a reviewer's later dismissal or change request supersedes an earlier approval.

The separate `policy-check.yml` client wrapper calls `reusable-policy-check.yml` on PR-target events and default-branch pushes, granting `contents: read`, `attestations: read`, `actions: read`, and `pull-requests: read`.
The Server App alone publishes the stable required `securefix-policy-check` result for that SHA.
It verifies source signatures, sensitive-path owner authorization, and current-head approval.
Approval and merge authorization can refresh that check after an owner command.
The default-branch ruleset binds this check to Server App ID `3872533` and dismisses stale reviews.
Thus a green check and approval for head A do not authorize sensitive head B, including Renovate direct merges.

## Merge readiness

The server waits up to 60 minutes from the manifest's fixed acceptance time.
Before every merge attempt it rechecks the exact head, comment, timeline, signatures, authorization, current-head review, and active server revision.
`status-check` must come from GitHub Actions App ID `15368`; a completed success or skipped result is accepted to preserve existing client aggregate workflows.
`securefix-policy-check` must come from the Server App with a completed success.
Duplicate matching policy check runs, pending checks, and missing approvals cannot pass.
GitHub's GraphQL review decision must also be `APPROVED`.

The contents-write token is created after readiness succeeds and is scoped to the target repository.
The Merge API receives the accepted SHA as its optimistic precondition.
HTTP 405, 422, and 503 retry within the same deadline after full revalidation; head conflicts fail immediately.
The squash body retains the PR description and unique co-author trailers.
For ordinary PRs, GitHub's review/check rules remain active and the Rust processor independently checks the review and required statuses before calling the Merge API. A separate review/check ruleset grants the Server App pull-request-only bypass used by the runtime distributor; the default-branch integrity ruleset remains bypass-free and requires signatures, linear history, pull-request-only changes, and deletion/non-fast-forward protection. GitHub's bypass applies to any PR the Server App merges, not only PRs authored by that App. The distributor's Rust fast path is restricted to its validated canonical managed-file PR; other Server App merge paths retain the normal Rust review and check gates. Renovate is not an actor in that bypass list, so its own native auto-merge still has to satisfy required checks.
Comment/timeline reads and the Merge API are separate requests, so timeline visibility can lag; the SHA precondition prevents merging a different head.

The Server App needs `actions: read`, `checks: write`, `statuses: read`, `contents: write`, `issues: write`, and `pull requests: write` on clients.
Workflows narrow tokens by operation.
Source-read tokens are read-only; authorization and notification tokens do not receive contents-write permission.

## Rollout

Follow [migration.md](migration.md) before activating the full configured set.
No verification-repository environment variable bypasses the exact policy.
A scratch repository must be explicitly added to a reviewed temporary capability policy.
The [historical GitHub tests](archive/merge-verification-2026-10-08.md) cover the former implementation and do not certify the Rust path.

Owner `/approve` and `/merge` commands receive a rocket reaction after the trusted request runtime validates the comment identity and exact command. The reaction acknowledges receipt for processing; it does not mean approval or merge succeeded. It appears when the Actions runner starts the capture step after loading the CLI.

A failed `securefix-policy-check` posts one English Server App comment with the rejection reason and a small Server CI/commit reference. Subsequent results hide this App's older marked failure comments as outdated. Success hides the failure history without posting a success comment. Other comments and owner authorization records remain visible. The check itself links directly to the server run that made the decision.
