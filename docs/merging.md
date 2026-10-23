# Approval and merging

Post the complete comment `/approve` or `/merge` on an open, non-draft PR targeting its repository's default branch.
Owner user ID `4525500` can authorize both commands. The separately configured Renovate bot may request `/merge` on its own PRs as described below; it cannot issue owner authorization or `/approve`.
The accepted head is the SHA observed by the intake workflow, which can run after the comment was posted.
If that head changes, resolve the failure and post a new command.
When automatic approval rejects a sensitive change, post `/approve` before `/merge` to obtain the bot review for that head; `/merge` still waits for a counted approval.

Automatic approval remains available to configured trusted actors for ordinary changes.
The server checks every source commit's verified signature and committer identity.
GitHub web commits additionally require the exact commit's GraphQL proof of a valid GitHub signature and a trusted author; a missing committer identity is rejected.
Fork PRs are rejected.
Missing, truncated, unsigned, or mismatched commit lists fail closed.
Sensitive paths in [`policy.json`](../policy.json), including dependency manifests and workflow/build configuration, require an owner command for the same head unless the author and every effective committer satisfy `sensitive_path_approval_exemptions`.
The deployed policy exempts Renovate by its exact bot ID/login. `trusted_committers` alone is insufficient. This exemption skips only owner authorization; signatures, current-head approval, provenance, and required checks remain mandatory.
Renames inspect both the current and previous path.
Every change in the server repository is sensitive.

## Request proof

Generated client wrappers are `.github/workflows/approve-request.yml` and `.github/workflows/merge-request.yml`.
They call the corresponding reusable at the source SHA selected by the active control revision.
Client callers grant `actions: read`, `contents: read`, `attestations: read`, `issues: read`, and `pull-requests: read`, and pass `SECUREFIX_CLIENT_PRIVATE_KEY`.
The Client App creates a server label whose description is only `civitaspo/<repository>/<run ID>`.
The versioned manifest travels as an immutable source-run artifact.
The server revalidates an explicit owner or Renovate command and its PR before adding a 🚀 reaction. For client calls, the caller's `GITHUB_TOKEN` remains read-only; the Server App uses its existing operation-scoped token for the reaction. Automatic PR-event approval has no command to acknowledge. The generated approval caller ignores unrelated issue comments; Rust still validates the exact owner command.

The server's own approve and merge wrappers call local reusable workflows at the same main revision. The processor verifies the local wrapper reference and matching Actions `referenced_workflows` revision. Generation eight at `v0.2.44` has removed the generation-six compatibility declarations: both wrappers and both reusable capture jobs grant Issues and PullRequests read access. The exact-source qualified publication supplies the final read-only external caller templates. See the [permission migration evidence](client-request-permission-verification-2026-10-21.md) for activation, rollout and the separate automatic PR-target limitation.

The Rust processor verifies the Client App sender ID/type, repository capability and ID, successful first attempt, event/path, default-branch ancestry, wrapper pin and Actions `referenced_workflows`, artifact identity, and manifest fields.
The request captures the full active control identity. A changed identity invalidates the request even when the runtime source remains an ancestor of `main`.
Edited or deleted command comments, reruns, expired requests, terminal receipts, head/base changes, and later force-push, close/reopen, or draft/ready transitions invalidate merge requests.
Timeline events within the acceptance second are treated conservatively.

## Exact-head protection

Owner commands create a Server App receipt identifying the accepted head, full active control identity, and command comment.
Approval uses the machine-user PAT only after validation and explicitly sends the accepted `commit_id` to GitHub.
The machine user's identity must be `civitaspo-bot`, and it cannot approve its own PR.
Only a non-author approval for the current head counts; a reviewer's later dismissal or change request supersedes an earlier approval.

The separate `policy-check.yml` Client wrapper calls `reusable-policy-check.yml` on `pull_request_target` events. That reusable captures and attests a native policy-check request, then dispatches its exact label to the configured Server instance. The caller grants `actions: read`, `contents: read`, `pull-requests: read`, `attestations: write`, and `id-token: write`; the Client App token is scoped to the Server repository and only receives `issues: write`.
The Server App alone publishes the stable required `securefix-policy-check` result for that SHA; its check metadata binds the full active control identity, and merge validation requires that identity for the same head.
It verifies source signatures, sensitive-path owner authorization, and current-head approval.
Approval and merge authorization can refresh that check after an owner command.
The default-branch ruleset binds this check to Server App ID `3872533` and dismisses stale reviews.
Thus a green check and approval for head A do not authorize sensitive head B, including Renovate direct merges.

For the external-config instance path, `securefix-native-request-policy-check` uses `native:v1:<head>:<authority SHA-256>:<request SHA-256>` as its external identity. Each authenticated fresh request creates a new check; an existing check for that exact request rejects replay. Previous authority results remain unchanged and cannot authorize the current authority. Both publication and merge read every page with `filter=all`, validate counts and reject duplicate check IDs.

Merge selects the greatest check-run ID among results for the exact head, configured App and current authority. The ID orders creation, independent of completion time and API list order. A newer failed or incomplete request blocks merge even if an earlier request succeeded. A request-only legacy scratch result never satisfies the instance authority check. Fresh owner commands and authority-bound approval are still required after configuration or Server placement changes; the writer revalidates authority, head, checks and approval immediately before writing.

## Merge readiness

The server waits up to 60 minutes from the manifest's fixed acceptance time.
Before every merge attempt it rechecks the exact head, comment, timeline, signatures, authorization, current-head review, and full active control identity.
`status-check` must come from GitHub Actions App ID `15368`; a completed success or skipped result is accepted to preserve existing client aggregate workflows.
`securefix-policy-check` must come from the Server App with a completed success.
Duplicate matching policy check runs, pending checks, and missing approvals cannot pass.
GitHub's GraphQL review decision must also be `APPROVED`.
Immediately before the merge request, the processor rereads the configured required checks, the authority-bound policy result, the latest exact-head approval marker and review ID, and GraphQL's review decision; it compares them with the accepted merge fence.

The contents-write token is created after readiness succeeds and is scoped to the target repository.
The Merge API receives the accepted SHA as its optimistic precondition.
HTTP 405, 422, and 503 retry within the same deadline after full revalidation; head conflicts fail immediately.
The squash body retains the PR description and unique co-author trailers.
For ordinary PRs, GitHub's review/check rules remain active and the Rust processor independently checks the review and required statuses before calling the Merge API. The controlled-merge rulesets name only the Server App with pull-request-only bypass; the dedicated repository-settings flow verifies that exact actor and mode. The bypass does not authorize a merge by itself: all protected mutations pass through the serialized server Actions lane and its Rust owner, review, check, exact-head, and control-identity checks. Runtime distribution opens reviewable caller PRs. Renovate uses comment requests, and the Server App performs their validated merges. Native auto-merge remains disabled.
Comment/timeline reads and the Merge API are separate requests, so timeline visibility can lag; the SHA precondition prevents merging a different head.

The Server App needs `actions: read`, `checks: write`, `statuses: read`, `contents: write`, `issues: write`, and `pull requests: write` on clients.
Workflows narrow tokens by operation. The policy-result token is scoped to the target repository with `checks: write`, `issues: write`, and `pull requests: write` for check publication, PR failure comments, and hiding obsolete comments; it has no contents-write permission.
Source-read tokens are read-only; authorization and notification tokens do not receive contents-write permission.
Successful client merges receive a completion comment with the squash SHA and Server run URL. Notification failure cannot retry a successful merge or request a Renovate rebase. Successful server self-merges skip post-merge notification because an activation can change the active control identity; the old runtime must not write after that change.

## Renovate requests

For ordinary instance-bound merge roles, optional `[identities.renovate_merge_bot]` in the protected external instance TOML identifies one exact Bot account by immutable ID and login; omission disables bot merge requests. The identity must be a trusted committer and remains separate from sensitive-path approval exemptions. The generic executable contains no compiled deployment bot identity, and the predecessor `policy.json` schema remains unchanged. A new, unedited `/merge` comment must come from the configured Bot account and trigger a successful first-attempt intake run by the same account. The current PR author must be that bot, the PR must be open, ready, same-repository and target the default branch, and every effective committer must match the bot. Verified GitHub web commits retain the additional GraphQL signature proof. This request never creates owner authorization.

The normal signature, sensitive-path policy, current-head review, required checks, timeline, expiry, replay and expected-head conditions apply throughout authorization, wait and apply. A bot merge request alone does not exempt sensitive paths; the separately configured author/committer exemption must still hold, or real owner authorization is required.

Each bot merge request also dispatches `approve-request-renovate-<source-run-id>` through the existing approval workflow. It validates the merge intake's own provenance and separate bot authorization, reruns the same own-PR, signature, effective-committer and sensitive-path checks, then refreshes the configured review account's approval for the exact head and current control. Both approve and merge capabilities are required. The review credential stays in the approval job, and no owner receipt is created. This lets a fresh Renovate request recover after a control change even when the existing head's review belongs to an older generation. Owner merge commands cannot use this automatic-review route.

Repositories use Renovate's [pr-comment automerge mode](https://docs.renovatebot.com/configuration-options/#automergetype), `automergeComment: "/merge"` and `platformAutomerge: false`. Eligible non-major and lockfile rules enable automerge; major rules keep it disabled. Renovate decides whether to submit a request under its repository rules and check results. The server validates that request rather than interpreting dependency changes or granting native merge access.

After an authorized Renovate merge attempt fails, the inline merge notifier may request one rebase for that PR. This covers failures in the wait or apply stages, including failed checks and timeouts. It does not run when initial authorization fails, and it does not retry a failed CI check before Renovate has requested `/merge`.
Cancelled runs and failures that prevent the notifier from starting do not request a rebase.

Before adding the standard `rebase` label, the notifier requires the accepted request to remain bound to the current active control and exact accepted head. It confirms that the PR is open, ready, in the same repository, targets the default branch, and is authored by the configured Renovate bot. It also verifies every commit signature and that each effective committer matches the configured Renovate bot, then rechecks the sensitive-path policy. A human-modified branch and signature, authorization, or policy failures do not qualify. Failed checks and wait timeouts qualify only after initial authorization succeeded and these current checks still pass.

The notifier records a durable Server App marker for the exact PR before it adds the label. The marker limits the rebase request to once per PR lifetime, even when the head or `/merge` comment changes. If the process stops after writing the marker but before adding the label, the allowance is spent; an operator can still request a manual Renovate rebase and retry. Recovery writes run in the existing `securefix-control` group, which serializes them with other protected mutations. The notifier does not delete the existing `/merge` comment. It adds no periodic scan, workflow, secret, or administrator credential.

The request's 60-minute expiry still prevents a later merge. The same-run accepted manifest may be read after expiry only for notification and recovery checks; that validation does not renew merge authorization. If the active control changes while the merge workflow runs, the old runtime cannot write the marker or label. Submit a fresh merge request under the new active runtime or retry Renovate manually.

Generation eight selects immutable runtime `v0.2.44`; the [2026-10-21 permission migration report](client-request-permission-verification-2026-10-21.md) records exact-source qualification, activation and caller rollout. The [2026-10-18 verification report](renovate-merge-verification-2026-10-18.md) records the earlier generation-four actual Renovate merge and separate scratch retry evidence; it does not certify later runtime changes. The Server App remains the sole controlled-merge bypass actor and native auto-merge remains disabled. Source changes and caller guards alone do not activate a runtime.

## Rollout

Follow [migration.md](migration.md) before activating the full configured set.
No verification-repository environment variable bypasses the exact policy.
The scratch repository and its capabilities must be explicitly configured in the reviewed policy. Candidate integration uses its separate, repository-scoped scratch context; it does not require widening the production allowlist.
The [historical GitHub tests](archive/merge-verification-2026-10-08.md) cover the former implementation and do not certify the Rust path.

Owner `/approve` and `/merge` commands receive a rocket reaction during server approval application or merge authorization, after the server reloads and revalidates the comment identity and exact command. The reaction acknowledges acceptance for processing; it does not mean approval or merge succeeded. A reaction-posting failure does not fail the operation.

A failed `securefix-policy-check` posts one English Server App comment with the rejection reason and a small Server CI/commit reference. Subsequent results hide this App's older marked failure comments as outdated. Success hides the failure history without posting a success comment. Other comments and owner authorization records remain visible. The check itself links directly to the server run that made the decision.

When sensitive-path changes require owner authorization, the rejection explains the policy requirement, lists up to ten matching changed paths (including previous paths for renames), and instructs the owner to post `/approve` for the current PR head. Rebases and force-pushes invalidate authorization for earlier heads. Sensitive-path exemptions and all other authorization checks remain unchanged.

Policy failure comments use wrapping paragraphs and preserve explicit line breaks. Sensitive-path explanations separate the reason, the next action, and one matching file per line; they do not use a horizontally scrolling preformatted block. Error text and filenames remain HTML-escaped.

Failure comments display matching filenames without JSON quotation marks in inline code, as well as standalone `/approve` and `/merge` commands. Filename text is decoded before HTML escaping so unusual characters remain safe.
