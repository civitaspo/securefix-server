# Pull request merging

Human pull requests merge after an authorized `/merge` comment. Securefix Server checks the request, waits for the required CI and review, then asks GitHub to squash-merge the recorded head SHA.

## Request a merge

Post a comment whose complete body is `/merge` on an open, non-draft pull request that targets the repository's default branch. Only GitHub user ID `4525500` can request a merge. Resolve failed checks or review requests, then post a new `/merge` comment.

The caller workflow runs from `.github/workflows/merge-request.yml` on `issue_comment: created`. It calls the pinned `reusable-merge-request.yml` workflow. The reusable checks the commenter again, saves the repository ID, pull request number, comment ID and update time, head SHA, base branch, acceptance time, and source run ID in a one-day artifact, and creates a `merge-request-<run ID>` label in this repository. The label description contains only `civitaspo/<repository>/<run ID>`.

The caller needs these repository variables:

| Variable | Value |
| --- | --- |
| `SECUREFIX_CLIENT_APP_ID` | `3872492` |
| `SECUREFIX_SERVER_REPOSITORY` | `securefix-server` |

The caller also needs the `SECUREFIX_CLIENT_PRIVATE_KEY` repository secret. The Client App needs `issues: write` on `civitaspo/securefix-server` to create the request label. The reusable workflow needs caller permissions `contents: read`, `issues: read`, and `pull-requests: read`.

## Server validation

The server accepts requests only from repositories in [`repo-settings/allowlist.json`](../repo-settings/allowlist.json). A separate verification repository can be enabled by setting the `MERGE_VERIFICATION_REPOSITORY` variable in the `main` environment to its exact `civitaspo/<repository>` name. An unset variable denies every extra repository. Remove the variable after testing.

The label event must come from the Client App bot account ID `288068203`, and the server workflow itself must be on its first attempt. The server then validates the source run through the Actions API. The run must use `.github/workflows/merge-request.yml`, originate from `issue_comment` on the default branch, complete successfully on its first attempt, and remain an ancestor of the current default branch. The source wrapper must contain exactly one full-SHA call to the Securefix reusable workflow, and the run's `referenced_workflows` record must report that same path and SHA. The reusable SHA must be an ancestor of the server's default branch. Previously reviewed SHAs on that branch remain valid, so normal wrapper version bumps need no central variable update.

The server checks its own Actions run history for the source run ID before downloading its artifact, so a deleted terminal comment cannot make a request reusable. It rejects expired, missing, duplicate, oversized, malformed, or replayed request records. A terminal receipt counts only when authored by the Server App bot account ID `288069019`. It reads no pull request files and executes no pull request code.

Before and during the wait, the server checks that the request comment still has the exact body and update time, that the pull request remains open and targets the same default branch, and that the head SHA still matches. It also rejects force-push, branch deletion, retargeting, merge, close/reopen, and draft/ready transitions recorded after acceptance, even if the pull request is restored to its original state. GitHub timeline timestamps have second precision, so an invalidating event in the acceptance second also expires the request conservatively. The required aggregate check is named `status-check`. Review readiness requires GitHub's `reviewDecision` to be `APPROVED`.

The wait ends when both conditions pass or 60 minutes have elapsed from the artifact's original acceptance time. The server checks every 30 seconds. Replays and workflow reruns do not extend that deadline. The per-pull-request job concurrency group prevents two requests for the same pull request from merging at once.

## Merge and limits

After readiness, the server creates a short-lived App token for the target repository. It sends the recorded head SHA and `squash` method to GitHub's Merge API. It omits `commit_title`, so GitHub uses the repository's `PR_TITLE` setting. The commit body contains the pull request description and unique `Co-authored-by` trailers from its commits.

GitHub remains the final authority for branch rules. The Merge API's SHA condition prevents merging a different head. Timeline and comment checks are not atomic with the merge request, and API event visibility can lag. A force-push followed by a return to the original SHA is rejected when its timeline event is visible.

The server posts a terminal result comment with the merge SHA or a request to post a fresh comment. It deletes the one-time request label. Server run failures before the request artifact has been validated are available in the server Actions run and do not produce a comment on the source pull request.

The Securefix Server App installation needs `actions: read`, `checks: read`, `commit statuses: read`, `contents: write`, and `pull requests: read/write` on client repositories. The workflow narrows source-read and merge tokens to one target repository. Source-read tokens receive only `contents: read`. Only the post-readiness token receives `contents: write`.

## Verify before rollout

Use a public scratch repository that is not in the production allowlist. Install both Apps and set `MERGE_VERIFICATION_REPOSITORY` in the server's `main` environment to that exact repository name. Pin the scratch workflow to a reviewed Securefix Server commit that is on its default branch. Exercise unauthorized comments, edited and deleted comments, reruns, replayed labels, changed heads, force-push-and-return, pending checks, pending review, timeout, and a successful squash merge. Confirm that direct pushes and merges without the required checks or review still fail under the repository rulesets.

Remove `MERGE_VERIFICATION_REPOSITORY` after testing. Keep production merge controls disabled until the real App permissions and scratch-repository merge path pass.

## Verification evidence

The following checks ran against the public `civitaspo/securefix-merge-verification` repository on October 8, 2026. Normal merges and App protection probes used separate, active `default-branch` and `controlled-merges` rulesets with native auto-merge disabled. The production distribution gate remained disabled.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Authorized `/merge` | Server App merged the recorded head, retained the description and unique Codex trailer, and deleted the request label. The squash commit was verified and its subject included `(#2)`. | [Server attempt 1](https://github.com/civitaspo/securefix-server/actions/runs/37715004379/attempts/1), commit `ac38b2c1c1b74e4d6c072ea471c5708237864ed6` |
| Human merge after successful CI and approval | Merge API rejected the protected-ref update. | [Scratch PR3](https://github.com/civitaspo/securefix-merge-verification/pull/3) |
| Forged request label | Rejected before any App token was issued; cleanup removed the label. | [Server run](https://github.com/civitaspo/securefix-server/actions/runs/37623214655) |
| Force-push followed by return to accepted SHA | Timeline validation rejected the request before creating a merge token. | [Server run](https://github.com/civitaspo/securefix-server/actions/runs/37715212665) |
| Comment edited and restored to `/merge` | Changed update time invalidated the request before creating a merge token. | [Server run](https://github.com/civitaspo/securefix-server/actions/runs/37715300466) |
| Workflow reruns | Intake attempt 2 was skipped; server attempt 2 was rejected before merge. | Source run `37713677192`, [Server attempt 2](https://github.com/civitaspo/securefix-server/actions/runs/37715004379/attempts/2) |
| Ordinary Actions direct push and merge | A `GITHUB_TOKEN` with write permissions received protected-ref rejection for both operations. The push candidate was ahead of main and `force` was false. | [Scratch CI](https://github.com/civitaspo/securefix-merge-verification/actions/runs/37716442878) |
| Server App direct push and missing-review merge | Its repository-scoped write token received protected-ref rejection for direct push and required-review rejection for PR4. It then merged the ready PR7 normally. | [Server run](https://github.com/civitaspo/securefix-server/actions/runs/37716555848), commit `5b72f5de4fbad9d148b5045794c9d6c6d0036d13` |
| Renovate automerge | Renovate created the `minimist` patch update from `1.2.7` to `1.2.8`, waited for CI and approval, and squash-merged it as `renovate[bot]`. The verified commit subject included `(#6)` and retained the Renovate trailer. | [Scratch PR6](https://github.com/civitaspo/securefix-merge-verification/pull/6), commit `5a07ead77537a92506ae2d17ef1b12fd7ded09d5` |
| Scratch repo-settings dispatch | Existing distribution accepted the bot invitation; bot access read back as `write`. | [Settings run](https://github.com/civitaspo/securefix-server/actions/runs/37714481583) |

The scratch checks exposed three runtime adapter defects, fixed in [PR46](https://github.com/civitaspo/securefix-server/pull/46), [PR47](https://github.com/civitaspo/securefix-server/pull/47), and [PR48](https://github.com/civitaspo/securefix-server/pull/48). The pinned github-script action requires `core.summary.addRaw` and the runner's `GITHUB_RUN_ATTEMPT`; the App-token action requires the input `permission-statuses`. The workflow fixture suite has 38 passing tests. Those tests are separate from the live evidence above.

The temporary Server App probe was restricted to scratch PR7 and removed after its successful run. It reused the existing post-readiness token without exporting credentials or adding a service.

The full rollout is not yet verified. Remaining live checks include isolated failed-CI and unsigned-commit rejection, Renovate direct-push rejection and preservation of production exclusions, the fixed 60-minute deadline, release PR merging, and repeated controlled-merges distribution without drift. Artifact forgery and final-head races have fixture coverage, but the entire negative matrix has not run against GitHub. Keep the production gate disabled until the remaining checks and client-pin updates are complete.
