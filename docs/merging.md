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

The Securefix Server App needs `actions: read`, `checks: read`, `commit statuses: read`, `contents: read`, and `pull requests: read/write` on client repositories. The workflow narrows source-read and merge tokens to one target repository. Only the post-readiness token receives `contents: write`.

## Verify before rollout

Use a public scratch repository that is not in the production allowlist. Install both Apps and set `MERGE_VERIFICATION_REPOSITORY` in the server's `main` environment to that exact repository name. Pin the scratch workflow to a reviewed Securefix Server commit that is on its default branch. Exercise unauthorized comments, edited and deleted comments, reruns, replayed labels, changed heads, force-push-and-return, pending checks, pending review, timeout, and a successful squash merge. Confirm that direct pushes and merges without the required checks or review still fail under the repository rulesets.

Remove `MERGE_VERIFICATION_REPOSITORY` after testing. Keep production merge controls disabled until the real App permissions and scratch-repository merge path pass.
