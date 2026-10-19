> Superseded on 2026-10-19: the owner trusts approved server development source
> and its verified runtime, permits the existing PAT/App authentication in normal
> operations, and withdrew server-wide execution centralization. The split review
> and host/candidate relay below are historical, removed implementation. See
> `testing-workflows-plan.md` → Current direction for the authoritative scope.

# Shared-App testing isolation review

Baseline: `7d94766dccf7231408c3aa7b6137315e5fcd7728`.
Owner decision: share the existing Apps; keep the trusted controller on
`civitaspo/securefix-server`; do not give candidates production keys or credentials.

## Owner threat-model decision (2026-10-19)

The owner trusts securefix-server change management and approved code. Compromise
of that authority or deliberate workflow-based secret retrieval by such code is
outside this test's scope. The Environment move and per-job owner approvals are
rejected, not pending. Keep the existing client repository secret. The historical
GitHub-side exposure and remediation sections below do not block live testing.
Keys, PAT, owner credentials and production-directed tokens must still stay out
of candidate processes; only trusted host code may handle them. Candidate runs
remain in the existing container with test-only scoped tokens. Native Client App
label dispatch and all scenario/provenance/readback requirements remain required.

## Correction: native label ingress remains required (2026-10-19)

Existing callers use `SECUREFIX_CLIENT_PRIVATE_KEY` to mint a Client App token
scoped to `securefix-server` with `issues:write`, then create a server request
label after uploading request artifacts. This Client App authority is distinct
from the Server App's commit/merge authority. A caller-scoped `GITHUB_TOKEN`
cannot replace the cross-repository label token. Server-hosted reusable definitions
also do not automatically supply server repository secrets to their callers.

The previous local secret-free capture plus owner-dispatched processor omitted
this label ingress; the local repair below now restores it. It does not establish normal automatic recovery and does not establish
that the client repository secret is unnecessary. Preserve the existing secret;
no deletion or copy has occurred. The earlier seven-consumers-versus-new-client
question is withdrawn. The remediation discussion below is historical exploration,
not an approved cutover: first inspect a native label-preserving trusted operation
using the existing container boundary. Candidate code must still receive neither
the key nor a server-repository token. The indirect workflow-mutation concern is resolved by the owner-defined scope
above; it does not authorize direct credential access by candidate code.

### Local repair of the omitted ingress

The three native testing reusables now accept the named Client key again, and
canonical testing callers preserve that exact secret forwarding. After candidate
container capture, host validation and upload, a separate dispatch job downloads
the immutable manifest and trusted validator, revalidates the manifest, and its
pinned host token action uses the key to mint only server `issues:write`. Trusted dispatch validates the current
isolated control and emits a testing request label. The candidate's Docker
arguments and explicit environment still exclude the key and server token.

The server testing processor is now a label-created workflow. Before App issuance,
trusted code checks Client App sender ID/login/type, exact server identity,
canonical label, fixed test-client/run locator, first attempt and source/workflow
identity. Existing source-run/artifact/provenance checks are reused. The trusted
User PAT review and container continuation remain separate. Only merges occupy
`securefix-control`; approval and policy processing may finish concurrently.
Trusted cleanup has only an exact testing-label DELETE API path. This repairs
the trigger omission locally; it does not remove the indirect repository-secret
exposure below or establish any hosted scenario.

## What can be reused

The `scratch` job in `.github/workflows/testing-securefix-server.yml` mints Server
and Client installation tokens for the singleton `testing-securefix-server`
repository. Its Docker invocation supplies a fixed environment list and four
mounts: executable, policy, fixture directory and CA certificates. It does not
mount the host home, key material, workflow command files or Docker socket.
The container runs without root, capabilities or a writable root filesystem.

The new controller must preserve that sandbox and token scoping. It must keep the
trusted validator on host PATH: the baseline's host candidate
`resolve-test-runtime` calls and host candidate client Action are not safe to
reuse in a key-holding job. Use containers or credential-free disposable jobs for
every candidate invocation, not just the main `integration run` invocation.

The local `scratch` patch now removes both candidate installations on host PATH
and mounts the downloaded candidate executable/policy directly into the two
container invocations. The trusted runtime performs both tag checks and output
validation. An explicit `chmod` restores the executable permission stripped from
downloaded artifacts. Actionlint passes; this patch has not run on a hosted runner.
The subsequent client-smoke increment replaces host candidate Action execution
with credential-free container CLI staging, bounded host validation and trusted
Client dispatch. It is local implementation and still needs hosted verification.

## Concrete GitHub-side exposure

Read-only queries on 2026-10-19 confirmed:

- Client repository: `civitaspo/testing-securefix-server`, ID `1410312556`.
- Repository secret: `SECUREFIX_CLIENT_PRIVATE_KEY` (name only; updated
  `2026-10-08T13:04:36Z`). No secret value was retrieved.
- Environments: none.
- Baseline scratch token requests include `contents:write` and `workflows:write`.

Inference: a candidate with that workflow-writing authority could create a
workflow in the scratch repository that references the shared Client key.
App-token events can trigger Actions; repository secrets can be supplied to
workflow steps. A container around the API client does not restrict the workflows
that the API token can create. No exploit was executed.

References: [triggering workflows](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow),
[repository secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets),
[environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Existing client key consumers

Inventory at client main `0851bea96e07756a8ee52c5721dba99b8527d13f`:

| Workflow | Trigger / key consumer | Current authority |
| --- | --- | --- |
| `approve-request.yml` | `pull_request_target`, owner `issue_comment`; reusable capture job | Production `reusable-approve-request.yml` |
| `merge-request.yml` | Owner/Renovate `issue_comment`; reusable capture job | Production `reusable-merge-request.yml` |
| `policy-check.yml` | `pull_request_target`, default-branch push; reusable request job | Production `reusable-policy-check.yml` |
| `release-pr.yml` | Default-branch push, dispatch; reusable prepare job | Production `reusable-release-pr.yml` |
| `release-tag.yml` | Merged release PR, dispatch; reusable tag job | Production `reusable-release-tag.yml` |
| `client-app-smoke.yml` | Owner main dispatch; probe job | Client App, singleton scratch repository, metadata read |
| `verify-server.yml` | Dispatch; reusable test workflow | Production `testing-securefix-server.yml` at `97269f5fa9a686d1f130f08b000d1fae867dee55` |

The first five pin production source
`1e2866cbab65c5ef4e218fa6853300c2731e73c0` (`v0.2.33`). None can be
changed merely by editing an environment on this client: reusable job definitions
are immutable at that pin. `release-pr-sync.yml`, `ci.yml`,
`fixture-validation.yml`, `runtime-smoke.yml`, and `verify-published-runtime.yml`
do not reference this repository key. This inventory is source inspection, not
successful execution of these old consumers.

Approval and policy use `pull_request_target`; an earlier concern that they
necessarily run on a PR ref was incorrect. Main-only environment rules therefore
must be evaluated against their actual event ref. They also cannot protect a key
from a candidate that can itself merge to the allowed branch. Do not use a branch
restriction alone as evidence that the shared key is inaccessible.

## Historical remediation exploration (superseded where it omits label ingress)

Keep the existing Apps. Resolve the existing key on the client before the new
tests receive workflow-writing tokens:

1. Inventory its existing key consumers and exact pinned reusable workflows.
2. Prepare host-issued, short-lived test-token replacements for those consumers
   as part of the development runtime/caller rollout; preserve automatic approval
   and the existing scratch workflows. The old production-targeted reusables
   cannot simply dispatch with a test-only token: the workflow host remains
   production. Split capture from trusted host dispatch; never pass a production
   repository token to the candidate. Callers must pin development reusables on
   `securefix-server`, not a second workflow server.
3. Remove the repository-level key only after its replacement is concrete,
   reviewed and read back. A secret cannot be read back or copied through the API;
   replacement tokens can be issued by the existing trusted host. Do not rotate
   or delete keys speculatively.
4. Verify an unreviewed branch cannot reach the production key, then allow the
   explicitly scoped test tokens to write generated workflows.

An environment-only move is incomplete: the current remote request reusables set
`environment: main` only for the production server repository, and other key
consumers do not select an environment. Adapt these callers deliberately; do not
silently stop the old flow or put a key in the candidate container.

No App registration, external issuer or generic authentication service is needed
by this proposal. The remaining work concerns existing key-consuming caller
configuration and the minimum trusted host operations needed for native Actions.
Both production and development workflows remain on `securefix-server`;
independent control state is a fixture storage concern. No remote change has
been made.

## Concrete automatic-review credential mismatch

`src/approval.rs` authenticates `SECUREFIX_APPROVE_TOKEN` with `GET /user` and
requires the configured review account to have type `User`. `src/request.rs` and
`src/merge.rs` also require its current-head, control-bound User review. The
normal hosted flow therefore cannot use an App installation token unchanged.
The lower-level `approve_current_head` and `ready_with_reviewer` already support
explicit Bot reviewers for the existing direct scratch probe; that probe does not
establish the native hosted flow.

Do not give the existing production machine-user PAT to test code. Do not assume
a fine-grained PAT solves this personal-repository collaborator case: GitHub
documents collaborator access as a limitation. The proposed Client App reviewer
was rejected by the owner. Keep `civitaspo-bot` as the configured User reviewer.
The PAT already available on `securefix-server` can be used by trusted host code;
lack of an installation-token replacement does not justify changing identity.
Candidate code must not receive that PAT or run as part of the credentialed
review operation.

Reuse `approve_current_head` from trusted code to create the exact-head,
control-bound User review, and have the candidate read it back before its
test-token-only continuation. The local `review-for-testing` and
`apply-reviewed-for-testing` split now reuses that core while preserving the
configured User. The former is a trusted-host operation; the latter requires
the exact User review before test-token writes without loading the PAT. Both
require the isolated testing policy. Local host workflow wiring and artifact
qualification are described below; hosted execution remains unverified. Separate
runner steps alone do not establish isolation.
The owner User review and separate commands remain mandatory. This is an
implementation boundary, not a pending reviewer or App decision.

## Local native capture and host relay

The new `testing-load-cli.yml` qualifies a pre-release as data. Its public server
API client is anonymous; the caller token reads only the fixed test descriptor.
Bundle verification clears token variables, uses an empty GitHub config and
temporary cache, and retains exact signer/source/ref/issuer/runner checks.
No candidate binary is installed on the trusted host PATH.

Before the native-ingress correction, the three testing reusables accepted no
secrets. They now retain host-only Client key use as described above. Their candidate containers
mount only binary/policy, the native event file, output directory and CA certs,
and receive the client token and explicit non-secret metadata. They cannot reach
the host validator artifact or Actions command files. After the container exits,
the host rejects symlink/directory/oversized/extra-file manifest outputs and
checks client/run/kind/source/control before upload.

`testing-process-request.yml` keeps the key and PAT in trusted host operations.
Its host binary is built separately from captured protected main, not taken from
the candidate archive. Before App issuance it validates the first-attempt Client App label event, exact
workflow/source and signed current main. The host independently
loads the native source artifact and the candidate revalidates it before writes.
Only the host `review-for-testing` step has the existing bot PAT. The continuation
container has singleton test tokens, read-only qualified request data, explicit
metadata and the existing restricted process/filesystem configuration. Its mounts
and environment omit the host GitHub token, PAT, keys, credentials and sockets.

The parent remains undeployed. Earlier inspection treated indirect retrieval of
the client repository key through a workflow-bearing PR as a rollout blocker.
The owner explicitly excludes deliberate use of trusted server authority for
that attack, retains the repository secret, and rejects the Environment move.
That historical blocker is resolved by the threat-model decision, not by a claim
that `workflows:write` omission prevents such retrieval. Native label dispatch
and the direct credential exclusion remain required.

The local `testing-merge-caller-migration.yml` uses this same boundary for the
existing dedicated migration lane. Trusted host code qualifies the runtime and
prepares the reviewed canonical plan. Candidate authorization, readiness and merge
receive only test tokens and read-only plan/event files in restricted containers.
The workflow issues its merge token only after readiness succeeds. Its candidate
container receives only test-repository tokens, never the retained Client key.
No repository-secret cutover or additional per-job approval is required.

References: [authenticated user token types](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
[review permissions](https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request),
[fine-grained PAT limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens-limitations).
