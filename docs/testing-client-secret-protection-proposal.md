# Client key protection before candidate workflow mutation

Status: rejected by owner on 2026-10-19; retained as proposal history. No
environment, secret, workflow pin or repository setting has been changed remotely.
The owner trusts securefix-server change management and approved code; compromise
of that authority and deliberate remote workflow-based secret retrieval are outside
the test threat model. Keep the existing repository secret and add no per-job
approval. Direct candidate access to credentials remains prohibited. See
[the current decision](testing-workflows-plan.md#owner-decision-trusted-server-and-unchanged-client-secret-2026-10-19).

The remainder records the rejected proposal, not an execution prerequisite. This is a concrete configuration question, not a new App
or token issuer proposal. Keep the shared Apps, User reviewer and native label
request protocol.

## Operation that cannot yet preserve the boundary

`.github/workflows/testing-securefix-server.yml` gives the existing scratch
candidate a Server App token with `contents:write` and `workflows:write` on
`civitaspo/testing-securefix-server`. That same repository has the repository
secret `SECUREFIX_CLIENT_PRIVATE_KEY` (name only inspected). Such a token can
create a workflow that references the repository secret and runs on its branch.
The container restricts local files and environment, but cannot restrict which
remote workflow this GitHub token writes. No exploit or secret read was performed.

Normal request capture and label dispatch do not need to grant that authority to
the candidate. Caller migration and workflow fixture creation do need workflow
changes somewhere in the test environment. Removing only the key argument from
Docker does not establish the required boundary for those operations. The separate
question of whether GitHub rejects workflow-bearing PR merges without a workflows
permission has not been established here; do not rely on either outcome as a
security proof. The existing explicit workflows-write token is already sufficient
to require protection before live execution.

## Smallest proposed configuration change

Keep the same Client App key and secret name. Store the test client's copy as an
Environment secret instead of a repository-wide secret. Proposed environment:
`testing-client-dispatch` in `civitaspo/testing-securefix-server`.

Proposed REST settings (not applied):

```json
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [{"type": "User", "id": 4525500}],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
```

Also disable administrator bypass in the environment UI and read back that
protection. This UI setting is not asserted to be a supported field of the REST
request above. The custom branch policy permits only `main`. Required owner review is the
credential gate; the branch rule by itself is insufficient. Self review remains
allowed because legitimate requests may originate from the owner's command.
Candidate code has no owner credential and no administration permission to change
this protection. The owner must review the workflow/source of every environment
approval; never approve an arbitrary candidate-created secret-reading job.

Native label dispatch still uses server `issues:write` from the same Client App.
The new testing reusables already separate `capture` and `dispatch` into different
jobs: the former runs only a sandboxed candidate with test tokens; the latter
runs the trusted validator against an immutable uploaded manifest and uses the
Client key. Selecting this environment belongs on that trusted dispatch job.
It adds an owner environment approval before each key-using job. This extra
manual step is an operational cost and must be accepted explicitly; it does not
replace the exact-head owner review or separate `/approve` and `/merge` commands.

## Required rollout, before changing the repository secret

Existing key consumers at client main
`0851bea96e07756a8ee52c5721dba99b8527d13f` are:

- `approve-request.yml`
- `merge-request.yml`
- `policy-check.yml`
- `release-pr.yml`
- `release-tag.yml`
- `client-app-smoke.yml`
- `verify-server.yml`

Prepare and review environment-aware replacements for all seven before cutover.
A reusable-workflow caller cannot itself select a job environment; the actual
key-using job in the called workflow must select it. Existing pinned production
reusables do not gain this behavior by editing client environment settings. Do
not update a pin to an unqualified source or alter production activation just to
work around that restriction. Release and smoke replacements are not implemented
yet; the three native testing request replacements are local only.

Create/read back the environment protection and stage the same key under the same
name there using the owner's existing secure key source; secret values cannot be
retrieved through the GitHub API and must not be pasted into chat. Switch only
after replacements are ready. Remove the repository-level copy as the final
cutover step, then verify an unapproved branch job cannot obtain the environment
secret without printing or transmitting it. Until then, keep existing consumers
operational and do not run candidate workflow-mutation tokens on this repository.

This proposal does not authorize a settings or secret mutation. Local controller,
fixture qualification and evidence work can continue while this decision is
pending. Environment setup alone is not proof of migration or normal recovery.

References: [environment secrets and required reviews](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[reusable-workflow environment secret behavior](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#passing-inputs-and-secrets-to-a-reusable-workflow),
[triggering workflows](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
