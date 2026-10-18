# Securefix Server

This context describes the identities and authority boundaries used by the privileged automation server.

## Language

**Client**:
A repository that requests an operation granted by the server's policy.
_Avoid_: consumer

**Server**:
The repository and runtime that validate requests and perform privileged operations for configured repositories.
_Avoid_: controller, unless referring to a specific control revision

**Capability**:
Permission for one named operation on one exact repository.
_Avoid_: access, permission (when the exact operation and repository matter)

**Request locator**:
The client repository and workflow run ID used to find a request.
_Avoid_: request ID

**Request manifest**:
The immutable record of a request and its captured repository, source, and target identities.
_Avoid_: request metadata

**Accepted head**:
The pull request head SHA captured when a request command is accepted.
_Avoid_: current head (unless referring to a later observation)

**Owner authorization**:
An owner command accepted for one exact pull request head and one active control revision.
_Avoid_: approval (when describing authorization to run the server operation)

**Renovate authorization**:
A merge request from the configured Renovate bot for its own pull request, bound to one accepted head and one active control revision.
_Avoid_: owner authorization

**Renovate rebase retry**:
One server-requested rebase after a failed authorized merge attempt for a Renovate PR. The allowance belongs to the PR and does not reset when its head or merge command changes.
_Avoid_: per-head retry

**Sensitive change**:
A change to a path that requires owner authorization for automatic approval.
_Avoid_: trusted change

**Runtime revision**:
A source revision of the server executable and the policy snapshot distributed with it.
_Avoid_: current main (these identities may differ)

**Control revision**:
A verified runtime revision selected for privileged operations, together with its publication evidence and predecessor identity.
_Avoid_: runtime promotion

**Control identity**:
The digest that identifies every field of a control revision, including its generation and predecessor.
_Avoid_: runtime SHA

**Policy snapshot**:
The policy bytes bundled with a runtime revision and identified by their digest.
The separate Renovate merge policy is embedded in the executable from
`src/renovate_merge_policy.json`, and bound by the runtime source and attested
archive digest. It does not add fields to the base policy parsed by a predecessor
controller or grant owner authorization.
_Avoid_: live policy (when referring to the active runtime's policy)

**Control activation**:
The reviewed protected-main change that selects a successor control revision.
_Avoid_: publication

**Caller migration**:
Generated workflow changes delivered to one configured client through a reviewable pull request.
_Avoid_: automatic rollout

**Release identity**:
The repository, merged release pull request, commit, tag, and version being published.
_Avoid_: release version (when the immutable repository objects matter)

**Release bundle**:
The unsigned, canonical publication assets produced by the isolated build job.
_Avoid_: runtime artifact (when referring to the verified published archive)

**Activation**:
Creating or reactivating the controlled-merges ruleset after checking the full configured repository set.
_Avoid_: control activation

**Reconciliation**:
Applying configured settings to an existing repository or active ruleset.
_Avoid_: activation
