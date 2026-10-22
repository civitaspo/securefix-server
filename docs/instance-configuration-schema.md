# External Server instance configuration schema

This document describes the bounded parser contract implemented by
`src/instance_config.rs` for U04a. It is a schema for configuration claims, not
an operational configuration loader or an authorization boundary. The parser is
not connected to production operations. Existing operations keep their current
policy loading and runtime behavior.

The complete synthetic valid example is
[instance-config.toml](../tests/fixtures/instance-config.toml). It uses only
placeholder identities and IDs.

## Parsing rules

`InstanceConfig::parse(&[u8])` accepts at most 256 KiB of UTF-8 TOML. Invalid
UTF-8, malformed TOML, an unsupported schema version, a missing required field,
or any unknown field at any nesting level returns an error. The parser does not
read files, environment variables, credentials, or the network.

Only `schema_version = 1` is supported. The root contains the required
`[instance]`, `[identities]` role tables, `[apps]`, `[policy]`, a
`repositories` array, `[workflow_roles]`, and `[acceptable_clients]`. The
repository array may be empty (`repositories = []`), which grants no repository
capabilities. The `[branches]` table is optional when no repository grants the
`release` capability.

## Fields

All IDs below are positive TOML integers deserialized as `u64`; the parser
checks their syntax and internal consistency, not their identity with GitHub.
Principal logins use the existing validator: 1–100 ASCII alphanumeric or
`-`, `_`, `[`, `]`, and `.` characters. All fields are strict: adding an
unlisted key is rejected.

| Field | Requiredness and validation |
| --- | --- |
| `schema_version` | Required integer; must equal `1`. |
| `release_request_label_prefix` | Required string. Empty disables the label namespace. Otherwise it must be at most 32 bytes, start with a lowercase ASCII letter, contain only lowercase ASCII letters, digits, or `-`, and end with `-`. |
| `[instance].repository` | Required `owner/name`; validated with the existing repository-name validator. |
| `[instance].id` | Required, nonzero repository ID claim. |
| `[instance].default_branch` | Required branch name; checked with the existing branch validator. |
| `[identities.owner]` | Required `{ login, id }` principal for the human owner role. |
| `[identities.repository_owner]` | Required `{ login, id }` principal. Its login must exactly match the owner segment of `instance.repository`. |
| `[identities.client_bot]`, `[identities.server_bot]` | Required `{ login, id }` principals. |
| `[identities.approval_reviewer]` | Required `{ login, id }` principal. |
| `[identities.renovate_merge_bot]` | Optional `{ login, id }`. Absence disables Renovate self-merge; there is no default actor. When present, its login must end in `[bot]`, it must be a trusted committer, and its ID must differ from the owner, Client Bot, Server Bot, and approval reviewer IDs. |
| `[apps].client_id`, `server_id`, `status_check_id`, `policy_check_id` | Required positive App identity claims. Client and Server IDs must differ; status-check and policy-check App IDs are configured independently. Native policy-check reads use the Server App and its check write uses the policy-check App; native Securefix commit writes use the Server App. |
| `[workflow_roles]` | Required closed map with keys `approve`, `merge`, `policy_check`, `securefix`, or `release`. Each value must be `.github/workflows/<name>.yml`, where `<name>` contains one or more ASCII letters, digits, `_`, or `-`. Names cannot contain `/` or `.`. Paths are preserved as written; duplicates reject after ASCII lowercase normalization. |
| `[branches].release` | Optional branch. Required if any configured repository grants `release`; when present it must pass the branch validator and differ from `instance.default_branch`. |
| `[policy].trusted_committers` | Required, nonempty array of valid logins. Case-insensitive duplicates reject. |
| `[policy].default_sensitive_paths` | Required, nonempty array of glob patterns accepted by `globset`. |
| `[policy].merge_controls_enabled` | Required boolean; omission is an error. |
| `users` in `[policy.sensitive_path_approval_exemptions]` | Optional array of `{ id, login }`; the table and key default to empty. Each ID is nonzero and the login must be a trusted committer. |
| `github_apps` in `[policy.sensitive_path_approval_exemptions]` | Optional array of `{ bot_id, bot_login }`; the table and key default to empty. Each ID is nonzero, login ends in `[bot]`, and the login must be a trusted committer. |
| `[[repositories]].repository` | Required `owner/name`, owned by the configured `repository_owner.login`. Repository names must be unique case-insensitively among repository rows. |
| `[[repositories]].id` | Required nonzero repository ID claim, unique among configured repository rows. |
| `[[repositories]].capabilities` | Required nonempty array of unique values: `approve`, `merge`, `securefix`, `release`, or `settings`. |
| `[[repositories]].release` | Optional strategy, `github-release` or `terraform-provider`. It must be present exactly when the `release` capability is present. |
| `[[repositories]].protect_tags` | Required boolean. |
| `[[repositories]].sensitive_paths` | Optional array of glob patterns. Missing or empty inherits `policy.default_sensitive_paths`; all effective patterns must parse. |
| `[[scratch_request_callers]]` | Optional array; missing defaults to empty. Each row declares one permitted caller tuple for a test request. Exact duplicate tuples reject. |
| `[[scratch_request_callers]].repository` | Required `owner/name` caller repository claim. Caller identity is independent from `[acceptable_clients]`, which identifies the Client package publisher. Repository claims must remain internally consistent with other repository IDs. |
| `[[scratch_request_callers]].id` | Required nonzero caller repository ID claim. |
| `[[scratch_request_callers]].workflow_path` | Required canonical `.github/workflows/<name>.yml` path using the same shallow ASCII filename rule as workflow roles. |
| `[[scratch_request_callers]].workflow_ref` | Required `refs/heads/<branch>` ref; the branch must pass the existing branch validator. |
| `[[scratch_request_callers]].event` | Required closed enum: `pull_request_target`, `pull_request`, `issue_comment`, or `workflow_dispatch`. |
| `[[scratch_request_callers]].operation` | Required closed enum: `policy_check`, `approval`, `merge`, or `securefix`. Runtime matching compares the full tuple: repository case-insensitively, then ID, workflow path, workflow ref, event, and operation exactly. |
| `[acceptable_clients].repository` | Required `owner/name` identifying the configured Client publisher claim. No same-owner constraint is applied. |
| `[acceptable_clients].id` | Required nonzero publisher repository ID claim. |
| `[acceptable_clients].producer_workflow` | Required canonical `.github/workflows/<name>.yml` path for the Client request-capture reusable workflow. Its literal full-SHA pin and attested signer identity must match at request verification. |
| `[acceptable_clients].version` | Required string parsed by `semver::VersionReq`, such as `>=1.4.0` or `>=1.4.0, <2.0.0`. It is a range, not an implementation selector or SHA allowlist. |

Require `approve`, `merge`, `securefix`, or `release` when any repository grants
the corresponding capability. Require `policy_check` whenever any repository
grants `merge`. A recognized role may be configured while its operation is
disabled. Do not configure a `settings` role. An empty map is valid when no
repository grants an ordinary capability, including an empty repository list
or a settings-only repository.

Every principal claim in `[identities]` and the sensitive-path exemption lists
must be internally consistent: the same case-insensitive login cannot name two
IDs, and one ID cannot name two case-insensitive logins. Repeating an identical
pair across role and exemption claims is allowed, including when the human
owner and repository owner are the same principal. Duplicate entries within
the exemption lists reject. App IDs in `[apps]` are a separate namespace and
are not compared with principal IDs. Existing role-separation and exemption
checks still apply.

Repository identity claims across `[instance]`, `[[repositories]]`, and
`[acceptable_clients]` are checked the same way: a case-insensitive `owner/name`
can map to only one ID, and an ID can map to only one case-insensitive
`owner/name`. A repeated matching claim is allowed, including when a repository
row or acceptable Client publisher names the instance repository with the same
ID. Duplicate names or IDs within `[[repositories]]` are still rejected by the
existing per-row checks. This verifies consistency only within the TOML; it does
not authenticate repository names or IDs against GitHub.

In particular, the owner, Client Bot, and Server Bot IDs must be pairwise
distinct. Owner, repository-owner, and approval-reviewer roles may share a
principal when every repeated login/ID pair is consistent; Renovate's explicit
separation from owner, Client Bot, Server Bot, and approval reviewer still
applies.

An empty or omitted per-repository sensitive-path list inherits the explicit
default list; it does not disable sensitive-path matching. Exemption lists
default to empty and never add a principal to `trusted_committers`.

## Deliberate exclusions and limits

There is no `[runtime]` table or implementation-version `[server]` table. The
YAML workflow/action pin remains the proposed implementation selector. The
parser has no legacy `integration`, `control_repository`,
`runtime_update_branch`, or `workflow_prefix` field. These and any other unknown
keys reject. `release_request_label_prefix` only namespaces release-request
labels; it does not select workflow paths. The parser does not invent a scratch
repository, legacy branch, or control identity.

`scratch_request_callers` declares caller identities separately from the
acceptable Client package publisher. The optional field does not infer or grant
a caller when absent; later authenticated request handling must compare the full
declared tuple before acting.

Workflow-role paths are claims only. Parsing does not check whether a mapped
file exists, is regular, or avoids symlinks. It does not inspect the wrapper,
resolve its pins, or authenticate its source or package identity. Those checks
belong to later authenticated runtime work and remain open gates.

Repository names and numeric IDs are still unverified claims. Parsing does not
fetch authenticated repository metadata, prove that an ID belongs to a name,
read a protected-main snapshot, verify the configuration path or digest, resolve
Client release provenance, establish a supported request protocol, or authorize
a write. Parsing a `VersionReq` does not establish a stable published Client
release or authenticate its source, producer, asset, or digest. Those checks
belong to later authenticated runtime work and remain open gates.

The parser is not wired into the current runtime and does not replace
`policy.json`, `control/active.json`, or any production authority. Missing or
invalid future configuration must fail closed; this parser itself does not
provide a loader, fallback, or authority fence.
