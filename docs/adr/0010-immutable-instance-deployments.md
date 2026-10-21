# Immutable instance deployments: parser boundary

Status: accepted for the U04a parser boundary only; D02 remains partial.

## Context

The existing server loads deployment policy through the legacy JSON policy and
active-runtime path. The immutable-instance plan needs a strict external
configuration format, but the surrounding field map, release proof, current
authority, anti-replay epoch, migration and recovery designs are still being
worked through. Adding a parser does not require changing those current paths.

The root-approved U04a boundary is a pure parser for bounded TOML bytes. It
produces claims for a later authenticated runtime; it does not resolve repository
IDs, select or load an implementation, or grant operational authority. The exact
schema is specified in the [instance configuration schema](../instance-configuration-schema.md).

## Decision

Add `InstanceConfig::parse(&[u8])` as a reusable, disconnected Rust API. It
accepts at most 256 KiB of UTF-8 TOML, supports only schema version 1, and
rejects missing required fields, unknown fields recursively, malformed values,
and inconsistent claims. It has no filesystem, environment, credential, or
network access. The optional Renovate merge bot is absent by default, which
disables that self-merge capability; it never substitutes a configured actor.
The release branch is optional unless a configured repository grants release
capability. An absent or empty repository-specific sensitive-path list inherits
the explicit server-wide default.

The parser accepts repository and principal IDs as positive integers and checks
internal consistency among repeated claims in the same input. Across
`[instance]`, `[[repositories]]`, and `[acceptable_clients]`, one
case-insensitive repository name must map to one ID, and one ID must map to one
case-insensitive repository name. Matching repeated claims are allowed, while
duplicate rows in `[[repositories]]` remain rejected. These checks do not
authenticate name/ID bindings against GitHub. A `VersionReq` is parsed as a
range only; stable release status, publisher identity, source and asset
provenance, digest, and supported request protocol are later runtime checks.
The workflow/action's literal immutable pin remains the proposed implementation
selector. There is no `[runtime]` selector or implementation-version `[server]`
table. Legacy `integration`, `control_repository`, `workflow_prefix`, and
`runtime_update_branch` fields are not fabricated in this schema. The parser
requires a closed `[workflow_roles]` table with the `approve`, `merge`,
`policy_check`, `securefix`, and `release` keys. A `BTreeMap` orders these
closed snake-case roles lexically for stable identity use. Require each role
when any configured repository grants its operation capability; `policy_check`
is required when any repository grants `merge`. Recognized roles may be present
for disabled operations, but `settings` is not a role. An empty map is valid
when no ordinary operation is enabled.

Each role value is a root-level `.github/workflows/<name>.yml` path. The
nonempty filename contains only ASCII letters, digits, `_`, or `-`. The parser
preserves path case and rejects duplicate claims after ASCII lowercase
normalization. These are syntax checks only; parsing does not check that a file
exists, is regular, or avoids symlinks, and it does not inspect wrapper
contents, resolve pins, or authenticate source or package identity.

To share existing syntax checks without coupling the parser to loaded global
configuration, the existing login predicate was extracted to
`config::is_valid_login`, and the existing sensitive-path exemption validator
was made reusable with explicit arguments. `Deployment::validate` still applies
the same login predicate. `Policy::parse` still validates the same exemption
entries against the same trusted-committer list; only the helper's arguments
changed. The new parser adds its own cross-claim consistency check and keeps
existing owner/Client/Server principal separation, trusted-committer and
exemption conditions.

## Consequences and limits

The parser and its synthetic fixture can be tested independently of the
production runtime. No production call site, policy JSON, workflow, credential
scope, descriptor or API write behavior changes. The currently active runtime
and production policy loading remain as before. The parser must not be described
as authenticated configuration or as an authority fence.

D02 remains partial until the complete source-to-schema field map, operational
loading API and old/new policy decision fixtures are reviewed. No D gate is
closed by local parser tests. In particular, the following remain open or
partial as recorded by the [execution guide](../development-loop-execution-guide.md):

- D01: defining-workflow revision, source, producer and immutable asset proof.
- D03/D04: deployment identity, complete operational closure, current-write
  rechecks, and a bounded anti-replay epoch.
- D05/D06/D08: coherent Server pins, Client protocol/provenance, and
  repo-settings reconciliation semantics.
- D07/D09: generic publication, cutover authority, self-update and an
  evidenced conditional return path.

The parser uses fully synthetic examples, including a separate legacy-policy
parity fixture. An earlier U04a checkpoint recorded 13 parser tests and passing
standard checks: `cargo fmt --all -- --check`, `cargo test --locked` (399 passed,
2 ignored), and `cargo clippy --locked --all-targets -- -D warnings`. Those
results predate the workflow-role map and do not verify this update. On
2026-10-21, `cargo test --locked instance_config::tests` passed 17 tests and
`cargo fmt --all -- --check` passed for the workflow-role update. After an
independent static review found no actionable issue, the assembled worktree
passed the standard checks: 73 library tests, 305 CLI tests (2 ignored), 22
bootstrap tests, 2 native-client tests, and 1 testing-runtime test passed;
`cargo clippy --locked --all-targets -- -D warnings` also passed. Logs are
`/private/tmp/securefix-c80e-roles-standard-fmt.log`,
`/private/tmp/securefix-c80e-roles-standard-test.log`, and
`/private/tmp/securefix-c80e-roles-standard-clippy.log`. This is code-level
evidence only. No scratch repository, hosted workflow, publication, control
activation, or production operation was run as part of U04a.
