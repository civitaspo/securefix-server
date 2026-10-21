# Protected-main instance authority and history epoch

Status: proposed. Root review, executable parity tests, hosted scratch
qualification, and D09 transition rehearsal remain required before any
operational caller uses this authority.

## Context

The instance configuration parser is pure and disconnected from production.
The generic package resolver checks the downloaded asset's length and
SHA-256 against immutable-release metadata. That proves content integrity, not
producer workflow provenance, attestation, or permission to execute the
bytes. This decision specifies how a later runtime may bind one operation to
the Server instance's current protected-main deployment without selecting an
implementation from TOML.

Use the terms from the development-loop guide:

- `M` is the exact protected-main commit captured for one read snapshot. It is
  a lookup root, not authority identity.
- `K` is the identity of the authenticated instance and exact configuration
  bytes.
- `W` is the bounded set of deployed operation wrappers and their verified
  first-party package pins.
- `E` is the anti-replay epoch derived from relevant first-parent changes.
- `D` is the deployment identity derived from the authenticated instance, `W`
  and `E`. `A = (K, D)` is always additionally bound to the exact PR head and
  the existing replay/expiry data.

The native request keeps Server and Client identities separate. Its strict
Client manifest carries the Client request repository and PR, producer
run/source/workflow claims, `client_workflow_epoch`, and a capture-time Server
authority snapshot. The Server repository and config path in that snapshot are
untrusted locators: the receiver must match them exactly to its authenticated
`GITHUB_REPOSITORY`, strict TOML instance, and explicit CLI config-path before
using the snapshot. The capture routine reads the named public or authorized
Server repository's protected default branch and constructs the snapshot; a
Client cannot provide a policy object or select another config. The receiver
reconstructs the snapshot and rejects a stale request before producer/artifact
processing, then checks the exact configured role path and protected-branch
workflow SHA from `GITHUB_WORKFLOW_REF` / `GITHUB_WORKFLOW_SHA`. `[repositories]`
authorizes the independent Client request repository; `[acceptable_clients]`
identifies the reusable Client producer. The Server recomputes the Client
workflow epoch through a Client-scoped read token, separately from the Server
`E`. Immediately before a write it rechecks both snapshots and the exact Client
PR head. The protected, hash-bound Server wrapper obtains the Client read token
and operation writer with its pinned `actions/create-github-app-token` step,
using the configured App identity and limiting each token to the configured
Client repository. Rust verifies that each installation token lists exactly
that repository. The installation-token API does not expose an endpoint that
proves the bearer token's App ID, so the repository-list response is not App
identity evidence; that identity comes from the authenticated wrapper's token
mint inputs. The current scratch-host contract test checks those inputs against
its strict test TOML, while runtime checks bind execution to the configured
protected workflow and its current bytes. The Server `GITHUB_TOKEN` reads only
Server authority. Exact runtime build-artifact identity in hosted scratch
remains unqualified. This slice does not yet define the final canonical
`K`/`D` digest or generic release acceptance.

The current config parser denies unknown fields. Add a required closed
`[workflow_roles]` table before freezing schema version 1, or bump the schema
version; do not silently default it. Its keys are the supported operation
roles (`policy_check`, `approve`, `merge`, `securefix`, and `release`) and its
values are unique normalized repository-relative workflow paths. Required
roles are determined by enabled operations, and a missing enabled role,
duplicate path, unknown role, absent file, symlink, or non-regular file
rejects configuration. The path is supplied explicitly by the trusted Server
wrapper, never by a Client or PR workspace; there is no implicit default.
Validate it as a root-relative path with no absolute path, `.`/`..` component,
alternate separator, or symlink traversal.

Each mapped workflow is a canonical thin wrapper: it contains no local action,
local reusable workflow, script, or client-controlled executable hook. It
selects the same first-party Server package release set through literal
lowercase full-SHA pins. A narrow validator checks the canonical wrapper shape
and extracts those literal pins; it is not a general workflow interpreter.
The independently resolved release and asset integrity result is part of
`W`, not a claim copied from TOML. D01 must additionally establish producer,
source, run/attempt, and signature evidence before downloaded bytes may run.
Changes to the package source on OSS `main` do not change the instance
identity while these wrappers still point at the old immutable SHA.
Third-party actions remain full-SHA pinned and are checked by the existing
workflow validator.

## Decision

### Snapshot and bounded Git retrieval

For each authority reconstruction:

1. Use the authenticated Server execution context and GitHub repository API
   to require the configured repository ID, canonical owner/name, and default
   branch. Read the protected default-branch ref and capture its exact commit
   as `M`.
2. Create a fresh temporary Git object store and fetch exactly `M` from the
   fixed origin `https://github.com/<validated-owner>/<validated-repository>.git`.
   Do not fetch a branch name, tags, submodules, or an arbitrary URL. Require
   `FETCH_HEAD == M` and the commit object to be present.
3. Fetch the complete commit/tree graph reachable from `M` with
   `--filter=blob:none --no-tags --no-recurse-submodules`; do not set a depth
   or stop at a commit-count boundary. The history operation needs commits and
   trees, not historical file contents. Require
   `git rev-parse --is-shallow-repository` to be `false` and reject a shallow
   boundary file. If the host does not honor the blob filter, reject when the
   monitored temporary object store exceeds its byte cap. A fetch/verification
   timeout, cap breach, bad object, or nonzero exit is an authorization
   failure.
4. Read only the configured TOML and mapped workflow paths at `M`. Use
   `git ls-tree -z` with literal pathspecs, require mode `100644` and blob
   object type, then use `git cat-file --batch-check` to identify missing
   current blobs. Collect their validated object IDs and fetch them together
   in one explicit `git fetch origin <oid...>` before one `git cat-file
   --batch` read. Never let `cat-file` lazily fetch each blob separately.
   Parse each response by its declared byte length; reject truncated output,
   duplicate paths/OIDs with conflicting identities, invalid UTF-8, or size
   overflow.
5. Independently re-read the protected branch ref and require it still equals
   `M`. If it moved during retrieval, discard the snapshot and retry only
   within the operation's fixed retry budget; otherwise fail closed.

The Git child process must use an isolated temporary home/object store and
environment: disable system/global Git configuration, prompts, hooks,
credential helpers, file protocol, redirects, tracing, and submodule
recursion; allow HTTPS only; invoke Git with argument arrays and no shell.
For a private instance, pass the already authorized repository-scoped
Contents-read token only to the Git child through a per-process
`http.extraheader` environment setting. Never put credentials in the origin
URL, command arguments, global config, logs, or captured error text. Discard
or redact stderr and report only the failed phase and exit status. This does
not require repository Administration access or add a settings preflight.
GitHub Enterprise origins are unsupported until their host identity is an
explicit authenticated input.

Apply these provisional hard bounds in the first implementation: 32
workflow-role paths; 256 KiB for TOML; 256 KiB per workflow; 4 MiB combined
current TOML/workflow bytes; 1 MiB captured output for metadata/history Git
processes; 5 MiB for the bounded current-blob batch; 64 MiB for the monitored
temporary object store, including in-progress packs; 64 KiB captured
diagnostic output (discarded on failure); 30 seconds per network Git child
and 60 seconds total for Git retrieval and history evaluation. The history
bound is storage and elapsed time, not a first-parent commit count: a long
sequence of small unrelated commits does not itself require an instance
update. Enforce child timeouts by terminating the process and bound output and
object-store growth while streaming. Reject when a bound is reached; never
return a partial identity. Revisit these resource caps if a legitimate
history or repository exceeds them.

The final repository head read in step 5 is a freshness check, not a
cross-service transaction. Every protected-main writer remains serialized in
`securefix-control`; at each mutation fence the writer reconstructs current
`A`, verifies it equals the accepted `A`, and repeats existing exact-head,
owner-review, signature, required-check, permission, and expected-head-CAS
checks. Never cache current `A` across requests or writes. Immutable package
proofs may be cached only by the complete publisher repository ID, source
SHA, release ID, asset ID and digest tuple, and their validated result.

### Canonical identity

Hash exact raw TOML bytes, including comments and whitespace. Use SHA-256 and
unambiguous canonical encoding: each field is UTF-8 or fixed-width unsigned
big-endian, prefixed by its byte length; arrays are sorted by their specified
stable key and include an element count. Use separate domain strings ending
in NUL for `securefix-instance-config-v1`, `securefix-instance-workflow-v1`,
and `securefix-instance-deployment-v1`.

`K` is the SHA-256 of the config domain plus:

1. authenticated GitHub repository numeric ID;
2. normalized root-relative config path;
3. schema version as `u32`;
4. SHA-256 of the exact bounded TOML bytes.

`W` is a role-sorted array. Each entry contains the closed role enum, exact
normalized workflow path, regular-file mode, SHA-256 of raw workflow bytes,
and the D01 package result selected by that wrapper: publisher repository ID,
component, source/implementation SHA, stable version, release ID, and asset
ID/name/size/digest. The current resolver verifies downloaded bytes against the
release digest, but does not establish producer provenance or attestation; do
not treat that result as executable until D01's independent host-side proof is
qualified. Protocol identity is not yet part of the package result and must
be added to the strict protocol contract before D06 closes. Require one
coherent first-party Server release set across all required roles. The
wrappers' bytes bind their events, permissions, environments, token
references, literal pins, and input/output wiring. No local dependency
closure is allowed, so this design does not have to discover local actions,
scripts, or lockfiles at runtime.

`E` is the SHA of the newest commit on the first-parent chain from `M` that
changes any exact path in `P = {config path} union {all configured role
paths}`. With the complete filtered graph fetched above, run one bounded Git
path-history traversal and parse its raw diff records:

```text
git log --first-parent --full-history --diff-merges=first-parent \
  --raw --no-renames -z --format=%H M \
  -- ':(literal)<config-path>' ':(literal)<role-path>' ...
```

Do not pass `--max-count=1`: `--full-history` can return a path-relevant merge
whose result is unchanged from parent zero. Parse the `-z` stream in commit
order: remember each full commit ID, skip commit headers with no raw diff
entry, and select the first raw diff record whose NUL-delimited path is an
exact member of `P`. `--first-parent` defines the protected-main lineage;
`--diff-merges=first-parent` makes a merge's raw diff its result against
parent zero; `--full-history` retains path-relevant merge candidates; and
`--no-renames` makes a rename a deletion/addition. A merge unchanged from
parent zero has no first-parent raw diff and is skipped, even if its second
parent changed the path. No raw diff result is a failure because the required
config file must have entered history. Reject malformed raw records, a path
outside literal `P`, truncated output, nonzero exit, or a timeout. Bound the
output while streaming; historical blob contents are never fetched. Disable
Git lazy fetching after explicitly hydrating current config and wrapper blobs
so a missing commit/tree fails instead of causing hidden network requests.

The complete fetch, absence of shallow boundaries, exact `M`, and successful
path traversal establish that the search was not truncated at an arbitrary
edge count. A missing commit/tree object, malformed raw output, nonzero Git
exit, truncated output, or timeout fails closed. If a currently mapped path is
absent at `M`, reject before history evaluation.

This produces the desired behavior: a relevant edit followed by an exact
revert yields the revert commit as `E`; a role/config mapping change changes
`K` and `E`; a rename is handled by the new path's addition and config
change; deletion of a required current role rejects; a merge uses its
protected first-parent result; unrelated Rust, documentation, or unreferenced
OSS `workflow_call` source changes leave `E` and `W` unchanged. A current
bytes-only check is insufficient because it would restore old authority after
an ABA revert.

`D` is the SHA-256 of the deployment domain plus authenticated repository ID,
canonical repository name, default branch, canonical `W`, and `E`. Do not
include `M` itself: unrelated protected-main changes must not invalidate
authority. Do not use commit timestamps, a manual generation counter, a
whole-main hash, a Client-provided path list, or an implementation version in
TOML.

### Direct writer boundary

`W` is the ordinary Server operation surface, not every workflow or credential
in the repository. The initial role set covers the CLI-backed
`policy_check`, `approve`, `merge`, `securefix`, and `release` operations.
Before enabling this authority, a source-owned required-CI inventory test
must classify every workflow that can mint an ordinary Server installation
token or perform an ordinary Server PR/protected-main write. Every such path
must be one of the configured canonical role wrappers; an unclassified
ordinary writer fails CI. A role addition/removal or path replacement must
edit the strict instance TOML, changing `K` and making the TOML path the
newest relevant event in `E`; each current role file is also included in `P`
and `W`. Thus role registration and role-content add/remove/revert cannot
restore an older ordinary `A`.

For a privileged run, derive the configured caller role from the
authenticated Actions workflow-run API response, not from the request or
Client manifest. Require the exact configured repository identity. For
`run.path`, accept only the exact configured root-relative workflow path, or
that exact path followed by `@<default-branch>` or
`@refs/heads/<default-branch>`. The optional suffix is a branch association,
not source-revision proof. Reject owner/repository-prefixed paths, other
refs, case mismatches, and every unsupported form; do not strip arbitrary
prefixes or split at an arbitrary `@`. Once a caller-source SHA is
independently authenticated, compare the canonical wrapper bytes at that SHA
with the configured pin; that comparison is a consistency check, not proof of
the SHA or artifact producer. The API's `head_sha` is event data and must not
be assumed to identify the workflow definition for every event. The PR-target
trace found `run.head_sha` at the PR head and `pull_requests` empty while
reusable references identified base/main. Keep the PR head and caller workflow
SHA as separate facts; the PR-target source adapter, including empty
associations, remains unresolved.
For a reusable workflow call, require one `referenced_workflows` entry whose
`path` is the exact concatenation of `<canonical-owner>/<canonical-repository>/`,
the configured path, `@`, and the expected lowercase 40-hex SHA. Require the
entry's `sha` and literal caller pin to equal that SHA. Do not normalize
repository identity, strip a repository/path prefix, or use the entry's `ref`
as a substitute for its resolved `sha`. These references and literal pins are
necessary correlation and consistency metadata only: they do not prove that
the reusable call executed. An artifact's `caller_workflow_sha` plus canonical
YAML fetched at that self-reported SHA does not independently authenticate the
caller source. `referenced_workflows` may include a skipped call, and job or
step display names plus same-run artifact metadata do not independently prove
the expected producer created the artifact. D01 remains blocked until an
independent proof authenticates both the actual caller-definition revision and
producer/artifact origin for every supported event. No metadata-only path is
accepted and no new proof mechanism is selected. Reusable workflows with
nested source-owned composites are only the candidate initial scope; a
standalone remote composite remains unsupported until its executed revision
can be proven. Reject missing, duplicate, or mismatched run records, caller
pins, or references. This unit adds no OIDC/id-token permission. A separately
reviewed D01 decision may select a native proof mechanism and its required
least permissions if justified; until then, OIDC is not selected.

The inventory is a closed check over this repository's exact known ordinary
Server token-minting/write patterns and exact allowed role paths. It is not a
workflow-language interpreter, does not scan every read-only workflow at
runtime, and does not claim to audit all credentials in the repository. It
runs as required CI on reviewed source changes. The trust model treats
owner-selected Server source/check changes as authorized; an owner or
protected-main/required-check compromise that deliberately bypasses or
weakens this inventory is outside the ordinary Server authority threat model.
Do not query repository Administration settings or add a runtime preflight
to make that source trust assumption appear stronger.

Repository-settings reconciliation and the trusted package publisher remain
separate authority lifecycles with their existing credentials, scopes, and
contracts. Their source changes do not enter ordinary Server `W` or `E`
merely because their definitions share the repository. The ordinary token
inventory must preserve that separation, not classify those writers as
ordinary roles. Scratch jobs retain their test-only installation scopes and
owner-selected source trust boundary. Do not enable ordinary operations
while an ordinary Server writer is unaccounted for.

### Evidence and cost

The exact-SHA partial-fetch probe on this public repository fetched
`M=6287b76f24d5f7023e84cd932bc84437c417447e` with blob filtering and no depth
limit in 1.196 seconds. Its first-parent chain has 134 commits, no merge
commits, and the resulting object store was 303.71 KiB. This demonstrates that a
complete exact-M filtered fetch for the current graph is practical; it does
not qualify a larger repository or prove hosted history corner cases.

A five-blob probe found that `git cat-file --batch` in a partial clone lazily
performed five separate fetch round trips. Explicitly fetching the five
missing object IDs together hydrated them in one pack request, after which a
single `cat-file --batch` read needed no network access. Therefore the
implementation must batch the missing IDs before reading.

The authority snapshot uses two GitHub reads before Git retrieval (repository
identity/default branch and branch head), one exact-M full-ancestry filtered
Git fetch, one bounded `git log` path-history traversal, one current-path
`ls-tree`, one batched missing-blob fetch when required, one `cat-file` batch,
and one final branch-head read. The current filtered object store was 303.71
KiB and the exact-M fetch took 1.196 seconds. A credential-free local fixture
with 600 unrelated first-parent commits found the correct `E` with one `git
log` process in 11.4 ms and 126 bytes of output; an equivalent
per-commit `diff-tree` loop used 602 processes and 14.5 seconds. The write
fence repeats the fresh snapshot and adds the existing API reads for
PR/head/review/check/CAS conditions. These measurements support one
path-history traversal instead of a per-commit API/process loop; the 64 MiB
store and 60-second bounds remain provisional until hosted scratch measures
the full retrieval. A repository that exceeds a byte or time cap stops
operations rather than guessing; this does not impose an update every fixed
number of unrelated commits.

Prior credential-free local Git fixtures passed role/config change-and-revert,
role-path registration and removal/revert, an unregistered ordinary
direct-writer rejection, unchanged identity after an unreferenced workflow-call
source edit, true-root creation, an unrelated merge whose path equals parent
zero, a merge equal to its side parent but changed from parent zero, octopus and
empty merges, rename, deletion, shallow-boundary rejection, and correct `E`
beyond 600 unrelated commits. For each merge/root/revert/rename case, the
single `git log` raw-diff result matched an independent first-parent
`diff-tree` oracle. The fixtures exercise a local Git graph, not the proposed
production fetch/runtime integration. A focused parser regression fixture also
used a 40-character lowercase-hex filename; it passes after path-state parsing
takes precedence over SHA-token classification. Current production main has no
merge commits, so hosted merge parity still requires scratch fixtures.

## Consequences and remaining gates

The derivation needs a bounded blob-filtered Git graph but no GitHub per-path
history ordering, REST compare-file list, or historical blob download. A
changed source-only commit leaves `A` stable; a changed role wrapper or config
does not. Failure to obtain current repository identity, ref, Git objects,
configuration, package proof, complete bounded history, or final head
agreement means no authorization.

Before D03/D04 can close, implement the retrieval with the exact process
isolation, bounds and shallow rejection above; compare its `E` against an
independent local first-parent oracle for add/edit/revert, merge variants,
octopus and empty merges, rename, delete/re-add, true root, incomplete shallow
fetch, and resource-cap cases; test role registration and an unregistered
ordinary writer; verify wrapper role provenance and package proofs for every
role; and exercise success plus rejection in the configured scratch
repository. Measure hosted API/process cost and audit the closed ordinary
writer inventory. If Git behavior, completeness, or hosted limits diverge,
stop and revise this ADR before enabling the mode.

D09 remains open. A self-pin/config change is validated as a complete
successor under current `A`; its expected-head merge is the terminal write
under the old authority. No post-merge marker or command may use old `A`.
Fresh runs under the new authority are required. This ADR does not establish
that a broken pin can be rolled back through the ordinary lane; do not claim
that return path until the exact transition and known-good restore are
rehearsed.

The design adds no direct Contents API write, native auto-merge, repository
Administration read, candidate sandbox, or fallback executable. It leaves
the current descriptor/runtime in force until generic publisher qualification,
scratch proof, and a reviewed cutover are complete. If the existing reviewed
lane cannot perform the exact authority transition, any bounded migration
executor requires separate justification and review; old-Client coexistence
alone does not require a runtime bridge.

## References

- [Development-loop execution guide](../development-loop-execution-guide.md)
- [Instance configuration schema](../instance-configuration-schema.md)
- [Git fetch](https://git-scm.com/docs/git-fetch)
- [Git rev-list](https://git-scm.com/docs/git-rev-list)
- [Git ls-tree](https://git-scm.com/docs/git-ls-tree)
- [Git diff-tree](https://git-scm.com/docs/git-diff-tree)
- [Git cat-file](https://git-scm.com/docs/git-cat-file)
- [GitHub workflow run API](https://docs.github.com/en/rest/actions/workflow-runs)
