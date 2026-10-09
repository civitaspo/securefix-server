# Reuse the upstream Securefix protocol

Status: superseded by [ADR 0008](0008-native-securefix.md). The following describes the historical upstream implementation.

The server used `csm-actions/securefix-action` v0.6.3 at commit `1b770a7af0ec5e04517295b4e14c4b451359d550` for preparation, commits, notifications, and its post-action cleanup.
Rust owns this server's repository capabilities, source workflow provenance, and allowed destination checks.
The workflow runs those checks between upstream `prepare` and `commit`.
This keeps client protocol changes with their upstream implementation instead of maintaining another artifact parser and commit engine.

The runtime and `securefix-config.yaml` come from the same attested server archive and stay outside `GITHUB_WORKSPACE`.
Preparation extracts client files into that workspace; those files must not replace the executable or authorization configuration.
The config permits the seven fixed release-capable clients on any branch name, with the destination repository kept the same as the source.
Rust permits a trusted default-branch release-PR source to target any non-default branch, after checking release capability and the pinned reusable workflow provenance.
PR CI fixes still target their own branch; the separate release product commands continue using `release/next`.
Same-branch fixes bypass upstream config matching, so Rust still checks the exact source repository and workflow.
Default-branch writes and cross-repository writes remain forbidden by that gate.

Source fixes do not require a successful source run.
The upstream client dispatches the artifact and label before deliberately failing same-branch CI to report pending fixes.
The label may therefore arrive while the source run is still running or after it has failed.
Approval, merge, and release publication retain their separate successful-run requirements.

## Accepted limitation

The upstream prepare action resolves the artifact name once and downloads the selected immutable ID.
The former claim that it repeatedly resolves an artifact by name was incorrect.

The upstream commit helper reads the destination head when creating a commit and updates the ref without force.
It does not pass the source run SHA as its commit parent.
If head B already exists before that lookup, an artifact made at A can replace file contents on top of B without a merge conflict.
If a normal branch advance occurs after the lookup, the non-force ref update rejects it.
We verified these paths using the commit helper extracted from the pinned distributed JavaScript with local API doubles; a full latest-action GitHub E2E remains pending.

We accept this stale-content limitation while an upstream fix is prepared separately.
It can undo newer file content, including a security fix, but we have not demonstrated an approval bypass or privilege escalation from this behavior alone.
Rust no longer implements a private ZIP parser, artifact snapshot, or expected-head commit engine for Securefix.
Owner authorization and required checks still apply to the resulting PR head before approval or merge.

## Approval remains in Rust

`csm-actions/approve-pr-action` v1.0.0 at commit `a8fdc60ab4d9b446694140534bbcc71c29fb499c` has no expected-head input.
Its server discovers live commits and approves its internally selected `lastSha`.
An update from authorized A to B between our gate and that action could therefore approve B.
It also does not enforce this server's sensitive-path owner authorization.
The native approval path continues to specify the accepted SHA in the review and revalidate authorization before writing.

Sources: [Securefix preparation](https://github.com/csm-actions/securefix-action/blob/1b770a7af0ec5e04517295b4e14c4b451359d550/src/prepare.ts), [Securefix commit](https://github.com/csm-actions/securefix-action/blob/1b770a7af0ec5e04517295b4e14c4b451359d550/src/commit.ts), [approval server](https://github.com/csm-actions/approve-pr-action/blob/a8fdc60ab4d9b446694140534bbcc71c29fb499c/src/server.ts), and [approval inputs](https://github.com/csm-actions/approve-pr-action/blob/a8fdc60ab4d9b446694140534bbcc71c29fb499c/action.yaml).
