# Native Securefix protocol and candidate verification

Status: accepted.
Supersedes ADR 0005's upstream implementation dependency.

The Rust executable owns artifact creation and validation, signed repair commits, pull request reconciliation and runtime distribution. Workflows isolate credentials and invoke the executable. The external metadata and fixed-file artifact envelope remains readable so existing clients can migrate without a simultaneous fleet deployment.

`policy.json` is the only repository capability registry. The duplicated upstream configuration is removed. Same-branch repairs bind the destination to the source run's exact head. GitHub's `createCommitOnBranch` compares that expected head atomically and supplies a verified signature. A release branch has its own validated destination tip; its source default head and pinned workflow provenance are checked independently before applying the destination CAS.

Production writes still require the current protected server revision. Candidate tests use a separate typed API context. It permits writes only to `civitaspo/testing-securefix-server`, verifies the immutable repository ID, and accepts only installation tokens scoped to exactly that repository. It does not change production policy resolution or allow stale production runtimes.

A secret-free job builds the candidate executable. A fresh execution job downloads its same-run immutable artifact and mints scratch-only installation tokens. Candidate processes receive those tokens, not App private keys, the bot's personal token, administrative credentials or release signing keys. Runtime Releases are reserved for stable protected-main promotion.

The integration harness records immutable fixture state, validates actual owner comments, remote signatures, current-head approval and required checks, performs a squash merge and proves stale-head rejection. Source-workflow artifact provenance has separate negative fixtures. Functional scratch testing does not represent a production deployment or bypass its provenance contract.
