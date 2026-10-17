# Use one Rust package for repository-owned logic

The original implementation scattered authorization and release decisions across Bash, Ruby, Python, and github-script steps.
We use one Rust package with modules for each operation, a shared GitHub API boundary, and one explicit repository policy.
Rust matches the maintainer's preference and makes request and operation states reviewable through typed data.

Workflows retain job isolation, environments, native token creation, pinned actions, and executable invocations.
Rust owns repository-specific authorization, artifact validation, commits, and notifications.
Keeping the implementation in a single package avoids another service or distribution system.
The normal `securefix` executable uses the verified active runtime. The one-time
`securefix-bootstrap` executable is built separately from the fixed protected-main
workflow source without production credentials; it qualifies candidate archives as
data before initial activation. Both use Rust and the existing shared modules.
