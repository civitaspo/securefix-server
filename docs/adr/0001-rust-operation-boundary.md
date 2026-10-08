# Use one Rust executable for repository-owned logic

The original implementation scattered authorization and release decisions across Bash, Ruby, Python, and github-script steps.
We use one Rust package with modules for each operation, a shared GitHub API boundary, and one explicit repository policy.
Rust matches the maintainer's preference and makes request and operation states reviewable through typed data.

Workflows retain job isolation, environments, native token creation, pinned actions, and executable invocations.
The upstream Securefix client artifact protocol remains supported; the privileged server implementation is native Rust.
Keeping the executable as a single package avoids another service or distribution system.
