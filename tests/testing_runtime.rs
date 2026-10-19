use std::process::Command;

#[test]
fn server_testing_runtime_requires_authenticated_reads_before_network_access() {
    let source = "a".repeat(40);
    let result = Command::new(env!("CARGO_BIN_EXE_securefix"))
        .args([
            "integration",
            "load-testing-runtime",
            "--workflow-sha",
            &source,
        ])
        .env("GITHUB_REPOSITORY", "civitaspo/securefix-server")
        .env("SECUREFIX_TEST_BASELINE_SHA", &source)
        .env("GITHUB_TOKEN", "")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("server GITHUB_TOKEN is empty"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
