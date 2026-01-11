//! Integration tests for proc_jail.
//!
//! These tests verify end-to-end behavior with real binaries.

use proc_jail::{ArgRules, CwdPolicy, EnvPolicy, InjectDoubleDash, ProcPolicy, ProcRequest, RiskyBinPolicy, Violation};
use std::time::Duration;

/// Helper to create a grep policy for testing.
fn grep_policy() -> ProcPolicy {
    ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules(
            "/usr/bin/grep",
            ArgRules::new()
                .allowed_flags(&["-n", "-i", "-l", "-c", "-r", "-E", "--color=never"])
                .max_flags(5)
                .max_positionals(10)
                .inject_double_dash(InjectDoubleDash::AfterFlags),
        )
        .env_policy(EnvPolicy::LocaleOnly)
        .cwd_policy(CwdPolicy::fixed("/tmp"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("valid policy")
}

#[tokio::test]
async fn test_grep_basic_execution() {
    let policy = grep_policy();

    // Create a temp file
    let content = "hello world\nfoo bar\nhello again\n";
    let tmp_file = "/tmp/proc_jail_test_grep.txt";
    std::fs::write(tmp_file, content).unwrap();

    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".to_string(), "hello".to_string(), tmp_file.to_string()],
    );

    let prepared = policy.prepare(request).unwrap();
    let output = prepared.spawn().await.unwrap();

    assert!(output.success());
    let stdout = output.stdout_string();
    assert!(stdout.contains("1:hello world"));
    assert!(stdout.contains("3:hello again"));

    std::fs::remove_file(tmp_file).ok();
}

#[tokio::test]
async fn test_double_dash_injection_works() {
    let policy = grep_policy();

    // Create a temp file
    let tmp_file = "/tmp/proc_jail_dd_test.txt";
    std::fs::write(tmp_file, "test content\n").unwrap();

    // Normal pattern that doesn't look like a flag
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".to_string(), "test".to_string(), tmp_file.to_string()],
    );

    let prepared = policy.prepare(request).unwrap();

    // Verify -- was injected between flags and positionals
    let argv = prepared.argv();
    assert!(argv.contains(&"--".to_string()), "Expected -- to be inserted");
    
    // The argv should be: ["-n", "--", "test", tmp_file]
    let dash_pos = argv.iter().position(|x| x == "--").unwrap();
    let n_pos = argv.iter().position(|x| x == "-n").unwrap();
    assert!(n_pos < dash_pos, "Flag should come before --");

    std::fs::remove_file(tmp_file).ok();
}

#[tokio::test]
async fn test_shell_injection_prevented() {
    let policy = grep_policy();

    // Create a temp file to search
    let tmp_file = "/tmp/proc_jail_injection_test.txt";
    std::fs::write(tmp_file, "test content").unwrap();

    // Try to inject shell command via pattern
    let malicious_query = "test'; rm -rf /tmp/important; echo '";

    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".to_string(), malicious_query.to_string(), tmp_file.to_string()],
    );

    let prepared = policy.prepare(request).unwrap();
    let output = prepared.spawn().await.unwrap();

    // The "injection" is just a literal pattern - grep won't find it
    // But importantly, no shell commands were executed
    assert!(output.stdout_string().is_empty() || !output.success());

    std::fs::remove_file(tmp_file).ok();
}

#[tokio::test]
async fn test_binary_not_allowed() {
    let policy = grep_policy();

    // Try to run a binary not in the allowlist
    let request = ProcRequest::new("/bin/ls", vec![]);

    let result = policy.prepare(request);
    assert!(matches!(result, Err(Violation::BinNotAllowed { .. })));
}

#[tokio::test]
async fn test_risky_binary_denied() {
    // Policy without RiskyBinPolicy::Disabled
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/bash")
        .arg_rules("/bin/bash", ArgRules::new())
        .build()
        .unwrap();

    let request = ProcRequest::new("/bin/bash", vec![]);
    let result = policy.prepare(request);

    assert!(matches!(result, Err(Violation::BinRiskyDenied { .. })));
}

#[tokio::test]
async fn test_flag_not_allowed() {
    let policy = grep_policy();

    // -f (file) is not in the allowlist
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-f".to_string(), "/etc/passwd".to_string()],
    );

    let result = policy.prepare(request);
    assert!(matches!(result, Err(Violation::ArgFlagNotAllowed { .. })));
}

#[tokio::test]
async fn test_timeout_kills_process() {
    // Create a policy with very short timeout
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/sleep")
        .arg_rules("/bin/sleep", ArgRules::new().max_positionals(1))
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();

    let request = ProcRequest::new("/bin/sleep", vec!["10".to_string()]);
    let prepared = policy.prepare(request).unwrap();
    let result = prepared.spawn().await;

    assert!(matches!(result, Err(proc_jail::ExecError::Timeout { .. })));
}

#[tokio::test]
async fn test_symlink_resolves_to_allowlist() {
    use std::os::unix::fs::symlink;

    // Create a symlink to grep
    let link_path = "/tmp/proc_jail_grep_link";
    let _ = std::fs::remove_file(link_path);

    // On macOS, grep is at /usr/bin/grep
    symlink("/usr/bin/grep", link_path).unwrap();

    // Policy allows /usr/bin/grep
    let policy = grep_policy();

    // Request via symlink should work (resolves to allowed binary)
    let request = ProcRequest::new(link_path, vec!["--help".to_string()]);

    // This should fail because --help is not in our allowed flags
    let result = policy.prepare(request);
    assert!(matches!(result, Err(Violation::ArgFlagNotAllowed { .. })));

    std::fs::remove_file(link_path).ok();
}

#[tokio::test]
async fn test_env_policy_empty() {
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/env")
        .arg_rules("/usr/bin/env", ArgRules::new().max_positionals(0))
        .risky_bin_policy(RiskyBinPolicy::Disabled) // env is risky
        .env_policy(EnvPolicy::Empty)
        .build()
        .unwrap();

    let request = ProcRequest::new("/usr/bin/env", vec![]);
    let prepared = policy.prepare(request).unwrap();
    let output = prepared.spawn().await.unwrap();

    // With empty env, /usr/bin/env should print nothing
    assert!(output.stdout_string().is_empty());
}

#[tokio::test]
async fn test_env_policy_locale_only() {
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/env")
        .arg_rules("/usr/bin/env", ArgRules::new().max_positionals(0))
        .risky_bin_policy(RiskyBinPolicy::Disabled)
        .env_policy(EnvPolicy::LocaleOnly)
        .build()
        .unwrap();

    let request = ProcRequest::new("/usr/bin/env", vec![]);
    let prepared = policy.prepare(request).unwrap();
    let output = prepared.spawn().await.unwrap();

    let stdout = output.stdout_string();
    assert!(stdout.contains("LANG=C.UTF-8"));
    assert!(stdout.contains("LC_ALL=C.UTF-8"));
}

#[tokio::test]
async fn test_subcommand_pinning() {
    // This test requires git to be installed
    if !std::path::Path::new("/usr/bin/git").exists() {
        return;
    }

    // Use "version" (without --) as subcommand since subcommands are positional
    // Actually git doesn't have a "version" subcommand, let's use "status"
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/git")
        .arg_rules(
            "/usr/bin/git",
            ArgRules::new()
                .subcommand("status")
                .allowed_flags(&["--porcelain", "-s"])
                .max_flags(2)
                .max_positionals(0),
        )
        .cwd_policy(CwdPolicy::fixed("/tmp"))
        .build()
        .unwrap();

    // Wrong subcommand rejected
    let request = ProcRequest::new("/usr/bin/git", vec!["push".to_string()]);
    let result = policy.prepare(request);
    assert!(matches!(result, Err(Violation::ArgSubcommandMismatch { .. })));

    // Correct subcommand accepted (might fail at runtime if /tmp isn't a git repo, but prepare succeeds)
    let request = ProcRequest::new("/usr/bin/git", vec!["status".to_string()]);
    let result = policy.prepare(request);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_positional_with_dash_like_content() {
    // Test that content that looks like a flag is properly handled as positional after --
    let policy = grep_policy();

    // Create a temp file
    let tmp_file = "/tmp/proc_jail_dash_content.txt";
    std::fs::write(tmp_file, "-e\n--verbose\n--help\n").unwrap();

    // Search for literal "-e" in the file
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".to_string(), "--".to_string(), "-e".to_string(), tmp_file.to_string()],
    );

    // This should work because -- is already present, and -e after -- is positional
    let prepared = policy.prepare(request).unwrap();
    let output = prepared.spawn().await.unwrap();

    assert!(output.success());
    assert!(output.stdout_string().contains("1:-e"));

    std::fs::remove_file(tmp_file).ok();
}
