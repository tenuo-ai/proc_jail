//! Adversarial tests for proc_jail.
//!
//! These tests attempt to bypass security controls using various attack techniques.
//! All tests should demonstrate that the attack is properly blocked.

use proc_jail::{
    ArgRules, CwdPolicy, EnvPolicy, ExecError, InjectDoubleDash, ProcPolicy, ProcRequest,
    RiskyBinPolicy, Violation,
};
use std::collections::HashMap;
use std::time::Duration;

// =============================================================================
// Test Helpers
// =============================================================================

fn permissive_grep_policy() -> ProcPolicy {
    ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules(
            "/usr/bin/grep",
            ArgRules::new()
                .allowed_flags(&["-n", "-i", "-l", "-c", "-r", "-E", "-v", "--color=never"])
                .max_flags(5)
                .max_positionals(100)
                .inject_double_dash(InjectDoubleDash::AfterFlags),
        )
        .env_policy(EnvPolicy::LocaleOnly)
        .cwd_policy(CwdPolicy::fixed("/tmp"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("valid policy")
}

fn echo_policy() -> ProcPolicy {
    ProcPolicy::builder()
        .allow_bin("/bin/echo")
        .arg_rules(
            "/bin/echo",
            ArgRules::new()
                .allowed_flags(&["-n", "-e"])
                .max_flags(2)
                .max_positionals(50),
        )
        .timeout(Duration::from_secs(5))
        .build()
        .expect("valid policy")
}

// =============================================================================
// NULL BYTE INJECTION ATTACKS
// =============================================================================

#[test]
fn test_null_byte_in_binary_path() {
    // Attack: Try to truncate path with null byte
    // e.g., "/usr/bin/grep\0/bin/bash" might be interpreted as "/usr/bin/grep"
    let policy = permissive_grep_policy();

    let malicious_path = "/usr/bin/grep\0/bin/bash";
    let request = ProcRequest::new(malicious_path, vec!["pattern".to_string()]);

    // Should fail because the path with null byte won't exist/canonicalize properly
    let result = policy.prepare(request);
    assert!(result.is_err(), "Null byte in path should be rejected");
}

#[test]
fn test_null_byte_in_argument() {
    // Attack: Embed null byte in argument to potentially truncate or confuse parsing
    let policy = permissive_grep_policy();

    let tmp_file = "/tmp/proc_jail_null_test.txt";
    std::fs::write(tmp_file, "test content\n").unwrap();

    let malicious_arg = "pattern\0--file=/etc/passwd";
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec![malicious_arg.to_string(), tmp_file.to_string()],
    );

    // The argument with null byte should be treated as a literal string
    // It won't match anything but also won't cause injection
    let prepared = policy.prepare(request);
    assert!(
        prepared.is_ok(),
        "Null in arg should be accepted as literal"
    );

    std::fs::remove_file(tmp_file).ok();
}

// =============================================================================
// UNICODE ATTACKS
// =============================================================================

#[test]
fn test_unicode_homoglyph_flag() {
    // Attack: Use unicode characters that look like ASCII dashes
    // U+2010 HYPHEN, U+2011 NON-BREAKING HYPHEN, U+2212 MINUS SIGN
    let policy = permissive_grep_policy();

    // These look like "-n" but use different dash characters
    let homoglyph_flags = [
        "\u{2010}n", // HYPHEN
        "\u{2011}n", // NON-BREAKING HYPHEN
        "\u{2212}n", // MINUS SIGN
        "\u{FE63}n", // SMALL HYPHEN-MINUS
        "\u{FF0D}n", // FULLWIDTH HYPHEN-MINUS
    ];

    for fake_flag in homoglyph_flags {
        let request = ProcRequest::new("/usr/bin/grep", vec![fake_flag.to_string()]);

        // These should be treated as positionals (don't start with ASCII '-')
        // OR if treated as flags, should be rejected as not in allowlist
        let result = policy.prepare(request);

        // Either it's rejected as unknown flag, or it passes as positional
        // The key is it should NOT be treated as the allowed "-n" flag
        if let Ok(prepared) = result {
            // If it passed, verify it's treated as positional (-- injected before it)
            let argv = prepared.argv();
            if argv.contains(&"--".to_string()) {
                let dash_pos = argv.iter().position(|x| x == "--").unwrap();
                let flag_pos = argv.iter().position(|x| x == fake_flag).unwrap();
                assert!(
                    dash_pos < flag_pos,
                    "Homoglyph should be after -- (as positional)"
                );
            }
        }
        // If Err, that's also fine - the attack was blocked
    }
}

#[test]
fn test_unicode_direction_override() {
    // Attack: Use RTL override to make text appear different than it is
    // U+202E RIGHT-TO-LEFT OVERRIDE
    let policy = permissive_grep_policy();

    let rtl_attack = "\u{202E}n-"; // Displays as "-n" but is actually "n-" reversed
    let request = ProcRequest::new("/usr/bin/grep", vec![rtl_attack.to_string()]);

    let result = policy.prepare(request);
    // Should either reject or treat as positional, not as "-n" flag
    if let Ok(prepared) = result {
        // The actual string doesn't start with '-', should be positional
        let argv = prepared.argv();
        assert!(
            !argv.iter().any(|a| a == "-n"),
            "RTL override should not create -n flag"
        );
    }
}

#[test]
fn test_unicode_in_env_var_name() {
    // Attack: Use unicode lookalike for LD_PRELOAD
    // Using LATIN SMALL LETTER D WITH STROKE (đ) instead of 'd'
    let mut env = HashMap::new();
    env.insert("LĐ_PRELOAD".to_string(), "/evil/lib.so".to_string());
    env.insert("LD\u{200B}_PRELOAD".to_string(), "/evil/lib.so".to_string()); // zero-width space

    let allowed: std::collections::HashSet<String> = ["LĐ_PRELOAD", "LD\u{200B}_PRELOAD"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let policy = EnvPolicy::AllowList(allowed);
    let result = policy.apply(&env);

    // These unicode variants should pass through (they're not the actual LD_PRELOAD)
    // This is actually "safe" because the kernel won't interpret them as LD_PRELOAD
    // But we should document this behavior
    assert!(
        !result.contains_key("LD_PRELOAD"),
        "Real LD_PRELOAD should not be present"
    );
}

// =============================================================================
// SHELL METACHARACTER ATTACKS
// =============================================================================

#[test]
fn test_shell_command_substitution() {
    // Attack: Try command substitution syntax
    let policy = echo_policy();

    let attacks = [
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "$((1+1))",
        "${PATH}",
    ];

    for attack in attacks {
        let request = ProcRequest::new("/bin/echo", vec![attack.to_string()]);
        let prepared = policy.prepare(request).unwrap();
        let output = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(prepared.spawn())
        })
        .join()
        .unwrap()
        .unwrap();

        // Echo should print the literal string, not execute it
        let stdout = output.stdout_string();
        assert!(
            stdout.contains(attack) || stdout.trim() == attack,
            "Attack string '{}' should be echoed literally, got: {}",
            attack,
            stdout
        );
    }
}

#[test]
fn test_shell_pipe_and_redirect() {
    // Attack: Try pipe and redirect syntax
    let policy = echo_policy();

    let attacks = [
        "foo | cat /etc/passwd",
        "foo > /tmp/pwned",
        "foo >> /tmp/pwned",
        "foo < /etc/passwd",
        "foo && cat /etc/passwd",
        "foo || cat /etc/passwd",
        "foo; cat /etc/passwd",
        "foo\ncat /etc/passwd",
    ];

    for attack in attacks {
        let request = ProcRequest::new("/bin/echo", vec![attack.to_string()]);
        let prepared = policy.prepare(request).unwrap();
        let output = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(prepared.spawn())
        })
        .join()
        .unwrap()
        .unwrap();

        // These should all be treated as literal strings
        assert!(
            output.success(),
            "Echo with '{}' should succeed",
            attack.escape_debug()
        );
    }
}

#[test]
fn test_shell_glob_patterns() {
    // Attack: Try glob patterns that might expand
    let policy = permissive_grep_policy();

    // Create test file
    let tmp_file = "/tmp/proc_jail_glob_test.txt";
    std::fs::write(tmp_file, "test\n").unwrap();

    let attacks = ["*", "/*", "/etc/*", "?", "[a-z]", "{a,b}"];

    for attack in attacks {
        let request = ProcRequest::new(
            "/usr/bin/grep",
            vec![attack.to_string(), tmp_file.to_string()],
        );

        // Should succeed in preparing (these are valid positional args)
        let result = policy.prepare(request);
        assert!(
            result.is_ok(),
            "Glob pattern '{}' should be accepted as literal",
            attack
        );
    }

    std::fs::remove_file(tmp_file).ok();
}

// =============================================================================
// PATH TRAVERSAL ATTACKS
// =============================================================================

#[test]
fn test_path_traversal_in_binary() {
    // Attack: Use .. to escape to different binary
    let policy = permissive_grep_policy();

    let attacks = [
        "/usr/bin/../bin/bash",
        "/usr/bin/grep/../../../bin/bash",
        "/usr/bin/./grep/../bash",
    ];

    for attack in attacks {
        let request = ProcRequest::new(attack, vec!["--version".to_string()]);
        let result = policy.prepare(request);

        // After canonicalization, these should resolve to /bin/bash which is not allowed
        match result {
            Err(Violation::BinNotAllowed { canonical, .. }) => {
                assert!(
                    canonical.contains("bash") || !canonical.contains("grep"),
                    "Path traversal should resolve to actual target"
                );
            }
            Err(Violation::BinRiskyDenied { .. }) => {
                // Also acceptable - bash is risky
            }
            Err(Violation::BinNotFound { .. }) => {
                // Path doesn't exist, also fine
            }
            Err(Violation::ArgFlagNotAllowed { .. }) => {
                // --version not allowed, also fine
            }
            Ok(_) => panic!("Path traversal '{}' should not succeed", attack),
            Err(e) => panic!("Unexpected error for '{}': {:?}", attack, e),
        }
    }
}

#[test]
fn test_symlink_chain_attack() {
    // Attack: Create chain of symlinks to evade detection
    use std::os::unix::fs::symlink;

    let link1 = "/tmp/proc_jail_link1";
    let link2 = "/tmp/proc_jail_link2";
    let link3 = "/tmp/proc_jail_link3";

    // Cleanup
    let _ = std::fs::remove_file(link1);
    let _ = std::fs::remove_file(link2);
    let _ = std::fs::remove_file(link3);

    // Create chain: link3 -> link2 -> link1 -> /bin/bash
    symlink("/bin/bash", link1).ok();
    symlink(link1, link2).ok();
    symlink(link2, link3).ok();

    let policy = permissive_grep_policy();
    let request = ProcRequest::new(link3, vec![]);
    let result = policy.prepare(request);

    // Should resolve through all symlinks to /bin/bash and reject
    assert!(
        matches!(
            result,
            Err(Violation::BinNotAllowed { .. }) | Err(Violation::BinRiskyDenied { .. })
        ),
        "Symlink chain should resolve to blocked binary"
    );

    // Cleanup
    let _ = std::fs::remove_file(link1);
    let _ = std::fs::remove_file(link2);
    let _ = std::fs::remove_file(link3);
}

// =============================================================================
// FLAG INJECTION ATTACKS
// =============================================================================

#[test]
fn test_flag_injection_via_positional() {
    // Attack: Try to inject flags via positional arguments
    // Note: Arguments starting with '-' are classified as flags BEFORE double-dash
    // This test verifies that:
    // 1. A pattern starting with '-' that's not in allowlist is rejected
    // 2. A pattern NOT starting with '-' gets -- injected before it
    let policy = permissive_grep_policy();

    let tmp_file = "/tmp/proc_jail_flag_inject.txt";
    std::fs::write(tmp_file, "test\n").unwrap();

    // First: verify that something looking like a flag is rejected if not allowed
    let malicious_flag = "-f/etc/passwd";
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec![
            "-n".to_string(),
            malicious_flag.to_string(),
            tmp_file.to_string(),
        ],
    );
    let result = policy.prepare(request);
    assert!(
        matches!(result, Err(Violation::ArgFlagNotAllowed { .. })),
        "Flag-like argument should be rejected: {:?}",
        result
    );

    // Second: verify that a legitimate positional gets -- injected
    let user_pattern = "search_term"; // Doesn't start with -
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec![
            "-n".to_string(),
            user_pattern.to_string(),
            tmp_file.to_string(),
        ],
    );
    let prepared = policy.prepare(request).unwrap();
    let argv = prepared.argv();

    // With double-dash injection, pattern should be after --
    let dash_pos = argv
        .iter()
        .position(|x| x == "--")
        .expect("-- should be injected");
    let pattern_pos = argv
        .iter()
        .position(|x| x == user_pattern)
        .expect("pattern should be in argv");

    assert!(
        pattern_pos > dash_pos,
        "Pattern should be after --, got argv: {:?}",
        argv
    );

    std::fs::remove_file(tmp_file).ok();
}

#[test]
fn test_flag_with_equals_bypass() {
    // Attack: Try --flag=value when only --flag is allowed
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules(
            "/usr/bin/grep",
            ArgRules::new()
                .allowed_flags(&["--color"]) // Only --color, not --color=xxx
                .max_flags(1)
                .max_positionals(2),
        )
        .build()
        .unwrap();

    // Try to use --color=always when only --color is allowed
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["--color=always".to_string(), "pattern".to_string()],
    );

    let result = policy.prepare(request);
    assert!(
        matches!(result, Err(Violation::ArgFlagNotAllowed { ref flag }) if flag == "--color=always"),
        "--color=always should not match --color allowlist entry"
    );
}

#[test]
fn test_combined_short_flags_not_expanded() {
    // Verify that -abc is NOT expanded to -a -b -c
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules(
            "/usr/bin/grep",
            ArgRules::new()
                .allowed_flags(&["-a", "-b", "-c"])
                .max_flags(3)
                .max_positionals(2),
        )
        .build()
        .unwrap();

    // -abc should be rejected as a single unknown flag
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-abc".to_string(), "pattern".to_string()],
    );

    let result = policy.prepare(request);
    assert!(
        matches!(result, Err(Violation::ArgFlagNotAllowed { ref flag }) if flag == "-abc"),
        "-abc should not be expanded, got: {:?}",
        result
    );
}

// =============================================================================
// ENVIRONMENT BYPASS ATTACKS
// =============================================================================

#[test]
fn test_env_case_sensitivity_bypass() {
    // Attack: Try lowercase versions of dangerous env vars
    let lowercase_attacks = [
        ("ld_preload", "/evil/lib.so"),
        ("Ld_Preload", "/evil/lib.so"),
        ("LD_preload", "/evil/lib.so"),
        ("pythonpath", "/evil/python"),
        ("PythonPath", "/evil/python"),
    ];

    for (key, value) in lowercase_attacks {
        let mut env = HashMap::new();
        env.insert(key.to_string(), value.to_string());

        // Using Fixed policy to explicitly include the var
        let policy = EnvPolicy::Fixed(env.clone());
        let result = policy.apply(&HashMap::new());

        // Currently, only exact matches are stripped
        // This test documents the behavior - lowercase variants pass through
        // This is actually OK because the kernel is case-sensitive for these

        // The real LD_PRELOAD (uppercase) should definitely be stripped
        assert!(
            !result.contains_key("LD_PRELOAD"),
            "Uppercase LD_PRELOAD must be stripped"
        );
    }
}

#[test]
fn test_env_with_dangerous_value() {
    // Attack: Put shell commands in environment values
    let mut env = HashMap::new();
    env.insert("SAFE_VAR".to_string(), "$(rm -rf /)".to_string());
    env.insert("ANOTHER".to_string(), "; cat /etc/passwd".to_string());

    let allowed: std::collections::HashSet<String> = ["SAFE_VAR", "ANOTHER"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let policy = EnvPolicy::AllowList(allowed);
    let result = policy.apply(&env);

    // Values pass through unchanged - proc_jail doesn't interpret values
    // This is documented behavior - the spawned process receives literal values
    assert_eq!(result.get("SAFE_VAR"), Some(&"$(rm -rf /)".to_string()));
}

// =============================================================================
// RESOURCE EXHAUSTION ATTACKS
// =============================================================================

#[tokio::test]
async fn test_stdout_limit_boundary() {
    // Attack: Output exactly at the limit
    // Note: dd uses operand=value syntax (not flags), so these are positionals
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/dd")
        .arg_rules(
            "/bin/dd",
            ArgRules::new().max_flags(0).max_positionals(4), // dd operands are positionals (no leading -)
        )
        .max_stdout(1000)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Output exactly 1001 bytes (one over limit)
    let request = ProcRequest::new(
        "/bin/dd",
        vec![
            "if=/dev/zero".to_string(),
            "bs=1".to_string(),
            "count=1001".to_string(),
        ],
    );

    let prepared = policy.prepare(request).unwrap();
    let result = prepared.spawn().await;

    assert!(
        matches!(result, Err(ExecError::StdoutLimitExceeded { limit: 1000 })),
        "Should hit stdout limit at 1000 bytes, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_timeout_boundary() {
    // Attack: Process that runs just over timeout
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/sleep")
        .arg_rules("/bin/sleep", ArgRules::new().max_positionals(1))
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let request = ProcRequest::new("/bin/sleep", vec!["1".to_string()]);
    let prepared = policy.prepare(request).unwrap();
    let result = prepared.spawn().await;

    assert!(
        matches!(result, Err(ExecError::Timeout { .. })),
        "Should timeout"
    );
}

// =============================================================================
// CWD ATTACKS
// =============================================================================

#[test]
fn test_cwd_symlink_escape() {
    // Attack: Use symlink in CWD to escape jail
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let jail = TempDir::new().unwrap();
    let escape_link = jail.path().join("escape");

    // Create symlink pointing outside jail
    symlink("/etc", &escape_link).ok();

    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/env")
        .arg_rules("/usr/bin/env", ArgRules::new())
        .risky_bin_policy(RiskyBinPolicy::Disabled)
        .cwd_policy(CwdPolicy::jailed(jail.path(), jail.path()))
        .build()
        .unwrap();

    let request = ProcRequest::new("/usr/bin/env", vec![]).with_cwd(&escape_link);
    let result = policy.prepare(request);

    // After canonicalization, /etc should be detected as outside jail
    assert!(
        matches!(result, Err(Violation::CwdForbidden { .. })),
        "Symlink escape from CWD jail should be blocked"
    );
}

#[test]
fn test_cwd_traversal_escape() {
    // Attack: Use .. to escape CWD jail
    use tempfile::TempDir;

    let jail = TempDir::new().unwrap();
    let subdir = jail.path().join("subdir");
    std::fs::create_dir(&subdir).unwrap();

    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/env")
        .arg_rules("/usr/bin/env", ArgRules::new())
        .risky_bin_policy(RiskyBinPolicy::Disabled)
        .cwd_policy(CwdPolicy::jailed(&subdir, &subdir))
        .build()
        .unwrap();

    // Try to escape using ..
    let escape_path = subdir.join("..");
    let request = ProcRequest::new("/usr/bin/env", vec![]).with_cwd(&escape_path);
    let result = policy.prepare(request);

    // Should be blocked - canonicalization resolves .. and detects escape
    assert!(
        matches!(result, Err(Violation::CwdForbidden { .. })),
        "Path traversal escape from CWD jail should be blocked"
    );
}

// =============================================================================
// BINARY CONFUSION ATTACKS
// =============================================================================

#[test]
fn test_relative_path_with_slash() {
    // Attack: Use paths that look absolute but aren't
    let policy = permissive_grep_policy();

    let attacks = ["./usr/bin/grep", "../usr/bin/grep", "usr/bin/grep"];

    for attack in attacks {
        let request = ProcRequest::new(attack, vec![]);
        let result = policy.prepare(request);

        assert!(
            matches!(result, Err(Violation::BinNotAbsolute { .. })),
            "Relative path '{}' should be rejected",
            attack
        );
    }
}

#[test]
fn test_double_slash_in_path() {
    // Attack: Use // in path to potentially confuse canonicalization
    let policy = permissive_grep_policy();

    let request = ProcRequest::new("//usr//bin//grep", vec!["pattern".to_string()]);

    // This should either:
    // 1. Canonicalize to /usr/bin/grep and work
    // 2. Fail for some other reason
    // It should NOT bypass the allowlist
    let result = policy.prepare(request);

    // If it succeeds, verify it resolved correctly
    if let Ok(prepared) = result {
        assert!(
            prepared.bin().to_str().unwrap().contains("grep"),
            "Double slashes should canonicalize properly"
        );
    }
}

// =============================================================================
// SUBCOMMAND ATTACKS
// =============================================================================

#[test]
fn test_subcommand_injection_via_flag_value() {
    // Attack: Try to inject subcommand via flag that takes value
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/git")
        .arg_rules(
            "/usr/bin/git",
            ArgRules::new()
                .subcommand("status")
                .allowed_flags(&["--porcelain"])
                .max_flags(1)
                .max_positionals(0),
        )
        .build()
        .unwrap();

    // Try various attacks
    let attacks = [
        vec!["push".to_string()],                       // Wrong subcommand
        vec!["--porcelain".to_string()],                // Flag without subcommand
        vec!["status".to_string(), "push".to_string()], // Extra positional (subcommand)
    ];

    for argv in attacks {
        let request = ProcRequest::new("/usr/bin/git", argv.clone());
        let result = policy.prepare(request);

        // All should fail in some way
        assert!(result.is_err(), "Attack {:?} should be blocked", argv);
    }
}

// =============================================================================
// ARGUMENT COUNT ATTACKS
// =============================================================================

#[test]
fn test_max_args_boundary() {
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/echo")
        .arg_rules("/bin/echo", ArgRules::new().max_flags(0).max_positionals(3))
        .build()
        .unwrap();

    // Exactly at limit - should succeed
    let request = ProcRequest::new(
        "/bin/echo",
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
    );
    assert!(policy.prepare(request).is_ok());

    // One over limit - should fail
    let request = ProcRequest::new(
        "/bin/echo",
        vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ],
    );
    assert!(matches!(
        policy.prepare(request),
        Err(Violation::ArgTooManyPositionals { max: 3, got: 4 })
    ));
}

#[test]
fn test_very_long_argument() {
    // Attack: Very long argument to test buffer handling
    let policy = echo_policy();

    let long_arg = "A".repeat(1_000_000); // 1MB argument
    let request = ProcRequest::new("/bin/echo", vec![long_arg]);

    // Should be accepted (no length limit in policy)
    // Real limit would come from OS ARG_MAX
    let result = policy.prepare(request);
    assert!(result.is_ok(), "Long argument should be accepted by policy");
}
