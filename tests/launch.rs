//! Tests for launching through a wrapper and process-group cleanup.

use proc_jail::{ArgRules, EnvPolicy, ExecError, ProcPolicy, ProcRequest, RiskyBinPolicy};
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

/// Policy that allows `/bin/sh -c <script>`.
fn sh_policy(timeout: Duration) -> ProcPolicy {
    ProcPolicy::builder()
        .allow_bin("/bin/sh")
        .arg_rules(
            "/bin/sh",
            ArgRules::new()
                .allowed_flags(&["-c"])
                .max_flags(1)
                .max_positionals(1),
        )
        .risky_bin_policy(RiskyBinPolicy::AllowWithWarning)
        .env_policy(EnvPolicy::Empty)
        .timeout(timeout)
        .max_stdout(64 * 1024)
        .build()
        .unwrap()
}

fn sh(script: &str) -> ProcRequest {
    ProcRequest::new("/bin/sh", vec!["-c".to_string(), script.to_string()])
}

fn pid_alive(pid: i32) -> bool {
    // Signal 0 checks for existence without sending anything.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait up to two seconds for `pid` to disappear (it may linger briefly as a
/// zombie until init reaps it).
fn wait_gone(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn read_pid(path: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(pid) = s.trim().parse() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "grandchild pid never written");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn test_timeout_kills_grandchildren() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!("/bin/sleep 30 & echo $! > {}; wait", pid_file.display());

    let prepared = sh_policy(Duration::from_millis(300))
        .prepare(sh(&script))
        .unwrap();
    let start = Instant::now();
    let result = prepared.spawn().await;

    assert!(matches!(result, Err(ExecError::Timeout { .. })));
    assert!(start.elapsed() < Duration::from_secs(5));
    let pid = read_pid(&pid_file);
    assert!(wait_gone(pid), "grandchild {} survived timeout", pid);
}

#[test]
fn test_timeout_kills_grandchildren_sync() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!("/bin/sleep 30 & echo $! > {}; wait", pid_file.display());

    let prepared = sh_policy(Duration::from_millis(300))
        .prepare(sh(&script))
        .unwrap();
    let start = Instant::now();
    let result = prepared.spawn_sync();

    assert!(matches!(result, Err(ExecError::Timeout { .. })));
    assert!(start.elapsed() < Duration::from_secs(5));
    let pid = read_pid(&pid_file);
    assert!(wait_gone(pid), "grandchild {} survived timeout", pid);
}

#[tokio::test]
async fn test_stdout_limit_kills_grandchildren() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!(
        "/bin/sleep 30 & echo $! > {}; while :; do echo xxxxxxxxxxxxxxxx; done",
        pid_file.display()
    );

    let prepared = sh_policy(Duration::from_secs(10))
        .prepare(sh(&script))
        .unwrap();
    let start = Instant::now();
    let result = prepared.spawn().await;

    assert!(matches!(result, Err(ExecError::StdoutLimitExceeded { .. })));
    assert!(start.elapsed() < Duration::from_secs(5));
    let pid = read_pid(&pid_file);
    assert!(wait_gone(pid), "grandchild {} survived stdout limit", pid);
}

#[tokio::test]
async fn test_wrap_with_launches_through_program() {
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/echo")
        .arg_rules("/bin/echo", ArgRules::new().max_positionals(1))
        .build()
        .unwrap();

    let prepared = policy
        .prepare(ProcRequest::new("/bin/echo", vec!["hello".to_string()]))
        .unwrap()
        .wrap_with("/bin/sh", ["-c", "echo wrapped; exec \"$@\"", "launcher"]);

    // Accessors still describe the validated command.
    assert_eq!(prepared.bin(), Path::new("/bin/echo"));
    assert_eq!(prepared.argv(), ["hello".to_string()]);
    assert_eq!(prepared.launch_program(), Path::new("/bin/sh"));
    let expected: Vec<OsString> = [
        "-c",
        "echo wrapped; exec \"$@\"",
        "launcher",
        "/bin/echo",
        "hello",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    assert_eq!(prepared.launch_args(), expected);

    let output = prepared.spawn().await.unwrap();
    assert!(output.success());
    assert_eq!(output.stdout_string(), "wrapped\nhello\n");
}

#[tokio::test]
async fn test_without_wrapper_launches_bin() {
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/echo")
        .arg_rules("/bin/echo", ArgRules::new().max_positionals(1))
        .build()
        .unwrap();

    let prepared = policy
        .prepare(ProcRequest::new("/bin/echo", vec!["hi".to_string()]))
        .unwrap();
    assert_eq!(prepared.launch_program(), prepared.bin().as_path());
    assert_eq!(prepared.launch_args(), vec![OsString::from("hi")]);
}

#[tokio::test]
async fn test_launch_env_added_after_policy() {
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/env")
        .arg_rules("/usr/bin/env", ArgRules::new().max_positionals(0))
        .risky_bin_policy(RiskyBinPolicy::Disabled) // env is risky
        .env_policy(EnvPolicy::Empty)
        .build()
        .unwrap();

    let request = ProcRequest::new("/usr/bin/env", vec![]).with_env_var("FROM_REQUEST", "1");
    let prepared = policy
        .prepare(request)
        .unwrap()
        .with_launch_env("TMPDIR", "/tmp/proc_jail_sandbox");

    assert!(prepared.env().is_empty());
    assert_eq!(
        prepared.launch_env(),
        [("TMPDIR".to_string(), "/tmp/proc_jail_sandbox".to_string())]
    );

    let output = prepared.spawn().await.unwrap();
    assert_eq!(output.stdout_string(), "TMPDIR=/tmp/proc_jail_sandbox\n");
}

#[test]
fn test_wrap_does_not_bypass_validation() {
    let policy = ProcPolicy::builder()
        .allow_bin("/bin/echo")
        .arg_rules("/bin/echo", ArgRules::new().max_positionals(1))
        .build()
        .unwrap();

    // Disallowed binaries are rejected before a wrapper can be attached.
    assert!(policy
        .prepare(ProcRequest::new("/bin/cat", vec![]))
        .is_err());
}
