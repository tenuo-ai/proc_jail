//! A command stopped by its timeout or an output limit still returns the
//! output it wrote before it was stopped.

use proc_jail::{ArgRules, EnvPolicy, ExecError, ProcPolicy, ProcRequest, RiskyBinPolicy};
use std::time::Duration;

/// Policy that allows `/bin/sh -c <script>`.
fn sh_policy(timeout: Duration, max_stdout: usize, max_stderr: usize) -> ProcPolicy {
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
        .max_stdout(max_stdout)
        .max_stderr(max_stderr)
        .build()
        .unwrap()
}

fn sh(script: &str) -> ProcRequest {
    ProcRequest::new("/bin/sh", vec!["-c".to_string(), script.to_string()])
}

#[tokio::test]
async fn timeout_returns_what_was_written() {
    let prepared = sh_policy(Duration::from_millis(500), 1024, 1024)
        .prepare(sh("echo started; echo warming up >&2; exec /bin/sleep 30"))
        .unwrap();
    let err = prepared.spawn().await.unwrap_err();

    assert!(matches!(err, ExecError::Timeout { .. }), "{err:?}");
    let partial = err.partial_output().unwrap();
    assert_eq!(partial.stdout_string(), "started\n");
    assert_eq!(partial.stderr_string(), "warming up\n");
}

#[test]
fn timeout_returns_what_was_written_sync() {
    let prepared = sh_policy(Duration::from_millis(500), 1024, 1024)
        .prepare(sh("echo started; exec /bin/sleep 30"))
        .unwrap();
    let err = prepared.spawn_sync().unwrap_err();

    assert_eq!(err.partial_output().unwrap().stdout, b"started\n");
}

#[tokio::test]
async fn stdout_limit_returns_exactly_the_limit() {
    let prepared = sh_policy(Duration::from_secs(10), 100, 1024)
        .prepare(sh("echo oops >&2; while :; do echo 0123456789; done"))
        .unwrap();
    let err = prepared.spawn().await.unwrap_err();

    let ExecError::StdoutLimitExceeded { limit, partial } = &err else {
        panic!("expected the stdout limit, got {err:?}");
    };
    assert_eq!(*limit, 100);
    assert_eq!(partial.stdout.len(), 100);
    assert!(partial.stdout.starts_with(b"0123456789\n"));
    // The other stream is read concurrently, so it may not be read yet.
    assert!(b"oops\n".starts_with(&partial.stderr));
}

#[tokio::test]
async fn stderr_limit_returns_exactly_the_limit() {
    let prepared = sh_policy(Duration::from_secs(10), 1024, 50)
        .prepare(sh("echo ok; while :; do echo 0123456789 >&2; done"))
        .unwrap();
    let err = prepared.spawn().await.unwrap_err();

    assert!(
        matches!(err, ExecError::StderrLimitExceeded { limit: 50, .. }),
        "{err:?}"
    );
    let partial = err.partial_output().unwrap();
    assert_eq!(partial.stderr.len(), 50);
    assert!(b"ok\n".starts_with(&partial.stdout));
}

#[tokio::test]
async fn partial_output_stays_out_of_debug_and_display() {
    let prepared = sh_policy(Duration::from_millis(300), 1024, 1024)
        .prepare(sh("echo secret-value; exec /bin/sleep 30"))
        .unwrap();
    let err = prepared.spawn().await.unwrap_err();

    assert!(!format!("{err:?}").contains("secret-value"), "{err:?}");
    assert!(!err.to_string().contains("secret-value"), "{err}");
    assert!(format!("{err:?}").contains("stdout_len: 13"), "{err:?}");
}

#[tokio::test]
async fn a_finished_command_has_no_partial_output() {
    let prepared = sh_policy(Duration::from_secs(10), 1024, 1024)
        .prepare(sh("exit 3"))
        .unwrap();
    let output = prepared.spawn().await.unwrap();
    assert_eq!(output.code(), Some(3));
}
