//! Prepared command ready for execution.
//!
//! This module contains `PreparedCommand`, which can only be created
//! by `ProcPolicy::prepare()`. This ensures all execution goes through validation.

use crate::error::ExecError;
use crate::limits::ResourceLimits;
use crate::output::{Output, PartialOutput};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// A validated command ready for execution.
///
/// This type cannot be constructed outside of `proc_jail`.
/// The only way to create it is via `ProcPolicy::prepare()`.
#[derive(Debug, Clone)]
pub struct PreparedCommand {
    pub(crate) bin: PathBuf,
    pub(crate) argv: Vec<String>,
    pub(crate) env: HashMap<String, String>,
    pub(crate) cwd: PathBuf,
    pub(crate) limits: ResourceLimits,
    pub(crate) wrapper: Option<Wrapper>,
    pub(crate) launch_env: Vec<(String, String)>,
}

/// A launcher program that the validated command is run through.
#[derive(Debug, Clone)]
pub(crate) struct Wrapper {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
}

impl PreparedCommand {
    /// Launch the validated command through another program.
    ///
    /// The process is started as `program args_before... bin argv...`, where
    /// `bin` and `argv` are the validated binary and arguments. This is meant
    /// for OS sandbox launchers (for example `sandbox-exec -p <profile>` or a
    /// namespace launcher that ends its own options with `--`).
    ///
    /// Validation is unaffected: the binary allowlist, argument rules, env
    /// policy and cwd policy were applied to the original `bin`/`argv` by
    /// `ProcPolicy::prepare()`, and [`bin()`](Self::bin) and
    /// [`argv()`](Self::argv) keep returning those. `program` and
    /// `args_before` are trusted caller input and are not checked against the
    /// policy. Use [`launch_program()`](Self::launch_program) and
    /// [`launch_args()`](Self::launch_args) to see what will actually be
    /// executed.
    ///
    /// Calling this again replaces the previous wrapper.
    pub fn wrap_with<P, I, A>(mut self, program: P, args_before: I) -> Self
    where
        P: Into<PathBuf>,
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.wrapper = Some(Wrapper {
            program: program.into(),
            args: args_before.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Add an environment variable to the launched process.
    ///
    /// Launch variables are applied after the env policy, so they are passed
    /// even if the policy would not allow them, and they override policy
    /// values with the same name. They are trusted caller input (for example a
    /// sandbox-specific `TMPDIR`), not something to fill from a request.
    pub fn with_launch_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.launch_env.push((key.into(), value.into()));
        self
    }

    /// Execute the prepared command asynchronously.
    ///
    /// # Returns
    ///
    /// The output of the command, or an error if execution failed.
    ///
    /// # Errors
    ///
    /// - `ExecError::SpawnFailed` if the process couldn't be started
    /// - `ExecError::Timeout` if the process exceeded the timeout
    /// - `ExecError::StdoutLimitExceeded` if stdout exceeded the limit
    /// - `ExecError::StderrLimitExceeded` if stderr exceeded the limit
    ///
    /// These three carry the output read before the command was stopped,
    /// capped at the limits ([`ExecError::partial_output`]).
    ///
    /// The command runs in its own process group. On error, or once the
    /// command exits, any processes still in that group are killed. If the
    /// returned future is dropped before it completes (for example because
    /// the caller cancelled the run), the group is killed too.
    pub async fn spawn(self) -> Result<Output, ExecError> {
        let start = Instant::now();

        // Build the command
        let mut cmd = Command::new(self.launch_program());
        cmd.args(self.launch_args())
            .current_dir(&self.cwd)
            .env_clear()
            .envs(&self.env)
            .envs(self.launch_env.iter().map(|(k, v)| (k, v)))
            // Own process group, so limits can kill grandchildren too.
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn
        let mut child = cmd.spawn().map_err(|e| ExecError::SpawnFailed {
            reason: e.to_string(),
        })?;
        let pgid = child.id();
        // Declared after `child`, so it is dropped first: the group is killed
        // while the child is still unreaped and its group id still reserved.
        let mut group = GroupGuard(pgid);

        // Take ownership of stdout/stderr
        let mut stdout = child.stdout.take().expect("stdout piped");
        let mut stderr = child.stderr.take().expect("stderr piped");

        let limits = self.limits;

        // The buffers live outside the timed future, so what was read before
        // a timeout or an output limit is still returned with the error.
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        // Read stdout and stderr concurrently with limits
        let read_future = async {
            let stdout_result = read_limited(
                &mut stdout,
                &mut stdout_buf,
                limits.max_stdout,
                Stop::Stdout,
                "stdout",
            );
            let stderr_result = read_limited(
                &mut stderr,
                &mut stderr_buf,
                limits.max_stderr,
                Stop::Stderr,
                "stderr",
            );

            // Run both concurrently; the first limit error stops both, so a
            // descendant holding the other pipe open cannot stall us.
            tokio::try_join!(stdout_result, stderr_result)?;
            Ok(())
        };

        // Read output while watching for the child to exit. Its exit is
        // observed without reaping it, so its pid (and process group id) stays
        // reserved; once it exits, the rest of its group is killed so that
        // descendants holding the pipes open cannot stall the read.
        let watch = async {
            let exited = match pgid {
                Some(pid) => wait_exited(pid).await,
                None => false,
            };
            if exited {
                kill_process_group(pgid);
            } else {
                // The child may already have been reaped, so its pid/group id
                // is no longer ours to signal and may be reused.
                group.disarm();
            }
            Ok::<_, Stop>(exited)
        };
        let run = async { tokio::try_join!(read_future, watch) };

        // Apply timeout
        let result = timeout(limits.timeout, run).await;
        let partial = |stdout: Vec<u8>, stderr: Vec<u8>| PartialOutput { stdout, stderr };

        match result {
            Ok(Ok(((), exited))) => {
                // Kill anything still left in the group after the pipes closed
                if exited {
                    kill_process_group(pgid);
                }
                group.disarm();
                let status = child.wait().await.map_err(|e| ExecError::SpawnFailed {
                    reason: format!("wait error: {}", e),
                })?;

                Ok(Output {
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                    status,
                })
            }
            Ok(Err(stop)) => {
                // Kill the process group on limit exceeded
                kill_process_group(pgid);
                drain(
                    &mut stdout,
                    &mut stderr,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    &limits,
                )
                .await;
                group.disarm();
                let _ = child.kill().await;
                let partial = partial(stdout_buf, stderr_buf);
                Err(match stop {
                    Stop::Stdout => ExecError::StdoutLimitExceeded {
                        limit: limits.max_stdout,
                        partial,
                    },
                    Stop::Stderr => ExecError::StderrLimitExceeded {
                        limit: limits.max_stderr,
                        partial,
                    },
                    Stop::Read(reason) => ExecError::SpawnFailed { reason },
                })
            }
            Err(_) => {
                // Timeout - kill and return error
                let elapsed = start.elapsed();
                kill_process_group(pgid);
                drain(
                    &mut stdout,
                    &mut stderr,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    &limits,
                )
                .await;
                group.disarm();
                let _ = child.kill().await;
                Err(ExecError::Timeout {
                    limit: limits.timeout,
                    elapsed,
                    partial: partial(stdout_buf, stderr_buf),
                })
            }
        }
    }

    /// Execute the prepared command synchronously.
    ///
    /// This is a convenience wrapper that creates a runtime if needed.
    pub fn spawn_sync(self) -> Result<Output, ExecError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            // A current-thread runtime cannot make progress while this call
            // blocks its only driver thread. Run an independent runtime on a
            // helper thread instead of borrowing the surrounding runtime.
            std::thread::scope(|scope| {
                scope
                    .spawn(move || self.spawn_on_new_runtime())
                    .join()
                    .unwrap_or_else(|_| {
                        Err(ExecError::SpawnFailed {
                            reason: "spawn worker thread panicked".to_string(),
                        })
                    })
            })
        } else {
            self.spawn_on_new_runtime()
        }
    }

    fn spawn_on_new_runtime(self) -> Result<Output, ExecError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ExecError::SpawnFailed {
                reason: format!("failed to create runtime: {}", e),
            })?;
        rt.block_on(self.spawn())
    }

    /// Get the validated binary path.
    ///
    /// This is the binary checked against the policy, even after
    /// [`wrap_with()`](Self::wrap_with).
    pub fn bin(&self) -> &PathBuf {
        &self.bin
    }

    /// Get the validated arguments (not including the binary).
    ///
    /// These are unchanged by [`wrap_with()`](Self::wrap_with).
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Get the environment produced by the env policy.
    ///
    /// Does not include variables added with
    /// [`with_launch_env()`](Self::with_launch_env).
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Get the variables added with [`with_launch_env()`](Self::with_launch_env).
    pub fn launch_env(&self) -> &[(String, String)] {
        &self.launch_env
    }

    /// Get the program that will be executed: the wrapper if set, else [`bin()`](Self::bin).
    pub fn launch_program(&self) -> &Path {
        match &self.wrapper {
            Some(w) => &w.program,
            None => &self.bin,
        }
    }

    /// Get the arguments passed to [`launch_program()`](Self::launch_program).
    ///
    /// Without a wrapper this equals [`argv()`](Self::argv). With one it is
    /// `args_before... bin argv...`.
    pub fn launch_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(w) = &self.wrapper {
            args.extend(w.args.iter().cloned());
            args.push(self.bin.clone().into_os_string());
        }
        args.extend(self.argv.iter().map(OsString::from));
        args
    }

    /// Get the working directory.
    pub fn cwd(&self) -> &PathBuf {
        &self.cwd
    }
}

/// Wait until the child `pid` has exited, leaving it unreaped (`WNOWAIT`).
///
/// Polls with `WNOHANG` on each SIGCHLD (and on a fallback interval), so the
/// future can be dropped at any point without leaving a blocked thread.
///
/// Returns `false` if the state could not be observed (for example the child
/// was already reaped), in which case its group id must not be signalled.
async fn wait_exited(pid: u32) -> bool {
    use tokio::signal::unix::{signal, SignalKind};

    // Register before the first check so an exit in between is not missed.
    let mut sigchld = signal(SignalKind::child()).ok();
    loop {
        match poll_exited(pid) {
            Some(exited) => return exited,
            None => {
                let tick = tokio::time::sleep(Duration::from_millis(50));
                match sigchld.as_mut() {
                    Some(sig) => {
                        tokio::select! {
                            _ = sig.recv() => {}
                            _ = tick => {}
                        }
                    }
                    None => tick.await,
                }
            }
        }
    }
}

/// Non-blocking exit check: `Some(true)` if exited, `None` if still running,
/// `Some(false)` if the state cannot be observed.
fn poll_exited(pid: u32) -> Option<bool> {
    let id: libc::id_t = pid;
    loop {
        // SAFETY: siginfo_t is plain data; zeroed is a valid initial value and
        // waitid only writes into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable siginfo_t for the duration of the call.
        let ret = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if ret == 0 {
            // With WNOHANG, si_pid stays 0 while the child is still running.
            // SAFETY: waitid filled `info` (or left it zeroed).
            let si_pid = unsafe { info.si_pid() };
            return if si_pid == 0 { None } else { Some(true) };
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Some(false);
        }
    }
}

/// Why reading output stopped early.
enum Stop {
    Stdout,
    Stderr,
    Read(String),
}

/// Reads `pipe` into `buf` until EOF, keeping at most `max` bytes and
/// stopping with `limit` once more arrive.
async fn read_limited<R: tokio::io::AsyncRead + Unpin>(
    pipe: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
    limit: Stop,
    name: &str,
) -> Result<(), Stop> {
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) => return Ok(()), // EOF
            Ok(n) => {
                if buf.len() + n > max {
                    let remaining = max.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remaining]);
                    return Err(limit);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(Stop::Read(format!("{name} read error: {e}"))),
        }
    }
}

/// How long to read what is left in the pipes once a command is stopped.
/// The pipes close when the killed group exits; a descendant that left the
/// group could hold them open, so the wait is bounded.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Reads what a stopped command wrote but was not yet read, up to the
/// limits, so the partial output ends where the command stopped.
async fn drain<O: tokio::io::AsyncRead + Unpin, E: tokio::io::AsyncRead + Unpin>(
    stdout: &mut O,
    stderr: &mut E,
    stdout_buf: &mut Vec<u8>,
    stderr_buf: &mut Vec<u8>,
    limits: &ResourceLimits,
) {
    // Each pipe is read only up to the room left in its buffer, so one
    // that is already full, or fills here, ends at once instead of waiting
    // on a pipe that may stay open.
    let room = |buf: &Vec<u8>, max: usize| max.saturating_sub(buf.len()) as u64;
    let mut stdout = stdout.take(room(stdout_buf, limits.max_stdout));
    let mut stderr = stderr.take(room(stderr_buf, limits.max_stderr));
    let _ = timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(
            read_limited(
                &mut stdout,
                stdout_buf,
                limits.max_stdout,
                Stop::Stdout,
                "stdout"
            ),
            read_limited(
                &mut stderr,
                stderr_buf,
                limits.max_stderr,
                Stop::Stderr,
                "stderr"
            ),
        );
    })
    .await;
}

/// Kills the process group when dropped, unless disarmed first. Disarm it
/// before reaping the child, after which the group id may be reused.
struct GroupGuard(Option<u32>);

impl GroupGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        kill_process_group(self.0);
    }
}

/// SIGKILL the process group led by `pgid` (the child spawned with `process_group(0)`).
///
/// Must be called before the child is reaped, so the group id cannot have
/// been reused.
fn kill_process_group(pgid: Option<u32>) {
    let Some(pgid) = pgid.and_then(|p| libc::pid_t::try_from(p).ok()) else {
        return;
    };
    if pgid <= 1 {
        return;
    }
    // SAFETY: killpg only sends a signal; it has no memory-safety preconditions.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_stdout: usize, max_stderr: usize) -> ResourceLimits {
        ResourceLimits::default()
            .with_max_stdout(max_stdout)
            .with_max_stderr(max_stderr)
    }

    #[tokio::test]
    async fn drain_appends_what_is_left_within_the_limits() {
        let (mut stdout, mut stderr): (&[u8], &[u8]) = (b"tail\n", b"0123456789");
        let (mut out, mut err) = (b"head\n".to_vec(), Vec::new());
        drain(&mut stdout, &mut stderr, &mut out, &mut err, &limits(64, 4)).await;
        assert_eq!(out, b"head\ntail\n");
        assert_eq!(err, b"0123");
    }

    #[tokio::test]
    async fn drain_gives_up_on_a_pipe_that_stays_open() {
        // The write end is kept open, as by a descendant that left the group.
        let (mut stdout, _writer) = tokio::io::duplex(64);
        let mut stderr: &[u8] = b"last words\n";
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let start = Instant::now();
        drain(
            &mut stdout,
            &mut stderr,
            &mut out,
            &mut err,
            &limits(64, 64),
        )
        .await;
        assert!(start.elapsed() < DRAIN_TIMEOUT * 4);
        assert_eq!(err, b"last words\n");
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn drain_does_not_wait_on_a_pipe_that_is_already_full() {
        // stdout is at its limit and its pipe stays open; stderr fills up.
        let (mut stdout, _writer) = tokio::io::duplex(64);
        let (mut stderr, mut stderr_writer) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut stderr_writer, b"0123456789")
            .await
            .unwrap();
        let (mut out, mut err) = (b"full".to_vec(), Vec::new());
        let start = Instant::now();
        drain(&mut stdout, &mut stderr, &mut out, &mut err, &limits(4, 4)).await;
        assert!(start.elapsed() < DRAIN_TIMEOUT / 2, "{:?}", start.elapsed());
        assert_eq!(out, b"full");
        assert_eq!(err, b"0123");
    }
}
