//! Python bindings for proc_jail - process execution guard for agentic systems.
//!
//! This module provides Python wrappers around the Rust proc_jail crate,
//! enabling secure process execution from Python applications.

#![allow(clippy::useless_conversion)]

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::time::Duration;

use proc_jail::{
    ArgRules as RustArgRules, CwdPolicy as RustCwdPolicy, EnvPolicy as RustEnvPolicy, ExecError,
    InjectDoubleDash as RustInjectDoubleDash, Output as RustOutput, ProcPolicy as RustProcPolicy,
    ProcRequest as RustProcRequest, RiskCategory as RustRiskCategory,
    RiskyBinPolicy as RustRiskyBinPolicy, Violation as RustViolation,
};

// =============================================================================
// Error Conversion
// =============================================================================

/// Convert proc_jail Violation to Python ValueError
fn violation_to_py_err(v: RustViolation) -> PyErr {
    PyValueError::new_err(v.to_string())
}

/// Convert proc_jail ExecError to Python RuntimeError
fn exec_error_to_py_err(e: ExecError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// =============================================================================
// Enums
// =============================================================================

/// Policy for handling risky binaries (shells, interpreters, etc.).
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RiskyBinPolicy {
    /// Deny risky binaries even if in allowlist (default)
    DenyByDefault = 0,
    /// Allow risky binaries if in allowlist, log warning
    AllowWithWarning = 1,
    /// No special handling
    Disabled = 2,
}

impl From<RiskyBinPolicy> for RustRiskyBinPolicy {
    fn from(p: RiskyBinPolicy) -> Self {
        match p {
            RiskyBinPolicy::DenyByDefault => RustRiskyBinPolicy::DenyByDefault,
            RiskyBinPolicy::AllowWithWarning => RustRiskyBinPolicy::AllowWithWarning,
            RiskyBinPolicy::Disabled => RustRiskyBinPolicy::Disabled,
        }
    }
}

/// Mode for double-dash injection.
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InjectDoubleDash {
    /// Never inject -- (default)
    Never = 0,
    /// Inject -- after flags, before first positional
    AfterFlags = 1,
}

impl From<InjectDoubleDash> for RustInjectDoubleDash {
    fn from(i: InjectDoubleDash) -> Self {
        match i {
            InjectDoubleDash::Never => RustInjectDoubleDash::Never,
            InjectDoubleDash::AfterFlags => RustInjectDoubleDash::AfterFlags,
        }
    }
}

/// Risk category for dangerous binaries.
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RiskCategory {
    Shell = 0,
    Interpreter = 1,
    Spawner = 2,
    Privilege = 3,
}

impl From<RustRiskCategory> for RiskCategory {
    fn from(c: RustRiskCategory) -> Self {
        match c {
            RustRiskCategory::Shell => RiskCategory::Shell,
            RustRiskCategory::Interpreter => RiskCategory::Interpreter,
            RustRiskCategory::Spawner => RiskCategory::Spawner,
            RustRiskCategory::Privilege => RiskCategory::Privilege,
        }
    }
}

// =============================================================================
// ArgRules
// =============================================================================

/// Rules for validating arguments to a binary.
///
/// Example:
///     >>> rules = ArgRules()
///     >>> rules = rules.allowed_flags(["-n", "-i", "--color=never"])
///     >>> rules = rules.max_flags(3)
///     >>> rules = rules.max_positionals(10)
///     >>> rules = rules.inject_double_dash(InjectDoubleDash.AfterFlags)
#[pyclass]
#[derive(Clone)]
pub struct ArgRules {
    inner: RustArgRules,
}

#[pymethods]
impl ArgRules {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustArgRules::new(),
        }
    }

    /// Set the required subcommand (first positional must match).
    fn subcommand(&self, cmd: &str) -> Self {
        Self {
            inner: self.inner.clone().subcommand(cmd),
        }
    }

    /// Set allowed flags from a list.
    fn allowed_flags(&self, flags: Vec<String>) -> Self {
        let flags_ref: Vec<&str> = flags.iter().map(|s| s.as_str()).collect();
        Self {
            inner: self.inner.clone().allowed_flags(&flags_ref),
        }
    }

    /// Set maximum number of flags.
    fn max_flags(&self, max: usize) -> Self {
        Self {
            inner: self.inner.clone().max_flags(max),
        }
    }

    /// Set maximum number of positional arguments.
    fn max_positionals(&self, max: usize) -> Self {
        Self {
            inner: self.inner.clone().max_positionals(max),
        }
    }

    /// Set double-dash injection mode.
    ///
    /// Args:
    ///     mode: Injection mode (default: AfterFlags for secure double-dash insertion)
    ///
    /// When called without arguments, defaults to AfterFlags which inserts `--`
    /// between flags and positional arguments to prevent flag injection.
    #[pyo3(signature = (mode=None))]
    fn inject_double_dash(&self, mode: Option<InjectDoubleDash>) -> Self {
        let mode = mode.unwrap_or(InjectDoubleDash::AfterFlags);
        Self {
            inner: self.inner.clone().inject_double_dash(mode.into()),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ArgRules(max_flags={}, max_positionals={})",
            self.inner.max_flags, self.inner.max_positionals
        )
    }
}

// =============================================================================
// ProcRequest
// =============================================================================

/// A proposed process execution request.
///
/// Example:
///     >>> request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
///     >>> request = request.with_cwd("/tmp")
#[pyclass]
#[derive(Clone)]
pub struct ProcRequest {
    inner: RustProcRequest,
}

#[pymethods]
impl ProcRequest {
    #[new]
    fn new(bin: &str, argv: Vec<String>) -> Self {
        Self {
            inner: RustProcRequest::new(bin, argv),
        }
    }

    /// Set the working directory.
    fn with_cwd(&self, cwd: &str) -> Self {
        Self {
            inner: self.inner.clone().with_cwd(cwd),
        }
    }

    /// Set environment variables from a dict.
    fn with_env(&self, env: HashMap<String, String>) -> Self {
        Self {
            inner: self.inner.clone().with_env(env),
        }
    }

    /// Add a single environment variable.
    fn with_env_var(&self, key: &str, value: &str) -> Self {
        Self {
            inner: self.inner.clone().with_env_var(key, value),
        }
    }

    /// Get the binary path.
    #[getter]
    fn bin(&self) -> String {
        self.inner.bin.display().to_string()
    }

    /// Get the arguments.
    #[getter]
    fn argv(&self) -> Vec<String> {
        self.inner.argv.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProcRequest('{}', {:?})",
            self.inner.bin.display(),
            self.inner.argv
        )
    }
}

// =============================================================================
// Output
// =============================================================================

/// Output from a successfully executed command.
#[pyclass]
pub struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    success: bool,
}

#[pymethods]
impl Output {
    /// Get stdout as string (lossy UTF-8).
    fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as string (lossy UTF-8).
    fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Get raw stdout bytes.
    #[getter]
    fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Get raw stderr bytes.
    #[getter]
    fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Get exit code (if available).
    #[getter]
    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Check if process exited successfully.
    #[getter]
    fn success(&self) -> bool {
        self.success
    }

    fn __repr__(&self) -> String {
        format!(
            "Output(success={}, exit_code={:?}, stdout_len={}, stderr_len={})",
            self.success,
            self.exit_code,
            self.stdout.len(),
            self.stderr.len()
        )
    }
}

impl From<RustOutput> for Output {
    fn from(o: RustOutput) -> Self {
        let exit_code = o.code();
        let success = o.success();
        Self {
            stdout: o.stdout,
            stderr: o.stderr,
            exit_code,
            success,
        }
    }
}

// =============================================================================
// PreparedCommand
// =============================================================================

/// A validated command ready for execution.
///
/// This can only be created via ProcPolicy.prepare().
#[pyclass]
pub struct PreparedCommand {
    inner: proc_jail::PreparedCommand,
}

#[pymethods]
impl PreparedCommand {
    /// Execute the command synchronously.
    ///
    /// Returns:
    ///     Output from the command
    ///
    /// Raises:
    ///     RuntimeError: If execution fails (timeout, limit exceeded, spawn failed)
    fn spawn_sync(&self) -> PyResult<Output> {
        self.inner
            .clone()
            .spawn_sync()
            .map(Output::from)
            .map_err(exec_error_to_py_err)
    }

    /// Get the binary path.
    #[getter]
    fn bin(&self) -> String {
        self.inner.bin().display().to_string()
    }

    /// Get the validated arguments.
    #[getter]
    fn argv(&self) -> Vec<String> {
        self.inner.argv().to_vec()
    }

    /// Get the working directory.
    #[getter]
    fn cwd(&self) -> String {
        self.inner.cwd().display().to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "PreparedCommand('{}', {:?})",
            self.inner.bin().display(),
            self.inner.argv()
        )
    }
}

// =============================================================================
// ProcPolicy
// =============================================================================

/// Process execution policy builder.
///
/// Example:
///     >>> policy = (ProcPolicy()
///     ...     .allow_bin("/usr/bin/grep")
///     ...     .arg_rules("/usr/bin/grep", ArgRules()
///     ...         .allowed_flags(["-n", "-i"])
///     ...         .max_flags(2)
///     ...         .max_positionals(10))
///     ...     .timeout_secs(30)
///     ...     .build())
#[pyclass]
#[derive(Clone)]
pub struct ProcPolicyBuilder {
    bins: Vec<String>,
    arg_rules: HashMap<String, RustArgRules>,
    risky_bin_policy: RustRiskyBinPolicy,
    env_policy: RustEnvPolicy,
    cwd: Option<String>,
    timeout_secs: u64,
    max_stdout: usize,
    max_stderr: usize,
}

#[pymethods]
impl ProcPolicyBuilder {
    #[new]
    fn new() -> Self {
        Self {
            bins: Vec::new(),
            arg_rules: HashMap::new(),
            risky_bin_policy: RustRiskyBinPolicy::default(),
            env_policy: RustEnvPolicy::default(),
            cwd: None,
            timeout_secs: 30,
            max_stdout: 10 * 1024 * 1024,
            max_stderr: 1024 * 1024,
        }
    }

    /// Add an allowed binary.
    fn allow_bin(&self, path: &str) -> Self {
        let mut new = self.clone();
        new.bins.push(path.to_string());
        new
    }

    /// Set argument rules for a binary.
    fn arg_rules(&self, path: &str, rules: &ArgRules) -> Self {
        let mut new = self.clone();
        new.arg_rules.insert(path.to_string(), rules.inner.clone());
        new
    }

    /// Set risky binary policy.
    fn risky_bin_policy(&self, policy: RiskyBinPolicy) -> Self {
        let mut new = self.clone();
        new.risky_bin_policy = policy.into();
        new
    }

    /// Allow risky binaries (shells, interpreters, etc.) to be executed.
    ///
    /// This is a convenience method equivalent to:
    ///     .risky_bin_policy(RiskyBinPolicy.Disabled)
    ///
    /// WARNING: Only use this if you understand the security implications.
    fn allow_risky_binaries(&self) -> Self {
        self.risky_bin_policy(RiskyBinPolicy::Disabled)
    }

    /// Set environment policy to empty (default).
    fn env_empty(&self) -> Self {
        let mut new = self.clone();
        new.env_policy = RustEnvPolicy::Empty;
        new
    }

    /// Set environment policy to locale only.
    fn env_locale_only(&self) -> Self {
        let mut new = self.clone();
        new.env_policy = RustEnvPolicy::LocaleOnly;
        new
    }

    /// Set environment policy to fixed values.
    fn env_fixed(&self, env: HashMap<String, String>) -> Self {
        let mut new = self.clone();
        new.env_policy = RustEnvPolicy::Fixed(env);
        new
    }

    /// Set environment policy to allowlist.
    fn env_allowlist(&self, keys: Vec<String>) -> Self {
        let mut new = self.clone();
        new.env_policy = RustEnvPolicy::AllowList(keys.into_iter().collect());
        new
    }

    /// Set fixed working directory.
    fn cwd(&self, path: &str) -> Self {
        let mut new = self.clone();
        new.cwd = Some(path.to_string());
        new
    }

    /// Set timeout in seconds.
    fn timeout_secs(&self, secs: u64) -> Self {
        let mut new = self.clone();
        new.timeout_secs = secs;
        new
    }

    /// Set timeout in seconds (convenience alias for timeout_secs).
    fn timeout(&self, secs: u64) -> Self {
        self.timeout_secs(secs)
    }

    /// Set maximum stdout bytes.
    fn max_stdout(&self, max: usize) -> Self {
        let mut new = self.clone();
        new.max_stdout = max;
        new
    }

    /// Set maximum stderr bytes.
    fn max_stderr(&self, max: usize) -> Self {
        let mut new = self.clone();
        new.max_stderr = max;
        new
    }

    /// Build the policy.
    ///
    /// Raises:
    ///     ValueError: If policy is invalid (missing arg_rules, bad paths, etc.)
    fn build(&self) -> PyResult<ProcPolicy> {
        let mut builder = RustProcPolicy::builder()
            .risky_bin_policy(self.risky_bin_policy)
            .env_policy(self.env_policy.clone())
            .timeout(Duration::from_secs(self.timeout_secs))
            .max_stdout(self.max_stdout)
            .max_stderr(self.max_stderr);

        if let Some(ref cwd) = self.cwd {
            builder = builder.cwd_policy(RustCwdPolicy::fixed(cwd));
        }

        for bin in &self.bins {
            builder = builder.allow_bin(bin);
            if let Some(rules) = self.arg_rules.get(bin) {
                builder = builder.arg_rules(bin, rules.clone());
            }
        }

        let policy = builder.build().map_err(violation_to_py_err)?;
        Ok(ProcPolicy { inner: policy })
    }

    fn __repr__(&self) -> String {
        format!("ProcPolicyBuilder(bins={:?})", self.bins)
    }
}

/// A built process execution policy.
#[pyclass]
pub struct ProcPolicy {
    inner: RustProcPolicy,
}

#[pymethods]
impl ProcPolicy {
    /// Validate a request and prepare it for execution.
    ///
    /// Args:
    ///     request: The execution request to validate
    ///
    /// Returns:
    ///     PreparedCommand ready for execution
    ///
    /// Raises:
    ///     ValueError: If the request violates the policy
    fn prepare(&self, request: &ProcRequest) -> PyResult<PreparedCommand> {
        self.inner
            .prepare(request.inner.clone())
            .map(|inner| PreparedCommand { inner })
            .map_err(violation_to_py_err)
    }

    fn __repr__(&self) -> String {
        "ProcPolicy(<built>)".to_string()
    }
}

// =============================================================================
// Module
// =============================================================================

/// Process execution guard for agentic systems.
///
/// proc_jail provides a safe wrapper around process spawning, preventing
/// command injection via argv-style execution with strict validation.
///
/// Example:
///     >>> from proc_jail import ProcPolicyBuilder, ProcRequest, ArgRules, InjectDoubleDash
///     >>>
///     >>> # Build a policy
///     >>> policy = (ProcPolicyBuilder()
///     ...     .allow_bin("/usr/bin/grep")
///     ...     .arg_rules("/usr/bin/grep", ArgRules()
///     ...         .allowed_flags(["-n", "-i", "-l"])
///     ...         .max_flags(3)
///     ...         .max_positionals(10)
///     ...         .inject_double_dash(InjectDoubleDash.AfterFlags))
///     ...     .timeout_secs(30)
///     ...     .build())
///     >>>
///     >>> # Create and execute a request
///     >>> request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
///     >>> prepared = policy.prepare(request)
///     >>> output = prepared.spawn_sync()
///     >>> print(output.stdout_string())
#[pymodule]
fn _proc_jail(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RiskyBinPolicy>()?;
    m.add_class::<InjectDoubleDash>()?;
    m.add_class::<RiskCategory>()?;
    m.add_class::<ArgRules>()?;
    m.add_class::<ProcRequest>()?;
    m.add_class::<Output>()?;
    m.add_class::<PreparedCommand>()?;
    m.add_class::<ProcPolicyBuilder>()?;
    m.add_class::<ProcPolicy>()?;
    Ok(())
}
