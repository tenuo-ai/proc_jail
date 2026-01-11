//! # proc_jail
//!
//! Process execution guard for agentic systems.
//!
//! `proc_jail` provides a safe wrapper around process spawning, enforcing deterministic
//! bounds on process execution to prevent command injection, unauthorized binary execution,
//! and resource abuse.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use proc_jail::{ProcPolicy, ProcRequest, ArgRules, InjectDoubleDash};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Define a policy
//! let policy = ProcPolicy::builder()
//!     .allow_bin("/usr/bin/grep")
//!     .arg_rules("/usr/bin/grep", ArgRules::new()
//!         .allowed_flags(&["-n", "-i", "-l", "-c"])
//!         .max_flags(4)
//!         .max_positionals(10)
//!         .inject_double_dash(InjectDoubleDash::AfterFlags))
//!     .timeout(Duration::from_secs(30))
//!     .build()?;
//!
//! // Create a request
//! let request = ProcRequest::new(
//!     "/usr/bin/grep",
//!     vec!["-n".to_string(), "pattern".to_string(), "file.txt".to_string()],
//! );
//!
//! // Validate and execute
//! let prepared = policy.prepare(request)?;
//! let output = prepared.spawn().await?;
//!
//! println!("stdout: {}", output.stdout_string());
//! # Ok(())
//! # }
//! ```
//!
//! ## Design Principles
//!
//! - **No shell interpretation**: Commands use argv-style execution, not shell strings
//! - **Absolute paths only**: Avoids PATH hijacking
//! - **Allowlist-only**: No denylists - explicit enumeration of what's permitted
//! - **Fail closed**: Any error or ambiguity results in denial
//! - **Type-safe API**: Only `PreparedCommand` can spawn processes
//!
//! ## Platform Support
//!
//! Unix only (Linux, macOS). Windows is not supported because `CreateProcess`
//! passes arguments as a string that each program parses differently, making
//! injection prevention impossible to guarantee.

#[cfg(windows)]
compile_error!(
    "proc_jail does not support Windows. \
     Windows CreateProcess passes arguments as a string that the child parses, \
     making injection prevention impossible to guarantee. \
     See docs/windows.md for details."
);

mod arg_parser;
mod arg_rules;
mod canonical;
mod cwd_policy;
mod double_dash;
mod env_policy;
mod error;
mod file_check;
mod limits;
mod output;
mod policy;
mod prepared;
mod request;
mod risky;

// Public API
pub use arg_rules::{ArgRules, InjectDoubleDash};
pub use cwd_policy::CwdPolicy;
pub use env_policy::{EnvPolicy, ALWAYS_STRIP};
pub use error::{ExecError, ProcError, RiskCategory, Violation};
pub use limits::ResourceLimits;
pub use output::Output;
pub use policy::{ProcPolicy, ProcPolicyBuilder};
pub use prepared::PreparedCommand;
pub use request::ProcRequest;
pub use risky::{
    RiskyBinPolicy, RISKY_INTERPRETERS, RISKY_PRIVILEGE, RISKY_SHELLS, RISKY_SPAWNERS,
};
