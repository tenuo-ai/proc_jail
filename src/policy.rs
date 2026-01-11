//! Process execution policy.
//!
//! The main entry point for proc_jail. `ProcPolicy` defines what can be executed
//! and validates requests before allowing execution.

use crate::arg_rules::ArgRules;
use crate::canonical::canonicalize_binary;
use crate::cwd_policy::CwdPolicy;
use crate::env_policy::EnvPolicy;
use crate::error::Violation;
use crate::file_check::check_binary;
use crate::limits::ResourceLimits;
use crate::prepared::PreparedCommand;
use crate::request::ProcRequest;
use crate::risky::{check_risky, RiskyBinPolicy};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// Process execution policy.
///
/// Defines what binaries can be executed, with what arguments,
/// environment, and resource limits.
///
/// Create using `ProcPolicy::builder()`.
#[derive(Debug, Clone)]
pub struct ProcPolicy {
    /// Allowed binaries (canonicalized absolute paths).
    allowed_bins: HashSet<PathBuf>,

    /// Argument rules for each allowed binary.
    arg_rules: HashMap<PathBuf, ArgRules>,

    /// Policy for risky binaries.
    risky_bin_policy: RiskyBinPolicy,

    /// Environment variable policy.
    env_policy: EnvPolicy,

    /// Working directory policy.
    cwd_policy: CwdPolicy,

    /// Resource limits.
    limits: ResourceLimits,
}

impl ProcPolicy {
    /// Create a new policy builder.
    pub fn builder() -> ProcPolicyBuilder {
        ProcPolicyBuilder::new()
    }

    /// Validate a request and prepare it for execution.
    ///
    /// This is the ONLY way to create a `PreparedCommand`.
    ///
    /// # Errors
    ///
    /// Returns a `Violation` if the request doesn't conform to the policy.
    pub fn prepare(&self, request: ProcRequest) -> Result<PreparedCommand, Violation> {
        // R2: Check absolute path
        if !request.bin.is_absolute() {
            return Err(Violation::BinNotAbsolute {
                path: request.bin.display().to_string(),
            });
        }

        // R3: Canonicalize
        let canonical_bin = canonicalize_binary(&request.bin)?;

        // R4: Check it's a regular executable file
        check_binary(&canonical_bin)?;

        // R5: Check allowlist
        if !self.allowed_bins.contains(&canonical_bin) {
            return Err(Violation::BinNotAllowed {
                path: request.bin.display().to_string(),
                canonical: canonical_bin.display().to_string(),
            });
        }

        // R6: Check risky binary policy
        check_risky(&canonical_bin, self.risky_bin_policy)?;

        // R7: Get argument rules (must exist)
        let arg_rules =
            self.arg_rules
                .get(&canonical_bin)
                .ok_or_else(|| Violation::ArgRulesRequired {
                    bin: canonical_bin.display().to_string(),
                })?;

        // R8-R9: Validate and transform arguments
        let validated_argv = arg_rules.validate(request.argv)?;

        // R10: Apply environment policy
        let env = self.env_policy.apply(&request.env);

        // R11: Validate working directory
        let cwd = self.cwd_policy.validate(request.cwd.as_deref())?;

        Ok(PreparedCommand {
            bin: canonical_bin,
            argv: validated_argv,
            env,
            cwd,
            limits: self.limits,
        })
    }
}

/// Builder for `ProcPolicy`.
#[derive(Debug, Clone)]
pub struct ProcPolicyBuilder {
    /// Binaries to allow (will be canonicalized at build time).
    bins: Vec<PathBuf>,

    /// Argument rules keyed by original path (resolved at build).
    arg_rules: HashMap<PathBuf, ArgRules>,

    /// Risky binary policy.
    risky_bin_policy: RiskyBinPolicy,

    /// Environment policy.
    env_policy: EnvPolicy,

    /// CWD policy.
    cwd_policy: CwdPolicy,

    /// Resource limits.
    limits: ResourceLimits,
}

impl ProcPolicyBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            bins: Vec::new(),
            arg_rules: HashMap::new(),
            risky_bin_policy: RiskyBinPolicy::default(),
            env_policy: EnvPolicy::default(),
            cwd_policy: CwdPolicy::default(),
            limits: ResourceLimits::default(),
        }
    }

    /// Add an allowed binary.
    ///
    /// The path will be canonicalized at build time.
    pub fn allow_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.bins.push(path.into());
        self
    }

    /// Set argument rules for a binary.
    ///
    /// The path should match what was passed to `allow_bin()`.
    pub fn arg_rules(mut self, path: impl Into<PathBuf>, rules: ArgRules) -> Self {
        self.arg_rules.insert(path.into(), rules);
        self
    }

    /// Set the risky binary policy.
    pub fn risky_bin_policy(mut self, policy: RiskyBinPolicy) -> Self {
        self.risky_bin_policy = policy;
        self
    }

    /// Set the environment policy.
    pub fn env_policy(mut self, policy: EnvPolicy) -> Self {
        self.env_policy = policy;
        self
    }

    /// Set the working directory policy.
    pub fn cwd_policy(mut self, policy: CwdPolicy) -> Self {
        self.cwd_policy = policy;
        self
    }

    /// Set the timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.limits.timeout = timeout;
        self
    }

    /// Set maximum stdout bytes.
    pub fn max_stdout(mut self, max: usize) -> Self {
        self.limits.max_stdout = max;
        self
    }

    /// Set maximum stderr bytes.
    pub fn max_stderr(mut self, max: usize) -> Self {
        self.limits.max_stderr = max;
        self
    }

    /// Set resource limits.
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Build the policy.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A binary path cannot be canonicalized
    /// - A binary doesn't have corresponding arg_rules
    pub fn build(self) -> Result<ProcPolicy, Violation> {
        let mut allowed_bins = HashSet::new();
        let mut final_arg_rules = HashMap::new();

        for bin_path in self.bins {
            // Canonicalize each binary
            let canonical = canonicalize_binary(&bin_path)?;

            // Check file validity
            check_binary(&canonical)?;

            // Find arg_rules (try both original and canonical paths)
            let rules = self
                .arg_rules
                .get(&bin_path)
                .or_else(|| self.arg_rules.get(&canonical))
                .cloned()
                .ok_or_else(|| Violation::ArgRulesRequired {
                    bin: bin_path.display().to_string(),
                })?;

            allowed_bins.insert(canonical.clone());
            final_arg_rules.insert(canonical, rules);
        }

        Ok(ProcPolicy {
            allowed_bins,
            arg_rules: final_arg_rules,
            risky_bin_policy: self.risky_bin_policy,
            env_policy: self.env_policy,
            cwd_policy: self.cwd_policy,
            limits: self.limits,
        })
    }
}

impl Default for ProcPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arg_rules::InjectDoubleDash;

    #[test]
    fn test_builder_requires_arg_rules() {
        let result = ProcPolicy::builder().allow_bin("/usr/bin/env").build();

        assert!(matches!(result, Err(Violation::ArgRulesRequired { .. })));
    }

    #[test]
    fn test_builder_with_arg_rules() {
        let result = ProcPolicy::builder()
            .allow_bin("/usr/bin/env")
            .arg_rules("/usr/bin/env", ArgRules::new().max_positionals(1))
            .risky_bin_policy(RiskyBinPolicy::Disabled) // env is risky
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_prepare_validates_binary() {
        let policy = ProcPolicy::builder()
            .allow_bin("/usr/bin/env")
            .arg_rules("/usr/bin/env", ArgRules::new().max_positionals(1))
            .risky_bin_policy(RiskyBinPolicy::Disabled)
            .build()
            .unwrap();

        // Allowed binary
        let request = ProcRequest::new("/usr/bin/env", vec!["true".to_string()]);
        assert!(policy.prepare(request).is_ok());

        // Disallowed binary
        let request = ProcRequest::new("/bin/ls", vec![]);
        let result = policy.prepare(request);
        assert!(matches!(result, Err(Violation::BinNotAllowed { .. })));
    }

    #[test]
    fn test_prepare_validates_args() {
        let policy = ProcPolicy::builder()
            .allow_bin("/usr/bin/env")
            .arg_rules(
                "/usr/bin/env",
                ArgRules::new()
                    .allowed_flags(&["-i"])
                    .max_flags(1)
                    .max_positionals(1),
            )
            .risky_bin_policy(RiskyBinPolicy::Disabled)
            .build()
            .unwrap();

        // Valid args
        let request = ProcRequest::new("/usr/bin/env", vec!["-i".to_string(), "true".to_string()]);
        assert!(policy.prepare(request).is_ok());

        // Invalid flag
        let request = ProcRequest::new("/usr/bin/env", vec!["-v".to_string()]);
        let result = policy.prepare(request);
        assert!(matches!(result, Err(Violation::ArgFlagNotAllowed { .. })));
    }

    #[test]
    fn test_risky_binary_denied_by_default() {
        // Don't set RiskyBinPolicy::Disabled - use default DenyByDefault
        let policy = ProcPolicy::builder()
            .allow_bin("/usr/bin/env")
            .arg_rules("/usr/bin/env", ArgRules::new())
            .build()
            .unwrap();

        let request = ProcRequest::new("/usr/bin/env", vec![]);
        let result = policy.prepare(request);
        assert!(matches!(result, Err(Violation::BinRiskyDenied { .. })));
    }

    #[test]
    fn test_double_dash_injection() {
        let policy = ProcPolicy::builder()
            .allow_bin("/usr/bin/env")
            .arg_rules(
                "/usr/bin/env",
                ArgRules::new()
                    .max_positionals(2)
                    .inject_double_dash(InjectDoubleDash::AfterFlags),
            )
            .risky_bin_policy(RiskyBinPolicy::Disabled)
            .build()
            .unwrap();

        let request = ProcRequest::new("/usr/bin/env", vec!["true".to_string(), "arg".to_string()]);
        let prepared = policy.prepare(request).unwrap();

        // Should have -- injected at start since no flags
        assert_eq!(prepared.argv, vec!["--", "true", "arg"]);
    }
}
