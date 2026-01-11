//! Risky binary detection and policy.
//!
//! Certain binaries are high-risk because they can execute arbitrary commands
//! or escalate privileges. This module provides detection and policy handling.

use crate::error::{RiskCategory, Violation};
use std::path::Path;

/// Policy for handling risky binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RiskyBinPolicy {
    /// Deny risky binaries even if in allowlist (default).
    ///
    /// This is the safest option - even if you accidentally add a shell
    /// to your allowlist, it will be rejected.
    #[default]
    DenyByDefault,

    /// Allow risky binaries if explicitly in allowlist, but log a warning.
    ///
    /// Use this if you genuinely need to run a risky binary and accept the risks.
    AllowWithWarning,

    /// No special handling for risky binaries.
    ///
    /// You're on your own. Only use this if you have external controls.
    Disabled,
}

/// Shell interpreters that can execute arbitrary commands.
pub const RISKY_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
];

/// Script interpreters that can execute arbitrary code.
pub const RISKY_INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "deno",
    "bun",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "awk",
    "gawk",
    "nawk",
    "mawk",
];

/// Process spawners that can execute other binaries.
pub const RISKY_SPAWNERS: &[&str] = &[
    "env",
    "xargs",
    "parallel",
    "nohup",
    "timeout",
    "time",
    "nice",
    "ionice",
    "strace",
    "ltrace",
    "watch",
    "exec",
];

/// Privilege escalation tools.
pub const RISKY_PRIVILEGE: &[&str] = &[
    "sudo", "su", "doas", "pkexec", "gksudo", "kdesudo", "runuser", "chroot",
];

/// Check if a binary is risky and return its category.
pub fn categorize_risky(path: &Path) -> Option<RiskCategory> {
    let filename = path.file_name()?.to_str()?;

    // Strip version suffixes (e.g., python3.11 -> python3)
    let base_name = filename
        .split('.')
        .next()
        .unwrap_or(filename)
        .trim_end_matches(|c: char| c.is_ascii_digit());

    if RISKY_SHELLS.iter().any(|&s| s == base_name || s == filename) {
        return Some(RiskCategory::Shell);
    }

    if RISKY_INTERPRETERS
        .iter()
        .any(|&s| s == base_name || s == filename)
    {
        return Some(RiskCategory::Interpreter);
    }

    if RISKY_SPAWNERS
        .iter()
        .any(|&s| s == base_name || s == filename)
    {
        return Some(RiskCategory::Spawner);
    }

    if RISKY_PRIVILEGE
        .iter()
        .any(|&s| s == base_name || s == filename)
    {
        return Some(RiskCategory::Privilege);
    }

    None
}

/// Check if a binary should be allowed according to the risky binary policy.
///
/// # Returns
///
/// - `Ok(())` if the binary is allowed
/// - `Err(Violation::BinRiskyDenied)` if denied
pub fn check_risky(path: &Path, policy: RiskyBinPolicy) -> Result<(), Violation> {
    match policy {
        RiskyBinPolicy::Disabled => Ok(()),
        RiskyBinPolicy::AllowWithWarning => {
            if let Some(category) = categorize_risky(path) {
                tracing::warn!(
                    path = %path.display(),
                    category = %category,
                    "Allowing risky binary execution"
                );
            }
            Ok(())
        }
        RiskyBinPolicy::DenyByDefault => {
            if let Some(category) = categorize_risky(path) {
                Err(Violation::BinRiskyDenied {
                    path: path.display().to_string(),
                    category,
                })
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_detected() {
        assert_eq!(
            categorize_risky(Path::new("/bin/bash")),
            Some(RiskCategory::Shell)
        );
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/zsh")),
            Some(RiskCategory::Shell)
        );
    }

    #[test]
    fn test_interpreter_detected() {
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/python3")),
            Some(RiskCategory::Interpreter)
        );
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/node")),
            Some(RiskCategory::Interpreter)
        );
    }

    #[test]
    fn test_spawner_detected() {
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/env")),
            Some(RiskCategory::Spawner)
        );
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/xargs")),
            Some(RiskCategory::Spawner)
        );
    }

    #[test]
    fn test_privilege_detected() {
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/sudo")),
            Some(RiskCategory::Privilege)
        );
    }

    #[test]
    fn test_safe_binary_not_detected() {
        assert_eq!(categorize_risky(Path::new("/usr/bin/grep")), None);
        assert_eq!(categorize_risky(Path::new("/usr/bin/jq")), None);
        assert_eq!(categorize_risky(Path::new("/usr/bin/git")), None);
    }

    #[test]
    fn test_versioned_interpreter_detected() {
        // python3.11 should still be detected as python3
        assert_eq!(
            categorize_risky(Path::new("/usr/bin/python3.11")),
            Some(RiskCategory::Interpreter)
        );
    }

    #[test]
    fn test_deny_by_default_blocks() {
        let result = check_risky(Path::new("/bin/bash"), RiskyBinPolicy::DenyByDefault);
        assert!(matches!(result, Err(Violation::BinRiskyDenied { .. })));
    }

    #[test]
    fn test_deny_by_default_allows_safe() {
        let result = check_risky(Path::new("/usr/bin/grep"), RiskyBinPolicy::DenyByDefault);
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_allows_all() {
        let result = check_risky(Path::new("/bin/bash"), RiskyBinPolicy::Disabled);
        assert!(result.is_ok());
    }
}
