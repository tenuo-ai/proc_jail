//! Argument rules and validation.
//!
//! This module defines `ArgRules` which specifies what arguments
//! are allowed for a particular binary.

use crate::arg_parser::{count_args, extract_flags, extract_positionals, parse_argv};
use crate::double_dash::inject_double_dash;
use crate::error::Violation;
use std::collections::HashSet;

// Re-export for convenience
pub use crate::double_dash::InjectDoubleDash;

/// Rules for validating arguments to a binary.
///
/// Every allowed binary MUST have an `ArgRules` entry.
/// There is no "allow any args" mode by design.
#[derive(Debug, Clone)]
pub struct ArgRules {
    /// Required first positional argument (subcommand pinning).
    ///
    /// If set, the first positional MUST match this value exactly.
    /// Useful for commands like `git status` where you want to pin the subcommand.
    pub subcommand: Option<String>,

    /// Allowed flags (exact match).
    ///
    /// Empty set means no flags are allowed.
    /// Flags are matched exactly as provided: `-f`, `--file`, `--color=always`.
    pub allowed_flags: HashSet<String>,

    /// Maximum number of flags allowed.
    pub max_flags: usize,

    /// Maximum number of positional arguments allowed (excluding subcommand if set).
    pub max_positionals: usize,

    /// Double-dash injection mode.
    pub inject_double_dash: InjectDoubleDash,
}

impl Default for ArgRules {
    fn default() -> Self {
        Self {
            subcommand: None,
            allowed_flags: HashSet::new(),
            max_flags: 0,
            max_positionals: 0,
            inject_double_dash: InjectDoubleDash::Never,
        }
    }
}

impl ArgRules {
    /// Create a new `ArgRules` with default (restrictive) settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the required subcommand.
    pub fn subcommand(mut self, cmd: impl Into<String>) -> Self {
        self.subcommand = Some(cmd.into());
        self
    }

    /// Set allowed flags from a slice.
    pub fn allowed_flags(mut self, flags: &[&str]) -> Self {
        self.allowed_flags = flags.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Add a single allowed flag.
    pub fn allow_flag(mut self, flag: impl Into<String>) -> Self {
        self.allowed_flags.insert(flag.into());
        self
    }

    /// Set maximum number of flags.
    pub fn max_flags(mut self, max: usize) -> Self {
        self.max_flags = max;
        self
    }

    /// Set maximum number of positional arguments.
    pub fn max_positionals(mut self, max: usize) -> Self {
        self.max_positionals = max;
        self
    }

    /// Set double-dash injection mode.
    pub fn inject_double_dash(mut self, mode: InjectDoubleDash) -> Self {
        self.inject_double_dash = mode;
        self
    }

    /// Validate arguments according to these rules.
    ///
    /// Returns the (possibly modified) argv on success, or a violation on failure.
    pub fn validate(&self, argv: Vec<String>) -> Result<Vec<String>, Violation> {
        let parsed = parse_argv(&argv);

        // Extract components
        let flags = extract_flags(&parsed);
        let positionals = extract_positionals(&parsed);

        // Count (not including terminator)
        let (flag_count, positional_count) = count_args(&parsed);

        // Check flag count
        if flag_count > self.max_flags {
            return Err(Violation::ArgTooManyFlags {
                max: self.max_flags,
                got: flag_count,
            });
        }

        // Validate each flag is in allowlist
        for flag in &flags {
            if !self.allowed_flags.contains(*flag) {
                return Err(Violation::ArgFlagNotAllowed {
                    flag: flag.to_string(),
                });
            }
        }

        // Handle subcommand
        let effective_positional_count = if self.subcommand.is_some() {
            // First positional must match subcommand
            let first_positional = positionals.first().map(|s| s.to_string());

            match (&self.subcommand, &first_positional) {
                (Some(expected), Some(got)) if expected == got => {
                    // Subcommand matches, count remaining positionals
                    positional_count.saturating_sub(1)
                }
                (Some(expected), got) => {
                    return Err(Violation::ArgSubcommandMismatch {
                        expected: expected.clone(),
                        got: got.clone(),
                    });
                }
                _ => positional_count,
            }
        } else {
            positional_count
        };

        // Check positional count
        if effective_positional_count > self.max_positionals {
            return Err(Violation::ArgTooManyPositionals {
                max: self.max_positionals,
                got: effective_positional_count,
            });
        }

        // Apply double-dash injection if needed
        let result = inject_double_dash(argv, self.inject_double_dash);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_empty_rules_rejects_everything() {
        let rules = ArgRules::new();

        // Any flag is rejected
        assert!(matches!(
            rules.validate(s(&["-n"])),
            Err(Violation::ArgTooManyFlags { .. })
        ));

        // Any positional is rejected
        assert!(matches!(
            rules.validate(s(&["file.txt"])),
            Err(Violation::ArgTooManyPositionals { .. })
        ));

        // Empty is OK
        assert!(rules.validate(vec![]).is_ok());
    }

    #[test]
    fn test_allowed_flags() {
        let rules = ArgRules::new()
            .allowed_flags(&["-n", "-i", "--color=never"])
            .max_flags(3);

        assert!(rules.validate(s(&["-n"])).is_ok());
        assert!(rules.validate(s(&["-n", "-i"])).is_ok());
        assert!(rules.validate(s(&["--color=never"])).is_ok());

        // Flag not in allowlist
        assert!(matches!(
            rules.validate(s(&["-f"])),
            Err(Violation::ArgFlagNotAllowed { flag }) if flag == "-f"
        ));

        // --file not same as --file=foo
        assert!(matches!(
            rules.validate(s(&["--color=auto"])),
            Err(Violation::ArgFlagNotAllowed { .. })
        ));
    }

    #[test]
    fn test_max_flags() {
        let rules = ArgRules::new()
            .allowed_flags(&["-a", "-b", "-c"])
            .max_flags(2);

        assert!(rules.validate(s(&["-a", "-b"])).is_ok());
        assert!(matches!(
            rules.validate(s(&["-a", "-b", "-c"])),
            Err(Violation::ArgTooManyFlags { max: 2, got: 3 })
        ));
    }

    #[test]
    fn test_max_positionals() {
        let rules = ArgRules::new().max_positionals(2);

        assert!(rules.validate(s(&["a", "b"])).is_ok());
        assert!(matches!(
            rules.validate(s(&["a", "b", "c"])),
            Err(Violation::ArgTooManyPositionals { max: 2, got: 3 })
        ));
    }

    #[test]
    fn test_subcommand_required() {
        let rules = ArgRules::new().subcommand("status").max_positionals(0);

        // Correct subcommand
        assert!(rules.validate(s(&["status"])).is_ok());

        // Wrong subcommand
        assert!(matches!(
            rules.validate(s(&["push"])),
            Err(Violation::ArgSubcommandMismatch { expected, got })
                if expected == "status" && got == Some("push".to_string())
        ));

        // Missing subcommand
        assert!(matches!(
            rules.validate(vec![]),
            Err(Violation::ArgSubcommandMismatch { expected, got })
                if expected == "status" && got.is_none()
        ));
    }

    #[test]
    fn test_subcommand_with_extra_positionals() {
        let rules = ArgRules::new().subcommand("log").max_positionals(1);

        // Subcommand + 1 extra positional OK
        assert!(rules.validate(s(&["log", "file.txt"])).is_ok());

        // Subcommand + 2 extra positionals exceeds limit
        assert!(matches!(
            rules.validate(s(&["log", "file1.txt", "file2.txt"])),
            Err(Violation::ArgTooManyPositionals { max: 1, got: 2 })
        ));
    }

    #[test]
    fn test_double_dash_injection() {
        let rules = ArgRules::new()
            .allowed_flags(&["-n", "-i"])
            .max_flags(2)
            .max_positionals(2)
            .inject_double_dash(InjectDoubleDash::AfterFlags);

        let result = rules.validate(s(&["-n", "pattern", "file.txt"])).unwrap();
        assert_eq!(result, s(&["-n", "--", "pattern", "file.txt"]));
    }

    #[test]
    fn test_stdin_dash_is_positional() {
        let rules = ArgRules::new().max_positionals(1);

        assert!(rules.validate(s(&["-"])).is_ok());
    }

    #[test]
    fn test_combined_flags_not_expanded() {
        // -abc is treated as a single flag, not -a -b -c
        let rules = ArgRules::new()
            .allowed_flags(&["-a", "-b", "-c"])
            .max_flags(3);

        assert!(matches!(
            rules.validate(s(&["-abc"])),
            Err(Violation::ArgFlagNotAllowed { flag }) if flag == "-abc"
        ));
    }
}
