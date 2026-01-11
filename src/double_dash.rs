//! Double-dash injection for argument separation.
//!
//! This module handles inserting `--` between flags and positionals
//! to prevent flag injection via positional arguments.

use crate::arg_parser::{parse_argv, ArgType};

/// Mode for double-dash injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InjectDoubleDash {
    /// Never inject `--` (default).
    #[default]
    Never,

    /// Inject `--` after validated flags, before first positional.
    ///
    /// Only injects if at least one positional argument exists.
    /// If no flags but positionals exist, inserts at the beginning.
    AfterFlags,
}

/// Inject double-dash into an argv vector according to the mode.
///
/// # Arguments
///
/// * `argv` - The argument vector (already validated)
/// * `mode` - The injection mode
///
/// # Returns
///
/// A new argv vector with `--` injected if appropriate.
pub fn inject_double_dash(argv: Vec<String>, mode: InjectDoubleDash) -> Vec<String> {
    match mode {
        InjectDoubleDash::Never => argv,
        InjectDoubleDash::AfterFlags => inject_after_flags(argv),
    }
}

fn inject_after_flags(argv: Vec<String>) -> Vec<String> {
    if argv.is_empty() {
        return argv;
    }

    // Parse to find structure
    let parsed = parse_argv(&argv);

    // Check if there are any positionals
    let has_positionals = parsed
        .iter()
        .any(|(t, _)| matches!(t, ArgType::Positional(_)));

    if !has_positionals {
        // No positionals, no injection needed
        return argv;
    }

    // Check if already has terminator
    let has_terminator = parsed.iter().any(|(t, _)| matches!(t, ArgType::Terminator));

    if has_terminator {
        // Already has --, no injection needed
        return argv;
    }

    // Find the position to insert: after last flag, before first positional
    let first_positional_idx = parsed
        .iter()
        .position(|(t, _)| matches!(t, ArgType::Positional(_)));

    match first_positional_idx {
        Some(idx) => {
            // Insert -- at the position of first positional
            let insert_pos = parsed[idx].1;
            let mut result = Vec::with_capacity(argv.len() + 1);
            result.extend(argv[..insert_pos].iter().cloned());
            result.push("--".to_string());
            result.extend(argv[insert_pos..].iter().cloned());
            result
        }
        None => argv, // Shouldn't happen since we checked has_positionals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_never_mode_no_change() {
        let argv = s(&["-r", "-n", "pattern", "file.txt"]);
        let result = inject_double_dash(argv.clone(), InjectDoubleDash::Never);
        assert_eq!(result, argv);
    }

    #[test]
    fn test_inject_after_flags() {
        let argv = s(&["-r", "-n", "pattern", "file.txt"]);
        let result = inject_double_dash(argv, InjectDoubleDash::AfterFlags);
        assert_eq!(result, s(&["-r", "-n", "--", "pattern", "file.txt"]));
    }

    #[test]
    fn test_inject_at_start_if_no_flags() {
        let argv = s(&["pattern", "file.txt"]);
        let result = inject_double_dash(argv, InjectDoubleDash::AfterFlags);
        assert_eq!(result, s(&["--", "pattern", "file.txt"]));
    }

    #[test]
    fn test_no_inject_if_no_positionals() {
        let argv = s(&["-r", "-n"]);
        let result = inject_double_dash(argv.clone(), InjectDoubleDash::AfterFlags);
        assert_eq!(result, argv);
    }

    #[test]
    fn test_no_inject_if_already_has_terminator() {
        let argv = s(&["-r", "--", "pattern"]);
        let result = inject_double_dash(argv.clone(), InjectDoubleDash::AfterFlags);
        assert_eq!(result, argv);
    }

    #[test]
    fn test_empty_argv() {
        let argv: Vec<String> = vec![];
        let result = inject_double_dash(argv.clone(), InjectDoubleDash::AfterFlags);
        assert_eq!(result, argv);
    }

    #[test]
    fn test_stdin_dash_is_positional() {
        let argv = s(&["-n", "-"]);
        let result = inject_double_dash(argv, InjectDoubleDash::AfterFlags);
        assert_eq!(result, s(&["-n", "--", "-"]));
    }

    #[test]
    fn test_user_input_with_dashes() {
        // Example from spec: user input looks like flags
        let argv = s(&[
            "-r",
            "-n",
            "pattern",
            "-e malicious --include=*.secret",
            "dir/",
        ]);
        let result = inject_double_dash(argv, InjectDoubleDash::AfterFlags);
        assert_eq!(
            result,
            s(&[
                "-r",
                "-n",
                "--",
                "pattern",
                "-e malicious --include=*.secret",
                "dir/"
            ])
        );
    }
}
