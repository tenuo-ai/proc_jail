//! Argument classification for POSIX-style parsing.
//!
//! This module classifies arguments as flags, positionals, or the `--` terminator.
//! It uses a simplified POSIX model without flag expansion or splitting.

/// Classification of a command-line argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgType {
    /// A flag (starts with `-` or `--`, except lone `-`)
    Flag(String),
    /// A positional argument (doesn't start with `-`, or is lone `-`, or after `--`)
    Positional(String),
    /// The `--` terminator
    Terminator,
}

/// Classify a single argument.
///
/// # Rules
///
/// - `-` alone is a positional (convention for stdin)
/// - `--` alone is a terminator
/// - Anything starting with `-` (including `--flag`) is a flag
/// - Everything else is a positional
///
/// # Arguments
///
/// * `arg` - The argument to classify
/// * `after_terminator` - If true, treat all args as positional (we're past `--`)
pub fn classify_arg(arg: &str, after_terminator: bool) -> ArgType {
    if after_terminator {
        return ArgType::Positional(arg.to_string());
    }

    match arg {
        // Lone dash is positional (stdin convention)
        "-" => ArgType::Positional(arg.to_string()),
        // Double dash is terminator
        "--" => ArgType::Terminator,
        // Anything starting with dash is a flag
        s if s.starts_with('-') => ArgType::Flag(s.to_string()),
        // Everything else is positional
        _ => ArgType::Positional(arg.to_string()),
    }
}

/// Parse an argv vector into classified arguments.
///
/// Returns a vector of (ArgType, original_position) tuples.
pub fn parse_argv(argv: &[String]) -> Vec<(ArgType, usize)> {
    let mut result = Vec::with_capacity(argv.len());
    let mut after_terminator = false;

    for (i, arg) in argv.iter().enumerate() {
        let classified = classify_arg(arg, after_terminator);
        if classified == ArgType::Terminator {
            after_terminator = true;
        }
        result.push((classified, i));
    }

    result
}

/// Count flags and positionals in parsed arguments.
///
/// Returns (flag_count, positional_count).
/// The terminator itself is not counted.
pub fn count_args(parsed: &[(ArgType, usize)]) -> (usize, usize) {
    let mut flags = 0;
    let mut positionals = 0;

    for (arg_type, _) in parsed {
        match arg_type {
            ArgType::Flag(_) => flags += 1,
            ArgType::Positional(_) => positionals += 1,
            ArgType::Terminator => {}
        }
    }

    (flags, positionals)
}

/// Extract all flags from parsed arguments.
pub fn extract_flags(parsed: &[(ArgType, usize)]) -> Vec<&str> {
    parsed
        .iter()
        .filter_map(|(arg_type, _)| match arg_type {
            ArgType::Flag(s) => Some(s.as_str()),
            _ => None,
        })
        .collect()
}

/// Extract all positionals from parsed arguments.
pub fn extract_positionals(parsed: &[(ArgType, usize)]) -> Vec<&str> {
    parsed
        .iter()
        .filter_map(|(arg_type, _)| match arg_type {
            ArgType::Positional(s) => Some(s.as_str()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_classification() {
        assert_eq!(
            classify_arg("-f", false),
            ArgType::Flag("-f".to_string())
        );
        assert_eq!(
            classify_arg("--verbose", false),
            ArgType::Flag("--verbose".to_string())
        );
        assert_eq!(
            classify_arg("--file=foo", false),
            ArgType::Flag("--file=foo".to_string())
        );
        assert_eq!(
            classify_arg("-abc", false),
            ArgType::Flag("-abc".to_string())
        );
    }

    #[test]
    fn test_positional_classification() {
        assert_eq!(
            classify_arg("file.txt", false),
            ArgType::Positional("file.txt".to_string())
        );
        assert_eq!(
            classify_arg("pattern", false),
            ArgType::Positional("pattern".to_string())
        );
    }

    #[test]
    fn test_stdin_dash_is_positional() {
        assert_eq!(
            classify_arg("-", false),
            ArgType::Positional("-".to_string())
        );
    }

    #[test]
    fn test_terminator() {
        assert_eq!(classify_arg("--", false), ArgType::Terminator);
    }

    #[test]
    fn test_after_terminator_all_positional() {
        assert_eq!(
            classify_arg("-f", true),
            ArgType::Positional("-f".to_string())
        );
        assert_eq!(
            classify_arg("--verbose", true),
            ArgType::Positional("--verbose".to_string())
        );
    }

    #[test]
    fn test_parse_mixed_argv() {
        let argv: Vec<String> = vec![
            "-n".into(),
            "-i".into(),
            "--".into(),
            "-pattern".into(),
            "file.txt".into(),
        ];
        let parsed = parse_argv(&argv);

        assert_eq!(parsed[0].0, ArgType::Flag("-n".to_string()));
        assert_eq!(parsed[1].0, ArgType::Flag("-i".to_string()));
        assert_eq!(parsed[2].0, ArgType::Terminator);
        assert_eq!(parsed[3].0, ArgType::Positional("-pattern".to_string()));
        assert_eq!(parsed[4].0, ArgType::Positional("file.txt".to_string()));
    }

    #[test]
    fn test_count_args() {
        let argv: Vec<String> = vec![
            "-n".into(),
            "-i".into(),
            "pattern".into(),
            "file1.txt".into(),
            "file2.txt".into(),
        ];
        let parsed = parse_argv(&argv);
        let (flags, positionals) = count_args(&parsed);

        assert_eq!(flags, 2);
        assert_eq!(positionals, 3);
    }
}
