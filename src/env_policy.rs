//! Environment variable policy.
//!
//! Controls which environment variables are passed to spawned processes.
//! Some variables are always stripped regardless of policy.

use std::collections::{HashMap, HashSet};

/// Environment variables that are ALWAYS stripped, even with AllowList policy.
///
/// These variables can be used to inject code or modify behavior in dangerous ways.
pub const ALWAYS_STRIP: &[&str] = &[
    // Library injection
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_PROFILE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    // Interpreter paths
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "RUBYLIB",
    "RUBYOPT",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "NODE_PATH",
    "NODE_OPTIONS",
    // Shell behavior
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS4",
    // Execution
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "SHELL",
    // Proxy hijacking
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    // Git hooks (can execute code)
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    // Locale (handled separately in LocaleOnly)
    // These are not stripped, but not passed by default either
];

/// Policy for environment variables passed to spawned processes.
#[derive(Debug, Clone, Default)]
pub enum EnvPolicy {
    /// Pass empty environment (default).
    ///
    /// The spawned process inherits no environment variables from the parent.
    /// This is the safest option.
    #[default]
    Empty,

    /// Pass only locale variables for consistent text handling.
    ///
    /// Sets: `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`
    LocaleOnly,

    /// Pass a fixed set of environment variables.
    ///
    /// The exact variables specified are passed. ALWAYS_STRIP is still applied.
    Fixed(HashMap<String, String>),

    /// Allowlist specific keys from the request.
    ///
    /// Only keys in the allowlist are passed from the request's env.
    /// ALWAYS_STRIP is still applied.
    AllowList(HashSet<String>),
}

impl EnvPolicy {
    /// Apply this policy to produce the final environment.
    ///
    /// # Arguments
    ///
    /// * `request_env` - Environment variables from the request
    ///
    /// # Returns
    ///
    /// The filtered environment to pass to the process.
    pub fn apply(&self, request_env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut result = match self {
            EnvPolicy::Empty => HashMap::new(),

            EnvPolicy::LocaleOnly => {
                let mut env = HashMap::new();
                env.insert("LANG".to_string(), "C.UTF-8".to_string());
                env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
                env
            }

            EnvPolicy::Fixed(fixed) => fixed.clone(),

            EnvPolicy::AllowList(allowed) => request_env
                .iter()
                .filter(|(k, _)| allowed.contains(*k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        // Always strip dangerous variables
        strip_dangerous(&mut result);

        result
    }

    /// Check if a specific key would be forbidden by ALWAYS_STRIP.
    pub fn is_forbidden(key: &str) -> bool {
        ALWAYS_STRIP.iter().any(|&s| s.eq_ignore_ascii_case(key))
    }
}

/// Remove dangerous environment variables from a map.
fn strip_dangerous(env: &mut HashMap<String, String>) {
    for key in ALWAYS_STRIP {
        env.remove(*key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_policy() {
        let policy = EnvPolicy::Empty;
        let request_env = HashMap::from([
            ("FOO".to_string(), "bar".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ]);

        let result = policy.apply(&request_env);
        assert!(result.is_empty());
    }

    #[test]
    fn test_locale_only() {
        let policy = EnvPolicy::LocaleOnly;
        let result = policy.apply(&HashMap::new());

        assert_eq!(result.get("LANG"), Some(&"C.UTF-8".to_string()));
        assert_eq!(result.get("LC_ALL"), Some(&"C.UTF-8".to_string()));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_fixed_policy() {
        let mut fixed = HashMap::new();
        fixed.insert("HOME".to_string(), "/home/user".to_string());
        fixed.insert("USER".to_string(), "user".to_string());

        let policy = EnvPolicy::Fixed(fixed);
        let result = policy.apply(&HashMap::new());

        assert_eq!(result.get("HOME"), Some(&"/home/user".to_string()));
        assert_eq!(result.get("USER"), Some(&"user".to_string()));
    }

    #[test]
    fn test_allowlist_policy() {
        let allowed: HashSet<String> = ["PATH", "HOME"].iter().map(|s| s.to_string()).collect();
        let policy = EnvPolicy::AllowList(allowed);

        let request_env = HashMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("SECRET".to_string(), "password".to_string()),
        ]);

        let result = policy.apply(&request_env);

        assert_eq!(result.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(result.get("HOME"), Some(&"/home/user".to_string()));
        assert!(!result.contains_key("SECRET"));
    }

    #[test]
    fn test_always_strip_applied() {
        let mut fixed = HashMap::new();
        fixed.insert("HOME".to_string(), "/home/user".to_string());
        fixed.insert("LD_PRELOAD".to_string(), "/evil/lib.so".to_string());

        let policy = EnvPolicy::Fixed(fixed);
        let result = policy.apply(&HashMap::new());

        assert!(result.contains_key("HOME"));
        assert!(!result.contains_key("LD_PRELOAD"));
    }

    #[test]
    fn test_always_strip_with_allowlist() {
        let allowed: HashSet<String> = ["LD_PRELOAD", "PYTHONPATH", "HOME"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let policy = EnvPolicy::AllowList(allowed);

        let request_env = HashMap::from([
            ("LD_PRELOAD".to_string(), "/evil/lib.so".to_string()),
            ("PYTHONPATH".to_string(), "/evil/python".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
        ]);

        let result = policy.apply(&request_env);

        // Dangerous vars stripped even though in allowlist
        assert!(!result.contains_key("LD_PRELOAD"));
        assert!(!result.contains_key("PYTHONPATH"));
        // Safe var passes
        assert!(result.contains_key("HOME"));
    }

    #[test]
    fn test_is_forbidden() {
        assert!(EnvPolicy::is_forbidden("LD_PRELOAD"));
        assert!(EnvPolicy::is_forbidden("PYTHONPATH"));
        assert!(EnvPolicy::is_forbidden("HTTP_PROXY"));
        assert!(!EnvPolicy::is_forbidden("HOME"));
        assert!(!EnvPolicy::is_forbidden("PATH"));
    }
}
