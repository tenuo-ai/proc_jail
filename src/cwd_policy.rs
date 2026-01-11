//! Working directory policy.
//!
//! Controls what working directory a spawned process can use.

use crate::error::Violation;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Policy for the working directory of spawned processes.
#[derive(Debug, Clone)]
pub enum CwdPolicy {
    /// Fixed directory (default).
    ///
    /// All processes use this directory regardless of request.
    Fixed(PathBuf),

    /// Must be within a specific directory tree.
    ///
    /// The requested cwd must be a subdirectory of (or equal to) the jail root.
    Jailed {
        /// Root of the jail
        root: PathBuf,
        /// Default if request doesn't specify cwd
        default: PathBuf,
    },

    /// Allowlist of specific directories.
    ///
    /// The requested cwd must exactly match one of the allowed paths.
    AllowList {
        allowed: HashSet<PathBuf>,
        /// Default if request doesn't specify cwd
        default: PathBuf,
    },
}

impl Default for CwdPolicy {
    fn default() -> Self {
        CwdPolicy::Fixed(PathBuf::from("/tmp"))
    }
}

impl CwdPolicy {
    /// Create a fixed cwd policy.
    pub fn fixed(path: impl Into<PathBuf>) -> Self {
        CwdPolicy::Fixed(path.into())
    }

    /// Create a jailed cwd policy.
    pub fn jailed(root: impl Into<PathBuf>, default: impl Into<PathBuf>) -> Self {
        CwdPolicy::Jailed {
            root: root.into(),
            default: default.into(),
        }
    }

    /// Create an allowlist cwd policy.
    pub fn allowlist(allowed: HashSet<PathBuf>, default: impl Into<PathBuf>) -> Self {
        CwdPolicy::AllowList {
            allowed,
            default: default.into(),
        }
    }

    /// Validate and resolve the working directory.
    ///
    /// # Arguments
    ///
    /// * `requested` - The requested cwd from the ProcRequest (if any)
    ///
    /// # Returns
    ///
    /// The validated cwd to use, or an error if the request is forbidden.
    pub fn validate(&self, requested: Option<&Path>) -> Result<PathBuf, Violation> {
        match self {
            CwdPolicy::Fixed(fixed) => {
                // Ignore requested, always use fixed
                Ok(fixed.clone())
            }

            CwdPolicy::Jailed { root, default } => {
                let target = requested.unwrap_or(default);

                // Canonicalize both paths for comparison
                let canonical_root =
                    std::fs::canonicalize(root).map_err(|e| Violation::CwdForbidden {
                        path: root.display().to_string(),
                        reason: format!("failed to canonicalize jail root: {}", e),
                    })?;

                let canonical_target =
                    std::fs::canonicalize(target).map_err(|e| Violation::CwdForbidden {
                        path: target.display().to_string(),
                        reason: format!("failed to canonicalize cwd: {}", e),
                    })?;

                // Check if target is within root
                if canonical_target.starts_with(&canonical_root) {
                    Ok(canonical_target)
                } else {
                    Err(Violation::CwdForbidden {
                        path: target.display().to_string(),
                        reason: format!("not within jail root {}", root.display()),
                    })
                }
            }

            CwdPolicy::AllowList { allowed, default } => {
                let target = requested.unwrap_or(default);

                // Canonicalize for comparison
                let canonical_target =
                    std::fs::canonicalize(target).map_err(|e| Violation::CwdForbidden {
                        path: target.display().to_string(),
                        reason: format!("failed to canonicalize cwd: {}", e),
                    })?;

                // Check each allowed path
                for allowed_path in allowed {
                    if let Ok(canonical_allowed) = std::fs::canonicalize(allowed_path) {
                        if canonical_target == canonical_allowed {
                            return Ok(canonical_target);
                        }
                    }
                }

                Err(Violation::CwdForbidden {
                    path: target.display().to_string(),
                    reason: "not in allowlist".to_string(),
                })
            }
        }
    }

    /// Get the default cwd for this policy.
    pub fn default_cwd(&self) -> &Path {
        match self {
            CwdPolicy::Fixed(p) => p,
            CwdPolicy::Jailed { default, .. } => default,
            CwdPolicy::AllowList { default, .. } => default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_fixed_policy() {
        let policy = CwdPolicy::fixed("/tmp");

        // Always returns fixed path regardless of request
        let result = policy.validate(None).unwrap();
        assert_eq!(result, PathBuf::from("/tmp"));

        let result = policy.validate(Some(Path::new("/home/user"))).unwrap();
        assert_eq!(result, PathBuf::from("/tmp"));
    }

    #[test]
    fn test_jailed_policy_allows_subdirs() {
        let tmp = TempDir::new().unwrap();
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let policy = CwdPolicy::jailed(tmp.path(), tmp.path());

        // Root itself is allowed
        assert!(policy.validate(Some(tmp.path())).is_ok());

        // Subdirectory is allowed
        assert!(policy.validate(Some(&subdir)).is_ok());
    }

    #[test]
    fn test_jailed_policy_denies_outside() {
        let tmp = TempDir::new().unwrap();
        let policy = CwdPolicy::jailed(tmp.path(), tmp.path());

        // Outside jail is denied
        let result = policy.validate(Some(Path::new("/tmp")));
        assert!(matches!(result, Err(Violation::CwdForbidden { .. })));
    }

    #[test]
    fn test_allowlist_policy() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();

        let allowed: HashSet<PathBuf> =
            [tmp1.path().to_path_buf(), tmp2.path().to_path_buf()].into();
        let policy = CwdPolicy::allowlist(allowed, tmp1.path());

        // Allowed paths work
        assert!(policy.validate(Some(tmp1.path())).is_ok());
        assert!(policy.validate(Some(tmp2.path())).is_ok());

        // Unapproved path denied
        let result = policy.validate(Some(Path::new("/tmp")));
        assert!(matches!(result, Err(Violation::CwdForbidden { .. })));
    }

    #[test]
    fn test_default_cwd_used_when_none_requested() {
        let tmp = TempDir::new().unwrap();
        let policy = CwdPolicy::jailed(tmp.path(), tmp.path());

        let result = policy.validate(None).unwrap();
        assert_eq!(result, std::fs::canonicalize(tmp.path()).unwrap());
    }
}
