//! Path canonicalization for binary validation.

use crate::error::Violation;
use std::path::{Path, PathBuf};

/// Canonicalize a binary path.
///
/// This function:
/// 1. Verifies the path is absolute
/// 2. Resolves all symlinks using `std::fs::canonicalize`
/// 3. Returns the canonical path or an appropriate error
///
/// # Errors
///
/// - `BinNotAbsolute` if path doesn't start with `/`
/// - `BinNotFound` if path doesn't exist
/// - `BinCanonicalizeFailed` for other canonicalization failures
pub fn canonicalize_binary(path: &Path) -> Result<PathBuf, Violation> {
    // R2: Absolute path required
    if !path.is_absolute() {
        return Err(Violation::BinNotAbsolute {
            path: path.display().to_string(),
        });
    }

    // R3: Canonicalize (resolve symlinks)
    std::fs::canonicalize(path).map_err(|e| {
        let path_str = path.display().to_string();
        match e.kind() {
            std::io::ErrorKind::NotFound => Violation::BinNotFound { path: path_str },
            _ => Violation::BinCanonicalizeFailed {
                path: path_str,
                reason: e.to_string(),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn test_absolute_path_required() {
        let result = canonicalize_binary(Path::new("relative/path"));
        assert!(matches!(result, Err(Violation::BinNotAbsolute { .. })));
    }

    #[test]
    fn test_relative_with_dot_rejected() {
        let result = canonicalize_binary(Path::new("./local/bin"));
        assert!(matches!(result, Err(Violation::BinNotAbsolute { .. })));
    }

    #[test]
    fn test_nonexistent_path() {
        let result = canonicalize_binary(Path::new("/nonexistent/binary/path"));
        assert!(matches!(result, Err(Violation::BinNotFound { .. })));
    }

    #[test]
    fn test_valid_path_canonicalizes() {
        // /usr/bin/env should exist on most Unix systems
        let result = canonicalize_binary(Path::new("/usr/bin/env"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_symlink_resolves() {
        let tmp = TempDir::new().unwrap();
        let real_file = tmp.path().join("real_binary");
        let link_path = tmp.path().join("symlink");

        // Create a real file
        std::fs::write(&real_file, "#!/bin/sh\necho test").unwrap();

        // Create symlink
        symlink(&real_file, &link_path).unwrap();

        // Canonicalize should resolve to real file
        let result = canonicalize_binary(&link_path).unwrap();
        assert_eq!(result, std::fs::canonicalize(&real_file).unwrap());
    }

    #[test]
    fn test_broken_symlink_rejected() {
        let tmp = TempDir::new().unwrap();
        let link_path = tmp.path().join("broken_link");

        // Create symlink to nonexistent target
        symlink("/nonexistent/target", &link_path).unwrap();

        let result = canonicalize_binary(&link_path);
        assert!(matches!(
            result,
            Err(Violation::BinNotFound { .. } | Violation::BinCanonicalizeFailed { .. })
        ));
    }
}
