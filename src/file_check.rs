//! File type and permission checks for binaries.

use crate::error::Violation;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Check that a path points to a valid executable binary.
///
/// This function verifies (R4):
/// 1. Path points to a regular file (not directory, device, socket, etc.)
/// 2. File is executable by the current user
///
/// # Arguments
///
/// * `path` - The canonicalized path to check
///
/// # Errors
///
/// - `BinIsDirectory` if path is a directory
/// - `BinNotRegularFile` if path is not a regular file
/// - `BinNotExecutable` if file is not executable
pub fn check_binary(path: &Path) -> Result<(), Violation> {
    let path_str = path.display().to_string();

    let metadata = std::fs::metadata(path).map_err(|e| Violation::BinCanonicalizeFailed {
        path: path_str.clone(),
        reason: e.to_string(),
    })?;

    // Check file type
    if metadata.is_dir() {
        return Err(Violation::BinIsDirectory { path: path_str });
    }

    if !metadata.is_file() {
        return Err(Violation::BinNotRegularFile { path: path_str });
    }

    // Check executable permission
    if !is_executable(&metadata) {
        return Err(Violation::BinNotExecutable { path: path_str });
    }

    Ok(())
}

/// Check if a file is executable by the current user.
///
/// This checks:
/// 1. If user is owner and owner execute bit is set
/// 2. If user is in file's group and group execute bit is set
/// 3. If other execute bit is set
fn is_executable(metadata: &Metadata) -> bool {
    let mode = metadata.permissions().mode();

    // Get current user/group
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let file_uid = metadata.uid();
    let file_gid = metadata.gid();

    // Check owner execute
    if uid == file_uid && (mode & 0o100) != 0 {
        return true;
    }

    // Check group execute
    if gid == file_gid && (mode & 0o010) != 0 {
        return true;
    }

    // Check other execute
    if (mode & 0o001) != 0 {
        return true;
    }

    // Also check if any execute bit is set and we're root
    if uid == 0 && (mode & 0o111) != 0 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_directory_rejected() {
        let tmp = TempDir::new().unwrap();
        let result = check_binary(tmp.path());
        assert!(matches!(result, Err(Violation::BinIsDirectory { .. })));
    }

    #[test]
    fn test_regular_file_not_executable() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("not_executable");
        std::fs::write(&file, "content").unwrap();

        // Ensure not executable
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = check_binary(&file);
        assert!(matches!(result, Err(Violation::BinNotExecutable { .. })));
    }

    #[test]
    fn test_executable_file_accepted() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("executable");
        std::fs::write(&file, "#!/bin/sh\necho test").unwrap();

        // Make executable
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = check_binary(&file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_system_binary() {
        // /usr/bin/env should be executable
        let result = check_binary(Path::new("/usr/bin/env"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_device_file_rejected() {
        // /dev/null is not a regular file
        let result = check_binary(Path::new("/dev/null"));
        assert!(matches!(result, Err(Violation::BinNotRegularFile { .. })));
    }
}
