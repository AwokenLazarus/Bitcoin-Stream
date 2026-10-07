//! Private files, portably: mode 0600/0640 on Unix; on other platforms the file is created with
//! the platform default (protect the run directory with the OS's own ACLs there).
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

fn with_mode(o: &mut OpenOptions, _mode: u32) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(_mode);
    }
    o
}

/// Open for append, creating with `mode`.
pub fn append(path: &Path, mode: u32) -> io::Result<File> {
    with_mode(OpenOptions::new().append(true).create(true), mode).open(path)
}

/// Create a new file (fails if it exists) with `mode`.
pub fn create_new(path: &Path, mode: u32) -> io::Result<File> {
    with_mode(OpenOptions::new().write(true).create_new(true), mode).open(path)
}

/// Create or truncate with `mode`.
pub fn create_truncate(path: &Path, mode: u32) -> io::Result<File> {
    with_mode(OpenOptions::new().write(true).create(true).truncate(true), mode).open(path)
}

/// chmod on Unix; a no-op elsewhere.
pub fn set_mode(path: &Path, _mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(_mode))?;
    }
    Ok(())
}

/// The file's permission bits (0 where the platform has none).
pub fn mode_of(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    }
    #[allow(unreachable_code)]
    { let _ = path; 0 }
}
