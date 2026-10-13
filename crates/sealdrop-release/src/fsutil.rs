//! Helpers for creating files that hold secrets.
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Creates `path` for writing, owner-only (0600 on Unix), and fails if it already exists.
pub fn create_new_private(path: &Path) -> io::Result<File> {
    options().create_new(true).open(path)
}

/// Creates `path` for writing, owner-only, replacing any existing content.
pub fn create_or_replace_private(path: &Path) -> io::Result<File> {
    let f = options().create(true).truncate(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Makes sure `path` exists, creating it owner-only (0600 on Unix) if needed. Existing files
/// keep their mode and content.
pub fn ensure_private(path: &Path) -> io::Result<()> {
    options()
        .create(true)
        .truncate(false)
        .open(path)
        .map(|_| ())
}
