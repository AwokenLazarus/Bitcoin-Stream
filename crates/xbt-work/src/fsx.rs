//! Durable, private state files: write a temporary file (mode 0600 on Unix), fsync it, rename it
//! over the old one. The provider records every debit this way before its handler runs (§9.2).
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}
