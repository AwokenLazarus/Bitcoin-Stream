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

/// Open for reading and appending, creating with `mode` (the append-only logs).
pub fn with_mode_rw_append(path: &Path, mode: u32) -> io::Result<File> {
    with_mode(OpenOptions::new().read(true).append(true).create(true), mode).open(path)
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

/// AGP-055: the steps of a durable write, as functions, so each one can be counted and (in tests)
/// made the last thing the process does. Every state file and log of the signer writes through these.
pub mod probe {
    use std::cell::Cell;

    /// What [`crash_at`] unwinds with: the process "died" at a durable step. A test catches it
    /// (`std::panic::catch_unwind`), drops every object and opens the wallet again from its files.
    #[derive(Debug)]
    pub struct Crash(pub &'static str, pub u64);

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct Counts {
        pub steps: u64,
        pub writes: u64,
        pub syncs: u64,
        pub renames: u64,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = const { Cell::new(Counts { steps: 0, writes: 0, syncs: 0, renames: 0 }) };
        static CRASH_AT: Cell<Option<(u64, bool)>> = const { Cell::new(None) };
    }

    /// Zero this thread's counters and disarm any crash.
    pub fn reset() {
        COUNTS.with(|c| c.set(Counts::default()));
        CRASH_AT.with(|c| c.set(None));
    }

    /// The durable steps this thread has taken since [`reset`].
    pub fn counts() -> Counts {
        COUNTS.with(Cell::get)
    }

    /// Let `steps` more durable steps of this thread through, then unwind with [`Crash`] at the
    /// next one. With `torn`, a write that dies first lands half its bytes. Nothing in the signer
    /// calls this: it exists for the crash tests.
    pub fn crash_at(steps: u64, torn: bool) {
        reset();
        CRASH_AT.with(|c| c.set(Some((steps, torn))));
    }

    /// Count one step; `Some(torn)` when this step is where the armed crash happens.
    pub(super) fn step(kind: &'static str) -> Option<bool> {
        let n = COUNTS.with(|c| {
            let mut v = c.get();
            v.steps += 1;
            match kind {
                "write" => v.writes += 1,
                "sync" => v.syncs += 1,
                "rename" => v.renames += 1,
                _ => {}
            }
            c.set(v);
            v.steps
        });
        match CRASH_AT.with(Cell::get) {
            Some((after, torn)) if n > after => Some(torn),
            _ => None,
        }
    }

    pub(super) fn die(kind: &'static str) -> ! {
        let n = counts().steps;
        CRASH_AT.with(|c| c.set(None));
        // resume_unwind: no panic hook, so a crash test prints nothing for the crash itself
        std::panic::resume_unwind(Box::new(Crash(kind, n)))
    }
}

/// Write all of `data` (one durable step).
pub fn write_all(f: &mut File, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if let Some(torn) = probe::step("write") {
        if torn {
            let _ = f.write_all(&data[..(data.len() / 2).max(1).min(data.len())]);
        }
        probe::die("write");
    }
    f.write_all(data)
}

/// fsync the file (one durable step).
pub fn sync(f: &File) -> io::Result<()> {
    if probe::step("sync").is_some() {
        probe::die("sync");
    }
    f.sync_all()
}

/// Cut the file to `len` bytes (one durable step).
pub fn truncate(f: &File, len: u64) -> io::Result<()> {
    if probe::step("truncate").is_some() {
        probe::die("truncate");
    }
    f.set_len(len)
}

/// Rename `from` onto `to` (one durable step).
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    if probe::step("rename").is_some() {
        probe::die("rename");
    }
    std::fs::rename(from, to)
}

/// fsync a directory, so a file created or renamed in it stays there after a power loss (one
/// durable step). Unix only: elsewhere a directory cannot be opened for this, and it is a no-op.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    if probe::step("sync").is_some() {
        probe::die("sync");
    }
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// The directory holding `path` (`.` for a bare file name).
pub fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}
