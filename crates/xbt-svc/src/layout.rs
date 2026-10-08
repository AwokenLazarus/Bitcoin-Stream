//! The data dir's owners and modes (docs/CONTAINER.md §1), and `xbt-init`, the one-shot that makes a
//! data dir match them (AGP-040).
//!
//! A Docker named volume takes its owners from the images' `/data` skeleton. A bind mount does not: an
//! Umbrel `${APP_DATA_DIR}` arrives owned by the box user (1000), and a StartOS volume arrives owned by
//! root. `xbt-init` runs once before the services, as root with only `CHOWN`, `FOWNER` and
//! `DAC_OVERRIDE`, no network, and:
//!
//! * creates `<data>/<component>/` and `<component>/secrets/` (0700) and the socket dirs `run/signer/`
//!   and `run/anchor/` (0750), owned by each component's uid (the same uid as its group);
//! * when a component dir had another owner (a fresh bind mount, or a box that ran everything as 1000),
//!   gives it and everything under it to the component. It never follows a symlink (`lchown`, no descent);
//! * provisions the secrets a box's installer holds: `node-rpc-auth` into `signer/` and `hub/`, the UI
//!   password into `ui/`, and the MCP bearer token, generated once. With the UI (a box), the token is
//!   `run/ui/mcp-http-token`: owned by the UI (uid 10005), 0640, in `run/ui/` (0750), and the MCP reads it
//!   through the `xbt-wallet-ui` group. Only the UI can replace it (the Agents page rotates it); the MCP
//!   has no way to (AGP-042). An older layout's copies (`mcp/secrets/`, `ui/secrets/`) are moved there
//!   once and removed. Without the UI, the token stays `mcp/secrets/mcp-http-token`. A secret is
//!   rewritten only when its value changes; a generated one never is.
//!
//! It reports what it did as JSON (names, owners and modes; never a secret's value).
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A component: its sub-dir of the data dir and its uid (= gid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub user: &'static str,
    pub uid: u32,
}

/// agentpay's components (the cmp rows of the table are cmp's to create).
pub const COMPONENTS: &[Component] = &[
    Component { name: crate::SIGNER, user: "xbt-signer", uid: 10001 },
    Component { name: crate::WITNESS, user: "xbt-anchor-witness", uid: 10002 },
    Component { name: crate::MCP, user: "xbt-wallet-mcp", uid: 10003 },
    Component { name: crate::HUB, user: "xbt402-hub", uid: 10004 },
    Component { name: crate::UI, user: "xbt-wallet-ui", uid: 10005 },
    Component { name: crate::RELAY, user: "xbt-work-relay", uid: 10006 },
];

/// The socket dirs: (dir under `run/`, the component that serves it).
pub const RUN_DIRS: &[(&str, &str)] = &[(crate::RUN_SIGNER, crate::SIGNER), (crate::RUN_ANCHOR, crate::WITNESS), (crate::RUN_UI, crate::UI)];

/// The shared MCP token's mode: the UI reads and writes it, the MCP (in the UI's group) reads it.
pub const MCP_TOKEN_MODE: u32 = 0o640;

pub fn component(name: &str) -> Option<&'static Component> {
    COMPONENTS.iter().find(|c| c.name == name)
}

/// Where each provisioned secret comes from (`xbt-init`'s environment, set by the box's installer).
#[derive(Default, Clone)]
pub struct Provision {
    /// `node-rpc-auth` (`user:password`).
    pub node_rpc_auth: Option<String>,
    /// The UI's login password.
    pub ui_password: Option<String>,
}

impl std::fmt::Debug for Provision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Provision(node_rpc_auth: {}, ui_password: {})", self.node_rpc_auth.is_some(), self.ui_password.is_some())
    }
}

fn file_or_env(file_var: &str, var: &str) -> Result<Option<String>, String> {
    if let Some(p) = crate::env(file_var) {
        let t = std::fs::read_to_string(&p).map_err(|e| format!("{file_var} {p}: {e}"))?;
        return Ok(Some(t.trim_end_matches(['\r', '\n']).to_string()).filter(|t| !t.is_empty()));
    }
    Ok(crate::env(var))
}

impl Provision {
    /// `XBT_INIT_NODE_RPC_AUTH_FILE` / `XBT_INIT_NODE_RPC_AUTH` (`user:password`), or
    /// `XBT_INIT_NODE_RPC_USER` + `XBT_INIT_NODE_RPC_PASS` (Umbrel: a dependency's exports);
    /// `XBT_INIT_UI_PASSWORD_FILE` / `XBT_INIT_UI_PASSWORD` (Umbrel: `${APP_PASSWORD}`).
    ///
    /// These are plain env values on purpose: `xbt-init` is the installer's step, it exits before any
    /// service starts, and the services themselves still read only files (production mode).
    pub fn from_env() -> Result<Self, String> {
        let mut node_rpc_auth = file_or_env("XBT_INIT_NODE_RPC_AUTH_FILE", "XBT_INIT_NODE_RPC_AUTH")?;
        if node_rpc_auth.is_none() {
            if let (Some(u), Some(p)) = (crate::env("XBT_INIT_NODE_RPC_USER"), crate::env("XBT_INIT_NODE_RPC_PASS")) {
                node_rpc_auth = Some(format!("{u}:{p}"));
            }
        }
        if let Some(a) = &node_rpc_auth {
            if !a.contains(':') {
                return Err("the node RPC credentials must be user:password".into());
            }
        }
        let ui_password = file_or_env("XBT_INIT_UI_PASSWORD_FILE", "XBT_INIT_UI_PASSWORD")?;
        if ui_password.as_deref().is_some_and(|p| p.chars().count() < 8) {
            return Err("the UI password is shorter than 8 characters".into());
        }
        Ok(Self { node_rpc_auth, ui_password })
    }
}

#[cfg(unix)]
fn owner_mode(p: &Path) -> io::Result<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p)?;
    Ok((m.uid(), m.gid(), m.mode() & 0o7777))
}

#[cfg(unix)]
fn lchown(p: &Path, uid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(p, Some(uid), Some(uid))
}

/// Open `p` itself: O_NOFOLLOW refuses a symlink in its last component (ELOOP), O_NONBLOCK keeps
/// a FIFO from blocking. AGP-063 K1: owner and mode then change through this fd, never by path.
#[cfg(unix)]
fn open_nofollow(p: &Path, dir: bool) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | if dir { libc::O_DIRECTORY } else { 0 };
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(p)
}

/// Where the entries of the directory open as `d` (at `path`) are named: through the fd on Linux
/// (`/proc/self/fd/N`), so a parent swapped for a symlink after it was opened is never followed.
#[cfg(unix)]
fn entries_of(d: &std::fs::File, path: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let proc = PathBuf::from(format!("/proc/self/fd/{}", d.as_raw_fd()));
        if proc.exists() {
            return proc;
        }
    }
    let _ = d;
    path.to_path_buf()
}

/// Give the directory open as `d` (at `path`) and everything under it to `uid`. Directories are
/// opened O_NOFOLLOW relative to their parent's fd and chowned through their own fd; anything else
/// is lchowned in place, so no symlink is ever followed, even one swapped in during the walk.
#[cfg(unix)]
fn chown_tree(d: &std::fs::File, path: &Path, uid: u32, changed: &mut u64) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = d.metadata()?;
    if md.uid() != uid || md.gid() != uid {
        std::os::unix::fs::fchown(d, Some(uid), Some(uid))?;
        *changed += 1;
    }
    if !md.file_type().is_dir() {
        return Ok(());
    }
    let base = entries_of(d, path);
    for e in std::fs::read_dir(&base)? {
        let name = e?.file_name();
        let p = base.join(&name);
        let m = std::fs::symlink_metadata(&p)?;
        if m.file_type().is_dir() {
            match open_nofollow(&p, true) {
                Ok(c) => chown_tree(&c, &path.join(&name), uid, changed)?,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                    lchown(&p, uid)?;
                    *changed += 1;
                }
                Err(e) => return Err(e),
            }
        } else if m.uid() != uid || m.gid() != uid {
            lchown(&p, uid)?;
            *changed += 1;
        }
    }
    Ok(())
}

/// A directory owned by `uid` with `mode`; created if missing. When its owner was another uid, its
/// contents change owner too (the bind-mount case). Returns a report row.
#[cfg(unix)]
fn own_dir(dir: &Path, uid: u32, mode: u32, recurse: bool) -> Result<Value, String> {
    let ctx = |e: io::Error| format!("{}: {e}", dir.display());
    let created = !dir.exists();
    if created {
        std::fs::create_dir_all(dir).map_err(ctx)?;
    }
    let f = match open_nofollow(dir, true) {
        Ok(f) => f,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
            return Err(format!("{}: is a symlink or not a directory; refusing", dir.display()));
        }
        Err(e) => return Err(ctx(e)),
    };
    let (u0, g0, m0) = {
        use std::os::unix::fs::MetadataExt;
        let m = f.metadata().map_err(ctx)?;
        (m.uid(), m.gid(), m.mode() & 0o7777)
    };
    let mut changed = 0u64;
    if u0 != uid || g0 != uid {
        if recurse {
            chown_tree(&f, dir, uid, &mut changed).map_err(ctx)?;
        } else {
            std::os::unix::fs::fchown(&f, Some(uid), Some(uid)).map_err(ctx)?;
            changed = 1;
        }
    }
    if m0 != mode {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(ctx)?;
    }
    Ok(json!({"path": dir.display().to_string(), "uid": uid, "mode": format!("{mode:o}"), "created": created,
              "was": {"uid": u0, "gid": g0, "mode": format!("{m0:o}")}, "chowned": changed}))
}

/// Write a secret owned by `uid` with `mode` (0600, or 0640 for the shared MCP token), only when its value differs. The temp file is created
/// exclusively (never through a symlink a service may have planted) and renamed over the target.
#[cfg(unix)]
fn put_secret(path: &Path, value: &[u8], uid: u32, mode: u32) -> Result<&'static str, String> {
    let ctx = |e: io::Error| format!("{}: {e}", path.display());
    if let Ok(mut f) = open_nofollow(path, false) {
        use std::os::unix::fs::MetadataExt;
        let md = f.metadata().map_err(ctx)?;
        let mut cur = vec![];
        if md.file_type().is_file() && std::io::Read::read_to_end(&mut f, &mut cur).is_ok() && cur == value {
            if (md.uid(), md.gid(), md.mode() & 0o7777) != (uid, uid, mode) {
                use std::os::unix::fs::PermissionsExt;
                std::os::unix::fs::fchown(&f, Some(uid), Some(uid)).map_err(ctx)?;
                f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(ctx)?;
                return Ok("fixed");
            }
            return Ok("unchanged");
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".xbt-init");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&tmp).map_err(ctx)?;
    std::os::unix::fs::fchown(&f, Some(uid), Some(uid)).map_err(ctx)?;
    f.write_all(value).and_then(|_| f.sync_all()).map_err(ctx)?;
    if mode != 0o600 {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).and_then(|_| f.sync_all()).map_err(ctx)?;
    }
    drop(f);
    std::fs::rename(&tmp, path).map_err(ctx)?;
    Ok("written")
}

/// Read a secret file if it is a regular file (not a symlink).
fn read_regular(path: &Path) -> Option<Vec<u8>> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    std::fs::read(path).ok().filter(|b| !b.is_empty())
}

/// Make `root` match the layout for `names` (component names) and provision the secrets.
#[cfg(unix)]
pub fn init(root: &Path, names: &[String], prov: &Provision) -> Result<Value, String> {
    init_with(root, names, prov, &|c: &Component| c.uid)
}

/// [`init`] with the uids from `uid_of` (tests run it as their own uid).
#[cfg(unix)]
fn init_with(root: &Path, names: &[String], prov: &Provision, uid_of: &dyn Fn(&Component) -> u32) -> Result<Value, String> {
    let comps: Vec<&Component> = names.iter().map(|n| component(n).ok_or_else(|| format!("unknown component {n}"))).collect::<Result<_, _>>()?;
    let has = |n: &str| comps.iter().any(|c| c.name == n);
    if !root.is_dir() {
        std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
    }
    let mut dirs = vec![];
    for c in &comps {
        let d = root.join(c.name);
        dirs.push(own_dir(&d, uid_of(c), 0o700, true)?);
        dirs.push(own_dir(&d.join("secrets"), uid_of(c), 0o700, true)?);
    }
    let run = root.join("run");
    if !run.is_dir() {
        std::fs::create_dir_all(&run).map_err(|e| format!("{}: {e}", run.display()))?;
        crate::set_mode(&run, 0o755).map_err(|e| format!("{}: {e}", run.display()))?;
    }
    for (dir, server) in RUN_DIRS {
        if let Some(c) = comps.iter().find(|c| c.name == *server) {
            dirs.push(own_dir(&run.join(dir), uid_of(c), 0o750, true)?);
        }
    }
    let mut secrets = vec![];
    let mut put = |comp: &str, name: &str, value: &[u8]| -> Result<(), String> {
        let c = component(comp).expect("known");
        let r = put_secret(&root.join(comp).join("secrets").join(name), value, uid_of(c), 0o600)?;
        secrets.push(json!({"component": comp, "name": name, "result": r}));
        Ok(())
    };
    if let Some(a) = &prov.node_rpc_auth {
        for comp in [crate::SIGNER, crate::HUB] {
            if has(comp) {
                put(comp, "node-rpc-auth", a.as_bytes())?;
            }
        }
    }
    if has(crate::UI) {
        if let Some(p) = &prov.ui_password {
            put(crate::UI, "xbt-ui-password", p.as_bytes())?;
        }
    }
    if has(crate::MCP) {
        let tp = root.join(crate::MCP).join("secrets").join(crate::MCP_TOKEN);
        let ui_copy = root.join(crate::UI).join("secrets").join(crate::MCP_TOKEN);
        let shared = root.join("run").join(crate::RUN_UI).join(crate::MCP_TOKEN);
        let fresh = || crate::to_hex(&crate::random_bytes(32)).into_bytes();
        if has(crate::UI) {
            // the UI owns the token (it rotates it); the MCP only reads it. The first run of this layout
            // keeps an older layout's token, so agents keep working across the upgrade.
            let token = read_regular(&shared).or_else(|| read_regular(&tp)).unwrap_or_else(fresh);
            let r = put_secret(&shared, &token, uid_of(component(crate::UI).expect("known")), MCP_TOKEN_MODE)?;
            secrets.push(json!({"component": crate::UI, "name": format!("run/{}/{}", crate::RUN_UI, crate::MCP_TOKEN), "result": r}));
            for (comp, old) in [(crate::MCP, &tp), (crate::UI, &ui_copy)] {
                if std::fs::symlink_metadata(old).is_ok() {
                    std::fs::remove_file(old).map_err(|e| format!("{}: {e}", old.display()))?;
                    secrets.push(json!({"component": comp, "name": crate::MCP_TOKEN, "result": "removed"}));
                }
            }
        } else {
            // an existing value stays (owner and mode only)
            put(crate::MCP, crate::MCP_TOKEN, &read_regular(&tp).unwrap_or_else(fresh))?;
        }
    }
    Ok(json!({"ok": true, "root": root.display().to_string(), "dirs": dirs, "secrets": secrets}))
}

/// Check `root` against the layout without changing anything: every component dir and socket dir has
/// its owner and mode, and every file under `secrets/` is 0600 and owned by the component.
#[cfg(unix)]
pub fn check(root: &Path, names: &[String]) -> Value {
    let mut problems = vec![];
    let mut rows = vec![];
    let mut want = |p: PathBuf, uid: u32, mode: u32, problems: &mut Vec<String>| match owner_mode(&p) {
        Ok((u, g, m)) => {
            rows.push(json!({"path": p.display().to_string(), "uid": u, "gid": g, "mode": format!("{m:o}")}));
            if (u, g, m) != (uid, uid, mode) {
                problems.push(format!("{}: {u}:{g} {m:o}, want {uid}:{uid} {mode:o}", p.display()));
            }
        }
        Err(e) => problems.push(format!("{}: {e}", p.display())),
    };
    for n in names {
        let Some(c) = component(n) else {
            problems.push(format!("unknown component {n}"));
            continue;
        };
        let mut want = |p, uid, mode| want(p, uid, mode, &mut problems);
        let d = root.join(c.name);
        want(d.clone(), c.uid, 0o700);
        want(d.join("secrets"), c.uid, 0o700);
        if let Ok(rd) = std::fs::read_dir(d.join("secrets")) {
            for e in rd.flatten() {
                want(e.path(), c.uid, 0o600);
            }
        }
        for (dir, server) in RUN_DIRS {
            if *server == c.name {
                want(root.join("run").join(dir), c.uid, 0o750);
            }
        }
        if c.name == crate::UI && names.iter().any(|n| n == crate::MCP) {
            want(root.join("run").join(crate::RUN_UI).join(crate::MCP_TOKEN), c.uid, MCP_TOKEN_MODE);
        }
    }
    json!({"ok": problems.is_empty(), "problems": problems, "paths": rows})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me() -> u32 {
        std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
    }

    #[test]
    fn table_matches_container_md() {
        let t: Vec<_> = COMPONENTS.iter().map(|c| (c.name, c.uid)).collect();
        assert_eq!(t, vec![("signer", 10001), ("witness", 10002), ("mcp", 10003), ("hub", 10004), ("ui", 10005), ("relay", 10006)]);
    }

    #[test]
    fn provision_needs_user_password() {
        std::env::set_var("XBT_INIT_NODE_RPC_AUTH", "nocolon");
        assert!(Provision::from_env().is_err());
        std::env::remove_var("XBT_INIT_NODE_RPC_AUTH");
        std::env::set_var("XBT_INIT_NODE_RPC_USER", "u");
        std::env::set_var("XBT_INIT_NODE_RPC_PASS", "p");
        assert_eq!(Provision::from_env().unwrap().node_rpc_auth.as_deref(), Some("u:p"));
        std::env::remove_var("XBT_INIT_NODE_RPC_USER");
        std::env::remove_var("XBT_INIT_NODE_RPC_PASS");
        assert!(!format!("{:?}", Provision { node_rpc_auth: Some("u:secret".into()), ui_password: None }).contains("secret"));
    }

    /// As an unprivileged user the chown steps only succeed for our own uid, so run the whole flow as
    /// "every component is me": dirs and modes, secrets, the token copy, idempotence, symlink refusal.
    /// (The real uids are exercised as root by the container tests.)
    #[test]
    fn init_flow_as_own_uid() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        // stand-in: the code path is the same with every uid = ours
        let names: Vec<String> = ["signer", "mcp", "ui"].iter().map(|s| s.to_string()).collect();
        let prov = Provision { node_rpc_auth: Some("xbt:pw".into()), ui_password: Some("correct horse".into()) };
        let r = init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(r["ok"], true);
        // AGP-042: with the UI, the token is the UI's run/ui/mcp-http-token (0640, the MCP reads it by group)
        let tok = std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap();
        assert_eq!(tok.len(), 64);
        assert!(!root.join("mcp/secrets/mcp-http-token").exists() && !root.join("ui/secrets/mcp-http-token").exists());
        assert_eq!(std::fs::metadata(root.join("run/ui/mcp-http-token")).unwrap().mode() & 0o777, 0o640);
        assert_eq!(std::fs::metadata(root.join("run/ui")).unwrap().mode() & 0o777, 0o750);
        assert_eq!(std::fs::read_to_string(root.join("signer/secrets/node-rpc-auth")).unwrap(), "xbt:pw");
        assert!(!root.join("hub").exists(), "only the listed components");
        for p in ["signer/secrets/node-rpc-auth", "ui/secrets/xbt-ui-password"] {
            assert_eq!(std::fs::metadata(root.join(p)).unwrap().mode() & 0o777, 0o600, "{p}");
        }
        assert_eq!(std::fs::metadata(root.join("run/signer")).unwrap().mode() & 0o777, 0o750);
        // a second run keeps the token and rewrites nothing
        let r2 = init_as(&root, &names, &prov, uid).unwrap();
        assert!(r2["secrets"].as_array().unwrap().iter().all(|s| s["result"] == "unchanged"), "{r2}");
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), tok);
        // a rotated token (the UI replaced it) survives a restart's init
        crate::replace_secret_file(&root.join("run/ui/mcp-http-token"), b"rotated", 0o640).unwrap();
        init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), "rotated");
        // a changed node password is rewritten; a planted symlink at the temp path is not followed
        let victim = t.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, root.join("signer/secrets/node-rpc-auth.xbt-init")).unwrap();
        let prov2 = Provision { node_rpc_auth: Some("xbt:new".into()), ..prov.clone() };
        init_as(&root, &names, &prov2, uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("signer/secrets/node-rpc-auth")).unwrap(), "xbt:new");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        // a component dir that is a symlink is refused
        std::fs::create_dir_all(t.path().join("elsewhere")).unwrap();
        let root2 = t.path().join("data2");
        std::fs::create_dir_all(&root2).unwrap();
        std::os::unix::fs::symlink(t.path().join("elsewhere"), root2.join("signer")).unwrap();
        assert!(init_as(&root2, &["signer".to_string()], &Provision::default(), uid).is_err());
    }

    /// An AGP-040 data dir (the token in mcp/secrets and a copy in ui/secrets) upgrades with the same token;
    /// without the UI the token stays the MCP's own secret.
    #[test]
    fn mcp_token_upgrade_and_mcp_only() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        let mcp_only: Vec<String> = ["signer", "mcp"].iter().map(|s| s.to_string()).collect();
        init_as(&root, &mcp_only, &Provision::default(), uid).unwrap();
        let old = std::fs::read_to_string(root.join("mcp/secrets/mcp-http-token")).unwrap();
        assert_eq!(std::fs::metadata(root.join("mcp/secrets/mcp-http-token")).unwrap().mode() & 0o777, 0o600);
        assert!(!root.join("run/ui").exists());
        std::fs::create_dir_all(root.join("ui/secrets")).unwrap();
        std::fs::write(root.join("ui/secrets/mcp-http-token"), &old).unwrap();
        let all: Vec<String> = ["signer", "mcp", "ui"].iter().map(|s| s.to_string()).collect();
        let r = init_as(&root, &all, &Provision::default(), uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), old, "agents keep their token");
        assert!(!root.join("mcp/secrets/mcp-http-token").exists() && !root.join("ui/secrets/mcp-http-token").exists(), "{r}");
        assert!(!r.to_string().contains(&old), "the report never holds a secret");
    }

    /// AGP-063 K1: the walk regroups everything under the tree and nothing a symlink in it points at.
    #[test]
    fn k1_chown_tree_regroups_the_tree_and_never_follows_a_symlink() {
        let uid = me();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let other = status.lines().find_map(|l| l.strip_prefix("Groups:")).into_iter()
            .flat_map(|g| g.split_whitespace().filter_map(|x| x.parse::<u32>().ok()).collect::<Vec<_>>()).find(|&g| g != uid);
        let Some(g) = other else { return };
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let (tree, outside) = (t.path().join("tree"), t.path().join("outside"));
        std::fs::create_dir_all(tree.join("a")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(tree.join("a/f"), "x").unwrap();
        std::fs::write(outside.join("v"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        for p in [tree.join("a/f"), outside.join("v"), outside.clone()] {
            std::os::unix::fs::chown(&p, None, Some(g)).unwrap();
        }
        let mut changed = 0;
        chown_tree(&open_nofollow(&tree, true).unwrap(), &tree, uid, &mut changed).unwrap();
        assert_eq!(std::fs::metadata(tree.join("a/f")).unwrap().gid(), uid);
        assert_eq!(std::fs::metadata(outside.join("v")).unwrap().gid(), g);
        assert_eq!(std::fs::metadata(&outside).unwrap().gid(), g);
        assert!(changed >= 1);
        assert!(open_nofollow(&tree.join("link"), true).is_err());
    }

    fn init_as(root: &Path, names: &[String], prov: &Provision, uid: u32) -> Result<Value, String> {
        init_with(root, names, prov, &|_| uid)
    }

    #[test]
    fn check_reports_problems() {
        let t = tempfile::tempdir().unwrap();
        let v = check(t.path(), &["signer".to_string()]);
        assert_eq!(v["ok"], false);
    }
}
