//! The login, sessions and CSRF tokens.
//!
//! * The password is checked against an scrypt hash (N=2^15, r=8, p=1): the platform's password is
//!   hashed at start, or the one set on first run is stored as `password.scrypt` (0600) in the data dir.
//! * First run without a platform password: a one-time setup code (`setup-code`, 0600, also printed on
//!   stderr) is needed to set it, unless `XBT_UI_SETUP_OPEN=1`.
//! * A session is 32 random bytes in an `HttpOnly; SameSite=Strict` cookie, with an idle and an absolute
//!   lifetime; each has its own CSRF token, required on every POST.
//! * Five failed logins within a minute lock the login for the rest of that minute.
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{ct_eq, random_bytes};

const LOG_N: u8 = 15;
const R: u32 = 8;
const P: u32 = 1;
pub const MIN_PASSWORD: usize = 10;
const MAX_SESSIONS: usize = 16;
const FAILS_PER_MIN: usize = 5;

#[derive(Clone)]
pub struct PwHash {
    salt: [u8; 16],
    hash: [u8; 32],
}

fn scrypt32(pw: &str, salt: &[u8]) -> [u8; 32] {
    let params = scrypt::Params::new(LOG_N, R, P, 32).expect("scrypt params");
    let mut out = [0u8; 32];
    scrypt::scrypt(pw.as_bytes(), salt, &params, &mut out).expect("scrypt");
    out
}

impl PwHash {
    pub fn new(pw: &str) -> Self {
        let salt = random_bytes::<16>();
        Self { salt, hash: scrypt32(pw, &salt) }
    }

    pub fn verify(&self, pw: &str) -> bool {
        ct_eq(&scrypt32(pw, &self.salt), &self.hash)
    }

    pub fn encode(&self) -> String {
        format!("scrypt${LOG_N}${R}${P}${}${}\n", hex::encode(self.salt), hex::encode(self.hash))
    }

    pub fn decode(s: &str) -> Option<Self> {
        let p: Vec<&str> = s.trim().split('$').collect();
        if p.len() != 6 || p[0] != "scrypt" || p[1] != LOG_N.to_string() || p[2] != R.to_string() || p[3] != P.to_string() {
            return None;
        }
        Some(Self { salt: hex::decode(p[4]).ok()?.try_into().ok()?, hash: hex::decode(p[5]).ok()?.try_into().ok()? })
    }
}

pub struct Session {
    pub csrf: String,
    created: Instant,
    last: Instant,
    /// One-shot message for the next page: (ok, text).
    pub flash: Option<(bool, String)>,
}

pub struct Auth {
    pw: Mutex<Option<PwHash>>,
    hash_path: PathBuf,
    setup_code: Option<String>,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<VecDeque<Instant>>,
    idle: Duration,
    max: Duration,
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

impl Auth {
    /// `password`: the platform's; otherwise the stored hash, or first-run setup.
    pub fn open(data_dir: &Path, password: Option<&str>, setup_open: bool, idle: Duration, max: Duration) -> Result<Self, String> {
        let hash_path = data_dir.join("password.scrypt");
        let pw = match password {
            Some(p) => Some(PwHash::new(p)),
            None => match std::fs::read_to_string(&hash_path) {
                Ok(t) => Some(PwHash::decode(&t).ok_or_else(|| format!("{}: not a password hash", hash_path.display()))?),
                Err(_) => None,
            },
        };
        let mut setup_code = None;
        if pw.is_none() && !setup_open {
            let p = data_dir.join("setup-code");
            let code = match std::fs::read_to_string(&p) {
                Ok(c) if c.trim().len() >= 10 => c.trim().to_string(),
                _ => {
                    let c = hex::encode(random_bytes::<6>());
                    write_private(&p, &format!("{c}\n")).map_err(|e| format!("{}: {e}", p.display()))?;
                    c
                }
            };
            eprintln!("xbt-wallet-ui: first run - open the UI and set a password with the setup code {code} (also in {})", p.display());
            setup_code = Some(code);
        }
        Ok(Self { pw: Mutex::new(pw), hash_path, setup_code, sessions: Mutex::new(HashMap::new()), fails: Mutex::new(VecDeque::new()), idle, max })
    }

    pub fn has_password(&self) -> bool {
        self.pw.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    pub fn needs_setup_code(&self) -> bool {
        self.setup_code.is_some()
    }

    fn throttled(&self) -> bool {
        let mut f = self.fails.lock().unwrap_or_else(|p| p.into_inner());
        while f.front().is_some_and(|t| t.elapsed() > Duration::from_secs(60)) {
            f.pop_front();
        }
        f.len() >= FAILS_PER_MIN
    }

    fn fail(&self) {
        self.fails.lock().unwrap_or_else(|p| p.into_inner()).push_back(Instant::now());
    }

    /// First run: set the password (with the setup code unless the setup is open).
    pub fn set_initial(&self, code: &str, pw: &str) -> Result<(), String> {
        if self.throttled() {
            return Err("too many attempts: wait a minute".into());
        }
        let mut g = self.pw.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_some() {
            return Err("a password is already set".into());
        }
        if let Some(c) = &self.setup_code {
            if !ct_eq(code.trim().to_lowercase().as_bytes(), c.as_bytes()) {
                self.fail();
                return Err("wrong setup code".into());
            }
        }
        if pw.chars().count() < MIN_PASSWORD {
            return Err(format!("the password needs at least {MIN_PASSWORD} characters"));
        }
        let h = PwHash::new(pw);
        write_private(&self.hash_path, &h.encode()).map_err(|e| format!("{}: {e}", self.hash_path.display()))?;
        let _ = std::fs::remove_file(self.hash_path.with_file_name("setup-code"));
        *g = Some(h);
        Ok(())
    }

    /// A new session id when the password is right.
    pub fn login(&self, pw: &str) -> Result<String, String> {
        if self.throttled() {
            return Err("too many failed logins: wait a minute".into());
        }
        let ok = self.pw.lock().unwrap_or_else(|p| p.into_inner()).as_ref().is_some_and(|h| h.verify(pw));
        if !ok {
            self.fail();
            return Err("wrong password".into());
        }
        Ok(self.new_session())
    }

    pub fn new_session(&self) -> String {
        let sid = hex::encode(random_bytes::<32>());
        let mut s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        s.retain(|_, v| v.created.elapsed() < self.max && v.last.elapsed() < self.idle);
        if s.len() >= MAX_SESSIONS {
            if let Some(oldest) = s.iter().min_by_key(|(_, v)| v.last).map(|(k, _)| k.clone()) {
                s.remove(&oldest);
            }
        }
        s.insert(sid.clone(), Session { csrf: hex::encode(random_bytes::<32>()), created: Instant::now(), last: Instant::now(), flash: None });
        sid
    }

    /// Run `f` on a live session (touching it), or `None` if it is unknown or expired.
    pub fn with_session<T>(&self, sid: &str, f: impl FnOnce(&mut Session) -> T) -> Option<T> {
        let mut s = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let live = s.get(sid).is_some_and(|v| v.created.elapsed() < self.max && v.last.elapsed() < self.idle);
        if !live {
            s.remove(sid);
            return None;
        }
        let v = s.get_mut(sid)?;
        v.last = Instant::now();
        Some(f(v))
    }

    pub fn logout(&self, sid: &str) {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).remove(sid);
    }

    pub fn check_csrf(&self, sid: &str, token: &str) -> bool {
        self.with_session(sid, |s| ct_eq(s.csrf.as_bytes(), token.as_bytes())).unwrap_or(false)
    }
}
