//! `xbt-init`: make a data dir match docs/CONTAINER.md before the services start (AGP-040).
//!
//!   xbt-init [init] [--data DIR] [--components signer,witness,mcp,ui]   fix owners and modes, provision
//!                                                                      secrets; prints a JSON report
//!   xbt-init check  [--data DIR] [--components ...]                    report only; exit 1 on a problem
//!
//! `--data` defaults to `XBT_DATA_DIR` (the images set `/data`); `--components` to `XBT_INIT_COMPONENTS`,
//! else signer,witness,mcp,ui. Secrets to provision come from `XBT_INIT_*` (see `xbt_svc::layout`).
//! Runs as root in the `xbt-init` image, with only CHOWN, FOWNER and DAC_OVERRIDE and no network: the
//! Umbrel app's init service and the StartOS package's oneshot.
fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: xbt-init [init|check] [--data DIR] [--components signer,witness,mcp,ui,hub]");
        return;
    }
    let root = arg(&args, "--data").or_else(|| xbt_svc::env("XBT_DATA_DIR")).unwrap_or_else(|| "/data".into());
    let names: Vec<String> = arg(&args, "--components")
        .or_else(|| xbt_svc::env("XBT_INIT_COMPONENTS"))
        .unwrap_or_else(|| "signer,witness,mcp,ui".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let root = std::path::PathBuf::from(root);
    let cmd = args.first().map(String::as_str).filter(|a| !a.starts_with("--")).unwrap_or("init");
    let (out, code) = match cmd {
        "check" => {
            let v = xbt_svc::layout::check(&root, &names);
            let ok = v["ok"] == true;
            (v, if ok { 0 } else { 1 })
        }
        "init" => match xbt_svc::layout::Provision::from_env().and_then(|p| xbt_svc::layout::init(&root, &names, &p)) {
            Ok(v) => {
                let c = xbt_svc::layout::check(&root, &names);
                let ok = c["ok"] == true;
                let mut v = v;
                v["check"] = c;
                v["ok"] = serde_json::Value::Bool(ok);
                (v, if ok { 0 } else { 1 })
            }
            Err(e) => (serde_json::json!({"ok": false, "error": e}), 1),
        },
        o => {
            eprintln!("xbt-init: unknown command {o} (try --help)");
            std::process::exit(2);
        }
    };
    println!("{out}");
    std::process::exit(code);
}

#[cfg(not(unix))]
fn main() {
    let _ = arg(&[], "");
    eprintln!("xbt-init: Unix only");
    std::process::exit(2);
}
