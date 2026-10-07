//! Prints the conformance table and exits 0 only when every vector is byte-identical.
//! `xbt-conformance [VECTORS_DIR]` (default: the workspace's vectors/).
fn main() {
    let dir = std::env::args().nth(1).map(std::path::PathBuf::from).unwrap_or_else(xbt402_interop::vectors_dir);
    let groups = xbt402_interop::conformance::run_all(&dir);
    let (mut n, mut t) = (0, 0);
    println!("{:<40} {:>9}  source", "group", "result");
    for g in &groups {
        println!("{:<40} {:>4}/{:<4}  {}", g.name, g.passed, g.total, g.source);
        for f in &g.failures {
            println!("    FAIL {f}");
        }
        n += g.passed;
        t += g.total;
    }
    let ok = groups.iter().all(|g| g.ok());
    println!("{}: {n}/{t} vectors byte-identical", if ok { "OK" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}
