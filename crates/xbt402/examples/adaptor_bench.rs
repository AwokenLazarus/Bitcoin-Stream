//! Adaptor-signature timings (release build): `cargo run --release -p xbt402 --example adaptor_bench`.
use std::time::Instant;

use xbt402::adaptor::{self, random_secret};
use xbt_primitives::ecdsa;

fn main() {
    let n = 2000;
    let (x, y) = (random_secret(), random_secret());
    let (xp, yp) = (ecdsa::pubkey(&x), adaptor::point_of(&y));
    let z = xbt_primitives::hash::sha256(b"state");
    let t = Instant::now();
    let pres: Vec<_> = (0..n).map(|_| adaptor::presign(&x, &z, &yp).unwrap()).collect();
    let presign = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let t = Instant::now();
    assert!(pres.iter().all(|p| adaptor::preverify(&xp, &z, &yp, p)));
    let preverify = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let t = Instant::now();
    let sigs: Vec<_> = pres.iter().map(|p| adaptor::adapt(p, &y).unwrap()).collect();
    let adapt = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let t = Instant::now();
    assert!(pres.iter().zip(&sigs).all(|(p, s)| adaptor::extract(p, s, &yp) == Some(y)));
    let extract = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("adaptor (µs per op, {n} ops): presign {presign:.1}, preverify {preverify:.1}, adapt {adapt:.1}, extract {extract:.1}");
}
