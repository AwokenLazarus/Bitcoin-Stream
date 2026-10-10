//! HeaderChain on synthetic regtest v2 headers (mined here: regtest's powLimit passes about every
//! other nonce): extension, most-work reorgs, ties, every refusal rule, and the review E3 rules
//! (bad-flags-highbits, bad-version, the median from the first header, pins, min-difficulty walk).
use xbt_primitives::header::{self, parse_header, v1_hash, ChainRules, HeaderChain, V2_FLAG};

const REGTEST_BITS: u32 = 0x207F_FFFF;
const T0: u32 = 1_800_000_000;
const VERSION: u32 = 0x2000_0000;

#[allow(clippy::too_many_arguments)]
fn mine_with(prev_display: [u8; 32], height: u32, time: u32, bits: u32, salt: u8, want_valid: bool, version: u32, flags: u8) -> Vec<u8> {
    let rules = header::ChainRules::regtest();
    for nonce in 0u32.. {
        let mut b = Vec::with_capacity(164);
        b.extend((version | V2_FLAG).to_le_bytes());
        let mut prev = prev_display;
        prev.reverse();
        b.extend(prev);
        b.extend([salt; 32]);
        b.extend(time.to_le_bytes());
        b.extend(bits.to_le_bytes());
        b.extend(nonce.to_le_bytes());
        b.extend([0u8; 8]);
        b.extend([0u8; 16]);
        b.extend(0u32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend([flags, 0u8]);
        b.extend([0u8; 16]);
        b.extend(height.to_le_bytes());
        b.extend([0u8; 32]);
        let h = parse_header(&b).unwrap();
        if header::check_pow(&h, &rules).is_ok() == want_valid {
            return b;
        }
    }
    unreachable!()
}

fn mine(prev_display: [u8; 32], height: u32, time: u32, bits: u32, salt: u8, want_valid: bool) -> Vec<u8> {
    mine_with(prev_display, height, time, bits, salt, want_valid, VERSION, 0)
}

/// An 80-byte v1 header (below the BLAKE2b switch: only its link and time matter).
fn v1(prev_display: [u8; 32], time: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend(VERSION.to_le_bytes());
    let mut prev = prev_display;
    prev.reverse();
    b.extend(prev);
    b.extend([0x5Au8; 32]);
    b.extend(time.to_le_bytes());
    b.extend(REGTEST_BITS.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b
}

/// The 10 v1 headers below the checkpoint (heights 91..=100), times `t, t+1, ...`.
fn priors(t: u32) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![];
    let mut prev = [3u8; 32];
    for i in 0..10 {
        let raw = v1(prev, t + i);
        prev = v1_hash(&raw).unwrap();
        out.push(raw);
    }
    out
}

fn tip_hash(prior: &[Vec<u8>]) -> [u8; 32] {
    v1_hash(prior.last().unwrap()).unwrap()
}

/// `n` headers on top of `parent`, one second apart after `t`.
fn branch(parent: &[u8], n: u32, t: u32, salt: u8) -> Vec<Vec<u8>> {
    let mut out = vec![];
    let mut p = parse_header(parent).unwrap();
    for i in 0..n {
        let raw = mine(p.hash, p.height + 1, t + i, REGTEST_BITS, salt, true);
        p = parse_header(&raw).unwrap();
        out.push(raw);
    }
    out
}

fn chain_at(cp: &[u8], prior: &[Vec<u8>]) -> HeaderChain {
    chain_with(cp, prior, ChainRules::regtest())
}

fn chain_with(cp: &[u8], prior: &[Vec<u8>], rules: ChainRules) -> HeaderChain {
    let h = parse_header(cp).unwrap();
    let mut c = HeaderChain::new("regtest", (h.height, &h.hash_hex()), None, || (T0 + 10_000) as u64).unwrap();
    c.rules = rules;
    c.set_checkpoint(cp, prior).unwrap();
    c
}

/// (the headers below the checkpoint, the checkpoint at 101)
fn base() -> (Vec<Vec<u8>>, Vec<u8>) {
    let p = priors(T0 - 100);
    let cp = mine(tip_hash(&p), 101, T0, REGTEST_BITS, 0, true);
    (p, cp)
}

#[test]
fn extends_and_reorgs_to_most_work() {
    let (p, cp) = base();
    let mut c = chain_at(&cp, &p);
    let main = branch(&cp, 20, T0 + 1, 1);
    let r = c.connect(101, &main).unwrap();
    assert!(r.adopted && r.tip == 121 && r.reorg == 0);
    // a competing branch from 111: 10 headers = equal work to our 10 above it -> first seen wins
    let fork_base = &main[9];
    let tie = branch(fork_base, 10, T0 + 100, 2);
    let r = c.connect(111, &tie).unwrap();
    assert!(!r.adopted && r.tip == 121);
    // 11 headers: more work -> adopted, 10 of ours replaced
    let more = branch(fork_base, 11, T0 + 100, 3);
    let r = c.connect(111, &more).unwrap();
    assert!(r.adopted && r.tip == 122 && r.reorg == 10);
    assert_eq!(c.tip().unwrap().raw, more[10]);
    assert_eq!(c.height_of(&parse_header(&more[0]).unwrap().hash), Some(112));
    assert!(c.connect(200, &more).is_err(), "no header of ours at 200");
}

#[test]
fn refuses_bad_headers() {
    let (p, cp) = base();
    let base = branch(&cp, 12, T0 + 1, 1);
    let mut c = chain_at(&cp, &p);
    c.connect(101, &base).unwrap();
    let tip = parse_header(base.last().unwrap()).unwrap();
    let t = tip.time + 1;
    // does not link
    assert!(c.connect(113, &[mine([9; 32], 114, t, REGTEST_BITS, 5, true)]).is_err());
    // wrong committed height
    assert!(c.connect(113, &[mine(tip.hash, 999, t, REGTEST_BITS, 5, true)]).is_err());
    // fails its own target
    assert!(c.connect(113, &[mine(tip.hash, 114, t, REGTEST_BITS, 5, false)]).is_err());
    // regtest is powLimit throughout
    assert!(c.connect(113, &[mine(tip.hash, 114, t, 0x207F_FFFE, 5, true)]).is_err());
    // time not above the median of the last 11
    assert!(c.connect(113, &[mine(tip.hash, 114, tip.time - 6, REGTEST_BITS, 5, true)]).is_err());
    // more than 2 h in the future (clock = T0 + 10000)
    assert!(c.connect(113, &[mine(tip.hash, 114, T0 + 10_000 + 7_201, REGTEST_BITS, 5, true)]).is_err());
    // a v1 header above the checkpoint
    assert!(c.connect(113, &[vec![0u8; 80]]).is_err());
    // the checkpoint must hash to the pinned value
    let other = mine(tip_hash(&p), 101, T0, REGTEST_BITS, 9, true);
    let mut fresh = HeaderChain::new("regtest", (101, &parse_header(&cp).unwrap().hash_hex()), None, || 0).unwrap();
    assert!(fresh.set_checkpoint(&other, &p).is_err());
    // and a good one still connects
    assert!(c.connect(113, &[mine(tip.hash, 114, t, REGTEST_BITS, 5, true)]).unwrap().adopted);
}

/// review E3: Knots refuses a v2 header with either of the top two flag bits set
/// (bad-flags-highbits, validation.cpp:4431) or a version below 4 (bad-version, 4757-4762).
#[test]
fn e3_flags_highbits_and_version() {
    let (p, cp) = base();
    let mut c = chain_at(&cp, &p);
    let h = parse_header(&cp).unwrap();
    for flags in [0x40u8, 0x80, 0xC0] {
        let bad = mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, true, VERSION, flags);
        let e = c.connect(101, &[bad]).unwrap_err().to_string();
        assert!(e.contains("bad-flags-highbits"), "{e}");
    }
    for version in [0u32, 1, 2, 3] {
        let bad = mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, true, version, 0);
        let e = c.connect(101, &[bad]).unwrap_err().to_string();
        assert!(e.contains("bad-version"), "{e}");
    }
    // the low flag bits (the ASIC profile, the time offset) and version 4 are fine
    let ok = mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, true, 4, 0x01);
    assert!(c.connect(101, &[ok]).unwrap().adopted);
}

/// review E3: the median-time rule holds from the first header above the checkpoint, because the
/// 10 headers below it are part of the chain (on main, the first 10 skipped it).
#[test]
fn e3_median_time_from_the_first_header() {
    // the headers below the checkpoint are later than the checkpoint's own time
    let p = priors(T0 + 1_000);
    let cp = mine(tip_hash(&p), 101, T0 + 1_010, REGTEST_BITS, 0, true);
    let mut c = chain_at(&cp, &p);
    let h = parse_header(&cp).unwrap();
    // the median of 91..=101 is T0 + 1005: a child at T0 + 500 is refused
    let early = mine(h.hash, 102, T0 + 500, REGTEST_BITS, 1, true);
    let e = c.connect(101, &[early]).unwrap_err().to_string();
    assert!(e.contains("not above the median"), "{e}");
    assert!(c.connect(101, &[mine(h.hash, 102, T0 + 1_006, REGTEST_BITS, 1, true)]).unwrap().adopted);
    // the headers below the checkpoint must be its ancestors, all of them
    let mut fresh = HeaderChain::new("regtest", (101, &h.hash_hex()), None, || 0).unwrap();
    assert!(fresh.set_checkpoint(&cp, &p[1..]).is_err(), "nine instead of ten");
    let mut swapped = p.clone();
    swapped.swap(3, 4);
    assert!(fresh.set_checkpoint(&cp, &swapped).is_err(), "not hash-linked");
    assert!(fresh.set_checkpoint(&cp, &priors(T0)).is_err(), "another chain's headers");
    fresh.set_checkpoint(&cp, &p).unwrap();
}

/// review E2/E3: a pinned height takes only the pinned hash (Knots checkpoint-mismatch), so a branch
/// forking below a pin can never pass it.
#[test]
fn pinned_heights_refuse_any_other_block() {
    let (p, cp) = base();
    let honest = branch(&cp, 10, T0 + 1, 1);
    let pin = parse_header(&honest[4]).unwrap(); // height 106
    let mut rules = ChainRules::regtest();
    rules.pins = vec![(106, pin.hash)];
    let mut c = chain_with(&cp, &p, rules);
    c.connect(101, &honest[..2]).unwrap();
    // a longer fork from 103 has more work but another block at 106
    let fork = branch(&honest[1], 20, T0 + 50, 2);
    let e = c.connect(103, &fork).unwrap_err().to_string();
    assert!(e.contains("checkpoint-mismatch"), "{e}");
    assert!(c.connect(103, &honest[2..]).unwrap().adopted);
    // above the pin, most work decides as before
    let fork = branch(&honest[6], 10, T0 + 50, 3);
    assert!(c.connect(108, &fork).unwrap().adopted);
    // mainnet ships Knots' assumevalid block
    assert_eq!(ChainRules::main().pins, vec![(964_264, xbt_primitives::hash::hex32(header::MAINNET_PINS[0].1).unwrap())]);
}

/// review E3: Knots' min-difficulty rule (pow.cpp:42-56): powLimit after a 20-minute gap, else the
/// bits of the last block that was not a min-difficulty one. Main allowed {parent, powLimit}.
#[test]
fn e3_min_difficulty_walk_back() {
    let harder = 0x207F_FFFEu32;
    let p = priors(T0 - 100);
    let cp = mine(tip_hash(&p), 101, T0, harder, 0, true);
    let mut c = chain_at(&cp, &p);
    let h = parse_header(&cp).unwrap();
    // within 20 minutes of a non-min-difficulty parent: its bits, not powLimit
    let e = c.connect(101, &[mine(h.hash, 102, T0 + 600, REGTEST_BITS, 1, true)]).unwrap_err().to_string();
    assert!(e.contains("207ffffe"), "{e}");
    // after a gap of more than 20 minutes: powLimit only
    let gap = T0 + 1_201;
    assert!(c.connect(101, &[mine(h.hash, 102, gap, harder, 1, true)]).is_err());
    let m1 = mine(h.hash, 102, gap, REGTEST_BITS, 1, true);
    c.connect(101, std::slice::from_ref(&m1)).unwrap();
    // after a min-difficulty block, quickly again: the walk back finds the checkpoint's bits
    let m1h = parse_header(&m1).unwrap();
    assert!(c.connect(102, &[mine(m1h.hash, 103, gap + 1, REGTEST_BITS, 2, true)]).is_err());
    assert!(c.connect(102, &[mine(m1h.hash, 103, gap + 1, harder, 2, true)]).unwrap().adopted);
}

/// Testnet3, testnet4 (BIP94) and signet have no header rules here: a chain refuses to start.
#[test]
fn unsupported_test_networks_fail_closed() {
    for chain in ["testnet4", "test", "signet", "nochain"] {
        assert!(HeaderChain::new(chain, (150_308, &"00".repeat(32)), None, || 0).is_err(), "{chain}");
    }
}

/// A branch grows chunk by chunk and keeps the valid prefix when a chunk turns bad.
#[test]
fn a_branch_validates_as_it_grows() {
    let (p, cp) = base();
    let mut c = chain_at(&cp, &p);
    let good = branch(&cp, 6, T0 + 1, 1);
    let mut b = c.branch(101).unwrap();
    b.extend(&good[..3]).unwrap();
    let mut bad = good[3].clone();
    bad[40] ^= 1; // another merkle root: another hash, the child no longer links
    let e = b.extend(&[bad, good[4].clone()]).unwrap_err().to_string();
    assert!(!e.is_empty());
    assert_eq!((b.len(), b.tip_height()), (3, 104));
    assert!(c.adopt(b).unwrap().adopted);
    assert_eq!(c.tip_height().unwrap(), 104);
    // a branch from a fork point that is no longer ours is not applied
    let mut stale = c.branch(104).unwrap();
    let mut b2 = c.branch(103).unwrap();
    b2.extend(&branch(&good[1], 3, T0 + 20, 2)).unwrap();
    assert!(c.adopt(b2).unwrap().adopted);
    stale.extend(&good[3..]).unwrap();
    assert!(!c.adopt(stale).unwrap().adopted, "its fork point 104 was replaced");
}

/// Real mainnet: the 10 v1 headers below 961640 link to it, and 961641..=961700 pass every rule.
#[test]
fn mainnet_checkpoint_with_its_real_priors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/mainnet_headers_961630.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(v["start"], 961_630);
    let raws: Vec<Vec<u8>> = v["headers"].as_array().unwrap().iter().map(|h| hex::decode(h.as_str().unwrap()).unwrap()).collect();
    let mut c = HeaderChain::with_system_clock("main", (header::MAINNET_CHECKPOINT.0, header::MAINNET_CHECKPOINT.1), None).unwrap();
    assert_eq!(c.prior_needed(), 10);
    assert!(c.set_checkpoint(&raws[10], &raws[1..10]).is_err(), "nine headers below");
    c.set_checkpoint(&raws[10], &raws[..10]).unwrap();
    let r = c.connect(961_640, &raws[11..]).unwrap();
    assert!(r.adopted && r.tip == 961_700, "{r:?}");
    // the same headers with a high flag bit set in one of them: refused from there on
    let mut bad = raws[11..].to_vec();
    bad[5][110] |= 0x80;
    let mut c2 = HeaderChain::with_system_clock("main", (header::MAINNET_CHECKPOINT.0, header::MAINNET_CHECKPOINT.1), None).unwrap();
    c2.set_checkpoint(&raws[10], &raws[..10]).unwrap();
    assert!(c2.connect(961_640, &bad).is_err());
    assert_eq!(c2.tip_height().unwrap(), 961_640, "connect is all or nothing");
}

#[test]
fn persists_and_reloads() {
    let dir = std::env::temp_dir().join(format!("xbt-hc-{}", std::process::id()));
    let path = dir.join("headers.bin");
    let (p, cp) = base();
    let hx = parse_header(&cp).unwrap().hash_hex();
    {
        let mut c = HeaderChain::new("regtest", (101, &hx), Some(&path), || (T0 + 10_000) as u64).unwrap();
        c.set_checkpoint(&cp, &p).unwrap();
        c.connect(101, &branch(&cp, 5, T0 + 1, 1)).unwrap();
    }
    let c = HeaderChain::new("regtest", (101, &hx), Some(&path), || (T0 + 10_000) as u64).unwrap();
    assert_eq!(c.tip_height().unwrap(), 106);
    // another checkpoint: the file is ignored
    let c2 = HeaderChain::new("regtest", (101, &"00".repeat(32)), Some(&path), || 0).unwrap();
    assert!(!c2.ready());
    // a store written before the headers below the checkpoint were kept: ignored, fetched again
    let meta = path.with_extension("json");
    let m = std::fs::read_to_string(&meta).unwrap();
    std::fs::write(&meta, m.replace("\"prior\": 10, ", "")).unwrap();
    let c3 = HeaderChain::new("regtest", (101, &hx), Some(&path), || (T0 + 10_000) as u64).unwrap();
    assert!(!c3.ready());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn hostile_bytes_never_panic() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for len in 0..400usize {
        let mut b = vec![0u8; len % 200];
        for byte in b.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = x as u8;
        }
        let _ = xbt_primitives::tx::Tx::parse(&b);
        let _ = header::parse_header(&b);
        let _ = header::parse_prior(&b, 100);
        let _ = header::split_headers(&b);
        let _ = header::parse_block(&b);
        let _ = xbt_primitives::address::address_to_spk(&String::from_utf8_lossy(&b), None);
        if b.len() >= 4 {
            b[3] |= 0x80;
            let _ = header::split_headers(&b);
        }
    }
}
