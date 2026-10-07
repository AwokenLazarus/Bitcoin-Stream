//! HeaderChain on synthetic regtest v2 headers (mined here: regtest's powLimit passes about every
//! other nonce): extension, most-work reorgs, ties, and every refusal rule.
use xbt_primitives::header::{self, parse_header, HeaderChain, V2_FLAG};

const REGTEST_BITS: u32 = 0x207F_FFFF;
const T0: u32 = 1_800_000_000;

fn mine(prev_display: [u8; 32], height: u32, time: u32, bits: u32, salt: u8, want_valid: bool) -> Vec<u8> {
    let rules = header::ChainRules::regtest();
    for nonce in 0u32.. {
        let mut b = Vec::with_capacity(164);
        b.extend((0x2000_0000u32 | V2_FLAG).to_le_bytes());
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
        b.extend([0u8, 0u8]);
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

fn chain_at(cp: &[u8]) -> HeaderChain {
    let h = parse_header(cp).unwrap();
    let mut c = HeaderChain::new("regtest", (h.height, &h.hash_hex()), None, Box::new(|| (T0 + 10_000) as u64)).unwrap();
    c.set_checkpoint(cp).unwrap();
    c
}

fn checkpoint() -> Vec<u8> {
    mine([7; 32], 101, T0, REGTEST_BITS, 0, true)
}

#[test]
fn extends_and_reorgs_to_most_work() {
    let cp = checkpoint();
    let mut c = chain_at(&cp);
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
    let cp = checkpoint();
    let base = branch(&cp, 12, T0 + 1, 1);
    let mut c = chain_at(&cp);
    c.connect(101, &base).unwrap();
    let tip = parse_header(base.last().unwrap()).unwrap();
    let t = tip.time + 1;
    // does not link
    assert!(c.connect(113, &[mine([9; 32], 114, t, REGTEST_BITS, 5, true)]).is_err());
    // wrong committed height
    assert!(c.connect(113, &[mine(tip.hash, 999, t, REGTEST_BITS, 5, true)]).is_err());
    // fails its own target
    assert!(c.connect(113, &[mine(tip.hash, 114, t, REGTEST_BITS, 5, false)]).is_err());
    // regtest allows the parent's bits or powLimit, nothing else
    assert!(c.connect(113, &[mine(tip.hash, 114, t, 0x207F_FFFE, 5, true)]).is_err());
    // time not above the median of the last 11
    assert!(c.connect(113, &[mine(tip.hash, 114, tip.time - 6, REGTEST_BITS, 5, true)]).is_err());
    // more than 2 h in the future (clock = T0 + 10000)
    assert!(c.connect(113, &[mine(tip.hash, 114, T0 + 10_000 + 7_201, REGTEST_BITS, 5, true)]).is_err());
    // a v1 header above the checkpoint
    assert!(c.connect(113, &[vec![0u8; 80]]).is_err());
    // the checkpoint must hash to the pinned value
    let other = mine([8; 32], 101, T0, REGTEST_BITS, 9, true);
    let mut fresh = HeaderChain::new("regtest", (101, &parse_header(&cp).unwrap().hash_hex()), None, Box::new(|| 0)).unwrap();
    assert!(fresh.set_checkpoint(&other).is_err());
    // and a good one still connects
    assert!(c.connect(113, &[mine(tip.hash, 114, t, REGTEST_BITS, 5, true)]).unwrap().adopted);
}

#[test]
fn persists_and_reloads() {
    let dir = std::env::temp_dir().join(format!("xbt-hc-{}", std::process::id()));
    let path = dir.join("headers.bin");
    let cp = checkpoint();
    let hx = parse_header(&cp).unwrap().hash_hex();
    {
        let mut c = HeaderChain::new("regtest", (101, &hx), Some(&path), Box::new(|| (T0 + 10_000) as u64)).unwrap();
        c.set_checkpoint(&cp).unwrap();
        c.connect(101, &branch(&cp, 5, T0 + 1, 1)).unwrap();
    }
    let c = HeaderChain::new("regtest", (101, &hx), Some(&path), Box::new(|| (T0 + 10_000) as u64)).unwrap();
    assert_eq!(c.tip_height().unwrap(), 106);
    // another checkpoint: the file is ignored
    let c2 = HeaderChain::new("regtest", (101, &"00".repeat(32)), Some(&path), Box::new(|| 0)).unwrap();
    assert!(!c2.ready());
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
        let _ = header::split_headers(&b);
        let _ = header::parse_block(&b);
        let _ = xbt_primitives::address::address_to_spk(&String::from_utf8_lossy(&b), None);
        if b.len() >= 4 {
            b[3] |= 0x80;
            let _ = header::split_headers(&b);
        }
    }
}
