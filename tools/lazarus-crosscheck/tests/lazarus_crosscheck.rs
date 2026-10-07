//! Cross-check of xbt-primitives' header/PoW code against the pool's own Rust, `lazarus-protocol`
//! (~/Bitcoin/lazarus/protocol, a read-only path dev-dependency of this standalone crate, outside the
//! workspace so a clean checkout never needs it). lazarus-protocol implements the
//! ASIC profile 0 the pool mines; every profile-0 header, random or captured from Knots, must hash
//! the same, and compact targets and merkle roots must agree.
use lazarus_protocol::pow as lz;
use xbt_primitives::header;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.next() as u8;
        }
    }
}

#[test]
fn profile0_pow_hash_matches_lazarus_protocol() {
    let mut r = Rng(0x2545_F491_4F6C_DD1D);
    for i in 0..2_000 {
        let mut b = [0u8; 164];
        r.fill(&mut b);
        b[3] |= 0x80;                       // v2
        b[110] &= !3;                       // ASIC profile 0 (the one lazarus-protocol implements)
        if i % 3 == 0 {
            b[112..128].fill(0);            // no XOR key
        }
        if i % 5 == 0 {
            b[110] &= !header::FLAG_USE_TIME_OFFSET;
        }
        let ours = header::v2_stages(&b).unwrap();
        let theirs = lz::HeaderV2::deserialize(&b);
        assert_eq!(theirs.serialize(), b, "lazarus round trip {i}");
        assert_eq!(ours.block_hash, theirs.pow_hash(), "pow hash {i}");
        assert_eq!(ours.h2, theirs.h2(), "h2 {i}");
        let parsed = header::parse_header(&b).unwrap();
        assert_eq!(parsed.time, theirs.time, "block time {i}");
        assert_eq!(parsed.height, theirs.height as u32);
    }
}

#[test]
fn captured_knots_headers_match_lazarus_protocol() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/blake2b_regtest.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut n = 0;
    for h in v["headers"].as_array().unwrap() {
        let raw = hex::decode(h["header"].as_str().unwrap()).unwrap();
        if raw.len() != 164 || raw[110] & 3 != 0 {
            continue;
        }
        let arr: [u8; 164] = raw.clone().try_into().unwrap();
        assert_eq!(hex::encode(lz::HeaderV2::deserialize(&arr).pow_hash()), h["hash"].as_str().unwrap());
        assert_eq!(header::parse_header(&raw).unwrap().hash_hex(), h["hash"].as_str().unwrap());
        n += 1;
    }
    assert_eq!(n, 5, "the capture has five v2 headers");
}

#[test]
fn compact_targets_match_lazarus_protocol() {
    let mut r = Rng(0x1234_5678_9ABC_DEF1);
    let mut n = 0;
    for _ in 0..5_000 {
        let exp = 3 + (r.next() % 30) as u32;          // 3..=32: the range lazarus-protocol decodes
        let mant = (r.next() as u32) & 0x007F_FFFF;    // non-negative, as Knots requires
        if mant == 0 || (exp == 32 && mant > 0xFFFF) || (exp == 31 && mant > 0xFF_FFFF) {
            continue;
        }
        let bits = exp << 24 | mant;
        let Ok(t) = header::bits_to_target(bits) else { continue };
        let Some(theirs) = lz::bits_to_target(bits) else { continue };
        assert_eq!(t.to_be_bytes::<32>(), theirs, "bits {bits:08x}");
        n += 1;
    }
    assert!(n > 4_000);
}

#[test]
fn merkle_roots_match_lazarus_protocol() {
    let mut r = Rng(99);
    for n in 1..40usize {
        let ids: Vec<[u8; 32]> = (0..n).map(|_| { let mut x = [0u8; 32]; r.fill(&mut x); x }).collect();
        assert_eq!(header::merkle_root(&ids), lz::merkle_root_from_txids(&ids), "{n} txids");
    }
}
