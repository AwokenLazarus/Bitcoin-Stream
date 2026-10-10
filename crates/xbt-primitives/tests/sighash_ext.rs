//! review S1: UnifiedSighash with an annex and a codeseparator position, against vectors from Knots'
//! independent Python implementation (`scripts/gen_unified_sighash_ext.py`).
use xbt_primitives::sighash::{
    unified_sighash, unified_sighash_ext, ScriptType, SpendExt, NO_CODESEP,
};
use xbt_primitives::tx::{Tx, TxOut};

struct Case {
    tx: Tx,
    index: usize,
    hash_type: u8,
    script_type: ScriptType,
    prevouts: Vec<TxOut>,
    leaf: Option<[u8; 32]>,
    annex: Option<Vec<u8>>,
    codesep_pos: u32,
    sighash: String,
}

fn cases() -> Vec<Case> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/unified_sighash_ext.json"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows[0][8], "sighash");
    rows[1..]
        .iter()
        .map(|r| Case {
            tx: Tx::parse_hex(r[0].as_str().unwrap()).unwrap(),
            index: r[1].as_u64().unwrap() as usize,
            hash_type: r[2].as_u64().unwrap() as u8,
            script_type: ScriptType::from_u8(r[3].as_u64().unwrap() as u8).unwrap(),
            prevouts: r[4]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    TxOut::new(
                        o[0].as_i64().unwrap(),
                        hex::decode(o[1].as_str().unwrap()).unwrap(),
                    )
                })
                .collect(),
            leaf: r[5]
                .as_str()
                .map(|h| xbt_primitives::hash::hex32(h).unwrap()),
            annex: r[6].as_str().map(|h| hex::decode(h).unwrap()),
            codesep_pos: r[7].as_u64().unwrap() as u32,
            sighash: r[8].as_str().unwrap().to_string(),
        })
        .collect()
}

#[test]
fn s1_annex_and_codesep_vectors_match_knots() {
    let cs = cases();
    assert_eq!(cs.len(), 60);
    assert!(cs.iter().filter(|c| c.annex.is_some()).count() >= 40);
    assert!(cs.iter().filter(|c| c.codesep_pos != NO_CODESEP).count() >= 20);
    for (n, c) in cs.iter().enumerate() {
        let ext = SpendExt {
            annex: c.annex.as_deref(),
            codesep_pos: c.codesep_pos,
        };
        let got = unified_sighash_ext(
            &c.tx,
            &c.prevouts,
            c.index,
            c.script_type,
            &[],
            c.hash_type,
            c.leaf.as_ref(),
            ext,
        )
        .unwrap();
        assert_eq!(hex::encode(got), c.sighash, "case {n}");
        if c.annex.is_none() && c.codesep_pos == NO_CODESEP {
            let plain = unified_sighash(
                &c.tx,
                &c.prevouts,
                c.index,
                c.script_type,
                &[],
                c.hash_type,
                c.leaf.as_ref(),
            )
            .unwrap();
            assert_eq!(
                hex::encode(plain),
                c.sighash,
                "case {n}: the default is no annex, no codeseparator"
            );
        }
    }
}

#[test]
fn s1_refuses_values_the_script_type_does_not_commit_to() {
    let c = &cases()[0];
    let leaf = [7u8; 32];
    let annex: &[u8] = &[0x50, 1, 2];
    let call = |st, leaf: Option<&[u8; 32]>, ext| {
        unified_sighash_ext(&c.tx, &c.prevouts, c.index, st, &[0x51], 0x21, leaf, ext)
    };
    for st in [ScriptType::Bare, ScriptType::WitnessV0] {
        assert!(
            call(
                st,
                None,
                SpendExt {
                    annex: Some(annex),
                    codesep_pos: NO_CODESEP
                }
            )
            .is_err(),
            "{st:?} has no annex"
        );
        assert!(
            call(
                st,
                None,
                SpendExt {
                    annex: None,
                    codesep_pos: 0
                }
            )
            .is_err(),
            "{st:?}: its script code carries the codeseparator"
        );
        assert!(call(st, None, SpendExt::default()).is_ok());
    }
    assert!(
        call(
            ScriptType::Taproot,
            None,
            SpendExt {
                annex: None,
                codesep_pos: 3
            }
        )
        .is_err(),
        "key path: no codeseparator"
    );
    assert!(
        call(
            ScriptType::Taproot,
            None,
            SpendExt {
                annex: Some(&[0x51, 1]),
                codesep_pos: NO_CODESEP
            }
        )
        .is_err(),
        "no 0x50 tag"
    );
    assert!(call(
        ScriptType::Taproot,
        None,
        SpendExt {
            annex: Some(&[]),
            codesep_pos: NO_CODESEP
        }
    )
    .is_err());
    let with = call(
        ScriptType::Tapscript,
        Some(&leaf),
        SpendExt {
            annex: Some(annex),
            codesep_pos: 2,
        },
    )
    .unwrap();
    let without = call(ScriptType::Tapscript, Some(&leaf), SpendExt::default()).unwrap();
    assert_ne!(with, without, "both are committed to");
}
