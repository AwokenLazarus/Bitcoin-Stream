//! Segwit addresses: bech32 (BIP173, witness v0) and bech32m (BIP350, witness v1+), with the
//! human-readable part fixed per chain.
use crate::error::{Error, Result};
use crate::network::Chain;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2BC8_30A3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let maxv = (1u32 << to) - 1;
    let mut ret = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &v in data {
        if (v as u32) >> from != 0 {
            return Err(Error::BadAddress("value out of range".into()));
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::BadAddress("bad padding".into()));
    }
    Ok(ret)
}

/// The address of a witness output script (`OP_n <program>`) under `hrp`.
pub fn segwit_address(hrp: &str, spk: &[u8]) -> Result<String> {
    let (ver, prog) = witness_program(spk).ok_or_else(|| Error::BadAddress("not a witness output script".into()))?;
    let mut data = vec![ver];
    data.extend(convert_bits(prog, 8, 5, true)?);
    let konst = if ver == 0 { BECH32_CONST } else { BECH32M_CONST };
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let chk = polymod(&values) ^ konst;
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for d in data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((chk >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Ok(s)
}

/// The address of `spk` on `chain`.
pub fn address_for(chain: Chain, spk: &[u8]) -> Result<String> {
    segwit_address(chain.hrp(), spk)
}

/// `(version, program)` of a witness output script.
pub fn witness_program(spk: &[u8]) -> Option<(u8, &[u8])> {
    if spk.len() < 4 || spk.len() > 42 {
        return None;
    }
    let ver = match spk[0] {
        0x00 => 0,
        0x51..=0x60 => spk[0] - 0x50,
        _ => return None,
    };
    let n = spk[1] as usize;
    if n + 2 != spk.len() || !(2..=40).contains(&n) {
        return None;
    }
    Some((ver, &spk[2..]))
}

/// The output script of a segwit address. With `hrp`, an address of another network is refused
/// (a `bcrt1` or `tb1` address on mainnet would pay a script nobody there expects). Witness v0
/// must use bech32 with a 20- or 32-byte program; v1+ must use bech32m.
pub fn address_to_spk(addr: &str, hrp: Option<&str>) -> Result<Vec<u8>> {
    if addr.len() > 90 || (addr.bytes().any(|c| c.is_ascii_uppercase()) && addr.bytes().any(|c| c.is_ascii_lowercase())) {
        return Err(Error::BadAddress("mixed case or too long".into()));
    }
    let addr = addr.to_ascii_lowercase();
    let pos = addr.rfind('1').ok_or_else(|| Error::BadAddress("not a bech32 address".into()))?;
    let (got, rest) = (&addr[..pos], &addr[pos + 1..]);
    if got.is_empty() || rest.len() < 7 || got.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(Error::BadAddress("not a bech32 address".into()));
    }
    let data: Vec<u8> = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or_else(|| Error::BadAddress("not a bech32 address".into()))?;
    let mut values = hrp_expand(got);
    values.extend_from_slice(&data);
    let konst = polymod(&values);
    if let Some(h) = hrp {
        if got != h {
            return Err(Error::BadAddress(format!("address is for hrp {got:?}, this network uses {h:?}")));
        }
    }
    let ver = data[0];
    if ver > 16 {
        return Err(Error::BadAddress("witness version above 16".into()));
    }
    let want = if ver == 0 { BECH32_CONST } else { BECH32M_CONST };
    if konst != want {
        return Err(Error::BadAddress("bad bech32 checksum".into()));
    }
    let prog = convert_bits(&data[1..data.len() - 6], 5, 8, false)?;
    if !(2..=40).contains(&prog.len()) || (ver == 0 && prog.len() != 20 && prog.len() != 32) {
        return Err(Error::BadAddress("bad witness program length".into()));
    }
    let mut spk = vec![if ver == 0 { 0 } else { 0x50 + ver }, prog.len() as u8];
    spk.extend_from_slice(&prog);
    Ok(spk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip173_and_bip350_vectors() {
        let cases = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
             "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
             "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ];
        for (addr, spk) in cases {
            let got = address_to_spk(addr, Some("bc")).unwrap();
            assert_eq!(hex::encode(&got), spk);
            assert_eq!(segwit_address("bc", &got).unwrap(), addr.to_ascii_lowercase());
        }
        // v0 with a bech32m checksum and v1 with bech32 are both invalid (BIP350)
        assert!(address_to_spk("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", None).is_err());
        assert!(address_to_spk("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", None).is_err());
        assert!(address_to_spk("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", Some("bc")).is_err());
    }
}
