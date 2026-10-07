//! Bitcoin's compact-size integers and a bounds-checked byte reader.
use crate::error::{Error, Result};

pub fn varint(n: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    write_varint(&mut v, n);
    v
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// `varint(len(b)) || b`.
pub fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

pub fn varbytes(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b.len() + 9);
    write_varbytes(&mut v, b);
    v
}

/// A cursor over untrusted bytes: every read is bounds-checked.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated { need: n - self.remaining() });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn peek_u8(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(Error::Truncated { need: 1 })
    }

    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn i32_le(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    pub fn i64_le(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub fn varint(&mut self) -> Result<u64> {
        Ok(match self.u8()? {
            0xFD => u16::from_le_bytes(self.array()?) as u64,
            0xFE => u32::from_le_bytes(self.array()?) as u64,
            0xFF => u64::from_le_bytes(self.array()?),
            n => n as u64,
        })
    }

    /// A length prefix that must fit in what is left (so no allocation is sized by an attacker).
    pub fn len_prefix(&mut self) -> Result<usize> {
        let n = self.varint()?;
        if n > self.remaining() as u64 {
            return Err(Error::Truncated { need: (n - self.remaining() as u64).min(usize::MAX as u64) as usize });
        }
        Ok(n as usize)
    }

    pub fn varbytes(&mut self) -> Result<&'a [u8]> {
        let n = self.len_prefix()?;
        self.take(n)
    }

    pub fn finish(&self) -> Result<()> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(Error::Trailing(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for n in [0u64, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX] {
            let v = varint(n);
            let mut r = Reader::new(&v);
            assert_eq!(r.varint().unwrap(), n);
            r.finish().unwrap();
        }
    }

    #[test]
    fn truncated_is_an_error() {
        let mut r = Reader::new(&[0xFE, 1, 2]);
        assert!(r.varint().is_err());
        let mut r = Reader::new(&[0x05, 1]);
        assert!(r.varbytes().is_err());
    }
}
