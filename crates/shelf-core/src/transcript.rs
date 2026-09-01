//! Length-prefixed binary transcripts. JSON is not a signature encoding.

/// Domain for enrollment request self-signatures.
pub const DOMAIN_ENROLL_REQUEST: &str = "shelf/enrollment/request/v1";
/// Domain for membership certificate signatures.
pub const DOMAIN_ENROLL_CERT: &str = "shelf/enrollment/cert/v1";
/// Domain for membership snapshot signatures.
pub const DOMAIN_ENROLL_SNAPSHOT: &str = "shelf/enrollment/snapshot/v1";
/// Domain for the two-way enrollment SAS.
pub const DOMAIN_ENROLL_SAS: &str = "shelf/enrollment/sas/v1";
/// Domain / AEAD AAD for hybrid epoch wrap.
pub const DOMAIN_ENROLL_WRAP: &str = "shelf/enrollment/wrap/v1";
/// Domain for first-device genesis certificate request-hash.
pub const DOMAIN_ENROLL_GENESIS: &str = "shelf/enrollment/genesis/v1";
/// Domain / AEAD AAD for root-authorized epoch rotation wraps.
pub const DOMAIN_EPOCH_TRANSITION: &str = "shelf/epoch-transition/v1";

/// Accumulates a canonical transcript.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    /// Start a transcript with a domain label.
    #[must_use]
    pub fn new(domain: &str) -> Self {
        let mut t = Self { buf: Vec::new() };
        t.push_label(domain);
        t
    }

    /// Length-prefixed UTF-8 label (`u8` length, max 255).
    pub fn push_label(&mut self, label: &str) {
        let bytes = label.as_bytes();
        let len = u8::try_from(bytes.len()).expect("transcript label exceeds 255 bytes");
        self.buf.push(len);
        self.buf.extend_from_slice(bytes);
    }

    /// Raw bytes with no length prefix (fixed-size fields).
    pub fn push_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// `u16` big-endian.
    pub fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// `u64` big-endian.
    pub fn push_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Variable bytes: `u32` big-endian length then payload.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).expect("transcript field exceeds u32");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }

    /// One byte.
    pub fn push_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// BLAKE3 of the transcript.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.buf).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_and_fields_are_stable() {
        let mut a = Transcript::new("shelf/test/v1");
        a.push_u16(1);
        a.push_fixed(&[0xab; 32]);
        let mut b = Transcript::new("shelf/test/v1");
        b.push_u16(1);
        b.push_fixed(&[0xab; 32]);
        assert_eq!(a.hash(), b.hash());
        let mut c = Transcript::new("shelf/test/v1");
        c.push_u16(2);
        c.push_fixed(&[0xab; 32]);
        assert_ne!(a.hash(), c.hash());
    }
}
