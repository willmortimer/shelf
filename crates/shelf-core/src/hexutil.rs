//! Hex encode/decode for opaque 32-byte identifiers.
//!
//! IDs are random and must not be confused with raw content hashes; hex is only
//! a display/serde form.

use serde::{Deserialize, Deserializer, Serializer};

/// Lowercase hex encoding of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn from_digit(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex digit"),
    }
}

/// Decode a 64-character hex string into 32 bytes.
pub(crate) fn decode_32(s: &str) -> Result<[u8; 32], &'static str> {
    if s.len() != 64 {
        return Err("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = from_digit(bytes[i * 2])?;
        let lo = from_digit(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a 128-character hex string into 64 bytes.
pub(crate) fn decode_64(s: &str) -> Result<[u8; 64], &'static str> {
    if s.len() != 128 {
        return Err("expected 128 hex characters");
    }
    let mut out = [0u8; 64];
    let bytes = s.as_bytes();
    for i in 0..64 {
        let hi = from_digit(bytes[i * 2])?;
        let lo = from_digit(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

pub(crate) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode(bytes))
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    decode_32(&s).map_err(serde::de::Error::custom)
}

pub(crate) mod hex64 {
    use super::{decode_64, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        decode_64(&s).map_err(serde::de::Error::custom)
    }
}

/// 32-byte opaque identifier with hex Display/Debug and serde.
macro_rules! define_id32 {
    ($(#[$meta:meta])* $vis:vis struct $name:ident;) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        $vis struct $name(#[serde(with = "crate::hexutil")] [u8; 32]);

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Generate a fresh random identifier. This is not a content hash.
            ///
            /// [`Default`] is the same: random, never the all-zero id.
            #[must_use]
            pub fn new() -> Self {
                Self(rand::random())
            }

            /// Wrap an existing 32-byte value.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&crate::hexutil::encode(&self.0))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("{}", self))
                    .finish()
            }
        }
    };
}

pub(crate) use define_id32;
