//! Standard Base64 (RFC 4648) for JSON `bytes` fields.

use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}
