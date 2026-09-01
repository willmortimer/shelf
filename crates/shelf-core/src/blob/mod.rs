//! Large-file manifests and chunk identifiers.

use serde::{Deserialize, Serialize};

use crate::hexutil::define_id32;

/// Default plaintext chunk size: 4 MiB.
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

define_id32! {
    /// Opaque chunk identifier. Not a raw plaintext hash.
    pub struct ChunkId;
}

/// Content manifest for a chunked file object.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileManifest {
    /// Logical filename presented to the user.
    pub filename: String,
    /// MIME type.
    pub mime: String,
    /// Total plaintext size in bytes.
    pub size: u64,
    /// Ordered opaque chunk ids.
    pub chunk_ids: Vec<ChunkId>,
}

impl FileManifest {
    /// Construct a manifest. Chunk size used when splitting is [`DEFAULT_CHUNK_SIZE`].
    #[must_use]
    pub fn new(
        filename: impl Into<String>,
        mime: impl Into<String>,
        size: u64,
        chunk_ids: Vec<ChunkId>,
    ) -> Self {
        Self {
            filename: filename.into(),
            mime: mime.into(),
            size,
            chunk_ids,
        }
    }

    /// Suggested number of chunks for `size` using [`DEFAULT_CHUNK_SIZE`].
    #[must_use]
    pub fn suggested_chunk_count(size: u64) -> u64 {
        size.div_ceil(DEFAULT_CHUNK_SIZE).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_chunk_size_is_4_mib() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_CHUNK_SIZE, 4_194_304);
    }

    #[test]
    fn manifest_holds_chunk_ids() {
        let id = ChunkId::from_bytes([0x22; 32]);
        let manifest = FileManifest::new("notes.bin", "application/octet-stream", 12, vec![id]);
        assert_eq!(manifest.chunk_ids, vec![id]);
        assert_eq!(FileManifest::suggested_chunk_count(0), 1);
        assert_eq!(
            FileManifest::suggested_chunk_count(DEFAULT_CHUNK_SIZE + 1),
            2
        );
    }
}
