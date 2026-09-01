//! Scratchpad CRDT wrapper around Yrs.
//!
//! Scratchpads are not [`crate::model::ShelfItem`]s; they are persistent
//! collaborative text documents with their own merge semantics.

use crate::hexutil::define_id32;
use thiserror::Error;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact, Update};

define_id32! {
    /// Opaque scratch pad identifier. Not a plaintext name.
    pub struct ScratchId;
}

/// Derive a stable pad id from a vault-local index key + human name.
///
/// The key is random per vault (not `VaultId`) so a stolen `state.db` cannot
/// dictionary-test pad names from the id alone.
#[must_use]
pub fn scratch_id_for(index_key: &[u8; 32], name: &str) -> ScratchId {
    ScratchId::from_bytes(*blake3::keyed_hash(index_key, name.as_bytes()).as_bytes())
}

/// Failure applying or decoding a Yrs update.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CrdtError {
    /// Update bytes were not a valid Yrs v1 update, or could not be merged.
    #[error("invalid CRDT update")]
    InvalidUpdate,
}

/// Named collaborative text document wrapping a [`yrs::Doc`].
pub struct ScratchPad {
    name: String,
    doc: Doc,
}

impl ScratchPad {
    /// Create an empty pad. `name` is the logical pad id (e.g. `Scratch`).
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            doc: Doc::new(),
        }
    }

    /// Logical pad name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn text_ref(&self) -> yrs::TextRef {
        self.doc.get_or_insert_text(self.name.as_str())
    }

    /// Append `content` to the pad.
    pub fn insert_text(&mut self, content: &str) {
        let text = self.text_ref();
        let mut txn = self.doc.transact_mut();
        text.push(&mut txn, content);
    }

    /// Current plaintext (formatting stripped).
    #[must_use]
    pub fn text(&self) -> String {
        let text = self.text_ref();
        let txn = self.doc.transact();
        text.get_string(&txn)
    }

    /// Encode the full document state as a Yrs v1 update from the empty vector.
    #[must_use]
    pub fn encode_update(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.encode_state_as_update_v1(&StateVector::default())
    }

    /// Encode this replica's Yrs v1 state vector.
    #[must_use]
    pub fn state_vector(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.state_vector().encode_v1()
    }

    /// Encode a Yrs v1 update containing only changes after `sv`.
    ///
    /// If `sv` is not a valid state vector, returns a full [`Self::encode_update`] so
    /// callers never persist an empty or truncated body.
    #[must_use]
    pub fn encode_diff_from(&self, sv: &[u8]) -> Vec<u8> {
        let Ok(decoded) = StateVector::decode_v1(sv) else {
            return self.encode_update();
        };
        let txn = self.doc.transact();
        txn.encode_state_as_update_v1(&decoded)
    }

    /// Merge a Yrs v1 update into this replica.
    pub fn apply_update(&mut self, update: &[u8]) -> Result<(), CrdtError> {
        let decoded = Update::decode_v1(update).map_err(|_| CrdtError::InvalidUpdate)?;
        self.doc
            .transact_mut()
            .apply_update(decoded)
            .map_err(|_| CrdtError::InvalidUpdate)?;
        Ok(())
    }
}

impl std::fmt::Debug for ScratchPad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScratchPad")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_b_applies_a_update() {
        let mut a = ScratchPad::new("Scratch");
        let mut b = ScratchPad::new("Scratch");
        a.insert_text("hello from A");
        b.apply_update(&a.encode_update()).unwrap();
        assert_eq!(a.text(), b.text());
        assert_eq!(a.text(), "hello from A");
    }

    #[test]
    fn divergent_inserts_merge() {
        let mut a = ScratchPad::new("Inbox");
        let mut b = ScratchPad::new("Inbox");
        a.insert_text("alpha");
        b.insert_text("beta");
        let ua = a.encode_update();
        let ub = b.encode_update();
        a.apply_update(&ub).unwrap();
        b.apply_update(&ua).unwrap();
        assert_eq!(a.text(), b.text());
        assert!(a.text().contains("alpha"), "merged {:?}", a.text());
        assert!(a.text().contains("beta"), "merged {:?}", a.text());
    }

    #[test]
    fn invalid_update_is_typed_error() {
        let mut pad = ScratchPad::new("Current");
        let err = pad.apply_update(b"not-a-yrs-update").unwrap_err();
        assert_eq!(err, CrdtError::InvalidUpdate);
    }

    #[test]
    fn second_edit_diff_is_smaller_and_merges() {
        let mut a = ScratchPad::new("Scratch");
        a.insert_text("hello from A");
        let first = a.encode_update();
        let sv = a.state_vector();

        a.insert_text(" and a second insert that should not rewrite the whole doc");
        let full = a.encode_update();
        let diff = a.encode_diff_from(&sv);
        assert!(
            diff.len() < full.len(),
            "diff {} bytes should be smaller than full {} bytes",
            diff.len(),
            full.len()
        );

        let mut b = ScratchPad::new("Scratch");
        b.apply_update(&first).unwrap();
        b.apply_update(&diff).unwrap();
        assert_eq!(a.text(), b.text());
        assert!(a.text().contains("hello from A"));
        assert!(a.text().contains("second insert"));
    }
}
