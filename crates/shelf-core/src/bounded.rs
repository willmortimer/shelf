//! Byte-at-a-time newline framing with a hard size cap.

use crate::MAX_FRAME_BYTES;

/// Frame exceeded [`MAX_FRAME_BYTES`] before a newline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTooLarge;

/// Incremental bounded line reader. Stops before allocating past the cap.
#[derive(Clone, Debug, Default)]
pub struct BoundedLine {
    buf: Vec<u8>,
}

impl BoundedLine {
    /// Empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Push one byte. `Some` when a newline completes a frame (newline included).
    pub fn push(&mut self, byte: u8) -> Result<Option<Vec<u8>>, FrameTooLarge> {
        if self.buf.len() >= MAX_FRAME_BYTES {
            return Err(FrameTooLarge);
        }
        self.buf.push(byte);
        if byte == b'\n' {
            Ok(Some(std::mem::take(&mut self.buf)))
        } else {
            Ok(None)
        }
    }
}
