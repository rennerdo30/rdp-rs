//! The history buffer shared by every bulk decompressor (MS-RDPBCGR 3.1.8.1).
//!
//! The buffer starts zero-filled and is "immediately regarded as valid";
//! decompressed bytes are written at HistoryOffset (`pos`), which only moves
//! forward until a flag resets it. Every write and copy is bounds-checked, so
//! the history size is also the hard cap on one packet's output.

use crate::error::{Result, proto};

pub(crate) struct History {
    buf: Vec<u8>,
    pos: usize,
}

impl History {
    pub fn new(size: usize) -> Self {
        Self {
            buf: vec![0; size],
            pos: 0,
        }
    }

    /// Refills the buffer with zeros and resets HistoryOffset (PACKET_FLUSHED).
    pub fn reset(&mut self) {
        self.buf.fill(0);
        self.pos = 0;
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Moves HistoryOffset back to the start without clearing (PACKET_AT_FRONT).
    pub fn rewind(&mut self) {
        self.pos = 0;
    }

    /// Bytes written since `start`.
    pub fn since(&self, start: usize) -> &[u8] {
        &self.buf[start.min(self.pos)..self.pos]
    }

    fn room(&self, n: usize) -> Result<()> {
        if n > self.buf.len() - self.pos {
            return proto(format!(
                "decompressed data overflows the {}-byte history at offset {}",
                self.buf.len(),
                self.pos
            ));
        }
        Ok(())
    }

    pub fn push(&mut self, b: u8) -> Result<()> {
        self.room(1)?;
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }

    pub fn extend(&mut self, data: &[u8]) -> Result<()> {
        self.room(data.len())?;
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Replicating copy of `len` bytes from `distance` bytes back
    /// (MS-RDPBCGR 3.1.8.2): source and destination may overlap, so a short
    /// distance repeats a pattern.
    pub fn copy_back(&mut self, distance: usize, len: usize) -> Result<()> {
        if distance == 0 || distance > self.pos {
            return proto(format!(
                "copy-offset {distance} outside the history at offset {}",
                self.pos
            ));
        }
        self.copy_from(self.pos - distance, len)
    }

    /// Replicating copy of `len` bytes from the absolute offset `src`.
    pub fn copy_from(&mut self, src: usize, len: usize) -> Result<()> {
        self.room(len)?;
        if src > self.buf.len() || len > self.buf.len() - src {
            return proto(format!("match at {src}+{len} outside the history"));
        }
        for i in 0..len {
            self.buf[self.pos + i] = self.buf[src + i];
        }
        self.pos += len;
        Ok(())
    }

    /// Keeps the last `keep` bytes before HistoryOffset at the start of the
    /// buffer and continues after them (RDP 6.0 slide-back).
    pub fn slide(&mut self, keep: usize) -> Result<()> {
        if self.pos < keep {
            return proto(format!(
                "history slide at offset {} (needs {keep})",
                self.pos
            ));
        }
        self.buf.copy_within(self.pos - keep..self.pos, 0);
        self.pos = keep;
        Ok(())
    }
}
