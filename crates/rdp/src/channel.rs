//! Static virtual channels (MS-RDPBCGR 2.2.6, 3.1.5.2, 3.2.5.11).
//!
//! A channel handler implements [`StaticChannel`]. The client advertises its
//! name in the GCC network data, joins the MCS channel the server assigns,
//! splits outgoing messages into chunks with a CHANNEL_PDU_HEADER and
//! reassembles incoming chunks before calling [`StaticChannel::process`].
//!
//! Channels are declared at connect time and cannot be added later, so
//! features that should toggle live (clipboard, drives, printers, smart cards)
//! keep their channel open and gate sharing inside the handler.

use crate::compress::Decompressor;
use crate::cursor::{Put, Reader};
use crate::error::Result;

pub const CHANNEL_FLAG_FIRST: u32 = 0x0000_0001;
pub const CHANNEL_FLAG_LAST: u32 = 0x0000_0002;
pub const CHANNEL_FLAG_SHOW_PROTOCOL: u32 = 0x0000_0010;
/// CHANNEL_PACKET_COMPRESSED, _AT_FRONT, _FLUSHED and the CompressionTypeMask
/// (2.2.6.1.1) are the bulk compression flags shifted left by 16.
const CHANNEL_COMPRESSION_SHIFT: u32 = 16;

pub const CHANNEL_OPTION_INITIALIZED: u32 = 0x8000_0000;
pub const CHANNEL_OPTION_ENCRYPT_RDP: u32 = 0x4000_0000;
pub const CHANNEL_OPTION_COMPRESS_RDP: u32 = 0x0080_0000;
pub const CHANNEL_OPTION_SHOW_PROTOCOL: u32 = 0x0020_0000;

/// Largest chunk body the client sends (VCChunkSize in our capability set).
pub const CHUNK_SIZE: usize = 1600;

/// Complete channel messages a handler wants sent, in order.
#[derive(Default)]
pub struct ChannelOut {
    pub(crate) msgs: Vec<Vec<u8>>,
}

impl ChannelOut {
    pub fn send(&mut self, msg: Vec<u8>) {
        self.msgs.push(msg);
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.msgs)
    }
}

/// One static virtual channel (`cliprdr`, `rdpdr`, `drdynvc`, ...). Runs on the
/// session's worker thread; the UI controls it through shared state the
/// handler owns (for example an `Arc<AtomicBool>` "enabled" flag).
pub trait StaticChannel: Send {
    /// Channel name, 1 to 7 ASCII characters.
    fn name(&self) -> &str;

    /// CHANNEL_DEF options advertised in the client network data.
    fn options(&self) -> u32 {
        CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP
    }

    /// One complete (reassembled) message from the server.
    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()>;

    /// Called on every session poll once the session is active, for traffic
    /// the client starts itself (a local clipboard change, a drive added).
    fn tick(&mut self, _out: &mut ChannelOut) -> Result<()> {
        Ok(())
    }

    /// The dynamic virtual channel host, if this is `drdynvc`; the client
    /// adds its own dynamic channels (graphics) through it.
    fn as_drdynvc(&mut self) -> Option<&mut crate::dvc::Drdynvc> {
        None
    }
}

/// Splits one message into CHANNEL_PDU_HEADER-prefixed chunks.
pub fn chunk(msg: &[u8], show_protocol: bool) -> Vec<Vec<u8>> {
    let extra = if show_protocol {
        CHANNEL_FLAG_SHOW_PROTOCOL
    } else {
        0
    };
    if msg.is_empty() {
        let mut c = Vec::with_capacity(8);
        c.put_u32(0);
        c.put_u32(CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | extra);
        return vec![c];
    }
    let parts: Vec<&[u8]> = msg.chunks(CHUNK_SIZE).collect();
    let n = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let mut flags = extra;
            if i == 0 {
                flags |= CHANNEL_FLAG_FIRST;
            }
            if i == n - 1 {
                flags |= CHANNEL_FLAG_LAST;
            }
            let mut c = Vec::with_capacity(8 + part.len());
            c.put_u32(msg.len() as u32);
            c.put_u32(flags);
            c.put_bytes(part);
            c
        })
        .collect()
}

/// Reassembles incoming chunks into complete messages.
#[derive(Default)]
pub struct Defragmenter {
    buf: Vec<u8>,
    total: usize,
}

impl Defragmenter {
    /// Adds one chunk, bulk-decompressing it with `bulk` (the connection's
    /// server-to-client state) when its header carries compression flags.
    pub fn feed(&mut self, chunk: &[u8], bulk: &mut Decompressor) -> Result<Option<Vec<u8>>> {
        let mut r = Reader::new(chunk);
        let total = r.u32()? as usize;
        let flags = r.u32()?;
        let data = bulk.decompress(r.rest(), (flags >> CHANNEL_COMPRESSION_SHIFT) as u8)?;
        if flags & CHANNEL_FLAG_FIRST != 0 {
            self.buf.clear();
            self.total = total;
        }
        self.buf.extend_from_slice(&data);
        if flags & CHANNEL_FLAG_LAST != 0 {
            if self.buf.len() != self.total {
                crate::trace!(
                    "channel message {} bytes, header said {}",
                    self.buf.len(),
                    self.total
                );
            }
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        Ok(None)
    }
}

/// A joined channel with its handler.
pub(crate) struct Slot {
    pub id: u16,
    pub handler: Box<dyn StaticChannel>,
    pub defrag: Defragmenter,
    /// Set after a handler error; the channel is then ignored.
    pub failed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_and_reassemble_round_trip() {
        let msg: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let chunks = chunk(&msg, false);
        assert_eq!(chunks.len(), 3);
        let mut d = Defragmenter::default();
        let mut bulk = Decompressor::default();
        assert!(d.feed(&chunks[0], &mut bulk).unwrap().is_none());
        assert!(d.feed(&chunks[1], &mut bulk).unwrap().is_none());
        assert_eq!(d.feed(&chunks[2], &mut bulk).unwrap().unwrap(), msg);
    }

    #[test]
    fn single_chunk_has_first_and_last() {
        let c = chunk(b"hello", true);
        assert_eq!(c.len(), 1);
        let flags = u32::from_le_bytes(c[0][4..8].try_into().unwrap());
        assert_eq!(
            flags,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | CHANNEL_FLAG_SHOW_PROTOCOL
        );
        let mut d = Defragmenter::default();
        let mut bulk = Decompressor::default();
        assert_eq!(d.feed(&c[0], &mut bulk).unwrap().unwrap(), b"hello");
    }

    #[test]
    fn compressed_chunk_is_decompressed() {
        // CHANNEL_FLAG_FIRST | LAST | CHANNEL_PACKET_COMPRESSED, type 8K:
        // MPPC "A", "B", <2,3>.
        let mut c = Vec::new();
        c.put_u32(5);
        c.put_u32(0x0020_0003);
        c.put_bytes(&[0x41, 0x42, 0xF0, 0x80]);
        let mut d = Defragmenter::default();
        let mut bulk = Decompressor::new(crate::compress::Compression::Rdp4);
        assert_eq!(d.feed(&c, &mut bulk).unwrap().unwrap(), b"ABABA");
        assert!(d.feed(&c, &mut Decompressor::default()).is_err());
    }
}
