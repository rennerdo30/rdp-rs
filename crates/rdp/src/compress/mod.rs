//! Bulk data compression, server to client (MS-RDPBCGR 3.1.8, MS-RDPEGDI 3.1.8).
//!
//! The client advertises the highest type it supports in the Client Info PDU
//! (INFO_COMPRESSION plus CompressionTypeMask, MS-RDPBCGR 2.2.1.11.1.1); the
//! server picks that type or a lower one and marks every compressed payload
//! with compression flags: the type in the low four bits plus
//! PACKET_COMPRESSED, PACKET_AT_FRONT and PACKET_FLUSHED (3.1.8.2.1). The
//! same flags appear in the share data header (2.2.8.1.1.1.2), the fast-path
//! update header (2.2.9.1.2.1) and, shifted left by 16, in the virtual channel
//! PDU header (2.2.6.1.1).
//!
//! Only decompression is implemented: client-to-server data stays
//! uncompressed. One [`Decompressor`] holds the server-to-client state for the
//! whole connection; each algorithm keeps its own history:
//! - [`mppc`]: RDP 4.0 (8 KB history) and RDP 5.0 (64 KB), MS-RDPBCGR 3.1.8.4
//! - [`ncrush`]: RDP 6.0 Huffman coding, MS-RDPEGDI 3.1.8.1
//! - [`xcrush`]: RDP 6.1 level-1 matches chained with RDP 5.0, MS-RDPEGDI 3.1.8.2
//!
//! Every input is server data: corrupt streams become [`Error::Protocol`] and
//! never panic, and each output is bounded by its history buffer.

mod bits;
mod history;
pub mod mppc;
pub mod ncrush;
pub mod xcrush;

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use crate::error::{Result, proto};

/// CompressionTypeMask in the compression flags (MS-RDPBCGR 2.2.8.1.1.1.2).
pub const COMPRESSION_TYPE_MASK: u8 = 0x0F;
/// The payload is compressed (MPPC bit C).
pub const PACKET_COMPRESSED: u8 = 0x20;
/// Decompress to the start of the history (MPPC bit B); RDP 6.0 slides the
/// history back by half instead (MS-RDPEGDI 3.1.8.1.3).
pub const PACKET_AT_FRONT: u8 = 0x40;
/// Reinitialize the history before anything else (MPPC bit A).
pub const PACKET_FLUSHED: u8 = 0x80;

pub const PACKET_COMPR_TYPE_8K: u8 = 0x0;
pub const PACKET_COMPR_TYPE_64K: u8 = 0x1;
pub const PACKET_COMPR_TYPE_RDP6: u8 = 0x2;
pub const PACKET_COMPR_TYPE_RDP61: u8 = 0x3;

/// The highest bulk compression type the client advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Compression {
    /// No bulk compression is advertised.
    #[default]
    Off,
    /// RDP 4.0: MPPC with an 8 KB history.
    Rdp4,
    /// RDP 5.0: MPPC with a 64 KB history.
    Rdp5,
    /// RDP 6.0: Huffman-coded matches with a 64 KB history (NCRUSH).
    Rdp6,
    /// RDP 6.1: 2 MB level-1 matches chained with RDP 5.0 (XCRUSH).
    Rdp61,
}

impl Compression {
    pub const ALL: [Compression; 5] = [
        Compression::Off,
        Compression::Rdp4,
        Compression::Rdp5,
        Compression::Rdp6,
        Compression::Rdp61,
    ];

    /// The CompressionTypeMask value (PACKET_COMPR_TYPE_*), `None` when off.
    pub fn type_code(self) -> Option<u8> {
        match self {
            Compression::Off => None,
            Compression::Rdp4 => Some(PACKET_COMPR_TYPE_8K),
            Compression::Rdp5 => Some(PACKET_COMPR_TYPE_64K),
            Compression::Rdp6 => Some(PACKET_COMPR_TYPE_RDP6),
            Compression::Rdp61 => Some(PACKET_COMPR_TYPE_RDP61),
        }
    }

    /// Short name: `off`, `rdp4`, `rdp5`, `rdp6` or `rdp61`.
    pub fn name(self) -> &'static str {
        match self {
            Compression::Off => "off",
            Compression::Rdp4 => "rdp4",
            Compression::Rdp5 => "rdp5",
            Compression::Rdp6 => "rdp6",
            Compression::Rdp61 => "rdp61",
        }
    }

    /// Parses [`Compression::name`].
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// Server-to-client bulk decompression state for one connection.
///
/// The histories are allocated on first use of each type, so an unused type
/// costs nothing (RDP 6.1 alone needs about 2 MB).
#[derive(Default)]
pub struct Decompressor {
    max: Compression,
    rdp4: Option<Box<mppc::Mppc>>,
    rdp5: Option<Box<mppc::Mppc>>,
    rdp6: Option<Box<ncrush::Ncrush>>,
    rdp61: Option<Box<xcrush::Xcrush>>,
}

impl Decompressor {
    /// Accepts every type up to `max`, the type the client advertised.
    pub fn new(max: Compression) -> Self {
        Self {
            max,
            ..Self::default()
        }
    }

    /// The advertised maximum.
    pub fn max(&self) -> Compression {
        self.max
    }

    /// Decompresses one payload tagged with `flags` (the compressedType or
    /// compressionFlags byte). Data without PACKET_COMPRESSED is returned as
    /// it is, after any history reset the flags ask for.
    pub fn decompress<'a>(&mut self, data: &'a [u8], flags: u8) -> Result<Cow<'a, [u8]>> {
        if flags & (PACKET_COMPRESSED | PACKET_AT_FRONT | PACKET_FLUSHED) == 0 {
            return Ok(Cow::Borrowed(data));
        }
        let Some(max) = self.max.type_code() else {
            if flags & PACKET_COMPRESSED == 0 {
                return Ok(Cow::Borrowed(data));
            }
            return proto("bulk-compressed data, but no compression was advertised");
        };
        let ty = flags & COMPRESSION_TYPE_MASK;
        if ty > max {
            return proto(format!(
                "compression type {ty} is above the advertised {max}"
            ));
        }
        let out = match ty {
            PACKET_COMPR_TYPE_8K => self
                .rdp4
                .get_or_insert_with(|| Box::new(mppc::Mppc::new(mppc::Variant::Rdp4)))
                .decompress(data, flags)?,
            PACKET_COMPR_TYPE_64K => self
                .rdp5
                .get_or_insert_with(|| Box::new(mppc::Mppc::new(mppc::Variant::Rdp5)))
                .decompress(data, flags)?,
            PACKET_COMPR_TYPE_RDP6 => self
                .rdp6
                .get_or_insert_with(|| Box::new(ncrush::Ncrush::new()))
                .decompress(data, flags)?,
            _ => self
                .rdp61
                .get_or_insert_with(|| Box::new(xcrush::Xcrush::new()))
                .decompress(data, flags)?,
        };
        Ok(match out {
            Some(d) => Cow::Owned(d.to_vec()),
            None => Cow::Borrowed(data),
        })
    }
}
