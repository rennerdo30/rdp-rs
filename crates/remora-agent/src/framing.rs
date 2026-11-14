//! Whole messages over a server-side dynamic virtual channel.
//!
//! On the server, `ReadFile` on a DVC's file handle returns one chunk at a
//! time, each starting with a `CHANNEL_PDU_HEADER` (`pchannel.h`):
//! `u32 length` (the length of the whole message) and `u32 flags`
//! (`CHANNEL_FLAG_FIRST` / `CHANNEL_FLAG_LAST`), followed by that chunk's
//! data. Microsoft's DVC server sample reads with a buffer of
//! `CHANNEL_PDU_LENGTH` (`CHANNEL_CHUNK_LENGTH` + header) and loops until
//! `CHANNEL_FLAG_LAST`; [`Reassembler`] does the same with a size cap.
//!
//! Writes are not chunked by the caller: the sample writes each message
//! (up to 128 KiB there) with a single `WriteFile` and asserts that all of it
//! was written; the DVC stack splits it into MS-RDPEDYC 2.2.3 Data First /
//! Data PDUs. One message is therefore one `WriteFile`. A short write cannot
//! be completed by a second `WriteFile` (that would be a second message), so
//! it closes the channel.
//!
//! Sources: <https://learn.microsoft.com/en-us/windows/win32/termserv/dvc-server-component-example>,
//! MS-RDPEDYC 2.2.3.

use std::io;
use std::time::{Duration, Instant};

/// Largest protocol message the agent sends or accepts (remora-link's
/// limit). Shared with `remora-link` once it lands; keep the two equal.
pub const MAX_MESSAGE_LEN: usize = 1 << 20;
/// Room for remora-link's header, AEAD tag and Noise handshake overhead on
/// top of [`MAX_MESSAGE_LEN`]. A DVC message larger than this closes the
/// channel.
pub const MAX_WIRE_MESSAGE_LEN: usize = MAX_MESSAGE_LEN + 4096;

/// `sizeof(CHANNEL_PDU_HEADER)`.
pub const CHANNEL_PDU_HEADER_LEN: usize = 8;
/// `CHANNEL_CHUNK_LENGTH` (`pchannel.h`).
pub const CHANNEL_CHUNK_LENGTH: usize = 1600;
/// `CHANNEL_PDU_LENGTH`: the read buffer size the server sample uses.
pub const CHANNEL_PDU_LENGTH: usize = CHANNEL_CHUNK_LENGTH + CHANNEL_PDU_HEADER_LEN;
pub const CHANNEL_FLAG_FIRST: u32 = 0x01;
pub const CHANNEL_FLAG_LAST: u32 = 0x02;

/// Why a chunk stream was rejected. Any of these closes the channel, because
/// message boundaries can no longer be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// A read returned fewer bytes than a `CHANNEL_PDU_HEADER`.
    TruncatedHeader(usize),
    /// The header announces a message larger than the cap.
    TooLarge { length: usize, cap: usize },
    /// A continuation chunk arrived without a first chunk.
    MissingFirst,
    /// A first chunk arrived while a message was still incomplete.
    UnexpectedFirst,
    /// A continuation chunk names a different total length.
    LengthMismatch { expected: usize, got: usize },
    /// The chunks carry more data than the header announced.
    Overrun { expected: usize },
    /// The last chunk arrived before the announced length was reached.
    Short { expected: usize, got: usize },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader(n) => write!(f, "chunk of {n} bytes has no full header"),
            Self::TooLarge { length, cap } => write!(f, "message of {length} bytes over cap {cap}"),
            Self::MissingFirst => write!(f, "continuation chunk without a first chunk"),
            Self::UnexpectedFirst => write!(f, "first chunk inside an unfinished message"),
            Self::LengthMismatch { expected, got } => {
                write!(
                    f,
                    "chunk length {got} differs from message length {expected}"
                )
            }
            Self::Overrun { expected } => write!(f, "chunks exceed message length {expected}"),
            Self::Short { expected, got } => {
                write!(f, "last chunk at {got} of {expected} bytes")
            }
        }
    }
}

impl std::error::Error for FramingError {}

impl From<FramingError> for io::Error {
    fn from(e: FramingError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Rebuilds whole messages from `CHANNEL_PDU_HEADER` chunks.
#[derive(Debug)]
pub struct Reassembler {
    cap: usize,
    /// The total length of the message being collected, if one is open.
    expected: Option<usize>,
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            expected: None,
            buf: Vec::new(),
        }
    }

    /// Whether part of a message has been collected.
    #[cfg(test)]
    pub fn in_progress(&self) -> bool {
        self.expected.is_some()
    }

    /// Feeds one chunk exactly as one `ReadFile` returned it. Returns the
    /// message once its last chunk arrived. On an error the partial message
    /// is dropped; the caller closes the channel.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        let r = self.push_inner(chunk);
        if r.is_err() {
            self.expected = None;
            self.buf = Vec::new();
        }
        r
    }

    fn push_inner(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        if chunk.len() < CHANNEL_PDU_HEADER_LEN {
            return Err(FramingError::TruncatedHeader(chunk.len()));
        }
        let length = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
        let flags = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let data = &chunk[CHANNEL_PDU_HEADER_LEN..];
        if flags & CHANNEL_FLAG_FIRST != 0 {
            if self.expected.is_some() {
                return Err(FramingError::UnexpectedFirst);
            }
            if length > self.cap {
                return Err(FramingError::TooLarge {
                    length,
                    cap: self.cap,
                });
            }
            self.expected = Some(length);
            self.buf = Vec::with_capacity(length);
        }
        let Some(expected) = self.expected else {
            return Err(FramingError::MissingFirst);
        };
        if length != expected {
            return Err(FramingError::LengthMismatch {
                expected,
                got: length,
            });
        }
        if self.buf.len() + data.len() > expected {
            return Err(FramingError::Overrun { expected });
        }
        self.buf.extend_from_slice(data);
        if flags & CHANNEL_FLAG_LAST == 0 {
            return Ok(None);
        }
        if self.buf.len() != expected {
            return Err(FramingError::Short {
                expected,
                got: self.buf.len(),
            });
        }
        self.expected = None;
        Ok(Some(std::mem::take(&mut self.buf)))
    }
}

/// The raw channel: chunked reads and whole-message writes. The Windows
/// implementation is the DVC file handle (`win::wts`); tests use a fake.
pub trait ChunkIo {
    /// Reads one chunk (header plus data) into `buf`, waiting at most
    /// `timeout`. `Ok(None)` means nothing arrived in time; nothing was
    /// consumed then.
    fn read_chunk(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>>;
    /// Writes one whole message; the system splits it into DVC PDUs.
    fn write_message(&mut self, msg: &[u8]) -> io::Result<()>;
}

/// A bidirectional message channel: what the protocol layer sees.
pub trait MessagePipe {
    /// Sends one whole message (at most [`MAX_WIRE_MESSAGE_LEN`] bytes).
    fn send(&mut self, msg: &[u8]) -> io::Result<()>;
    /// Waits up to `timeout` for the next whole message. `Ok(None)` on
    /// timeout; a partly received message is kept for the next call. An
    /// error means the channel is unusable and must be closed.
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>>;
}

/// [`MessagePipe`] over a DVC's chunked reads.
pub struct DvcPipe<C> {
    io: C,
    reassembler: Reassembler,
    buf: Vec<u8>,
}

impl<C: ChunkIo> DvcPipe<C> {
    pub fn new(io: C) -> Self {
        Self::with_cap(io, MAX_WIRE_MESSAGE_LEN)
    }

    pub fn with_cap(io: C, cap: usize) -> Self {
        Self {
            io,
            reassembler: Reassembler::new(cap),
            buf: vec![0; CHANNEL_PDU_LENGTH],
        }
    }
}

impl<C: ChunkIo> MessagePipe for DvcPipe<C> {
    fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        if msg.len() > self.reassembler.cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "message of {} bytes over cap {}",
                    msg.len(),
                    self.reassembler.cap
                ),
            ));
        }
        self.io.write_message(msg)
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(n) = self.io.read_chunk(&mut self.buf, left)? else {
                return Ok(None);
            };
            // After the deadline the next read waits zero time, so the loop
            // still ends as soon as no chunk is ready.
            if let Some(msg) = self.reassembler.push(&self.buf[..n])? {
                return Ok(Some(msg));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Builds the chunks the server's DVC stack would hand to `ReadFile`.
    pub fn chunks(msg: &[u8], size: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let parts: Vec<&[u8]> = if msg.is_empty() {
            vec![&[][..]]
        } else {
            msg.chunks(size).collect()
        };
        let n = parts.len();
        for (i, part) in parts.into_iter().enumerate() {
            let mut flags = 0;
            if i == 0 {
                flags |= CHANNEL_FLAG_FIRST;
            }
            if i + 1 == n {
                flags |= CHANNEL_FLAG_LAST;
            }
            out.push(chunk(msg.len() as u32, flags, part));
        }
        out
    }

    pub fn chunk(length: u32, flags: u32, data: &[u8]) -> Vec<u8> {
        let mut c = Vec::with_capacity(8 + data.len());
        c.extend_from_slice(&length.to_le_bytes());
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(data);
        c
    }

    #[derive(Default)]
    pub struct FakeIo {
        pub reads: VecDeque<io::Result<Vec<u8>>>,
        pub writes: Vec<Vec<u8>>,
    }

    impl ChunkIo for FakeIo {
        fn read_chunk(&mut self, buf: &mut [u8], _: Duration) -> io::Result<Option<usize>> {
            match self.reads.pop_front() {
                None => Ok(None),
                Some(Err(e)) => Err(e),
                Some(Ok(c)) => {
                    if c.len() > buf.len() {
                        // What ERROR_MORE_DATA looks like to the pipe.
                        return Err(io::Error::other("chunk larger than read buffer"));
                    }
                    buf[..c.len()].copy_from_slice(&c);
                    Ok(Some(c.len()))
                }
            }
        }
        fn write_message(&mut self, msg: &[u8]) -> io::Result<()> {
            self.writes.push(msg.to_vec());
            Ok(())
        }
    }

    fn pipe_with(chunks: Vec<Vec<u8>>) -> DvcPipe<FakeIo> {
        let io = FakeIo {
            reads: chunks.into_iter().map(Ok).collect(),
            writes: Vec::new(),
        };
        DvcPipe::new(io)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn reassembles_at_any_split() {
        for len in [0, 1, 1599, 1600, 1601, 5000, 70_001] {
            for size in [1, 13, 1600] {
                if len > 20_000 && size < 1000 {
                    continue;
                }
                let msg = pattern(len);
                let mut p = pipe_with(chunks(&msg, size));
                let got = p.recv(Duration::ZERO).unwrap().unwrap();
                assert_eq!(got, msg, "len {len} split {size}");
                assert!(!p.reassembler.in_progress());
            }
        }
    }

    #[test]
    fn two_messages_back_to_back() {
        let (a, b) = (pattern(3000), pattern(10));
        let mut c = chunks(&a, 1600);
        c.extend(chunks(&b, 1600));
        let mut p = pipe_with(c);
        assert_eq!(p.recv(Duration::ZERO).unwrap().unwrap(), a);
        assert_eq!(p.recv(Duration::ZERO).unwrap().unwrap(), b);
        assert!(p.recv(Duration::ZERO).unwrap().is_none());
    }

    #[test]
    fn timeout_mid_message_keeps_the_part() {
        let msg = pattern(4000);
        let c = chunks(&msg, 1600);
        let mut p = pipe_with(c[..1].to_vec());
        assert!(p.recv(Duration::ZERO).unwrap().is_none());
        assert!(p.reassembler.in_progress());
        p.io.reads.extend(c[1..].iter().cloned().map(Ok));
        assert_eq!(p.recv(Duration::ZERO).unwrap().unwrap(), msg);
    }

    #[test]
    fn largest_allowed_message_passes_and_one_more_byte_fails() {
        let mut r = Reassembler::new(MAX_WIRE_MESSAGE_LEN);
        let ok = chunk(MAX_WIRE_MESSAGE_LEN as u32, CHANNEL_FLAG_FIRST, &[]);
        assert_eq!(r.push(&ok), Ok(None));
        let mut r = Reassembler::new(MAX_WIRE_MESSAGE_LEN);
        let big = chunk(MAX_WIRE_MESSAGE_LEN as u32 + 1, CHANNEL_FLAG_FIRST, &[1]);
        assert!(matches!(r.push(&big), Err(FramingError::TooLarge { .. })));
        // A 4 GiB claim is refused before any allocation.
        let huge = chunk(u32::MAX, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, &[]);
        assert!(matches!(r.push(&huge), Err(FramingError::TooLarge { .. })));
    }

    #[test]
    fn rejects_broken_chunk_streams() {
        let mut r = Reassembler::new(100);
        assert_eq!(r.push(&[1, 2, 3]), Err(FramingError::TruncatedHeader(3)));
        assert_eq!(
            r.push(&chunk(10, CHANNEL_FLAG_LAST, &[0; 10])),
            Err(FramingError::MissingFirst)
        );
        r.push(&chunk(10, CHANNEL_FLAG_FIRST, &[0; 4])).unwrap();
        assert_eq!(
            r.push(&chunk(10, CHANNEL_FLAG_FIRST, &[0; 4])),
            Err(FramingError::UnexpectedFirst)
        );
        // The error dropped the partial message; a fresh one works.
        assert!(!r.in_progress());
        r.push(&chunk(10, CHANNEL_FLAG_FIRST, &[0; 4])).unwrap();
        assert_eq!(
            r.push(&chunk(11, 0, &[0; 4])),
            Err(FramingError::LengthMismatch {
                expected: 10,
                got: 11
            })
        );
        r.push(&chunk(10, CHANNEL_FLAG_FIRST, &[0; 4])).unwrap();
        assert_eq!(
            r.push(&chunk(10, 0, &[0; 7])),
            Err(FramingError::Overrun { expected: 10 })
        );
        r.push(&chunk(10, CHANNEL_FLAG_FIRST, &[0; 4])).unwrap();
        assert_eq!(
            r.push(&chunk(10, CHANNEL_FLAG_LAST, &[0; 4])),
            Err(FramingError::Short {
                expected: 10,
                got: 8
            })
        );
    }

    #[test]
    fn io_errors_and_framing_errors_reach_the_caller() {
        let mut p = pipe_with(vec![chunk(5, CHANNEL_FLAG_LAST, &[0; 5])]);
        let e = p.recv(Duration::ZERO).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let mut p = pipe_with(vec![]);
        p.io.reads
            .push_back(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        assert_eq!(
            p.recv(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        // A chunk bigger than the read buffer is an error, never a silent cut.
        let mut p = pipe_with(vec![chunk(4000, CHANNEL_FLAG_FIRST, &[0; 3000])]);
        assert!(p.recv(Duration::ZERO).is_err());
    }

    #[test]
    fn send_is_one_write_per_message_and_capped() {
        let mut p = pipe_with(vec![]);
        let msg = pattern(MAX_WIRE_MESSAGE_LEN);
        p.send(&msg).unwrap();
        p.send(b"").unwrap();
        assert_eq!(p.io.writes.len(), 2);
        assert_eq!(p.io.writes[0].len(), MAX_WIRE_MESSAGE_LEN);
        let over = vec![0; MAX_WIRE_MESSAGE_LEN + 1];
        assert_eq!(
            p.send(&over).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(p.io.writes.len(), 2);
    }
}
