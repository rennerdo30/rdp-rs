//! The server's clipboard on demand (RDP-62, RDP-63).
//!
//! A backend that can put data on the local clipboard *lazily* (Windows: an
//! OLE data object) receives a [`RemoteOffer`] for every server Format List
//! instead of the data itself. Nothing is fetched until a local program
//! pastes: the backend then asks the [`RemoteSource`] for the text, the
//! image, the File List or ranges of a file, and the channel turns each ask
//! into a Format Data Request (MS-RDPECLIP 2.2.5.1) or a File Contents
//! Request (2.2.5.3) on its next tick. Answers travel back on a one-shot
//! channel ([`Pending`]).
//!
//! - Several File Contents Requests may be in flight (each has its own
//!   streamId), so a reader can keep a few ranges ahead of the paste.
//! - Format Data Responses carry no format id: they answer requests in
//!   order (3.1.5.2.2), which [`super::Cliprdr`] keeps in one queue with its
//!   own requests.
//! - An offer is only good while it is the latest one of its channel: a new
//!   server copy, sharing off or the end of the session make older sources
//!   answer `None` at once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use super::files::{FileDescriptor, parse_file_list};

/// What the server's clipboard holds, as far as this client handles it.
#[derive(Clone)]
pub struct RemoteOffer {
    /// Unique across all channels of this process.
    pub id: u64,
    pub text: bool,
    /// A bitmap is offered: CF_DIB, or CF_DIBV5 when `dib_v5`.
    pub dib: bool,
    /// The bitmap is CF_DIBV5 (the server offered no CF_DIB).
    pub dib_v5: bool,
    /// The registered "PNG" format is offered.
    pub png: bool,
    /// A File List ("FileGroupDescriptorW") is offered.
    pub files: bool,
    pub source: RemoteSource,
}

impl RemoteOffer {
    /// True if any format this client handles is offered.
    pub fn any(&self) -> bool {
        self.text || self.dib || self.png || self.files
    }
}

/// A format the backend can ask the server for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteFormat {
    /// CF_UNICODETEXT: UTF-16LE with a NUL.
    Text,
    /// A device-independent bitmap: BITMAPINFO and bits, as CF_DIB has it.
    Dib,
    /// PNG file bytes.
    Png,
    /// The Packed File List (2.2.5.2.3).
    FileList,
}

/// An answer still on its way: `None` when the server failed the request,
/// the offer is outdated, or the session ended.
pub type Pending = mpsc::Receiver<Option<Vec<u8>>>;

/// Waits for an answer, at most `timeout`.
pub fn wait(p: &Pending, timeout: Duration) -> Option<Vec<u8>> {
    p.recv_timeout(timeout).ok().flatten()
}

pub(super) type Reply = mpsc::SyncSender<Option<Vec<u8>>>;

/// A request from a [`RemoteSource`] to the channel.
pub(super) enum SourceRequest {
    Data {
        offer: u64,
        format: RemoteFormat,
        reply: Reply,
    },
    /// FILECONTENTS_SIZE (`size` None) or FILECONTENTS_RANGE.
    Contents {
        offer: u64,
        lindex: u32,
        position: u64,
        size: Option<u32>,
        reply: Reply,
    },
}

/// Fetches the data of one [`RemoteOffer`]. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct RemoteSource {
    pub(super) offer: u64,
    pub(super) tx: mpsc::Sender<SourceRequest>,
    /// The channel's latest offer id.
    pub(super) latest: Arc<AtomicU64>,
}

impl RemoteSource {
    /// True while this is the channel's latest offer.
    pub fn current(&self) -> bool {
        self.latest.load(Ordering::Relaxed) == self.offer
    }

    fn send(&self, make: impl FnOnce(Reply) -> SourceRequest) -> Pending {
        let (reply, pending) = mpsc::sync_channel(1);
        if self.current() {
            // A closed channel drops the request and with it the reply
            // sender: the receiver then reports None at once.
            let _ = self.tx.send(make(reply));
        }
        pending
    }

    /// Asks for a whole format.
    pub fn data(&self, format: RemoteFormat) -> Pending {
        let offer = self.offer;
        self.send(|reply| SourceRequest::Data {
            offer,
            format,
            reply,
        })
    }

    /// Asks for `size` bytes of file `lindex` at `position`; the answer
    /// may be shorter at the end of the file.
    pub fn range(&self, lindex: u32, position: u64, size: u32) -> Pending {
        let offer = self.offer;
        self.send(|reply| SourceRequest::Contents {
            offer,
            lindex,
            position,
            size: Some(size),
            reply,
        })
    }

    /// Asks for the size of file `lindex` (8 bytes, little endian).
    pub fn size(&self, lindex: u32) -> Pending {
        let offer = self.offer;
        self.send(|reply| SourceRequest::Contents {
            offer,
            lindex,
            position: 0,
            size: None,
            reply,
        })
    }

    /// The server's File List, parsed (waits at most `timeout`).
    pub fn file_list(&self, timeout: Duration) -> Option<Vec<FileDescriptor>> {
        let body = wait(&self.data(RemoteFormat::FileList), timeout)?;
        match parse_file_list(&body) {
            Ok(l) => Some(l),
            Err(e) => {
                crate::trace!("cliprdr: bad file list ({e})");
                None
            }
        }
    }
}

/// Offer ids, unique in this process (several sessions share one
/// clipboard).
pub(super) fn next_offer_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
