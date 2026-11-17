//! The helper's picture stream (RDP-67, experimental): the session's own
//! picture, captured (DXGI Desktop Duplication), converted and encoded as
//! H.264 on the server's GPU when it has one, and sent to Remora on the
//! Bulk channel in place of RDP's picture.
//!
//! One thread per stream. It captures only while fewer than [`IN_FLIGHT`]
//! pictures wait for Remora's acknowledgement, so a slow network or client
//! gets fewer, fresher pictures instead of a queue; Windows accumulates the
//! changed regions meanwhile. Each picture carries the regions that changed
//! since the last one sent, so Remora converts only those.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::{D3D11_TEXTURE2D_DESC, ID3D11Texture2D};
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_MORE_DATA, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    DXGI_OUTDUPL_MOVE_RECT, IDXGIResource,
};
use windows::Win32::Media::MediaFoundation::{
    MF_VERSION, MFSTARTUP_NOSOCKET, MFShutdown, MFStartup,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
use windows::core::Interface;

use super::agent::Input;
use super::probe::{self, encode::Live};
use crate::{info, warn};

/// Pictures sent and not yet acknowledged before capture pauses.
const IN_FLIGHT: u32 = 2;
/// Changed rectangles per picture before they become one.
const MAX_RECTS: usize = remora_link::msg::MAX_STREAM_RECTS;

enum Cmd {
    Ack(u32),
}

/// A running stream; dropping it stops the thread.
pub struct Stream {
    tx: Option<Sender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl Stream {
    /// Starts streaming; [`Input::StreamState`] answers `request_id` (started
    /// with the size, or failed), [`Input::StreamPicture`] carries pictures.
    pub fn start(request_id: u32, max_fps: u8, kbps: u32, out: Sender<Input>) -> Stream {
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("picture-stream".into())
            .spawn(move || run(request_id, max_fps, kbps, &rx, &out))
            .ok();
        Stream {
            tx: Some(tx),
            thread,
        }
    }

    /// Remora decoded picture `seq`.
    pub fn ack(&self, seq: u32) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Cmd::Ack(seq));
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn state(out: &Sender<Input>, request_id: u32, state: u8, size: (u32, u32), text: String) {
    let _ = out.send(Input::StreamState {
        request_id,
        state,
        width: size.0,
        height: size.1,
        text,
    });
}

fn run(request_id: u32, max_fps: u8, kbps: u32, rx: &Receiver<Cmd>, out: &Sender<Input>) {
    // SAFETY: COM and Media Foundation for this thread, shut down below.
    let mf = unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET).is_ok()
    };
    if !mf {
        state(
            out,
            request_id,
            2,
            (0, 0),
            "Media Foundation did not start".into(),
        );
        return;
    }
    match stream(request_id, max_fps, kbps, rx, out) {
        Ok(()) => state(out, 0, 1, (0, 0), String::new()),
        Err(e) => {
            warn!("picture stream: {e}");
            state(out, request_id, 2, (0, 0), e);
        }
    }
    // SAFETY: matches the MFStartup above; the encoder is gone.
    let _ = unsafe { MFShutdown() };
}

fn stream(
    request_id: u32,
    max_fps: u8,
    kbps: u32,
    rx: &Receiver<Cmd>,
    out: &Sender<Input>,
) -> Result<(), String> {
    let mut log = String::new();
    let adapters = probe::adapters(&mut log);
    let Some(mut d) = probe::duplicate(&adapters, &mut log) else {
        return Err("this session's picture cannot be captured".into());
    };
    // The first full frame: the encoder's size and format.
    let mut first: Option<ID3D11Texture2D> = None;
    let t = Instant::now();
    while first.is_none() {
        if t.elapsed() > Duration::from_secs(3) {
            return Err("no picture from the desktop within 3 s".into());
        }
        let mut fi = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        // SAFETY: the acquired frame is copied, then released.
        unsafe {
            match d.dupl.AcquireNextFrame(200, &mut fi, &mut res) {
                Ok(()) => {
                    if fi.LastPresentTime != 0
                        && let Some(tex) = res.and_then(|r| r.cast::<ID3D11Texture2D>().ok())
                    {
                        probe::keep_frame(&d, &tex, &mut first);
                    }
                    let _ = d.dupl.ReleaseFrame();
                }
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                    // Nothing changed: an empty desktop still has a picture
                    // once something is drawn; keep waiting.
                }
                Err(e) => return Err(format!("capture: {e}")),
            }
        }
    }
    let first = first.ok_or("no first picture")?;
    let mut live = Live::start(&d.device, &d.context, &first, kbps)?;
    let size = live.encoded_size();
    info!(
        "picture stream started: {}x{}, {} kbit/s, at most {max_fps} fps, {}",
        size.0, size.1, kbps, live.name
    );
    state(out, request_id, 0, size, String::new());
    let full = [[0, 0, size.0.min(0xffff) as u16, size.1.min(0xffff) as u16]];
    // The first picture is the whole frame.
    let mut pending: Vec<[u16; 4]> = full.to_vec();
    if let Some(t) = live.push(&first)? {
        let mut by_time = HashMap::new();
        by_time.insert(t, std::mem::take(&mut pending));
        return pump(&mut d, &mut live, by_time, size, max_fps, rx, out);
    }
    pump(&mut d, &mut live, HashMap::new(), size, max_fps, rx, out)
}

#[allow(clippy::too_many_arguments)]
fn pump(
    d: &mut probe::Dup,
    live: &mut Live,
    mut by_time: HashMap<i64, Vec<[u16; 4]>>,
    size: (u32, u32),
    max_fps: u8,
    rx: &Receiver<Cmd>,
    out: &Sender<Input>,
) -> Result<(), String> {
    let full = vec![[0, 0, size.0.min(0xffff) as u16, size.1.min(0xffff) as u16]];
    let gap = Duration::from_secs(1) / u32::from(max_fps.clamp(1, 120));
    let mut pending: Vec<[u16; 4]> = Vec::new();
    let mut seq = 0u32;
    let mut acked = 0u32;
    let mut last = Instant::now() - gap;
    loop {
        // Remora's acknowledgements, or the stop (the sender is gone).
        loop {
            match rx.recv_timeout(Duration::ZERO) {
                Ok(Cmd::Ack(s)) => acked = acked.max(s),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        for e in live.take()? {
            seq = seq.wrapping_add(1);
            let rects = by_time.remove(&e.time).unwrap_or_else(|| full.clone());
            let _ = out.send(Input::StreamPicture {
                seq,
                key: e.key,
                rects,
                data: e.data,
            });
        }
        if seq.wrapping_sub(acked) >= IN_FLIGHT || last.elapsed() < gap {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        let mut fi = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        // SAFETY: the frame is copied by `push` before it is released.
        let got = unsafe { d.dupl.AcquireNextFrame(8, &mut fi, &mut res) };
        match got {
            Ok(()) => {
                let changed = fi.LastPresentTime != 0 || fi.TotalMetadataBufferSize > 0;
                if changed {
                    changed_rects(d, &fi, size, &mut pending);
                    if let Some(tex) = res.and_then(|r| r.cast::<ID3D11Texture2D>().ok())
                        && same_size(&tex, size)
                        && let Some(t) = live.push(&tex)?
                    {
                        by_time.insert(t, std::mem::take(&mut pending));
                        last = Instant::now();
                    }
                }
                // SAFETY: the frame acquired above.
                let _ = unsafe { d.dupl.ReleaseFrame() };
            }
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {}
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                // The desktop switched (lock screen, UAC, a mode change).
                // SAFETY: a new duplication of the same output.
                match unsafe { d.output.DuplicateOutput(&d.device) } {
                    Ok(n) => {
                        d.dupl = n;
                        pending = full.clone();
                    }
                    Err(e) => return Err(format!("the desktop cannot be captured again: {e}")),
                }
            }
            Err(e) => return Err(format!("capture: {e}")),
        }
    }
}

/// Whether a captured frame still has the encoder's size (a resolution
/// change ends the stream in a later version; until then it is skipped).
fn same_size(tex: &ID3D11Texture2D, size: (u32, u32)) -> bool {
    let mut d = D3D11_TEXTURE2D_DESC::default();
    // SAFETY: a plain getter.
    unsafe { tex.GetDesc(&mut d) };
    (d.Width & !1, d.Height & !1) == size
}

/// Adds this frame's changed regions (dirty and moved-to rectangles) to
/// `pending`, clipped to the picture; too many become the whole picture.
fn changed_rects(
    d: &probe::Dup,
    fi: &DXGI_OUTDUPL_FRAME_INFO,
    size: (u32, u32),
    pending: &mut Vec<[u16; 4]>,
) {
    let full = [0, 0, size.0.min(0xffff) as u16, size.1.min(0xffff) as u16];
    if pending.first() == Some(&full) {
        return;
    }
    let mut rects: Vec<RECT> = Vec::new();
    if fi.TotalMetadataBufferSize > 0 {
        let n = fi.TotalMetadataBufferSize as usize / std::mem::size_of::<RECT>() + 1;
        let mut moves = vec![DXGI_OUTDUPL_MOVE_RECT::default(); n];
        let mut need = 0u32;
        // SAFETY: buffers of the stated byte sizes.
        let ok = unsafe {
            d.dupl.GetFrameMoveRects(
                (moves.len() * std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32,
                moves.as_mut_ptr(),
                &mut need,
            )
        };
        match ok {
            Ok(()) => {
                let k = need as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
                rects.extend(
                    moves[..k.min(moves.len())]
                        .iter()
                        .map(|m| m.DestinationRect),
                );
            }
            Err(e) if e.code() == DXGI_ERROR_MORE_DATA => {
                pending.clear();
                pending.push(full);
                return;
            }
            Err(_) => {}
        }
        let mut dirty = vec![RECT::default(); n];
        let mut need = 0u32;
        // SAFETY: as above.
        let ok = unsafe {
            d.dupl.GetFrameDirtyRects(
                (dirty.len() * std::mem::size_of::<RECT>()) as u32,
                dirty.as_mut_ptr(),
                &mut need,
            )
        };
        match ok {
            Ok(()) => {
                let k = need as usize / std::mem::size_of::<RECT>();
                rects.extend_from_slice(&dirty[..k.min(dirty.len())]);
            }
            Err(_) => {
                pending.clear();
                pending.push(full);
                return;
            }
        }
    } else if fi.LastPresentTime != 0 {
        // A new picture without metadata: assume all of it.
        pending.clear();
        pending.push(full);
        return;
    }
    for r in rects {
        let (x0, y0) = (r.left.max(0) as u32, r.top.max(0) as u32);
        let (x1, y1) = (
            (r.right.max(0) as u32).min(size.0),
            (r.bottom.max(0) as u32).min(size.1),
        );
        if x1 > x0 && y1 > y0 {
            pending.push([x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16]);
        }
    }
    if pending.len() > MAX_RECTS {
        pending.clear();
        pending.push(full);
    }
}
