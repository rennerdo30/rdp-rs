//! Windowing Alternate Secondary Drawing Orders (MS-RDPERP 2.2.1.3) and the
//! drawing order framing that carries them in fast-path and slow-path orders
//! updates (MS-RDPEGDI 2.2.2.1, 2.2.2.2).
//!
//! The client negotiates no primary or secondary drawing orders (its order
//! capability set is all zeros), so these window orders are the only ones it
//! expects. Anything else is skipped when its length is known (secondary
//! orders, other window orders) and otherwise ends the batch, because a
//! primary or unknown alternate secondary order carries no length field.

use crate::cursor::Reader;
use crate::error::{Result, proto};
use crate::trace;

/// controlFlags class bits (MS-RDPEGDI 2.2.2.2.1).
pub const TS_STANDARD: u8 = 0x01;
pub const TS_SECONDARY: u8 = 0x02;
/// orderType of a Windowing Alternate Secondary Drawing Order (MS-RDPEGDI 2.2.2.2.1.3.1.1).
pub const TS_ALTSEC_WINDOW: u8 = 0x0B;
/// updateType of a slow-path Orders Update (MS-RDPEGDI 2.2.2.1).
pub const UPDATETYPE_ORDERS: u16 = 0x0000;

// FieldsPresentFlags shared by all window orders (MS-RDPERP 2.2.1.3).
pub const WINDOW_ORDER_TYPE_WINDOW: u32 = 0x0100_0000;
pub const WINDOW_ORDER_TYPE_NOTIFY: u32 = 0x0200_0000;
pub const WINDOW_ORDER_TYPE_DESKTOP: u32 = 0x0400_0000;
pub const WINDOW_ORDER_STATE_NEW: u32 = 0x1000_0000;
pub const WINDOW_ORDER_STATE_DELETED: u32 = 0x2000_0000;
pub const WINDOW_ORDER_ICON: u32 = 0x4000_0000;
pub const WINDOW_ORDER_CACHEDICON: u32 = 0x8000_0000;

// New or Existing Window (2.2.1.3.1.2.1).
pub const WINDOW_ORDER_FIELD_APPBAR_EDGE: u32 = 0x0000_0001;
pub const WINDOW_ORDER_FIELD_OWNER: u32 = 0x0000_0002;
pub const WINDOW_ORDER_FIELD_TITLE: u32 = 0x0000_0004;
pub const WINDOW_ORDER_FIELD_STYLE: u32 = 0x0000_0008;
pub const WINDOW_ORDER_FIELD_SHOW: u32 = 0x0000_0010;
pub const WINDOW_ORDER_FIELD_APPBAR_STATE: u32 = 0x0000_0040;
pub const WINDOW_ORDER_FIELD_RESIZE_MARGIN_X: u32 = 0x0000_0080;
pub const WINDOW_ORDER_FIELD_WNDRECTS: u32 = 0x0000_0100;
pub const WINDOW_ORDER_FIELD_VISIBILITY: u32 = 0x0000_0200;
pub const WINDOW_ORDER_FIELD_WNDSIZE: u32 = 0x0000_0400;
pub const WINDOW_ORDER_FIELD_WNDOFFSET: u32 = 0x0000_0800;
pub const WINDOW_ORDER_FIELD_VISOFFSET: u32 = 0x0000_1000;
pub const WINDOW_ORDER_FIELD_ICON_BIG: u32 = 0x0000_2000;
pub const WINDOW_ORDER_FIELD_CLIENTAREAOFFSET: u32 = 0x0000_4000;
pub const WINDOW_ORDER_FIELD_CLIENTDELTA: u32 = 0x0000_8000;
pub const WINDOW_ORDER_FIELD_CLIENTAREASIZE: u32 = 0x0001_0000;
pub const WINDOW_ORDER_FIELD_RPCONTENT: u32 = 0x0002_0000;
pub const WINDOW_ORDER_FIELD_ROOTPARENT: u32 = 0x0004_0000;
pub const WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER: u32 = 0x0008_0000;
pub const WINDOW_ORDER_FIELD_ICON_OVERLAY: u32 = 0x0010_0000;
pub const WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL: u32 = 0x0020_0000;
pub const WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION: u32 = 0x0040_0000;
pub const WINDOW_ORDER_FIELD_TASKBAR_BUTTON: u32 = 0x0080_0000;
pub const WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y: u32 = 0x0800_0000;

// New or Existing Notification Icon (2.2.1.3.2.2.1).
pub const WINDOW_ORDER_FIELD_NOTIFY_TIP: u32 = 0x0000_0001;
pub const WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP: u32 = 0x0000_0002;
pub const WINDOW_ORDER_FIELD_NOTIFY_STATE: u32 = 0x0000_0004;
pub const WINDOW_ORDER_FIELD_NOTIFY_VERSION: u32 = 0x0000_0008;

// Desktop orders (2.2.1.3.3.2).
pub const WINDOW_ORDER_FIELD_DESKTOP_NONE: u32 = 0x0000_0001;
pub const WINDOW_ORDER_FIELD_DESKTOP_HOOKED: u32 = 0x0000_0002;
pub const WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED: u32 = 0x0000_0004;
pub const WINDOW_ORDER_FIELD_DESKTOP_ARC_BEGAN: u32 = 0x0000_0008;
pub const WINDOW_ORDER_FIELD_DESKTOP_ZORDER: u32 = 0x0000_0010;
pub const WINDOW_ORDER_FIELD_DESKTOP_ACTIVEWND: u32 = 0x0000_0020;

/// Largest icon side the decoder accepts; the spec allows up to 96 (2.2.2.2.2).
const MAX_ICON_SIDE: u16 = 256;

/// TS_RECTANGLE_16 (MS-RDPERP 2.2.1.2.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect16 {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Rect16 {
    fn read(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            left: r.u16()?,
            top: r.u16()?,
            right: r.u16()?,
            bottom: r.u16()?,
        })
    }
}

/// The optional fields of a New or Existing Window order (2.2.1.3.1.2.1);
/// `None` means "not sent, keep the previous value".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowInfo {
    pub owner: Option<u32>,
    /// (Style, ExtendedStyle).
    pub style: Option<(u32, u32)>,
    pub show_state: Option<u8>,
    pub title: Option<String>,
    pub client_offset: Option<(i32, i32)>,
    pub client_area_size: Option<(u32, u32)>,
    /// (left, right) hit-testable margins.
    pub resize_margin_x: Option<(u32, u32)>,
    /// (top, bottom) hit-testable margins.
    pub resize_margin_y: Option<(u32, u32)>,
    pub rp_content: Option<u8>,
    pub root_parent: Option<u32>,
    pub window_offset: Option<(i32, i32)>,
    pub client_delta: Option<(i32, i32)>,
    pub window_size: Option<(u32, u32)>,
    pub window_rects: Option<Vec<Rect16>>,
    pub visible_offset: Option<(i32, i32)>,
    pub visibility_rects: Option<Vec<Rect16>>,
    pub overlay_description: Option<String>,
    /// WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL: the overlay icon was removed.
    pub icon_overlay_null: bool,
    pub taskbar_button: Option<u8>,
    pub enforce_server_zorder: Option<u8>,
    pub appbar_state: Option<u8>,
    pub appbar_edge: Option<u8>,
}

/// TS_ICON_INFO (2.2.1.2.3), raw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IconInfo {
    pub cache_entry: u16,
    /// 0xFF: do not cache.
    pub cache_id: u8,
    pub bpp: u8,
    pub width: u16,
    pub height: u16,
    pub color_table: Vec<u8>,
    pub bits_mask: Vec<u8>,
    pub bits_color: Vec<u8>,
}

/// TS_CACHED_ICON_INFO (2.2.1.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedIcon {
    pub cache_entry: u16,
    pub cache_id: u8,
}

/// Which icon of a window an icon order sets (ICON_BIG, ICON_OVERLAY).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IconSlot {
    pub big: bool,
    pub overlay: bool,
}

/// TS_NOTIFY_ICON_INFOTIP (2.2.1.3.2.2.3): a balloon tooltip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfoTip {
    pub timeout_ms: u32,
    /// NIIF_* flags.
    pub flags: u32,
    pub text: String,
    pub title: String,
}

/// The optional fields of a New or Existing Notification Icon order (2.2.1.3.2.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifyIconInfo {
    pub version: Option<u32>,
    pub tooltip: Option<String>,
    pub info_tip: Option<InfoTip>,
    pub state: Option<u32>,
    pub icon: Option<IconInfo>,
    pub cached_icon: Option<CachedIcon>,
}

/// Actively Monitored Desktop (2.2.1.3.3.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopInfo {
    pub hooked: bool,
    pub arc_began: bool,
    pub arc_completed: bool,
    pub active_window: Option<u32>,
    /// Top-level window ids, front to back.
    pub z_order: Option<Vec<u32>>,
}

/// One parsed Windowing Alternate Secondary Drawing Order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowOrder {
    Window {
        id: u32,
        new: bool,
        info: WindowInfo,
    },
    Icon {
        id: u32,
        slot: IconSlot,
        icon: IconInfo,
    },
    CachedIcon {
        id: u32,
        slot: IconSlot,
        cached: CachedIcon,
    },
    WindowDeleted {
        id: u32,
    },
    NotifyIcon {
        window_id: u32,
        icon_id: u32,
        new: bool,
        info: NotifyIconInfo,
    },
    NotifyIconDeleted {
        window_id: u32,
        icon_id: u32,
    },
    Desktop(DesktopInfo),
    /// Non-Monitored Desktop (2.2.1.3.3.2.2).
    DesktopNone,
}

/// UNICODE_STRING (2.2.1.2.1): CbString, then UTF-16LE. Trailing NULs are dropped.
fn unicode_string(r: &mut Reader) -> Result<String> {
    let n = r.u16()? as usize;
    Ok(utf16_text(r.bytes(n)?))
}

/// UTF-16LE text up to the first NUL (or the end).
pub(crate) fn utf16_text(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn pair_i32(r: &mut Reader) -> Result<(i32, i32)> {
    Ok((r.u32()? as i32, r.u32()? as i32))
}

fn pair_u32(r: &mut Reader) -> Result<(u32, u32)> {
    Ok((r.u32()?, r.u32()?))
}

fn rects(r: &mut Reader) -> Result<Vec<Rect16>> {
    let n = r.u16()?;
    (0..n).map(|_| Rect16::read(r)).collect()
}

impl IconInfo {
    fn read(r: &mut Reader) -> Result<Self> {
        let cache_entry = r.u16()?;
        let cache_id = r.u8()?;
        let bpp = r.u8()?;
        let width = r.u16()?;
        let height = r.u16()?;
        // CbColorTable is present only for 1, 4 and 8 bpp.
        let cb_table = if matches!(bpp, 1 | 4 | 8) {
            r.u16()? as usize
        } else {
            0
        };
        let cb_mask = r.u16()? as usize;
        let cb_color = r.u16()? as usize;
        // Field order on the wire: BitsMask, ColorTable, BitsColor.
        let bits_mask = r.bytes(cb_mask)?.to_vec();
        let color_table = r.bytes(cb_table)?.to_vec();
        let bits_color = r.bytes(cb_color)?.to_vec();
        Ok(Self {
            cache_entry,
            cache_id,
            bpp,
            width,
            height,
            color_table,
            bits_mask,
            bits_color,
        })
    }

    /// Decodes the icon to top-down RGBA (4 bytes per pixel). The bitmaps are
    /// device-independent bitmaps as Windows stores icons: bottom-up rows, each
    /// padded to `cb / height` bytes; a set bit in the 1 bpp mask is
    /// transparent. A 32 bpp icon with any nonzero alpha uses its alpha
    /// channel instead of the mask.
    pub fn to_rgba(&self) -> Result<Vec<u8>> {
        let (w, h) = (self.width as usize, self.height as usize);
        if w == 0 || h == 0 || self.width > MAX_ICON_SIDE || self.height > MAX_ICON_SIDE {
            return proto(format!("icon size {w}x{h}"));
        }
        let bpp = self.bpp as usize;
        if !matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32) {
            return proto(format!("icon depth {bpp}"));
        }
        let color_stride = self.bits_color.len() / h;
        if color_stride < (w * bpp).div_ceil(8) {
            return proto("icon color bitmap too short");
        }
        let mask_stride = self.bits_mask.len() / h;
        if mask_stride != 0 && mask_stride < w.div_ceil(8) {
            return proto("icon mask too short");
        }
        let palette: Vec<[u8; 3]> = self
            .color_table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|q| [q[2], q[1], q[0]]) // RGBQUAD: blue, green, red, reserved
            .collect();
        let index = |i: usize| palette.get(i).copied().unwrap_or([0, 0, 0]);
        let mut out = vec![0u8; w * h * 4];
        let mut alpha_seen = false;
        for y in 0..h {
            let src = h - 1 - y;
            let row = &self.bits_color[src * color_stride..][..color_stride];
            for x in 0..w {
                let px = match bpp {
                    32 => {
                        let p = &row[x * 4..x * 4 + 4];
                        alpha_seen |= p[3] != 0;
                        [p[2], p[1], p[0], p[3]]
                    }
                    24 => {
                        let p = &row[x * 3..x * 3 + 3];
                        [p[2], p[1], p[0], 0xFF]
                    }
                    16 => {
                        // 16 bpp BI_RGB DIBs are 5-5-5.
                        let v = u16::from_le_bytes([row[x * 2], row[x * 2 + 1]]);
                        let c = |s: u16| {
                            let v = ((v >> s) & 0x1F) as u8;
                            (v << 3) | (v >> 2)
                        };
                        [c(10), c(5), c(0), 0xFF]
                    }
                    8 => rgb(index(row[x] as usize)),
                    4 => rgb(index(
                        ((row[x / 2] >> if x % 2 == 0 { 4 } else { 0 }) & 0x0F) as usize,
                    )),
                    _ => rgb(index(((row[x / 8] >> (7 - x % 8)) & 1) as usize)),
                };
                out[(y * w + x) * 4..][..4].copy_from_slice(&px);
            }
        }
        if bpp == 32 && alpha_seen {
            return Ok(out);
        }
        for y in 0..h {
            let mask_row = (mask_stride != 0)
                .then(|| &self.bits_mask[(h - 1 - y) * mask_stride..][..mask_stride]);
            for x in 0..w {
                let transparent = mask_row.is_some_and(|m| (m[x / 8] >> (7 - x % 8)) & 1 == 1);
                out[(y * w + x) * 4 + 3] = if transparent { 0 } else { 0xFF };
            }
        }
        Ok(out)
    }
}

fn rgb(c: [u8; 3]) -> [u8; 4] {
    [c[0], c[1], c[2], 0xFF]
}

impl CachedIcon {
    fn read(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            cache_entry: r.u16()?,
            cache_id: r.u8()?,
        })
    }
}

/// Parses one complete window order: the alternate secondary header byte,
/// OrderSize, FieldsPresentFlags and the body (`order.len()` = OrderSize).
pub fn parse_window_order(order: &[u8]) -> Result<WindowOrder> {
    let mut r = Reader::new(order);
    let header = r.u8()?;
    if header & 0x03 != TS_SECONDARY || header >> 2 != TS_ALTSEC_WINDOW {
        return proto(format!("not a window order: header {header:#04x}"));
    }
    r.u16()?; // OrderSize; the caller sliced the order to it
    let flags = r.u32()?;
    let has = |f: u32| flags & f != 0;
    if has(WINDOW_ORDER_TYPE_WINDOW) {
        let id = r.u32()?;
        let slot = IconSlot {
            big: has(WINDOW_ORDER_FIELD_ICON_BIG),
            overlay: has(WINDOW_ORDER_FIELD_ICON_OVERLAY),
        };
        if has(WINDOW_ORDER_STATE_DELETED) {
            return Ok(WindowOrder::WindowDeleted { id });
        }
        if has(WINDOW_ORDER_ICON) {
            let icon = IconInfo::read(&mut r)?;
            return Ok(WindowOrder::Icon { id, slot, icon });
        }
        if has(WINDOW_ORDER_CACHEDICON) {
            let cached = CachedIcon::read(&mut r)?;
            return Ok(WindowOrder::CachedIcon { id, slot, cached });
        }
        return Ok(WindowOrder::Window {
            id,
            new: has(WINDOW_ORDER_STATE_NEW),
            info: window_info(&mut r, flags)?,
        });
    }
    if has(WINDOW_ORDER_TYPE_NOTIFY) {
        let window_id = r.u32()?;
        let icon_id = r.u32()?;
        if has(WINDOW_ORDER_STATE_DELETED) {
            return Ok(WindowOrder::NotifyIconDeleted { window_id, icon_id });
        }
        let mut info = NotifyIconInfo::default();
        if has(WINDOW_ORDER_FIELD_NOTIFY_VERSION) {
            info.version = Some(r.u32()?);
        }
        if has(WINDOW_ORDER_FIELD_NOTIFY_TIP) {
            info.tooltip = Some(unicode_string(&mut r)?);
        }
        if has(WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP) {
            info.info_tip = Some(InfoTip {
                timeout_ms: r.u32()?,
                flags: r.u32()?,
                text: unicode_string(&mut r)?,
                title: unicode_string(&mut r)?,
            });
        }
        if has(WINDOW_ORDER_FIELD_NOTIFY_STATE) {
            info.state = Some(r.u32()?);
        }
        if has(WINDOW_ORDER_ICON) {
            info.icon = Some(IconInfo::read(&mut r)?);
        }
        if has(WINDOW_ORDER_CACHEDICON) {
            info.cached_icon = Some(CachedIcon::read(&mut r)?);
        }
        return Ok(WindowOrder::NotifyIcon {
            window_id,
            icon_id,
            new: has(WINDOW_ORDER_STATE_NEW),
            info,
        });
    }
    if has(WINDOW_ORDER_TYPE_DESKTOP) {
        if has(WINDOW_ORDER_FIELD_DESKTOP_NONE) {
            return Ok(WindowOrder::DesktopNone);
        }
        let mut d = DesktopInfo {
            hooked: has(WINDOW_ORDER_FIELD_DESKTOP_HOOKED),
            arc_began: has(WINDOW_ORDER_FIELD_DESKTOP_ARC_BEGAN),
            arc_completed: has(WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED),
            ..Default::default()
        };
        if has(WINDOW_ORDER_FIELD_DESKTOP_ACTIVEWND) {
            d.active_window = Some(r.u32()?);
        }
        if has(WINDOW_ORDER_FIELD_DESKTOP_ZORDER) {
            let n = r.u8()?;
            d.z_order = Some((0..n).map(|_| r.u32()).collect::<Result<_>>()?);
        }
        return Ok(WindowOrder::Desktop(d));
    }
    proto(format!("window order of unknown type, flags {flags:#010x}"))
}

/// The fields of a New or Existing Window order, in wire order.
fn window_info(r: &mut Reader, flags: u32) -> Result<WindowInfo> {
    let has = |f: u32| flags & f != 0;
    let mut w = WindowInfo::default();
    if has(WINDOW_ORDER_FIELD_OWNER) {
        w.owner = Some(r.u32()?);
    }
    if has(WINDOW_ORDER_FIELD_STYLE) {
        w.style = Some(pair_u32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_SHOW) {
        w.show_state = Some(r.u8()?);
    }
    if has(WINDOW_ORDER_FIELD_TITLE) {
        w.title = Some(unicode_string(r)?);
    }
    if has(WINDOW_ORDER_FIELD_CLIENTAREAOFFSET) {
        w.client_offset = Some(pair_i32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_CLIENTAREASIZE) {
        w.client_area_size = Some(pair_u32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_RESIZE_MARGIN_X) {
        w.resize_margin_x = Some(pair_u32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y) {
        w.resize_margin_y = Some(pair_u32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_RPCONTENT) {
        w.rp_content = Some(r.u8()?);
    }
    if has(WINDOW_ORDER_FIELD_ROOTPARENT) {
        w.root_parent = Some(r.u32()?);
    }
    if has(WINDOW_ORDER_FIELD_WNDOFFSET) {
        w.window_offset = Some(pair_i32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_CLIENTDELTA) {
        w.client_delta = Some(pair_i32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_WNDSIZE) {
        w.window_size = Some(pair_u32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_WNDRECTS) {
        w.window_rects = Some(rects(r)?);
    }
    if has(WINDOW_ORDER_FIELD_VISOFFSET) {
        w.visible_offset = Some(pair_i32(r)?);
    }
    if has(WINDOW_ORDER_FIELD_VISIBILITY) {
        w.visibility_rects = Some(rects(r)?);
    }
    if has(WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION) {
        w.overlay_description = Some(unicode_string(r)?);
    }
    w.icon_overlay_null = has(WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL);
    if has(WINDOW_ORDER_FIELD_TASKBAR_BUTTON) {
        w.taskbar_button = Some(r.u8()?);
    }
    if has(WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER) {
        w.enforce_server_zorder = Some(r.u8()?);
    }
    if has(WINDOW_ORDER_FIELD_APPBAR_STATE) {
        w.appbar_state = Some(r.u8()?);
    }
    if has(WINDOW_ORDER_FIELD_APPBAR_EDGE) {
        w.appbar_edge = Some(r.u8()?);
    }
    Ok(w)
}

/// Walks `count` DRAWING_ORDERs (MS-RDPEGDI 2.2.2.2.1) and returns the window
/// orders among them. A malformed window order is skipped by its OrderSize;
/// secondary orders are skipped by orderLength + 13 (2.2.2.2.1.2.1.1). A
/// primary or other alternate secondary order has no length field, so the
/// rest of the batch is dropped. Never fails: bad data is traced.
pub fn parse_order_data(count: u16, data: &[u8]) -> Vec<WindowOrder> {
    let mut out = Vec::new();
    let mut at = 0usize;
    for i in 0..count {
        let Some(&control) = data.get(at) else {
            trace!("orders update: {} of {count} orders missing", count - i);
            break;
        };
        let len = match control & 0x03 {
            TS_SECONDARY if control >> 2 == TS_ALTSEC_WINDOW => {
                let Some(size) = crate::cursor::le16(data, at + 1) else {
                    trace!("window order truncated");
                    break;
                };
                let size = size as usize;
                let Some(order) = data.get(at..at + size).filter(|_| size >= 3) else {
                    trace!("window order size {size} exceeds the update");
                    break;
                };
                match parse_window_order(order) {
                    Ok(o) => out.push(o),
                    Err(e) => trace!("window order skipped: {e}"),
                }
                size
            }
            0x03 => {
                // Secondary order: orderLength is the length minus 13.
                let Some(raw) = crate::cursor::le16(data, at + 1) else {
                    break;
                };
                let total = (raw as i16 as isize + 13).max(6) as usize;
                trace!(
                    "secondary drawing order type {:?} skipped",
                    data.get(at + 5)
                );
                total
            }
            _ => {
                trace!(
                    "drawing order {control:#04x} not negotiated; {} orders dropped",
                    count - i
                );
                break;
            }
        };
        at += len;
    }
    out
}

/// TS_FP_UPDATE_ORDERS body (MS-RDPEGDI 2.2.2.2): numberOrders, orderData.
pub fn parse_fastpath_orders(update: &[u8]) -> Result<Vec<WindowOrder>> {
    let mut r = Reader::new(update);
    let count = r.u16()?;
    Ok(parse_order_data(count, r.rest()))
}

/// TS_UPDATE_ORDERS_PDU_DATA after the share data header (MS-RDPEGDI
/// 2.2.2.1): updateType, pad, numberOrders, pad, orderData.
pub fn parse_slowpath_orders(update: &[u8]) -> Result<Vec<WindowOrder>> {
    let mut r = Reader::new(update);
    let ty = r.u16()?;
    if ty != UPDATETYPE_ORDERS {
        return proto(format!("update type {ty} is not orders"));
    }
    r.u16()?;
    let count = r.u16()?;
    r.u16()?;
    Ok(parse_order_data(count, r.rest()))
}
