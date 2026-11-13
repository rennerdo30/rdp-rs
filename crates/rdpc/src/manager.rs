//! The connection manager: saved connections on the left, the edit form and
//! running sessions on the right, a status bar at the bottom.
//!
//! Painting is immediate: every paint lays out the whole window and records
//! hit rectangles. The window diffs frames to find what changed, so only
//! changed tiles are presented (cheap for RDP encoders).

use ffwd_render::{Canvas, FontId, Rect, TextEngine};

use crate::store::{Connection, Store};
use crate::text_field::TextField;
use crate::theme::*;

pub struct Fonts {
    pub ui: FontId,
    pub semi: FontId,
}

pub fn load_fonts(te: &mut TextEngine) -> Option<Fonts> {
    type P = &'static [&'static str];
    #[cfg(windows)]
    let (ui, semi): (P, P) = (
        &[
            r"C:\Windows\Fonts\Inter-Regular.ttf",
            r"C:\Windows\Fonts\segoeui.ttf",
        ],
        &[
            r"C:\Windows\Fonts\Inter-SemiBold.ttf",
            r"C:\Windows\Fonts\seguisb.ttf",
            r"C:\Windows\Fonts\segoeuib.ttf",
        ],
    );
    #[cfg(not(windows))]
    let (ui, semi): (P, P) = (
        &[
            "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ],
        &[
            "/usr/share/fonts/truetype/inter/Inter-SemiBold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ],
    );
    // fontdue parses every outline up front, so the faces load in parallel.
    let read = |paths: P| {
        std::thread::spawn(move || {
            paths
                .iter()
                .find_map(|p| std::fs::read(p).ok())
                .and_then(TextEngine::parse)
        })
    };
    let (a, b) = (read(ui), read(semi));
    let ui = te.add(a.join().ok()??);
    let semi = b.join().ok().flatten().map_or(ui, |f| te.add(f));
    Some(Fonts { ui, semi })
}

pub const SIZES: [(u16, u16); 4] = [(1280, 800), (1600, 900), (1920, 1080), (2560, 1440)];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Filter = 0,
    Name,
    Host,
    Port,
    User,
    Password,
}

const FORM: [Field; 5] = [
    Field::Name,
    Field::Host,
    Field::Port,
    Field::User,
    Field::Password,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hit {
    Row(usize),
    New,
    Field(Field),
    Size(usize),
    Connect,
    Save,
    Delete,
    Show(u64),
    Close(u64),
    Dismiss(u64),
}

pub enum RowState {
    Connecting,
    Connected { width: u16, height: u16, bpp: u16 },
    Ended(String),
    Failed(String),
}

pub struct SessionRow {
    pub id: u64,
    pub name: String,
    pub host: String,
    pub state: RowState,
}

pub enum Action {
    Connect { name: String, cfg: Box<rdp::Config> },
    Show(u64),
    Close(u64),
}

pub enum Key {
    Char(char),
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    Tab,
    BackTab,
    Enter,
    Esc,
    SelectAll,
    Paste(String),
    New,
    Save,
}

pub struct Manager {
    store: Store,
    selected: Option<usize>,
    fields: [TextField; 6],
    size: usize,
    focus: Option<Field>,
    pub sessions: Vec<SessionRow>,
    hover: Option<Hit>,
    press: Option<Hit>,
    hits: Vec<(Rect, Hit)>,
    field_rects: Vec<(Field, Rect)>,
    message: Option<(String, u32)>,
    pub scale: f32,
    pub renderer: String,
}

impl Manager {
    pub fn new(store: Store, scale: f32) -> Manager {
        let mut m = Manager {
            store,
            selected: None,
            fields: Default::default(),
            size: 0,
            focus: None,
            sessions: Vec::new(),
            hover: None,
            press: None,
            hits: Vec::new(),
            field_rects: Vec::new(),
            message: None,
            scale,
            renderer: "CPU".into(),
        };
        m.fields[Field::Password as usize] = TextField::secret();
        if m.store.connections.is_empty() {
            m.new_connection();
        } else {
            m.select(0);
        }
        m
    }

    fn field(&self, f: Field) -> &TextField {
        &self.fields[f as usize]
    }

    fn field_mut(&mut self, f: Field) -> &mut TextField {
        &mut self.fields[f as usize]
    }

    pub fn set_message(&mut self, text: impl Into<String>, color: u32) {
        self.message = Some((text.into(), color));
    }

    fn select(&mut self, i: usize) {
        let Some(c) = self.store.connections.get(i).cloned() else {
            return;
        };
        self.selected = Some(i);
        self.field_mut(Field::Name).set(&c.name);
        self.field_mut(Field::Host).set(&c.host);
        self.field_mut(Field::Port).set(&c.port.to_string());
        self.field_mut(Field::User).set(&c.user);
        self.field_mut(Field::Password).set("");
        self.size = SIZES
            .iter()
            .position(|&s| s == (c.width, c.height))
            .unwrap_or(0);
        self.focus = Some(Field::Password);
    }

    fn new_connection(&mut self) {
        self.selected = None;
        for f in FORM {
            self.field_mut(f).set("");
        }
        self.field_mut(Field::Port).set("3389");
        self.size = 0;
        self.focus = Some(Field::Host);
    }

    fn form(&self) -> Result<Connection, String> {
        let host = self.field(Field::Host).text.trim().to_string();
        if host.is_empty() {
            return Err("Enter a host name or address.".into());
        }
        let port = match self.field(Field::Port).text.trim() {
            "" => 3389,
            p => p
                .parse::<u16>()
                .map_err(|_| format!("Port {p:?} is not a number from 1 to 65535."))?,
        };
        let user = self.field(Field::User).text.trim().to_string();
        if user.is_empty() {
            return Err("Enter a user name.".into());
        }
        let name = match self.field(Field::Name).text.trim() {
            "" => host.clone(),
            n => n.to_string(),
        };
        let (width, height) = SIZES[self.size];
        Ok(Connection {
            name,
            host,
            port,
            user,
            width,
            height,
        })
    }

    fn save(&mut self) {
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => return self.set_message(e, ERR),
        };
        let name = c.name.clone();
        match self.selected {
            Some(i) => self.store.connections[i] = c,
            None => {
                self.store.connections.push(c);
                self.selected = Some(self.store.connections.len() - 1);
            }
        }
        self.field_mut(Field::Name).set(&name);
        match self.store.save() {
            Ok(()) => self.set_message(format!("Saved {name}."), TEXT_2),
            Err(e) => self.set_message(e, ERR),
        }
    }

    fn delete(&mut self) {
        let Some(i) = self.selected else { return };
        let gone = self.store.connections.remove(i);
        if let Err(e) = self.store.save() {
            return self.set_message(e, ERR);
        }
        self.set_message(format!("Deleted {}.", gone.name), TEXT_2);
        if self.store.connections.is_empty() {
            self.new_connection();
        } else {
            self.select(i.min(self.store.connections.len() - 1));
        }
    }

    fn connect(&mut self) -> Option<Action> {
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => {
                self.set_message(e, ERR);
                return None;
            }
        };
        let mut cfg = rdp::Config::new(&c.host, &c.user, &self.field(Field::Password).text);
        cfg.port = c.port;
        cfg.width = c.width;
        cfg.height = c.height;
        self.set_message(format!("Connecting to {}…", c.host), TEXT_2);
        Some(Action::Connect {
            name: c.name,
            cfg: Box::new(cfg),
        })
    }

    /// Indices of the connections that match the filter.
    fn visible(&self) -> Vec<usize> {
        let q = self.field(Field::Filter).text.to_lowercase();
        (0..self.store.connections.len())
            .filter(|&i| {
                let c = &self.store.connections[i];
                q.is_empty()
                    || [&c.name, &c.host, &c.user]
                        .iter()
                        .any(|s| s.to_lowercase().contains(&q))
            })
            .collect()
    }

    fn hit_at(&self, x: i32, y: i32) -> Option<Hit> {
        self.hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(x, y))
            .map(|(_, h)| *h)
    }

    /// Returns true when the hover target changed (needs a repaint).
    pub fn mouse_move(&mut self, x: i32, y: i32) -> bool {
        let h = self.hit_at(x, y);
        let changed = h != self.hover;
        self.hover = h;
        changed
    }

    pub fn cursor_is_text(&self) -> bool {
        matches!(self.hover, Some(Hit::Field(_)))
    }

    pub fn mouse_down(&mut self, x: i32, y: i32, te: &mut TextEngine, fonts: &Fonts) {
        self.press = self.hit_at(x, y);
        match self.press {
            Some(Hit::Field(f)) => {
                self.focus = Some(f);
                if let Some(&(_, r)) = self.field_rects.iter().find(|(ff, _)| *ff == f) {
                    let display = self.field(f).display();
                    let size = 13.5 * self.scale;
                    let rel =
                        (x - r.x) as f32 - 10.0 * self.scale + self.field_scroll(f, r, te, fonts);
                    let mut caret = 0;
                    let mut prefix = String::new();
                    for c in display.chars() {
                        let before = te.measure(fonts.ui, size, &prefix);
                        prefix.push(c);
                        let after = te.measure(fonts.ui, size, &prefix);
                        if rel < (before + after) / 2.0 {
                            break;
                        }
                        caret += 1;
                    }
                    let tf = self.field_mut(f);
                    tf.caret = caret;
                    tf.all = false;
                }
            }
            Some(_) => {}
            None => self.focus = None,
        }
    }

    pub fn mouse_up(&mut self, x: i32, y: i32) -> Option<Action> {
        let pressed = self.press.take();
        let hit = self.hit_at(x, y);
        if pressed.is_some() && pressed == hit {
            self.activate(hit?)
        } else {
            None
        }
    }

    fn activate(&mut self, hit: Hit) -> Option<Action> {
        match hit {
            Hit::Row(i) => self.select(i),
            Hit::New => self.new_connection(),
            Hit::Field(f) => self.focus = Some(f),
            Hit::Size(i) => self.size = i,
            Hit::Connect => return self.connect(),
            Hit::Save => self.save(),
            Hit::Delete => self.delete(),
            Hit::Show(id) => return Some(Action::Show(id)),
            Hit::Close(id) => return Some(Action::Close(id)),
            Hit::Dismiss(id) => self.sessions.retain(|s| s.id != id),
        }
        None
    }

    pub fn key(&mut self, k: Key) -> Option<Action> {
        match k {
            Key::Enter => return self.connect(),
            Key::Esc => self.focus = None,
            Key::New => self.new_connection(),
            Key::Save => self.save(),
            Key::Tab | Key::BackTab => {
                let back = matches!(k, Key::BackTab);
                let i = self.focus.and_then(|f| FORM.iter().position(|&x| x == f));
                let n = FORM.len();
                let next = match (i, back) {
                    (Some(i), false) => (i + 1) % n,
                    (Some(i), true) => (i + n - 1) % n,
                    (None, false) => 0,
                    (None, true) => n - 1,
                };
                self.focus = Some(FORM[next]);
                self.field_mut(FORM[next]).select_all();
            }
            Key::Up | Key::Down if self.focus.is_none() || self.focus == Some(Field::Filter) => {
                let vis = self.visible();
                if !vis.is_empty() {
                    let pos = self.selected.and_then(|s| vis.iter().position(|&v| v == s));
                    let next = match (pos, matches!(k, Key::Up)) {
                        (Some(p), true) => p.saturating_sub(1),
                        (Some(p), false) => (p + 1).min(vis.len() - 1),
                        (None, _) => 0,
                    };
                    let keep = self.focus;
                    self.select(vis[next]);
                    self.focus = keep;
                }
            }
            other => {
                let f = self.focus?;
                let tf = self.field_mut(f);
                match other {
                    Key::Char(c) => tf.insert(&c.to_string()),
                    Key::Paste(s) => tf.insert(s.lines().next().unwrap_or("")),
                    Key::Backspace => tf.backspace(),
                    Key::Delete => tf.delete(),
                    Key::Left => tf.left(),
                    Key::Right => tf.right(),
                    Key::Home => tf.home(),
                    Key::End => tf.end(),
                    Key::SelectAll => tf.select_all(),
                    _ => {}
                }
            }
        }
        None
    }

    /// How far a field's text is scrolled left so the caret stays visible.
    fn field_scroll(&self, f: Field, r: Rect, te: &mut TextEngine, fonts: &Fonts) -> f32 {
        let tf = self.field(f);
        let size = 13.5 * self.scale;
        let inner = r.w as f32 - 20.0 * self.scale;
        let caret_x = te.measure(
            fonts.ui,
            size,
            &tf.display().chars().take(tf.caret).collect::<String>(),
        );
        (caret_x - inner + 2.0).max(0.0)
    }

    pub fn paint(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.hits.clear();
        self.field_rects.clear();
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        cv.fill(Rect::new(0, 0, w, h), BG);
        let bar_h = p(30.0);
        let body_h = h - bar_h;
        let side_w = p(290.0).min(w * 2 / 5);

        self.paint_sidebar(cv, te, f, Rect::new(0, 0, side_w, body_h));
        cv.fill(Rect::new(side_w, 0, 1, body_h), BORDER_SOFT);
        self.paint_main(cv, te, f, Rect::new(side_w + 1, 0, w - side_w - 1, body_h));

        // Status bar
        let bar = Rect::new(0, body_h, w, bar_h);
        cv.fill(bar, BG_BAR);
        cv.fill(Rect::new(0, body_h, w, 1), BORDER_SOFT);
        let right = format!("{} renderer · damage-only presents", self.renderer);
        let rw = te.measure(f.ui, 12.0 * s, &right) as i32;
        te.draw_in(
            cv,
            f.ui,
            12.0 * s,
            Rect::new(w - rw - p(16.0), body_h, rw + p(16.0), bar_h),
            0.0,
            &right,
            TEXT_4,
        );
        let (msg, color) = self
            .message
            .clone()
            .unwrap_or_else(|| ("Ready".into(), TEXT_3));
        te.draw_in(
            cv,
            f.ui,
            12.0 * s,
            Rect::new(0, body_h, w - rw - p(32.0), bar_h),
            p(16.0) as f32,
            &msg,
            color,
        );
    }

    fn paint_sidebar(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(area, BG_SIDEBAR);
        let pad = p(16.0);

        let head = Rect::new(pad, p(14.0), area.w - 2 * pad, p(28.0));
        te.draw_in(cv, f.semi, 11.5 * s, head, 0.0, "CONNECTIONS", TEXT_3);
        let nw = p(66.0);
        let new_r = Rect::new(head.right() - nw, head.y, nw, head.h);
        self.button(cv, te, f, new_r, "+ New", Style::Ghost, Hit::New);

        let filter_r = Rect::new(pad, p(50.0), area.w - 2 * pad, p(32.0));
        self.text_input(cv, te, f, filter_r, Field::Filter, "Filter");

        let list = Rect::new(0, p(94.0), area.w, area.h - p(94.0));
        let old = cv.set_clip(list);
        let vis = self.visible();
        if self.store.connections.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(pad, list.y + p(8.0), list.w - 2 * pad, p(22.0)),
                0.0,
                "No saved connections yet.",
                TEXT_3,
            );
            te.draw_in(
                cv,
                f.ui,
                12.0 * s,
                Rect::new(pad, list.y + p(30.0), list.w - 2 * pad, p(20.0)),
                0.0,
                "Fill in the form and press Save.",
                TEXT_4,
            );
        } else if vis.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(pad, list.y + p(8.0), list.w - 2 * pad, p(22.0)),
                0.0,
                "No match.",
                TEXT_3,
            );
        }
        let row_h = p(54.0);
        for (n, &i) in vis.iter().enumerate() {
            let r = Rect::new(
                p(8.0),
                list.y + n as i32 * (row_h + p(2.0)),
                area.w - p(16.0),
                row_h,
            );
            if r.y > list.bottom() {
                break;
            }
            let hit = Hit::Row(i);
            let selected = self.selected == Some(i);
            if selected {
                cv.fill_round(r, 6.0 * s, BG_SELECT);
                cv.fill_round(
                    Rect::new(r.x, r.y + p(12.0), p(3.0), r.h - p(24.0)),
                    1.5 * s,
                    ACCENT,
                );
            } else if self.hover == Some(hit) {
                cv.fill_round(r, 6.0 * s, BG_HOVER);
            }
            let c = &self.store.connections[i];
            let dot = self.connection_dot(c);
            let text_w = r.w - p(24.0) - if dot.is_some() { p(16.0) } else { 0 };
            te.draw(
                cv,
                f.semi,
                13.5 * s,
                (r.x + p(14.0)) as f32,
                (r.y + p(23.0)) as f32,
                &c.name,
                TEXT,
                text_w as f32,
            );
            let sub = if c.port == 3389 {
                format!("{} · {}", c.host, c.user)
            } else {
                format!("{}:{} · {}", c.host, c.port, c.user)
            };
            te.draw(
                cv,
                f.ui,
                12.0 * s,
                (r.x + p(14.0)) as f32,
                (r.y + p(41.0)) as f32,
                &sub,
                TEXT_3,
                text_w as f32,
            );
            if let Some(color) = dot {
                cv.fill_circle(
                    (r.right() - p(16.0)) as f32,
                    (r.y + r.h / 2) as f32,
                    4.0 * s,
                    color,
                );
            }
            self.hits.push((r.intersect(list), hit));
        }
        cv.set_clip(old);
    }

    /// Green dot while a session of this connection is up, amber while connecting.
    fn connection_dot(&self, c: &Connection) -> Option<u32> {
        let mut out = None;
        for row in self
            .sessions
            .iter()
            .filter(|r| r.name == c.name && r.host == c.host)
        {
            match row.state {
                RowState::Connected { .. } => return Some(OK),
                RowState::Connecting => out = Some(WARN),
                _ => {}
            }
        }
        out
    }

    fn paint_main(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let x0 = area.x + p(32.0);
        let label_w = p(96.0);
        let fx = x0 + label_w;
        let fw = p(440.0).min(area.right() - p(32.0) - fx).max(p(160.0));
        let form_w = label_w + fw;

        let title = match self.selected {
            Some(i) => self.store.connections[i].name.clone(),
            None => "New connection".into(),
        };
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x0 as f32,
            (area.y + p(46.0)) as f32,
            &title,
            TEXT,
            form_w as f32,
        );
        let sub = match self.selected {
            Some(_) => "Saved connection. The password is never stored.".to_string(),
            None => "Not saved yet. The password is never stored.".to_string(),
        };
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x0 as f32,
            (area.y + p(68.0)) as f32,
            &sub,
            TEXT_3,
            form_w as f32,
        );

        let mut y = area.y + p(92.0);
        let row = p(44.0);
        let fh = p(32.0);
        let label = |cv: &mut Canvas, te: &mut TextEngine, y: i32, text: &str| {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(x0, y, label_w, fh),
                0.0,
                text,
                TEXT_2,
            );
        };

        label(cv, te, y, "Name");
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw, fh),
            Field::Name,
            "Defaults to the host",
        );
        y += row;
        label(cv, te, y, "Host");
        let port_w = p(96.0);
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw - port_w - p(8.0), fh),
            Field::Host,
            "Name or IP address",
        );
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx + fw - port_w, y, port_w, fh),
            Field::Port,
            "Port",
        );
        y += row;
        label(cv, te, y, "User");
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw, fh),
            Field::User,
            r"DOMAIN\user or user@domain",
        );
        y += row;
        label(cv, te, y, "Password");
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw, fh),
            Field::Password,
            "Asked for each connection",
        );
        y += row;
        label(cv, te, y, "Display");
        let mut cx = fx;
        for (i, (sw, sh)) in SIZES.iter().enumerate() {
            let text = format!("{sw} × {sh}");
            let cw = te.measure(f.ui, 12.5 * s, &text) as i32 + p(24.0);
            let r = Rect::new(cx, y + p(2.0), cw, fh - p(4.0));
            let hit = Hit::Size(i);
            let chosen = self.size == i;
            let (border, fill, color) = if chosen {
                (ACCENT_BORDER, BG_CHOSEN, TEXT)
            } else if self.hover == Some(hit) {
                (BORDER_HOVER, CONTROL_HOVER, TEXT_2)
            } else {
                (BORDER, BG, TEXT_3)
            };
            cv.round_border(r, 6.0 * s, border, fill);
            centered(cv, te, f.ui, 12.5 * s, r, &text, color);
            self.hits.push((r, hit));
            cx += cw + p(6.0);
        }
        y += row + p(10.0);

        let bh = p(34.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(fx, y, p(116.0), bh),
            "Connect",
            Style::Primary,
            Hit::Connect,
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(fx + p(124.0), y, p(84.0), bh),
            "Save",
            Style::Secondary,
            Hit::Save,
        );
        if self.selected.is_some() {
            self.button(
                cv,
                te,
                f,
                Rect::new(fx + fw - p(84.0), y, p(84.0), bh),
                "Delete",
                Style::Danger,
                Hit::Delete,
            );
        }
        let hint = "Enter connects · Tab next field · Ctrl+N new · Ctrl+S save";
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            fx as f32,
            (y + bh + p(20.0)) as f32,
            hint,
            TEXT_4,
            fw as f32,
        );

        // Sessions
        y += bh + p(52.0);
        cv.fill(Rect::new(x0, y, form_w, 1), BORDER_SOFT);
        y += p(18.0);
        te.draw_in(
            cv,
            f.semi,
            11.5 * s,
            Rect::new(x0, y, form_w, p(20.0)),
            0.0,
            "SESSIONS",
            TEXT_3,
        );
        y += p(28.0);
        if self.sessions.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                12.5 * s,
                Rect::new(x0, y, form_w, p(22.0)),
                0.0,
                "No sessions. Connect opens the remote desktop in its own window.",
                TEXT_4,
            );
        }
        let srow = p(44.0);
        type Row = (String, String, u32, Vec<(&'static str, Hit, Style)>);
        let rows: Vec<Row> = self
            .sessions
            .iter()
            .map(|r| {
                let (state, color, buttons) = match &r.state {
                    RowState::Connecting => (
                        "Connecting…".to_string(),
                        WARN,
                        vec![("Cancel", Hit::Close(r.id), Style::Secondary)],
                    ),
                    RowState::Connected { width, height, bpp } => (
                        format!("Connected · {width} × {height} · {bpp} bpp"),
                        OK,
                        vec![
                            ("Show", Hit::Show(r.id), Style::Secondary),
                            ("Disconnect", Hit::Close(r.id), Style::Secondary),
                        ],
                    ),
                    RowState::Ended(why) => (
                        format!("Ended: {why}"),
                        TEXT_4,
                        vec![("Dismiss", Hit::Dismiss(r.id), Style::Ghost)],
                    ),
                    RowState::Failed(why) => (
                        format!("Failed: {why}"),
                        ERR,
                        vec![("Dismiss", Hit::Dismiss(r.id), Style::Ghost)],
                    ),
                };
                (r.name.clone(), state, color, buttons)
            })
            .collect();
        for (name, state, color, buttons) in rows {
            if y > area.bottom() {
                break;
            }
            let r = Rect::new(x0, y, form_w, srow);
            cv.round_border(r, 6.0 * s, BORDER_SOFT, BG_BAR);
            cv.fill_circle(
                (r.x + p(16.0)) as f32,
                (r.y + r.h / 2) as f32,
                4.0 * s,
                color,
            );
            let mut bx = r.right() - p(8.0);
            for (text, hit, style) in buttons.iter().rev() {
                let bw = te.measure(f.ui, 12.5 * s, text) as i32 + p(24.0);
                bx -= bw;
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(bx, r.y + p(8.0), bw, r.h - p(16.0)),
                    text,
                    *style,
                    *hit,
                );
                bx -= p(6.0);
            }
            let tx = r.x + p(30.0);
            let name_w = te
                .measure(f.semi, 13.0 * s, &name)
                .min((bx - tx) as f32 * 0.45);
            te.draw_in(
                cv,
                f.semi,
                13.0 * s,
                Rect::new(tx, r.y, name_w as i32 + 1, r.h),
                0.0,
                &name,
                TEXT,
            );
            let state_x = tx + name_w as i32 + p(10.0);
            let state_color = if color == ERR { ERR } else { TEXT_3 };
            te.draw_in(
                cv,
                f.ui,
                12.5 * s,
                Rect::new(state_x, r.y, bx - state_x - p(8.0), r.h),
                0.0,
                &state,
                state_color,
            );
            y += srow + p(6.0);
        }
        cv.set_clip(old);
    }

    fn text_input(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        field: Field,
        placeholder: &str,
    ) {
        let s = self.scale;
        let hit = Hit::Field(field);
        let focused = self.focus == Some(field);
        let border = if focused {
            ACCENT_BORDER
        } else if self.hover == Some(hit) {
            BORDER_HOVER
        } else {
            BORDER
        };
        cv.round_border(r, 6.0 * s, border, BG_INPUT);
        let pad = 10.0 * s;
        let size = 13.5 * s;
        let inner = r.inset((pad - 1.0) as i32, 2);
        let tf = self.field(field).clone();
        let display = tf.display();
        if display.is_empty() && !focused {
            te.draw_in(cv, f.ui, size, r, pad, placeholder, TEXT_4);
        } else {
            let scroll = if focused {
                self.field_scroll(field, r, te, f)
            } else {
                0.0
            };
            let old = cv.set_clip(inner.intersect(cv.clip()));
            let base = r.y as f32 + (r.h as f32 + te.ascent(f.ui, size) * 0.72) / 2.0;
            let x = r.x as f32 + pad - scroll;
            if focused && tf.all {
                let tw = te.measure(f.ui, size, &display);
                cv.fill(
                    Rect::new(
                        x as i32,
                        r.y + (6.0 * s) as i32,
                        tw.ceil() as i32 + 1,
                        r.h - (12.0 * s) as i32,
                    ),
                    BG_TEXT_SELECT,
                );
            }
            if display.is_empty() {
                let after_caret = x + (5.0 * s).round();
                te.draw(
                    cv,
                    f.ui,
                    size,
                    after_caret,
                    base.round(),
                    placeholder,
                    TEXT_4,
                    f32::MAX,
                );
            } else {
                te.draw(cv, f.ui, size, x, base.round(), &display, TEXT, f32::MAX);
            }
            if focused {
                let cx = x + te.measure(
                    f.ui,
                    size,
                    &display.chars().take(tf.caret).collect::<String>(),
                );
                cv.fill(
                    Rect::new(
                        cx.round() as i32,
                        r.y + (7.0 * s) as i32,
                        (1.5 * s).max(1.0).round() as i32,
                        r.h - (14.0 * s) as i32,
                    ),
                    ACCENT,
                );
            }
            cv.set_clip(old);
        }
        self.hits.push((r, hit));
        self.field_rects.push((field, r));
    }

    #[allow(clippy::too_many_arguments)]
    fn button(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        style: Style,
        hit: Hit,
    ) {
        let s = self.scale;
        let hover = self.hover == Some(hit);
        let press = hover && self.press == Some(hit);
        let (border, fill, color) = match style {
            Style::Primary => {
                let fill = if press {
                    ACCENT_PRESS
                } else if hover {
                    ACCENT_HOVER
                } else {
                    ACCENT
                };
                (fill, fill, ACCENT_TEXT)
            }
            Style::Secondary => (
                if hover { BORDER_HOVER } else { BORDER },
                if press {
                    BG_PRESS
                } else if hover {
                    CONTROL_HOVER
                } else {
                    BG_INPUT
                },
                TEXT,
            ),
            Style::Ghost => (
                if hover { BORDER } else { BG_SIDEBAR_OR_BG },
                if press {
                    BG_PRESS
                } else if hover {
                    BG_HOVER
                } else {
                    BG_SIDEBAR_OR_BG
                },
                if hover { TEXT } else { TEXT_2 },
            ),
            Style::Danger => (
                if hover { ERR } else { DANGER_BORDER },
                if press {
                    BG_PRESS
                } else if hover {
                    CONTROL_HOVER
                } else {
                    BG
                },
                ERR,
            ),
        };
        if matches!(style, Style::Ghost) && !hover {
            // Ghost buttons sit on any background: draw only the label at rest.
        } else {
            cv.round_border(r, 6.0 * s, border, fill);
        }
        let font = if matches!(style, Style::Primary) {
            f.semi
        } else {
            f.ui
        };
        centered(cv, te, font, 13.0 * s, r, label, color);
        self.hits.push((r, hit));
    }
}

/// Draws `text` centred in `r` without a width cap (labels are sized to fit),
/// so glyph rounding can never turn a short label into an ellipsis.
fn centered(
    cv: &mut Canvas,
    te: &mut TextEngine,
    font: FontId,
    size: f32,
    r: Rect,
    text: &str,
    color: u32,
) {
    let tw = te.measure(font, size, text);
    let x = r.x as f32 + ((r.w as f32 - tw) / 2.0).max(0.0);
    let base = r.y as f32 + (r.h as f32 + te.ascent(font, size) * 0.72) / 2.0;
    te.draw(
        cv,
        font,
        size,
        x.round(),
        base.round(),
        text,
        color,
        f32::MAX,
    );
}

/// Placeholder colour for ghost buttons at rest (not drawn).
const BG_SIDEBAR_OR_BG: u32 = BG_SIDEBAR;

#[derive(Clone, Copy)]
enum Style {
    Primary,
    Secondary,
    Ghost,
    Danger,
}

/// Sample data for `--snapshot-ui`; never the user's saved connections.
pub fn sample() -> Manager {
    let store = Store::memory(vec![
        Connection {
            name: "Office workstation".into(),
            host: "10.0.0.15".into(),
            port: 3389,
            user: r"CORP\alex".into(),
            width: 1280,
            height: 800,
        },
        Connection {
            name: "Build server".into(),
            host: "build-01.lab.local".into(),
            port: 3389,
            user: r"LAB\builder".into(),
            width: 1920,
            height: 1080,
        },
        Connection {
            name: "Test VM (Windows 11)".into(),
            host: "192.168.56.20".into(),
            port: 3390,
            user: "tester".into(),
            width: 1600,
            height: 900,
        },
    ]);
    let mut m = Manager::new(store, 1.0);
    m.sessions = vec![
        SessionRow {
            id: 1,
            name: "Office workstation".into(),
            host: "10.0.0.15".into(),
            state: RowState::Connected {
                width: 1280,
                height: 800,
                bpp: 32,
            },
        },
        SessionRow {
            id: 2,
            name: "Build server".into(),
            host: "build-01.lab.local".into(),
            state: RowState::Failed(
                "authentication failed: server error 0xc000006d STATUS_LOGON_FAILURE".into(),
            ),
        },
    ];
    m.set_message("Connected to 10.0.0.15.", TEXT_2);
    m
}
