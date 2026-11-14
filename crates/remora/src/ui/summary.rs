//! The editor's Summary column on wide windows: what Connect will do with
//! the connection as it stands in the form (saved or not), in plain words,
//! with the group each inherited part comes from.

use ffwd_render::{Canvas, Rect, TextEngine};

use super::{Field, Fonts, SIZES, Ui, home, normalize_path, preset_name};
use crate::icons::Icon;
use crate::kit::{Font, Kit, Lead};
use crate::store::{Connection, Inherit, Opens};
use crate::theme::{self, Tone, pal, size};

/// One line of the summary.
struct Line {
    icon: Icon,
    title: String,
    detail: String,
    /// The group this part comes from (inherited).
    from: Option<String>,
    tone: Tone,
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "a, b and c".
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

impl Ui {
    /// The connection as the form shows it now (unsaved edits included);
    /// the stored one fills in what the form cannot express.
    fn form_preview(&self) -> Connection {
        let mut c = self
            .selected
            .and_then(|i| self.store.connections.get(i))
            .cloned()
            .unwrap_or_default();
        let text = |f: Field| self.field(f).text.trim().to_string();
        c.name = text(Field::Name);
        c.host = text(Field::Host);
        c.port = text(Field::Port).parse().unwrap_or(3389);
        c.user = text(Field::User);
        c.gateway = text(Field::Gateway);
        c.group = normalize_path(&text(Field::GroupPath));
        c.kerberos = self.kerberos;
        c.inherit = self.form_inherit();
        (c.width, c.height) = if self.size == 0 {
            (0, 0)
        } else {
            SIZES[self.size - 1]
        };
        c.options = self.opts.clone();
        c.opens = self.opens;
        c.apps = self.apps.clone();
        if !self.field(Field::Password).text.is_empty() {
            c.password = Some(String::new());
        }
        c
    }

    fn summary_lines(&self) -> Vec<Line> {
        let own = self.form_preview();
        let r = self.store.resolve(&own);
        let from = |pick: fn(&Inherit) -> bool| {
            self.store
                .source_of(&own.group, &own.inherit, pick)
                .map(|g| g.name().to_string())
        };
        let mut out = Vec::new();

        // What it opens.
        if r.opens == Opens::Apps {
            let names: Vec<&str> = r.apps.iter().take(3).map(|a| a.name.as_str()).collect();
            out.push(Line {
                icon: Icon::Apps,
                title: format!("Opens {}", plural(r.apps.len(), "app", "apps")),
                detail: if names.is_empty() {
                    "Add the programs on the General page".into()
                } else {
                    format!("Each in its own window: {}", and_list(&names))
                },
                from: None,
                tone: Tone::Accent,
            });
        } else {
            out.push(Line {
                icon: Icon::Window,
                title: "Opens the whole desktop".into(),
                detail: "In a tab; full screen or on chosen monitors from the bar".into(),
                from: None,
                tone: Tone::Accent,
            });
        }

        // Size, monitors, scale.
        let o = &r.options;
        let monitors = o.monitors.len();
        let title = if monitors > 1 {
            format!("Spans {monitors} monitors")
        } else if r.width == 0 {
            "Fits the window".into()
        } else {
            format!("{} × {} desktop", r.width, r.height)
        };
        let scale = o.scale.map_or("scaled like this PC".to_string(), |v| {
            format!("{v} % scale")
        });
        out.push(Line {
            icon: if monitors > 1 {
                Icon::Monitors
            } else {
                Icon::Monitor
            },
            title,
            detail: format!(
                "{scale} · {}",
                if r.width == 0 && monitors < 2 {
                    "follows the window as you resize it"
                } else {
                    "fixed when the session starts"
                }
            ),
            from: from(|i| i.display),
            tone: Tone::Info,
        });

        // Quality.
        let q = &o.quality;
        out.push(Line {
            icon: Icon::Sliders,
            title: format!("{} quality", preset_name(q.connection)),
            detail: format!(
                "{}-bit colour · {}",
                q.color_depth,
                if q.gfx {
                    "GFX graphics pipeline"
                } else {
                    "bitmap graphics"
                }
            ),
            from: from(|i| i.display),
            tone: Tone::Info,
        });

        // Sharing.
        let mut shared: Vec<&str> = Vec::new();
        for (on, name) in [
            (o.clipboard, "clipboard"),
            (o.sound, "sound"),
            (o.microphone, "microphone"),
            (o.printers, "printers"),
            (o.smart_cards, "smart cards"),
        ] {
            if on {
                shared.push(name);
            }
        }
        let folders = o.drives.len();
        let folder_text = plural(folders, "folder", "folders");
        if folders > 0 {
            shared.push(&folder_text);
        }
        out.push(Line {
            icon: if shared.is_empty() {
                Icon::Lock
            } else {
                Icon::Clipboard
            },
            title: match shared.len() {
                0 => "Shares nothing".into(),
                1 | 2 => format!("Shares {}", and_list(&shared)),
                n => format!("Shares {}, {} and {} more", shared[0], shared[1], n - 2),
            },
            detail: match shared.len() {
                0 => "Turn on clipboard, sound or folders on the Sharing page".into(),
                1 | 2 => "Changeable live from the session's panel".into(),
                _ => {
                    let mut d = and_list(&shared);
                    d[..1].make_ascii_uppercase();
                    d
                }
            },
            from: from(|i| i.sharing),
            tone: if shared.is_empty() {
                Tone::Neutral
            } else {
                Tone::Success
            },
        });

        // Sign-in.
        let user = if r.user.is_empty() {
            "no user yet".to_string()
        } else {
            r.user.clone()
        };
        let (title, detail, icon) = if r.kerberos {
            (
                "Signs in with Windows".to_string(),
                if r.user.is_empty() {
                    "As you, with Kerberos (NTLM as fallback)".to_string()
                } else {
                    format!("As {user}, with Kerberos (NTLM as fallback)")
                },
                Icon::ShieldCheck,
            )
        } else if r.password.is_some() {
            (
                format!("Signs in as {user}"),
                "With the saved password, no questions".into(),
                Icon::Key,
            )
        } else {
            (
                format!("Signs in as {user}"),
                "Asks for the password each time".into(),
                Icon::User,
            )
        };
        out.push(Line {
            icon,
            title,
            detail,
            from: from(|i| i.credentials),
            tone: Tone::Warning,
        });

        // Route.
        out.push(Line {
            icon: Icon::Globe,
            title: if r.gateway.is_empty() {
                "Direct connection".into()
            } else {
                format!("Through {}", r.gateway)
            },
            detail: if r.gateway.is_empty() {
                format!(
                    "To {}{}",
                    if r.host.is_empty() {
                        "the host"
                    } else {
                        &r.host
                    },
                    if r.port == 3389 {
                        String::new()
                    } else {
                        format!(" on port {}", r.port)
                    }
                )
            } else {
                "RD Gateway over HTTPS, with the same sign-in".into()
            },
            from: from(|i| i.credentials).filter(|_| !r.gateway.is_empty()),
            tone: Tone::Info,
        });

        // History.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let now = self.home_clock().unwrap_or(now);
        out.push(Line {
            icon: Icon::Clock,
            title: match own.last_used {
                Some(t) => format!("Last used {}", home::ago(now, t)),
                None => "Not used yet".into(),
            },
            detail: match own.last_duration {
                Some(d) => format!("The last session ran {}", home::span(d)),
                None if self.selected.is_none() => "Save keeps it in the sidebar".into(),
                None => "Its first session starts with Connect".into(),
            },
            from: None,
            tone: Tone::Neutral,
        });
        out
    }

    /// The Summary card at (x, y), `w` wide; returns its bottom.
    pub(super) fn paint_summary(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let lines = self.summary_lines();
        let mut k = Kit::new(cv, te, f, s);
        k.section(x, y - p(2.0), w, "Summary", None);
        let y = y + p(28.0);
        let head = p(58.0);
        let row = p(62.0);
        let r = Rect::new(x, y, w, head + lines.len() as i32 * row + p(8.0));
        k.cv.round_border(r, theme::radius::CARD * s, c.border, c.surface);
        k.text(
            Font::Semi,
            size::HEADING,
            x + p(18.0),
            y + p(28.0),
            "What Connect will do",
            c.text,
            w - p(36.0),
        );
        k.text(
            Font::Regular,
            size::SMALL - 0.5,
            x + p(18.0),
            y + p(46.0),
            "Follows the form as you edit it",
            c.text_muted,
            w - p(36.0),
        );
        let mut ly = y + head;
        for (n, line) in lines.iter().enumerate() {
            if n > 0 {
                k.cv.fill(Rect::new(x + p(62.0), ly, w - p(80.0), 1), c.divider);
            }
            // A tinted tile with the icon.
            let d = p(32.0);
            let tile = Rect::new(x + p(16.0), ly + (row - d) / 2, d, d);
            k.cv.fill_round(tile, 9.0 * s, line.tone.subtle());
            let fg = match line.tone {
                Tone::Neutral | Tone::Muted => c.text_secondary,
                t => t.color(),
            };
            k.icon_in(line.icon, tile, 16.0, fg);
            let tx = tile.right() + p(14.0);
            let mut tw = x + w - p(16.0) - tx;
            if let Some(g) = &line.from {
                let chip = format!("from {g}");
                let pw = k.pill_width(&chip, Lead::Dot);
                if pw < tw / 2 {
                    let path = self
                        .store
                        .groups
                        .iter()
                        .find(|gr| gr.name() == g)
                        .map(|gr| gr.path.clone())
                        .unwrap_or_default();
                    let swatch = theme::group_solid(self.store.group_color(&path));
                    k.pill(
                        x + w - p(14.0) - pw,
                        ly + p(12.0),
                        &chip,
                        Tone::Neutral,
                        Lead::Swatch(swatch),
                    );
                    tw -= pw + p(8.0);
                }
            }
            k.text(
                Font::Semi,
                size::BODY,
                tx,
                ly + p(27.0),
                &line.title,
                c.text,
                tw,
            );
            k.text(
                Font::Regular,
                size::SMALL - 0.5,
                tx,
                ly + p(45.0),
                &line.detail,
                c.text_muted,
                x + w - p(16.0) - tx,
            );
            ly += row;
        }
        r.bottom()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_follows_the_form_and_names_inherited_parts() {
        let mut m = super::super::sample_form(0);
        let lines = m.summary_lines();
        let titles: Vec<&str> = lines.iter().map(|l| l.title.as_str()).collect();
        assert!(titles.contains(&"Opens the whole desktop"), "{titles:?}");
        assert!(titles.contains(&"Spans 2 monitors"), "{titles:?}");
        assert!(
            titles.contains(&"Shares clipboard, sound and 2 more"),
            "{titles:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.detail == "Clipboard, sound, microphone and 1 folder")
        );
        // Edits show before saving.
        m.opts.clipboard = false;
        m.opts.sound = false;
        m.opts.microphone = false;
        m.opts.drives.clear();
        assert!(
            m.summary_lines()
                .iter()
                .any(|l| l.title == "Shares nothing")
        );
        // A member of Work takes its sign-in from the group.
        let mut g = super::super::sample(false);
        g.select(0);
        let lines = g.summary_lines();
        let sign_in = lines
            .iter()
            .find(|l| l.title.starts_with("Signs in"))
            .unwrap();
        assert_eq!(sign_in.from.as_deref(), Some("Work"));
        assert_eq!(and_list(&["a", "b", "c"]), "a, b and c");
    }
}
