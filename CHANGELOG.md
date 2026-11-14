# Changelog

## Unreleased

- **The session panel folds to a strip and floats.** By default the side panel is now a slim strip of page icons (with tooltips) at the picture's right edge; an icon, the toolbar's Panel button or **Ctrl+Alt+P** (also from inside the session) opens the panel floating over the picture, so the remote desktop is not resized. A click on the picture or **Esc** closes it, and neither reaches the session. The pin in its header docks it beside the picture as before; Remora remembers the choice, and the palette has **Pin/Unpin session panel**. Full screen has no strip.
- **No more repeated reconnects on some servers.** RemoteFX/NSCodec surface commands and drawing orders, new in 0.1.0-beta.2, are off again by default: a Windows server failed its picture encoding with them (0x112F) or dropped the connection after the window's size was applied, which looked like five connection timeouts before compatible mode took over. Remora draws as in 0.1.0-beta.1 again; `--surface-commands` and `--drawing-orders` turn them on for testing.
- **The microphone works.** Remora never told the server at logon that it can record audio (INFO_AUDIOCAPTURE), so the server never opened the microphone channel and the remote PC reported no microphone, whether **Microphone** was switched on before or after connecting. It now does, and the switch works live in a running session.

## 0.1.0-beta.4

- **A sidebar that folds and resizes, and a resizable side panel.** The menu button at the sidebar's top left, **Ctrl+B** or **Collapse sidebar** in the palette folds the sidebar to a narrow rail of icons with each connection's initials, live dot and a tooltip. Drag the sidebar's right edge (200 to 480 px; narrower folds it) and the session side panel's left edge (280 to 560 px); a double-click on an edge resets it. A fitted session is resized once when the drag ends. The fold and both widths are remembered.
- **A connection's RemoteApp programs no longer depend on Opens.** They were listed only while the connection opened Apps, so listing them made **Connect** start the first app instead of the desktop, and switching back to Desktop hid them. Now **Opens** decides only what Connect does (the desktop by default), and the programs are listed under the connection in the sidebar, the editor and the palette whatever it opens; each starts its own RemoteApp window.

## 0.1.0-beta.3

- **Servers whose picture encoding failed now connect.** Some Windows servers gave up about a second after logon with error 0x112F ("the server's graphics subsystem failed"). Remora now reconnects such a session once in compatible mode, without RemoteFX surface commands and drawing orders, as 0.1.0-beta.1 drew the screen, and keeps that mode for the tab's later reconnects.
- **Closer to the specification:** Remora offers a receive buffer large enough for a whole frame at the desktop size (it was 8 MB), and promises the server its cached-bitmap list only when it sends one.
- **Clearer errors:** the server's graphics and monitor errors (0x112C to 0x1136) are named instead of "server rejected a client PDU".
- **Open log** on the error screen opens Explorer with `remora.log` selected, in front of Remora.

## 0.1.0-beta.2

- **rdpc is now Remora.** The app has a new name and a new logo: a remora fish whose body is a screen. The executable is `remora.exe`, the setup is `remora-<version>-setup.exe`, and it installs to `%LOCALAPPDATA%\Programs\Remora` with a Start menu and Installed apps entry named Remora. The protocol library (`rdp`) and the repository (`rdp-rs`) keep their names.
  - **Updating from rdpc 0.1.0-beta.1 needs nothing from you:** rdpc's updater finds the new release as before, and the setup moves the install: it waits for rdpc to close, installs Remora, removes rdpc's program folder, Start menu shortcut and Installed apps entry, and starts Remora.
  - **Your data stays where it is:** saved connections, the vault, settings, known hosts and logs remain in the `rdp-rs` folders under `%APPDATA%` and `%LOCALAPPDATA%`. The diagnostic log is now `remora.log`, and new recordings go to `Videos\Remora` (earlier ones stay in `Videos\rdpc`).
  - A taskbar button pinned to rdpc stops working after the move; pin Remora again.
- **A website and a user guide.** [remora.renner.dev](https://remora.renner.dev) shows Remora with real screenshots, and `docs/` has a getting-started page, a user guide, every keyboard shortcut, troubleshooting for each error screen, and what is stored where.
- **A new look.** Every screen is redesigned: dark and light themes (following Windows or chosen in Settings), a new icon set and calmer layouts.
  - **Home** shows running sessions with live thumbnails, favourites and recent PCs, with quick connect for a name, an address or `user@host:port`.
  - **Ctrl+K command palette** finds sessions, connections, RemoteApp programs, groups and commands; **Ctrl+Alt+K** opens it inside a session.
  - **Connecting** shows each step of the connection. A failure says why, where it stopped and what to try; an ended session says why it ended and offers to reconnect.
  - A floating session toolbar replaces the old bar in full screen.
- **Monitors:** pick any subset of this PC's monitors per connection on a map in the editor. The session gets one borderless window per chosen monitor; the others stay free.
- **RemoteApp:** publish programs per connection and launch them from the sidebar, Home or the palette. Each remote window becomes its own local window with a taskbar button.
- **Sign in with Windows:** Kerberos through Windows (NTLM as fallback), and single sign-on with an empty user name. It's a switch in the editor, inherited like the sign-in.
- **Keyboard:** Remora tells the server this PC's keyboard layout at connect. A new Keyboard option translates typing for a server with a different layout. Text without a key (touch keyboard, emoji panel) is sent as Unicode.
- **Touch and pen** (MS-RDPEI): multi-touch, and pen with pressure and tilt.
- **Picture:** H.264 AVC444 (experimental, with AVC420 as before), drawing orders with glyph, brush and offscreen caches, a persistent bitmap cache per server (at most 100 MB), and RemoteFX and NSCodec surface bits for RDP 7 servers.
- **Sound:** AAC, MP3 and ADPCM playback besides PCM.
- **Connection:** server redirection (session broker and load balancing) while connecting and during a session; network auto-detect with a "Detect automatically" speed, whose results appear in the session panel; the full licensing exchange, with licenses kept in `%LOCALAPPDATA%\rdp-rs\licenses`.

Not yet: UDP transport, RD Gateway over RPC/HTTP, legacy RDP security, serial ports, USB, cameras, plug and play devices, video redirection and shadowing. Most of what is new has been tested against the specifications and in unit tests, not yet against every kind of Windows server. The setup is still not code-signed, so Windows SmartScreen warns on the first run.

## 0.1.0-beta.1

The first beta of rdp-rs: an RDP client written from the Microsoft Open
Specifications, with its own protocol stack (no FreeRDP, no mstsc). Expect
rough edges, and please report them.

- **Connection:** X.224 negotiation (TLS, NLA, NLA with early user authorization), CredSSP v6 with NTLMv2, MCS/GCC, licensing, capability exchange, finalization and reactivation. **RD Gateway** (MS-TSGU HTTP transport over WebSocket, NTLM).
- **Security:** the server certificate is checked before any password is sent: trust on first use, a warning when it changes (`known_hosts.json`). The same check covers the gateway.
- **Display:** fast-path and slow-path bitmap updates (planar, interleaved RLE), the default for the lowest latency. Optional **graphics pipeline** (RDPGFX): ZGFX, ClearCodec, NSCodec, RemoteFX Progressive and H.264 (AVC420, Windows Media Foundation), still experimental. Fit-to-window and live scaling via Display Control; full screen with a hiding bar (Ctrl+Alt+Break).
- **Quality:** connection speed presets (LAN to modem), colour depth (32/24/16/15-bit), desktop experience switches (wallpaper, font smoothing, composition, animations, …) and bulk compression (RDP 5.0 to 6.1).
- **Input:** keyboard with this PC's layout, mouse, Ctrl+Alt+Del. Windows key combinations (Win, Alt+Tab, …) go to the remote session on this PC, remotely, or in full screen only.
- **Sharing,** off until you enable it and switchable live without reconnecting:
  - clipboard (text and files, both ways);
  - shared folders (with a folder picker);
  - printers (Easy Print, no drivers on the server);
  - smart cards;
  - sound, on the output device you choose;
  - microphone, from the device you choose.
- **Sessions:** a tab per session, a quick panel (Sharing, Display, Quality, Session), auto-reconnect with the server's cookie and heartbeat, and recording to MP4.
- **Connections:** an editor in sections (General, Display, Experience, Sharing, Advanced); groups with inheritance and Connect all; an encrypted vault (Argon2id + XChaCha20-Poly1305) for saved passwords with a master password, idle auto-lock, "unlock on this PC" (DPAPI) and encrypted export/import.
- **App:** Settings (security, backup, updates, diagnostic log); asks before quitting with open sessions.
- **Windows setup:** a per-user installer (no admin rights) and a portable zip. Installed copies update themselves from GitHub releases (Automatic, Stable or Beta channel); every download is checked against the release's `SHA256SUMS.txt`.

Not yet: Kerberos, AVC444, multi-monitor, drawing orders, UDP transport, RDS licensing and legacy RDP security. The setup is not code-signed, so Windows SmartScreen warns on the first run.
