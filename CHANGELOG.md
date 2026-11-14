# Changelog

## Unreleased

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
