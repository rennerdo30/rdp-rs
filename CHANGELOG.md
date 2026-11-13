# Changelog

## Unreleased

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
