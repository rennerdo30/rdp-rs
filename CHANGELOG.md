# Changelog

## Unreleased

The first version of rdp-rs: an RDP client written from the Microsoft Open
Specifications. It is an early prototype; expect rough edges.

- **Connection:** X.224 negotiation (TLS, NLA, NLA with early user authorization), TLS upgrade, CredSSP v6 with NTLMv2 (MIC, key exchange, sealing, public key binding), MCS/GCC, licensing, capability exchange, finalization and reactivation.
- **Display:** fast-path and slow-path bitmap updates; planar (32 bpp) and interleaved RLE (15/16/24 bpp) codecs; live resize to the window via Display Control.
- **Input:** fast-path keyboard (scancodes) and mouse (buttons, wheel); a Ctrl+Alt+Del button.
- **Sharing,** off until you enable it and switchable live without reconnecting:
  - clipboard (Unicode text and files, both ways);
  - shared folders (drive redirection, confined to the shared folder);
  - printers (Easy Print / XPS, no drivers on the server);
  - smart cards (forwarded to the local WinSCard);
  - sound (PCM).
- **Cursor:** the remote pointer shapes as native cursors.
- **Client (`rdpc`, Windows):** one window with a connections sidebar, a tab per session and a control panel per session. Command line sessions, a headless `--screenshot` mode and `--version`.
- **Connections:** groups with inheritance (credentials, display and sharing taken from the nearest group that sets them) and Connect all. Settings live in `%APPDATA%\rdp-rs\connections.json`; with a master password everything moves into an encrypted vault (Argon2id + XChaCha20-Poly1305), which can also hold passwords. "Remember on this PC" keeps the key with Windows DPAPI.
- **Auto-reconnect:** a network drop reconnects up to five times, using the server's auto-reconnect cookie.
- **Windows setup:** a per-user installer (no admin rights) with a Start menu entry, an Installed apps entry and an uninstaller, plus a portable zip. The app and the setup carry the rdp-rs icon. Installed copies can update themselves from GitHub releases; every download is checked against the release's `SHA256SUMS.txt`.

Not yet: Kerberos, server certificate validation, the graphics pipeline (RDPGFX / H.264), RemoteFX, drawing orders, bulk compression, audio input, RD Gateway, UDP transport, RDS licensing and legacy RDP security.
