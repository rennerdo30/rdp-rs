# Remora Host: architecture

Remora Host is an experimental RDP server (Pair Desk RDP-51, MVP RDP-52). It
serves one machine's desktop to Remora or another RDP client. How to try it
and its security model for users: `crates/remora-host/README.md`.

## Layers

| Layer | Where | What it does |
|---|---|---|
| Protocol | `crates/rdp/src/server/` | Server side of MS-RDPBCGR, sans-IO, next to the client in the same crate and reusing its encoders and parsers |
| Transport | `rdp::server::transport` | TCP, the TLS upgrade (rustls as server), PDU framing; a reader thread, so no socket read timeouts |
| Core | `crates/remora-host/src/host.rs`, `tiles.rs` | Accept loop, one session at a time, logon check, frame pacing, damage tiles, input delivery |
| Identity | `auth.rs`, `cert.rs`, `paths.rs` | Argon2id password hash, rate limit, self-signed certificate with a protected key, data directory |
| Backends | `backend/` | `Capturer`, `InputSink`, `Authenticator`; demo, Windows, unsupported (Linux, macOS) |

### Protocol module (`rdp::server`)

- `connect`: X.224 Connection Request and Confirm/Failure (2.2.1.1, 2.2.1.2),
  MCS Connect Initial/Response (2.2.1.3, 2.2.1.4), GCC client and server data
  blocks, Erect Domain, Attach User, Channel Join, Send Data, Disconnect
  Provider Ultimatum.
- `pdu`: Client Info (2.2.1.11), the licensing "valid client" message
  (2.2.1.12), Demand Active and Confirm Active (2.2.1.13), finalization
  (2.2.1.14 to 2.2.1.22), Set Error Info (2.2.5.1.1), Refresh Rect and
  Suppress Output (2.2.11.2, 2.2.11.3), Shutdown Request (2.2.2.2).
- `input`: fast-path input (2.2.8.1.2) and the slow-path Input Event PDU
  (2.2.8.1.1.3): scancode, Unicode, mouse, extended mouse, relative mouse,
  synchronize.
- `output`: fast-path output PDUs with fragmentation (2.2.9.1.2), uncompressed
  32 bpp TS_BITMAP_DATA (rows bottom-up, width padded to four), the default
  system pointer.
- `session`: the state machine. It is fed one complete PDU at a time and
  queues the PDUs to send; it reports `Logon`, `Active`, `Input`, `Refresh`,
  `Output` (Suppress Output) and `Closed`. The host decides the logon.
- `transport`: `ServerTransport` and `tls_config`.

Every encoder is tested against the client's own parser in the same crate
(and against the spec's example bytes where it has them), so the two halves
cannot drift apart silently.

### Connection sequence (server view)

1. X.224: PROTOCOL_SSL when the client offers it, else RDP_NEG_FAILURE
   SSL_REQUIRED_BY_SERVER and close. NLA is not implemented, so a client that
   offers HYBRID next to SSL gets SSL.
2. TLS handshake with the host certificate.
3. MCS Connect Initial; the response's server data: core (echoing the
   client's requested protocols), security (ENCRYPTION_METHOD_NONE and
   ENCRYPTION_LEVEL_NONE: TLS protects the connection), network (I/O channel
   1003, an id from 1004 for each requested static channel, no message
   channel). Static channels are joined and their data ignored: the simplest
   behaviour every client accepts.
4. Erect Domain, Attach User (user channel after the static channels, as
   Windows numbers them), Channel Joins (unknown channels refused).
5. Client Info: the credentials go to the `Authenticator`. Accepted: the
   licensing "valid client" message and Demand Active. Refused: Set Error
   Info ERRINFO_SERVER_DENIED_CONNECTION, the ultimatum, close.
6. Demand Active with General (fast-path output, refresh rect, suppress
   output), Bitmap (the host's desktop size, 32 bpp), Order (no orders),
   Pointer, Input (scancodes, Unicode, extended mouse, horizontal wheel,
   fast-path), Virtual Channel, Share, Font and Multifragment Update. The
   host's desktop size wins; clients adapt to it.
7. Confirm Active (the client's MaxRequestSize bounds each update), then each
   client finalization PDU is answered: Synchronize, Cooperate, Granted
   Control, Font Map. The session is active; the whole desktop and the
   default pointer are sent.

### Core loop

One thread per session owns the TLS connection. It waits for client PDUs
until the next frame tick (at most 30 per second), handles them, and at the
tick asks the capturer for a frame (no wait), copies the damaged 64 x 64
cells into its shadow copy and sends only the cells whose pixels changed,
plus any area the client asked for again. Nothing is sent while Suppress
Output is in force. Input goes to the `InputSink` as it arrives; a button
event at a new position moves the pointer first. A second client is closed
at once while a session runs; an address with too many wrong passwords is
closed before TLS.

### Backend traits

```rust
trait Capturer: Send {
    fn size(&self) -> (u16, u16);
    fn next_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame<'_>>>;
}
trait InputSink: Send {
    fn key(&mut self, scancode: u16, extended: bool, down: bool);
    fn unicode(&mut self, ch: u16, down: bool);
    fn mouse_move(&mut self, x: u16, y: u16);
    fn button(&mut self, b: Button, down: bool);
    fn wheel(&mut self, delta: i16, horizontal: bool);
    fn sync(&mut self, toggles: Toggles);
}
trait Authenticator: Send + Sync {
    fn check(&self, user: &str, domain: &str, password: &str) -> bool;
}
```

A `Frame` is a borrowed BGRA view (rows top-down, a stride) with its damage
rectangles; the first frame covers everything.

- Demo: a gradient and checkerboard; animated, a moving bar pair and a
  seconds counter; the input it receives is drawn into the picture. The
  end-to-end tests use its static mode.
- Windows: DXGI Desktop Duplication of the first output of the default
  adapter (move and dirty rectangles as damage, re-created after
  ACCESS_LOST); SendInput with scancodes, Unicode, absolute coordinates over
  the virtual desktop, X buttons and both wheels; Pause (E1) as VK_PAUSE;
  synchronize toggles Caps, Num and Scroll Lock to the client's state.
- Linux, macOS: an error that says the platform is not supported yet.

## Security model

TLS only; the password inside TLS in the Client Info PDU (no NLA yet), so the
client must check the certificate fingerprint (Remora asks on first connect).
The password is stored as an Argon2id hash; checks use Argon2's constant-time
comparison; failures are delayed per address (doubling, up to 30 s) and an
address is refused after 5 failures in a minute. The TLS key is DPAPI-wrapped
on Windows and a 0600 file elsewhere. The password is never logged; its
parsed copy is wiped when the Client Info has been checked (the received TLS
buffers are not).

## Tests

- `rdp::server` unit tests: every PDU against the client's parser or the
  spec's example bytes, malformed input as errors, and the session state
  machine through a scripted client.
- `crates/remora-host/tests/e2e.rs`: the host on 127.0.0.1 with the static
  demo picture and a recording input sink, and the `rdp` client:
  `client_sees_the_desktop_and_its_input_arrives` (pixel-exact first frame,
  keyboard, Unicode, mouse, both wheels, live updates, a second client
  refused), `wrong_password_is_refused_without_a_picture`,
  `client_without_tls_is_refused`.
- The Windows capture and input code is compiled and its pure mapping logic
  is tested; it never runs in tests (it would show the screen and type into
  the desktop of the machine running them).

## Roadmap

1. NLA with the host's own credentials (CredSSP with NTLM as the server, as
   GNOME Remote Desktop does), so the password never reaches the host in
   the clear and mstsc's NLA requirement is met. Optionally Windows accounts
   through SSPI.
2. The graphics pipeline (MS-RDPEGFX) with H.264 (Media Foundation, VA-API,
   VideoToolbox) or a lossless codec; until then a compressed bitmap codec
   (planar or interleaved RLE) to cut bandwidth.
3. Clipboard (MS-RDPECLIP) and audio output (MS-RDPEA).
4. Several monitors (all outputs, Monitor Layout PDU) and desktop resize.
5. A Windows service that follows the console session and the secure desktop
   (lock screen, UAC), with input for elevated windows.
6. Linux (xdg-desktop-portal RemoteDesktop and ScreenCast with PipeWire; X11
   XShm and XTest) and macOS (ScreenCaptureKit, CGEvent, TCC permissions)
   backends.
7. The pointer shape (color and large pointers) and a cursor-only update path.
