# rdp-rs

A Remote Desktop Protocol client written from scratch in Rust from the
Microsoft Open Specifications. Only the TLS layer (rustls) and SHA-256/RNG
(ring) come from crates. Every RDP layer is implemented here, along with MD4,
MD5, HMAC-MD5, RC4, ASN.1 DER/BER/PER, NTLMv2 and CredSSP.

Status: **prototype of the minimal client.** It completes the full connection
sequence against Windows (NLA, licensing, capability exchange, finalization,
logon). Desktop rendering and input against a live server are not confirmed yet
(Pair Desk RDP-1).

## Layout

| Crate | What |
|---|---|
| `crates/rdp` | Protocol library: connection sequence, session loop, codecs |
| `crates/rdpc` | Client: connection manager and session windows, headless PNG screenshot |

## What the prototype implements

- X.224 negotiation (TLS, NLA, NLA with early user authorization), TLS upgrade
- NLA: CredSSP v6 with NTLMv2 (MIC, key exchange, sealing, public key binding)
- MCS/GCC connect, erect domain, attach user, channel joins
- Client info (auto-logon), licensing ("valid client" path), capability exchange, finalization
- Fast-path and slow-path bitmap updates, fragment reassembly
- Codecs: planar (32 bpp, RLE and raw) and interleaved RLE (15/16/24 bpp), uncompressed
- Fast-path keyboard (scancodes) and mouse input (buttons, wheel)
- Reactivation (Deactivate All followed by a new Demand Active), error info reporting

## Not yet

Kerberos, server certificate validation (fingerprint printed only), virtual
channels (clipboard, audio, drives), the graphics pipeline (RDPGFX/H.264),
RemoteFX, drawing orders, bulk compression, pointer shapes, RD Gateway, UDP
transport, auto-reconnect, RDS licensing (LICENSE_REQUEST), legacy RDP security,
GPU presentation of the session view (planned, RDP-2).

## Usage

The password comes from `RDP_PASSWORD` or an interactive prompt (in the
manager: the Password field, never saved). In `cmd.exe`, write `DOMAIN\user`
without quotes (cmd keeps single quotes literally; rdpc strips one matching
pair anyway).

```
# connection manager: saved connections, connect, running sessions
cargo run -p rdpc

# one session window straight from the command line
cargo run -p rdpc -- 192.168.1.20 -u DOMAIN\user
cargo run -p rdpc -- 192.168.1.20:3390 -u user -d DOMAIN --size 1600x900

# headless: wait until the screen settles, save a PNG, disconnect
cargo run -p rdpc -- 192.168.1.20 -u DOMAIN\user --screenshot desk.png --wait 15

# protocol trace to stderr (sent PDUs as hex; the Client Info PDU with the password is redacted)
cargo run -p rdpc -- 192.168.1.20 -u DOMAIN\user -v

# render the manager offscreen with sample data (look review, no window)
cargo run -p rdpc -- --snapshot-ui manager.png --scale 1.5

# optimized build
cargo run --release -p rdpc
```

Manager keys: Enter connects, Tab moves between fields, Ctrl+N new connection,
Ctrl+S save, Ctrl+V paste, Ctrl+A select the field, Up/Down move through the list.

On the owner's PC, `.cargo/config.toml` (copied from `.cargo/config.example.toml`)
uses the shared sccache and rust-lld and puts build output in
`E:/Development/_cache/cargo-target/rdp-rs`, so the binary is
`E:/Development/_cache/cargo-target/rdp-rs/debug/rdpc.exe`.

## UI

Same renderer path as ffwd (its decision 0001): winit for windows and input,
softbuffer for presents, drawing on the CPU with `ffwd-render` (a path
dependency on `../ffwd` for now). There is no frame loop, and only changed
rectangles are presented: the manager diffs frames in 64 x 16 tiles, and
sessions present the rectangles of each bitmap update. That keeps the client
cheap to run over RDP itself. Saved connections live in
`%APPDATA%\rdp-rs\connections.json`; passwords are never stored.

## Tests

`cargo test` covers the crypto primitives (RFC vectors), NTLMv2 (MS-NLMP 4.2.4
vectors), DER/TSRequest encoding, MCS/GCC/PDU framing, both bitmap codecs,
fast-path reassembly, input encoding and the manager's text field.
