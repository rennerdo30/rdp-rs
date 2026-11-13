# rdp-rs

A Remote Desktop Protocol client written from scratch in Rust from the
Microsoft Open Specifications. Only the TLS layer (rustls) and SHA-256/RNG
(ring) come from crates. Every RDP layer is implemented here, along with MD4,
MD5, HMAC-MD5, RC4, ASN.1 DER/BER/PER, NTLMv2 and CredSSP.

Status: **prototype of the minimal client**, not yet tested against a live server.

## Layout

| Crate | What |
|---|---|
| `crates/rdp` | Protocol library: connection sequence, session loop, codecs |
| `crates/rdpc` | Prototype client: window mode (minifb) or headless PNG screenshot |

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
transport, auto-reconnect, RDS licensing (LICENSE_REQUEST), legacy RDP security.

## Usage

```
cargo build --release
# password from RDP_PASSWORD or an interactive prompt
target/release/rdpc 192.168.1.20 -u 'DOMAIN\user' --size 1280x800
target/release/rdpc 192.168.1.20 -u user --screenshot desk.png --wait 15 -v
```

Window mode: Ctrl+Alt+F12 closes the client locally. `-v` traces the protocol to stderr.

## Tests

`cargo test` covers the crypto primitives (RFC vectors), NTLMv2 (MS-NLMP 4.2.4
vectors), DER/TSRequest encoding, MCS/GCC/PDU framing, both bitmap codecs,
fast-path reassembly and input encoding.
