# rdp-rs agent rules

Read `E:/Development/AGENTS.md` and `E:/Development/general-agent-rules.md` first; they hold the hard stops and shared rules. This file adds the project's own rules.

## Project

- RDP client written from the Microsoft Open Specifications (MS-RDPBCGR, MS-CSSP, MS-NLMP, MS-RDPEGDI, MS-RDPECLIP, MS-RDPEFS, MS-RDPEDYC, MS-RDPEDISP, ...). Cite the spec section in doc comments for every PDU.
- Crates: `crates/rdp` (protocol library, no UI), `crates/rdpc` (manager and session windows: winit + softbuffer + `ffwd-render`).
- Pair Desk project: `rdp-rs` (issues `RDP-n`). Every change belongs to an issue.

## Build and test

- Machine-local `.cargo/config.toml` (from `.cargo/config.example.toml`): shared sccache, rust-lld, output in `E:/Development/_cache/cargo-target/rdp-rs`. Never commit `.cargo/config.toml`.
- Toolchain pinned in `rust-toolchain.toml`.
- Checks: `cargo build`, `cargo clippy --all-targets` (no warnings), `cargo test` (fast unit tests only; no load tests).
- Protocol code gets unit tests with spec example bytes where the spec has them, and round-trip tests otherwise. Tests must be able to fail.

## Protocol rules

- Parsing never panics on server data: bounds-checked `cursor::Reader`, errors as `Error::Protocol`.
- A virtual channel error disables that channel; it never ends the session (`channel.rs`).
- Never log secrets: no passwords, NTLM keys or credential PDUs in `trace!` output (the Client Info PDU is redacted in `-v` dumps).
- Sharing features (clipboard, drives, printers, smart cards) are off unless the user enables them, and can be toggled live without reconnecting.

## UI rules

- Renderer path of ffwd decision 0001: no frame loop, damage-only presents, solid fills (cheap over RDP). Agent runs never open visible windows; use `rdpc --snapshot-ui` for look review.
