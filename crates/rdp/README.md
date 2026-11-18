# rdp-proto

The Remote Desktop Protocol stack behind [Remora](https://remora.renner.dev),
written from scratch in Rust from the Microsoft Open Specifications: the
connection sequence, NLA (CredSSP and NTLMv2), legacy RDP security, the bitmap
codecs, the graphics pipeline, bulk compression, virtual channels (clipboard,
drive and device redirection, sound, dynamic channels), RD Gateway, UDP
transport and a server side. Only TLS (rustls) and SHA-256 and randomness
(ring) come from other crates.

The library is named `rdp` in code:

```toml
[dependencies]
rdp-proto = "0.1"
```

```rust
use rdp::Config;
```

It has no UI and builds on Windows, macOS and Linux. The feature list, with
the specification for each, is in the
[repository README](https://github.com/rennerdo30/rdp-rs#rdp-coverage-about-91-).

This project is not affiliated with or endorsed by Microsoft.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
