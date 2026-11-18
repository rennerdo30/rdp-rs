# remora-link

The protocol between [Remora](https://remora.renner.dev) and its server
helper, `remora-agent`: message framing, Noise-encrypted sessions
(`Noise_XX_25519_ChaChaPoly_BLAKE2s`), pairing with a short authentication
string, and resumable file transfer with per-block BLAKE3 hashes. Shared by
the client and the helper; published so that the client can be installed with
`cargo install remora-client`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
