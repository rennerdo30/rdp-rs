# Remora Host (experimental)

An RDP server written from the Microsoft Open Specifications, on the `rdp`
crate's server module. Remora (or our `rdp` client) connects to it and sees
the machine's desktop, with keyboard and mouse. This is the bare minimum
version: no NLA, no clipboard, no audio, one monitor, one client at a time.

## What works

- TLS only (PROTOCOL_SSL), with a self-signed certificate made on first run.
  A client that offers no TLS is refused (SSL_REQUIRED_BY_SERVER); plaintext
  and legacy RDP security are never used. A client that offers NLA (CredSSP)
  next to TLS, as Remora and mstsc do, gets TLS.
- The host's own password (any user name), checked against an Argon2id hash.
  Wrong passwords are answered after a delay that doubles per failure (1 s up
  to 30 s), and after 5 failures in a minute the address is refused for the
  rest of that minute.
- The desktop as uncompressed 32 bpp fast-path bitmap updates of the 64 x 64
  tiles that changed, at most 30 per second; Refresh Rect and Suppress Output.
- Keyboard (scancodes and Unicode) and mouse (move, five buttons, vertical
  and horizontal wheel), fast-path and slow-path.
- Backends: `--demo` (a test pattern that shows the input it receives, on any
  platform) and Windows (DXGI Desktop Duplication of the primary monitor,
  SendInput). Linux and macOS run `--demo` only for now.

## Try it locally with the demo pattern

The demo captures nothing and injects nothing, so it is safe on any PC.

```
remora-host set-password
remora-host run --demo --bind 127.0.0.1
```

`run` prints the certificate fingerprint. Connect with Remora to
`127.0.0.1:3390` (any user name, the host password) and compare the
fingerprint Remora shows with the printed one. You see moving bars and a
seconds counter; your input appears in the picture: a crosshair at the mouse,
the last scancode (green while held), the last typed character as hex and a
square per mouse button. The host's console logs each key and button.

From a terminal: `set RDP_PASSWORD=...` then `remora 127.0.0.1:3390 -u me`.

## Run the real Windows backend (on another machine)

Never on the PC you work at: the client's input goes to that desktop.

1. Copy `remora-host.exe` to the machine (for example a test PC or VM) and
   log on there as the user whose desktop should be shared.
2. `remora-host set-password`, then `remora-host run` (port 3390, all
   interfaces). It prints the fingerprint and a warning that it is reachable
   from the network.
3. Allow the port in the firewall for your network only, for example
   (elevated): `netsh advfirewall firewall add rule name="Remora Host"
   dir=in action=allow protocol=TCP localport=3390 remoteip=localsubnet`.
4. Connect from Remora to `<machine>:3390`. Ctrl+C on the host ends it; the
   firewall rule stays until you delete it
   (`netsh advfirewall firewall delete rule name="Remora Host"`).

The host runs in the user's session: the lock screen, UAC prompts and
Ctrl+Alt+Del (the secure desktop) are not captured and take no input, and
windows of elevated programs ignore its input unless the host runs elevated.
An HDR desktop is not supported yet.

## Security model

- TLS protects everything after the X.224 negotiation. Without NLA the
  password travels inside TLS in the Client Info PDU, so check the
  fingerprint on first connect: a man in the middle with another certificate
  would otherwise learn the password.
- The password is stored only as an Argon2id hash (64 MiB, 3 passes) in
  `password.argon2`; it is never logged.
- The private key is `host-key.bin`: DPAPI-protected (user scope) on Windows,
  a 0600 file in a 0700 directory elsewhere. A key that cannot be read is
  kept as `host-key.bin.old` and a new identity is made (the fingerprint
  changes and clients warn).
- Files live in `%LOCALAPPDATA%\rdp-rs\host` (Windows),
  `~/.local/share/rdp-rs/host` (Linux) or
  `~/Library/Application Support/rdp-rs/host` (macOS); `--data-dir` overrides.
- One client at a time: a second connection is closed at once while a session
  is active (refusing is safer than taking over a session without a prompt).

## What mstsc does

mstsc offers TLS and NLA, so it gets TLS and then asks for credentials it
puts into the Client Info PDU; it warns about the self-signed certificate
first. If mstsc is set to require NLA (or `enablecredsspsupport` and
"authentication level" settings force it), it refuses a server without NLA.
mstsc has not been tried against the host yet.

See `docs/HOST.md` for the architecture and the roadmap.
