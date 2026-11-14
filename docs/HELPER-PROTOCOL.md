# Remora-Link: the server helper protocol

This is the contract between Remora (the client) and `remora-agent` (the
helper that runs in the user's session on the Windows server). The shared
implementation is the `remora-link` crate; the client side is
`crates/remora/src/helper.rs`. Background and owner decisions: Pair Desk
RDP-41 (research, encryption comments), RDP-42 (core), RDP-43 (file
transfer), RDP-44 (links).

Version: **1.1** (`PROTO_MAJOR = 1`, `PROTO_MINOR = 1`). 1.1 adds
`PeerPairing` and `ClientName`: Remora has a persistent key that the helper
pins (section 4.3).

## 1. Channels

The helper opens two dynamic virtual channels with
`WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, name, flags)`:

| Name           | Flags                                             | Carries |
|----------------|---------------------------------------------------|---------|
| `Remora::Ctl`  | `DYNAMIC \| PRI_MED \| NO_COMPRESS`               | handshake, pairing, hello, heartbeat, session info, links, transfer control |
| `Remora::Bulk` | `DYNAMIC \| PRI_LOW \| NO_COMPRESS`               | file data only |

- `NO_COMPRESS` is required: Remora closes a dynamic channel that receives
  compressed data (MS-RDPEDYC 2.2.3.3/2.2.3.4 are not supported).
- One DVC message (one `WriteFile` on the channel handle) is exactly one
  protocol message. The DVC layer fragments and reassembles; Remora caps a
  helper message at `MAX_WIRE + 4096` bytes, whether announced in
  `DYNVC_DATA_FIRST` or sent as one plain `DYNVC_DATA`, and closes the
  channel above it. A message Remora queued before closing (a rejection, an
  error) is sent before the `DYNVC_CLOSE`.
- One helper instance per session: while a channel is open, Remora refuses a
  second `DYNVC_CREATE` for the same name (`E_ACCESSDENIED`) and tells the
  user.
- `Remora::Bulk` is opened only after `HelloAck` arrived on `Remora::Ctl`.
  Remora closes a Bulk channel that opens earlier.
- Remora answers nothing until it knows the RDP connection is TLS-protected
  (it always is today; a legacy-security connection closes both channels).
  Until then it keeps at most 16 messages and 2 MiB per channel; more
  closes the channel.

## 2. Framing

Every protocol message is one frame, little-endian:

| Offset | Size | Field         | Meaning |
|-------:|-----:|---------------|---------|
| 0      | 2    | `type`        | message type (section 6) |
| 2      | 2    | `flags`       | reserved: send 0, ignore on receipt |
| 4      | 4    | `request_id`  | pairs a request with its result; 0 when unused |
| 8      | 4    | `payload_len` | exact payload length |
| 12     | n    | payload       | |

- A frame is at most **1 MiB (1,048,576 bytes) including the header**
  (`frame::MAX_MESSAGE`). Encoders refuse more; decoders refuse a larger
  buffer or `payload_len` before reading.
- A buffer must hold exactly one frame: truncated data or trailing bytes are
  an error.
- Payload field types: `u8/u16/u32/u64` little-endian; `bool` is one byte,
  0 or 1 (anything else is an error); `str` is a `u16` byte length plus
  UTF-8 with a per-field maximum; `blob` is a `u32` length plus bytes;
  `[N]` is N raw bytes. A payload must be consumed exactly.
- After the handshake the whole frame, header included, is encrypted
  (section 3), so none of these fields is visible on the wire.

## 3. Secure session

### 3.1 Handshake

`Noise_XX_25519_ChaChaPoly_BLAKE2s` (Noise Protocol Framework rev. 34,
pattern XX in section 7.5), implemented by the `snow` crate. **The helper is
the initiator, Remora the responder.**

```
helper (initiator)                        Remora (responder)
  -> e                 payload "RLNK" u16 major u16 minor   (plaintext, hashed)
  <- e, ee, s, es      payload "RLNK" u16 major u16 minor   (encrypted)
  -> s, se             payload empty
```

- **Prologue** (Noise section 6), identical on both sides:
  `"Remora-Link/1\0" || channel name || "\0" || token`, where `token` is
  32 zero bytes on `Remora::Ctl` and the `bulk_token` from `HelloAck` on
  `Remora::Bulk`. A different channel or token fails the handshake, so
  messages recorded on one channel never verify on the other.
- **Version:** each side checks the other's major version in its handshake
  payload; a different major fails the handshake (`Error::Version`).
- **Static keys:** the helper and Remora each keep one persistent X25519
  key per user, DPAPI-protected (section 4.1). Remora checks the helper's
  static key (proved by the handshake) against its pin store, the helper
  checks Remora's against its client store (section 4).
- **Why XX and not IK:** IK needs the helper's key before the first message,
  which Remora only has after pairing, and would add a second handshake
  shape. XX with pinning gives the same authentication for one extra
  half round trip per channel open.
- **Bulk binding:** Remora opens Bulk as responder with
  `Binding { bulk_token, expected_remote: helper key from Ctl }`. The
  handshake fails unless the helper knows the token (sent only inside the
  paired Ctl session) and proves the same static key as on Ctl. The helper
  should likewise set `expected_remote` to Remora's Ctl key.

### 3.2 Transport

- After the handshake, each frame is encrypted with ChaCha20-Poly1305 under
  the per-direction keys from Noise `Split()`, with Noise's implicit 64-bit
  counter nonce (section 5.1). Fresh ephemeral keys per channel open give
  forward secrecy.
- A Noise message holds at most 65,535 bytes, so a frame longer than
  65,519 bytes is encrypted as consecutive segments of 65,519 plaintext
  bytes, each with its own nonce and 16-byte tag, concatenated into one DVC
  message. `MAX_WIRE = 1 MiB + 17 * 16` bytes.
- **Any failure is fatal for that channel:** a bad tag, a replayed,
  reordered or dropped message (the counter no longer matches), a split or
  merged DVC message (caught by the frame length check), a malformed frame,
  a message of the other channel's kind, or a message in the wrong state.
  The session refuses everything afterwards; the channel is closed and
  opened again from scratch.

### 3.3 SAS pairing step (Ctl only)

A short string taken from the handshake hash alone could be ground by a man
in the middle. So both sides run a commit-reveal step inside the encrypted
session right after the handshake (as in ZRTP):

| Type     | Name        | Direction       | Payload |
|----------|-------------|-----------------|---------|
| `0x0001` | `SasCommit` | helper → Remora | `[32]` c = BLAKE3-derive-key("Remora-Link v1 SAS commit", h ‖ nI) |
| `0x0002` | `SasNonce`  | Remora → helper | `[32]` nR (random) |
| `0x0003` | `SasReveal` | helper → Remora | `[32]` nI; Remora checks c |

- `h` is the 32-byte Noise handshake hash.
- SAS = first 8 bytes (u64 little-endian) of
  BLAKE3-derive-key("Remora-Link v1 SAS", h ‖ nI ‖ nR), modulo 1,000,000,
  shown as six digits `123 456`.
- Neither side picks its nonce after seeing the other's, so an attacker
  matches the strings with probability 10⁻⁶ **per attempt**.
- `SecureSession` runs this step itself and emits `Event::Sas` on both
  ends; application messages are refused until then. Bulk has no SAS step.

**The bound holds only with an attempt limit.** The helper (initiator)
learns the SAS when Remora's nonce arrives, before it reveals. A man in the
middle playing the helper can therefore drop the channel whenever the code
it would cause does not match the real helper's, and try again, silently
(306 tries matched two digits in a test). So Remora counts every Ctl session
that finished the handshake with an **unpinned or changed** helper key and
ended (closed, failed or rejected by the helper) before **Remora's user**
answered the code. The user's own answer, and sessions with a pinned key or
an admin-set fingerprint, never count.

- **Per RDP connection:** after 2 such aborts Remora refuses `Remora::Ctl`
  for the rest of the connection (`HelperState::PairingBlocked`).
- **Per server** (`helper-attempts.json` next to `helpers.json`, keyed like
  the pins): 3 aborts within 24 hours block pairing with that server: an
  unpinned key is refused right after the handshake, before any nonce is
  sent. The block stays until the user chooses **Retry pairing** (helper
  card) or **Retry helper pairing** (palette).

An attacker thus gets at most 3 tries per server and day before the user is
told, so the chance of a matching code stays at most 3 × 10⁻⁶ per day and
server, and every failed try is visible.

## 4. Pairing and pinning

### 4.1 Keys and fingerprints

- The helper keeps one static key per Windows user on the server
  (`%LOCALAPPDATA%\rdp-rs\agent-key.bin`, DPAPI user scope).
- Remora keeps one static key per Windows user on the client
  (`%APPDATA%\rdp-rs\link-client-key.bin`, DPAPI user scope; elsewhere a
  0600 file). Both use the `remora_link::keyfile` format: a 4-byte file
  magic (`RAK1` helper, `RCK1` client), a `u32` length and the protected
  blob of a 4-byte magic and the private key. An unusable file is kept as
  `.old` and a new key made; the peer then sees a changed or unknown key.
- **Fingerprint** of a key: the first 20 bytes of BLAKE3 of the 32-byte
  X25519 public key, shown as ten groups of four lower-case hex digits
  (`3f9a 07c2 b18e …`). `remora-agent fingerprint` prints the helper's;
  Remora shows it in the pairing dialog and on the helper card, and its own
  in Settings → Security.

### 4.2 Remora pins the helper

Remora keeps pinned helper keys in `helpers.json` next to `known_hosts.json`
(`%APPDATA%\rdp-rs\`), keyed by lower-case `user@host:port` (the helper's
key is per user on the server; `DOMAIN\user` from the connection, or
`host:port` alone when no user name is known yet):
`{ "user@host:3389": { "key": "<hex>", "first_seen": <unix s>, "last_seen": <unix s> } }`.

- **Migration:** stores written before 1.1 hold plain `host:port` keys. A
  lookup for `user@host:port` without its own entry uses that plain entry as
  the same pin; pinning writes the user's own entry and drops the plain one
  if it holds the same key. Forgetting a server removes it for every user.
- Every change re-reads, merges and writes the file under a lock file
  (`helpers.json.lock`, taken over when older than 10 s) through a unique
  temporary file and a rename, so two Remora windows never lose a pin.
- A changed key is never accepted silently: Remora warns and asks again.
- An unreadable pin store counts as "changed" (never as "new"), and Remora
  does not overwrite it.
- **Admin pin:** a connection may hold an expected helper fingerprint
  (editor, Sharing page). Then Remora accepts only the key with that
  fingerprint, pins it, and sends `Pairing{Known}` without a code; any other
  key closes Ctl. A fingerprint that does not parse matches no key.

After `Event::Sas` Remora sends `ClientName` (1.1) and then `Pairing`
(`0x0103`, payload `u8 status`):

| Status | Name        | Meaning for the helper |
|-------:|-------------|------------------------|
| 0      | `Known`     | Remora has the helper's key pinned (or admin-pinned); Remora shows no code unless the helper asks (4.3) |
| 1      | `Confirm`   | first contact or **changed key**: Remora shows the SAS; the helper shows its code until 2 or 3 arrives |
| 2      | `Confirmed` | Remora's user confirmed the code |
| 3      | `Rejected`  | Remora's user rejected; Remora sends `Error{PAIRING_REJECTED}` and closes |

Remora pins a new helper key only once **both** users confirmed: its own
user, and the helper's (`PeerPairing` `Known` or `Confirmed`; a 1.0 helper
that never sends `PeerPairing` needs Remora's confirmation only).

### 4.3 The helper pins Remora (1.1)

The helper keeps the Remora clients its user confirmed in
`%LOCALAPPDATA%\rdp-rs\agent-clients.json`, keyed by the client key's
fingerprint (40 hex digits): `{ "<fp>": { "key": "<hex or empty>",
"first_seen": <unix s>, "label": "<ClientName>" } }`, written like
`helpers.json`. An entry without a key was added by fingerprint
(`remora-agent trust-client <fingerprint>`, an admin pre-seeding a PC) and
pins the key with that fingerprint.

Right after the SAS, before `Hello`, the helper sends `PeerPairing`
(`0x0106`, payload `u8 status`, same values):

| Status | Name        | Meaning for Remora |
|-------:|-------------|--------------------|
| 0      | `Known`     | the helper has this client key pinned |
| 1      | `Confirm`   | it does not: the helper shows its code and asks its user now, whatever `Pairing` says; Remora shows its code too (also for a pinned helper) |
| 2      | `Confirmed` | the helper's user confirmed |
| 3      | `Rejected`  | the helper's user rejected; the helper sends `Error{PAIRING_REJECTED}` and closes |

- **First contact** (client key unknown to the helper) needs the helper-side
  Confirm in the server's dialog **and** Remora's user's confirmation; after
  both, both sides pin.
- **`Pairing{Known}` from Remora is honoured only if the helper also knows
  the client key**; otherwise the helper shows its SAS dialog and needs its
  own user's answer.
- **Server→client data** (`FILE_DOWN` offers, `OpenUrl`) goes only to a
  client key the helper has pinned, and never while its dialog waits for an
  answer (`LinkProtocol::server_to_client_allowed`, the single gate).
- `remora-agent clients` lists the pinned clients, `remora-agent
  forget-client <fingerprint>` removes one (its next session asks again).

Until `HelloAck` is sent (paired and `Hello` received), Remora only accepts
`Hello`, `Heartbeat`, `PeerPairing`, `Error`, `Unsupported` and unknown
types; anything else gets `Error{NOT_ALLOWED}`.

## 5. Session flow

1. Helper opens `Remora::Ctl`, sends handshake message 1.
2. Handshake (3 messages), then the SAS step (3 messages).
3. Helper sends `PeerPairing` (1.1), then `Hello` (Remora holds it until
   paired); if it does not know the client key, its dialog shows now.
4. Remora sends `ClientName` and `Pairing`; on `Known` or after its user
   confirms, it sends `HelloAck` with the accepted capabilities and a fresh
   `bulk_token`.
5. Helper opens `Remora::Bulk` with that token (if a file capability was
   accepted), runs the Bulk handshake.
6. Both sides send `Heartbeat` (Remora every 10 s); the helper sends
   `SessionInfo` periodically if accepted.
7. On disconnect both sides drop the sessions. The helper reopens the
   channels on `WTS_REMOTE_CONNECT` and starts again at step 1 (pairing is
   silent then: `Known` both ways). File transfers resume (section 8).

## 6. Messages

All on `Remora::Ctl` unless marked Bulk. Maximum string lengths in bytes.

| Type     | Name             | Dir | Payload |
|----------|------------------|-----|---------|
| `0x0100` | `Hello`          | H→R | `u16 major, u16 minor, str helper_version (≤64), u32 os_build, u8 session_kind (0 desktop, 1 RemoteApp), u32 capabilities, u32 policy` |
| `0x0101` | `HelloAck`       | R→H | `u16 major, u16 minor, u32 capabilities (accepted), u32 max_message, u32 max_chunk, u32 window, [32] bulk_token` |
| `0x0102` | `Heartbeat`      | both | `u32 seq` |
| `0x0103` | `Pairing`        | R→H | `u8 status` (section 4) |
| `0x0104` | `Unsupported`    | both | `u16 type` — answer to an unknown type |
| `0x0105` | `Error`          | both | `u32 code, str message (≤1024)` |
| `0x0106` | `PeerPairing`    | H→R | `u8 status` (section 4.3); 1.1 |
| `0x0107` | `ClientName`     | R→H | `str name (≤64)`: a label for the helper's client list, never trusted; 1.1 |
| `0x0200` | `SessionInfo`    | H→R | `bool locked, u32 idle_ms, u8 cpu_percent (0..100), u64 mem_used, u64 mem_total` |
| `0x0300` | `OpenUrl`        | H→R | `str url (≤8192)`; `request_id` ≠ 0 |
| `0x0301` | `OpenUrlResult`  | R→H | `u8 status` (0 opened, 1 declined, 2 invalid, 3 disabled); same `request_id` |
| `0x0400` | `FileOffer`      | sender→receiver | `[16] id, str name (≤1024), u64 size, u64 mtime (ms since 1970), u32 block_size (4 MiB)` |
| `0x0401` | `FileAccept`     | receiver→sender | `[16] id, u32 epoch, u64 offset, u64 limit` |
| `0x0402` | `FileReject`     | receiver→sender | `[16] id, u8 reason` |
| `0x0403` | `FileCredit`     | receiver→sender | `[16] id, u32 epoch, u64 limit` |
| `0x0404` | `FileCancel`     | both | `[16] id, u8 reason` |
| `0x0405` | `FileComplete`   | receiver→sender | `[16] id` |
| `0x0480` | `FileChunk`      | Bulk, sender→receiver | `[16] id, u32 epoch, u64 offset, blob data (≤256 KiB)` |
| `0x0481` | `FileBlockHash`  | Bulk, sender→receiver | `[16] id, u32 epoch, u32 index, [32] BLAKE3 of the block` |
| `0x0482` | `FileEnd`        | Bulk, sender→receiver | `[16] id, u32 epoch, [32] root` |

- **Unknown types** (a newer minor version) get `Unsupported{type}`; the
  channel stays open. A malformed message of a known type is fatal.
- **Version:** a different major closes (handshake, or `Hello` →
  `Error{VERSION}`). Minors only add new message types; existing payloads
  never change within a major (decoders reject trailing bytes).
- **Capability bits** (`Hello` offers, `HelloAck` accepts a subset):
  `1` session info, `2` open URL, `4` file transfer up (client → server),
  `8` file transfer down (server → client). Remora accepts only what the
  user enabled (default: session info only).
- **Policy flags** (`Hello`): `1` clipboard redirection disabled, `2` drive
  redirection disabled. Either one switches both file directions off.
- **Error codes:** `1` pairing rejected, `2` version, `3` second instance,
  `4` not allowed (capability not accepted or not paired), `5` protocol.
- **Links:** Remora passes only absolute `http`/`https` URLs without spaces
  or control characters to the app, which asks the user (or uses a per-host
  allow list); at most 8 requests wait at a time.

## 7. File transfer

Both directions use the same engine (`remora_link::transfer::Engine`). The
helper sets `set_permissions(send = FILE_DOWN accepted, receive = FILE_UP
accepted)`; Remora the reverse.

```
sender                                     receiver
  FileOffer{id,name,size,mtime}  --Ctl-->    check name; ask the user
                                 <--Ctl--    FileAccept{epoch,offset,limit}
  FileChunk{epoch,offset,data}   --Bulk->    write "<name>.remora-part"
  FileBlockHash{epoch,i,hash}    --Bulk->    compare; record in the sidecar
                                 <--Ctl--    FileCredit{epoch,limit}
  ...
  FileEnd{epoch,root}            --Bulk->    compare root; rename
                                 <--Ctl--    FileComplete
```

- **Ids:** 16 random bytes (UUID v4 layout).
- **Chunks:** at most 256 KiB, in order (`offset` = bytes received so far),
  never crossing a 4 MiB block boundary.
- **Credit:** `limit` is an absolute byte offset; the sender never sends
  past it. The receiver grants `received + 2 MiB` whenever less than 1 MiB
  of credit is left, so at most about 2 MiB are in flight. A credit never
  shrinks; a credit of an older epoch is ignored.
- **Integrity:** the sender sends `FileBlockHash` after each 4 MiB block
  (and the short last one); the receiver compares it with the BLAKE3 of
  what it received. `root` = BLAKE3-derive-key("Remora-Link v1 file root",
  u64 size ‖ every block hash). A bad block: the receiver truncates to the
  last good block and sends a new `FileAccept` (new epoch); after 3 bad
  tries it cancels with reason `INTEGRITY`.
- **Epochs:** every `FileAccept` starts a new epoch; chunks, hashes and ends
  of older epochs are ignored. A sender accepts any epoch on a new
  connection and only higher ones within one.
- **Finishing:** the part file is synced, gets the Mark-of-the-Web (the
  app's hook; an NTFS stream survives the rename), then is renamed to the
  final name; the hook runs again on the stored file as a fallback. An
  existing file is never replaced: the receiver picks `name (2).ext`,
  `name (3).ext`, ... (also when a file appears during the transfer).
- **Cancel:** either side sends `FileCancel`; the receiver deletes the part
  and the sidecar. A transfer only ever deletes files it created (or the
  sidecar of its own id it resumed), never another transfer's.
- **Link-up:** when its link comes up, a receiver sends `FileAccept` (a new
  epoch at the verified offset) for every transfer it accepted and that is
  paused, also one accepted while the link was down: the sender sent its
  offer before and does not offer it again. A re-offer that arrives before
  any data of the epoch in force is answered with the same `FileAccept`.
- **Refused unseen:** an offer refused before the user saw it (direction
  off, too many transfers, a bad name or block size) gets `FileReject`, and
  the app a `Failed` event (Remora says once that receiving is off).
- **Threads:** both ends run the engine on a worker thread
  (`transfer::worker::EngineWorker`): the channel's thread only posts and
  takes messages. Incoming chunk bytes not yet written are capped at every
  transfer's window plus 4 MiB (past it the Bulk channel closes); the worker
  reads at most 4 MiB ahead of the channel.
- **Reasons** (`FileReject`, `FileCancel`): 1 user, 2 disabled, 3 bad name,
  4 no space, 5 I/O, 6 integrity, 7 source changed, 8 protocol, 9 busy.
- **Limits:** 32 transfers per direction; 4 MiB blocks fixed in 1.x.

### 7.1 Names (receiving side)

Only plain file names; no folders in 1.x. Refused with reason 3 before the
user sees the offer: empty names, `.`/`..`/dots only, `/` `\` `:` (paths,
drives, alternate data streams), `< > " | ? *`, control characters, bidi
and invisible format characters (U+200B–200F, U+202A–202E, U+2066–2069,
U+FEFF), trailing dots or spaces, reserved device names with or without
extension in any case (CON, PRN, AUX, NUL, COM0–9, LPT0–9, COM¹²³, LPT¹²³,
CONIN$, CONOUT$; "NUL .txt" counts), more than 255 UTF-16 units, and the
engine's own working files: names ending in `.remora-part`,
`.remora-part.meta` or `.tmp` in any case (a delivered sidecar must never
steer a later resume). Files are written only into the folder the user
chose; free space is checked first when the app provides a query.

Names the Windows shell acts on just by showing the folder are stored with
`.download` appended, so Explorer treats them as data and never resolves an
icon or target from them (the NTLM-leak class): `.lnk`, `.url`, `.scf`,
`.website`, `.library-ms`, `.searchConnector-ms`, `.appref-ms`,
`.settingcontent-ms`, and `desktop.ini` (also `*.desktop.ini`), in any
case. `Completed` reports the stored name.

## 8. Resume

- The receiver writes `<name>.remora-part` and a sidecar
  `<name>.remora-part.meta`, an append-only log: one JSON header line
  (`{"v":2,"id","name","size","mtime","block"}`), then one line per verified
  block (64 hex digits), appended after the part is synced. A torn last line
  loses only that block. The log is rewritten compactly (through a fresh
  `create_new` temporary file with a random suffix and a rename) when a
  transfer opens or resumes, and deleted on completion.
- A sidecar resumes only the transfer whose id it names, and only under the
  stored name or one of its numbered variants (`name (2).ext` ...): a
  sidecar for another name is ignored whatever it says. Recorded hashes
  past the file's last block are ignored.
- When the link drops, both engines pause. After the channels are back, the
  sender offers the **same id** again. The receiver (same process, or a new
  one that finds the sidecar in the accepted folder) re-hashes the recorded
  blocks of the part file, keeps the verified prefix and answers
  `FileAccept{offset = verified bytes}`.
- The sender continues only if the source's size and mtime are unchanged
  (otherwise reason 7); it re-hashes the skipped prefix if it no longer has
  those block hashes.
- A repeated offer for a transfer the receiver already completed is answered
  with `FileComplete` again (the sender missed it in the disconnect).

## 9. Security model

- **Threats addressed:** RDP proxies or bastions that end TLS (session
  recording gateways) and server-side tools that log virtual channel
  traffic see only ciphertext; pairing authenticates the helper to Remora
  and Remora to the helper; nothing falls back to plaintext.
- **Untrusted helper:** any process of the same user on the server can read
  the helper's key or open the channel names, so Remora treats every helper
  message as untrusted: one instance, only user-enabled capabilities,
  links and files need the user, files go only into the chosen folder,
  nothing is ever executed on the client, and malformed input closes the
  channel without affecting the RDP session.
- **Client authentication (1.1):** Remora's key is persistent and the
  helper pins it (4.3). A TLS-terminating proxy playing Remora has another
  key: the helper shows its dialog, and sends no file or link to it before
  its user confirmed. `Pairing{Known}` alone proves nothing to the helper.
- **Design limit: the server-side code travels in the RDP picture.** The
  helper shows its code on the remote desktop, and the user reads it through
  the very RDP connection the pairing is meant to protect. A man in the
  middle that controls that connection (it ends TLS and re-encrypts) also
  controls the picture: it can draw a fake server-side dialog showing
  whatever code Remora displays, and the user would see matching codes. The
  SAS then protects only against attackers who cannot rewrite the picture
  (channel loggers, passive recorders). Where that matters, compare
  **out of band**:
  - run `remora-agent fingerprint` on the server through another trusted
    path (console, management tool) and compare it with the fingerprint in
    Remora's pairing dialog or helper card; better, set it as the
    connection's **helper fingerprint** (admin pin, 4.2): Remora then accepts
    only that key and never asks for a code;
  - give the server the client's fingerprint the same way
    (`remora-agent trust-client <fingerprint>` with the value from Remora's
    Settings → Security), so the helper never needs its dialog for that PC.
- **Attempt limit:** SAS grinding by silent aborts is bounded per connection
  and per server (3.3).
- **At rest:** part files and sidecars use the folder's normal permissions;
  the pin stores hold public keys only.

## 10. Non-goals in 1.x

- Folder transfers, compression of chunks (the frame `flags` field is
  reserved for a later minor), side connections (any future one must be
  TLS 1.3 or QUIC pinned over this channel), running programs on the
  client, IK handshakes, and rekeying (64-bit counters cannot run out).

## 11. Driving it (both sides)

`remora-link` is sans-IO. Per channel:

```rust
// Helper: open the DVC, then
let (mut s, first) = SecureSession::initiator(Channel::Ctl, &helper_key, Binding::default())?;
pipe.send(&first)?;
loop {
    let msg = pipe.recv()?;                 // one whole DVC message
    for ev in s.on_message(&msg)? {         // Err => close the DVC, start over
        match ev {
            Event::Send(bytes) => pipe.send(&bytes)?,
            Event::Established { remote_static } => { /* Remora's key */ }
            Event::Sas(sas) => { /* keep; show it if Pairing{Confirm} arrives */ }
            Event::Message { request_id, msg } => { /* dispatch */ }
        }
    }
}
// Sending: pipe.send(&s.send(request_id, &Message::Hello(..))?)?
```

File transfer: feed received file messages to `Engine::handle`, call
`Engine::poll(budget)` regularly, send `Engine::take_messages()` on the
channel each one names (`Message::channel()`), and read
`Engine::next_event()`. Call `Engine::set_connected(true)` once Ctl is
paired and Bulk is ready, `false` when either drops. Both ends use
`transfer::worker::EngineWorker` instead (the same calls, `post` for
`handle`, and no `poll`: the worker pumps and calls its notify hook).

## 12. The helper's behaviour (remora-agent)

How `remora-agent` (`crates/remora-agent/src/link.rs`) uses this
contract.

- **Channels:** Ctl opens on every client connect; Bulk opens only after
  `HelloAck` accepted `FILE_UP` or `FILE_DOWN`, as initiator with
  `Binding { bulk_token, expected_remote: Remora's Ctl key }`. Ctl closing
  (or failing) closes Bulk. A second Ctl open drops all Ctl state and
  starts again from the handshake.
- **Pairing (4.3):** after the SAS the agent sends `PeerPairing` (`Known`
  for a client key in `agent-clients.json`, else `Confirm`) and shows the
  SAS with Confirm and Reject when the client is unknown or Remora sends
  `Pairing{Confirm}`. Confirm sends `PeerPairing{Confirmed}`; once Remora
  confirmed too (`Pairing` Known or Confirmed, or `HelloAck`), the client
  key is pinned with Remora's `ClientName` as its label. Reject (or closing
  the dialog) sends `PeerPairing{Rejected}` and `Error{PAIRING_REJECTED}`
  and closes Ctl. While the answer is pending the transfer link stays down;
  receiving rights apply, the send right is left as it was (a paused
  download is not cancelled by a pending answer).
- **Server-to-client data:** file offers to Remora (`FILE_DOWN`) and
  `OpenUrl` only when `server_to_client_allowed()`: a pinned client key and
  no dialog waiting. A paused download is never offered to an unpinned key.
- **Hello** goes out right after `PeerPairing`, once the agent has a session
  snapshot (taken when Ctl opens). File bits are not offered when policy
  disables clipboard or drive redirection; if that policy appears during a
  session, file transfer stops at once and Bulk closes.
- **Transfer link:** up as soon as Bulk is ready and no answer is pending.
  The 1 s grace and the holding of early offers of 1.0 are gone: an offer
  accepted while a receiver's link is down asks for its data on link-up
  (section 7).
- **Transfer worker:** the engine runs on its own thread
  (`EngineWorker`); it wakes the agent's event loop when it has messages,
  so file I/O never delays heartbeats, links or the pairing dialog.
- **Heartbeat** every 10 s after `HelloAck`; `SessionInfo` every 5 s (and
  on lock changes) if accepted. No idle timeout closes the channel.
- **Links:** `OpenUrl` with a fresh non-zero `request_id`. `Opened` or
  `Declined` → the link is handled by Remora; `Invalid` or `Disabled` →
  the server's own fallback browser opens it. Remora answers after its user
  decided, so after 2 s without an answer the link counts as handed over
  (never opened twice). At most 8 links wait at a time.
- **Receiving:** every offer is accepted into `<Downloads>\From Remora`
  (free space via `GetDiskFreeSpaceExW`); the part gets a `Zone.Identifier`
  stream with `ZoneId=3` before its rename and the stored file again after
  it.
- **Sending:** `remora-agent send <files>` (the Send To shortcut) passes
  absolute paths over the agent's per-session pipe (`RMS1` request, at most
  64 paths and 64 KiB per request). The agent opens each without following
  reparse points and sends regular disk files only, never transfer working
  files (7.1).
- **Unknown types** get `Unsupported`; client-bound types arriving at the
  helper get `Error{PROTOCOL}`; file messages before `HelloAck` get
  `Error{NOT_ALLOWED}`; none of these closes the channel.
- **Commands:** `fingerprint` (this helper's key), `clients`,
  `forget-client <fingerprint>`, `trust-client <fingerprint>`.
