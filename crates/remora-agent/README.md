# remora-agent

A small helper that runs **inside your session on a Windows remote desktop host** and connects that session to the Remora client on your own PC. It uses two dynamic virtual channels of the RDP connection that is already open (`Remora::Ctl` for control, `Remora::Bulk` for file data), so it needs no extra network connection, no firewall rule and no administrator rights.

Everything on these channels is end-to-end encrypted (Noise, then ChaCha20-Poly1305) on top of RDP's own TLS, so RDP proxies and recording gateways see only ciphertext. The protocol is `docs/HELPER-PROTOCOL.md`; the code is the `remora-link` crate.

## What it does

- Opens `Remora::Ctl` whenever a Remora client attaches to the session, and `Remora::Bulk` once Remora has accepted file transfer. Closes them on disconnect and reopens on reconnect. On the console, or under a client without Remora (mstsc), it stays idle and retries only on the next connect (plus a slow backoff: 30 s, doubling, at most 10 min).
- Pairs with Remora (below), then reports session information: locked or not, idle time, CPU and memory load, Windows build, desktop or RemoteApp session, and whether clipboard or drive redirection is disabled by policy. If either is disabled, file transfer is off in both directions.
- Receives files you drop onto the Remora window into **`Downloads\From Remora`** (see below).
- Sends files to your PC with **Send To > Send to my PC (Remora)** in Explorer.
- Opens links you click in the session in the browser on your own PC (after Remora asks you), once you pick "Remora Agent" as the app for HTTP and HTTPS.
- Runs once per session (a second copy exits).

Supported: Windows 10/11 Pro and Enterprise, Remote Desktop Session Host, RemoteApp sessions, Server Core. It has no tray icon; the only windows it shows are the pairing dialog and, for Send To, a message when nothing could be sent.

## Pairing

The agent has one key per user, made on first start and kept DPAPI-protected (only your account on this server can read it) in `%LOCALAPPDATA%\rdp-rs\agent-key.bin`.

The first time Remora meets the agent (or when the agent's key changed), both show the same six-digit code:

- Remora asks you to compare it.
- On the server, a small **"Remora Agent: pair with Remora"** window shows the code with **Confirm** and **Reject**.

Confirm in **both** places only if the codes match. Reject (or closing the server window, or five minutes without an answer) ends the connection.

After that Remora remembers the agent and does not ask again. **Until Remora also has a key the agent can remember, the agent sends files and links to your PC only in a session where you confirmed the code on the server.** On a later reconnect without a code (Remora already knows the agent), session information and files from Remora still work, but Send To and links answer "not connected". This is deliberate: the agent cannot yet tell your Remora from a machine in the middle that ends TLS; a later version adds that.

If the key file is damaged or cannot be decrypted (for example after an administrator reset your password), the agent makes a new key, keeps the old file as `agent-key.bin.old` and logs it; Remora then warns that the agent's key changed and asks you to compare codes again.

## Files

**From your PC to the server:** drop files onto the Remora window (when Remora allows files to this server). They land in `Downloads\From Remora` (the folder is created when the first file arrives; a moved Downloads folder is followed).

- An existing file is never replaced: the new one is saved as `name (2).ext`, and so on.
- Files are written as `name.remora-part` with a `name.remora-part.meta` record and renamed when complete and verified (BLAKE3 per 4 MiB block). A dropped connection resumes from the last verified block after you reconnect, also after a restart of the agent.
- Free space is checked first.
- Received files get the Mark-of-the-Web (`Zone.Identifier`, Internet zone), like a download: Windows warns before running them and Office opens them in Protected View.

**From the server to your PC:** select files in Explorer, then **Send To > Send to my PC (Remora)**, or run `remora-agent send <file>...`. Remora asks you where to save them. Only regular files are sent in this version: no folders, links or devices. If Remora is not connected, has not allowed files to your PC, or the code was not confirmed on the server in this session, a short message says so.

## Install

Put `remora-agent.exe` where it should stay (for example `%LOCALAPPDATA%\Programs\Remora\`), then in that session:

```
remora-agent install
```

This creates:

- a scheduled task for **your user only** that starts the agent at logon and whenever a client reconnects to your session. It runs with your normal rights (least privilege), hidden, and is restarted up to three times if it fails;
- the shortcut **Send to my PC (Remora)** in your own SendTo folder.

`remora-agent install --dry-run` prints both without creating them; `remora-agent print-task-xml` prints only the task definition; `remora-agent status` shows whether the task is installed.

Why not the `Run` key: entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` are started by Explorer, and RemoteApp sessions have no Explorer, so the agent would never start there. The scheduled task works in every kind of session. You can also start the agent by hand (`remora-agent`).

### Links

```
remora-agent register-links
```

Registers the agent (for your user, under `HKEY_CURRENT_USER`) as an app that can open HTTP and HTTPS links. Then pick **Remora Agent** for HTTP and HTTPS in *Settings > Apps > Default apps*. Windows does not let programs make themselves the default browser, so this one step is yours; an administrator can set it for all users with a default-associations XML.

When no Remora client is connected (or links are not allowed for this session), links open in the browser that was your default when you registered (it is remembered then). If none was found, the link is not opened and the log says why. Remora answers a link only after you decided there; if it has not answered within two seconds, the link counts as handed over and is not opened on the server as well.

## Uninstall

```
remora-agent uninstall
```

Removes the scheduled task, the Send To shortcut and the link registration. `--dry-run` shows what it would do. If Remora Agent was your browser, Windows asks which app to use for the next link. The key file and `Downloads\From Remora` stay; delete them by hand if you like.

## Log

`%LOCALAPPDATA%\rdp-rs\logs\remora-agent.log`, at most 1 MiB plus one older file (`remora-agent.log.1`). It records starts, channel and pairing events, session events, transfer ids and sizes, and errors: never message contents, keys or links. File names appear only with `REMORA_AGENT_DEBUG=1` in the agent's environment.

## What it never does

- It never asks for elevation (its manifest says `asInvoker`) and never installs services, drivers or anything machine-wide.
- It opens no network ports. Its only local endpoint is a named pipe that only your user, in your session, can open; it carries a link from `remora-agent open-url`, or file paths from `remora-agent send`, to the running agent.
- It never runs programs or commands, except starting your previous browser with a checked `http`/`https` link when Remora is not connected (directly, without a shell). Received files are only written, never opened.
- It writes received files only into `Downloads\From Remora`, never replaces a file, and sends only files you chose with Send To.
- It never changes system settings or other users' settings; everything it writes is under your own `HKEY_CURRENT_USER`, your own profile folders and your own scheduled task.
- It sends nothing outside the RDP connection you already have.

## Verify on a real host

These need a Windows RDP host and a Remora client with the matching listener:

- that a standard user can create the task (logon and remote-connect triggers for themselves), and that the remote-connect trigger starts the agent in the reconnected session on a multi-session host;
- whether `WTSVirtualChannelOpenEx` blocks or fails fast when the client has no listener;
- the read semantics: one `CHANNEL_PDU_HEADER` per `ReadFile`, chunks up to `CHANNEL_CHUNK_LENGTH`, and 1 MiB writes in one `WriteFile`;
- RemoteApp detection (`rdpshell.exe` / `rdpinit.exe` in the session);
- the pairing dialog (topmost, closes when Remora rejects or disconnects), the Send To shortcut, DPAPI key storage across logons;
- file transfer both ways, a transfer resumed after a disconnect, and the Mark-of-the-Web on received files;
- the link registration in Default apps on Windows 10, Windows 11 and Windows Server.
