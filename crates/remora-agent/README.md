# remora-agent

A small helper that runs **inside your session on a Windows remote desktop host** and connects that session to the Remora client on your own PC. It uses two dynamic virtual channels of the RDP connection that is already open (`Remora::Ctl` for control, `Remora::Bulk` for file data), so it needs no extra network connection, no firewall rule and no administrator rights.

Status: milestone 1 plumbing (RDP-41, RDP-42, RDP-44). The helper protocol (handshake, end-to-end encryption, pairing, file transfer) comes from `remora-link` and is not wired in yet. Until it is, the agent opens its channels and collects session information, but it does not send anything.

## What it does

- Opens its channels whenever a Remora client attaches to the session, closes them on disconnect and reopens them on reconnect. On the console, or under a client without Remora (mstsc), it stays idle and retries only on the next connect (plus a slow backoff: 30 s, doubling, at most 10 min).
- Reports session information to Remora: locked or not, idle time, CPU and memory load, Windows version, desktop or RemoteApp session, and whether clipboard or drive redirection is disabled by policy. If either is disabled, file transfer is off too.
- Opens links you click in the session in the browser on your own PC (after Remora asks you), once you pick "Remora Agent" as the app for HTTP and HTTPS.
- Runs once per session (a second copy exits).

Supported: Windows 10/11 Pro and Enterprise, Remote Desktop Session Host, RemoteApp sessions, Server Core. It has no window and no tray icon.

## Install

Put `remora-agent.exe` where it should stay (for example `%LOCALAPPDATA%\Programs\Remora\`), then in that session:

```
remora-agent install
```

This creates a scheduled task for **your user only** that starts the agent at logon and whenever a client reconnects to your session. It runs with your normal rights (least privilege), hidden, and is restarted up to three times if it fails. `remora-agent install --dry-run` prints the task without creating it; `remora-agent print-task-xml` prints only the task definition; `remora-agent status` shows whether it is installed.

Why not the `Run` key: entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` are started by Explorer, and RemoteApp sessions have no Explorer, so the agent would never start there. The scheduled task works in every kind of session. You can also start the agent by hand (`remora-agent`).

### Links

```
remora-agent register-links
```

Registers the agent (for your user, under `HKEY_CURRENT_USER`) as an app that can open HTTP and HTTPS links. Then pick **Remora Agent** for HTTP and HTTPS in *Settings > Apps > Default apps*. Windows does not let programs make themselves the default browser, so this one step is yours; an administrator can set it for all users with a default-associations XML.

When no Remora client is connected, links open in the browser that was your default when you registered (it is remembered then). If none was found, the link is not opened and the log says why.

## Uninstall

```
remora-agent uninstall
```

Removes the scheduled task and the link registration. `--dry-run` shows what it would do. If Remora Agent was your browser, Windows asks which app to use for the next link.

## Log

`%LOCALAPPDATA%\rdp-rs\logs\remora-agent.log`, at most 1 MiB plus one older file (`remora-agent.log.1`). It records starts, channel events, session events and errors, with sizes only: never message contents, links or file names.

## What it never does

- It never asks for elevation (its manifest says `asInvoker`) and never installs services, drivers or anything machine-wide.
- It opens no network ports. Its only local endpoint is a named pipe that only your user, in your session, can open; it carries a link from `remora-agent open-url` to the running agent.
- It never runs programs or commands, except starting your previous browser with a checked `http`/`https` link when Remora is not connected (directly, without a shell).
- It never changes system settings or other users' settings; everything it writes is under your own `HKEY_CURRENT_USER` and your own scheduled task.
- It sends nothing outside the RDP connection you already have.

## Verify on a real host

These need a Windows RDP host and a Remora client with the matching listener:

- that a standard user can create the task (logon and remote-connect triggers for themselves), and that the remote-connect trigger starts the agent in the reconnected session on a multi-session host;
- whether `WTSVirtualChannelOpenEx` blocks or fails fast when the client has no listener;
- the read semantics: one `CHANNEL_PDU_HEADER` per `ReadFile`, chunks up to `CHANNEL_CHUNK_LENGTH`, and 1 MiB writes in one `WriteFile`;
- RemoteApp detection (`rdpshell.exe` / `rdpinit.exe` in the session);
- the link registration in Default apps on Windows 10, Windows 11 and Windows Server.
