# Installing rdpc

Download from [Releases](https://github.com/rennerdo30/rdp-rs/releases).

## Windows

- **Setup:** run `rdpc-<version>-setup.exe`.
  - It installs per user to `%LOCALAPPDATA%\Programs\rdpc` without admin rights, and adds a Start menu entry and an Installed apps entry.
  - It does not change PATH or file types.
  - The installed copy updates itself.
- **Silent install:** `rdpc-<version>-setup.exe /S`.
- **Portable:** unpack `rdpc-<version>-windows-x64.zip` anywhere and run `rdpc.exe`. A portable copy reports updates but does not install them.
- **Uninstall:** Settings → Apps → Installed apps → rdpc, or `"%LOCALAPPDATA%\Programs\rdpc\uninstall.exe" /S`. Your saved connections in `%APPDATA%\rdp-rs` stay.

Builds are not signed yet, so SmartScreen warns on the first run (More info → Run anyway).

The command line modes work from the installed copy too, for example `"%LOCALAPPDATA%\Programs\rdpc\rdpc.exe" 192.168.1.20 -u DOMAIN\user` (see the [README](../README.md#build-and-run)).

## macOS and Linux

There are no packages yet: the `rdpc` client is a Windows program today. The `rdp` protocol library builds on macOS and Linux from source (`cargo build -p rdp`).

## Verifying a download

`SHA256SUMS.txt` in each release lists every package:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing          # Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing      # macOS
```

On Windows, compare it with `Get-FileHash .\rdpc-<version>-setup.exe`.
