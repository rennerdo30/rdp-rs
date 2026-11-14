# Installing Remora

Download from [Releases](https://github.com/rennerdo30/rdp-rs/releases).

## Windows

- **Setup:** run `remora-<version>-setup.exe`.
  - It installs per user to `%LOCALAPPDATA%\Programs\Remora` without admin rights, and adds a Start menu entry and an Installed apps entry.
  - It does not change PATH or file types.
  - The installed copy updates itself.
  - **Coming from rdpc** (Remora's old name, 0.1.0-beta.1): rdpc updates itself to Remora, or run the Remora setup. It removes rdpc's program folder (`%LOCALAPPDATA%\Programs\rdpc`), Start menu shortcut and Installed apps entry; saved connections and settings stay.
- **Silent install:** `remora-<version>-setup.exe /S`.
- **Portable:** unpack `remora-<version>-windows-x64.zip` anywhere and run `remora.exe`. A portable copy does not look for updates; new versions are on the releases page.
- **Uninstall:** Settings → Apps → Installed apps → Remora, or `"%LOCALAPPDATA%\Programs\Remora\uninstall.exe" /S`. Your saved connections in `%APPDATA%\rdp-rs` stay.

Builds are not signed yet, so SmartScreen warns on the first run (More info → Run anyway).

The command line modes work from the installed copy too, for example `"%LOCALAPPDATA%\Programs\Remora\remora.exe" 192.168.1.20 -u DOMAIN\user` (see the [README](../README.md#build-and-run)).

## macOS and Linux

There are no packages yet: Remora, the client, is a Windows program today. The `rdp` protocol library builds on macOS and Linux from source (`cargo build -p rdp`).

## Verifying a download

`SHA256SUMS.txt` in each release lists every package:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing          # Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing      # macOS
```

On Windows, compare it with `Get-FileHash .\remora-<version>-setup.exe`.
