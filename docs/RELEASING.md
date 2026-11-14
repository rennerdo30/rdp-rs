# Releasing Remora

Every release needs the owner's yes. CI builds and tests the packages and prepares a **draft** GitHub release. Publishing that draft is the owner's yes; nothing in CI publishes on its own.

## What is released

- **Remora for Windows (x64):** a per-user setup and a portable zip.
- **The server helper (x64):** `remora-agent-<version>-windows-x64.exe`, to copy onto a server as `remora-agent.exe` (also in the zip; the setup installs Remora only). Listed in `SHA256SUMS.txt`; no updater reads it.
- **Not packaged:** macOS and Linux. The `rdp` protocol library builds and is tested there in CI, but Remora, the client, is a Windows program today (window chrome, clipboard, printers, smart cards and sound use Windows APIs) and is neither built nor tested there, so the release has no archives for them.

## Versions

There is one version for the whole workspace: `version` under `[workspace.package]` in `Cargo.toml`, following SemVer.
- Prereleases look like `0.2.0-beta.1`. Their tags have a `-` and become GitHub prereleases.
- A stable `0.2.0` ranks above every `0.2.0-…`.

## Cutting a release

1. **Prepare the commit on `main`:**
   - set the workspace version;
   - move the `## Unreleased` notes in [`CHANGELOG.md`](../CHANGELOG.md) into a `## X.Y.Z` section;
   - commit, and let CI run.
2. **Tag that commit and push the tag:**
   ```sh
   git tag -a v0.1.0 -m "Remora 0.1.0"
   git push origin refs/tags/v0.1.0
   ```
3. **The release workflow runs** ([`.github/workflows/release.yml`](../.github/workflows/release.yml)):
   - It checks that the tag matches the workspace version.
   - It builds `remora-<version>-setup.exe` (per-user NSIS 3.13 setup), its legacy copy `rdpc-<version>-setup.exe` (see below), `remora-<version>-windows-x64.zip` (Remora and the helper) and `remora-agent-<version>-windows-x64.exe`.
   - It runs the installer lifecycle test on the disposable runner: install, reinstall, a running Remora blocks setup, the update from the published rdpc 0.1.0-beta.1 (including a running rdpc and partly removed rdpc installs), uninstall leaves nothing.
   - Every package carries `LICENSE.txt` (both licence texts) and `THIRD-PARTY-NOTICES.txt` (cargo-about, `about.toml`).
   - It checks that the legacy copy is byte-identical, writes one `SHA256SUMS.txt` over all packages and creates a **draft** release with the changelog section as notes.
   - Rerunning it (Actions → release → Run workflow, with the tag) refreshes a draft and never touches a published release.
4. **The owner reviews the draft and publishes it.** Only then do installed copies see the update.

The setup's file name `remora-<version>-setup.exe` and `SHA256SUMS.txt` are the contract with the in-app updater (`crates/remora-update`); keep both names.

### Legacy asset for rdpc (keep until the owner drops it)

Remora was called **rdpc** up to 0.1.0-beta.1. That build's updater only looks for `rdpc-<version>-setup.exe` and checks it against its own line in `SHA256SUMS.txt`. So every release also carries **`rdpc-<version>-setup.exe`, a byte-identical copy of the Remora setup**, listed in `SHA256SUMS.txt` under that name. Without it, installed rdpc copies never see another update.

- `scripts/package.ps1` makes the copy; the release workflow uploads it, checks it with `cmp` and lists it in `SHA256SUMS.txt`.
- **Publish it with every release until the owner decides to drop it.** To drop it, remove the copy from `scripts/package.ps1`, the upload path, the `cmp` line and `rdpc-*` from the checksum command in `release.yml`, and step 5 of `scripts/test-installer.ps1`.
- The Remora updater never reads the legacy name.

What happens on an rdpc install:
1. rdpc 0.1.0-beta.1 finds the release, downloads `SHA256SUMS.txt` and `rdpc-<version>-setup.exe`, checks the hash, starts the setup with `/S /UPDATE` and closes.
2. The setup waits for `rdpc.exe` to exit (up to 30 s; a silent setup gives up with exit code 2 and changes nothing), then for a running `remora.exe`.
3. It installs Remora to `%LOCALAPPDATA%\Programs\Remora`, with the Start menu shortcut and Installed apps entry **Remora**.
4. Then it removes rdpc: the files rdpc's setup installed in `%LOCALAPPDATA%\Programs\rdpc` (or the folder rdpc's uninstall key names, if it ends in `\rdpc`), that folder if it is empty, the `rdpc` uninstall key and the `rdpc.lnk` shortcuts in the Start menu and on the desktop. Every step skips what is already gone, so a rerun or a partly removed rdpc is fine. The data folders `%APPDATA%\rdp-rs` and `%LOCALAPPDATA%\rdp-rs` are never touched.
5. With `/UPDATE` it starts `remora.exe`.

A taskbar button pinned to rdpc points at the removed `rdpc.exe`; the user pins Remora again.

## Updates in the app

Updates need two things: a **published** release (drafts are invisible) and a copy **installed by the setup** (`%LOCALAPPDATA%\Programs\Remora`). Portable copies and development builds only name the release page.

- The check runs on a worker thread, never on the UI thread, at most once a day, when the connection manager opens. The time of the last check is kept in `%LOCALAPPDATA%\rdp-rs\update-check`; a failed check also waits a day.
- A newer release shows as an **Update to X.Y.Z** button in the status bar; **Ctrl+Shift+U** does the same. Nothing downloads until then. With sessions open, the first request says how many will close; the second goes ahead.
- **Settings → Updates:** switch the daily check off, **Check now**, and the channel: **Automatic** (the default: follows the installed version), **Stable** or **Beta**. Settings live in `%APPDATA%\rdp-rs\settings.json`. Portable copies and development builds never check; **Check now** names the release page instead.
- Installing an update:
  1. Remora downloads `SHA256SUMS.txt` and the setup;
  2. it checks the setup's SHA-256 and writes it into a fresh temporary folder, checks it again on disk, and starts it with `/S /UPDATE`;
  3. Remora closes, and the setup waits for it (up to 30 s), installs and starts Remora again.
- **Channels:** a prerelease build follows **beta** (newest published release, prerelease or stable); a stable build follows **stable**. Drafts, downgrades and releases without both assets are never offered.
- **Fetched URLs:** only GitHub's API for `rennerdo30/rdp-rs` and its release downloads, over HTTPS, with the user agent `Remora/<version>`.
  - Windows: WinHTTP, so the system proxy settings apply.
  - Elsewhere: the system `curl`.
  - Metadata is capped at 8 MiB and the setup at 200 MiB; requests time out after 60 s.

## What protects an update

- **The checksum protects integrity, not authenticity.** It comes from the same release as the setup.
- **The setup is not Authenticode-signed yet**, so Windows SmartScreen warns on the first run. Signing is a separate owner decision.
- **Nothing runs elevated.** The setup installs per user.

## Building the packages locally

`scripts\package.bat` builds the release binary, the setup, its legacy copy, the zip and `SHA256SUMS.txt` into `artifacts\installer`. It never installs or starts anything.
- **NSIS:** it uses the portable NSIS 3.13 at `E:/Development/_cache/tools/nsis-3.13/` (or `-MakeNsis`, or the `REMORA_MAKENSIS` environment variable); `scripts/fetch-nsis.ps1` downloads the pinned ZIP elsewhere.
- **Notices:** without cargo-about it writes a placeholder notice. Release builds always generate the real one in CI.
- **Icon:** `assets/remora.ico` is generated from the icon Remora draws (`scripts/make-icon.ps1`) and embedded into `remora.exe` by `crates/remora/build.rs`; rerun the script after changing `crates/remora/src/icon.rs`. `assets/logo.svg` draws the same geometry.
- **Never run `scripts/test-installer.ps1` on a real PC.** It installs and uninstalls for the current user (Remora and the published rdpc 0.1.0-beta.1), and refuses to run outside GitHub Actions.
