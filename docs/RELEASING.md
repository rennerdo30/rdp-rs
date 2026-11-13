# Releasing rdpc

Every release needs the owner's yes. CI builds and tests the packages and prepares a **draft** GitHub release. Publishing that draft is the owner's yes; nothing in CI publishes on its own.

## What is released

- **rdpc for Windows (x64):** a per-user setup and a portable zip.
- **Not packaged:** macOS and Linux. The `rdp` protocol library builds and is tested there in CI, but the `rdpc` client is a Windows program today (window chrome, clipboard, printers, smart cards and sound use Windows APIs) and is neither built nor tested there, so the release has no archives for them.

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
   git tag -a v0.1.0 -m "rdpc 0.1.0"
   git push origin refs/tags/v0.1.0
   ```
3. **The release workflow runs** ([`.github/workflows/release.yml`](../.github/workflows/release.yml)):
   - It checks that the tag matches the workspace version.
   - It builds `rdpc-<version>-setup.exe` (per-user NSIS 3.13 setup) and `rdpc-<version>-windows-x64.zip`.
   - It runs the installer lifecycle test on the disposable runner: install, reinstall, a running rdpc blocks setup, uninstall leaves nothing.
   - Every package carries `LICENSE.txt` (both licence texts) and `THIRD-PARTY-NOTICES.txt` (cargo-about, `about.toml`).
   - It writes one `SHA256SUMS.txt` over all packages and creates a **draft** release with the changelog section as notes.
   - Rerunning it (Actions → release → Run workflow, with the tag) refreshes a draft and never touches a published release.
4. **The owner reviews the draft and publishes it.** Only then do installed copies see the update.

The setup's file name `rdpc-<version>-setup.exe` and `SHA256SUMS.txt` are the contract with the in-app updater (`crates/rdpc-update`); keep both names.

## Updates in the app

Updates need two things: a **published** release (drafts are invisible) and a copy **installed by the setup** (`%LOCALAPPDATA%\Programs\rdpc`). Portable copies and development builds only name the release page.

- The check runs on a worker thread, never on the UI thread, at most once a day, when the connection manager opens. The time of the last check is kept in `%LOCALAPPDATA%\rdp-rs\update-check`; a failed check also waits a day.
- A newer release shows as an **Update to X.Y.Z** button in the status bar; **Ctrl+Shift+U** does the same. Nothing downloads until then. With sessions open, the first request says how many will close; the second goes ahead.
- **Settings → Updates:** switch the daily check off, **Check now**, and the channel: **Automatic** (the default: follows the installed version), **Stable** or **Beta**. Settings live in `%APPDATA%\rdp-rs\settings.json`. Portable copies and development builds never check; **Check now** names the release page instead.
- Installing an update:
  1. rdpc downloads `SHA256SUMS.txt` and the setup;
  2. it checks the setup's SHA-256 and writes it into a fresh temporary folder, checks it again on disk, and starts it with `/S /UPDATE`;
  3. rdpc closes, and the setup waits for it (up to 30 s), installs and starts rdpc again.
- **Channels:** a prerelease build follows **beta** (newest published release, prerelease or stable); a stable build follows **stable**. Drafts, downgrades and releases without both assets are never offered.
- **Fetched URLs:** only GitHub's API for `rennerdo30/rdp-rs` and its release downloads, over HTTPS.
  - Windows: WinHTTP, so the system proxy settings apply.
  - Elsewhere: the system `curl`.
  - Metadata is capped at 8 MiB and the setup at 200 MiB; requests time out after 60 s.

## What protects an update

- **The checksum protects integrity, not authenticity.** It comes from the same release as the setup.
- **The setup is not Authenticode-signed yet**, so Windows SmartScreen warns on the first run. Signing is a separate owner decision.
- **Nothing runs elevated.** The setup installs per user.

## Building the packages locally

`scripts\package.bat` builds the release binary, the setup, the zip and `SHA256SUMS.txt` into `artifacts\installer`. It never installs or starts anything.
- **NSIS:** it uses the portable NSIS 3.13 at `E:/Development/_cache/tools/nsis-3.13/`; `scripts/fetch-nsis.ps1` downloads the pinned ZIP elsewhere.
- **Notices:** without cargo-about it writes a placeholder notice. Release builds always generate the real one in CI.
- **Icon:** `assets/rdpc.ico` is generated from the icon rdpc draws (`scripts/make-icon.ps1`) and embedded into `rdpc.exe` by `crates/rdpc/build.rs`; rerun the script after changing `crates/rdpc/src/icon.rs`.
- **Never run `scripts/test-installer.ps1` on a real PC.** It installs and uninstalls for the current user, and refuses to run outside GitHub Actions.
