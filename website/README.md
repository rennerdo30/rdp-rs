# remora.renner.dev

The project homepage, served by GitHub Pages from this folder. Plain static files: no build step,
no external fonts or scripts, a strict Content Security Policy. `releases.js` asks the public
GitHub API for the newest published release with a Remora setup (beta or stable) to link the
setup, the zip and `SHA256SUMS.txt` directly and to name the version; without it the buttons
point at the releases page and the sentence stays hidden.

- **Screenshots** in `assets/shots/` are real renders of the app, made offscreen by
  `scripts/screenshots.ps1` with `remora --snapshot-ui`: the app's own paint code with sample
  connections and a stand-in remote desktop, never anyone's saved data. The same run writes the
  user guide's images in `docs/images/`, the link preview `assets/og.jpg`, and copies the icons
  (`assets/logo.svg`, `favicon.ico`, `assets/icon-*.png`) from the app's. Retake them when the
  interface changes, and commit the results.
- **Claims:** every statement on the page is checked against the code. There are no speed
  numbers: none has been measured yet, and none is added before it is. The coverage figure
  (29 of 38 features done, 1 partly, 78 %) comes from the table in the main README; change
  both together, including the meter width in `style.css`.
- **Deploy:** run the **Website Pages** workflow from the Actions tab (manual only, from `main`).
  It needs GitHub Pages set to "GitHub Actions" in the repository settings and a DNS record for
  `remora.renner.dev` (`CNAME`) pointing at `rennerdo30.github.io`.
