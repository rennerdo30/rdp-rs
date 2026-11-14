// Remora homepage: links the download buttons to the newest published release's files and
// names it, from the public GitHub API. Without this script (or without network) the buttons
// keep pointing at the releases page and the sentence stays hidden.
(function () {
  'use strict';

  var API = 'https://api.github.com/repos/rennerdo30/rdp-rs/releases?per_page=10';
  if (!window.fetch) return;

  function all(name) { return document.querySelectorAll('[data-release="' + name + '"]'); }
  function link(name, url) {
    if (!url) return;
    all(name).forEach(function (a) { a.href = url; });
  }
  function asset(release, test) {
    var hit = (release.assets || []).filter(function (a) { return test.test(a.name); })[0];
    return hit && /^https:\/\/github\.com\//.test(hit.browser_download_url) ? hit.browser_download_url : null;
  }

  fetch(API, { headers: { Accept: 'application/vnd.github+json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (list) {
      // Newest published release with a Remora setup, beta or stable (the list is newest
      // first). Releases also carry rdpc-<version>-setup.exe, a copy for rdpc's own updater;
      // the page links the Remora files only.
      var r = (list || []).filter(function (x) {
        return !x.draft && /^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(x.tag_name || '') &&
          asset(x, /^remora-.*-setup\.exe$/i);
      })[0];
      if (!r) return;
      link('setup', asset(r, /^remora-.*-setup\.exe$/i));
      link('zip', asset(r, /^remora-.*-windows-x64\.zip$/i));
      link('sums', asset(r, /^SHA256SUMS\.txt$/));
      var date = new Date(r.published_at);
      if (isNaN(date)) return;
      all('version').forEach(function (e) { e.textContent = 'Remora ' + r.tag_name.replace(/^v/, ''); });
      all('date').forEach(function (e) { e.textContent = date.toLocaleDateString('en', { day: 'numeric', month: 'long', year: 'numeric' }); });
      all('found').forEach(function (e) { e.hidden = false; });
    })
    .catch(function () { /* offline or rate limited: keep the fallbacks */ });
})();
