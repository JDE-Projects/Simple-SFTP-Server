// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks layout in the real
// pywebview window, using the one user tools/ui_check/fixture.py writes.
//
// Covers: the Users table keeps each row's Edit and Delete buttons inside the
// panel with a long username, a long folder path, the longest permissions
// summary, and a password-and-key user; the
// update notice sits on the bar's true center and the bar stays one row; the
// Public IP button names the services it asks. Each layout check runs twice:
// at the window's own width, and with the page narrowed to 960px, a little
// under what the app's 980px minimum window leaves for the page.
//
// The long path and permissions are set on the page's copy of the user list
// only (nothing is saved). The notice comes from a real press of Check for
// updates, which asks GitHub for the latest version.
// Does not cover: resizing the real window, or the Public IP lookup itself
// (it contacts outside services).

const NARROW_PX = 960;

async function measure(helpers, label) {
  const { evaluate, check } = helpers;
  const t = await evaluate(`(() => {
    const body = document.querySelector('#userRows').closest('.pane-body');
    const box = body.getBoundingClientRect();
    const rows = [...document.querySelectorAll('#userRows tr')].map(tr => {
      const act = tr.querySelector('td.act');
      const btns = [...act.querySelectorAll('button')].map(b => b.getBoundingClientRect());
      const folder = tr.querySelector('td.folder');
      return {
        btnLeft: Math.min(...btns.map(r => r.left)),
        btnRight: Math.max(...btns.map(r => r.right)),
        btnCount: btns.length,
        actLeft: act.getBoundingClientRect().left,
        btnTopsMatch: btns.every(r => Math.abs(r.top - btns[0].top) < 1),
        folderCut: folder.scrollWidth > folder.clientWidth,
        tagsInCell: [...tr.querySelectorAll('td .tag')].every(t =>
          t.getBoundingClientRect().right <= t.parentElement.getBoundingClientRect().right + 0.5),
      };
    });
    return { right: box.right, scrollW: body.scrollWidth, clientW: body.clientWidth, rows };
  })()`);
  check(`${label}: Users table does not scroll sideways`, t.scrollW <= t.clientW,
    `scrollWidth ${t.scrollW} > clientWidth ${t.clientW}`);
  t.rows.forEach((r, i) => {
    check(`${label}: row ${i + 1} Edit and Delete fully inside the panel, side by side`,
      r.btnCount === 2 && r.btnRight <= t.right + 0.5 && r.btnLeft >= r.actLeft - 0.5 && r.btnTopsMatch,
      JSON.stringify({ ...r, panelRight: t.right }));
    check(`${label}: row ${i + 1} long folder path shortened`, r.folderCut, JSON.stringify(r));
    check(`${label}: row ${i + 1} permission and sign-in tags stay in their columns`,
      r.tagsInCell, JSON.stringify(r));
  });
}

async function measureBar(helpers, label, emptyHeight) {
  const { evaluate, check } = helpers;
  const b = await evaluate(`(() => {
    const bar = document.querySelector('.statusbar').getBoundingClientRect();
    const n = document.getElementById('updateNotice').getBoundingClientRect();
    return { barMid: bar.left + bar.width / 2, noteMid: n.left + n.width / 2,
             noteW: n.width, barH: bar.height,
             text: document.getElementById('updateNotice').textContent };
  })()`);
  check(`${label}: update notice has text to measure`, b.noteW > 0, JSON.stringify(b));
  check(`${label}: update notice on the bar's center (within 1px)`,
    Math.abs(b.barMid - b.noteMid) <= 1, JSON.stringify(b));
  check(`${label}: bottom bar stays one row`, Math.abs(b.barH - emptyHeight) <= 0.5,
    `height ${b.barH}, empty ${emptyHeight}`);
}

async function showNotice(helpers) {
  const { click, waitFor, evaluate } = helpers;
  await evaluate("document.getElementById('updateNotice').textContent=''");
  await click("#updateBtn");
  return waitFor("document.getElementById('updateNotice').textContent.length > 0 && !document.getElementById('updateBtn').disabled", 15000);
}

export default async function layout(helpers) {
  const { evaluate, waitFor, check, screenshot } = helpers;

  await waitFor("typeof API !== 'undefined' && API && meta && users.length === 1", 10000);

  const pubTitle = await evaluate("document.getElementById('pubBtn').title");
  check("Public IP button names both services",
    pubTitle.includes("api.ipify.org") && pubTitle.includes("checkip.amazonaws.com"), pubTitle);

  // Page-only test data: a long folder path and every permission but one,
  // which gives the longest summary. A second user with the default ones.
  await evaluate(`(() => {
    const u = users[0];
    u.home = 'C:\\\\Users\\\\someone\\\\Documents\\\\Shared with the team\\\\Quarterly reports and invoices\\\\2026\\\\incoming';
    u.permissions = Object.fromEntries(PERM_KEYS.map(k => [k, k !== 'delete_dir']));
    users.push({ ...u, username: 'a-much-longer-username-here', auth: 'both', key_count: 3,
                 permissions: Object.fromEntries(PERM_KEYS.map(k => [k, k === 'list'])) });
    renderUsers();
  })()`);

  const emptyHeight = await evaluate("document.querySelector('.statusbar').getBoundingClientRect().height");

  await measure(helpers, "full width");
  check("full width: notice appears after Check for updates", await showNotice(helpers));
  await measureBar(helpers, "full width", emptyHeight);
  await screenshot("layout-full-width", 0);

  await evaluate(`document.querySelector('.app').style.width='${NARROW_PX}px'`);
  await measure(helpers, `${NARROW_PX}px`);
  check(`${NARROW_PX}px: notice appears after Check for updates`, await showNotice(helpers));
  await measureBar(helpers, `${NARROW_PX}px`, emptyHeight);
  await screenshot("layout-narrow", 0);
}
