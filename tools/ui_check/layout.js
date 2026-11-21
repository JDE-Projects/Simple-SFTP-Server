// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks layout in the real
// pywebview window, using the one user tools/ui_check/fixture.py writes.
//
// Covers: the Users table keeps each row's Manage button inside the panel
// with a long username, a long folder path, the longest permissions summary,
// a password-or-key user, and a key-only user with a two-digit key count;
// every sign-in label shows in full; the account editor's sign-in choices fit
// on one row, the "Password or key" helper note shows only for that choice,
// and Delete user shows only when managing an existing user; the update
// notice sits on the bar's true center and the bar stays one row; the Public
// IP button names the services it asks. Each layout check runs twice:
// at the window's own width, and with the page narrowed to 960px, a little
// under what the app's 980px minimum window leaves for the page.
//
// The long path and permissions are set on the page's copy of the user list
// only (nothing is saved). Last, the fixture's user is deleted for real from
// the Manage dialog, keeping its folder, inside the throwaway app copy. The notice comes from a real press of Check for
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
      const btnEls = [...act.querySelectorAll('button')];
      const btns = btnEls.map(b => b.getBoundingClientRect());
      const folder = tr.querySelector('td.folder');
      return {
        btnLeft: Math.min(...btns.map(r => r.left)),
        btnRight: Math.max(...btns.map(r => r.right)),
        btnCount: btns.length,
        actLeft: act.getBoundingClientRect().left,
        btnText: btnEls.map(b => b.textContent).join(','),
        btnTextCut: btnEls.some(b => b.scrollWidth > b.clientWidth),
        folderCut: folder.scrollWidth > folder.clientWidth,
        tagsInCell: [...tr.querySelectorAll('td .tag')].every(t =>
          t.getBoundingClientRect().right <= t.parentElement.getBoundingClientRect().right + 0.5),
        authText: tr.children[2].querySelector('.tag').textContent,
        authCut: (t => t.scrollWidth > t.clientWidth)(tr.children[2].querySelector('.tag')),
      };
    });
    return { right: box.right, scrollW: body.scrollWidth, clientW: body.clientWidth, rows };
  })()`);
  check(`${label}: Users table does not scroll sideways`, t.scrollW <= t.clientW,
    `scrollWidth ${t.scrollW} > clientWidth ${t.clientW}`);
  t.rows.forEach((r, i) => {
    check(`${label}: row ${i + 1} one Manage button, fully inside the panel, text not cut`,
      r.btnCount === 1 && r.btnText === 'Manage' && !r.btnTextCut &&
      r.btnRight <= t.right + 0.5 && r.btnLeft >= r.actLeft - 0.5,
      JSON.stringify({ ...r, panelRight: t.right }));
    check(`${label}: row ${i + 1} long folder path shortened`, r.folderCut, JSON.stringify(r));
    check(`${label}: row ${i + 1} permission and sign-in tags stay in their columns`,
      r.tagsInCell, JSON.stringify(r));
    check(`${label}: row ${i + 1} sign-in label "${r.authText}" not cut`, !r.authCut, JSON.stringify(r));
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

// Opens the account editor and walks the three sign-in choices: the helper
// note shows only for "Password or key", and the three buttons stay on one
// row inside the dialog. Screenshots the editor with that choice picked in
// both themes, then closes it without saving.
async function checkEditor(helpers, label, shotName) {
  const { click, evaluate, check, screenshot } = helpers;
  await click("#addUser");
  check(`${label}: Add User dialog has no Delete user button`,
    await evaluate("document.getElementById('umDelete').offsetParent === null"));
  for (const v of ["password", "key", "both"]) {
    await click(`#umAuth button[data-v="${v}"]`);
    const helpShown = await evaluate("document.getElementById('umAuthHelp').offsetParent !== null");
    check(`${label}: editor helper note ${v === "both" ? "shown" : "hidden"} for ${v}`,
      helpShown === (v === "both"), `shown=${helpShown}`);
  }
  const e = await evaluate(`(() => {
    const btns = [...document.querySelectorAll('#umAuth button')];
    const rs = btns.map(b => b.getBoundingClientRect());
    const card = document.querySelector('#userModal .card').getBoundingClientRect();
    return { text: btns[2].textContent,
             oneRow: rs.every(r => Math.abs(r.top - rs[0].top) < 1),
             inside: rs.every(r => r.left >= card.left - 0.5 && r.right <= card.right + 0.5),
             noWrap: btns.every(b => b.scrollWidth <= b.clientWidth) };
  })()`);
  check(`${label}: third sign-in choice reads "Password or key"`, e.text === "Password or key", e.text);
  check(`${label}: sign-in choices on one row, inside the dialog, text not cut`,
    e.oneRow && e.inside && e.noWrap, JSON.stringify(e));
  // The open dialog covers the theme button, so it is pressed from the page.
  const toggleTheme = "document.getElementById('theme-btn').click()";
  await screenshot(`${shotName}-dark`, 0);
  await evaluate(toggleTheme);
  check(`${label}: editor switches to light`, await evaluate("document.body.classList.contains('light')"));
  await screenshot(`${shotName}-light`, 0);
  await evaluate(toggleTheme);
  await click("#umCancel");
}

async function showNotice(helpers) {
  const { click, waitFor, evaluate } = helpers;
  await evaluate("document.getElementById('updateNotice').textContent=''");
  await click("#updateBtn");
  return waitFor("document.getElementById('updateNotice').textContent.length > 0 && !document.getElementById('updateBtn').disabled", 15000);
}

export default async function layout(helpers) {
  const { click, evaluate, waitFor, check, screenshot } = helpers;

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
    users.push({ ...u, username: 'keyuser', auth: 'key', key_count: 12 });
    renderUsers();
  })()`);

  const emptyHeight = await evaluate("document.querySelector('.statusbar').getBoundingClientRect().height");

  await measure(helpers, "full width");
  check("full width: notice appears after Check for updates", await showNotice(helpers));
  await measureBar(helpers, "full width", emptyHeight);
  await screenshot("layout-full-width", 0);
  await checkEditor(helpers, "full width", "editor-full-width");

  await evaluate(`document.querySelector('.app').style.width='${NARROW_PX}px'`);
  await measure(helpers, `${NARROW_PX}px`);
  check(`${NARROW_PX}px: notice appears after Check for updates`, await showNotice(helpers));
  await measureBar(helpers, `${NARROW_PX}px`, emptyHeight);
  await screenshot("layout-narrow", 0);
  await checkEditor(helpers, `${NARROW_PX}px`, "editor-narrow");

  // Delete from the Manage dialog, for real, keeping the folder. The reply
  // replaces the page's list with the saved one, so the page-only users go too.
  await evaluate("document.querySelector('.app').style.width=''");
  await click("#userRows tr:first-child td.act button");
  const m = await evaluate(`({ title: document.getElementById('umTitle').textContent,
    del: document.getElementById('umDelete').offsetParent !== null,
    user: document.getElementById('umUser').value })`);
  check("Manage opens the editor for that user, with Delete user shown",
    m.title === "Manage user" && m.del && m.user === "fixtureuser", JSON.stringify(m));
  await screenshot("manage-dialog-dark", 0);
  await evaluate("document.getElementById('theme-btn').click()");
  await screenshot("manage-dialog-light", 0);
  await evaluate("document.getElementById('theme-btn').click()");
  await click("#umDelete");
  check("Delete user asks first",
    await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000));
  await click("#cfKeep");
  check("after Delete, both dialogs close and the user is gone",
    await waitFor(`!document.getElementById('confirmModal').classList.contains('show') &&
      !document.getElementById('userModal').classList.contains('show') &&
      users.length === 0`, 10000),
    await evaluate("JSON.stringify(users.map(u => u.username))"));
}
