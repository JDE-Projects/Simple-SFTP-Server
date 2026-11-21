// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks layout in the real
// pywebview window, using the one user tools/ui_check/fixture.py writes.
//
// Covers: the one-line Users table keeps its compact permissions and sign-in
// tags, user names, and Manage buttons inside the panel. Its hover card shows
// complete user details and stays within the Users panel at full and narrow
// widths. It also retains the editor, delete-flow, bottom-bar, and Public IP
// layout checks. The page-only users are never saved.
//
// The long path and permissions are set on the page's copy of the user list
// only (nothing is saved). Last, the fixture's user is deleted for real from
// the Manage dialog, keeping its folder, inside the throwaway app copy. The notice comes from a real press of Check for
// updates, which asks GitHub for the latest version.
// Does not cover: resizing the real window, or the Public IP lookup itself
// (it contacts outside services).

const NARROW_PX = 960;
const KEYUSER_COMMENT = "keyuser-comment-that-is-deliberately-longer-than-eighty-characters-to-check-the-editor-truncation-title";

// Hover text on each row's sign-in label, in the order the test users are added.
const EXPECTED_HOVER = [
  "Signs in with a password",
  "Signs in with a password or a public key (ed25519, alice@laptop)",
  `Signs in with a public key (ed25519, ${KEYUSER_COMMENT})`,
];

const PERMISSION_LABELS = [
  "List", "Download", "Upload", "Delete files", "Rename files",
  "Rename folders", "Create folder", "Delete folder",
];

async function measure(helpers, label) {
  const { evaluate, check } = helpers;
  const t = await evaluate(`(() => {
    const body = document.querySelector('#userRows').closest('.pane-body');
    const box = body.getBoundingClientRect();
    const rows = [...document.querySelectorAll('#userRows tr')].map(tr => {
      const act = tr.querySelector('td.act');
      const btnEls = [...act.querySelectorAll('button')];
      const btns = btnEls.map(b => b.getBoundingClientRect());
      const user = tr.children[0];
      const permissions = tr.children[1].querySelector('.tag');
      const auth = tr.children[2].querySelector('.tag');
      return {
        btnLeft: Math.min(...btns.map(r => r.left)),
        btnRight: Math.max(...btns.map(r => r.right)),
        btnCount: btns.length,
        actLeft: act.getBoundingClientRect().left,
        btnText: btnEls.map(b => b.textContent).join(','),
        btnTextCut: btnEls.some(b => b.scrollWidth > b.clientWidth),
        tagsInCell: [...tr.querySelectorAll('td .tag')].every(t =>
          t.getBoundingClientRect().right <= t.parentElement.getBoundingClientRect().right + 0.5),
        username: user.textContent,
        userCut: user.scrollWidth > user.clientWidth,
        permissionsText: permissions.textContent,
        permissionsCut: permissions.scrollWidth > permissions.clientWidth,
        authText: auth.textContent,
        authCut: auth.scrollWidth > auth.clientWidth,
        authLabel: auth.getAttribute('aria-label'),
        manageLabel: btnEls[0].getAttribute('aria-label'),
      };
    });
    const headsCut = [...document.querySelectorAll('#userRows')[0].closest('table').querySelectorAll('thead th')]
      .filter(th => th.scrollWidth > th.clientWidth).map(th => th.textContent);
    return { right: box.right, scrollW: body.scrollWidth, clientW: body.clientWidth, headsCut,
      listScrolls: body.scrollHeight > body.clientHeight, rows,
      expectedUsers: window.__layoutUsers, expectedPermissions: window.__layoutPermissions };
  })()`);
  check(`${label}: Users table does not scroll sideways`, t.scrollW <= t.clientW,
    `scrollWidth ${t.scrollW} > clientWidth ${t.clientW}`);
  check(`${label}: no Users column heading cut`, t.headsCut.length === 0, JSON.stringify(t.headsCut));
  check(`${label}: Users list scrolls for the added rows`, t.rows.length > 5 && t.listScrolls,
    JSON.stringify({ rows: t.rows.length, listScrolls: t.listScrolls }));
  t.rows.forEach((r, i) => {
    check(`${label}: row ${i + 1} one Manage button, fully inside the panel, text not cut`,
      r.btnCount === 1 && r.btnText === 'Manage' && !r.btnTextCut &&
      r.btnRight <= t.right + 0.5 && r.btnLeft >= r.actLeft - 0.5,
      JSON.stringify({ ...r, panelRight: t.right }));
    check(`${label}: row ${i + 1} permission and sign-in tags stay in their columns`,
      r.tagsInCell, JSON.stringify(r));
    const expectedUser = t.expectedUsers[i].username;
    const expectedPermissions = t.expectedPermissions[i];
    check(`${label}: row ${i + 1} permissions tag "${expectedPermissions}" not cut`,
      r.permissionsText === expectedPermissions && !r.permissionsCut, JSON.stringify(r));
    const longUserMayCut = i === 1;
    check(`${label}: row ${i + 1} username ${longUserMayCut ? "is only cut when needed" : "not cut"}`,
      r.username === expectedUser && (longUserMayCut ? (label === `${NARROW_PX}px` ? r.userCut : true) : !r.userCut), JSON.stringify(r));
    check(`${label}: row ${i + 1} Manage label names the user`,
      r.manageLabel === `Manage ${expectedUser}`, JSON.stringify(r));
    check(`${label}: row ${i + 1} sign-in label "${r.authText}" not cut`, !r.authCut, JSON.stringify(r));
    const expectedAuth = EXPECTED_HOVER[i] ?? "Signs in with a password";
    check(`${label}: row ${i + 1} sign-in spoken text "${r.authLabel}"`,
      r.authLabel === expectedAuth, `expected "${expectedAuth}"`);
  });
}

async function checkHoverCard(helpers, label, shotName) {
  const { click, evaluate, waitFor, check, screenshot, press } = helpers;
  const cardVisible = "document.getElementById('userHoverCard').style.display === 'block'";
  const moveAway = () => click(".col:nth-child(2) .pane-title");
  await click('#userRows tr:first-child td:first-child');
  check(`${label}: row 1 hover card opens`, await waitFor(cardVisible, 2000));
  const cardInside = await evaluate(`(() => {
    const card = document.getElementById('userHoverCard').getBoundingClientRect();
    const pane = document.querySelector('#userRows').closest('.pane-body').getBoundingClientRect();
    return { inside: card.left >= pane.left - .5 && card.right <= pane.right + .5 &&
      card.top >= pane.top - .5 && card.bottom <= pane.bottom + .5, card, pane };
  })()`);
  const first = await evaluate(`(() => {
    const card = document.getElementById('userHoverCard');
    const folder = card.querySelector('.hover-folder');
    const entries = [...card.querySelectorAll('.hover-permission')].map(e => ({
      label: e.lastChild.textContent, allowed: !e.classList.contains('off') }));
    return { user: card.querySelector('.hover-user').textContent,
      signIn: [...card.querySelectorAll('.hover-section')][0].textContent.replace('Sign-in', ''),
      folder: folder.textContent, folderCut: folder.scrollWidth > folder.clientWidth, entries };
  })()`);
  const expected = await evaluate(`({ user: window.__layoutUsers[0].username, home: window.__layoutUsers[0].home,
    allowed: window.__layoutUsers[0].permissions, keys: PERM_KEYS })`);
  check(`${label}: row 1 card has complete sign-in, folder, and permissions`,
    first.user === expected.user && first.signIn === EXPECTED_HOVER[0] && first.folder === expected.home &&
    !first.folderCut && first.entries.length === 8 &&
    first.entries.every((entry, i) => entry.label === PERMISSION_LABELS[i] && entry.allowed === !!expected.allowed[expected.keys[i]]),
    JSON.stringify(first));
  check(`${label}: hover card stays inside the Users panel`, cardInside.inside, JSON.stringify(cardInside));
  await screenshot(shotName, 0);

  await moveAway();
  check(`${label}: moving away closes the hover card`, await waitFor(`!(${cardVisible})`, 1000));
  await click('#userRows tr:first-child td:first-child');
  check(`${label}: card reopens before Escape`, await waitFor(cardVisible, 2000));
  await press('Escape');
  check(`${label}: Escape closes the hover card`, await waitFor(`!(${cardVisible})`, 1000));

  // With row 2's card open (below row 2), moving up to row 1 closes it at
  // once, before row 1's own card is due.
  await click('#userRows tr:nth-child(2) td:first-child');
  check(`${label}: row 2 card opens`, await waitFor(`${cardVisible} && document.querySelector('#userHoverCard .hover-user').textContent === window.__layoutUsers[1].username`, 2000));
  await click('#userRows tr:first-child td:first-child');
  check(`${label}: moving to row 1 closes row 2's card at once`, await waitFor(`!(${cardVisible})`, 300));
  check(`${label}: row 1 card follows`, await waitFor(`${cardVisible} && document.querySelector('#userHoverCard .hover-user').textContent === window.__layoutUsers[0].username`, 2000));
  await moveAway();
  await waitFor(`!(${cardVisible})`, 1000);

  // Scrolling closes the card, so each hover waits for the scroll event first.
  const scrollList = async (toEnd) => {
    await evaluate(`(() => { const pane = document.querySelector('#userRows').closest('.pane-body');
      window.__listScrolled = false;
      pane.addEventListener('scroll', () => { window.__listScrolled = true; }, { once: true });
      pane.scrollTop = ${toEnd ? "pane.scrollHeight" : "0"}; })()`);
    await waitFor("window.__listScrolled", 2000);
  };
  await scrollList(true);
  await click('#userRows tr:last-child td:first-child');
  check(`${label}: last row hover card opens after scrolling`, await waitFor(cardVisible, 2000));
  const last = await evaluate(`(() => { const card = document.getElementById('userHoverCard').getBoundingClientRect();
    const row = document.querySelector('#userRows tr:last-child').getBoundingClientRect();
    const pane = document.querySelector('#userRows').closest('.pane-body').getBoundingClientRect();
    return { above: card.bottom <= row.top + .5, inside: card.left >= pane.left - .5 && card.right <= pane.right + .5 &&
      card.top >= pane.top - .5 && card.bottom <= pane.bottom + .5, card, row, pane }; })()`);
  check(`${label}: last row card opens above the row and stays inside the panel`, last.above && last.inside, JSON.stringify(last));

  await scrollList(false);
  check(`${label}: scrolling closes the hover card`, await waitFor(`!(${cardVisible})`, 1000));
  await click('#userRows tr:nth-child(2) td:first-child');
  check(`${label}: row 2 card opens before re-render`, await waitFor(`${cardVisible} && document.querySelector('#userHoverCard .hover-user').textContent === window.__layoutUsers[1].username`, 2000));
  await evaluate('renderUsers()');
  check(`${label}: renderUsers closes the hover card`, await waitFor(`!(${cardVisible})`, 1000));
  await moveAway();
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

async function checkOneKeyEditor(helpers) {
  const { click, evaluate, waitFor, check, screenshot } = helpers;
  const file = {
    key: "ssh-ed25519 file-key-data file@laptop",
    described: { type: "ed25519", comment: "file@laptop", fingerprint: "SHA256:FileFingerPrintIsLongEnoughForTheTitle" },
  };
  const pasted = {
    key: "ssh-ed25519 pasted-key-data paste@laptop",
    described: { type: "ed25519", comment: "paste@laptop", fingerprint: "SHA256:PastedFingerPrintIsLongEnoughForTheTitle" },
  };
  const generated = {
    key: "ssh-ed25519 generated-key-data generated@laptop",
    described: { type: "ed25519", comment: "generated@laptop", fingerprint: "SHA256:GeneratedFingerPrintIsLongEnoughForTheTitle" },
  };
  await evaluate(`(() => {
    window.__oneKeyData = ${JSON.stringify({ file, pasted, generated })};
    window.__oneKeyOriginalApi = {
      pick_key_file: API.pick_key_file, check_public_key: API.check_public_key,
      generate_keypair: API.generate_keypair, save_user: API.save_user,
    };
    window.__oneKeyPickError = false;
    window.__oneKeyUsers = users;
    API.pick_key_file = async () => window.__oneKeyPickError
      ? { ok: false, error: "The chosen file is not a public key." }
      : { ok: true, ...window.__oneKeyData.file };
    API.check_public_key = async text => {
      const data = text.includes("pasted-key") ? window.__oneKeyData.pasted
        : text.includes("generated-key") ? window.__oneKeyData.generated
        : window.__oneKeyData.file;
      return { ok: true, ...data };
    };
    API.generate_keypair = async () => ({ ok: true, public: window.__oneKeyData.generated.key,
      private_path: "C:\\Users\\someone\\.ssh\\id_ed25519" });
    API.save_user = async payload => {
      window.__oneKeySaved = payload;
      return { ok: true, users: window.__oneKeyUsers };
    };
  })()`);
  try {
    await click("#userRows tr:nth-child(3) td.act button");
    await waitFor("document.getElementById('userModal').classList.contains('show')", 5000);
    const current = await evaluate(`(() => {
      const key = document.getElementById('umKeyCurrent');
      const dialog = document.querySelector('#userModal .card').getBoundingClientRect();
      const box = key.getBoundingClientRect();
      return { inside: box.left >= dialog.left - .5 && box.right <= dialog.right + .5,
        cut: key.scrollWidth > key.clientWidth, title: key.title };
    })()`);
    check("narrow editor: current key stays inside, is cut, and titles the full key",
      current.inside && current.cut && current.title.includes(KEYUSER_COMMENT) &&
      current.title.includes("SHA256:KeyuserFingerPrintIsLongEnoughForTheTitle"), JSON.stringify(current));

    await click("#umKeyFile");
    check("Choose file: shows the chosen key as pending",
      await evaluate(`document.getElementById('umKeyPending').offsetParent !== null &&
        document.getElementById('umKeyPending').textContent.includes(${JSON.stringify(file.described.comment)})`));
    // The key section with a cut current key and a pending key, in both themes.
    await evaluate("document.getElementById('umKeyWrap').scrollIntoView({block: 'center'})");
    await screenshot("key-section-narrow-dark", 0);
    await evaluate("document.getElementById('theme-btn').click()");
    await screenshot("key-section-narrow-light", 0);
    await evaluate("document.getElementById('theme-btn').click()");

    await evaluate(`(() => { const e = document.getElementById('umKeys');
      e.value = ${JSON.stringify(pasted.key)}; e.dispatchEvent(new Event('change')); })()`);
    await waitFor(`document.getElementById('umKeyPending').textContent.includes(${JSON.stringify(pasted.described.comment)})`, 5000);
    check("Paste: replaces pending, then clears the textarea",
      await evaluate("document.getElementById('umKeys').value === ''"));

    await click("#umKeygen");
    await waitFor("document.getElementById('keygenModal').classList.contains('show')", 5000);
    await evaluate("document.getElementById('kgPath').value='C:\\\\Users\\\\someone\\\\.ssh\\\\id_ed25519'");
    await click("#kgGo");
    await waitFor(`document.getElementById('umKeyPending').textContent.includes(${JSON.stringify(generated.described.comment)})`, 5000);
    check("Generate: replaces pending with the generated key", true);
    await click("#kgClose");

    await evaluate("window.__oneKeyPickError = true");
    await click("#umKeyFile");
    const error = await evaluate(`({ error: document.getElementById('umKeyErr').textContent,
      pending: document.getElementById('umKeyPending').textContent })`);
    check("Choose file error: shows the error and keeps pending", error.error === "The chosen file is not a public key." &&
      error.pending.includes(generated.described.comment), JSON.stringify(error));

    await click("#umSave");
    await waitFor("!document.getElementById('userModal').classList.contains('show')", 5000);
    const saved = await evaluate("window.__oneKeySaved");
    check("Save: sends the pending public key without authorized_keys",
      saved.public_key === generated.key && !("authorized_keys" in saved), JSON.stringify(saved));

    await click("#userRows tr:nth-child(3) td.act button");
    await click("#umCancel");
    await click("#userRows tr:nth-child(3) td.act button");
    const reset = await evaluate(`({ pending: document.getElementById('umKeyPending').offsetParent !== null,
      text: document.getElementById('umKeys').value, error: document.getElementById('umKeyErr').textContent })`);
    check("Cancel then reopen: pending, pasted text, and key error are cleared",
      !reset.pending && reset.text === "" && reset.error === "", JSON.stringify(reset));
    await click("#umCancel");

    const authTags = await evaluate("[...document.querySelectorAll('#userRows tr')].slice(0, 3).map(tr => tr.children[2].textContent)");
    check("Auth tags show PW, PW or Key, and Key without counts",
      JSON.stringify(authTags) === JSON.stringify(["PW", "PW or Key", "Key"]), JSON.stringify(authTags));
  } finally {
    await evaluate(`(() => {
      Object.assign(API, window.__oneKeyOriginalApi);
      delete window.__oneKeyOriginalApi;
      delete window.__oneKeyData;
      delete window.__oneKeyUsers;
    })()`);
  }
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

  // Page-only test data exercises compact permission counts, truncation, and
  // scrolling without changing the saved fixture user.
  await evaluate(`(() => {
    const u = users[0];
    const all = value => Object.fromEntries(PERM_KEYS.map(k => [k, value(k)]));
    u.home = 'C:\\\\Users\\\\someone\\\\Documents\\\\Shared with the team\\\\Quarterly reports and invoices\\\\2026\\\\incoming';
    u.permissions = all(k => k !== 'delete_dir');
    users.push({ ...u, username: 'thirty-two-character-user-name-x', auth: 'both',
                  key: {type: 'ed25519', comment: 'alice@laptop', fingerprint: 'SHA256:BothUserFingerPrintIsLongEnoughForTheTitle'},
                 permissions: all(k => k === 'list') });
    users.push({ ...u, username: 'keyuser', auth: 'key',
                  key: {type: 'ed25519', comment: '${KEYUSER_COMMENT}', fingerprint: 'SHA256:KeyuserFingerPrintIsLongEnoughForTheTitle'} });
    users.push({ ...u, username: 'allaccess', permissions: all(() => true) });
    users.push({ ...u, username: 'noaccess', permissions: all(() => false) });
    for (let i = 1; i <= 20; i += 1) users.push({ ...u, username: 'scrolluser' + i, home: 'D:\\\\Shares\\\\Team\\\\' + i });
    window.__layoutUsers = users.map(u => ({ ...u, permissions: { ...u.permissions } }));
    window.__layoutPermissions = users.map(u => {
      const count = PERM_KEYS.filter(k => u.permissions[k]).length;
      return count === 8 ? 'All' : count === 0 ? 'None' : count + ' of 8';
    });
    renderUsers();
  })()`);

  const emptyHeight = await evaluate("document.querySelector('.statusbar').getBoundingClientRect().height");

  await measure(helpers, "full width");
  await checkHoverCard(helpers, "full width", "hover-card-full-width-dark");
  check("full width: notice appears after Check for updates", await showNotice(helpers));
  await measureBar(helpers, "full width", emptyHeight);
  await screenshot("layout-full-width", 0);
  await checkEditor(helpers, "full width", "editor-full-width");

  await evaluate(`document.querySelector('.app').style.width='${NARROW_PX}px'`);
  await measure(helpers, `${NARROW_PX}px`);
  await checkHoverCard(helpers, `${NARROW_PX}px`, "hover-card-narrow-dark");
  check(`${NARROW_PX}px: notice appears after Check for updates`, await showNotice(helpers));
  await measureBar(helpers, `${NARROW_PX}px`, emptyHeight);
  await screenshot("layout-narrow", 0);
  await checkEditor(helpers, `${NARROW_PX}px`, "editor-narrow");
  await checkOneKeyEditor(helpers);

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
