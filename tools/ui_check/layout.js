// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks layout in the real
// pywebview window, using the one user tools/ui_check/fixture.py writes.
//
// Covers: the one-line Users table keeps its compact permissions and sign-in
// tags, user names, and Manage buttons inside the panel. Its hover card shows
// complete user details and stays within the Users panel at full and narrow
// widths. It also retains the editor, delete-flow, bottom-bar, and Public IP
// layout checks, including saved-key on/off behavior. The page-only users are
// never saved.
//
// The long path and permissions are set on the page's copy of the user list
// only (nothing is saved). Last, the fixture's user is deleted for real from
// the Manage dialog, keeping its folder, inside the throwaway app copy. The notice comes from a real press of Check for
// updates, which asks GitHub for the latest version.
// Does not cover: resizing the real window, or the Public IP lookup itself
// (it contacts outside services).

const NARROW_PX = 960;
const KEYUSER_COMMENT = "keyuser-comment-that-is-deliberately-longer-than-eighty-characters-to-check-the-editor-truncation-title";
const MULTI_KEYS = [
  { type: "ed25519", comment: "first-device", fingerprint: "SHA256:FirstDeviceFingerPrint" },
  { type: "rsa", comment: "second-device", fingerprint: "SHA256:SecondDeviceFingerPrint" },
];

// Hover text on each row's sign-in label, in the order the test users are added.
const EXPECTED_HOVER = [
  "Signs in with a password",
  "Signs in with a password or a public key. Keys: 1 on",
  "Signs in with a public key. Keys: 1 on",
  "Signs in with a public key. Keys: 2 on, 1 off",
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

async function checkMultiKeyEditor(helpers) {
  const { click, evaluate, waitFor, check, screenshot } = helpers;
  await evaluate(`(() => {
    const result = (key, name = "") => ({ key: name ? key + " " + name : key,
      described: { type: key.split(" ")[0].replace("ssh-", ""), comment: name,
        fingerprint: "SHA256:" + key.split(" ")[1] + "Fingerprint" }, note: null });
    window.__multiOriginalApi = { pick_key_file: API.pick_key_file, check: API.check_public_key,
      generate_keypair: API.generate_keypair, save_user: API.save_user };
    window.__multi = { result, fileMode: "one", saved: null, delayed: null };
    API.check_public_key = async text => {
      if (text.includes("delayed")) return new Promise(resolve => { window.__multi.delayed = () => resolve({ ok: true, keys: [result("ssh-ed25519 delayed-data", "delayed")] }); });
      if (text.includes("invalid")) return { ok: false, error: "That is not a valid public key." };
      const keys = text.trim().split(/\\n+/).map(line => { const p = line.trim().split(/\\s+/, 3); return result(p[0] + " " + p[1], p[2] || ""); });
      return { ok: true, keys };
    };
    API.pick_key_file = async () => ({ ok: true, keys: window.__multi.fileMode === "one"
      ? [result("ssh-ed25519 file-data", "file@laptop")]
      : [result("ssh-ed25519 file-one", "one"), result("ssh-rsa file-two", "two")] });
    API.generate_keypair = async () => ({ ok: true, public: "ssh-ed25519 generated-data generated@laptop", private_path: "C:\\\\keys\\\\id_ed25519" });
    API.save_user = async payload => { window.__multi.saved = payload; return { ok: true, users }; };
    window.__multiUser = { username: "multikey", home: "C:\\\\keys", auth: "key", has_password: false,
      permissions: Object.fromEntries(PERM_KEYS.map(key => [key, key === "list"])), key_count: 2,
      key: { type: "ed25519", comment: "first", fingerprint: "SHA256:first-dataFingerprint" }, keys: [
        { line: "ssh-ed25519 first-data first", valid: true, type: "ed25519", comment: "first", fingerprint: "SHA256:first-dataFingerprint", name_problem: null },
        { line: "ssh-rsa second-data", valid: true, type: "rsa", comment: "", fingerprint: "SHA256:second-dataFingerprint", name_problem: null },
      ] };
  })()`);
  try {
    await evaluate("openUser(window.__multiUser);setAuth('key')");
    check("W1 list renders stored keys with name, fingerprint, Rename, and Remove", await evaluate(`(() => {
      const rows = [...document.querySelectorAll('#umKeyList .key-row')]; return rows.length === 2 && rows.every(row => row.textContent.includes('Rename') && row.textContent.includes('Remove')) &&
        rows[0].textContent.includes('ed25519') && rows[0].textContent.includes('first') && rows[1].textContent.includes('(no name)'); })()`));
    const narrow = await evaluate(`(() => { document.querySelector('.app').style.width='${NARROW_PX}px'; const list=document.getElementById('umKeyList'); const rows=[...list.querySelectorAll('.key-row')]; return rows.every(row => row.getBoundingClientRect().right <= list.getBoundingClientRect().right + 1 && row.querySelector('.key-rename-btn').offsetParent !== null && row.querySelector('.key-remove').offsetParent !== null) && rows[0].title.includes('SHA256:'); })()`);
    check("W2 full and narrow rows keep Rename and Remove inside the panel", narrow);
    // Screenshots of filled rows: a named key, an unnamed key turned off, a long name, a
    // name that must be renamed, and an invalid entry, in both themes.
    const showRows = `(() => { workingKeys = [
      { line:'ssh-ed25519 shot-a alice@laptop', valid:true, type:'ed25519', comment:'alice@laptop', fingerprint:'SHA256:Abc123Def456Ghi789Jkl012Mno345Pqr678Stu901', name_problem:null },
      { line:'ssh-rsa shot-b', valid:true, type:'rsa', comment:'', fingerprint:'SHA256:Zyx987Wvu654Tsr321Qpo098Nml765Kji432Hgf109', name_problem:null, enabled:false },
      { line:'ssh-ed25519 shot-c long', valid:true, type:'ed25519', comment:'build-server-in-the-basement-rack-two-with-a-deliberately-long-friendly-name-for-truncation', fingerprint:'SHA256:Lmn456Opq789Rst012Uvw345Xyz678Abc901Def234', name_problem:null },
      { line:'ssh-ed25519 shot-d odd', valid:true, type:'ed25519', comment:'odd name', fingerprint:'SHA256:Qrs111Tuv222Wxy333Zab444Cde555Fgh666Ijk777', name_problem:'The key name contains hidden characters.' },
      { line:'garbage', valid:false, type:'', comment:'', fingerprint:'', name_problem:null },
    ]; renderKeyList(); document.getElementById('umKeyWrap').scrollIntoView({block:'start'}); })()`;
    await evaluate(showRows);
    await screenshot("keys-narrow-dark", 0);
    await evaluate("document.querySelector('.app').style.width=''");
    await evaluate(showRows);
    await screenshot("keys-full-width-dark", 0);
    await evaluate("document.getElementById('theme-btn').click()");
    await screenshot("keys-full-width-light", 0);
    await evaluate("document.getElementById('theme-btn').click()");
    await evaluate(`(() => { workingKeys = Array.from({length:25}, (_, i) => ({ line:'ssh-ed25519 many-'+i+' key-'+i, valid:true, type:'ed25519', comment:'key-'+i, fingerprint:'SHA256:many-'+i, name_problem:null })); renderKeyList(); })()`);
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 extra-data extra'");await click("#umKeyAdd");
    check("W3 25 keys stay usable and Add refuses the limit", await evaluate("document.getElementById('umKeyCount').textContent === '25 keys (up to 25)' && document.getElementById('umKeyList').scrollHeight >= document.getElementById('umKeyList').clientHeight && document.getElementById('umKeyErr').textContent.includes('at most 25')"));
    await evaluate("openUser({...window.__multiUser, keys:[{line:'bad',valid:false,type:'',comment:'',fingerprint:'',name_problem:null}]});setAuth('key')");await click("#umSave");
    check("W4 invalid stored entry blocks Save", await evaluate("document.getElementById('umKeyErr').textContent === 'Remove the key marked Not a valid key before saving.'"));
    await evaluate("openUser(window.__multiUser);setAuth('key')");await click("#umKeyList .key-remove");await evaluate("closeModal('userModal');openUser(window.__multiUser);setAuth('key')");const restored=await evaluate("workingKeys.length === 2");await click("#umKeyList .key-remove");await evaluate("window.__multi.saved=null");await click("#umSave");
    check("W5 Remove, Cancel, reopen, and Save preserve the working copy", restored && await evaluate("Array.isArray(window.__multi.saved.authorized_keys) && window.__multi.saved.authorized_keys.length === 1"));
    await waitFor("!document.getElementById('userModal').classList.contains('show')", 5000);await evaluate("openUser(window.__multiUser);setAuth('key')");
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 single-data';");await click("#umKeyAdd");
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 second-data';");await click("#umKeyAdd");
    check("W6 nameless pasted keys receive the next username-based names", await evaluate("workingKeys.some(key => key.line === 'ssh-ed25519 single-data multikey-key1') && workingKeys.some(key => key.line === 'ssh-ed25519 second-data multikey-key2')"));
    check("W7 removed naming controls and label are absent", await evaluate("!document.getElementById(['umKey', 'Name'].join('')) && !document.getElementById(['umKey', 'NameHint'].join('')) && !document.getElementById('userModal').innerText.includes(['Friendly', 'Name'].join(' '))"));
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 three-one one\\nssh-rsa three-two two\\nssh-ed25519 three-three three';");
    await click("#umKeyAdd");
    check("W8 three pasted keys retain names and append", await evaluate("workingKeys.length === 7"));
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 three-one one'");await click("#umKeyAdd");
    check("W9 duplicate paste is skipped", await evaluate("document.getElementById('umKeyErr').textContent === 'Already on the list: one.'"));
    await evaluate("workingKeys=[];renderKeyList();window.__multi.fileMode='one'");await click("#umKeyFile");const oneFile=await evaluate("document.getElementById('umKeys').value.includes('file-data')");await evaluate("window.__multi.fileMode='many'");await click("#umKeyFile");await click("#umKeygen");await evaluate("document.getElementById('kgPath').value='C:\\\\keys\\\\id'");await click("#kgGo");
    check("W10 file and generated keys add without replacing rows", oneFile && await evaluate("workingKeys.length === 2 && document.getElementById('umKeys').value.includes('generated-data')"));
    await click("#kgClose");await click("#umKeyList .key-rename-btn");await evaluate("const input=document.querySelector('#umKeyList .key-rename');input.value='renamed';input.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))");await waitFor("workingKeys[0].comment === 'renamed'", 2000);const renamed=await evaluate("workingKeys[0].line");await click("#umKeyList .key-rename-btn");await evaluate("document.querySelector('#umKeyList .key-rename').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))");
    const stillOpen = await evaluate("document.getElementById('userModal').classList.contains('show') && !document.querySelector('#umKeyList .key-rename') && workingKeys[0].comment === 'renamed'");
    check("W11 Rename opens the name box, Enter saves, and Escape cancels without closing the window", renamed === "ssh-ed25519 file-one renamed" && stillOpen);
    await evaluate("document.getElementById('umKeys').value='ssh-ed25519 save-data save';window.__multi.saved=null");await click("#umSave");await waitFor("window.__multi.saved !== null", 2000);const saveText=await evaluate("window.__multi.saved.authorized_keys.some(key => key.includes('save-data'))");await evaluate("openUser(window.__multiUser);setAuth('key');document.getElementById('umKeys').value='invalid'");await click("#umSave");
    check("W12 Save adds pasted text and refuses invalid text", saveText && await evaluate("document.getElementById('umKeyErr').textContent.includes('not a valid') && window.__multi.saved !== null"));
    await evaluate("cur={connections:[{user:'multikey',active:0}]};openUser(window.__multiUser);setAuth('key');document.getElementById('umKeys').value='ssh-ed25519 warning-data warning'");await click("#umSave");const warned=await evaluate("document.getElementById('confirmModal').classList.contains('show')");await click("#cfCancel");await evaluate("openUser(window.__multiUser);setAuth('key');window.__multi.saved=null");await click("#umSave");
    check("W13 added key warns for a live user, rename-only does not", warned && await evaluate("window.__multi.saved !== null && !document.getElementById('confirmModal').classList.contains('show')"));
    const hover=await evaluate("authHover({...window.__multiUser,key_count:1})+'|'+authHover(window.__multiUser)+'|'+document.body.innerText.includes('older'+' version')");
    check("W14 hover counts keys the same way for one or several, with no key type and no old wording", hover === 'Signs in with a public key. Keys: 1 on|Signs in with a public key. Keys: 2 on|false', hover);
    await evaluate("openUser(window.__multiUser);setAuth('key');document.getElementById('umKeys').value='ssh-ed25519 delayed-data delayed'");await click("#umKeyAdd");await evaluate("closeModal('userModal');openUser(window.__multiUser);window.__multi.delayed()")
    await waitFor("!keyBusy", 2000);
    check("W15 stale Add reply does not change a reopened window", await evaluate("workingKeys.length === 2 && !workingKeys.some(key => key.line.includes('delayed-data'))"));
    await evaluate("openUser({...window.__multiUser,keys:[...window.__multiUser.keys,{line:'bad',valid:false,type:'',comment:'',fingerprint:'',name_problem:null}]});setAuth('key')");
    check("W15 each valid row has a switch before Remove and the invalid entry has none", await evaluate(`(() => {
      const rows=[...document.querySelectorAll('#umKeyList .key-row')]; return rows.slice(0,2).every(row=>{
        const sw=row.querySelector('.key-toggle');const remove=row.querySelector('.key-remove');return sw&&remove&&sw.compareDocumentPosition(remove)&Node.DOCUMENT_POSITION_FOLLOWING;
      })&&!rows[2].querySelector('.key-toggle'); })()`));
    await evaluate("openUser({ ...window.__multiUser, key_count: 1, off_count: 1, keys: [{ ...window.__multiUser.keys[0], enabled: true }, { ...window.__multiUser.keys[1], enabled: false }] });setAuth('key')");
    check("W16 a stored off key opens with its switch off and its row dimmed", await evaluate("!document.querySelectorAll('#umKeyList .key-toggle input')[1].checked && document.querySelectorAll('#umKeyList .key-row')[1].classList.contains('key-off')"));
    await evaluate("cur=null;openUser(window.__multiUser);setAuth('key');window.__multi.saved=null;document.querySelectorAll('#umKeyList .key-toggle input')[0].click()");await click("#umSave");await waitFor("window.__multi.saved !== null",2000);
    const offSaved=await evaluate("window.__multi.saved.disabled_keys.some(key=>key.includes('first-data'))&&!window.__multi.saved.authorized_keys.some(key=>key.includes('first-data'))");
    await evaluate("openUser({ ...window.__multiUser, key_count: 1, off_count: 1, keys: [{ ...window.__multiUser.keys[0], enabled: false }, { ...window.__multiUser.keys[1], enabled: true }] });setAuth('key');window.__multi.saved=null;document.querySelectorAll('#umKeyList .key-toggle input')[0].click()");await click("#umSave");await waitFor("window.__multi.saved !== null",2000);
    check("W17 Save sends off keys only in disabled_keys and on keys only in authorized_keys", offSaved&&await evaluate("window.__multi.saved.authorized_keys.some(key=>key.includes('first-data'))&&!window.__multi.saved.disabled_keys.some(key=>key.includes('first-data'))"));
    await evaluate("openUser({ ...window.__multiUser, key_count: 1, off_count: 1, keys: [{ ...window.__multiUser.keys[0], enabled: true }, { ...window.__multiUser.keys[1], enabled: false }] });setAuth('key');document.querySelectorAll('#umKeyList .key-toggle input')[1].click();closeModal('userModal');openUser({ ...window.__multiUser, key_count: 1, off_count: 1, keys: [{ ...window.__multiUser.keys[0], enabled: true }, { ...window.__multiUser.keys[1], enabled: false }] });setAuth('key')");
    check("W18 Cancel after flipping a switch restores the stored state when reopened", await evaluate("!document.querySelectorAll('#umKeyList .key-toggle input')[1].checked"));
    await evaluate("openUser({ ...window.__multiUser, key_count: 0, off_count: 2, key: null, keys: window.__multiUser.keys.map(key=>({...key,enabled:false})) });setAuth('key');window.__multi.saved=null");await click("#umSave");
    check("W19 every key off stops Save before the back end", await evaluate("document.getElementById('umKeyErr').textContent === 'Turn on at least one key (or switch to password auth).' && window.__multi.saved === null"));
    await evaluate("cur={connections:[{user:'multikey',active:0}]};openUser(window.__multiUser);setAuth('key');document.querySelectorAll('#umKeyList .key-toggle input')[0].click();window.__multi.saved=null");await click("#umSave");
    const toggleWarned=await evaluate("document.getElementById('confirmModal').classList.contains('show')");await click("#cfCancel");
    const offRenameOnly=await evaluate("(() => { openUser({ ...window.__multiUser, key_count: 1, off_count: 1, keys: [{ ...window.__multiUser.keys[0], enabled: true }, { ...window.__multiUser.keys[1], enabled: false }] }); setAuth('key'); workingKeys[1].line='ssh-rsa second-data renamed'; workingKeys[1].comment='renamed'; return !changesAccess({username:'multikey',home:'C:\\\\keys',auth:'key',password:'',permissions:getPermissions(),authorized_keys:[workingKeys[0].line],disabled_keys:[workingKeys[1].line]}); })()");
    check("W20 turning a key off warns for a live user and renaming only an off key does not", toggleWarned&&offRenameOnly);
    await evaluate("openUser({ ...window.__multiUser, key_count: 1, off_count: 2, key: window.__multiUser.key, keys: [{ ...window.__multiUser.keys[0], enabled: true }, { ...window.__multiUser.keys[1], enabled: false }, { ...window.__multiUser.keys[1], line: 'ssh-rsa third-data third', comment: 'third', enabled: false }] });setAuth('key')");
    check("W21 count line, row labels, and hover card show off-key wording", await evaluate("document.getElementById('umKeyCount').textContent === '3 keys, 2 off (up to 25)' && [...document.querySelectorAll('#umKeyList .key-state')].map(el=>el.textContent).join() === 'On,Off,Off' && [...document.querySelectorAll('#umKeyList .key-fingerprint')].every(el=>el.textContent.startsWith('ID ')) && authHover({auth:'key',key_count:3,off_count:1}) === 'Signs in with a public key. Keys: 3 on, 1 off' && authHover({auth:'both',key_count:1,off_count:0}) === 'Signs in with a password or a public key. Keys: 1 on' && authHover({auth:'key',key_count:0,off_count:2}) === 'Signs in with a public key. Keys: 0 on, 2 off' && authHover({auth:'key',key_count:0,off_count:0}) === 'Signs in with a public key. Keys: none'"));
    const switchedRows=await evaluate(`(() => { const list=document.getElementById('umKeyList'); const inside=()=>[...list.querySelectorAll('.key-row')].every(row=>row.getBoundingClientRect().right<=list.getBoundingClientRect().right+1); const full=inside(); document.querySelector('.app').style.width='${NARROW_PX}px'; const narrow=inside(); document.querySelector('.app').style.width=''; return full&&narrow; })()`);
    check("W22 a row with a switch stays inside the list at full and narrow width", switchedRows);
    await evaluate("cur=null;openUser(window.__multiUser);setAuth('password');window.__multi.saved=null");await click("#umSave");
    const lossText=await evaluate("document.getElementById('confirmModal').classList.contains('show') ? document.getElementById('cfTitle').textContent+'|'+document.getElementById('cfText').textContent : 'no warning'");
    await click("#cfCancel");const notSaved=await evaluate("window.__multi.saved === null");
    await evaluate("openUser({...window.__multiUser,auth:'password',key_count:0,keys:[]});setAuth('password');document.getElementById('umPw').value='a-test-password-1';window.__multi.saved=null");await click("#umSave");await waitFor("window.__multi.saved !== null",2000);
    const noKeysNoWarning=await evaluate("!document.getElementById('confirmModal').classList.contains('show')");
    check("W23 switching to password only warns that the keys will be deleted, Cancel saves nothing, and a user with no keys gets no warning", lossText.startsWith("Delete saved keys?|Password only sign-in deletes the 2 public keys") && notSaved && noKeysNoWarning, lossText);
    await evaluate("closeModal('userModal');document.querySelector('.app').style.width=''");
  } finally {
    await evaluate("API.pick_key_file=window.__multiOriginalApi.pick_key_file;API.check_public_key=window.__multiOriginalApi.check;API.generate_keypair=window.__multiOriginalApi.generate_keypair;API.save_user=window.__multiOriginalApi.save_user;delete window.__multiOriginalApi;delete window.__multi;delete window.__multiUser;");
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
                  key: {type: 'ed25519', comment: 'alice@laptop', fingerprint: 'SHA256:BothUserFingerPrintIsLongEnoughForTheTitle'}, key_count: 1,
                 permissions: all(k => k === 'list') });
    users.push({ ...u, username: 'keyuser', auth: 'key',
                  key: {type: 'ed25519', comment: '${KEYUSER_COMMENT}', fingerprint: 'SHA256:KeyuserFingerPrintIsLongEnoughForTheTitle'}, key_count: 1 });
    users.push({ ...u, username: 'multikeys', auth: 'key', key: ${JSON.stringify(MULTI_KEYS[0])}, keys: ${JSON.stringify(MULTI_KEYS)}, key_count: 2, off_count: 1 });
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
  await checkMultiKeyEditor(helpers);

  // Delete from the Manage dialog, for real, keeping the folder. The reply
  // The reply sets the page's list to the saved one, so the page-only users go too.
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
