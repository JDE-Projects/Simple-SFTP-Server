// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks the spacing and text
// treatment rules in the real app window, using the saved weak-key user from
// tools/ui_check/fixture_weak_key.py. Page-only changes set up transient
// lists, errors, and dialogs; no users, keys, or files are saved.
//
// Covers: labels, hints, section steps, errors, warnings, dialogs, the key
// generator, both themes, and a scrolling small-window dialog. Screenshots
// show the requested Manage, key-generator, and folder-confirm states.
// Does not cover: native file pickers, saving users or keys, or update checks.

const TOLERANCE = 0.5;

// A fresh ed25519 public key line in OpenSSH form. The fixture's weak RSA key
// is refused by the key check, so it cannot stand in for a valid paste.
async function ed25519Line(comment) {
  const { generateKeyPairSync } = await import("node:crypto");
  const raw = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const part = buf => { const len = Buffer.alloc(4); len.writeUInt32BE(buf.length); return Buffer.concat([len, buf]); };
  const blob = Buffer.concat([part(Buffer.from("ssh-ed25519")), part(raw)]);
  return `ssh-ed25519 ${blob.toString("base64")} ${comment}`;
}

function near(value, expected) {
  return Math.abs(value - expected) <= TOLERANCE;
}

async function gap(helpers, upper, lower) {
  return helpers.evaluate(`(() => {
    const up = document.querySelector(${JSON.stringify(upper)});
    const down = document.querySelector(${JSON.stringify(lower)});
    if (!up || !down) return { missing: !up ? ${JSON.stringify(upper)} : ${JSON.stringify(lower)} };
    const a = up.getBoundingClientRect(), b = down.getBoundingClientRect();
    return { value: b.top - a.bottom, upper: { top:a.top, bottom:a.bottom, height:a.height },
      lower: { top:b.top, bottom:b.bottom, height:b.height } };
  })()`);
}

async function checkGap(helpers, name, upper, lower, expected) {
  const value = await gap(helpers, upper, lower);
  helpers.check(name, !value.missing && near(value.value, expected),
    value.missing || `measured ${value.value}px, expected ${expected}px (±${TOLERANCE}px)`);
}

async function checkStyle(helpers, name, selector, expected) {
  const actual = await helpers.evaluate(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return { missing: true };
    const probe = document.createElement('span');
    probe.style.color = ${JSON.stringify(expected.variable)};
    document.body.append(probe);
    const result = { color: getComputedStyle(el).color, variable: getComputedStyle(probe).color,
      size: parseFloat(getComputedStyle(el).fontSize), italic: getComputedStyle(el).fontStyle };
    probe.remove();
    return result;
  })()`);
  helpers.check(name, !actual.missing && actual.color === actual.variable &&
    near(actual.size, expected.size) && (!expected.italic || actual.italic === 'italic'), JSON.stringify(actual));
}

async function checkErrorLine(helpers, id, upper, lower, message) {
  const { evaluate, check } = helpers;
  await evaluate(`document.getElementById(${JSON.stringify(id)}).textContent = ''`);
  const empty = await evaluate(`(() => { const el = document.getElementById(${JSON.stringify(id)}); return el.getBoundingClientRect().height; })()`);
  check(`${id}: empty error line has zero height`, near(empty, 0), `measured ${empty}px`);
  const before = await evaluate(`document.getElementById('userModal').querySelector('.card').scrollHeight`);
  await evaluate(`document.getElementById(${JSON.stringify(id)}).textContent = ${JSON.stringify(message)}`);
  const shown = await evaluate(`(() => { const el = document.getElementById(${JSON.stringify(id)}); return { height: el.getBoundingClientRect().height,
    scrollHeight: document.getElementById('userModal').querySelector('.card').scrollHeight }; })()`);
  await checkGap(helpers, `${id}: shown error is 4px under the preceding content`, upper, `#${id}`, 4);
  await checkGap(helpers, `${id}: next section is 16px below the shown error`, `#${id}`, lower, 16);
  check(`${id}: error increases dialog content by its own height`,
    shown.scrollHeight - before >= shown.height - TOLERANCE,
    JSON.stringify({ before, after: shown.scrollHeight, errorHeight: shown.height }));
  await evaluate(`document.getElementById(${JSON.stringify(id)}).textContent = ''`);
}

// Every visible section in a dialog: its label sits 6px above the next
// element, its last visible content sits 16px above the next section's label,
// and the last section sits 16px above the dialog buttons.
async function checkSections(helpers, name, modalId) {
  const r = await helpers.evaluate(`(() => {
    const card = document.querySelector('#${modalId} .card');
    const vis = el => el.offsetParent !== null && el.getBoundingClientRect().height > 0;
    const rows = [...card.querySelectorAll(':scope > .row')].filter(vis);
    const lastBottom = row => Math.max(...[...row.querySelectorAll('*')].filter(vis).map(e => e.getBoundingClientRect().bottom));
    const bad = [];
    rows.forEach((row, i) => {
      for (const label of row.querySelectorAll(':scope > .f > .field-label:first-child')) {
        const next = label.nextElementSibling;
        if (next && vis(next)) {
          const g = next.getBoundingClientRect().top - label.getBoundingClientRect().bottom;
          if (Math.abs(g - 6) > ${TOLERANCE}) bad.push(label.textContent.trim() + ' label: ' + g);
        }
      }
      const after = i + 1 < rows.length ? rows[i + 1].querySelector('.field-label') : card.querySelector(':scope > .modal-actions');
      const g = after.getBoundingClientRect().top - lastBottom(row);
      if (Math.abs(g - 16) > ${TOLERANCE}) bad.push('after section ' + (i + 1) + ': ' + g);
    });
    return { sections: rows.length, bad };
  })()`);
  helpers.check(name, r.sections > 0 && r.bad.length === 0, JSON.stringify(r));
}

async function setTheme(helpers, theme) {
  const { evaluate, waitFor } = helpers;
  const isLight = await evaluate("document.body.classList.contains('light')");
  if (isLight !== (theme === 'light')) {
    await evaluate('toggleTheme()');
    await waitFor(`document.body.classList.contains('light') === ${theme === 'light'}`, 5000);
  }
}

export default async function spacing(helpers) {
  const { click, evaluate, waitFor, check, screenshot, fixture } = helpers;

  // 1. Fonts and the live page must both be ready before any measurement.
  await waitFor("document.fonts && document.fonts.status === 'loaded' && typeof API !== 'undefined' && API && meta && users.length === 1", 10000);
  check('1. fonts and app are ready before measuring',
    await evaluate("document.fonts.status === 'loaded' && !!API && !!meta"));

  for (const theme of ['dark', 'light']) {
    await setTheme(helpers, theme);
    const prefix = `${theme}:`;

    // 2. Add User, password mode.
    await evaluate('openUser(null)');
    await waitFor("document.getElementById('userModal').classList.contains('show')", 5000);
    await checkGap(helpers, `${prefix} 2. Username label is 6px above its field`, '#umTitle + .row .field-label', '#umUser', 6);
    await checkGap(helpers, `${prefix} 2. password label is 6px above its field`, '#umPwWrap .field-label', '#umPw', 6);
    await checkGap(helpers, `${prefix} 2. password hint is 4px under its field`, '#umPwWrap > .f > div:nth-of-type(1)', '#umPwHint', 4);
    await checkSections(helpers, `${prefix} 2. Add User sections follow the rule`, 'userModal');
    const addUser = await evaluate(`({ hint: document.getElementById('umPwHint').textContent,
      deleteHidden: document.getElementById('umDelete').offsetParent === null })`);
    check(`${prefix} 2. Add User has its password hint and hides Delete`,
      addUser.hint.includes('one-way hash') && addUser.deleteHidden, JSON.stringify(addUser));
    await evaluate("closeModal('userModal')");

    // 3. Existing user, password, key, and both modes.
    await evaluate("openUser({...users[0], auth:'password', has_password:true})");
    await checkGap(helpers, `${prefix} 3. Manage password hint is 4px under its field`, '#umPwWrap > .f > div:nth-of-type(1)', '#umPwHint', 4);
    await checkSections(helpers, `${prefix} 3. Manage password-mode sections follow the rule`, 'userModal');
    await evaluate("setAuth('key')");
    await waitFor("document.getElementById('umKeyWrap').offsetParent !== null", 2000);
    await checkSections(helpers, `${prefix} 3. Manage key-mode sections follow the rule`, 'userModal');
    await checkGap(helpers, `${prefix} 3. Public keys label is 6px above its list`, '#umKeyWrap .field-label', '#umKeyList', 6);
    await evaluate("setAuth('both')");
    const both = await evaluate("document.getElementById('umAuthHelp').offsetParent !== null");
    check(`${prefix} 3. both mode shows its help hint`, both);
    await checkSections(helpers, `${prefix} 3. Manage both-mode sections follow the rule`, 'userModal');
    await checkGap(helpers, `${prefix} 3. both-mode help hint is 4px under sign-in choices`, '#umAuth', '#umAuthHelp', 4);

    // 4. Empty, filled, multi-paste, and weak-key warning states.
    await evaluate("openUser({...users[0], auth:'key', keys:[]});setAuth('key')");
    await checkGap(helpers, `${prefix} 4. empty key list is 6px above paste box`, '#umKeyList', '#umKeys', 6);
    await evaluate(`workingKeys=[{line:'ssh-ed25519 page-one alpha',valid:true,enabled:true,type:'ed25519',comment:'alpha',fingerprint:'SHA256:page-one',name_problem:null}];renderKeyList()`);
    await checkGap(helpers, `${prefix} 4. filled key list is 6px above paste box`, '#umKeyList', '#umKeys', 6);
    await evaluate(`document.getElementById('umKeys').value=${JSON.stringify(`${await ed25519Line("spacing-one")}\n${await ed25519Line("spacing-two")}`)};document.getElementById('umKeys').dispatchEvent(new Event('input'))`);
    await waitFor("document.getElementById('umKeyNameHint').offsetParent !== null", 5000);
    await checkGap(helpers, `${prefix} 4. Friendly Name label is 6px under paste box`, '#umKeys', '#umKeyWrap label.field-label.step', 6);
    await checkGap(helpers, `${prefix} 4. Friendly Name hint is 4px under its field`, '#umKeyName', '#umKeyNameHint', 4);
    await checkGap(helpers, `${prefix} 4. key action row is 6px after the last key step`, '#umKeyNameHint', '#umKeyAdd', 6);
    await evaluate("openUser(users[0]);setAuth('key')");
    await waitFor("document.querySelector('#umKeyList .key-note.warn')", 5000);
    await checkStyle(helpers, `${prefix} 4. weak-key warning is amber and italic`, '#umKeyList .key-note.warn',
      { variable: 'var(--amber)', size: 11, italic: true });
    await screenshot(`spacing-manage-key-filled-${theme}`);

    // 5. Each error line takes space only when shown.
    await evaluate("openUser({...users[0],auth:'both',has_password:true});setAuth('both')");
    await checkErrorLine(helpers, 'umUserErr', '#umUser', '#userModal .row:nth-of-type(2) .field-label', 'Username is required.');
    await checkErrorLine(helpers, 'umKeyErr', '#umKeygen', '#userModal .row:nth-of-type(6) .field-label', 'Add a valid key.');
    await checkErrorLine(helpers, 'umPermErr', '#userModal .perm-grid', '#userModal .modal-actions', 'Choose at least one permission.');

    // 6. Key generator before and after a result. keygenSuccess writes only to the page.
    await evaluate("document.getElementById('umUser').value='spacing-user';openKeygen()");
    await waitFor("document.getElementById('keygenModal').classList.contains('show')", 5000);
    const aligned = await evaluate(`(() => { const a=document.getElementById('kgType').getBoundingClientRect();
      const b=document.getElementById('kgPath').getBoundingClientRect(); return { topA:a.top,topB:b.top,diff:Math.abs(a.top-b.top) }; })()`);
    check(`${prefix} 6. Type and Save-as fields are top-aligned`, aligned.diff <= TOLERANCE, JSON.stringify(aligned));
    await checkSections(helpers, `${prefix} 6. key-generator sections follow the rule`, 'keygenModal');
    await checkGap(helpers, `${prefix} 6. key-generator hint is 4px under field row`, '#kgPath', '#keygenModal .hint', 4);
    await evaluate(`keygenSuccess({public:${JSON.stringify(fixture.weak_paste)},private_path:${JSON.stringify("C:\\ui-drive\\spacing-key")}})`);
    await waitFor("document.getElementById('kgResult').offsetParent !== null", 2000);
    await checkGap(helpers, `${prefix} 6. Copy row is 6px below generated public key`, '#kgPub', '#kgCopy', 6);
    await screenshot(`spacing-keygen-result-${theme}`);
    await evaluate("closeModal('keygenModal')");

    // 7. Simple and folder confirm forms, with the folder warning hidden and shown.
    await evaluate("showSimpleConfirm('Confirm spacing','This is a simple confirmation.',()=>{})");
    await checkGap(helpers, `${prefix} 7. simple confirmation buttons are 16px under text`, '#cfText', '#cfSimpleRow', 16);
    await evaluate("closeModal('confirmModal');showConfirmStop('Stop spacing','Stop the temporary share?','C:\\\\a\\\\very\\\\long\\\\folder\\\\path\\\\for\\\\the\\\\spacing\\\\check',false,()=>{})");
    await checkGap(helpers, `${prefix} 7. folder buttons are 16px under folder line`, '#cfFolderLabel', '#cfKeep', 16);
    await evaluate("closeModal('confirmModal');showConfirmStop('Stop spacing','Stop the temporary share?','C:\\\\a\\\\very\\\\long\\\\folder\\\\path\\\\for\\\\the\\\\spacing\\\\check',true,()=>{})");
    await checkGap(helpers, `${prefix} 7. folder warning is 6px below folder line`, '#cfFolderLabel', '#cfFolderWarning', 6);
    await checkGap(helpers, `${prefix} 7. Keep/Delete row is 16px under warning`, '#cfFolderWarning', '#cfKeep', 16);
    await checkStyle(helpers, `${prefix} 7. folder warning is amber and italic`, '#cfFolderWarning',
      { variable: 'var(--amber)', size: 11, italic: true });
    await screenshot(`spacing-confirm-folder-${theme}`);
    await evaluate("closeModal('confirmModal')");

    // 8. Informational dialogs.
    await evaluate("showInfo('Spacing information','This paragraph stays until it is acknowledged.')");
    await checkGap(helpers, `${prefix} 8. info paragraph is 16px above buttons`, '#infoText', '#infoModal .modal-actions', 16);
    await evaluate("closeModal('infoModal');openUpdateErrorModal('The update check was intentionally not run.')");
    await checkGap(helpers, `${prefix} 8. update-error paragraph is 16px above buttons`, '#updateErrMsg', '#updateErrModal .modal-actions', 16);
    await evaluate("closeModal('updateErrModal')");

    // 9. Main-window Port field.
    await checkGap(helpers, `${prefix} 9. Port label is 6px above Port input`, '.conn .port .field-label', '#port', 6);

    // 11. A constrained dialog scrolls its actions fully into view.
    await evaluate(`(() => {
      const card=document.querySelector('#confirmModal .card'); window.__spacingMaxHeight=card.style.maxHeight;
      card.style.maxHeight='140px';
      showConfirmStop('Small window','A deliberately long folder path checks the scrollable dialog actions.',
        'C:\\\\long\\\\${'folder\\\\'.repeat(30)}end',true,()=>{});
      card.scrollTop=card.scrollHeight;
      const action=document.getElementById('cfDelete').getBoundingClientRect(), box=card.getBoundingClientRect();
      window.__spacingScroll={scrollTop:card.scrollTop,scrollHeight:card.scrollHeight,clientHeight:card.clientHeight,
        visible:action.top>=box.top && action.bottom<=box.bottom};
    })()`);
    const scroll = await evaluate('window.__spacingScroll');
    check(`${prefix} 11. small dialog scrolls buttons fully into view`,
      scroll.scrollHeight > scroll.clientHeight && scroll.scrollTop > 0 && scroll.visible, JSON.stringify(scroll));
    await evaluate("(() => { const c=document.querySelector('#confirmModal .card');c.style.maxHeight=window.__spacingMaxHeight;closeModal('confirmModal'); })()");
    await evaluate("closeModal('userModal')");
  }
}
