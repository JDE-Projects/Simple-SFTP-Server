// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks how the Manage window
// shows RSA keys under 2048 bits, using the user tools/ui_check/fixture_weak_key.py
// writes: a saved 1024-bit RSA key and an Ed25519 key.
//
// Covers: the saved weak key keeps its row, shows as off with its switch
// locked, and gets a "Too weak" note naming its size; the strong key gets no
// note and stays switchable; Save is not blocked by the weak key; pasting
// another weak key is refused with a plain-language message and is not added;
// with only the weak key left, Save asks for a valid key. Screenshots in both
// themes.
// Does not cover: sign-in refusal (tests/test_sftp_boundary.py), or the native
// file picker.

export default async function weakKey(helpers) {
  const { click, evaluate, waitFor, check, screenshot, fixture } = helpers;
  await waitFor("typeof API !== 'undefined' && API && meta && users.length === 1", 10000);

  await evaluate("openUser(users[0])");
  check("Manage window opens",
    await waitFor("document.getElementById('userModal').classList.contains('show')", 5000));
  await waitFor("document.querySelectorAll('#umKeyList .key-row').length === 2", 5000);

  const rows = await evaluate(`[...document.getElementById('umKeyList').children].map(w => ({
    name: (w.querySelector('.key-name') || {}).textContent || '',
    notes: [...w.querySelectorAll('.key-note')].map(n => n.textContent),
    state: (w.querySelector('.key-state') || {}).textContent || '',
    checked: (w.querySelector('.key-toggle input') || {}).checked,
    locked: (w.querySelector('.key-toggle input') || {}).disabled }))`);
  const weak = rows.find(r => r.name === "old-laptop");
  const strong = rows.find(r => r.name === "new-laptop");
  check("both saved keys are listed", !!weak && !!strong, JSON.stringify(rows));
  check("weak key shows the too-weak note with its size",
    !!weak && weak.notes.length === 1 &&
    weak.notes[0] === "Too weak (1024-bit RSA): this key can't be turned on. Replace it with a stronger one.",
    JSON.stringify(weak));
  const style = await evaluate(`(() => {
    const n = document.querySelector('#umKeyList .key-note');
    const probe = document.createElement('span'); probe.style.color = 'var(--amber)'; document.body.append(probe);
    const amber = getComputedStyle(probe).color; probe.remove();
    const cs = getComputedStyle(n);
    return { color: cs.color, amber, italic: cs.fontStyle };
  })()`);
  check("weak key note is styled as a warning (amber, italic)",
    style.color === style.amber && style.italic === "italic", JSON.stringify(style));
  check("strong key shows no note",!!strong && strong.notes.length === 0, JSON.stringify(strong));
  check("weak key is off, its switch locked; strong key on and switchable",
    !!weak && weak.state === "Off" && weak.checked === false && weak.locked === true &&
    !!strong && strong.state === "On" && strong.checked === true && strong.locked === false,
    JSON.stringify(rows));
  check("key count shows the weak key as off",
    /2 keys, 1 off/.test(await evaluate("document.getElementById('umKeyCount').textContent")));
  check("Save is not blocked by the weak key",
    !(await evaluate("document.getElementById('umSave').disabled")) && !(await evaluate("keyHasProblem()")));
  await screenshot("weak-key-dark", 0);
  await evaluate("document.getElementById('theme-btn').click()");
  check("Manage window switches to light", await evaluate("document.body.classList.contains('light')"));
  await screenshot("weak-key-light", 0);
  await evaluate("document.getElementById('theme-btn').click()");

  await evaluate(`document.getElementById('umKeys').value = ${JSON.stringify(fixture.weak_paste)}`);
  await click("#umKeyAdd");
  let refused = false;
  try {
    refused = await waitFor("/too weak/.test(document.getElementById('umKeyErr').textContent)", 5000);
  } catch { refused = false; }
  const err = await evaluate("document.getElementById('umKeyErr').textContent");
  check("pasting a weak key is refused with a plain-language message",
    refused && err === "This is a 1024-bit RSA key, which is too weak. Use an RSA key of 2048 bits or more, or an Ed25519 key.",
    err);
  check("the refused key is not added",
    (await evaluate("document.querySelectorAll('#umKeyList .key-row').length")) === 2);
  await screenshot("weak-key-paste-refused", 0);

  // With the strong key removed, only the locked weak key is left.
  await evaluate(`(() => {
    const wraps = [...document.getElementById('umKeyList').children];
    const w = wraps.find(x => (x.querySelector('.key-name') || {}).textContent === 'new-laptop');
    w.querySelector('.key-remove').click();
  })()`);
  await evaluate("document.getElementById('umKeys').value = ''; document.getElementById('umKeyErr').textContent = ''");
  const measure = `(() => {
    const card = document.getElementById('umTitle').closest('.card');
    const r = el => el.getBoundingClientRect();
    const cardTop = r(card).top, titleTop = r(document.getElementById('umTitle')).top;
    const wrap = document.getElementById('umKeyList').children[0];
    const row = wrap.querySelector('.key-row'), note = wrap.querySelector('.key-note');
    const label = document.querySelector('#umKeyWrap .field-label');
    const ta = document.getElementById('umKeys');
    const fn = ta.nextElementSibling;
    return { scrollTop: card.scrollTop, titleGap: Math.round(titleTop - cardTop),
      labelToBox: Math.round(r(wrap).top - r(label).bottom),
      noteInBox: r(note).bottom <= r(wrap).bottom - 1 && r(note).left >= r(wrap).left,
      rowToNote: Math.round(r(note).top - r(row).bottom),
      boxToPaste: Math.round(r(ta).top - r(wrap).bottom),
      pasteToName: Math.round(r(fn).top - r(ta).bottom),
      noteTextVsKeyText: (() => { const range = document.createRange(); range.selectNodeContents(note);
        return Math.round(range.getBoundingClientRect().left - r(row.querySelector('.key-type')).left); })() };
  })()`;
  await evaluate("document.getElementById('umTitle').closest('.card').scrollTop = 0");
  const m = await evaluate(measure);
  const detail = JSON.stringify(m);
  check("window scrolled to the top shows the title's normal gap", m.scrollTop === 0 && m.titleGap >= 18, detail);
  check("note sits inside its key's box, 4px below the key line", m.noteInBox && m.rowToNote === 4, detail);
  check("note text lines up with the text inside the key box", Math.abs(m.noteTextVsKeyText) <= 1, detail);
  check("6px spacing: label to key box, key box to paste box, paste box to next label",
    m.labelToBox === 6 && m.boxToPaste === 6 && m.pasteToName === 6, detail);
  await screenshot("weak-key-only", 0);
  await click("#umSave");
  let asked = false;
  try {
    asked = await waitFor("/valid public key/.test(document.getElementById('umKeyErr').textContent)", 5000);
  } catch { asked = false; }
  const saveErr = await evaluate("document.getElementById('umKeyErr').textContent");
  check("only a weak key left: Save asks for a valid key",
    asked && saveErr === "Add at least one valid public key (or switch to password auth).", saveErr);
  check("only a weak key left: window stays open",
    await evaluate("document.getElementById('userModal').classList.contains('show')"));
}
