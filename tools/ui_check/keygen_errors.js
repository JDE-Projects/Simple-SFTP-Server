// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks how the key generator
// shows its errors, using the one user tools/ui_check/fixture.py writes.
//
// Covers: when a key pair can't be put back after a failed replace (the
// result carries restore_failed), the message opens a dialog instead of the
// short-lived message bar, outlasts the message bar's 3.4 second timer, has
// its text selectable so the path can be copied, focuses OK, and closes on OK
// leaving the key generator open. Both routes are checked: a first try, and
// Replace after the "key already exists" question. Any other key generation
// error still uses the message bar.
//
// The page's generate_keypair call is swapped for one returning a canned
// result, so no key files are written. The Python side setting
// restore_failed is covered by tests/test_key_generation.py.
// Does not cover: a real file failure, or the native save picker.

const PATH = "C:\\Users\\someone\\.ssh\\id_ed25519";
const BACKUP = PATH + ".tmp-1234-0123456789abcdef0123456789abcdef";
const RESTORE_ERROR =
  `Key generation failed, and the old private key couldn't be put back. It is saved as ${BACKUP}. ` +
  "Rename it to id_ed25519 to restore it. Until then, the key files at that path may be missing or not match.";

const pause = (helpers, ms) => helpers.evaluate(`new Promise(r => setTimeout(r, ${ms}))`);

// Replaces the page's generate_keypair with one that returns the given
// results in order, one per call.
async function stubKeygen(helpers, results) {
  await helpers.evaluate(`(() => {
    window.__kgResults = ${JSON.stringify(results)};
    API.generate_keypair = async () => window.__kgResults.shift();
  })()`);
}

async function openKeygenWithPath(helpers) {
  const { click, evaluate, waitFor } = helpers;
  await click("#umKeygen");
  await waitFor("document.getElementById('keygenModal').classList.contains('show')", 5000);
  await evaluate(`document.getElementById('kgPath').value = ${JSON.stringify(PATH)}`);
}

async function checkInfoDialog(helpers, label, title) {
  const { evaluate, waitFor, check } = helpers;
  const open = await waitFor("document.getElementById('infoModal').classList.contains('show')", 5000);
  check(`${label}: restore failure opens a dialog`, open);
  const d = await evaluate(`(() => {
    const t = document.getElementById('infoText');
    return { title: document.getElementById('infoTitle').textContent, text: t.textContent,
             select: getComputedStyle(t).userSelect,
             focusOk: document.activeElement === document.getElementById('infoOk'),
             toast: document.getElementById('toast').classList.contains('show') };
  })()`);
  check(`${label}: dialog title is "${title}"`, d.title === title, d.title);
  check(`${label}: dialog shows the full message with the backup path`,
    d.text === RESTORE_ERROR && d.text.includes(BACKUP), d.text);
  check(`${label}: dialog text can be selected`, d.select === "text", d.select);
  check(`${label}: OK has focus`, d.focusOk);
  check(`${label}: message bar not used`, !d.toast);
  await pause(helpers, 4500);
  check(`${label}: dialog still open after 4.5 seconds`,
    await evaluate("document.getElementById('infoModal').classList.contains('show')"));
}

async function closeInfoDialog(helpers, label) {
  const { click, evaluate, check } = helpers;
  await click("#infoOk");
  const s = await evaluate(`({
    info: document.getElementById('infoModal').classList.contains('show'),
    kg: document.getElementById('keygenModal').classList.contains('show') })`);
  check(`${label}: OK closes the dialog and leaves the key generator open`,
    !s.info && s.kg, JSON.stringify(s));
}

export default async function keygenErrors(helpers) {
  const { click, evaluate, waitFor, check, screenshot } = helpers;
  await waitFor("typeof API !== 'undefined' && API && meta && users.length === 1", 10000);

  await click("#addUser");
  await waitFor("document.getElementById('userModal').classList.contains('show')", 5000);
  await evaluate("document.getElementById('umUser').value = 'keyuser'");
  await click('#umAuth button[data-v="key"]');
  await openKeygenWithPath(helpers);

  // First try fails and the cleanup fails too.
  await stubKeygen(helpers, [{ ok: false, restore_failed: true, error: RESTORE_ERROR }]);
  await click("#kgGo");
  await checkInfoDialog(helpers, "first try", "Key not created");
  await screenshot("restore-dialog-dark", 0);
  await evaluate("document.getElementById('theme-btn').click()");
  check("restore dialog switches to light", await evaluate("document.body.classList.contains('light')"));
  await screenshot("restore-dialog-light", 0);
  await evaluate("document.getElementById('theme-btn').click()");
  await closeInfoDialog(helpers, "first try");

  // Replace route: "key already exists", Confirm, then the restore failure.
  await stubKeygen(helpers, [
    { ok: false, exists: true, error: "A key already exists at that path." },
    { ok: false, restore_failed: true, error: RESTORE_ERROR },
  ]);
  await click("#kgGo");
  check("replace: the replace question opens",
    await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000));
  await click("#cfOk");
  await checkInfoDialog(helpers, "replace", "Key not replaced");
  await closeInfoDialog(helpers, "replace");

  // Any other error keeps the message bar.
  await stubKeygen(helpers, [{ ok: false, error: "Couldn't write there (permission denied)." }]);
  await click("#kgGo");
  let toastUp = false;
  try {
    toastUp = await waitFor(
      "document.getElementById('toast').classList.contains('show') && /permission denied/.test(document.getElementById('toast').textContent)",
      5000);
  } catch { toastUp = false; }
  check("other error: shown in the message bar", toastUp,
    await evaluate("document.getElementById('toast').textContent"));
  check("other error: no dialog",
    !(await evaluate("document.getElementById('infoModal').classList.contains('show')")));
}
