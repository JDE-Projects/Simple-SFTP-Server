// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Drives the real pywebview window
// from a fresh copy of the app: no host key and no Quick Start folder, and a
// config holding the one user tools/ui_check/fixture.py writes (a regular
// Start needs at least one user).
//
// Covers: the page-to-Python bridge answering with the real version; a bad
// port refused with a plain-language message; a theme round trip with a
// screenshot of each theme; a regular start and stop on an unusual port; and
// three Quick Start runs checking the stop dialog: the first (folder created
// by the app) shows no pre-existing warning, the second (folder kept from the
// first) shows it, and choosing Delete there removes the folder, which the
// third run confirms by reporting the folder as new again.
//
// While a server runs it listens on every network connection this PC has.
// Does not cover: users, key generation, connecting a client, the Public IP
// button (it contacts outside services), native folder and save pickers, or
// clicking "Open folder" (it opens a File Explorer window).

const PORT = 48222;

async function toastShows(helpers, pattern, timeoutMs = 8000) {
  return helpers.waitFor(
    `document.getElementById('toast').classList.contains('show') && ${pattern}.test(document.getElementById('toast').textContent)`,
    timeoutMs
  );
}

async function waitStopped(helpers) {
  await helpers.waitFor("running === false && !document.getElementById('startBtn').disabled", 10000);
}

async function shown(helpers, id) {
  return helpers.evaluate(`document.getElementById('${id}').offsetParent !== null`);
}

async function quickStartAndOpenStopDialog(helpers, label) {
  const { click, waitFor, check } = helpers;
  await click("#quickBtn");
  const started = await waitFor("running === true && isQuick === true && cur && cur.quick", 15000);
  check(`${label}: Quick Start runs`, started);
  await click("#stopBtn");
  const open = await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000);
  check(`${label}: stop dialog opens`, open);
}

export default async function smoke(helpers) {
  const { click, type, evaluate, waitFor, check, screenshot } = helpers;

  // The page-to-Python link answers, with the real version.
  await waitFor("typeof API !== 'undefined' && API && meta", 10000);
  const verLabel = await evaluate("document.getElementById('verLabel').textContent");
  check("version label shows a version", /^v\d+\.\d+\.\d+$/.test(verLabel), verLabel);
  const m = await evaluate("API.get_meta()");
  check("bridge get_meta answers with the version shown on screen", "v" + m.version === verLabel,
    JSON.stringify(m));

  // Error path: a bad port is refused in plain language and nothing starts.
  await type("#port", "abc");
  await click("#startBtn");
  let ok = await toastShows(helpers, "/whole number/");
  check("bad port shows a plain-language error",
    ok, await evaluate("document.getElementById('toast').textContent"));
  check("bad port does not start the server", (await evaluate("running")) === false);
  await waitFor("!document.getElementById('toast').classList.contains('show')", 6000);

  // Theme round trip.
  await click("#theme-btn");
  check("theme switches to light", await evaluate("document.body.classList.contains('light')"));
  await screenshot("theme-light");
  await click("#theme-btn");
  check("theme switches back to dark", !(await evaluate("document.body.classList.contains('light')")));
  await screenshot("theme-dark");

  // Regular start and stop on an unusual port. Quick Start then reuses it.
  await type("#port", String(PORT));
  // The hidden toast keeps its last text and colour class, so clear it
  // before waiting for either a start or a fresh error.
  await evaluate("document.getElementById('toast').className='';document.getElementById('toast').textContent=''");
  await click("#startBtn");
  ok = await waitFor(`(running === true && isQuick === false && cur && cur.port === ${PORT}) ||
    document.getElementById('toast').className === 'err show'`, 15000);
  ok = await evaluate(`running === true && cur && cur.port === ${PORT}`);
  check("regular server starts on the chosen port", ok,
    await evaluate("document.getElementById('toast').textContent"));
  if (!ok) return;
  check("regular server reports no pre-existing Quick Start folder",
    (await evaluate("cur.quick_folder_preexisting")) === false);
  await click("#stopBtn");
  await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000);
  check("regular stop dialog has no Open folder button", !(await shown(helpers, "cfOpenFolder")));
  check("regular stop dialog has no folder warning", !(await shown(helpers, "cfFolderWarning")));
  await click("#cfOk");
  await waitStopped(helpers);

  // Quick Start 1: the app creates the folder, so no warning. Keep it.
  await quickStartAndOpenStopDialog(helpers, "Quick Start 1");
  check("Quick Start 1: uses the saved port", (await evaluate("cur.port")) === PORT,
    String(await evaluate("cur.port")));
  check("Quick Start 1: Open folder button shown", await shown(helpers, "cfOpenFolder"));
  check("Quick Start 1: no pre-existing warning for an app-created folder",
    !(await shown(helpers, "cfFolderWarning")));
  check("Quick Start 1: Delete offered", await shown(helpers, "cfDelete"));
  await screenshot("stop-dialog-new-folder");
  await click("#cfKeep");
  await waitStopped(helpers);

  // Quick Start 2: the kept folder already exists, so the warning shows. Delete it.
  await quickStartAndOpenStopDialog(helpers, "Quick Start 2");
  check("Quick Start 2: status reports the folder as pre-existing",
    (await evaluate("cur.quick_folder_preexisting")) === true);
  check("Quick Start 2: pre-existing warning shown", await shown(helpers, "cfFolderWarning"));
  const warnText = await evaluate("document.getElementById('cfFolderWarning').textContent");
  check("Quick Start 2: warning wording",
    warnText === "This folder existed before this Quick Start started. Check its contents before deleting.",
    warnText);
  check("Quick Start 2: Delete still offered", await shown(helpers, "cfDelete"));
  check("Quick Start 2: button labels are the Quick Start ones",
    (await evaluate("document.getElementById('cfDelete').textContent")) === "Delete folder & files");
  await screenshot("stop-dialog-preexisting-folder");
  await click("#cfDelete");
  ok = await toastShows(helpers, "/share folder deleted/");
  check("Quick Start 2: Delete reports the folder deleted",
    ok, await evaluate("document.getElementById('toast').textContent"));
  await waitStopped(helpers);

  // Quick Start 3: the folder is new again, which proves Delete removed it.
  await quickStartAndOpenStopDialog(helpers, "Quick Start 3");
  check("Quick Start 3: folder is app-created again after Delete",
    (await evaluate("cur.quick_folder_preexisting")) === false);
  check("Quick Start 3: no pre-existing warning", !(await shown(helpers, "cfFolderWarning")));
  await click("#cfDelete");
  await waitStopped(helpers);
}
