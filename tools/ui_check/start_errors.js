// ui_drive scenario for Simple SFTP Server's Start and Stop error handling
// (see build-tools/ui_drive/README.md). tools/ui_check/fixture_start_errors.py
// plants an RSA 2048 host key as host_ed25519 and keeps the config file open,
// so every config save fails.
//
// Covers: the RSA host key loads and its fingerprint is shown; Start still
// runs when the port cannot be saved and shows that warning; a refused start
// shows its error and gives the buttons back; and when a bridge call itself
// fails (simulated here by swapping one method for a failing one in the page,
// since the app has no safe way to make its backend throw), Start, Quick
// Start, and both kinds of Stop show an error and give the buttons back.

const PORT = 48223;
const BUTTONS = ["startBtn", "stopBtn", "quickBtn", "checkBtn"];

async function clearToast(helpers) {
  await helpers.evaluate("document.getElementById('toast').className='';document.getElementById('toast').textContent=''");
}

async function toastText(helpers) {
  return helpers.evaluate("document.getElementById('toast').textContent");
}

async function toastShows(helpers, cls, pattern, timeoutMs = 10000) {
  try {
    return await helpers.waitFor(
      `document.getElementById('toast').className === '${cls}' && ${pattern}.test(document.getElementById('toast').textContent)`,
      timeoutMs
    );
  } catch {
    return false;
  }
}

// Start/Quick/Check are usable when stopped; Stop is usable when running.
async function buttonsBack(helpers) {
  return helpers.evaluate(`(() => {
    const d = id => document.getElementById(id).disabled;
    return running
      ? !d('stopBtn') && d('startBtn') === true
      : !d('startBtn') && !d('quickBtn') && !d('checkBtn');
  })()`);
}

async function failNext(helpers, method) {
  await helpers.evaluate(`(() => {
    window.__realAPI = window.__realAPI || API;
    const real = window.__realAPI;
    API = new Proxy(real, { get: (t, k) => k === '${method}'
      ? () => Promise.reject(new Error('simulated bridge failure'))
      : t[k] });
  })()`);
}

async function restoreApi(helpers) {
  await helpers.evaluate("if (window.__realAPI) API = window.__realAPI");
}

async function confirmStop(helpers) {
  await helpers.click("#stopBtn");
  await helpers.waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000);
  // Quick Start's dialog: Keep; regular dialog: OK.
  const quick = await helpers.evaluate("document.getElementById('cfKeep').offsetParent !== null");
  await helpers.click(quick ? "#cfKeep" : "#cfOk");
}

export default async function startErrors(helpers) {
  const { type, click, evaluate, waitFor, check, screenshot, fixture } = helpers;

  await waitFor("typeof API !== 'undefined' && API && meta", 10000);

  // A refused start (bad port) shows its error and gives the buttons back.
  await type("#port", "abc");
  await clearToast(helpers);
  await click("#startBtn");
  check("refused start shows an error", await toastShows(helpers, "err show", "/whole number/"),
    await toastText(helpers));
  check("refused start gives the buttons back", await buttonsBack(helpers));

  // Start with the config locked: runs, warns the port was not saved,
  // and shows the planted RSA key's fingerprint.
  await type("#port", String(PORT));
  await clearToast(helpers);
  await click("#startBtn");
  const warned = await toastShows(helpers, "warn show", /could not be saved/.toString());
  check("start with an unsaveable port shows the warning", warned, await toastText(helpers));
  await screenshot("port-not-saved-warning", 300);
  check("server is running after the warning",
    await evaluate(`running === true && cur && cur.port === ${PORT}`));
  const fp = await evaluate("document.getElementById('vFp').textContent");
  check("RSA host key loads and its fingerprint is shown", fp === fixture.fingerprint,
    `shown ${fp}, expected ${fixture.fingerprint}`);
  check("buttons correct while running", await buttonsBack(helpers));

  // Regular Stop when the bridge call fails.
  await failNext(helpers, "stop_server");
  await clearToast(helpers);
  await confirmStop(helpers);
  check("failed regular Stop shows an error",
    await toastShows(helpers, "err show", "/Could not stop the server/"), await toastText(helpers));
  check("failed regular Stop gives the buttons back", await buttonsBack(helpers));
  await restoreApi(helpers);
  await confirmStop(helpers);
  await waitFor("running === false && !document.getElementById('startBtn').disabled", 10000);

  // Start when the bridge call fails.
  await failNext(helpers, "start_server");
  await clearToast(helpers);
  await click("#startBtn");
  check("failed Start shows an error",
    await toastShows(helpers, "err show", "/Could not start the server/"), await toastText(helpers));
  await screenshot("start-bridge-failure", 300);
  check("failed Start gives the buttons back", await buttonsBack(helpers));
  await restoreApi(helpers);

  // Quick Start when the bridge call fails.
  await failNext(helpers, "quick_start");
  await clearToast(helpers);
  await click("#quickBtn");
  check("failed Quick Start shows an error",
    await toastShows(helpers, "err show", "/Could not start Quick Start/"), await toastText(helpers));
  check("failed Quick Start gives the buttons back", await buttonsBack(helpers));
  await restoreApi(helpers);

  // Quick Start Stop when the bridge call fails.
  await click("#quickBtn");
  await waitFor("running === true && isQuick === true", 15000);
  await failNext(helpers, "stop_server");
  await clearToast(helpers);
  await confirmStop(helpers);
  check("failed Quick Start Stop shows an error",
    await toastShows(helpers, "err show", "/Could not stop the server/"), await toastText(helpers));
  check("failed Quick Start Stop gives the buttons back", await buttonsBack(helpers));
  await restoreApi(helpers);
  await click("#stopBtn");
  await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000);
  await click("#cfDelete");
  await waitFor("running === false && !document.getElementById('startBtn').disabled", 10000);
  check("server stopped at the end", (await evaluate("running")) === false);
}
