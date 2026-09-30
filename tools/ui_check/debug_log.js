// ui_drive scenario for Simple SFTP Server's debug-log warnings
// (see build-tools/ui_drive/README.md). tools/ui_check/fixture_debug_log.py
// plants five dated logs and locks the oldest, then locks the live log after
// the Debug log switch creates it.

async function warnToastShows(helpers, text, timeoutMs = 10000) {
  try {
    await helpers.waitFor(
      `(() => {
        const toast = document.getElementById('toast');
        return toast.className === 'warn show' && toast.textContent.includes(${JSON.stringify(text)});
      })()`,
      timeoutMs
    );
    return true;
  } catch {
    return false;
  }
}

async function toastText(helpers) {
  return helpers.evaluate("document.getElementById('toast').textContent");
}

export default async function debugLog(helpers) {
  const { click, evaluate, waitFor, check, screenshot } = helpers;

  await waitFor("typeof API !== 'undefined' && API && meta", 10000);

  // init drains launch-time warnings immediately, so start polling before the
  // toast's short display time expires.
  const launchWarning = await warnToastShows(helpers, "Debug_Log_01012026_010000.txt");
  const launchText = await toastText(helpers);
  check(
    "launch warning names the locked old log",
    launchWarning && launchText.includes("could not delete"),
    launchText
  );
  await screenshot("launch-warning", 300);

  // The checkbox itself has pointer events disabled. Its enclosing label is
  // the real clickable control for this switch.
  await click("label.toggle");
  const debugOn = await evaluate("document.getElementById('debugChk').checked");
  const debugOnToast = await waitFor(
    "document.getElementById('toast').className === 'show' && document.getElementById('toast').textContent.includes('Debug log on')",
    5000
  ).then(() => true, () => false);
  check("Debug switch turns on", debugOn && debugOnToast, await toastText(helpers));

  // Give the fixture time to find and lock the live log file.
  await new Promise(resolve => setTimeout(resolve, 3000));

  await click("label.toggle");
  await waitFor("!document.getElementById('debugChk').checked", 5000);
  await click("label.toggle");
  const writeWarning = await warnToastShows(helpers, "write failed");
  const writeText = await toastText(helpers);
  const debugOff = await evaluate("!document.getElementById('debugChk').checked");
  check(
    "locked live log disables Debug after a write failure",
    writeWarning && writeText.includes("Logging turned off") && debugOff,
    writeText
  );
  await screenshot("write-failure", 300);
}
