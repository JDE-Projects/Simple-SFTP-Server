// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks saving a user whose entry
// in the config file was edited by hand while the Manage window was open, using
// the user tools/ui_check/fixture_stale_save.py writes (list and download only).
//
// Covers: Save is refused with the plain-language "changed outside the app"
// message in an error toast, the Manage window stays open, and the config file
// is left exactly as the hand edit made it; the main list refreshes to the
// hand-edited permissions; closing and reopening the user shows the fresh
// permissions, and saving again then works and reaches the file. Screenshots of
// the refusal in both themes. This change does not produce the "Save anyway"
// confirmation (no one is connected and no keys are lost), so the script clicks
// it only if it appears.
// Does not cover: the backend revision check itself (tests/test_save_stale_user.py),
// or a hand edit that deletes or renames the user.

export default async function staleSave(helpers) {
  const { click, evaluate, waitFor, check, screenshot, fixture } = helpers;
  const fs = await import("node:fs");
  const STALE = "This user was changed outside the app since you opened this window. Close it and open the user again.";
  const modalOpen = "document.getElementById('userModal').classList.contains('show')";
  await waitFor("typeof API !== 'undefined' && API && meta && users.length === 1", 10000);

  // a. Open the Manage window for the user.
  await evaluate("openUser(users[0])");
  check("Manage window opens",
    await waitFor(modalOpen, 5000));
  check("form starts with Upload off and Download on",
    (await evaluate("!document.getElementById('pUpload').checked && document.getElementById('pDownload').checked")));

  // b. Hand-edit the config file while the window is open.
  const cfg = JSON.parse(fs.readFileSync(fixture.config_path, "utf-8"));
  const target = cfg.users.find(u => u.username === fixture.user);
  target.permissions.upload = true;
  fs.writeFileSync(fixture.config_path, JSON.stringify(cfg, null, 2), "utf-8");
  const afterEdit = fs.readFileSync(fixture.config_path);
  check("hand edit turned Upload on in the file",
    JSON.parse(afterEdit.toString("utf-8")).users[0].permissions.upload === true);

  // c. Try to save from the stale window.
  await click("#umSave");
  const confirmShown = await evaluate("document.getElementById('confirmModal').classList.contains('show')");
  if (confirmShown) await click("#cfOk");
  console.log("confirm dialog appeared on the stale save: " + confirmShown);
  let toasted = false;
  try {
    toasted = await waitFor("document.getElementById('toast').classList.contains('err') && document.getElementById('toast').classList.contains('show')", 5000);
  } catch { toasted = false; }
  const toastText = await evaluate("document.getElementById('toast').textContent");
  check("stale save shows an error toast with the exact message", toasted && toastText === STALE, toastText);
  check("Manage window stays open after the refusal", await evaluate(modalOpen));
  check("config file is unchanged by the refused save",
    fs.readFileSync(fixture.config_path).equals(afterEdit));

  // d. The main list picked up the hand edit.
  check("main list refreshed to the hand-edited permissions",
    (await evaluate("users[0].permissions.upload")) === true);

  // e. Screenshots in both themes.
  await screenshot("stale-save-dark");
  await evaluate("document.getElementById('theme-btn').click()");
  check("refusal screen switches to light", await evaluate("document.body.classList.contains('light')"));
  await screenshot("stale-save-light");
  await evaluate("document.getElementById('theme-btn').click()");

  // f. Close, reopen from the fresh list, and see the new permission.
  await evaluate("closeModal('userModal')");
  check("Manage window closes", await waitFor("!" + modalOpen, 5000));
  await evaluate("openUser(users[0])");
  check("Manage window reopens", await waitFor(modalOpen, 5000));
  check("reopened form shows Upload ticked",
    await evaluate("document.getElementById('pUpload').checked === true"));

  // g. Save again, unticking Download so the save changes something visible.
  await click("#pDownload");
  await click("#umSave");
  if (await evaluate("document.getElementById('confirmModal').classList.contains('show')")) await click("#cfOk");
  let saved = false;
  try {
    saved = await waitFor("document.getElementById('toast').textContent === 'User saved.'", 5000);
  } catch { saved = false; }
  check("second save shows \"User saved.\"", saved, await evaluate("document.getElementById('toast').textContent"));
  check("Manage window closes after the save", await waitFor("!" + modalOpen, 5000));
  const finalPerms = JSON.parse(fs.readFileSync(fixture.config_path, "utf-8")).users[0].permissions;
  check("config file reflects the save (Upload on, Download off)",
    finalPerms.upload === true && finalPerms.download === false && finalPerms.list === true,
    JSON.stringify(finalPerms));
}
