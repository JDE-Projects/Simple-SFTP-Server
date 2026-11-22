// ui_drive scenario for Simple SFTP Server (see build-tools/ui_drive/README.md
// for the helpers and how this is launched). Checks deleting a user whose entry
// in the config file was edited by hand while the Manage window was open, using
// the user tools/ui_check/fixture_stale_save.py writes (list and download only).
//
// Covers: Delete is refused with the plain-language "changed outside the app"
// message in an error toast, the Manage window stays open, the config file and
// user folder are left intact, and the main list refreshes to the hand-edited
// permissions. Closing and reopening the user then permits deletion while
// keeping its folder. Screenshots of the refusal in both themes.
// Does not cover: the backend revision check itself (tests/test_delete_stale_user.py),
// or deletion that removes the user's folder.

export default async function staleDelete(helpers) {
  const { click, evaluate, waitFor, check, screenshot, fixture } = helpers;
  const fs = await import("node:fs");
  const STALE = "This user was changed outside the app since you opened this window. Close it and open the user again.";
  const modalOpen = "document.getElementById('userModal').classList.contains('show')";
  await waitFor("typeof API !== 'undefined' && API && meta && users.length === 1", 10000);

  // a. Open the Manage window for the user.
  await evaluate("openUser(users[0])");
  check("Manage window opens", await waitFor(modalOpen, 5000));

  // b. Hand-edit the config file while the window is open.
  const cfg = JSON.parse(fs.readFileSync(fixture.config_path, "utf-8"));
  const target = cfg.users.find(u => u.username === fixture.user);
  target.permissions.upload = true;
  fs.writeFileSync(fixture.config_path, JSON.stringify(cfg, null, 2), "utf-8");
  const afterEdit = fs.readFileSync(fixture.config_path);
  check("hand edit turned Upload on in the file",
    JSON.parse(afterEdit.toString("utf-8")).users[0].permissions.upload === true);

  // c. Try to delete from the stale window, including the folder.
  await click("#umDelete");
  check("delete confirmation opens",
    await waitFor("document.getElementById('confirmModal').classList.contains('show')", 5000));
  await click("#cfDelete");

  // d. The stale deletion leaves the user and folder intact.
  let toasted = false;
  try {
    toasted = await waitFor("document.getElementById('toast').classList.contains('err') && document.getElementById('toast').classList.contains('show')", 5000);
  } catch { toasted = false; }
  const toastText = await evaluate("document.getElementById('toast').textContent");
  check("stale delete shows an error toast with the exact message", toasted && toastText === STALE, toastText);
  check("Manage window stays open after the refusal", await evaluate(modalOpen));
  check("config file is unchanged by the refused delete",
    fs.readFileSync(fixture.config_path).equals(afterEdit));
  check("user folder remains after the refused delete", fs.existsSync(fixture.home));
  check("main list refreshed to the hand-edited permissions",
    (await evaluate("users[0].permissions.upload")) === true);

  // e. Screenshots in both themes.
  await screenshot("stale-delete-dark");
  await evaluate("document.getElementById('theme-btn').click()");
  check("refusal screen switches to light", await evaluate("document.body.classList.contains('light')"));
  await screenshot("stale-delete-light");
  await evaluate("document.getElementById('theme-btn').click()");

  // f. Reopen the user to receive its fresh revision.
  await evaluate("closeModal('userModal')");
  check("Manage window closes", await waitFor("!" + modalOpen, 5000));
  await evaluate("openUser(users[0])");
  check("Manage window reopens", await waitFor(modalOpen, 5000));

  // g. Delete the refreshed user while keeping its folder.
  await click("#umDelete");
  await click("#cfKeep");
  let deleted = false;
  try {
    deleted = await waitFor("document.getElementById('toast').textContent === 'User deleted.'", 5000);
  } catch { deleted = false; }
  check("delete shows \"User deleted.\"", deleted,
    await evaluate("document.getElementById('toast').textContent"));
  check("Manage window closes after the delete", await waitFor("!" + modalOpen, 5000));
  const finalConfig = JSON.parse(fs.readFileSync(fixture.config_path, "utf-8"));
  check("config file no longer has the deleted user",
    !finalConfig.users.some(u => u.username === fixture.user));
  check("user folder remains after keeping it", fs.existsSync(fixture.home));
}
