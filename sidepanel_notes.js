/**
 * sidepanel_notes.js
 * Logic for the Encrypted Site Notes UI
 */

// 1. Save Note

async function saveNote(type = "notes") {
  const masterPwd = document.getElementById("m-pass").value;
  const noteText = document.getElementById("site-notes-input").value;
  const status = document.getElementById("synth-status");

  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  }

  try {
    const key = wiseHash(masterPwd, currentHost);
    const encryptedNote = keyEncrypt(noteText, key);

    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    hostData.crypt = hostData.crypt || {};

    // Store in the specified key (notes or once)
    hostData.crypt[type] = encryptedNote;

    await chrome.storage.sync.set({ [currentHost]: hostData });

    status.textContent =
      type === "once" ? "Read-once note saved." : "Notes saved.";
    status.style.color = "#22c55e";
    setTimeout(() => {
      status.textContent = "";
    }, 3000);
  } catch (e) {
    status.textContent = "Error: " + e.message;
  }
}

// 2. Clear Note Storage
async function clearNotes() {
  if (
    !confirm("Delete the saved note for this site? This cannot be undone.")
  ) {
    return;
  }

  try {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};

    if (hostData.crypt) {
      hostData.crypt.notes = null;
      await chrome.storage.sync.set({ [currentHost]: hostData });
    }

    document.getElementById("site-notes-input").value = "";
    const status = document.getElementById("synth-status");
    status.textContent = "Note deleted.";
    status.style.color = "#22c55e";

    setTimeout(() => {
      status.textContent = "";
    }, 2000);
  } catch (e) {
    alert("Error deleting note: " + e.message);
  }
}

function unlockNotes() {
  const masterPwd = document.getElementById("m-pass").value;
  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  }
  unlockAndDecryptNote();
}

// 3. Load/Decrypt Note
async function loadSiteNotes(masterPwd) {
  const input = document.getElementById("site-notes-input");
  const status = document.getElementById("synth-status");

  if (!currentHost) return;

  const data = await chrome.storage.sync.get([currentHost]);
  const encryptedNote = data[currentHost]?.crypt?.notes;

  if (!encryptedNote) {
    input.value = "";
    input.placeholder = "No notes saved for this site.";
    return;
  }

  if (!masterPwd) {
    input.value = "";
    input.placeholder = "[Locked - Enter Master Password]";
    return;
  }

  try {
    const key = wiseHash(masterPwd, currentHost);
    const decrypted = keyDecrypt(encryptedNote, key);
    input.value = decrypted;
    status.textContent = "Notes decrypted.";
    status.style.color = "#22c55e";
    setTimeout(() => {
      status.textContent = "";
    }, 2000);
  } catch (e) {
    input.value = "";
    input.placeholder = "[Decryption Failed]";
  }
}

async function enterNotesMode(host) {
  if (!host) return;

  // 1. Check storage for an encrypted note
  const data = await chrome.storage.sync.get([host]);
  const encNote = data[host]?.crypt?.notes;

  const editorArea = document.getElementById("notes-editor"); // The textarea + save btn
  const lockedArea = document.getElementById("notes-locked"); // The "Unlock" prompt

  if (encNote) {
    // Note exists: Show locked state
    editorArea.classList.add("hidden");
    lockedArea.classList.remove("hidden");

    // NEW: Auto-unlock if password is already there
    const masterPwd = document.getElementById("m-pass").value;
    if (masterPwd) {
      unlockAndDecryptNote(); // Decrypt immediately
    } else {
      cards.masterSection.classList.remove("hidden");
    }
  } else {
    // 3. No note: Show empty editor immediately
    editorArea.classList.remove("hidden");
    lockedArea.classList.add("hidden");
    document.getElementById("site-notes-input").value = "";
  }
}

async function unlockAndDecryptNote() {
  const masterPwd = document.getElementById("m-pass").value;
  const status = document.getElementById("synth-status");
  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  }

  try {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    const key = wiseHash(masterPwd, currentHost);

    let finalDisplay = "";
    let deletedOnce = false;

    // 1. Decrypt Regular Note if it exists
    if (hostData.crypt?.notes) {
      finalDisplay += keyDecrypt(hostData.crypt.notes, key);
    }

    // 2. Decrypt Read-Once Note if it exists
    if (hostData.crypt?.once) {
      const onceText = keyDecrypt(hostData.crypt.once, key);
      finalDisplay +=
        (finalDisplay ? "\n\n--- READ-ONCE NOTE ---\n\n" : "") + onceText;

      // Mark for deletion
      hostData.crypt.once = null;
      deletedOnce = true;
    }

    if (!finalDisplay && !deletedOnce) {
      enterNotesMode(currentHost);
      return;
    }

    // 3. Update UI and Storage
    document.getElementById("site-notes-input").value = finalDisplay;
    document.getElementById("notes-locked").classList.add("hidden");
    document.getElementById("notes-editor").classList.remove("hidden");

    if (deletedOnce) {
      await chrome.storage.sync.set({ [currentHost]: hostData });
      alert(
        "Read-once note was displayed and has been permanently deleted from storage.",
      );
      status.textContent = "Read-once note deleted.";
    } else {
      status.textContent = "Notes decrypted.";
    }

    status.style.color = "#22c55e";
    setTimeout(() => {
      status.textContent = "";
    }, 2000);
  } catch (e) {
    console.error("Decryption failed:", e);
    alert("Decryption failed. Check your Master Password.");
  }
}