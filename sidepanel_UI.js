// Global variables to track state and prevent unnecessary UI updates

let lastState = {}; // Global variable to track the current state
let isChangingPassword = false;

//functions for side panel UI interactions

function showCard(card) {
  if (card) card.classList.remove("hidden");
}

function hideCard(card) {
  if (card) card.classList.add("hidden");
}

const cards = {
  synth: document.getElementById("card-synth"),
  synthExtra: document.getElementById("synth-extra-inputs"),
  crypto: document.getElementById("card-crypto"), // Unified card
  note: document.getElementById("card-note"),
  masterSection: document.getElementById("master-password-section"),
};

function setCryptoMode(mode) {
  const card = cards.crypto;
  if (card) {
    card.dataset.mode = mode;
    showCard(card);
  }

  // Toggle email visibility in the MP section
  const emailDisplay = document.getElementById('decrypt-email-display');
  const mpSection = document.getElementById('master-password-section');

  if (emailDisplay) {
    if (mode === 'encrypt' || mode === 'decrypt') {
      emailDisplay.classList.remove('hidden');
      if (mpSection) mpSection.classList.remove('hidden');
    } else {
      emailDisplay.classList.add('hidden');
    }
  }
}

// Pull state immediately on load
// Improved getRegisteredDomain function
function getRegisteredDomain(hostname) {
  if (!hostname) return hostname;
  // normalize, drop port and trailing dot
  hostname = hostname.toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  // IP or single-label host (localhost)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.indexOf(".") === -1)
    return hostname;
  // strip common www variants
  hostname = hostname.replace(/^www\d*\./, "");
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const tld = parts[parts.length - 1];
  // if TLD is 2 chars (likely ccTLD), use last 3 parts where possible
  if (tld.length === 2 && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  // default: last 2 parts
  return parts.slice(-2).join(".");
}

// function to safely initialize the encrypt card once
function setupCryptoCardListeners() {
  const lockList = document.getElementById('lockList');
  if (lockList) {
    // Remove first to avoid double-binding if updateUI runs multiple times
    lockList.removeEventListener('change', updateRecipientStatus);
    lockList.addEventListener('change', updateRecipientStatus);
  }

  const toolBar = document.getElementById('toolBar');
  if (toolBar) {
    toolBar.addEventListener('click', (e) => {
      const cmdBtn = e.target.closest('.intLink');
      if (cmdBtn) {
        const cmd = cmdBtn.getAttribute('data-command');
        const box = document.getElementById('composeBox');
        if (box) {
          box.focus();
          document.execCommand(cmd, false, null);
          setTimeout(updateToolbarState, 10);
        }
      }
    });
  }
}

// 2. Robust State Checker
function updateToolbarState() {
  const buttons = document.querySelectorAll('#toolBar .intLink');
  buttons.forEach(btn => {
    const cmd = btn.getAttribute('data-command');
    if (cmd) {
      try {
        if (document.queryCommandState(cmd)) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      } catch (e) {
        // Some commands might not support queryCommandState in all contexts
      }
    }
  });
}

// 3. Track state via multiple events inside the box
const box = document.getElementById('composeBox');
if (box) {
  ['keyup', 'mouseup', 'focus'].forEach(evt => {
    box.addEventListener(evt, updateToolbarState);
  });
}

// Also keep the global selection listener as a backup
document.addEventListener('selectionchange', () => {
  if (document.activeElement.id === 'composeBox') {
    updateToolbarState();
  }
});

let masterPwdTimeout = null;

/*
function updateUI(state) {
  // 1. Handle the Change Password button visibility
  const changeBtn = document.getElementById('change-synth');
  if (changeBtn) {
    // Show if 2+ password fields are detected
    if (state.hasPasswords && state.passwordCount >= 2) {
      changeBtn.style.display = 'inline-block';
    } else {
      changeBtn.style.display = 'none';
    }
  }

  // If the core state is identical to the last one, ignore the message
  if (lastState &&
    lastState.hasLargeInputField === state.hasLargeInputField &&
    lastState.hasPasswords === state.hasPasswords &&
    lastState.hasCrypto === state.hasCrypto &&
    lastState.host === state.host) {
    return;
  }

  lastState = { ...state };

  // 1. Normalize Host and Load Data
  if (state.host) {
    currentHost = getRegisteredDomain(state.host);
    loadHostData(currentHost);
  }

  // 2. Hide all cards first
  Object.values(cards).forEach((c) => {
    if (c) c.classList.add("hidden");
  });

  let active = false;

  // 3. Priority 1: Password Synthesis (Synth Card)
  if (state.hasPasswords) {
    masterPasswordContext = "synth";
    showCard(cards.synth);
    showCard(cards.masterSection);
    showCard(cards.synthExtra);
    if (typeof DirectoryEditor !== "undefined") DirectoryEditor.setMode("synth");
    active = true;
  }
  // 4. Priority 2: Large Input Field Detected (Encrypt Mode)
  else if (state.hasLargeInputField) {
    masterPasswordContext = "encrypt";
    setCryptoMode("encrypt"); // Unified Card in Encrypt mode
    showCard(cards.masterSection);

    if (typeof DirectoryEditor !== "undefined") {
      DirectoryEditor.setMode("encrypt");
    }
    if (typeof renderDirectory === 'function') {
      renderDirectory();
    }
    active = true;
  }

  // 5. Priority 3: Encrypted Content (Decrypt Mode)
  else if (state.hasCrypto) {
    masterPasswordContext = "decrypt";
    setCryptoMode("decrypt"); // Unified Card in Decrypt mode

    if (state.needPasswordInput) {
      showCard(cards.masterSection);
      showCard(cards.decryptEmail);
    } else {
      hideCard(cards.masterSection);
      hideCard(cards.decryptEmail);
    }

    if (typeof DirectoryEditor !== "undefined") {
      DirectoryEditor.setMode("decrypt");
    }
    active = true;
  }

  // 6. Fallback: Notes (no passwords, no crypto, no large input)
  if (!active) {
    masterPasswordContext = "notes";
    showCard(cards.note);

    if (typeof DirectoryEditor !== "undefined") {
      DirectoryEditor.setMode("notes");
    }

    enterNotesMode(currentHost);
  }
}
*/

function updateUI(state) {
  if (state) lastState = state;
  const s = lastState;

  if (state.host) {
  currentHost = getRegisteredDomain(state.host);
  // Ensure the global window object is also updated if scripts are mixed
  window.currentHost = currentHost; 
  
  loadHostData(currentHost);
  
  // Trigger the list update now that we have a host
  if (typeof updateLockList === 'function') {
    updateLockList();
  }
}

  // 1. Map agent-core.js keys to our priority logic
  const hasPasswords = s.hasPasswords || (s.passwordCount > 0);
  const hasTextAreas = s.hasLargeInputField || false;
  const hasBlobs = s.hasCrypto || false;
  const hasNotes = window.notesAreEncrypted || false;

  // Elements
  const masterSection = document.getElementById('master-password-section');
  const emailDisplay = document.getElementById('decrypt-email-display');
  const synthExtra = document.getElementById('synth-extra-inputs');
  const cardSynth = document.getElementById('card-synth');
  const cardCrypto = document.getElementById('card-crypto');
  const cardNote = document.getElementById('card-note');
  const dropTarget = document.getElementById('dropTargetCard');
  const composeBox = document.getElementById('composeBox');
  const toolBar = document.getElementById('toolBar');
  const decoyContainer = document.getElementById('decoy-container');
  const actionButtons = document.getElementById('encryptBtn')?.parentElement;

  // 2. Reset: Hide everything first
  [masterSection, cardSynth, cardCrypto, cardNote, dropTarget, composeBox, toolBar, decoyContainer].forEach(el => el?.classList.add('hidden'));
  if (actionButtons) actionButtons.classList.remove('hidden');

  // Priority 1: Passwords
  if (hasPasswords) {
    masterSection.classList.remove('hidden');
    emailDisplay.classList.add('hidden');
    cardSynth.classList.remove('hidden');
    return;
  }

  // Priority 2: Text Areas (Compose)
  if (hasTextAreas) {
    masterSection.classList.remove('hidden');
    emailDisplay.classList.remove('hidden');
    synthExtra.classList.add('hidden');
    cardCrypto.classList.remove('hidden');
    cardCrypto.setAttribute('data-mode', 'encrypt');
    composeBox.classList.remove('hidden');
    toolBar.classList.remove('hidden');
    decoyContainer.classList.remove('hidden');
    dropTarget.classList.remove('hidden');
    return;
  }

  // Priority 3: Base64 Blobs (Encrypted Content)
  if (hasBlobs) {
    masterSection.classList.remove('hidden');
    emailDisplay.classList.remove('hidden');
    synthExtra.classList.add('hidden');
    cardCrypto.classList.remove('hidden');
    cardCrypto.setAttribute('data-mode', 'decrypt');
    composeBox.classList.remove('hidden');
    toolBar.classList.remove('hidden');
    decoyContainer.classList.add('hidden');
    dropTarget.classList.remove('hidden');
    return;
  }

  // Priority 4: Manual File Mode Override
  if (window.isManualFileMode) {
    masterSection.classList.remove('hidden');
    emailDisplay.classList.remove('hidden');
    synthExtra.classList.add('hidden');
    cardCrypto.classList.remove('hidden');
    cardCrypto.setAttribute('data-mode', 'encrypt');

    composeBox.classList.add('hidden');
    toolBar.classList.add('hidden');
    decoyContainer.classList.add('hidden');
    if (actionButtons) actionButtons.classList.add('hidden');

    dropTarget.classList.remove('hidden');
    if (window.updateLockList) window.updateLockList();
    return;
  }

  if (cardCrypto && !cardCrypto.classList.contains('hidden')) {
  if (window.updateLockList) {
    setTimeout(() => window.updateLockList(), 100); // Delay to ensure data is ready
  }
}

  if (masterSection) {
    masterSection.classList.remove('hidden');
    // Show all direct children or specific sub-elements
    masterSection.querySelectorAll('*').forEach(el => {
      if (el.id !== 'decrypt-email-display') { // Don't show email display in password mode
        el.classList.remove('hidden');
      }
    });
  }

  // Priority 5: Default / Notes
  if (cardNote) {
    cardNote.classList.remove('hidden');

    const notesLocked = document.getElementById('notes-locked');
    const notesEditor = document.getElementById('notes-editor');

    if (hasNotes) {
      if (!hasMaster) {
        // Locked state
        notesLocked.classList.remove('hidden');
        notesEditor.classList.add('hidden');
        masterSection.classList.remove('hidden');
        emailDisplay.classList.add('hidden');
        synthExtra.classList.add('hidden');
      } else {
        // Unlocked state (editor)
        notesLocked.classList.add('hidden');
        notesEditor.classList.remove('hidden');
        masterSection.classList.add('hidden');
      }
    } else {
      // No encrypted notes: show editor to create new notes
      notesLocked.classList.add('hidden');
      notesEditor.classList.remove('hidden');
      masterSection.classList.add('hidden');
    }
  }
}

function resetDecryptButtonStyle() {
  const decryptBtn = document.getElementById("do-decrypt-selection");
  if (decryptBtn) {
    decryptBtn.style.background = "";
    decryptBtn.style.color = "";
  }
}

/**
 * Updates Synth-related UI elements.
 */
function updateSynthUI(synthData) {
  document.getElementById("serial").value = synthData.serial || "";
  document.getElementById("allowed-chars").value = synthData.allowedChars || "";
  document.getElementById("length-limit").value = synthData.lengthLimit || "";
}

/**
 * Updates Crypt-related UI elements.
 */
function updateCryptUI(cryptData) {
  const emailField = document.getElementById("user-email");
  if (emailField) {
    emailField.value = cryptData.email || "";
  }
}

// ===== SERIAL etc STORAGE =====
/**
 * Loads all host-specific data (synth & crypt) and updates the UI.
 */
function loadHostData(host) {
  if (!host) return;

  chrome.storage.sync.get([host], (result) => {
    const hostData = result[host] || {};
    const synth = hostData.synth || {};
    const crypt = hostData.crypt || {};

    // Update Synth UI
    updateSynthUI(synth);

    // Update Decrypt UI
    updateCryptUI(crypt);

    // Notify DirectoryEditor of host change
    if (
      typeof DirectoryEditor !== "undefined" &&
      typeof DirectoryEditor.setHost === "function"
    ) {
      DirectoryEditor.setHost(host);
    }
  });
}

/**
 * Updates Synth-related UI elements.
 */
/*
function updateSynthUI(synthData) {
  document.getElementById("serial").value = synthData.serial || "";
  document.getElementById("allowed-chars").value = synthData.allowedChars || "";
  document.getElementById("length-limit").value = synthData.lengthLimit || "";
}

/**
 * Updates Crypt-related UI elements.
 */
/*
function updateCryptUI(cryptData) {
  const emailField = document.getElementById("user-email");
  if (emailField) {
    emailField.value = cryptData.email || "";
  }
}*/

function updateRecipientStatus() {
  const lockList = document.getElementById('lockList');
  const statusBox = document.getElementById('composeRecipientsBox');

  if (!lockList || !statusBox) return;

  // Get the text of all selected options
  const selected = Array.from(lockList.selectedOptions).map(o => o.textContent);

  if (selected.length === 0) {
    statusBox.textContent = "Nobody! (Making an invitation)";
  } else {
    // Join names with commas for the display
    statusBox.textContent = selected.join(', ');
  }
}

function saveHostData(host) {
  if (!host) return;
  const serial = document.getElementById("serial").value;
  const allowedChars = document.getElementById("allowed-chars").value;
  const lengthLimit = document.getElementById("length-limit").value;

  chrome.storage.sync.get([host], (result) => {
    const hostData = result[host] || {};
    const updatedData = {
      ...hostData,
      synth: {
        serial: serial,
        allowedChars: allowedChars,
        lengthLimit: lengthLimit,
      },
    };

    chrome.storage.sync.set({ [host]: updatedData }, () => {
      if (chrome.runtime.lastError) {
        console.error("Save error:", chrome.runtime.lastError);
      }
    });
  });
}

let hashiliTimer = null;

/// ===== MASTER PASSWORD STRENGTH & HASHILI =====
document.getElementById("m-pass").addEventListener("input", (e) => {
  const pwd = e.target.value;
  const hashEl = document.getElementById("hashili");
  const fill = document.getElementById("strength-fill");

  if (hashiliTimer) clearTimeout(hashiliTimer);

  if (!pwd.trim()) {
    fill.style.width = "0%";
    hashEl.textContent = "";
    return;
  }

  // Update strength bar
  const entropy =
    typeof entropyCalc === "function" ? entropyCalc(pwd) : pwd.length * 4;
  const percentage = Math.min(100, (entropy / 80) * 100);
  fill.style.width = percentage + "%";
  fill.style.background =
    percentage < 30 ? "#ef4444" : percentage < 70 ? "#f59e0b" : "#22c55e";

  // Debounced Hashili
  hashiliTimer = setTimeout(() => {
    if (typeof makeHashili === "function") {
      hashEl.textContent = makeHashili(pwd);
    }
  }, 1000);
});

// Enter key handling
document.getElementById("m-pass").addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    if (masterPasswordContext === "synth") {
      document.getElementById("do-synth").click();
    } else if (masterPasswordContext === "decrypt") {
      document.getElementById("do-decrypt-selection").click();
    } else if (masterPasswordContext === "notes") {
      unlockAndDecryptNote();
    }
  }
});

// ===== TOGGLE MASTER PASSWORD VISIBILITY =====
document.getElementById("toggle-mpass").addEventListener("click", () => {
  const input = document.getElementById("m-pass");
  const eyeOpen = document.getElementById("icon-eye-open");
  const eyeClosed = document.getElementById("icon-eye-closed");

  if (input.type === "password") {
    input.type = "text";
    eyeOpen.style.display = "none";
    eyeClosed.style.display = "block";
  } else {
    input.type = "password";
    eyeOpen.style.display = "block";
    eyeClosed.style.display = "none";
  }
});

function setStatus(msg, color = "#22c55e") {
  const el = document.getElementById("synth-status");
  if (!el) return;

  // Define which messages are "low priority" and can be blocked
  const genericMessages = ["Settings saved", "Password filled!", "Password filled and settings saved."];

  // If a Change Password flow is active, don't let generic messages overwrite the instructions
  if (window.isChangingPassword && genericMessages.includes(msg)) {
    return;
  }

  el.textContent = msg;
  el.style.color = color;
}

// Add a way to open the directory
function openDirectory() {
  DirectoryEditor.open();
}

setupCryptoCardListeners();  //formatting buttons etc.

// Listen for close event
window.addEventListener("closeDirectory", () => {
  // Go back to previous state
  updateUI(lastState);
});
/*
window.updateLockList = function() {
    const lockList = document.getElementById('lockList');
//    const emailDisplay = document.getElementById('decrypt-email-display');
    if (!lockList) return;

    // Use currentHost directly as per your preference
    const host = currentHost; 
    const storageKeys = ['locDir', 'myEmail'];
    if (host) storageKeys.push(host);

    console.log("Updating LockList for host:", host);

    chrome.storage.sync.get(storageKeys, (result) => {
        const locDir = result.locDir || {};
        
        // 1. Handle Sender Email Population
        let myEmail = result.myEmail || "";
        let myLock = "";

        if (host && result[host] && result[host].crypt) {
            if (result[host].crypt.email) myEmail = result[host].crypt.email;
            if (result[host].crypt.lock) myLock = result[host].crypt.lock;
        }
/*
        if (emailDisplay) {
            emailDisplay.textContent = myEmail ? `Sender: ${myEmail}` : "Sender: (Not set)";
            console.log("Populated Sender Email:", myEmail);
        }
*/
        // 2. Populate Recipients List
/*        lockList.innerHTML = '';

        // Add "Me" first
        if (myLock) {
            const meOption = document.createElement('option');
            meOption.value = myLock;
            meOption.textContent = "Me";
            lockList.appendChild(meOption);
        }

        // Add Directory entries
        let entryCount = 0;
        for (const [name, value] of Object.entries(locDir)) {
            const lockValue = Array.isArray(value) ? value[0] : value;
            if (lockValue && lockValue !== myLock) {
                const option = document.createElement('option');
                option.value = lockValue;
                option.textContent = name;
                lockList.appendChild(option);
                entryCount++;
            }
        }
        
        console.log(`LockList updated. Entries: ${entryCount}, Me Found: ${!!myLock}`);
    });
};*/

window.updateLockList = function() {
    const lockList = document.getElementById('lockList');
    if (!lockList) return;

    // 1. Save current selections
    const selectedValues = Array.from(lockList.selectedOptions).map(o => o.value);

    chrome.storage.sync.get(['locDir', currentHost], (result) => {
        const locDir = result.locDir || {};
        lockList.innerHTML = '';

        // 2. Add "Me" option at the top
        const meOption = document.createElement('option');
        meOption.value = "me";
        meOption.textContent = "Me";
        if (selectedValues.includes("me")) meOption.selected = true;
        lockList.appendChild(meOption);

        // 3. Filter and Categorize
        const groups = [];
        const individuals = [];

        for (const [name, value] of Object.entries(locDir)) {
            // Skip legacy locks starting with $
            if (name.startsWith('$')) continue;

            const valString = Array.isArray(value) ? value[0] : value;
            const isGroup = typeof valString === 'string' && valString.includes(',');
            
            const entry = { name, value: valString };

            if (isGroup) {
                groups.push(entry);
            } else {
                individuals.push(entry);
            }
        }

        // 4. Sort Alphabetically and Append Groups (bracketed in =)
        groups.sort((a, b) => a.name.localeCompare(b.name));
        groups.forEach(group => {
            const option = document.createElement('option');
            option.value = group.value;
            option.textContent = `=${group.name}=`;
            if (selectedValues.includes(group.value)) option.selected = true;
            lockList.appendChild(option);
        });

        // 5. Sort Alphabetically and Append Individuals
        individuals.sort((a, b) => a.name.localeCompare(b.name));
        individuals.forEach(indiv => {
            const option = document.createElement('option');
            option.value = indiv.value;
            option.textContent = indiv.name;
            if (selectedValues.includes(indiv.value)) option.selected = true;
            lockList.appendChild(option);
        });
    });
};

window.updateLockList = updateLockList; // Expose globally if needed

function updateRecipientStatus() {
  const lockList = document.getElementById('lockList');
  const recipientDisplay = document.getElementById('composeRecipientsBox');
  if (!lockList || !recipientDisplay) return;

  const selectedOptions = Array.from(lockList.selectedOptions).filter(opt => opt.value);

  if (selectedOptions.length === 0) {
    recipientDisplay.textContent = "Nobody! (Making an invitation)";
    recipientDisplay.style.color = "#666";
  } else {
    // Use textContent to show "Me" and "=Groups=" exactly as they appear in the list
    const names = selectedOptions.map(opt => opt.textContent);
    recipientDisplay.textContent = names.join(", ");
    recipientDisplay.style.color = "#2e7d32"; // Success Green
  }
}

document.getElementById("open-directory-btn").addEventListener("click", () => {
  DirectoryEditor.setMode("locDir"); // Force global directory mode
  DirectoryEditor.open();
});

chrome.runtime.onMessage.addListener((request) => {
  if (request.type === "STATE_UPDATE") {
    window.isManualFileMode = false; // Reset manual override on new state
    updateUI(request.state);
  }

  if (request.type === "BLOB_CLICKED") {
    // 1. Inject blob into the unified box
    const box = document.getElementById("composeBox");
    if (box) {
      box.textContent = request.blob.raw;
    }

    // 2. Switch to the unified crypto card in decrypt mode
    // This replaces the check for cards.decrypt.classList
    setCryptoMode("decrypt");

    // 3. Ensure Master Password gate logic is set
    masterPasswordContext = "decrypt";

    // 4. Update status
    const statusEl = document.getElementById("synth-status");
    if (statusEl) {
      statusEl.textContent = `Loaded: ${request.blob.type}`;
    }
  }
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]) {
    chrome.tabs.sendMessage(
      tabs[0].id,
      { type: "GET_CURRENT_STATE" },
      (response) => {
        if (chrome.runtime.lastError) {
          console.log("Agent not active on this tab. Please refresh.");
          return;
        }
        if (response) {
          updateUI(response);
        }
      },
    );
  }
});

// ===== MASTER PASSWORD TIMEOUT (5 minutes) =====
let pwdTimeoutTimer = null;

function startMasterPwdTimeout() {
  if (typeof pwdTimeoutTimer !== 'undefined' && pwdTimeoutTimer) {
    clearTimeout(pwdTimeoutTimer);
  }

  pwdTimeoutTimer = setTimeout(() => {
    // Clear sensitive globals
    window.activeFolderKey = null;
    window.lastDecryptedPadding = null;

    const pwdInput = document.getElementById('m-pass');
    if (pwdInput) pwdInput.value = "";

    const folderIndicator = document.getElementById('folder-active-indicator');
    if (folderIndicator) folderIndicator.style.display = 'none';

    const status = document.getElementById('synth-status');
    if (status) {
      status.textContent = "Session timed out. Keys cleared.";
      status.style.color = "#ef4444";
    }

    console.log("Inactivity timeout: Sensitive data wiped.");
  }, 5 * 60 * 1000);
}

// Reset the timeout on any meaningful UI interaction
['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(eventType => {
  document.addEventListener(eventType, () => {
    if (typeof startMasterPwdTimeout === 'function') {
      startMasterPwdTimeout();
    }
  }, { passive: true });
});

// Also trigger it once when the sidepanel first loads
document.addEventListener('DOMContentLoaded', () => {
  if (typeof startMasterPwdTimeout === 'function') {
    startMasterPwdTimeout();
  }
});

// UI Logic for the Decoy Section with Byte Counting
const dToggle = document.getElementById('decoyModeToggle');
const dArea = document.getElementById('decoyMessageArea');
const dInputArea = document.getElementById('decoy-input-area');
const dCount = document.getElementById('decoyByteCount');
const encoder = new TextEncoder();

dToggle.addEventListener('change', () => {
  dInputArea.style.display = dToggle.checked ? 'block' : 'none';
  if (dToggle.checked) dArea.focus();
});

dArea.addEventListener('input', () => {
  const bytes = encoder.encode(dArea.value).length;
  dCount.textContent = bytes;
  dCount.style.color = bytes > 75 ? 'red' : '#666';
});

//for the compose toolbar buttons

// === TOOLBAR WIRING ===

// Dropdowns
document.getElementById('formatBlock')?.addEventListener("change", function () {
  formatDoc('formatBlock', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('fontName')?.addEventListener("change", function () {
  formatDoc('fontName', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('fontSize')?.addEventListener("change", function () {
  formatDoc('fontSize', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('foreColor')?.addEventListener("change", function () {
  formatDoc('foreColor', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

// Icon buttons
const toolBar2 = document.getElementById('toolBar2');
if (toolBar2) {
  toolBar2.children[0]?.addEventListener("click", () => formatDoc('bold'));
  toolBar2.children[1]?.addEventListener("click", () => formatDoc('italic'));
  toolBar2.children[2]?.addEventListener("click", () => formatDoc('underline'));
  toolBar2.children[3]?.addEventListener("click", () => formatDoc('undo'));
  toolBar2.children[4]?.addEventListener("click", () => formatDoc('redo'));
  toolBar2.children[5]?.addEventListener("click", () => formatDoc('justifyleft'));
  toolBar2.children[6]?.addEventListener("click", () => formatDoc('justifycenter'));
  toolBar2.children[7]?.addEventListener("click", () => formatDoc('insertorderedlist'));
  toolBar2.children[8]?.addEventListener("click", () => formatDoc('insertunorderedlist'));
  toolBar2.children[9]?.addEventListener("click", () => {
    const url = prompt('Enter URL:', 'https://');
    if (url && url !== '' && url !== 'https://') formatDoc('createlink', url);
  });
  toolBar2.children[10]?.addEventListener("click", () => formatDoc('removeFormat'));
}

// File inputs
document.getElementById('imgFile')?.addEventListener('change', loadImage);
document.getElementById('imgFile')?.addEventListener('click', function () { this.value = ''; });

document.getElementById('mainFile')?.addEventListener('change', loadFile);
document.getElementById('mainFile')?.addEventListener('click', function () { this.value = ''; });

// Download all button
document.getElementById('downloadAllBtn')?.addEventListener("click", downloadAllFiles);

// Update toolbar state on selection change
document.getElementById('composeBox')?.addEventListener('mouseup', updateToolbarState);
document.getElementById('composeBox')?.addEventListener('keyup', updateToolbarState);

// === HELPER FUNCTION ===

/**
 * Executes a document.execCommand and updates toggle button states
 */
function formatDoc(command, value = null) {
  document.execCommand(command, false, value);
  document.getElementById('composeBox')?.focus();

  // Update toggle button states
  updateToolbarState();
}

/**
 * Updates the visual state of toggle buttons based on current selection
 */
function updateToolbarState() {
  const toolBar2 = document.getElementById('toolBar2');
  if (!toolBar2) return;

  // Map of commands to button indices
  const toggleButtons = [
    { index: 0, command: 'bold' },
    { index: 1, command: 'italic' },
    { index: 2, command: 'underline' },
    { index: 5, command: 'justifyleft' },
    { index: 6, command: 'justifycenter' },
    { index: 7, command: 'insertorderedlist' },
    { index: 8, command: 'insertunorderedlist' }
  ];

  toggleButtons.forEach(btn => {
    const button = toolBar2.children[btn.index];
    if (button && button.classList.contains('intLink')) {
      const isActive = document.queryCommandState(btn.command);
      button.style.backgroundColor = isActive ? '#b0d4ff' : '';
    }
  });
}

// Also update state when user clicks in the compose box
document.getElementById('composeBox')?.addEventListener('mouseup', updateToolbarState);
document.getElementById('composeBox')?.addEventListener('keyup', updateToolbarState);

/**
 * Handles image selection and inserts as a visible image wrapped in a download anchor
 */
function loadImage(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const dataURL = e.target.result;

    // Insert just the image with the filename stored in alt and title
    const imgTag = `<img src="${dataURL}" alt="${file.name}" title="${file.name}" style="max-width:100%; height:auto; border:1px solid #ccc; display:inline-block; margin:5px;" /> `;

    document.execCommand('insertHTML', false, imgTag);
    setStatus(`Image "${file.name}" loaded.`);
  };

  reader.readAsDataURL(file);
  event.target.value = ''; // Reset input so same file can be loaded again
}

function loadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const dataURL = e.target.result;

    // Create anchor element for file download
    const anchor = `<a href="${dataURL}" download="${file.name}" title="Click to download ${file.name}" style="display:inline-block; margin:5px; padding:5px; background:#fff8dc; border:1px solid #ccc; text-decoration:none;">[File: ${file.name}]</a> `;

    document.execCommand('insertHTML', false, anchor);
  };

  reader.readAsDataURL(file);
}

/**
 * Downloads all embedded files from the compose box
 */
function downloadAllFiles() {
  const box = document.getElementById('composeBox');
  const anchors = box.querySelectorAll('a[href^="data:"]');

  if (anchors.length === 0) {
    setStatus("No files found to download.");
    return;
  }

  let downloaded = 0;
  anchors.forEach((anchor, index) => {
    // Stagger downloads to prevent browser blocking
    setTimeout(() => {
      const link = document.createElement('a');
      link.href = anchor.href;
      link.download = anchor.download || `file_${index + 1}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      downloaded++;
      if (downloaded === anchors.length) {
        setStatus(`Downloaded ${downloaded} file(s).`);
      }
    }, index * 300); // 300ms delay between each download
  });

  setStatus(`Downloading ${anchors.length} file(s)...`);
}

document.getElementById('decryptFileBtn')?.addEventListener('click', () => {
  document.getElementById('plkFileInput').click();
});

const dropTarget = document.getElementById('dropTarget');

if (dropTarget) {
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropTarget.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, false);
  });

  dropTarget.addEventListener('dragenter', () => {
    dropTarget.classList.add('drag-over');
    // Check if a Folder Key is active to apply the green style
    if (window.activeFolderKey) {
      dropTarget.classList.add('folder-active');
    } else {
      dropTarget.classList.remove('folder-active');
    }
  });

  dropTarget.addEventListener('dragleave', () => {
    dropTarget.classList.remove('drag-over');
  });

  dropTarget.addEventListener('drop', (e) => {
    dropTarget.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleDroppedFiles(files);
    }
  });
}

// Main handler for dropped files
async function handleDroppedFiles(files) {
  const statusMsg = document.getElementById('encryptMsg'); // Unified ID
  const masterPwd = document.getElementById('m-pass')?.value;

  // 1. Check if any dropped files require decryption
  const hasPlk = Array.from(files).some(f => f.name.toLowerCase().endsWith('.plk'));

  // 2. Guard: If decrypting, require Master Password
  if (hasPlk && (!masterPwd || masterPwd.length === 0)) {
    if (statusMsg) {
      statusMsg.textContent = "Enter Master Password before decrypting .plk files.";
      statusMsg.style.color = "#ef4444";
    }
    showCard(cards.masterSection);
    document.getElementById('m-pass').focus();
    return;
  }

  if (statusMsg) {
    statusMsg.textContent = `Processing ${files.length} file(s)...`;
    statusMsg.style.color = ""; // Reset color
  }

  const readers = Array.from(files).map(file => readFileAsArrayBuffer(file));

  try {
    const buffers = await Promise.all(readers);

    for (let i = 0; i < buffers.length; i++) {
      const fileInBin = new Uint8Array(buffers[i]);
      const fileName = files[i].name;

      if (fileName.toLowerCase().endsWith('.plk')) {
        const outName = fileName.slice(0, -4);
        await processFileDecryption(fileInBin, outName);
      } else {
        const outName = fileName + '.plk';
        await processFileEncryption(fileInBin, outName);
      }
    }
    if (statusMsg) statusMsg.textContent = "All files processed.";
  } catch (err) {
    console.error("File processing error:", err);
    if (statusMsg) statusMsg.textContent = "Error processing files.";
  }
}

// Helper: Promise-based file reader
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = () => {
      console.error("FileReader error:", fr.error); // 👈 LOG ERROR
      reject(fr.error);
    }
    fr.readAsArrayBuffer(file);
  });
}

// Helper: Trigger browser download
function triggerDownload(uint8Array, fileName) {
  const blob = new Blob([uint8Array], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

// Add to the bottom of sidepanel_UI.js
document.addEventListener('DOMContentLoaded', () => {
  if (typeof startMasterPwdTimeout === 'function') {
    startMasterPwdTimeout();
  }
  setupCryptoCardListeners();
  if (typeof updateRecipientStatus === 'function') {
    updateRecipientStatus();
  }
  const closeDirBtn = document.getElementById('close-directory');
  if (closeDirBtn) {
    closeDirBtn.addEventListener('click', () => {
      // 1. Hide the directory card
      const dirCard = document.getElementById("directory-card");
      if (dirCard) dirCard.classList.add("hidden");

      // 2. Show the Unified Crypto Card
      if (cards.crypto) {
        cards.crypto.classList.remove("hidden");
      }
    });
  }
});

document.getElementById('help-btn')?.addEventListener('click', () => {
  // 1. Determine context
  let context = 'general';

  if (!document.getElementById('directory-card').classList.contains('hidden')) {
    context = 'directory';
  } else if (cards.crypto.dataset.mode === 'encrypt') {
    context = 'encrypt';
  } else if (cards.crypto.dataset.mode === 'decrypt') {
    context = 'decrypt';
  } else if (cards.crypto.dataset.mode === 'synthesis') {
    context = 'synthesis';
  }

  // 2. Open the corresponding local help file
  const helpFile = `help_${context}.html`;
  chrome.tabs.create({ url: chrome.runtime.getURL(helpFile) });
});

document.getElementById('clear-folder-key')?.addEventListener('click', () => {
  window.activeFolderKey = null;
  document.getElementById('folder-active-indicator').style.display = 'none';

  const status = document.getElementById('synth-status');
  if (status) {
    status.textContent = "Folder Key cleared. Standard modes restored.";
    status.style.color = ""; // Reset color
  }

  // Optional: Reset the border if you changed it
  document.getElementById('card-crypto').style.borderColor = '';
});

// Initialize the flag
window.isManualFileMode = false;
document.getElementById('manual-file-mode-btn').addEventListener('click', () => {
  window.isManualFileMode = true;
  updateUI();
});