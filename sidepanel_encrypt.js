//functions for encryption side panel

/**
 * Builds the binary header for the encrypted message.
 * @param {boolean} isAnon - Whether it's anonymous mode.
 * @param {number} recipientCount - Number of recipients.
 * @param {Uint8Array} nonce15 - The 15-byte nonce.
 * @param {Uint8Array | null} ephemeralPub - Ephemeral public key for anonymous mode (32 bytes).
 * @param {string} decoyPlaintext - The optional decoy message text.
 * @param {Uint8Array} mySecretKey - The sender's secret key (for decoy encryption).
 * @returns {Uint8Array} The constructed header.
 */
function buildBinaryHeader(mode, recipientCount, nonce15, ephemeralPub, decoyPlaintext, mySecretKey) {
  // 1. Build the 2-byte header
  const outHeader = new Uint8Array(2);
  // mode: 0 for Anonymous ('A'), 72 for Signed ('S'), 56 for Read-once ('O')
  outHeader[0] = mode;
  outHeader[1] = recipientCount & 0xFF;

  // 2. Build the 100-byte padding (may contain encrypted decoy message)
  let padding;
  if (decoyPlaintext && decoyPlaintext.length > 0) {
    padding = decoyEncrypt(decoyPlaintext);
  } else {
    padding = nacl.randomBytes(100);
  }

  // 3. Assemble: [2-byte header] + [15-byte nonce] + [100-byte padding]
  let header = concatUi8([outHeader, nonce15, padding]);

  // 4. If Anonymous mode (0), append the ephemeral public key (32 bytes)
  if (mode === 0 && ephemeralPub) {
    header = concatUi8([header, ephemeralPub]);
  }

  return header;
}

/**
 * Encrypts the message key for a single recipient, handling standard and Read-once modes.
 * In Read-once mode, it manages a per-recipient state machine to ensure Perfect Forward Secrecy (PFS).
 * 
 * @param {Uint8Array} recipientSigningPub - Recipient's permanent Edwards public key.
 * @param {Uint8Array} nonce24 - 24-byte nonce used for the entire message.
 * @param {Uint8Array} msgKey - 32-byte random key that encrypts the actual message body.
 * @param {Uint8Array} mySecretKey - Sender's permanent Curve25519 secret key.
 * @param {string} storageKey - Key used to encrypt locDir state for this recipient.
 * @param {number} mode - 0 (Anonymous), 72 (Signed), 56 (Read-once).
 * @param {string} recipientEmail - Email used to look up ephemeral state in locDir.
 */
function encryptForRecipientWithLock(recipientSigningPub, nonce24, msgKey, mySecretKey, storageKey, mode, recipientEmail) {
  // Convert recipient's signing key (Edwards) to encryption key (Montgomery/Curve25519)
  const recipientPub = ed2curve.convertPublicKey(recipientSigningPub);
  if (!recipientPub) return null;

  // --- 1. STANDARD MODES (Signed or Anonymous) ---
  if (mode === 72 || mode === 0) {
    const sharedKey = nacl.box.before(recipientPub, mySecretKey);
    const cipher2 = nacl.secretbox(msgKey, nonce24, sharedKey);
    const idTag = nacl.secretbox(recipientSigningPub, nonce24, sharedKey).slice(0, 8);
    return concatUi8([idTag, cipher2]);
  }

  // --- 2. READ-ONCE MODE (56) ---
  else if (mode === 56) {
    // FIX 1: Always read from the GLOBAL locDir
    if (!window.locDir[recipientEmail]) {
        window.locDir[recipientEmail] = { 
            lock: changeBase(nacl.util.encodeBase64(recipientSigningPub), base64, base36, true),
            ro: { lastkey: null, lastlock: null, turn: null } 
        };
    }
    const entry = window.locDir[recipientEmail]; // Reference the global entry

    const lastKeyCipher = entry.ro?.lastkey;
    const lastLockCipher = entry.ro?.lastlock;
    const turnstring = entry.ro?.turn;

    const secdum = nacl.randomBytes(32);
    let typeByte;
    let isReset = false;

    if (turnstring === 'reset' || !turnstring) {
      typeByte = new Uint8Array([172]);
      isReset = true;
    } else if (turnstring === 'unlock') {
      typeByte = new Uint8Array([164]);
    } else {
      typeByte = new Uint8Array([160]);
    }

    let lastKey;
    if (lastKeyCipher) {
      lastKey = keyDecrypt(lastKeyCipher, storageKey, true);
    } else {
      lastKey = secdum; // Use the new random key if there's no previous key (first-time setup)
      if (!isReset) {
        typeByte = new Uint8Array([164]);
      }
    }

    let lastLock;
    if (lastLockCipher) {
      lastLock = keyDecrypt(lastLockCipher, storageKey, true);
    } else {
      lastLock = convertPubStr(entry.lock); //use permanent Lock if nothig stored yet
    }

    const sharedKey = nacl.box.before(lastLock, lastKey);
//    const idKey = nacl.box.before(recipientPub, mySecretKey);
    const idKey = nacl.box.before(lastLock, mySecretKey);

    const cipher2 = nacl.secretbox(msgKey, nonce24, sharedKey);
    const idTag = nacl.secretbox(recipientSigningPub, nonce24, idKey).slice(0, 8);

    let newLockCipher;
    if (turnstring !== 'lock') {
      newLockCipher = nacl.secretbox(makePub(lastKey), nonce24, idKey); // Reuse lastKey as the new Lock key for the next turn, if a message has been sent already
    } else {
      newLockCipher = nacl.secretbox(makePub(secdum), nonce24, idKey);  //store new key if truly a new turn
    }

    // FIX 2: Update the global entry in-place
    if (!entry.ro) entry.ro = {};

    if (turnstring === 'lock' || !lastKeyCipher) {
      entry.ro.lastkey = keyEncrypt(secdum, storageKey);
    }

//    if (!isReset) {
      entry.ro.turn = 'unlock';
//    }
    // No need to reassign: entry is already a reference to window.locDir[recipientEmail]

    // FIX 3: Trigger the global save
    syncLocDir().catch(err => console.error("Failed to sync locDir:", err));
    console.log("Read-once state updated and saved for:", recipientEmail);

    return concatUi8([idTag, cipher2, typeByte, newLockCipher]);
  }

  return null;
}

/**
 * G-mode (Invitation) encryption handler
 * Triggered when no recipients are selected
 */
async function handleInvitationEncryption(msgUint8, mySecretKey) {
  const pwd = prompt("Enter a password for Symmetric encryption, or leave empty for an Invitation (using your Lock):");

  if (pwd === null) return null; // User cancelled

  let encryptionKey;
  let modeLabel = "INVITATION";

  const nonce15 = nacl.randomBytes(15);
  const nonce24 = makeNonce24(nonce15);

  if (pwd.trim() !== "") {
    // Symmetric Mode: Use password
    encryptionKey = wiseHash(pwd, nacl.util.encodeBase64(nonce15));
    modeLabel = "SYMMETRIC";
  } else {
    // Invitation Mode: Use sender's Lock
    const storage = await chrome.storage.sync.get([currentHost]);
    const myLock = storage[currentHost]?.crypt?.lock;
    if (!myLock) throw new Error("Your Lock is missing. Open Signed mode once to initialize.");
    encryptionKey = ezLockToUint8(myLock);

    if (!encryptionKey || encryptionKey.length !== 32) {
      throw new Error("Invalid Lock format. Could not derive encryption key.");
    }
  }

  let padding;
  const decoyToggle = document.getElementById('decoyModeToggle');
  const decoyArea = document.getElementById('decoyMessageArea');

  if (decoyToggle?.checked && decoyArea?.value.trim()) {
    padding = decoyEncrypt(decoyArea.value.trim());
  } else {
    padding = nacl.randomBytes(100);
  }

  const ciphertext = nacl.secretbox(msgUint8, nonce24, encryptionKey);

  return {
    finalBin: concatUi8([new Uint8Array([128]), nonce15, padding, ciphertext]),
    modeLabel: modeLabel
  };
}

// --- Main Encryption Trunk ---
async function startEncryption() {
  const statusMsg = document.getElementById('encryptMsg');
  const composeBox = document.getElementById('composeBox');
  const lockList = document.getElementById('lockList');
  const isAnon = document.getElementById('anonMode')?.checked;
  const isOnce = document.getElementById('onceMode')?.checked; // Check for Read-once mode
  const includeLock = document.getElementById('includeLock');
  const decoyToggle = document.getElementById('decoyModeToggle');
  const decoyArea = document.getElementById('decoyMessageArea');

  if (statusMsg) statusMsg.textContent = "Encrypting...";

  try {
    // --- KEY FILE TRIGGER ---
    let msgUint8;
    const rawHTML = composeBox.innerHTML.trim();

    // 1. Unified Logic: If box is empty, offer Folder Key
    if (!rawHTML) {
      const promptMsg = window.activeFolderKey
        ? "Compose box is empty. Use the ACTIVE Folder Key as payload?"
        : "Compose box is empty. Generate a NEW 32-byte Folder Key?";

      if (confirm(promptMsg)) {
        // Use active key if it exists, otherwise generate new
        msgUint8 = window.activeFolderKey || nacl.randomBytes(32);
      } else {
        if (statusMsg) statusMsg.textContent = "";
        return;
      }
    } else {
      msgUint8 = new TextEncoder().encode(rawHTML);
    }

    // Determine mode: 0 for Anonymous ('A'), 72 for Signed ('S'), 56 for Read-once ('O')
    let mode;
    if (isAnon) {
      mode = 0; // Anonymous
    } else if (isOnce) {
      mode = 56; // Read-once
    } else {
      mode = 72; // Signed (default)
    }

    // --- CALL CORE ENCRYPTION ---
    const settings = {
      selectedRecipients: Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s),
      mode: mode, // Use the new mode parameter
      masterPwd: document.getElementById('m-pass')?.value,
      myEmail: "",
      activeFolderKey: window.activeFolderKey,
      decoyText: (decoyToggle && decoyToggle.checked) ? decoyArea.value.trim() : ""
    };

    const result = await coreEncrypt(msgUint8, settings);
    if (!result) {
      if (statusMsg) statusMsg.textContent = "";
      return;
    }

    const { finalBin, modeLabel, base36Lock, suppressLock } = result;

    // --- OUTPUT AS TEXT ---
    const ciphertextB64 = nacl.util.encodeBase64(finalBin).replace(/=+$/, '');
    let lockPrefix = "";

    if (!suppressLock) {
      const forceLock = (modeLabel === "INVITATION");
      const optionalLock = (includeLock?.checked &&
        (modeLabel === "SIGNED" || modeLabel === "ANONYMOUS" || modeLabel === "READ-ONCE" || modeLabel === "SYMMETRIC")); // Added READ-ONCE

      if (forceLock || optionalLock) {
        const storage = await chrome.storage.sync.get([currentHost]);
        // This is now a Base36 string
        const lockToConvert = base36Lock || storage[currentHost]?.crypt?.lock || "";

        if (lockToConvert) {
          // SURGICAL CHANGE: Remove changeBase since it's already Base36
          // Just use the string directly.
          lockPrefix = lockToConvert + "//////";
        }
      }
    }

    const wrapped = (lockPrefix + ciphertextB64).match(/.{1,80}/g).join("\n");
    let fullBlock = `<pre>\n----BEGIN PASSLOK ${modeLabel} MESSAGE----==\n${wrapped}\n==----END PASSLOK ${modeLabel} MESSAGE----\n</pre>`;
    if (modeLabel === "INVITATION") fullBlock = wrapInvitationText(fullBlock);

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.tabs.sendMessage(tab.id, { type: "INSERT_ENCRYPTED_TEXT", text: "\n" + fullBlock + "\n", messageId: Date.now() }, (response) => {
      if (chrome.runtime.lastError) {
        reportCryptoFailure("Failed to inject. Refresh the page.");
      } else if (response?.success) {
        // 1. Clear the unified box on success
        if (composeBox) composeBox.innerHTML = "";
        // 2. Reset to a neutral state or stay in encrypt mode
        setCryptoMode("encrypt");

        // 3. --- NEW DETAILED REPORTING ---
        if (typeof reportCryptoSuccess === "function") {
          reportCryptoSuccess("encrypt", {
            mode: modeLabel,
            recipientCount: settings.selectedRecipients.length
          });
        } else {
          statusMsg.textContent = "Message encrypted and sent!";
        }
      }
    });

    if (decoyArea) { decoyArea.value = ""; document.getElementById('decoyByteCount').textContent = "0"; }
    if (typeof startMasterPwdTimeout === "function") startMasterPwdTimeout();

  } catch (err) {
    console.error("Encryption Error:", err);
    if (statusMsg) statusMsg.textContent = err.message;
  }
}

/**
 * Formats the final message with onboarding instructions
 */
function wrapInvitationText(encryptedBlock) {
  // We remove the newlines and indentation to prevent large gaps in the UI
  return `<div class="passlok-invitation" style="font-family: sans-serif; line-height: 1.4; color: #333;"><p>The gibberish link below contains a message from me that has been encrypted with PassLok Universal. To decrypt it, do this:</p><ol><li><strong>Install</strong> the PassLok Universal extension:<br>Chrome: <a href="https://chrome.google.com/webstore/detail/passlok-universal/lbmlbnfgnbfppkfijbbpnecpglockled">Link</a> | Firefox: <a href="https://addons.mozilla.org/en-US/firefox/addon/passlok-universal/">Link</a></li><li><strong>Reload</strong> your email and get back to this message.</li><li><strong>Click</strong> the PassLok logo above (orange key). You will be asked to supply a Password.</li></ol><p style="font-size: 0.9em; color: #666;">If you don't want to install an extension, you can use the standalone app at <a href="https://passlok.com/app">passlok.com/app</a></p><div style="margin-top: 10px; border-top: 1px dashed #ccc; padding-top: 10px;">${encryptedBlock}</div></div>`.trim();
}

// --- Decoy Encryption Function ---

function decoyEncrypt(plaintext) {
  const TOTAL_PADDING_LENGTH = 100;
  const NONCE_LENGTH = 9;

  try {
    if (!plaintext) return nacl.randomBytes(TOTAL_PADDING_LENGTH);

    const decoyKeyStr = prompt("Enter the secret key to encrypt the hidden message:");
    if (!decoyKeyStr) return nacl.randomBytes(TOTAL_PADDING_LENGTH);

    // 1. Fill 75 bytes with spaces (0x20)
    const finalPlaintext = new Uint8Array(75).fill(0x20);
    const textBytes = nacl.util.decodeUTF8(plaintext);
    finalPlaintext.set(textBytes.subarray(0, Math.min(textBytes.length, 75)));

    // 2. Standard encryption
    const nonce = nacl.randomBytes(NONCE_LENGTH);
    const nonce24 = makeNonce24(nonce);
    const sharedKey = wiseHash(decoyKeyStr, nacl.util.encodeBase64(nonce));
    const cipher = nacl.secretbox(finalPlaintext, nonce24, sharedKey);

    // 3. Assemble: 9 (nonce) + 91 (cipher) = 100 bytes exactly
    return concatUi8([nonce, cipher]);

  } catch (e) {
    console.error("Decoy encryption failed:", e);
    return nacl.randomBytes(TOTAL_PADDING_LENGTH);
  }
}

//for encrypting as file instead of text, not currently used but may be added as an option in the future

function packPassLokDocument() {
  const box = document.getElementById('composeBox').cloneNode(true);
  const files = [];

  // 1. Extract Images (standalone)
  const imgElements = box.querySelectorAll('img[src^="data:"]');
  imgElements.forEach((el, index) => {
    const dataURI = el.src;
    const name = el.alt || el.title || `image_${index}`;

    // Convert Data URI to Uint8Array
    const parts = dataURI.split(',');
    const byteString = atob(parts[1]);
    const array = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) array[i] = byteString.charCodeAt(i);

    files.push({ name: new TextEncoder().encode(name), data: array });

    // Replace with placeholder
    el.src = `plk-file:${files.length - 1}`;
  });

  // 2. Extract File Anchors
  const anchorElements = box.querySelectorAll('a[href^="data:"]');
  anchorElements.forEach((el, index) => {
    const dataURI = el.href;
    const name = el.download || el.title || `file_${index}`;

    // Convert Data URI to Uint8Array
    const parts = dataURI.split(',');
    const byteString = atob(parts[1]);
    const array = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) array[i] = byteString.charCodeAt(i);

    files.push({ name: new TextEncoder().encode(name), data: array });

    // Replace with placeholder
    el.href = `plk-file:${files.length - 1}`;
  });

  // 3. Compress the HTML Text using LZString
  const compressedTextBytes = LZString.compressToUint8Array(box.innerHTML);

  // 4. Calculate total size
  let totalSize = 4 + compressedTextBytes.length + 2;
  files.forEach(f => totalSize += 2 + f.name.length + 4 + f.data.length);

  // 5. Assemble Buffer
  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Write Compressed Text
  view.setUint32(offset, compressedTextBytes.length); offset += 4;
  buffer.set(compressedTextBytes, offset); offset += compressedTextBytes.length;

  // Write File Count
  view.setUint16(offset, files.length); offset += 2;

  // Write Files
  files.forEach(f => {
    view.setUint16(offset, f.name.length); offset += 2;
    buffer.set(f.name, offset); offset += f.name.length;
    view.setUint32(offset, f.data.length); offset += 4;
    buffer.set(f.data, offset); offset += f.data.length;
  });

  return buffer;
}

// Bridge for File Encryption
async function processFileEncryption(fileUint8, outName) {
  try {
    const lockList = document.getElementById('lockList');
    const decoyToggle = document.getElementById('decoyModeToggle');
    const decoyArea = document.getElementById('decoyMessageArea');

    // --- MODIFIED: Handle three modes instead of just isAnon ---
    let mode = 72; // Default to Signed ('S')
    if (document.getElementById('anonMode')?.checked) mode = 0;   // Anonymous ('A')
    if (document.getElementById('onceMode')?.checked) mode = 56;  // Read-once ('O')

    const settings = {
      selectedRecipients: Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s),
      mode: mode,
      masterPwd: document.getElementById('m-pass')?.value,
      myEmail: "",
      activeFolderKey: window.activeFolderKey,
      decoyText: (decoyToggle && decoyToggle.checked) ? decoyArea.value.trim() : ""
    };

    const result = await coreEncrypt(fileUint8, settings);
    if (result && result.finalBin) {
      triggerDownload(result.finalBin, outName);
      // OPTIONAL: Clear decoy area after success
      if (decoyArea) { decoyArea.value = ""; }
    }
  } catch (err) {
    console.error("File Encryption Error:", err);
    alert("Encryption failed: " + err.message);
  }
}

async function coreEncrypt(msgUint8, settings) {
  // settings: { selectedRecipients, mode, masterPwd, myEmail, activeFolderKey, decoyText }
  let finalBin, modeLabel;
  let base36Lock = "";
  let suppressLock = false;

  // 1. Folder Key Path
  if (settings.selectedRecipients.length === 0) {
    if (settings.activeFolderKey) {
      const nonce15 = nacl.randomBytes(15);
      const nonce24 = makeNonce24(nonce15);

      let padding;
      if (settings.decoyText && settings.decoyText.length > 0) {
        padding = decoyEncrypt(settings.decoyText);
      } else {
        padding = nacl.randomBytes(100);
      }

      const ciphertext = nacl.secretbox(msgUint8, nonce24, settings.activeFolderKey);
      finalBin = concatUi8([new Uint8Array([128]), nonce15, padding, ciphertext]);
      modeLabel = "FOLDER";
      suppressLock = true;
    } else {
      const result = await handleInvitationEncryption(msgUint8, null);
      if (!result) return null;
      finalBin = result.finalBin;
      modeLabel = result.modeLabel;
    }
  }
  // 2. Signed / Anonymous / Read-once Path
  else {
    // mode: 0 for Anonymous ('A'), 72 for Signed ('S'), 56 for Read-once ('O')
    modeLabel = settings.mode === 0 ? "ANONYMOUS" : (settings.mode === 72 ? "SIGNED" : "READ-ONCE");
    const storage = await chrome.storage.sync.get([currentHost, 'locDir']);
    const locDir = storage.locDir || {};
    const userData = storage[currentHost] || {};
    const myStoredLock = userData?.crypt?.lock || "";

    let mySecretKey, ephemeralPub = null;
    if (settings.mode === 0) { // Anonymous mode
      const ephemeral = nacl.box.keyPair();
      mySecretKey = ephemeral.secretKey;
      ephemeralPub = ephemeral.publicKey;
    } else { // Signed or Read-once mode
      if (!settings.masterPwd) throw new Error("Master password required.");
      const common = await prepareCommonData(settings.masterPwd, settings.myEmail || userData?.crypt?.email || "", null);
      mySecretKey = common.myKey;
      base36Lock = common.base36Lock;
      storageKey = common.storageKey;
    }

    const msgKey = nacl.randomBytes(32);
    const nonce15 = nacl.randomBytes(15);
    const nonce24 = makeNonce24(nonce15);

    // --- 1. Resolve everything into a unique set of 50-char LOCK STRINGS ---
    const finalLocks = new Set();

    const resolveToLocks = (input) => {
      if (!input || typeof input !== 'string') return;
      const trimmed = input.trim();

      // SPECIAL CASE: If it's literally "me", use the site-specific lock
      if (trimmed.toLowerCase() === 'me') {
        const myLock = base36Lock || myStoredLock;
        if (myLock && isStrictLock(myLock)) {
          finalLocks.add(myLock);
        }
        return;
      }

      // A. If it's a 50-char PassLok lock string, add it
      if (isStrictLock(trimmed)) {
        finalLocks.add(trimmed);
        return;
      }

      // B. If it's a comma-separated list, split and recurse
      if (trimmed.includes(',')) {
        trimmed.split(',').forEach(item => resolveToLocks(item.trim()));
        return;
      }

      // C. Otherwise, it's a Name/Key in locDir
      const cleanName = trimmed.replace(/^=|=$/g, '');
      const entry = locDir[cleanName];
      const value = entry.lock;

      if (value) {
        resolveToLocks(value); // Recurse to handle if value is a lock or a group
      }
    };

    // Resolve all selected recipients to their locks
    for (const sel of settings.selectedRecipients) {
      if (sel.toLowerCase() === "me") {
        // SKIP adding "Me" if we are in Read-once mode (56)
        if (settings.mode === 56) continue;

        const myLock = base36Lock || myStoredLock;
        if (myLock && isStrictLock(myLock)) finalLocks.add(myLock);
        continue;
      }
      resolveToLocks(sel);
    }

    // --- 2. Convert the unique Locks into encrypted Slots ---
    const recipientSlots = [];
    for (const lockB36 of finalLocks) {
      // 1. Find the email associated with this lock in locDir
      let recipientEmail = "";
      for (const [email, data] of Object.entries(locDir)) {
        if (data.lock === lockB36) {
          recipientEmail = email;
          break;
        }
      }

      // 2. Convert the lock to Uint8Array for the crypto functions
      const recipientUint8 = nacl.util.decodeBase64(changeBase(lockB36, base36, base64, true));

      // 3. Call our refactored function with the email context
      const slot = encryptForRecipientWithLock(
        recipientUint8,
        nonce24,
        msgKey,
        mySecretKey,
        storageKey,
        settings.mode,
        recipientEmail // Now the function can manage the ratchet state
      );

      if (slot) {
        recipientSlots.push(slot);
      }
    }

    // 2. Build header with the ACTUAL count of slots created
    let outArray = buildBinaryHeader(settings.mode, recipientSlots.length, nonce15, ephemeralPub, settings.decoyText || "", mySecretKey);

    // 3. Shuffle slots
    for (let i = recipientSlots.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [recipientSlots[i], recipientSlots[j]] = [recipientSlots[j], recipientSlots[i]];
    }
    recipientSlots.forEach(slot => outArray = concatUi8([outArray, slot]));

    const mainCipher = nacl.secretbox(msgUint8, nonce24, msgKey);
    finalBin = concatUi8([outArray, mainCipher]);
  }

  return { finalBin, modeLabel, base36Lock, suppressLock };
}

const isStrictLock = (str) => {
  if (typeof str !== 'string') return false;
  const trimmed = str.trim();
  // Exactly 50 characters. 
  // Set: 0-9, a-k, m-z (lowercase), and L (uppercase)
  return /^[0-9a-kLm-z]{50}$/.test(trimmed);
};

async function encryptToFile() {
  const statusMsg = document.getElementById('encryptMsg');
  const composeBox = document.getElementById('composeBox');
  const lockList = document.getElementById('lockList');

  // --- MODIFIED: Handle three modes instead of just isAnon ---
  let mode = 72; // Default to Signed ('S')
  if (document.getElementById('anonMode')?.checked) mode = 0;   // Anonymous ('A')
  if (document.getElementById('onceMode')?.checked) mode = 56;  // Read-once ('O')

  const decoyToggle = document.getElementById('decoyModeToggle');
  const decoyArea = document.getElementById('decoyMessageArea');

  if (statusMsg) statusMsg.textContent = "Encrypting to file...";

  try {
    const rawHTML = composeBox.innerHTML.trim();
    let msgUint8;
    let isFolderKey = false;

    if (!rawHTML || rawHTML === "Type or decrypt here..." || rawHTML === "Select an item to view...") {
      const promptMsg = window.activeFolderKey
        ? "Compose box is empty. Encrypt the ACTIVE Folder Key to this file?"
        : "Compose box is empty. Generate and encrypt a NEW random Folder Key?";

      const confirmed = confirm(promptMsg);
      if (!confirmed) {
        if (statusMsg) statusMsg.textContent = "";
        return;
      }
      msgUint8 = window.activeFolderKey || nacl.randomBytes(32);
      isFolderKey = true;
    } else {
      msgUint8 = new TextEncoder().encode(rawHTML);
    }

    const settings = {
      selectedRecipients: Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s),
      // --- MODIFIED: Pass mode instead of isAnon ---
      mode: mode,
      masterPwd: document.getElementById('m-pass')?.value,
      myEmail: "",
      activeFolderKey: window.activeFolderKey,
      decoyText: (decoyToggle && decoyToggle.checked) ? decoyArea.value.trim() : ""
    };

    const result = await coreEncrypt(msgUint8, settings);
    if (!result) {
      if (statusMsg) statusMsg.textContent = "";
      return;
    }

    const { finalBin, modeLabel } = result;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const fileName = isFolderKey ? `folder_key_${timestamp}.plk` : `passlok_${timestamp}.htm.plk`;

    triggerDownload(finalBin, fileName);

    if (typeof reportCryptoSuccess === "function") {
      reportCryptoSuccess("encrypt", {
        mode: isFolderKey ? "FOLDER KEY" : modeLabel,
        recipientCount: settings.selectedRecipients.length
      });
    } else {
      if (statusMsg) statusMsg.textContent = `Saved as ${fileName}`;
    }

    if (composeBox) composeBox.innerHTML = "";
    if (decoyArea) {
      decoyArea.value = "";
      const count = document.getElementById('decoyByteCount');
      if (count) count.textContent = "0";
    }

    if (typeof startMasterPwdTimeout === "function") startMasterPwdTimeout();

  } catch (err) {
    console.error("Encrypt to File Error:", err);
    if (statusMsg) {
      statusMsg.textContent = err.message;
      statusMsg.style.color = "#ef4444";
    }
  }
}