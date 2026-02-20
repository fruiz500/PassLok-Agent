//functions for blob decryption  

function extractEmbeddedLock(text) {
  // Ensure we are working with a string
  if (typeof text !== 'string') return { hasLock: false, ezLock: null, text: "" };

  const clean = text
    .replace(/[\s\r\n]/g, "")
    .replace(/-{3,}/g, "")
    .replace(/=/g, "");

  const lockMatch = clean.match(/^([0-9a-km-zL]{50})\/\/\/\/\/\/(.*)$/);

  if (!lockMatch) {
    return { hasLock: false, ezLock: null, text: clean };
  }

  return {
    hasLock: true,
    ezLock: lockMatch[1],
    text: lockMatch[2]
  };
}

// 3. Decrypt Button Listener
function doDecryptSelection() {
  // 1. Read from the unified box
  const box = document.getElementById("composeBox");
  const blobText = box.textContent.trim();

  // 2. Updated validation check
  if (!blobText) {
    alert("No encrypted message loaded. Click on an encrypted blob on the page or drop a .plk file.");
    return;
  }

  const masterPwd = document.getElementById("m-pass").value;
  const keysAvailable = masterPwd && masterPwd.length > 0;

  if (!keysAvailable) {
    // Use the unified state update
    updateUI({
      hasCrypto: true,
      needPasswordInput: true,
      cryptoItems: [],
      host: currentHost,
    });

    document.getElementById("synth-status").textContent = "Enter Master Password to decrypt content";
    document.getElementById("m-pass").focus();
    return;
  }

  // 3. Prepare blob for decryption
  const blob = {
    type: "MESSAGE",
    raw: blobText,
    // Improved mode detection logic
    mode: blobText.startsWith("A") ? "anonymous" : "signed",
  };

  decryptUniversal(blob);
}

// ==== UNIVERSAL DECRYPTION ====

function decryptUniversal(blob) {
  // 1. Check if we have Master Password
  const masterPwd = document.getElementById("m-pass").value;
  if (!masterPwd) {
    alert("Please enter your Master Password first");
    return;
  }

  // 2. Get email (salt) from the inline editable field
  const myEmail = document.getElementById("user-email").value;
  if (!myEmail || !myEmail.includes("@")) {
    alert("Please enter a valid email address in the Decrypt card");
    return;
  }

  // REMOVED: pendingFileBytes check. We are back to text-only.
  continueDecrypt(blob, masterPwd, myEmail);
}

/**
 * Refactored main decryption pipeline.
 * Orchestrates mode detection, key derivation, decryption, and post-processing.
 */

async function continueDecrypt(input, masterPwd, myEmail) {
  const statusMsg = document.getElementById('decryptMsg');
  if (!input) return;

  try {
    let fullBytes;
    let parsed = { hasLock: false, ezLock: null };

    // 1. UNIFY INPUT: Ensure we have a Uint8Array
    if (typeof input === 'string' || (input.raw && typeof input.raw === 'string')) {
      const text = input.raw || input.text || input;
      parsed = extractEmbeddedLock(text);
      fullBytes = nacl.util.decodeBase64(parsed.text);
    } else {
      // It's already binary (from continueDecryptBinary)
      fullBytes = input.raw || input;
    }

    // 2. UNIFIED TYPE DETECTION: Use the first byte
    const marker = fullBytes[0];
    let type;
    if (marker === 128) type = "g";
    else if (marker === 0) type = "A";
    else if (marker === 72) type = "S";
    else if (marker === 56) type = "O"; // Added: Read-once mode ('O')
    else type = String.fromCharCode(marker); // Fallback for ASCII-based markers

    // 3. ROUTE: Pass the binary bytes to the handlers
    const commonData = await prepareCommonData(masterPwd, myEmail, parsed);
    const result = await routeByMode(type, fullBytes, parsed, commonData);

    if (!result.success) throw new Error(result.error);

    // 3. Decrypt the payload
    let finalPlaintext;
    if (result.plaintext) {
      finalPlaintext = result.plaintext;
    } else {
      finalPlaintext = await decryptPayload(result.cipher, result.nonce, result.messageKey);
    }

    // 4. Display the result
    if (finalPlaintext instanceof Uint8Array) {
      if (finalPlaintext.length === 32) {
        window.activeFolderKey = finalPlaintext;
        // Pass "FOLDER" as the mode
        displayResult("Folder Key activated", "FOLDER", result.senderName);
      } else {
        const htmlContent = new TextDecoder().decode(finalPlaintext);
        // Pass result.modeLabel (e.g., "SIGNED", "ANONYMOUS")
        displayResult(htmlContent, result.modeLabel || "MESSAGE", result.senderName);
      }
    } else {
      displayResult(finalPlaintext, result.modeLabel || "MESSAGE", result.senderName);
    }

    // 5. Cleanup and UI updates
    await postProcessDecryption(parsed, type);
    window.lastDecryptedPadding = result.padding;

    // Show the decoy check button if applicable
    const decoySection = document.getElementById('decoy-decrypt-section');
    if (decoySection) decoySection.style.display = 'block';

    if (typeof startMasterPwdTimeout === "function") {
      startMasterPwdTimeout();
    }

    return {
      plaintext: finalPlaintext,
      type: type,
      senderName: result.senderName,
      padding: result.padding // Ensure this is returned
    };

  } catch (e) {
    console.error("Decryption error:", e);

    // Friendly message for known error
    let userMsg = e.message;
    if (e.message.includes("No matching sender Lock found")) {
      userMsg = "Decryption failed: This message was not encrypted for you.";
    }

    reportCryptoFailure(userMsg);

    // Optionally, show master password section if relevant
    if (e.message.includes("Master password") || e.message.includes("Lock")) {
      document.getElementById('master-password-section')?.classList.remove('hidden');
    }
  }
}

async function prepareCommonData(masterPwd, myEmail, parsed) {
  const KeySgn = nacl.sign.keyPair.fromSeed(wiseHash(masterPwd, myEmail)).secretKey;
  const myKey = ed2curve.convertSecretKey(KeySgn);
  const myLockbin = nacl.sign.keyPair.fromSecretKey(KeySgn).publicKey;

  // 1. Convert to Base64 first
  const b64 = nacl.util.encodeBase64(myLockbin);
  // 2. Convert to Base36 for storage and validation
  const base36Lock = changeBase(b64, base64, base36, true);

  // Now validate using the Base36 version
  await validateAndUpdateMeLock(myEmail, base36Lock, currentHost);

  return { myKey, myLockbin, base36Lock }; // Renamed internally to base36Lock
}

async function routeByMode(type, cipherText, parsed, commonData) {
  switch (type) {
    case "g": return handleGMode(cipherText, parsed);
    case "A": return handleAnonymousMode(cipherText, commonData);
    case "S": return handleSignedMode(cipherText, parsed, commonData);
    case "O": return handleOnceMode(cipherText, parsed, commonData); // Read-once mode uses same handler for now
    default: return { success: false, error: `Unsupported mode: ${type}` };
  }
}

async function handleGMode(input, parsed) {
  try {
    // 1. Normalize input and extract binary components
    const fullBlob = (typeof input === 'string') ? nacl.util.decodeBase64(input) : input;
    if (fullBlob[0] !== 128) throw new Error("Invalid g-mode marker");

    const nonce15 = fullBlob.slice(1, 16);
    const padding = fullBlob.slice(16, 116);
    const cipher = fullBlob.slice(116);
    const nonce24 = makeNonce24(nonce15);

    let messageKey = null;
    let senderName = "Invitation/Self";

    // 2. Attempt 1: Embedded Lock (Invitation Mode)
    if (parsed.hasLock && parsed.ezLock) {
      try {
        const lockKey = ezLockToUint8(parsed.ezLock);
        // Test if this key works
        if (nacl.secretbox.open(cipher, nonce24, lockKey)) {
          messageKey = lockKey;
          senderName = "Invitation Lock";
        }
      } catch (e) { messageKey = null; }
    }

    // 3. Attempt 2: Active Folder Key
    if (!messageKey && window.activeFolderKey) {
      if (nacl.secretbox.open(cipher, nonce24, window.activeFolderKey)) {
        messageKey = window.activeFolderKey;
        senderName = "Folder Key";
      }
    }

    // 4. Attempt 3: Symmetric Password
    if (!messageKey) {
      const pwd = prompt("Enter the password for this g-mode message:");
      if (!pwd) throw new Error("Password required for g-mode.");

      const symKey = wiseHash(pwd, nacl.util.encodeBase64(nonce15));
      if (nacl.secretbox.open(cipher, nonce24, symKey)) {
        messageKey = symKey;
        senderName = "Symmetric Password";
      }
    }

    if (!messageKey) throw new Error("Decryption failed. Wrong password or corrupted data.");

    // 5. Return standardized object
    // Note: We return 'cipher' so continueDecrypt can call decryptPayload
    return {
      success: true,
      messageKey: messageKey,
      nonce: nonce24,
      padding: padding,
      cipher: cipher,
      senderName: senderName,
      modeLabel: (senderName === "Folder Key") ? "FOLDER" : "INVITATION"
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function handleAnonymousMode(cipherInput, commonData) {
  try {
    const { myKey, myLockbin } = commonData;
    // REMOVED: nacl.util.decodeBase64(cipherText)
    // cipherInput is now already a Uint8Array

    // Extract components from binary
    const recipients = cipherInput[1];
    const nonce = cipherInput.slice(2, 17); // 15 bytes
    const padding = cipherInput.slice(17, 117); // 100 bytes
    const pubdum = cipherInput.slice(117, 149); // 32 bytes

    const sharedKey = makeShared(pubdum, myKey);
    const nonce24 = makeNonce24(nonce);
    const stuffForId = myLockbin;
    const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);

    const cipherData = cipherInput.slice(149);
    const cipher = cipherData.slice(56 * recipients);

    const msgKeycipher = findEncryptedMessageKey(recipients, cipherData, idTag);
    if (!msgKeycipher) throw new Error("This message was not encrypted for you");

    const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
    if (!msgKey) throw new Error("Failed to decrypt message key");

    return { success: true, messageKey: msgKey, nonce: nonce24, padding: padding, cipher };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function handleSignedMode(cipherInput, parsed, commonData) {
  try {
    const { myKey, myLockbin } = commonData;
    // cipherInput is now already a Uint8Array

    const recipients = cipherInput[1];
    const nonce = cipherInput.slice(2, 17);
    const padding = cipherInput.slice(17, 117);
    const nonce24 = makeNonce24(nonce);
    const stuffForId = myLockbin;

    const cipherData = cipherInput.slice(117);
    const cipher = cipherData.slice(56 * recipients);

    // 1. If prepended Lock, try to decrypt with it
    if (parsed.hasLock) {
      const senderLock = ezLockToUint8(parsed.ezLock);
      if (senderLock) {
        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);
        const msgKeycipher = findEncryptedMessageKey(recipients, cipherData, idTag);

        if (msgKeycipher) {
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return { success: true, messageKey: msgKey, nonce: nonce24, padding: padding, cipher, senderName: "Prepended Lock" };
          }
        }
      }
    }

    // 2. Fallback: Try site-specific lock and all known Locks in locDir
    const host = currentHost;
    const storageKeys = ['locDir'];
    if (host) storageKeys.push(host);

    const storageData = await chrome.storage.sync.get(storageKeys);
    const locDir = storageData.locDir || {};

    let locksToTry = [];

    // Correctly navigate the nested structure: host -> crypt -> lock
    if (host && storageData[host] && storageData[host].crypt && storageData[host].crypt.lock) {
      locksToTry.push({
        name: "Me",
        lockStr: storageData[host].crypt.lock
      });
    }

    // Add locDir entries
    for (const [name, data] of Object.entries(locDir)) {
      locksToTry.push({
        name: name,
        lockStr: data.lock
      });
    }

    // Now loop through the prioritized list
    for (const entry of locksToTry) {
      try {
        const senderLock = ezLockToUint8(entry.lockStr);
        if (!senderLock) continue;

        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);
        const msgKeycipher = findEncryptedMessageKey(recipients, cipherData, idTag);

        if (msgKeycipher) {
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return {
              success: true,
              messageKey: msgKey,
              nonce: nonce24,
              padding: padding,
              cipher,
              senderName: entry.name
            };
          }
        }
      } catch (e) {
        continue;
      }
    }

    return { success: false, error: "No matching sender Lock found in directory" };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

//for the time being, identical to handleSignedMode since the main difference is in how the message is encrypted (e.g. no sender lock, different marker byte). The handler logic can be the same since we are trying all known locks anyway. We can differentiate later if we want to enforce that "once" mode messages must not have sender locks, etc.
async function handleOnceMode(cipherInput, parsed, commonData) {
  try {
    const { myKey, myLockbin } = commonData;
    // cipherInput is now already a Uint8Array

    const recipients = cipherInput[1];
    const nonce = cipherInput.slice(2, 17);
    const padding = cipherInput.slice(17, 117);
    const nonce24 = makeNonce24(nonce);
    const stuffForId = myLockbin;

    const cipherData = cipherInput.slice(117);
    const cipher = cipherData.slice(56 * recipients);

    // 1. If prepended Lock, try to decrypt with it
    if (parsed.hasLock) {
      const senderLock = ezLockToUint8(parsed.ezLock);
      if (senderLock) {
        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);
        const msgKeycipher = findEncryptedMessageKey(recipients, cipherData, idTag);

        if (msgKeycipher) {
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return { success: true, messageKey: msgKey, nonce: nonce24, padding: padding, cipher, senderName: "Prepended Lock" };
          }
        }
      }
    }

    // 2. Fallback: Try site-specific lock and all known Locks in locDir
    const host = currentHost;
    const storageKeys = ['locDir'];
    if (host) storageKeys.push(host);

    const storageData = await chrome.storage.sync.get(storageKeys);
    const locDir = storageData.locDir || {};

    let locksToTry = [];

    // Correctly navigate the nested structure: host -> crypt -> lock
    if (host && storageData[host] && storageData[host].crypt && storageData[host].crypt.lock) {
      locksToTry.push({
        name: "Me",
        lockStr: storageData[host].crypt.lock
      });
    }

    // Add locDir entries
    for (const [name, data] of Object.entries(locDir)) {
      locksToTry.push({
        name: name,
        lockStr: data.lock
      });
    }

    // Now loop through the prioritized list
    for (const entry of locksToTry) {
      try {
        const senderLock = ezLockToUint8(entry.lockStr);
        if (!senderLock) continue;

        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);
        const msgKeycipher = findEncryptedMessageKey(recipients, cipherData, idTag);

        if (msgKeycipher) {
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return {
              success: true,
              messageKey: msgKey,
              nonce: nonce24,
              padding: padding,
              cipher,
              senderName: entry.name
            };
          }
        }
      } catch (e) {
        continue;
      }
    }

    return { success: false, error: "No matching sender Lock found in directory" };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function decryptPayload(cipher, nonce, messageKey) {
  const plain = nacl.secretbox.open(cipher, nonce, messageKey);
  if (!plain) throw new Error("Failed to decrypt message");

  // NEW: If exactly 32 bytes, it's a Folder Key. Return raw binary.
  if (plain.length === 32) {
    return plain;
  }

  // 1. Check if it's a Binary Container (new format)
  if (plain.length >= 6) {
    const view = new DataView(plain.buffer, plain.byteOffset);
    const textLen = view.getUint32(0);

    if (textLen > 0 && textLen < plain.length && textLen + 6 <= plain.length) {
      try {
        const htmlContent = unpackPassLokDocument(plain);
        return htmlContent;
      } catch (e) {
        console.warn("Binary container detection failed, trying legacy formats:", e);
      }
    }
  }

  // 2. Legacy Format: Try LZ decompression first
  let plaintext;
  try {
    plaintext = LZString.decompressFromUint8Array(plain);
    if (!plaintext) plaintext = nacl.util.encodeUTF8(plain);
  } catch {
    plaintext = nacl.util.encodeUTF8(plain);
  }

  return plaintext;
}

async function postProcessDecryption(parsed, type) {
  // Instead of auto-saving, prompt user if Lock is new
  if (type === "g" || type === "A" || type === "S") {
    await promptUserToNameSenderLock(parsed);
  }
}

async function promptUserToNameSenderLock(parsed) {
  if (!parsed.hasLock) return;

  // 1. REMOVE the conversion. We work with Base36 now.
  const theirLockB36 = parsed.ezLock;

  const data = await chrome.storage.sync.get(['locDir']);
  const locDir = data.locDir || {};

  // 2. Check against locDir using the Base36 string
  const knownEntry = Object.entries(locDir).find(([_, data]) => {
    const storedLock = data.lock || "";
    return storedLock === theirLockB36;
  });

  if (knownEntry) {
    const [knownName] = knownEntry;
    setStatus(`Decrypted (Sender: ${knownName})`);
    document.getElementById("sender-prompt-overlay")?.classList.add("hidden");
  } else {
    setStatus("Decrypted (New sender lock detected)");
    // 3. Pass the Base36 lock to the prompt function
    promptForSenderName(theirLockB36);
  }
}

/**
 * Finds the encrypted message key by matching the recipient's ID tag.
 */
function findEncryptedMessageKey(recipients, cipherInput, idTag) {
  const cipherArray = [];
  for (let i = 0; i < recipients; i++) {
    cipherArray.push(cipherInput.slice(56 * i, 56 * (i + 1)));
  }

  for (let i = 0; i < recipients; i++) {
    let match = true;
    for (let j = 0; j < 8; j++) {
      if (idTag[j] !== cipherArray[i][j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return cipherArray[i].slice(8);
    }
  }

  return null;
}

/**
 * Centralized error handler.
 */
function handleError(error) {
  console.error("Decryption error:", error);
  document.getElementById("synth-status").textContent = "Decryption failed.";
  document.getElementById("synth-status").style.color = "#ef4444";
  alert("Decryption failed: " + error.message);
}

/**
 * Displays decrypted plaintext and updates status with sender info if available.
 */

function displayResult(content, modeLabel, senderName) {
  const box = document.getElementById('composeBox');
  if (!box) return;

  if (typeof content === 'string') {
    box.innerHTML = content;
  }

  setCryptoMode("decrypt");

  // Show the indicator if a Folder Key was just activated
  if (modeLabel === "FOLDER") {
    const folderIndicator = document.getElementById('folder-active-indicator');
    if (folderIndicator) folderIndicator.style.display = 'block';
  }
  // Note: We do NOT hide it here for other modes, because the key 
  // is still in memory and still overriding standard logic.

  reportCryptoSuccess("decrypt", {
    type: modeLabel,
    length: content.length,
    senderLock: senderName
  });

  box.focus();
}

/*
// Helper function to prompt user to select sender Lock from stored Locks
function promptUserToSelectSenderLock(locDir, callback) {
  alert("Sender Lock selection UI not fully implemented yet.");
  // Filter to ensure we only pick keys that have a lock property
  const validNames = Object.keys(locDir).filter(name => locDir[name].lock);
  callback(validNames[0]);
}
*/

let pendingLock = null;

function promptForSenderName(theirLockB36) {
  pendingLock = theirLockB36;
  const overlay = document.getElementById("sender-prompt-overlay");
  const preview = document.getElementById("sender-lock-preview");

  if (overlay && preview) {
    preview.textContent = theirLockB36.slice(0, 12) + "...";
    overlay.classList.remove("hidden");
    // Don't change synth-status here, let continueDecrypt handle it
  }
}

// 2. The Save Button Listener
function saveSenderLock() {
  const name = document.getElementById("new-sender-name").value.trim();
  if (!name) {
    alert("Please enter a name.");
    return;
  }

  // This is where locDir is created/updated in Chrome Sync
  chrome.storage.sync.get(["locDir"], (result) => {
    let locDir = result.locDir || {}; // Initialize if it doesn't exist

    // If the entry exists and is an object, merge the lock. 
    // Otherwise, create a new object.
    if (typeof locDir[name] === 'object' && locDir[name] !== null && !Array.isArray(locDir[name])) {
      locDir[name].lock = pendingLock;
    } else {
      locDir[name] = { lock: pendingLock };
    }

    chrome.storage.sync.set({ locDir }, () => {
      document.getElementById("sender-prompt-overlay").classList.add("hidden");
      document.getElementById("synth-status").textContent =
        `Decrypted (Saved as: ${name})`;
      document.getElementById("synth-status").style.color = "#22c55e";
      pendingLock = null;
    });
  });
}

// 1. New Validation Function
async function validateAndUpdateMeLock(email, generatedLock, host) {
  if (!email || !generatedLock || !host) return true;

  const data = await chrome.storage.sync.get([host]);
  const hostData = data[host] || {};
  const crypt = hostData.crypt || {};
  const existingLock = crypt.lock || null;

  // If no lock exists, save it silently
  if (!existingLock) {
    crypt.lock = generatedLock;
    crypt.email = email;
    hostData.crypt = crypt;
    await chrome.storage.sync.set({ [host]: hostData });
    return true;
  }

  // If it matches, proceed
  if (existingLock === generatedLock) return true;

  // If mismatch, ask user
  const confirmUpdate = confirm(
    `The Lock generated from your password does not match the stored Lock for (Me) ${email}.\n\nUpdate the stored Lock to match your current password?`,
  );

  if (confirmUpdate) {
    crypt.lock = generatedLock;
    crypt.email = email;
    hostData.crypt = crypt;
    await chrome.storage.sync.set({ [host]: hostData });
    return true;
  }
  return false;
}

function doDecoyDecrypt() {

  // 1. Hide the button immediately to prevent double-clicks
  const section = document.getElementById('decoy-decrypt-section');
  if (section) section.style.display = 'none';

  const padding = window.lastDecryptedPadding;
  if (!padding) return;

  const decoyKeyStr = prompt("Enter the secret key for the hidden message:");
  if (!decoyKeyStr) return;

  try {
    const nonce = padding.slice(0, 9);
    const cipherMsg = padding.slice(9);
    const nonce24 = makeNonce24(nonce);

    // The 'work' happens here
    const sharedKey = wiseHash(decoyKeyStr, nacl.util.encodeBase64(nonce));
    const plain = nacl.secretbox.open(cipherMsg, nonce24, sharedKey);

    if (plain) {
      const decoded = decodeURI(nacl.util.encodeUTF8(plain)).trim();
      const readMsg = document.getElementById('composeBox');

      // Append the hidden message to the display
      const hiddenDiv = document.createElement('div');
      hiddenDiv.style.marginTop = "10px";
      hiddenDiv.style.padding = "8px";
      hiddenDiv.style.borderLeft = "4px solid #607d8b";
      hiddenDiv.style.backgroundColor = "#f1f1f1";
      hiddenDiv.innerHTML = "<strong>Hidden Message:</strong><br>" + decoded;

      readMsg.appendChild(hiddenDiv);

      // Clean up

      window.lastDecryptedPadding = null;
    } else {
      alert("No hidden message found.");
    }
  } catch (err) {
    console.error("Decoy Decryption Error:", err);
    alert("Error attempting decoy decryption.");
  }
}

// Entry point for file decryption
async function startDecryption(fileBytes) {
  const statusMsg = document.getElementById('decryptMsg');
  const masterPwdField = document.getElementById('m-pass');

  // 1. Store the bytes globally
  window.pendingFileBytes = fileBytes;

  // 2. Set the context so the Enter key knows what to do
  window.masterPasswordContext = "decrypt";

  // 3. If password is ready, just click the button for the user
  if (masterPwdField?.value) {
    document.getElementById("do-decrypt-selection").click();
  } else {
    // 4. Otherwise, prompt and focus
    if (statusMsg) statusMsg.textContent = "Enter Master Password to decrypt file.";
    masterPwdField?.focus();
  }
}

/**
 * Helper to actually run the decryption once we have bytes and password
 */
async function proceedWithFileDecryption(fileBytes, masterPwd) {
  const storage = await chrome.storage.sync.get([currentHost]);
  const myEmail = storage[currentHost]?.crypt?.email || "";

  const blob = {
    raw: fileBytes,
    base64: nacl.util.encodeBase64(fileBytes)
  };

  await continueDecrypt(blob, masterPwd, myEmail);
  window.pendingFileBytes = null; // Clear after success
}

// Bridge for File Decryption
async function processFileDecryption(fileUint8, outName) {
  const statusMsg = document.getElementById('encryptMsg'); // Transient status

  try {
    let decrypted;

    // Inside processFileDecryption:
    if (fileUint8[0] === 128) {
      const result = await handleGMode(fileUint8, { hasLock: false });
      if (!result?.plaintext) throw new Error("Decryption failed.");
      decrypted = result.plaintext;
      window.lastDecryptedPadding = result.padding; // Explicitly set global
    } else {
      const result = await continueDecryptBinary(fileUint8);
      if (!result?.plaintext) throw new Error("Decryption failed.");
      decrypted = result.plaintext;
      window.lastDecryptedPadding = result.padding; // Explicitly set global
    }

    if (decrypted instanceof Uint8Array && decrypted.length === 32) {
      window.activeFolderKey = decrypted;
      // Report Folder Key activation to the top status bar
      reportCryptoSuccess("decrypt", { type: "Folder Key", length: 32 });
      return;
    }

    const isUIContent = outName.toLowerCase().endsWith('.htm');

    if (isUIContent) {
      const composeBox = document.getElementById('composeBox');
      const content = (decrypted instanceof Uint8Array) ? new TextDecoder().decode(decrypted) : decrypted;

      if (composeBox) {
        composeBox.innerHTML = content;
        setCryptoMode("decrypt");
        hideCard(document.getElementById('master-password-section'));

        // --- NEW DETAILED REPORTING ---
        reportCryptoSuccess("decrypt", {
          type: "Message",
          length: content.length,
          senderLock: "" // Placeholder for future sender extraction
        });

        composeBox.focus();
      }
    } else {
      const data = (decrypted instanceof Uint8Array) ? decrypted : new TextEncoder().encode(decrypted);
      triggerDownload(data, outName);

      // --- NEW DETAILED REPORTING ---
      reportCryptoSuccess("decrypt", {
        type: `File (${outName})`,
        length: data.length
      });
    }

  } catch (err) {
    console.error("File Decryption Error:", err);
    const errorDisplay = statusMsg || document.getElementById('synth-status');
    if (errorDisplay) {
      errorDisplay.textContent = err.message;
      errorDisplay.style.color = "#ef4444";
    }
  }
}

async function continueDecryptBinary(uint8) {
  const mpInput = document.getElementById('m-pass');
  const mp = mpInput?.value;

  if (!mp && !window.activeFolderKey) {
    // 1. Get the actual element by its correct ID
    const mpSection = document.getElementById('master-password-section');

    if (mpSection) {
      // 2. Pass the element, not the string
      showCard(mpSection);

      // 3. Focus the input for the user
      mpInput?.focus();
    }

    //    throw new Error("Please enter your Master Password and try again.");
  }

  const storage = await chrome.storage.sync.get([currentHost]);
  const myEmail = storage[currentHost]?.crypt?.email || "";

  //  const b64 = nacl.util.encodeBase64(uint8).replace(/=+$/, '');

  return await continueDecrypt(uint8, mp, myEmail);
}