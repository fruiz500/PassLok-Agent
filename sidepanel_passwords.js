//functions for password generation 

// ===== SYNTHESIZE & FILL =====
// Helper function to build charset from user input
function buildAllowedCharset(inputStr) {
  const keywordMap = {
    numbers: "0123456789",
    numeric: "0123456789",
    alpha: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alphanumeric:
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    hex: "0123456789abcdef",
  };

  let charset = "";

  // Split input into keywords and literals
  const parts = inputStr.match(/[a-z]+|[^a-z]+/gi) || [];

  parts.forEach((part) => {
    const lowerPart = part.toLowerCase();
    if (keywordMap[lowerPart]) {
      charset += keywordMap[lowerPart];
    } else {
      // Add literal characters as-is
      charset += part;
    }
  });

  // Remove duplicates
  charset = Array.from(new Set(charset.split("")))
    .join("")
    .replace(/\s+/g, "");

  return charset;
}

// Synth password generation handler
document.getElementById("do-synth").addEventListener("click", () => {
  const masterPwd = document.getElementById("m-pass").value.trim();
  const serial = document.getElementById("serial").value.trim();
  const host = currentHost;
  
  if (!masterPwd) { alert("Please enter your Master Password"); return; }

  const synthesized = getSynthesizedPassword();

  // 1. Save data (now silent)
  saveHostData(host);
  
  // 2. Fill the page
  fillPasswordOnPage(synthesized);

  // 3. Set the correct status message
  if (window.isChangingPassword) {
    setStatus("New password filled! Now PASTE the old password from your clipboard into the 'Current Password' field.", "#0284c7");
    // DO NOT reset the flag to false immediately here. 
    // If we reset it here, the async "Settings saved" might still catch it.
    // Let's reset it after a short delay.
    setTimeout(() => { window.isChangingPassword = false; }, 500);
  } else {
    setStatus("Password filled and settings saved.", "#22c55e");
  }

  startMasterPwdTimeout();
});

// Helper to generate password without filling
function getSynthesizedPassword() {
  const masterPwd = document.getElementById("m-pass").value.trim();
  const serial = document.getElementById("serial").value.trim();
  const host = currentHost;
  const allowedInput = document.getElementById("allowed-chars").value.trim();
  const lengthInput = document.getElementById("length-limit").value.trim();

  if (!masterPwd) return null;

  const defaultCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=";
  let charset = allowedInput ? buildAllowedCharset(allowedInput) : defaultCharset;

  const hashBytes = wiseHash(masterPwd, host + serial);
  let bigIntHash = BigInt(0);
  for (let i = 0; i < hashBytes.length; i++) {
    bigIntHash = (bigIntHash << 8n) + BigInt(hashBytes[i]);
  }

  const base = BigInt(charset.length);
  let synthesized = "";
  while (bigIntHash > 0n) {
    const remainder = bigIntHash % base;
    synthesized = charset[Number(remainder)] + synthesized;
    bigIntHash = bigIntHash / base;
  }

  const length = lengthInput ? Math.min(parseInt(lengthInput), synthesized.length) : synthesized.length;
  return synthesized.slice(0, length);
}

// The "Change Password" button listener
document.getElementById("change-synth")?.addEventListener("click", async () => {
  const oldPwd = getSynthesizedPassword(); // Uses the helper function
  if (!oldPwd) {
    alert("Please enter your Master Password first.");
    return;
  }

  try {
    await navigator.clipboard.writeText(oldPwd);
    window.isChangingPassword = true; // Set the flag for the next 'Fill' click
    setStatus("Old password copied! Change serial and click 'Synthesize and Fill'.", "#0284c7");
  } catch (err) {
    alert("Failed to copy to clipboard.");
  }
});

// sends password to content script to fill into page
function fillPasswordOnPage(password) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.tabs.sendMessage(tabs[0].id, {
      type: "FILL_PASSWORD",
      password: password,
    });
    setStatus("Password filled!");
  });
}

// ===== VAULT PASSWORD MANAGEMENT =====

// vault.js (or add to crypto-symmetric.js utilities)

async function getVaultPwd(host) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(host, (data) => {
      resolve(data?.[host]?.crypt?.pwd || null);
    });
  });
}

async function setVaultPwd(host, encryptedPwd) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(host, (data) => {
      const item = data[host] || {};
      item.crypt = item.crypt || {};
      item.crypt.pwd = encryptedPwd || null; // null = delete
      chrome.storage.sync.set({ [host]: item }, resolve);
    });
  });
}

document.getElementById("useVaultPwd").addEventListener("click", async () => {
  if (!currentHost) {
    alert("No active host detected.");
    return;
  }

  const masterPwd = document.getElementById("m-pass")?.value;
  if (!masterPwd) {
    alert("Please enter Master Password first.");
    return;
  }

  const stored = await getVaultPwd(currentHost);

  if (stored) {
    handleVaultOptions(stored, currentHost);
  } else {
    showVaultPrompt(currentHost);
  }
});

async function handleVaultOptions(ciphertext, host) {
  const masterPwd = document.getElementById("m-pass")?.value;
  if (!masterPwd) {
    alert("Please enter Master Password first.");
    return;
  }

  try {
    const salt = await wiseHash(masterPwd, host);
    const decrypted = await keyDecrypt(ciphertext, salt);

    if (decrypted) {
      const action = confirm(
        "Use stored password? (OK=use, Cancel=change/delete)",
      );
      if (action) {
        fillPasswordOnPage(decrypted);
      } else {
        showVaultPrompt(host); // User can change or DELETE
      }
    } else {
      alert("Decryption failed. Wrong Master Password?"); // <--- Add this
    }
  } catch (e) {
    console.error("Vault options error:", e);
    alert("Decryption error. Check Master Password."); // <--- And this
  }
}

function showVaultPrompt(host) {
  const pwd = prompt(
    "Enter password to store for this site.\nTo delete stored password, enter: DELETE",
  );

  if (pwd === null) return; // User cancelled

  if (pwd === "DELETE" || pwd === "delete") {
    deleteVaultPwd(host);
    return;
  }

  if (pwd.trim() === "") {
    alert("Password not stored.");
    return;
  }

  encryptAndStoreVaultPwd(pwd, host);
}

async function encryptAndStoreVaultPwd(plainPwd, host) {
  const masterPwd = document.getElementById("m-pass")?.value;
  if (!masterPwd) {
    alert("Please enter Master Password first.");
    return;
  }

  try {
    const salt = await wiseHash(masterPwd, host);
    const ciphertext = await keyEncrypt(plainPwd, salt);

    await setVaultPwd(host, ciphertext);
    alert("Password stored.");

    fillPasswordOnPage(plainPwd);
  } catch (e) {
    console.error("Vault encrypt error:", e);
  }

  await updateVaultStatus();
}

async function deleteVaultPwd(host) {
  await setVaultPwd(host, null);
  alert("Stored password deleted.");

  await updateVaultStatus();
}

async function updateVaultStatus() {
  const statusEl = document.getElementById("synth-status");

  if (!statusEl || !currentHost) return;

  const stored = await getVaultPwd(currentHost);

  if (stored) {
    statusEl.textContent = "Stored password available.";
  } else {
    statusEl.textContent = ""; // Clear if none
  }
}