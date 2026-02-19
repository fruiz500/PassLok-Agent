//code for editing the directory entries (synth and locDir) in sync storage

let currentMode = "synth";        //initial mode (can be 'synth' or 'locDir')
let currentHost = "";
let masterPasswordContext = null; // 'synth', 'decrypt', or 'notes'

function setHost(host) {
  currentHost = host;
}

function setMode(mode) {
  currentMode = mode;
  updateInputLabels();
}

// Update input placeholders based on mode

function updateInputLabels() {
  const nameInput = document.getElementById("new-lock-name");
  const valueInput = document.getElementById("new-lock-value");
  if (!nameInput || !valueInput) return;

  if (currentMode === "synth") {
    nameInput.placeholder = "Name (e.g. Alice)";
    valueInput.placeholder = "Lock (Public Key)";
  } else {
    nameInput.placeholder = "Name/Email";
    valueInput.placeholder = "Value";
  }
}

// Render Directory Entries (Exclusively for locDir)
let lastRenderTime = 0;

async function renderDirectory() {
  // Debounce rapid calls
  const now = Date.now();
  if (now - lastRenderTime < 500) {
    return;
  }
  lastRenderTime = now;

  const container = document.getElementById("directory-list");
  if (!container) return;

  container.innerHTML =
    '<div style="padding: 10px; text-align: center;">Loading...</div>';
  updateInputLabels();

  // 1. Load Global Directory (locDir) - This is the only source for editing
  const globalData = await chrome.storage.sync.get(["locDir"]);
  let directory = globalData.locDir || {};

  // 2. Include "(Me)" entry from site-specific crypt data
  if (currentHost) {
    const hostData = await chrome.storage.sync.get([currentHost]);
    const crypt = (hostData[currentHost] || {}).crypt;
    if (crypt && crypt.email) {
      directory["(Me) " + crypt.email] = crypt.lock || "No Lock";
    }
  }

  // 3. Clear and Render
  container.innerHTML = "";
  const entries = Object.entries(directory).filter(
    ([name]) => name && name !== "null"
  );

  if (entries.length === 0) {
    container.innerHTML =
      '<div style="padding: 10px; color: #666;">No entries found.</div>';
    return;
  }

  entries.forEach(([name, value]) => {
    const item = document.createElement("div");
    item.style =
      "display: flex; justify-content: space-between; align-items: center; padding: 8px; border-bottom: 1px solid #eee; font-size: 12px;";

    // locDir values are arrays [lock]
    const displayValue = Array.isArray(value) ? value[0] : value;
    const previewText =
      typeof displayValue === "string"
        ? displayValue
        : JSON.stringify(displayValue);

    item.innerHTML = `
      <div style="flex: 1; overflow: hidden; text-overflow: ellipsis; margin-right: 10px;">
        <strong>${name}</strong><br>
        <span style="color: #666; font-family: monospace; font-size: 10px;">${previewText}</span>
      </div>
      <div style="display: flex; gap: 5px;">
        <button class="edit-entry" data-name="${name}" data-value='${JSON.stringify(value)}' style="padding: 2px 5px; cursor: pointer;">Edit</button>
        <button class="delete-entry" data-name="${name}" style="padding: 2px 5px; cursor: pointer; color: red;">Del</button>
      </div>
    `;
    container.appendChild(item);
  });

  // 4. Delete Logic
  container.querySelectorAll(".delete-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const name = e.target.dataset.name;
      if (!confirm(`Remove ${name} from directory?`)) return;

      // Always delete from locDir (except for "(Me)")
      if (name.startsWith("(Me) ")) {
        const d = await chrome.storage.sync.get([currentHost]);
        if (d[currentHost]?.crypt) {
          delete d[currentHost].crypt;
          await chrome.storage.sync.set({ [currentHost]: d[currentHost] });
        }
      } else {
        const d = await chrome.storage.sync.get(["locDir"]);
        let locDir = d.locDir || {};
        delete locDir[name];
        await chrome.storage.sync.set({ locDir });
      }
      renderDirectory();
    });
  });

  // 5. Edit Logic (Update Value Only)
  container.querySelectorAll(".edit-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const name = e.target.dataset.name;
      let rawValue = JSON.parse(e.target.dataset.value);
      const currentValue = Array.isArray(rawValue) ? rawValue[0] : rawValue;

      const newValue = prompt(`Update Lock for ${name}:`, currentValue);
      if (newValue === null || newValue === currentValue) return;

      // Always edit in locDir (except for "(Me)")
      if (name.startsWith("(Me) ")) {
        const d = await chrome.storage.sync.get([currentHost]);
        if (d[currentHost]?.crypt) {
          d[currentHost].crypt.lock = newValue;
          await chrome.storage.sync.set({ [currentHost]: d[currentHost] });
        }
      } else {
        const d = await chrome.storage.sync.get(["locDir"]);
        let locDir = d.locDir || {};
        locDir[name] = [newValue]; // Maintain array structure
        await chrome.storage.sync.set({ locDir });
      }
      renderDirectory();
    });
  });
}

// Add Entry Logic
document.getElementById("add-to-directory").addEventListener("click", async () => {
  const name = document.getElementById("new-lock-name").value.trim();
  const value = document.getElementById("new-lock-value").value.trim();
  if (!name || !value) return;

  if (currentMode === "synth") {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    hostData.synth = hostData.synth || {};
    hostData.synth[name] = value;
    await chrome.storage.sync.set({ [currentHost]: hostData });
  } else {
    const data = await chrome.storage.sync.get(["locDir"]);
    const locDir = data.locDir || {};
    locDir[name] = [value];
    await chrome.storage.sync.set({ locDir });
  }

  document.getElementById("new-lock-name").value = "";
  document.getElementById("new-lock-value").value = "";
  renderDirectory();
});

// Listen for close event
window.addEventListener("closeDirectory", () => {
  // Ensure directory card is hidden (redundant but safe)
  const dirCard = document.getElementById('directory-card');
  if (dirCard) dirCard.classList.add('hidden');

  // If we're in manual file mode, ensure the crypto UI is visible
  if (window.isManualForThisTab) {
    const cryptoCard = document.getElementById('card-crypto');
    if (cryptoCard) {
      cryptoCard.classList.remove('hidden');
      // Re-run updateUI to ensure all elements are in the right state
      setTimeout(() => updateUI(lastState), 0);
    }
  } else {
    // Normal state restoration
    updateUI(lastState);
  }
});

// 1. Define the variable outside the object
let previousVisibleCards = [];

window.DirectoryEditor = {
  renderDirectory,
  setMode,
  setHost,
  // In directory_editor.js
  open: () => {
    const cards = document.querySelectorAll(".card");
    previousVisibleCards = [];
    cards.forEach((card) => {
      // Check if it's visible (not hidden)
      if (window.getComputedStyle(card).display !== "none" && !card.classList.contains("hidden")) {
        previousVisibleCards.push(card.id);
      }
      card.classList.add("hidden");
    });

    const masterSection = document.getElementById("master-password-section");
    if (masterSection && !masterSection.classList.contains("hidden")) {
      previousVisibleCards.push("master-password-section");
    }
    if (masterSection) masterSection.classList.add("hidden");

    document.getElementById("directory-card").classList.remove("hidden");
    renderDirectory();
  },

  close: () => {
    document.getElementById("directory-card").classList.add("hidden");

    previousVisibleCards.forEach((id) => {
      const el = document.getElementById(id);
      if (el) {
        el.classList.remove("hidden");
      }
    });

    window.dispatchEvent(new CustomEvent("closeDirectory"));
  },
};

// For debugging: Display all sync storage in console
function displaySync() {
  chrome.storage.sync.get(null, (items) => {
    chrome.storage.sync.get(null, (items) => {
      console.log('All sync storage:', items);
    });
  });
}

window.displaySync = displaySync;