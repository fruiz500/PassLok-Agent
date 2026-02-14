// ===== PASSLOK AND PASSWORD DETECTION AGENT (LEAN VERSION) =====

// ---- Helper: Get registered domain ----
function getRegisteredDomain(hostname) {
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname;
  const tld = parts[parts.length - 1];
  const exceptions = ["ai", "io", "me", "tv", "cc", "fm", "am"];
  if (tld.length === 2 && !exceptions.includes(tld)) {
    return parts.slice(parts.length - 3).join(".");
  }
  return parts.slice(parts.length - 2).join(".");
}

// ---- Main detection function ----
function scanPage() {
  // 1. Password Detection
  const passwordFields = document.querySelectorAll("input[type='password']");
  const passwordCount = passwordFields.length;

  // 2. Simplified Crypto Detection (Boolean only)
  const bodyText = document.body ? document.body.innerText : "";
  const hasCrypto = bodyText.includes("//////") || /[ASg][A-Za-z0-9+/]{50,}/.test(bodyText);

  // 3. Large Input Detection
  const hasLargeInputField = checkForLargeInputFields();

  const state = {
    hasPasswords: passwordCount > 0,
    passwordCount,
    hasCrypto,
    hasLargeInputField,
    host: getRegisteredDomain(window.location.hostname),
  };

  try {
    if (chrome.runtime?.id) {
      chrome.runtime.sendMessage({ type: "STATE_UPDATE", state });
    } else if (observer) {
      observer.disconnect();
    }
  } catch (e) {
    if (observer) observer.disconnect();
  }
}

// ---- Large Input Detection ----
let autoTargetInput = null;
function checkForLargeInputFields() {
  const candidates = document.querySelectorAll('textarea, [contenteditable]');
  for (const el of candidates) {
    if (el.tagName !== 'TEXTAREA' && !el.isContentEditable) continue;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') continue;
    if (el.offsetWidth > 100 && el.offsetHeight > 50) {
      autoTargetInput = el;
      return true;
    }
  }
  return false;
}

// ---- Message Listener ----
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!chrome.runtime?.id) return;

  if (request.type === "GET_CURRENT_STATE") {
    scanPage(); // This will trigger a STATE_UPDATE message
    return true;
  }

  if (request.type === "FILL_PASSWORD") {
    const pwd = request.password;
    document.querySelectorAll('input[type="password"]').forEach(field => {
      field.value = pwd;
      ['input', 'change', 'keydown', 'keyup'].forEach(ev => field.dispatchEvent(new Event(ev, { bubbles: true })));
      // Fallback for frameworks
      setTimeout(() => { field.value = pwd; field.dispatchEvent(new Event('input', { bubbles: true })); }, 200);
    });
  }

  if (request.type === "INSERT_ENCRYPTED_TEXT") {
    const target = autoTargetInput || document.activeElement;
    if (target && (target.tagName === 'TEXTAREA' || target.isContentEditable)) {
      insertTextAtTarget(target, request.text);
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false });
    }
    return true;
  }
});

// ---- Text Insertion Helper ----
function insertTextAtTarget(target, text) {
  target.focus();
  if (target.tagName === 'TEXTAREA') {
    const start = target.selectionStart;
    const end = target.selectionEnd;
    target.value = target.value.substring(0, start) + text + target.value.substring(end);
  } else {
    const selection = window.getSelection();
    const range = (selection.rangeCount && target.contains(selection.anchorNode)) 
      ? selection.getRangeAt(0) 
      : document.createRange();
    if (!selection.rangeCount || !target.contains(selection.anchorNode)) {
      range.selectNodeContents(target);
      range.collapse(false);
    }
    range.deleteContents();
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = text;
    const fragment = document.createDocumentFragment();
    while (tempDiv.firstChild) fragment.appendChild(tempDiv.firstChild);
    range.insertNode(fragment);
    selection.removeAllRanges();
    selection.addRange(range);
    selection.collapseToEnd();
  }
  target.dispatchEvent(new Event('input', { bubbles: true }));
}

// ---- Click-to-Load Logic ----
document.addEventListener("click", (e) => {
  if (e.target.tagName === "BUTTON" || e.target.tagName === "INPUT") return;
  const blob = getSelectedBlob();
  if (blob) chrome.runtime.sendMessage({ type: "BLOB_CLICKED", blob });
}, true);

function getSelectedBlob() {
  const sel = window.getSelection();
  let text = sel.toString().trim();
  
  // If no selection, find blob near cursor
  if (!text) {
    if (sel.rangeCount === 0) return null;
    const range = sel.getRangeAt(0);
    let el = range.commonAncestorContainer.nodeType === Node.TEXT_NODE ? range.commonAncestorContainer.parentElement : range.commonAncestorContainer;
    while (el && el.innerText?.length < 200) el = el.parentElement;
    if (!el) return null;
    text = el.innerText || el.textContent || "";
  }

  const clean = text.replace(/[\s\r\n]/g, "");
  // Strategy 1: //////
  const slashMatch = clean.match(/[0-9a-km-zL]{50}\/\/\/\/\/\/[A-Za-z0-9+/]+/);
  if (slashMatch) return { type: "MESSAGE", raw: slashMatch[0], hasLock: true };

  // Strategy 2: Visual Blob
  const blobMatch = clean.match(/[ASg][A-Za-z0-9+/]{100,}/);
  if (blobMatch) return { type: "MESSAGE", raw: blobMatch[0], hasLock: false };

  return null;
}

// ---- Observers and Initialization ----
let scanTimeout = null;
let observer = new MutationObserver(() => {
  if (scanTimeout) clearTimeout(scanTimeout);
  scanTimeout = setTimeout(scanPage, 150);
});
observer.observe(document.body, { childList: true, subtree: true });

document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") scanPage(); });
scanPage();