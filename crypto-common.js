/**
 * Core Crypto Utilities
 * Moved from legacy keylock.js to support standalone Agent functionality.
 */

//Alphabets for base conversion. Used in making and reading the ezLock format
const base36 = "0123456789abcdefghijkLmnopqrstuvwxyz"; //capital L so it won't be mistaken for 1
const base64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//function to test key strength and come up with appropriate key stretching. Based on WiseHash
function keyStrength(string) {
  var entropy = entropyCalc(string),
    msg,
    colorName;

  if (entropy == 0) {
    msg = "This is a known bad Password!";
    colorName = "magenta";
  } else if (entropy < 20) {
    msg = "Terrible!";
    colorName = "magenta";
  } else if (entropy < 40) {
    msg = "Weak!";
    colorName = "red";
  } else if (entropy < 60) {
    msg = "Medium";
    colorName = "darkorange";
  } else if (entropy < 90) {
    msg = "Good!";
    colorName = "green";
  } else if (entropy < 120) {
    msg = "Great!";
    colorName = "blue";
  } else {
    msg = "Overkill  !!";
    colorName = "cyan";
  }

  var iter = Math.max(1, Math.min(20, Math.ceil(24 - entropy / 5))); //set the scrypt iteration exponent based on entropy: 1 for entropy >= 120, 20(max) for entropy <= 20

  return iter;
}

//takes a string and calculates its entropy in bits, taking into account the kinds of characters used and parts that may be in the general wordlist (reduced credit) or the blacklist (no credit)
function entropyCalc(string) {
  //find the raw Keyspace
  var numberRegex = new RegExp("^(?=.*[0-9]).*$", "g");
  var smallRegex = new RegExp("^(?=.*[a-z]).*$", "g");
  var capRegex = new RegExp("^(?=.*[A-Z]).*$", "g");
  var base64Regex = new RegExp("^(?=.*[/+]).*$", "g");
  var otherRegex = new RegExp("^(?=.*[^a-zA-Z0-9/+]).*$", "g");

  string = string.replace(/\s/g, ""); //no credit for spaces

  var Ncount = 0;
  if (numberRegex.test(string)) {
    Ncount = Ncount + 10;
  }
  if (smallRegex.test(string)) {
    Ncount = Ncount + 26;
  }
  if (capRegex.test(string)) {
    Ncount = Ncount + 26;
  }
  if (base64Regex.test(string)) {
    Ncount = Ncount + 2;
  }
  if (otherRegex.test(string)) {
    Ncount = Ncount + 31; //assume only printable characters
  }

  //start by finding words that might be on the blacklist (no credit)
  string = reduceVariants(string);
  var wordsFound = string.match(blackListExp); //array containing words found on the blacklist
  if (wordsFound) {
    for (var i = 0; i < wordsFound.length; i++) {
      string = string.replace(wordsFound[i], ""); //remove them from the string
    }
  }

  //now look for regular words on the wordlist
  wordsFound = string.match(wordListExp); //array containing words found on the regular wordlist
  if (wordsFound) {
    wordsFound = wordsFound.filter(function (elem, pos, self) {
      return self.indexOf(elem) == pos;
    }); //remove duplicates from the list
    var foundLength = wordsFound.length; //to give credit for words found we need to count how many
    for (var i = 0; i < wordsFound.length; i++) {
      string = string.replace(new RegExp(wordsFound[i], "g"), ""); //remove all instances
    }
  } else {
    var foundLength = 0;
  }

  string = string.replace(/(.+?)\1+/g, "$1"); //no credit for repeated consecutive character groups

  if (string != "") {
    return (
      (string.length * Math.log(Ncount) +
        foundLength * Math.log(wordLength + blackLength)) /
      Math.LN2
    );
  } else {
    return (foundLength * Math.log(wordLength + blackLength)) / Math.LN2;
  }
}

//take into account common substitutions, ignore spaces and case
function reduceVariants(string) {
  return string
    .toLowerCase()
    .replace(/[óòöôõo]/g, "0")
    .replace(/[!íìïîi]/g, "1")
    .replace(/[z]/g, "2")
    .replace(/[éèëêe]/g, "3")
    .replace(/[@áàäâãa]/g, "4")
    .replace(/[$s]/g, "5")
    .replace(/[t]/g, "7")
    .replace(/[b]/g, "8")
    .replace(/[g]/g, "9")
    .replace(/[úùüû]/g, "u");
}

const vowel = "aeiou";
const consonant = "bcdfghjklmnprstvwxyz";

//makes 'pronounceable' hash of a string, so user can be sure the password was entered correctly
function makeHashili(str) {
  const s = str.trim();
  if (!s) return "";

  const fullHash = nacl.hash(nacl.util.decodeUTF8(s));
  const code = fullHash.slice(-2);
  let code10 = ((code[0] << 8) + code[1]) % 10000;

  let output = "";
  for (let i = 0; i < 2; i++) {
    const remainder = code10 % 100;
    output += consonant[Math.floor(remainder / 5)] + vowel[remainder % 5];
    code10 = Math.floor(code10 / 100);
  }
  return output; // e.g. "lomu"
}

//stretches a password string with a salt string to make a 256-bit Uint8Array Password
function wiseHash(string, salt) {
  var iter = keyStrength(string),
    secArray = new Uint8Array(32),
    keyBytes;
  //	if(salt.length == 43) iter = 1;								//random salt: no extra stretching needed
  scrypt(string, salt, iter, 8, 32, 0, function (x) {
    keyBytes = x;
  });
  for (var i = 0; i < 32; i++) {
    secArray[i] = keyBytes[i];
  }
  return secArray;
}

//makes a full 24-byte nonce from a short nonce (e.g. 16 bytes). Returns Uint8Array
function makeNonce24(shortNonce) {
  // Standard PassLok helper to pad a short nonce to 24 bytes for NaCl
  const fullNonce = new Uint8Array(24);
  fullNonce.set(shortNonce);
  return fullNonce;
}

//makes the DH public string of a DH secret key array. Returns a base64 string
function makePub(sec) {
  return (pub = nacl.box.keyPair.fromSecretKey(sec).publicKey);
}

//Diffie-Hellman combination of a DH public key array and a DH secret key array. Returns Uint8Array
function makeShared(pub, sec) {
  return nacl.box.before(pub, sec);
}

//makes the DH public key (Montgomery) from a published Lock, which is a Signing public key (Edwards)
function convertPubStr(Lock) {
  var LockBin = nacl.util.decodeBase64(Lock);
  if (!LockBin) return false;
  return ed2curve.convertPublicKey(LockBin);
}

// Symmetric encryption with optional LZ compression
// Returns Uint8Array ciphertext
function symEncrypt(plainstr, nonce24, symKey, isCompressed) {
  let plain;
  
  // Skip compression if data contains embedded files (data URIs)
  if (!isCompressed || plainstr.match('="data:')) {
    plain = nacl.util.decodeUTF8(plainstr);
  } else {
    plain = LZString.compressToUint8Array(plainstr);
  }
  
  return nacl.secretbox(plain, nonce24, symKey);
}

//concatenates multiple Uint8Arrays into one. Input: array of Uint8Arrays. Output: single Uint8Array
function concatUi8(arrays) {
  let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);
  let result = new Uint8Array(totalLength);
  let length = 0;
  for (let array of arrays) {
    result.set(array, length);
    length += array.length;
  }
  return result;
}

// Implements PassLok k-mode (Symmetric Encryption)

function keyEncrypt(plaintext, key) {
  const nonce = nacl.randomBytes(24);
  const msgUint8 = nacl.util.decodeUTF8(plaintext);
  const box = nacl.secretbox(msgUint8, nonce, key);

  const fullMessage = new Uint8Array(1 + nonce.length + box.length);
  fullMessage[0] = 144; // PassLok k-mode marker
  fullMessage.set(nonce, 1);
  fullMessage.set(box, 1 + nonce.length);

  return nacl.util.encodeBase64(fullMessage);
}

function keyDecrypt(ciphertextBase64, key) {
  const fullMessage = nacl.util.decodeBase64(ciphertextBase64);

  if (fullMessage[0] !== 144) {
    throw new Error("Not a valid k-mode message (marker 144 missing)");
  }

  const nonce = fullMessage.slice(1, 25);
  const box = fullMessage.slice(25);

  const decrypted = nacl.secretbox.open(box, nonce, key);
  if (!decrypted) {
    throw new Error("Decryption failed (wrong key or corrupted data)");
  }

  return nacl.util.encodeUTF8(decrypted);
}

//changes the base of a number. inAlpha and outAlpha are strings containing the base code for the original and target bases, as in '0123456789' for decimal
//adapted from http://snippetrepo.com/snippets/bignum-base-conversion, by kybernetikos

function changeBase(numberIn, inAlpha, outAlpha, isLock) {
  // 1. Setup bases
  const baseIn = BigInt(inAlpha.length);
  const baseOut = BigInt(outAlpha.length);
  let value = BigInt(0);

  // 2. Convert input string to a BigInt value
  for (let i = 0; i < numberIn.length; i++) {
    const index = inAlpha.indexOf(numberIn[i]);
    if (index === -1) continue; // Skip characters not in alphabet (like newlines or padding)
    value = value * baseIn + BigInt(index);
  }

  // 3. Convert BigInt value to output string
  let result = "";
  if (value === BigInt(0)) {
    result = outAlpha[0];
  } else {
    while (value > 0) {
      result = outAlpha[Number(value % baseOut)] + result;
      value = value / baseOut;
    }
  }

  // 4. Handle PassLok Lock padding (leading zeros)
  if (isLock) {
    // PassLok standard: Base36 Locks are 50 chars, Base64 are 43 chars
    const lockLength = (baseOut === 36n) ? 50 : 43;
    while (result.length < lockLength) {
      result = outAlpha[0] + result;
    }
  }

  return result;
}

function stripPadd(str) {
  return typeof str === 'string' ? str.replace(/=/g, '') : str;
}

function reportCryptoSuccess(mode, details) {
  const mainStatus = document.getElementById('synth-status');
  const actionStatus = document.getElementById('encryptMsg');

  if (actionStatus) actionStatus.textContent = "";

  if (mainStatus) {
    mainStatus.style.color = "#2e7d32";
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    let statusText = `[${time}] `;
    
    if (mode === "decrypt") {
      // If it's SIGNED and we have a sender, show both
      const modeStr = details.type || "Message";
      const senderStr = details.senderLock ? ` from ${details.senderLock}` : "";
      
      statusText += `Decrypted ${modeStr}${senderStr} (${details.length} chars)`;
    } 
    else if (mode === "encrypt") {
      const recips = details.recipientCount > 0 
        ? ` for ${details.recipientCount} recipient(s)` 
        : "";
      statusText += `Encrypted ${details.mode}${recips}`;
    }
    
    mainStatus.textContent = statusText;
  }
}

function reportCryptoFailure(msg) {
  const mainStatus = document.getElementById('synth-status');
  const actionStatus = document.getElementById('encryptMsg');

  if (actionStatus) actionStatus.textContent = ""; // Clear "Encrypting..."

  if (mainStatus) {
    mainStatus.style.color = "#ef4444"; // Error Red
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    mainStatus.textContent = `[${time}] ERROR: ${msg}`;
  }
}

function ezLockToUint8(lockB36) {
  if (!lockB36.trim()) return null;
  // 1. Convert Base36 string to Base64 string using your changeBase
  const b64 = changeBase(lockB36.trim(), base36, base64, true);
  // 2. Convert Base64 string to Uint8Array for nacl
  return nacl.util.decodeBase64(b64);
}