// sidepanel_stego.js

document.addEventListener('DOMContentLoaded', () => {
    const stegoToggle = document.getElementById('stegoModeToggle');
    const stegoContainer = document.getElementById('stego-image-container');
    const stegoPreview = document.getElementById('stego-image-preview');
    const stegoPlaceholder = document.getElementById('stego-placeholder');
    const stegoCapacity = document.getElementById('stego-capacity-display');
    const stegoCapacityValue = document.getElementById('stego-capacity-value');
    const stegoActions = document.getElementById('stego-actions');

    if (stegoActions) {
        stegoActions.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation(); // Prevent click from bubbling to image container
            });
        });
    }

    // 1. Toggle Visibility
    // Inside the stegoToggle event listener:
    stegoToggle.addEventListener('change', () => {
        const composeBox = document.getElementById('composeBox');
        const toolBar = document.getElementById('toolBar');

        if (stegoToggle.checked) {
            // Checkbox no longer touches stegoContainer or stegoActions
            if (composeBox) composeBox.classList.remove('hidden');
            if (toolBar) toolBar.classList.remove('hidden');
            if (composeBox) composeBox.focus();
        } else {
            // Checkbox no longer touches stegoContainer or stegoActions
            const needsCompose = lastState && (lastState.hasLargeInputField || lastState.hasCrypto);
            if (!needsCompose) {
                if (composeBox) composeBox.classList.add('hidden');
                if (toolBar) toolBar.classList.add('hidden');
            }
        }
    });

    // 2. Image Loading Logic
    stegoContainer.addEventListener('click', () => {
        // Unhide compose box and toolbar on click
        const composeBox = document.getElementById('composeBox');
        const toolBar = document.getElementById('toolBar');
        if (composeBox) composeBox.classList.remove('hidden');
        if (toolBar) toolBar.classList.remove('hidden');
        if (composeBox) composeBox.focus();

        //image input logic
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/png, image/jpeg';
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (event) => {
                const dataUrl = event.target.result;
                stegoPreview.src = dataUrl;
                stegoPreview.style.display = 'block';
                stegoPlaceholder.style.display = 'none';

                stegoPreview.onload = () => {
                    const isPng = dataUrl.startsWith('data:image/png');
                    updateStegoCapacity(stegoPreview, isPng);
                };
            };
            reader.readAsDataURL(file);
        };
        input.click();
    });

    // 3. Capacity Estimation
    function updateStegoCapacity(img, isPng) {
        const totalPixels = img.naturalWidth * img.naturalHeight;
        let bytes;

        if (isPng) {
            // PNG: 3 bits per pixel (LSB in R, G, B)
            bytes = Math.floor((totalPixels * 3) / 8);
        } else {
            // JPEG (F5): Highly variable, but 10% of pixels is a safe "improved F5" estimate
            bytes = Math.floor(totalPixels * 0.1);
        }

        // Subtract overhead for EOF marker (48 bits = 6 bytes)
        bytes = Math.max(0, bytes - 6);

        stegoCapacityValue.textContent = bytes.toLocaleString();
        stegoCapacity.classList.remove('hidden');

        if (stegoActions) {
            stegoActions.classList.remove('hidden');
            stegoActions.style.display = 'flex'; // Ensure it uses the flex layout
        }
    }
});

// Helper: Convert Uint8Array to bit array (0/1)
function bytesToBits(bytes) {
    let bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let j = 7; j >= 0; j--) {
            bits.push((bytes[i] >> j) & 1);
        }
    }
    return bits;
}

// Helper: Convert bit array (0/1) to Uint8Array
function bitsToBytes(bits) {
    let bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            if (bits[i * 8 + j]) byte |= (1 << (7 - j));
        }
        bytes[i] = byte;
    }
    return bytes;
}

// --- Button Listeners ---


/**
 * Handles steganographic encryption for a given format (PNG/JPG).
 * @param {string} format - 'PNG' or 'JPG'
 */
async function handleStegoEncrypt(isPng) {
    const imgPreview = document.getElementById('stego-image-preview');
    if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
        alert("Please load a cover image first.");
        return;
    }

    // 1. Get inputs using the unified Folder Key aware function
    const inputs = await getStegoEncryptionInputs();
    if (!inputs) {
        console.log("Stego encryption cancelled or failed to get inputs.");
        return;
    }

    // 2. Determine if we should skip internal randomization
    // This flag is set in sidepanel_encrypt.js when bridging a PassLok message
    const skipEncrypt = !!window.isStegoPayloadEncrypted;
    console.log(`Stego payload is encrypted: ${skipEncrypt}`);
    delete window.isStegoPayloadEncrypted; // Clean up immediately

    try {
        const encodeFunction = isPng ? encodePNG : encodeJPG;
        const formatName = isPng ? 'PNG' : 'JPG';

        const resultURI = await encodeFunction({
            image: imgPreview,
            data: inputs.data1,
            password: inputs.pwd1,
            skipEncrypt: skipEncrypt, // Correctly set based on payload type
            iterations: 1, // Safe because password is pre-stretched
            data2: inputs.data2,
            password2: inputs.pwd2,
            iterations2: inputs.pwd2 ? 1 : 0 // Only iterate if pwd2 exists
        });

        imgPreview.src = resultURI;
        //        alert(`${formatName} updated with hidden data.`);
    } catch (error) {
        console.error("Stego Encryption Error:", error);
        alert("Stego error: " + error.message);
    }
}

// Convert a UTF-8 string to a bit array (0/1) using nacl.util
function textToBits(str) {
    const uint8Array = new TextEncoder().encode(str);
    return bytesToBits(uint8Array);
}

// Convert a bit array (0/1) back to a UTF-8 string using nacl.util
function bitsToText(bits) {
    const uint8Array = bitsToBytes(bits);
    return new TextDecoder().decode(uint8Array);
}

// Base64 encoding helper
function getStegoSecret(label) {
    if (window.activeFolderKey) {
        console.log(`Using active Folder Key for ${label}`);
        // Stretch the folder key with a salt to ensure it's a unique stego key
        const stretchedKey = wiseHash(encodeBase64(window.activeFolderKey), "stego-salt");
        return encodeBase64(stretchedKey);
    }

    const rawPwd = prompt(`Enter stego password for ${label}:`);
    if (!rawPwd) return null;

    console.log(`Stretching manual stego password for ${label}`);
    const stretchedKey = wiseHash(rawPwd, "stego-salt");
    return encodeBase64(stretchedKey);
}

// Unified, deterministic key derivation
function deriveStegoKey(rawInput, isSecondary = false) {
    const salt = isSecondary ? "PASSLOK_STEGO_SECONDARY" : "PASSLOK_STEGO_PRIMARY";
    console.log(`Derive key - Input: ${rawInput.substring(0, 10)}..., Salt: ${salt}`);
    const stretched = wiseHash(rawInput, salt);
    return encodeBase64(stretched);
}

// Unified helper to get the final stretched password
function getFinalStegoPassword(label, isSecondary = false) {
    // These MUST be identical in both encryption and decryption
    const salt = isSecondary ? "PASSLOK_STEGO_SECONDARY" : "PASSLOK_STEGO_PRIMARY";
    
    let rawInput;
    // Only automate the PRIMARY message if a folder is active
    if (window.activeFolderKey && !isSecondary) {
        rawInput = encodeBase64(window.activeFolderKey);
    } else {
        rawInput = prompt(`Enter stego password for ${label}:`);
    }

    if (!rawInput) return null;

    // Log these to the console to verify they match during test
    console.log(`Stego Key Derivation - Label: ${label}, Salt: ${salt}, Input (first 5): ${rawInput.substring(0,5)}`);
    
    const stretched = wiseHash(rawInput, salt);
    return encodeBase64(stretched);
}

/**
 * Gathers user input for steganographic encryption.
 * @returns {Promise<{data1: Uint8Array, pwd1: string, data2: Uint8Array|null, pwd2: string|null} | null>}
 */
async function getStegoEncryptionInputs() {
    if (window.pendingStegoBin) {
        const data1 = window.pendingStegoBin;
        delete window.pendingStegoBin;

        // Silent flow: Use Folder Key if available, otherwise prompt
        const pwd1 = getFinalStegoPassword('bridged encrypted message');
        if (!pwd1) return null; // User canceled manual prompt

        return { data1, pwd1, data2: null, pwd2: null };
    }

    if (window.pendingStegoText) {
        const plainText = window.pendingStegoText;
        delete window.pendingStegoText;

        const data1 = new TextEncoder().encode(plainText);
        const pwd1 = getFinalStegoPassword('bridged plain message');
        if (!pwd1) return null;

        return { data1, pwd1, data2: null, pwd2: null };
    }

    // Manual input path
    const payloadInput = prompt('Enter text to embed (use | for second message):');
    if (!payloadInput) return null;

    const payload = payloadInput.trim();
    if (payload === "") return null;

    // Get primary password (silent if Folder Key, prompt if not)
    const pwd1 = getFinalStegoPassword('primary message');
    if (!pwd1) return null;

    // Split for dual-message support
    const payloadParts = payload.split('|').map(p => p.trim());

    const data1 = new TextEncoder().encode(payloadParts[0]);

    let data2 = null;
    let pwd2 = null;

    // Handle secondary message if it exists
    if (payloadParts.length > 1 && payloadParts[1] !== "") {
        pwd2 = getFinalStegoPassword('secondary message', true);
        if (pwd2) {
            data2 = new TextEncoder().encode(payloadParts[1]);
        }
        // If user cancels secondary password prompt, we proceed with single message
    }

    return { data1, pwd1, data2, pwd2 };
}

/**
 * Gathers user input for steganographic decryption.
 * @returns {{pwd1: string, pwd2: string|null} | null}
 */
function getStegoDecryptionPasswords() {
    const passwordInput = prompt("Enter stego password(s) (use | for second password):");
    if (!passwordInput) return null; // User canceled

    const passwords = passwordInput.trim();
    if (passwords === "") return null; // Empty input

    const passwordParts = passwords.split('|').map(p => p.trim());
    const pwd1 = passwordParts[0];
    const pwd2 = (passwordParts.length > 1 && passwordParts[1] !== "") ? passwordParts[1] : null;

    return { pwd1, pwd2 };
}

document.addEventListener('DOMContentLoaded', () => {
    const imgPreview = document.getElementById('stego-image-preview');

    // Encrypt PNG Button
    document.getElementById('stego-encrypt-png').addEventListener('click', async () => {
        const imgPreview = document.getElementById('stego-image-preview');
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            alert('Please load a cover image first.');
            return;
        }

        const inputs = await getStegoEncryptionInputs();
        if (!inputs) return; // User canceled or invalid input

        try {
            const resultURI = await encodePNG({
                image: imgPreview,
                data: inputs.data1,
                password: inputs.pwd1,
                iterations: 1,
                data2: inputs.data2,
                password2: inputs.pwd2,
                iterations2: 1
            });

            imgPreview.src = resultURI;
            const statusMsg = inputs.pwd2 ? "Dual messages embedded successfully." : "Primary message embedded successfully.";
            alert(statusMsg);
        } catch (error) {
            alert('PNG stego embedding failed: ' + error.message);
        }
    });

    // Encrypt JPG Button
    document.getElementById('stego-encrypt-jpg').addEventListener('click', async () => {
        const imgPreview = document.getElementById('stego-image-preview');
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            alert('Please load a cover image first.');
            return;
        }

        const inputs = await getStegoEncryptionInputs();
        if (!inputs) return; // User canceled or invalid input

        try {
            const resultURI = await encodeJPG({
                image: imgPreview,
                data: inputs.data1,
                password: inputs.pwd1,
                skipEncrypt: false,
                iterations: 1,
                data2: inputs.data2,
                password2: inputs.pwd2,
                iterations2: 1
            });

            imgPreview.src = resultURI;
            const statusMsg = inputs.pwd2 ? "Dual messages embedded successfully." : "Primary message embedded successfully.";
            alert(statusMsg);
        } catch (error) {
            alert('JPG stego embedding failed: ' + error.message);
        }
    });

    // Extract and Decrypt Button
    // Extract and Decrypt Button
    document.getElementById('stego-decrypt-btn').addEventListener('click', async () => {
        const imgPreview = document.getElementById('stego-image-preview');
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            alert("Please load a stego image first.");
            return;
        }

        //        const passwords = getStegoDecryptionPasswords();

        //        if (!passwords) return; // User canceled or invalid input

//        let pwd1, pwd2 = null;

        // 1. Get Primary Key (Silent if folder active, prompt if not)
    const pwd1 = getFinalStegoPassword("primary message", false);
    if (!pwd1) return;

    // 2. Optional Secondary Key
    let pwd2 = null;
    if (confirm("Check for secondary hidden message?")) {
        pwd2 = getFinalStegoPassword("secondary message", true);
    }

        try {
            //            const isUsingFolderKey = !!window.activeFolderKey;
            //            const skipEncrypt = isUsingFolderKey || window.isStegoOnlyWithFolderKey;

            const result = await decodeImage({
                image: imgPreview,
                password: pwd1,
                skipEncrypt: false,
                iterations: 1, // Safe because password is already strong
                password2: pwd2,
                iterations2: 1
            });

            // Clean up the flag
            delete window.isStegoOnlyWithFolderKey;

            let outputText = "";

            // Process primary
            if (result.primary && result.primary.length > 0) {
                const data = result.primary;
                const firstByte = data[0];

                // Recognized PassLok Type Bytes: 0, 72, 56, 128
                const passlokMarkers = [0, 72, 56, 128];
                const isPassLokBinary = passlokMarkers.includes(firstByte);

                if (isPassLokBinary) {
                    console.log("PassLok binary detected (Type Byte: " + firstByte + "). Triggering decryption.");

                    const masterPwd = document.getElementById("m-pass").value;
                    const myEmail = document.getElementById("user-email").value;

                    if (!masterPwd || !myEmail) {
                        // Fallback: show armored version if credentials missing
                        const armored = encodeBase64(data);
                        const composeBox = document.getElementById('composeBox');
                        if (composeBox) composeBox.value = armored;
                        alert("PassLok message extracted. Please enter your Email and Master Password, then click Decrypt.");
                        return;
                    }

                    if (typeof continueDecrypt === 'function') {
                        continueDecrypt(data, masterPwd, myEmail);
                    }
                    return; // Exit after handling PassLok binary
                } else if (firstByte === 103) {
                    // Stego-Only mode: Strip byte 103 and decode as UTF-8
                    try {
                        const plainText = new TextDecoder().decode(data.subarray(1));
                        const composeBox = document.getElementById('composeBox');
                        if (composeBox) {
                            // Use innerHTML or value depending on your composeBox type
                            if (composeBox.tagName === 'DIV') composeBox.innerHTML = plainText;
                            else composeBox.value = plainText;
                        }
                        return; // Exit after handling Stego-Only message
                    } catch (e) {
                        console.error("Failed to decode Stego-Only message:", e);
                    }
                } else {
                    // Fallback for plain text (no marker)
                    try {
                        const outputText = new TextDecoder().decode(data);
                        const composeBox = document.getElementById('composeBox');
                        if (composeBox) {
                            if (composeBox.tagName === 'DIV') composeBox.innerHTML = outputText;
                            else composeBox.value = outputText;
                        }
                        return; // Exit after handling plain text
                    } catch (e) {
                        console.log("Extracted data is binary but not a recognized type.");
                    }
                }
            }

            // Process secondary only if a second password was provided
            if (passwords.pwd2 && result.secondary && result.secondary.length > 0) {
                const text2 = new TextDecoder().decode(result.secondary);
                outputText += "|" + text2;
            }

            if (outputText) {
                alert("Extracted text:\n\n" + outputText);
                const composeBox = document.getElementById('composeBox');
                if (composeBox) composeBox.value = outputText;
            } else {
                alert("No hidden data found or incorrect password(s).");
            }
        } catch (e) {
            console.error("Stego Decryption Error:", e);
            alert("Failed to extract: " + e.message);
        }
    });
});
