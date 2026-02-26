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
    stegoToggle.addEventListener('change', () => {
        const composeBox = document.getElementById('composeBox');
        const toolBar = document.getElementById('toolBar');

        if (stegoToggle.checked) {
            stegoContainer.classList.remove('hidden');
            if (composeBox) composeBox.classList.remove('hidden');
            if (toolBar) toolBar.classList.remove('hidden');
            if (composeBox) composeBox.focus();
        } else {
            stegoContainer.classList.add('hidden');

            // Check the global lastState to see if the page context 
            // actually requires the composeBox to be visible.
            const needsCompose = lastState && (lastState.hasLargeInputField || lastState.hasCrypto);

            // If the page doesn't need it and we aren't in manual mode, hide it.
            if (!needsCompose) {
                if (composeBox) composeBox.classList.add('hidden');
                if (toolBar) toolBar.classList.add('hidden');
            }
        }
    });

    // 2. Image Loading Logic
    stegoContainer.addEventListener('click', () => {
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
async function handleStegoEncrypt(format) {
    const imgPreview = document.getElementById('stego-image-preview');

    if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
        alert("Please load a cover image first.");
        return;
    }

    // 1. Get payload
    const textToEncrypt = prompt("Enter text to embed in the image:");
    if (!textToEncrypt) return;

    // 2. Convert to Uint8Array (modern format)
    const dataArray = nacl.util.decodeUTF8(textToEncrypt);

    // 3. Get password
    const stegoPwd = prompt(`Enter stego password for ${format}:`);
    if (stegoPwd === null) return;

    try {
        if (format === 'PNG') {
            // 4. Await the modernized PNG encoding
            const resultURI = await encodePNG({
                image: imgPreview,
                data: dataArray,
                password: stegoPwd,
                iterations: 1,
                password2: null,
                iterations2: 1
            });

            imgPreview.src = resultURI;
            alert("PNG updated with hidden data.");
        } else {
            // 5. Await the modernized JPG encoding
            const resultURI = await encodeJPG({
                image: imgPreview,
                data: dataArray,
                password: stegoPwd,
                skipEncrypt: false,
                iterations: 1,
                data2: null,
                password2: null,
                iterations2: 1
            });

            imgPreview.src = resultURI;
            alert("JPG updated with hidden data.");
        }
    } catch (error) {
        alert("Stego error: " + error.message);
    }
}

// Convert a UTF-8 string to a bit array (0/1) using nacl.util
function textToBits(str) {
    const uint8Array = nacl.util.decodeUTF8(str);
    return bytesToBits(uint8Array);
}

// Convert a bit array (0/1) back to a UTF-8 string using nacl.util
function bitsToText(bits) {
    const uint8Array = bitsToBytes(bits);
    return nacl.util.encodeUTF8(uint8Array);
}

/**
 * Gathers user input for steganographic encryption.
 * @returns {Promise<{data1: Uint8Array, pwd1: string, data2: Uint8Array|null, pwd2: string|null} | null>}
 */
async function getStegoEncryptionInputs() {
    const payloadInput = prompt('Enter text to embed (use | for second message):');
    if (!payloadInput) return null; // User canceled

    const payload = payloadInput.trim();
    if (payload === "") return null; // Empty input

    const passwordInput = prompt('Enter stego password(s) (use | for second password):');
    if (!passwordInput) return null; // User canceled

    const passwords = passwordInput.trim();
    if (passwords === "") return null; // Empty input

    // Split and trim parts
    const payloadParts = payload.split('|').map(p => p.trim());
    const passwordParts = passwords.split('|').map(p => p.trim());

    // Primary data and password (always required)
    const data1 = nacl.util.decodeUTF8(payloadParts[0]);
    const pwd1 = passwordParts[0];

    // Secondary data and password: ONLY if both parts exist and are non-empty
    let data2 = null;
    let pwd2 = null;

    if (payloadParts.length > 1 && payloadParts[1] !== "" &&
        passwordParts.length > 1 && passwordParts[1] !== "") {
        data2 = nacl.util.decodeUTF8(payloadParts[1]);
        pwd2 = passwordParts[1];
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

        const passwords = getStegoDecryptionPasswords();
        if (!passwords) return; // User canceled or invalid input

        try {
            const result = await decodeImage({
                image: imgPreview,
                password: passwords.pwd1,
                skipEncrypt: false,
                iterations: 1,
                password2: passwords.pwd2, // null if no second password
                iterations2: 1
            });

            let outputText = "";

            // Process primary
            if (result.primary && result.primary.length > 0) {
                outputText = nacl.util.encodeUTF8(result.primary);
            }

            // Process secondary only if a second password was provided
            if (passwords.pwd2 && result.secondary && result.secondary.length > 0) {
                const text2 = nacl.util.encodeUTF8(result.secondary);
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
