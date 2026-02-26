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
/*
// 1. Encrypt and Hide (PNG or JPG)
async function handleStegoEncrypt(format) {
    const imgPreview = document.getElementById('stego-image-preview');
    const composeBox = document.getElementById('composeBox');
    const textToEncrypt = composeBox.value || composeBox.innerText;

    if (!textToEncrypt) {
        alert("Please enter a message in the compose box first.");
        return;
    }

    // Use the existing encryption logic but get raw bytes
    // We'll call a helper that performs the core encryption
    try {
        const result = await coreEncrypt(textToEncrypt); // Assuming this returns {ciphertext: Uint8Array, ...}
        const bits = bytesToBits(result.ciphertext);

        const stegoPwd = prompt(`Enter stego password for ${format}:`);
        if (stegoPwd === null) return;

        const callback = (success, msg) => {
            if (!success) alert("Stego error: " + msg);
        };

        if (format === 'PNG') {
            encodePNG(imgPreview, bits, stegoPwd, callback);
        } else {
            encodeJPG(imgPreview, bits, stegoPwd, callback);
        }
    } catch (e) {
        alert("Encryption failed: " + e.message);
    }
}*/

async function handleStegoEncrypt(format) {
    const imgPreview = document.getElementById('stego-image-preview');

    if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
        alert("Please load a cover image first.");
        return;
    }

    // TEMP: Prompt for plain text payload instead of encrypting
    const textToEncrypt = prompt("Enter text to embed in the image:");
    if (textToEncrypt === null || textToEncrypt.trim() === "") {
        alert("No text entered.");
        return;
    }

    // Convert text to bits
    const bits = textToBits(textToEncrypt);

    const stegoPwd = prompt(`Enter stego password for ${format}:`);
    if (stegoPwd === null) return;

    const callback = (success, msg) => {
        if (success) {
            alert(`${format} stego image created and downloaded`);
        } else {
            alert("Stego error: " + msg);
        }
    };

    if (format === 'PNG') {
        encodePNG(imgPreview, bits, stegoPwd, callback);
    } else {
        encodeJPG(imgPreview, bits, stegoPwd, callback);
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

document.addEventListener('DOMContentLoaded', () => {
    const imgPreview = document.getElementById('stego-image-preview');

    // Encrypt buttons
    document.getElementById('stego-encrypt-png').addEventListener('click', () => {
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            alert('Please load a cover image first.');
            return;
        }
        const payload = prompt('Enter text to embed in the image:');
        if (payload === null || payload.length === 0) return;

        const bits = textToBits(payload);
        const stegoPwd = prompt('Enter stego password to protect the hidden payload:');
        if (stegoPwd === null) return;

        encodePNG(imgPreview, bits, stegoPwd, (success, msg) => {
            if (success) alert('PNG stego image created and downloaded');
            else alert('Stego embedding failed: ' + (msg || 'unknown error'));
        });
    });

    document.getElementById('stego-encrypt-jpg').addEventListener('click', () => {
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            alert('Please load a cover image first.');
            return;
        }
        const payload = prompt('Enter text to embed in the image:');
        if (payload === null || payload.length === 0) return;

        const bits = textToBits(payload);
        const stegoPwd = prompt('Enter stego password to protect the hidden payload:');
        if (stegoPwd === null) return;

        encodeJPG(imgPreview, bits, stegoPwd, (success, msg) => {
            if (success) alert('JPG stego image created and downloaded');
            else alert('Stego embedding failed: ' + (msg || 'unknown error'));
        });
    });

    // Extract and decrypt button (already present)
    document.getElementById('stego-decrypt-btn').addEventListener('click', () => {
    const imgPreview = document.getElementById('stego-image-preview');
    const stegoPwd = prompt("Enter stego password to extract:");
    if (stegoPwd === null) return;

    decodeImage(imgPreview, stegoPwd, (bits, msg) => {
        if (!bits || bits.length === 0) {
            alert("No hidden data found or incorrect password.");
            return;
        }

        try {
            const text = bitsToText(bits);
            alert("Extracted text:\n\n" + text);
            
            // Optional: Put it in composeBox
            const composeBox = document.getElementById('composeBox');
            if (composeBox) composeBox.innerText = text;
        } catch (e) {
            alert("Failed to decode text: " + e.message);
        }
    });
});
});
/*
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('stego-encrypt-png').addEventListener('click', () => handleStegoEncrypt('PNG'));
    document.getElementById('stego-encrypt-jpg').addEventListener('click', () => handleStegoEncrypt('JPG'));

    // 2. Extract and Decrypt
    document.getElementById('stego-decrypt-btn').addEventListener('click', () => {
        const imgPreview = document.getElementById('stego-image-preview');
        const stegoPwd = prompt("Enter stego password to extract:");
        if (stegoPwd === null) return;

        decodeImage(imgPreview, stegoPwd, async (bits, msg) => {
            if (msg) {
                alert("Extraction error: " + msg);
                return;
            }

            const cipherBytes = bitsToBytes(bits);
            try {
                // Pass raw bytes directly to the binary decryption pipeline
                await continueDecryptBinary(cipherBytes);
            } catch (e) {
                alert("Decryption failed: " + e.message);
            }
        });
    });
});*/