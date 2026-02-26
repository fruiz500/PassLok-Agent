/*
		@source: https://github.com/fruiz500/passlok-stego

		@licstart  The following is the entire license notice for the
		JavaScript code in this page.

		Copyright (C) 2017  Francisco Ruiz

		The JavaScript code in this page is free software: you can
		redistribute it and/or modify it under the terms of the GNU
		General Public License (GNU GPL) as published by the Free Software
		Foundation, either version 3 of the License, or (at your option)
		any later version.  The code is distributed WITHOUT ANY WARRANTY;
		without even the implied warranty of MERCHANTABILITY or FITNESS
		FOR A PARTICULAR PURPOSE.  See the GNU GPL for more details.

		As additional permission under GNU GPL version 3 section 7, you
		may distribute non-source (e.g., minimized or compacted) forms of
		that code without the copy of the GNU GPL normally required by
		section 4, provided you include this license notice and a URL
		through which recipients can access the Corresponding Source.


		@licend  The above is the entire license notice
		for the JavaScript code in this page.
		*/

//PassLok-stego image encoding, based on F5 by A. Westfeld
/*	Usage:
	To encode a binary item into an image loaded in the DOM, use either of the following statements:

	encodePNG(image element (object), item to be encoded (binary array), password (string), callback function(error message to be displayed (string)), [encryptToggle (Boolean), iter (number)],[item2 (binary array), password2 (string), iter2 (number)])
	encodeJPG(image element (object), item to be encoded (binary array), password (string), callback function(error message to be displayed (string)), [encryptToggle (Boolean), iter (number)],[item2 (binary array), password2 (string), iter2 (number)])
	
	The first function converts the image into a PNG image, the second into a JPG image. The original image can be any type recognized by the browser. The first argument is 		the image element present in the DOM, which will contain the image data encoded as base64. The item to be encoded is an array containing only 1's and 0's. The callback function is used to display a string error message elsewhere in the DOM. For instance: function(msg){imageMsg.textContent = msg}. The optional variable encryptToggle is a Boolean (default: false) that instructs the program to skip the step where noise is added or subtracted, in case the embedded data already has sufficient randomness. Optional variable iter is a number that, if larger than 0, will consume an extra amount of time proportional to 2^iter, useful as a sort of key-derivation function.
	
	The rest of the parameters are to embed a second message: item2 as binary array, password2 as string, iter2 as number. This message is encoded after the first one, taking advantage of whatever space is left. As a minimum there should be space for 144 bits, or 18 uncompressed characters, but typically there is substantially more.
	
	To decode a hidden item out of an image, use either of these statements, depending on the type of image loaded:
	
	decodePNG(image element (object), password (string), callback function(item extracted (binary array)), message to be displayed (string)), [encryptToggle (Boolean), iter (number)],[password2 (string), callback2 (function), iter2 (number)])
	decodeJPG(image element (object), password (string), callback function(item extracted (binary array)), message to be displayed (string)), [encryptToggle (Boolean), iter (number)],[password2 (string), callback2 (function), iter2 (number)])
	
	Here the callback function should have two arguments: the first is the item extracted from the image as an array containing only 1's and 0's, the second a string message indicating whether or not the operation has been successful. There is also a function that determines automatically the type of image file (PNG or JPG) and calls the appropriate decoding function:
	
	decodeImage(image element (object), password (string), callback function(item extracted (binary array)), message to be displayed (string)), [encryptToggle (Boolean), iter (number)],[password2 (string), callback2 (function), iter2 (number)])
	
	iOS users beware: as of version 10.2 of iOS, the jsstegdecoder library crashes at line 541. This means that you will be able to do encode/decode for PNG, and encode for JPG, but not decode for JGP.
*/

//const imgEOF = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];			//end of encoded message marker

const imgEOF = new Uint8Array([0, 0, 0, 255, 255, 255]); //end of encoded message marker, chosen to be unlikely to appear in the data, and also to be easy to identify in the decoding process. The first four zeros are needed because the encoding is done in RGB channels, and the last 255 is needed because only opaque pixels are used for encoding

// Add this helper function at the top of plstego.js, by Claude AI
function createOptimizedCanvas(width, height) {
	// Use OffscreenCanvas if available (better performance)
	if (typeof OffscreenCanvas !== 'undefined') {
		return new OffscreenCanvas(width, height);
	}
	// Fallback to regular canvas
	var canvas = document.createElement('canvas');
	canvas.width = width;
	canvas.height = height;
	return canvas;
}

//this function does the PNG encoding as LSB in all channels except alpha, which is kept with original values

function encodePNG(imageElement, msgBin, password, callback, encryptToggle, iter, msgBin2, password2, iter2) {
	return new Promise((resolve, reject) => {
		let msgBytes;

		// 1. Handle Input Formats
		if (Array.isArray(msgBin)) {
			msgBytes = legacyBitsToUint8Array(msgBin);
		} else if (msgBin instanceof Uint8Array) {
			msgBytes = msgBin;
		} else {
			const err = new Error("Data must be Uint8Array or legacy bit array");
			if (callback) callback(err.message);
			return reject(err);
		}

		try {
			// 2. Setup Canvas
			if (!imageElement || !imageElement.naturalWidth) {
				throw new Error('Invalid image element provided');
			}

			const shadowCanvas = document.createElement('canvas');
			const shadowCtx = shadowCanvas.getContext('2d', { willReadFrequently: true });

			if (!shadowCtx) {
				throw new Error('Failed to get canvas context');
			}

			shadowCanvas.width = imageElement.naturalWidth;
			shadowCanvas.height = imageElement.naturalHeight;
			shadowCtx.drawImage(imageElement, 0, 0, shadowCanvas.width, shadowCanvas.height);

			const imageData = shadowCtx.getImageData(0, 0, shadowCanvas.width, shadowCanvas.height);
			const length = imageData.data.length;

			// 3. Extract RGB coefficients from opaque pixels
			const alphaData = new Uint8Array(length / 4);
			let k = 0;
			let coefficients = new Uint8Array(length / 4 * 3);

			for (let i = 3; i < length; i += 4) {
				const alphaIndex = Math.floor(i / 4);
				alphaData[alphaIndex] = imageData.data[i];
				if (imageData.data[i] === 255) {
					for (let j = 0; j < 3; j++) {
						coefficients[k++] = imageData.data[i - 3 + j];
					}
				}
			}
			coefficients = coefficients.slice(0, k);

			// 4. Prepare Message (Append EOF)
			const finalMsgBytes = new Uint8Array(msgBytes.length + imgEOF.length);
			finalMsgBytes.set(msgBytes);
			finalMsgBytes.set(imgEOF, msgBytes.length);

			// 5. Stego Logic (PRNG & Shuffle)
			const seed = password + length.toString() + 'png';
			seedPRNG(seed, iter);

			const myPermutation = shuffleCoefficients(coefficients, 0);

			const skipEncrypt = encryptToggle || false;

			let processedBytes = skipEncrypt ? finalMsgBytes : addNoise(finalMsgBytes);

			// encodeToCoefficients expects legacy bits
			const legacyMsgBin = uint8ArrayToLegacyBits(processedBytes);

			const lastIndex = encodeToCoefficients('png', legacyMsgBin, 0, coefficients, (msg) => {
				if (msg) throw new Error(msg);
			});

			// 6. Handle Second Message (Optional)
			if (msgBin2) {
				let msgBytes2 = Array.isArray(msgBin2) ? legacyBitsToUint8Array(msgBin2) : msgBin2;
				const finalMsgBytes2 = new Uint8Array(msgBytes2.length + imgEOF.length);
				finalMsgBytes2.set(msgBytes2);
				finalMsgBytes2.set(imgEOF, msgBytes2.length);

				const seed2 = password2 + lastIndex.toString() + 'png';
				seedPRNG(seed2, iter2);

				const myPermutation2 = shuffleCoefficients(coefficients, lastIndex + 1);

				let processedBytes2 = skipEncrypt ? finalMsgBytes2 : addNoise(finalMsgBytes2);
				const legacyMsgBin2 = uint8ArrayToLegacyBits(processedBytes2);

				encodeToCoefficients('png', legacyMsgBin2, lastIndex + 1, coefficients, (msg) => {
					if (msg) throw new Error(msg);
				});

				unShuffleCoefficients(coefficients, myPermutation2, lastIndex + 1);
			}

			unShuffleCoefficients(coefficients, myPermutation, 0);

			// 7. Reconstruct Image
			k = 0;
			for (let i = 3; i < length; i += 4) {
				const alphaIndex = Math.floor(i / 4);
				if (alphaData[alphaIndex] === 255) {
					for (let j = 0; j < 3; j++) {
						imageData.data[i - 3 + j] = coefficients[k++];
					}
				}
			}

			shadowCtx.putImageData(imageData, 0, 0);

			// 8. Finalize Output
			const dataUrl = shadowCanvas.toDataURL('image/png');
			imageElement.src = dataUrl;

			if (callback) callback(true);
			resolve(dataUrl);

		} catch (error) {
			if (callback) callback('Error encoding PNG: ' + error.message);
			console.error('encodePNG error:', error);
			reject(error);
		}
	});
}

//decodes data stored in PNG image

function decodePNG(imageElement, password, callback, encryptToggle, iter, password2, callback2, iter2) {
	return new Promise((resolve, reject) => {
		try {
			if (!imageElement || !imageElement.naturalWidth) {
				throw new Error('Invalid image element provided');
			}

			const shadowCanvas = document.createElement('canvas');
			const shadowCtx = shadowCanvas.getContext('2d', { willReadFrequently: true });

			if (!shadowCtx) {
				throw new Error('Failed to get canvas context');
			}

			shadowCanvas.style.display = 'none';
			shadowCanvas.width = imageElement.naturalWidth;
			shadowCanvas.height = imageElement.naturalHeight;
			shadowCtx.drawImage(imageElement, 0, 0, shadowCanvas.width, shadowCanvas.height);

			const imageData = shadowCtx.getImageData(0, 0, shadowCanvas.width, shadowCanvas.height);
			const length = imageData.data.length;

			// Extract RGB coefficients from opaque pixels
			let k = 0;
			let coefficients = new Uint8Array(length / 4 * 3);

			for (let i = 3; i < length; i += 4) {
				if (imageData.data[i] === 255) { // opaque pixel
					for (let j = 0; j < 3; j++) {
						coefficients[k++] = imageData.data[i - 3 + j];
					}
				}
			}
			coefficients = coefficients.slice(0, k);

			const seed = password + length.toString() + 'png';

			seedPRNG(seed, iter);

			const myPermutation = shuffleCoefficients(coefficients, 0);

			const skipEncrypt = encryptToggle || false;

			const result = decodeFromCoefficients('png', 0, coefficients);

			if (callback) callback(result[0], result[1]);

			let result2 = null;
			if (password2) {
				const seed2 = password2 + result[2].toString() + 'png';
				seedPRNG(seed2, iter2);
				const myPermutation2 = shuffleCoefficients(coefficients, result[2] + 1);
				result2 = decodeFromCoefficients('png', result[2] + 1, coefficients);
				if (callback2) callback2(result2[0], result2[1]);
				unShuffleCoefficients(coefficients, myPermutation2, result[2] + 1);
			}

			unShuffleCoefficients(coefficients, myPermutation, 0);

			resolve({
				primary: { data: result[0], message: result[1] },
				secondary: result2 ? { data: result2[0], message: result2[1] } : null
			});

		} catch (error) {
			if (callback) callback('Error decoding PNG: ' + error.message);
			console.error('decodePNG error:', error);
			reject(error);
		}
	});
}

// Global variables for js-steg compatibility
var globalBin, jpgPassword, jpgIter, showError, skipEncrypt, globalBin2, jpgPassword2, jpgIter2;

function encodeJPG(imageElement, msgBin, password, callback, encryptToggle, iter, msgBin2, password2, iter2) {
	// Set globals for modifyCoefficients
	globalBin = msgBin;
	globalBin2 = msgBin2;
	jpgPassword = password;
	jpgPassword2 = password2;
	jpgIter = iter;
	jpgIter2 = iter2;
	showError = callback;
	skipEncrypt = encryptToggle || false;

	const startEncoding = () => {
		try {
			if (!imageElement || !imageElement.src) throw new Error('No image provided');

			if (imageElement.src.slice(11, 15).match(/gif;|png;/)) {
				transparent2white(imageElement);
			}

			// Call js-steg with global modifyCoefficients
			jsSteg.reEncodeWithModifications(imageElement.src, modifyCoefficients, function (resultURI) {
				imageElement.src = resultURI;
				// Clear globals
				globalBin = null;
				globalBin2 = null;
				jpgPassword = '';
				jpgPassword2 = '';
				showError = null;
			});
		} catch (error) {
			console.error('encodeJPG error:', error);
			if (callback) callback('Error encoding JPEG: ' + error.message);
		}
	};

	if (imageElement.complete && imageElement.naturalWidth !== 0) {
		startEncoding();
	} else {
		imageElement.onload = startEncoding;
		imageElement.onerror = () => callback('Failed to load image for JPEG encoding');
	}
}

//this function gets the jpeg coefficients (first luma, then chroma) and extracts the hidden material. Stops when the 48-bit endText code is found
var allCoefficients, permutation, permutation2;

function decodeJPG(imageElement, password, callback, encryptToggle, iter, password2, callback2, iter2) {
	try {
		jsSteg.getCoefficients(imageElement.src, function (coefficients) {
			const length = coefficients[1].length;
			if (coefficients[2].length !== length) {
				callback('', 'This image does not contain anything, or perhaps the password is wrong');
				throw ('image is chroma subsampled');
			}

			// 1. Keep the size at 3 planes
			const rawLength = 3 * length * 64;
			const rawCoefficients = new Int16Array(rawLength);

			// 2. Use 1, 2, 3 for the library, but (index - 1) for the offset
			for (let index = 1; index <= 3; index++) {
				// index 1 -> offset 0
				// index 2 -> offset 1 * length * 64
				// index 3 -> offset 2 * length * 64
				const planeOffset = (index - 1) * length * 64;

				for (let i = 0; i < length; i++) {
					const blockOffset = i * 64;
					const block = coefficients[index][i];

					// Safety check: if the library returns fewer blocks than expected
					if (!block) break;

					for (let j = 0; j < 64; j++) {
						rawCoefficients[planeOffset + blockOffset + j] = block[j];
					}
				}
			}

			// Remove zeros
			let allCoefficients = removeZeros(rawCoefficients);

			// Seed PRNG and shuffle
			const seed = password + allCoefficients.length.toString() + 'jpeg';
			seedPRNG(seed, iter);
			const myPermutation = shuffleCoefficients(allCoefficients, 0);

			const skipEncrypt = encryptToggle || false;

			// Decode from coefficients
			const result = decodeFromCoefficients('jpeg', 0, allCoefficients);

			// If noise was added, decodeFromCoefficients should handle noise removal internally
			// (Make sure decodeFromCoefficients uses byte-based addNoise as well)

			callback(result[0], result[1]);

			// Handle second password if provided
			if (password2) {
				const seed2 = password2 + result[2].toString() + 'jpeg';
				seedPRNG(seed2, iter2);
				const myPermutation2 = shuffleCoefficients(allCoefficients, result[2] + 1);
				const result2 = decodeFromCoefficients('jpeg', result[2] + 1, allCoefficients);
				callback2(result2[0], result2[1]);
				unShuffleCoefficients(allCoefficients, myPermutation2, result[2] + 1);
			}

			unShuffleCoefficients(allCoefficients, myPermutation, 0);

			// Clear local state
			allCoefficients = null;
			myPermutation = null;

		});
	} catch (error) {
		console.error('decodeJPG error:', error);
		if (callback) callback('', 'Error decoding JPEG: ' + error.message);
	}
}

/**
 * Called when encoding a JPEG
 * - coefficients: coefficients[0] is an array of luminosity blocks, coefficients[1] and
 *   coefficients[2] are arrays of chrominance blocks. Each block has 64 "modes"
 */
function modifyCoefficients(coefficients) {
	// Validate global state
	if (!globalBin) throw new Error("No message data provided to stego encoder");

	// 1. Convert input message to bytes
	let msgBytes;
	if (Array.isArray(globalBin)) {
		msgBytes = legacyBitsToUint8Array(globalBin);
	} else if (globalBin instanceof Uint8Array) {
		msgBytes = globalBin;
	} else {
		throw new Error("Data must be Uint8Array or legacy bit array");
	}

	// 2. Append EOF as bytes
	const finalMsgBytes = new Uint8Array(msgBytes.length + imgEOF.length);
	finalMsgBytes.set(msgBytes);
	finalMsgBytes.set(imgEOF, msgBytes.length);

	const length = coefficients[0].length;
	const rawLength = 3 * length * 64;

	// 3. Linearize coefficients into typed array
	const rawCoefficients = new Int16Array(rawLength);
	for (let index = 0; index < 3; index++) {
		const planeOffset = index * length * 64;
		for (let i = 0; i < length; i++) {
			const blockOffset = i * 64;
			for (let j = 0; j < 64; j++) {
				rawCoefficients[planeOffset + blockOffset + j] = coefficients[index][i][j];
			}
		}
	}

	// 4. Remove zeros and prepare for stego
	let allCoefficients = removeZeros(rawCoefficients);

	const seed = jpgPassword + allCoefficients.length.toString() + 'jpeg';
	seedPRNG(seed, jpgIter);

	let myPermutation = shuffleCoefficients(allCoefficients, 0);

	// 5. Add noise (byte-based)
	let processedBytes = skipEncrypt ? finalMsgBytes : addNoise(finalMsgBytes);

	// 6. Convert to legacy bits for encodeToCoefficients
	const legacyMsgBin = uint8ArrayToLegacyBits(processedBytes);

	const lastIndex = encodeToCoefficients('jpeg', legacyMsgBin, 0, allCoefficients, (msg) => {
		if (showError) showError(msg);
		throw ('insufficient cover image capacity');
	});

	// 7. Handle second message (if any)
	if (globalBin2) {
		let msgBytes2;
		if (Array.isArray(globalBin2)) {
			msgBytes2 = legacyBitsToUint8Array(globalBin2);
		} else if (globalBin2 instanceof Uint8Array) {
			msgBytes2 = globalBin2;
		}

		const finalMsgBytes2 = new Uint8Array(msgBytes2.length + imgEOF.length);
		finalMsgBytes2.set(msgBytes2);
		finalMsgBytes2.set(imgEOF, msgBytes2.length);

		const seed2 = jpgPassword2 + lastIndex.toString() + 'jpeg';
		seedPRNG(seed2, jpgIter2);

		let myPermutation2 = shuffleCoefficients(allCoefficients, lastIndex + 1);

		let processedBytes2 = skipEncrypt ? finalMsgBytes2 : addNoise(finalMsgBytes2);
		const legacyMsgBin2 = uint8ArrayToLegacyBits(processedBytes2);

		encodeToCoefficients('jpeg', legacyMsgBin2, lastIndex + 1, allCoefficients, (msg) => {
			if (showError) showError(msg);
			throw ('insufficient cover image capacity');
		});

		unShuffleCoefficients(allCoefficients, myPermutation2, lastIndex + 1);
	}

	// 8. Unshuffle and reconstruct image
	unShuffleCoefficients(allCoefficients, myPermutation, 0);

	let j = 0;
	for (let i = 0; i < rawLength; i++) {
		if (rawCoefficients[i] !== 0) {
			rawCoefficients[i] = allCoefficients[j++];
		}
	}

	for (let index = 0; index < 3; index++) {
		const planeOffset = index * length * 64;
		for (let i = 0; i < length; i++) {
			const blockOffset = i * 64;
			for (let j = 0; j < 64; j++) {
				coefficients[index][i][j] = rawCoefficients[planeOffset + blockOffset + j];
			}
		}
	}

	// Clear local refs
	allCoefficients = null;
	myPermutation = null;
}

//seeds the PRNG and adds spurious computations according to Password weakness
function seedPRNG(seed, iter) {
	SeededPRNG.seed(seed);										//re-seed the PRNG
	if (iter) SeededPRNG.prng(Math.pow(2, iter) - 1)					//spurious computations, the more the worse the password
}

/**
 * Shuffles the provided array in-place.
 * @param {Uint8Array|Int8Array} coeffs - The array to shuffle.
 * @param {number} startIndex - Optional start index.
 * @returns {Array} The permutation array generated (to be stored locally by the caller).
 */
function shuffleCoefficients(coeffs, startIndex = 0) {
	const length = coeffs.length;
	const subLength = length - startIndex;
	const perm = randPerm(subLength);

	// We still need a temporary buffer for the shuffle step to avoid overwriting 
	// values before they are moved, but we keep it local.
	const temp = new coeffs.constructor(subLength);

	for (let i = 0; i < subLength; i++) {
		temp[i] = coeffs[startIndex + perm[i]];
	}

	// Copy back into the original array (In-place modification)
	for (let i = 0; i < subLength; i++) {
		coeffs[startIndex + i] = temp[i];
	}

	return perm; // Return the permutation so the caller can save it locally
}

/**
 * Un-shuffles the provided array in-place using a saved permutation.
 * @param {Uint8Array|Int8Array} coeffs - The array to un-shuffle.
 * @param {Array} perm - The permutation array returned by shuffleCoefficients.
 * @param {number} startIndex - Optional start index.
 */
function unShuffleCoefficients(coeffs, perm, startIndex = 0) {
	const length = coeffs.length;
	const subLength = length - startIndex;
	const inversePerm = new Array(subLength);
	const temp = new coeffs.constructor(subLength);

	// Create inverse permutation
	for (let i = 0; i < subLength; i++) {
		inversePerm[perm[i]] = i;
	}

	for (let i = 0; i < subLength; i++) {
		temp[i] = coeffs[startIndex + inversePerm[i]];
	}

	// Copy back into the original array (In-place modification)
	for (let i = 0; i < subLength; i++) {
		coeffs[startIndex + i] = temp[i];
	}
}

//obtain a random permutation using isaac re-seedable PRNG, for use in image steganography
function randPerm(n) {
	var result = new Array(n);
	result[0] = 0;

	for (var i = 1; i < n; ++i) {
		var idx = (SeededPRNG.random() * (i + 1)) | 0;			//here is the call to the isaac PRNG library, floating point version
		if (idx < i) {
			result[i] = result[idx]
		}
		result[idx] = i
	}
	return result
}

function addNoise(byteArray) {
	const length = byteArray.length;
	for (let i = 0; i < length; i++) {
		let noisyByte = 0;
		for (let bit = 0; bit < 8; bit++) {
			// Generate a random bit (0 or 1)
			const randBit = SeededPRNG.rand() >= 0 ? 1 : 0;
			// Extract the bit from the original byte
			const originalBit = (byteArray[i] >> (7 - bit)) & 1;
			// XOR original bit with random bit
			const newBit = originalBit ^ randBit;
			// Set the new bit in the noisyByte
			noisyByte |= (newBit << (7 - bit));
		}
		byteArray[i] = noisyByte;
	}
	return byteArray;
}

//convert binary array to decimal number
function binArray2dec(array) {
	var length = array.length,
		output = 0,
		mult = 1;

	for (var i = 0; i < length; i++) {
		output += array[length - 1 - i] * mult;
		mult = mult * 2
	}
	return output
}

//to get the parity of a number. Positive: 0 if even, 1 if odd. Negative: 0 if odd, 1 if even. 0 is even
function stegParity(number) {
	if (number >= 0) {
		return number % 2
	} else {
		return -(number - 1) % 2
	}
}

//faster Boolean filter for array
function removeZeros(array) {
	const length = array.length;
	let nonZeros = 0;

	for (let i = 0; i < length; i++) {
		if (array[i] !== 0) nonZeros++;
	}

	const outArray = new Int16Array(nonZeros);
	let j = 0;

	for (let i = 0; i < length; i++) {
		if (array[i] !== 0) {
			outArray[j++] = array[i];
		}
	}
	return outArray;
}

//gets counts in the DCT AC histogram: 2's plus -2, 3's plus -3, outputs array containing the counts
function partialHistogram(array) {
	var output = [0, 0],
		length = array.length;

	for (var j = 0; j < length; j++) {
		for (var i = 2; i <= 3; i++) {
			if (array[j] == i || array[j] == -i) output[i - 2]++
		}
	}
	return output
}

//matrix encoding of allCoefficients with variable k, which is prepended to the message. Selectable for png or jpeg encoding.
/*
function encodeToCoefficients(type, inputBin, startIndex, coefficients, callback) {
	// 1. Calculate capacity
	const length = (startIndex === 0)
		? coefficients.length - 222
		: coefficients.length - startIndex - 4;

	const rate = inputBin.length / length;
	let k = 2;

	if (inputBin.length > length) {
		// Reset local variables on failure (caller should handle cleanup)
		if (callback) callback(
			(startIndex === 0)
				? `This image can hide ${length} bits. But the box contains ${inputBin.length} bits`
				: `This image can add a hidden message ${length} bits long. But the hidden message in the box has ${inputBin.length} bits`
		);
		return;
	}

	// 2. Determine k (matrix encoding parameter)
	while (k / (Math.pow(2, k) - 1) > rate) k++;
	k--;
	if (k > 16) k = 16;

	// 3. Encode k into the first 4 coefficients
	const kCode = new Uint8Array(4);
	for (let j = 0; j < 4; j++) kCode[3 - j] = ((k - 1) >> j) & 1;

	if (type === 'jpeg') {
		// JPEG-specific histogram adjustment
		const count2to3 = partialHistogram(coefficients.slice(startIndex + 4));
		const y = count2to3[1] / (count2to3[0] + count2to3[1]);
		let ones = 0, minusones = 0;

		for (let i = 0; i < 4; i++) {
			const idx = startIndex + i;
			const val = coefficients[idx];
			if (val > 0) {
				if (kCode[i] === 1 && stegParity(val) === 0) coefficients[idx]--;
				else if (kCode[i] === 0 && stegParity(val) !== 0) {
					coefficients[idx] = (val !== 1) ? val - 1 : -1;
				}
			} else {
				if (kCode[i] === 0 && stegParity(val) !== 0) coefficients[idx]++;
				else if (kCode[i] === 1 && stegParity(val) === 0) {
					coefficients[idx] = (val !== -1) ? val + 1 : 1;
				}
			}
		}
	} else {
		// PNG-specific k encoding
		for (let i = 0; i < 4; i++) {
			const idx = startIndex + i;
			if (kCode[i] === 1 && stegParity(coefficients[idx]) === 0) coefficients[idx]++;
			else if (kCode[i] === 0 && stegParity(coefficients[idx]) !== 0) coefficients[idx]--;
		}
	}

	// 4. Encode actual data
	const n = Math.pow(2, k) - 1;
	const blocks = Math.ceil(inputBin.length / k);

	// Helper to get bit from inputBin (supports Uint8Array or legacy array)
	const getPayloadBit = (idx) => {
		if (idx >= inputBin.length) return 0; // Padding
		return (inputBin instanceof Uint8Array) ? getBit(inputBin, idx) : inputBin[idx];
	};

	for (let i = 0; i < blocks; i++) {
		// Calculate inputNumber (decimal value of the k-bit block)
		let inputNumber = 0;
		for (let bitIdx = 0; bitIdx < k; bitIdx++) {
			if (getPayloadBit(i * k + bitIdx)) {
				inputNumber |= (1 << (k - 1 - bitIdx));
			}
		}

		// Calculate hash of the cover block parity
		let hash = 0;
		for (let j = 1; j <= n; j++) {
			const coeff = coefficients[startIndex + 4 + i * n + (j - 1)];
			hash ^= (stegParity(coeff) * j);
		}

		const outputNumber = inputNumber ^ hash;

		if (outputNumber !== 0) {
			const pos = startIndex + 3 + i * n + outputNumber;
			const val = coefficients[pos];

			if (type === 'jpeg') {
				// JPEG F5-style embedding with shrinkage/expansion logic
				if (val > 0) {
					if (val === 1) {
						if (minusones <= 0) { coefficients[pos] = -1; ones--; minusones++; }
						else { coefficients[pos] = 2; ones--; }
					} else if (val === 2) {
						if (ones <= 0) { coefficients[pos]--; ones++; }
						else { coefficients[pos]++; }
					} else {
						coefficients[pos] += (Math.random() > y) ? -1 : 1;
					}
				} else if (val < 0) {
					if (val === -1) {
						if (ones <= 0) { coefficients[pos] = 1; minusones--; ones++; }
						else { coefficients[pos] = -2; minusones--; }
					} else if (val === -2) {
						if (minusones <= 0) { coefficients[pos]++; minusones++; }
						else { coefficients[pos]--; }
					} else {
						coefficients[pos] += (Math.random() > y) ? 1 : -1;
					}
				}
			} else {
				// PNG LSB embedding
				if (val % 2 !== 0) coefficients[pos]--;
				else coefficients[pos]++;
			}
		}
	}

	return startIndex + (blocks * n) + 3;
}*/
function encodeToCoefficients(type, inputBin, startIndex, coefficients, callback) {
	// Validate inputs
	if (!coefficients || !coefficients.length) {
		return callback("No coefficients provided");
	}

	var length = (startIndex === 0) ? coefficients.length - 222 : coefficients.length - startIndex - 4;

	if (inputBin.length > length) {
		if (startIndex === 0) {
			callback('This image can hide ' + length.toString() + ' bits. But the box contains ' + inputBin.length.toString() + ' bits');
		} else {
			callback('This image can add a hidden message ' + length.toString() + ' bits long. But the hidden message in the box has ' + inputBin.length.toString() + ' bits');
		}
		return;
	}

	// Determine k
	var rate = inputBin.length / length;
	var k = 2;
	while (k / (Math.pow(2, k) - 1) > rate) k++;
	k--;

	if (k > 16) k = 16;
	var kCode = new Array(4);
	for (var j = 0; j < 4; j++) kCode[3 - j] = (k - 1 >> j) & 1;

	// JPEG-specific variables
	var y, ones = 0, minusones = 0;
	if (type === 'jpeg') {
		var count2to3 = partialHistogram(coefficients.slice(startIndex + 4));
		y = count2to3[1] / (count2to3[0] + count2to3[1]);
	}

	// Encode k into coefficients
	if (type === 'jpeg') {
		for (var i = 0; i < 4; i++) {
			if (coefficients[startIndex + i] > 0) {
				if (kCode[i] === 1 && stegParity(coefficients[startIndex + i]) === 0) {
					coefficients[startIndex + i]--;
				} else if (kCode[i] === 0 && stegParity(coefficients[startIndex + i]) !== 0) {
					if (coefficients[startIndex + i] !== 1) {
						coefficients[startIndex + i]--;
					} else {
						coefficients[startIndex + i] = -1;
					}
				}
			} else {
				if (kCode[i] === 0 && stegParity(coefficients[startIndex + i]) !== 0) {
					coefficients[startIndex + i]++;
				} else if (kCode[i] === 1 && stegParity(coefficients[startIndex + i]) === 0) {
					if (coefficients[startIndex + i] !== -1) {
						coefficients[startIndex + i]++;
					} else {
						coefficients[startIndex + i] = 1;
					}
				}
			}
		}
	} else {
		for (var i = 0; i < 4; i++) {
			if (kCode[i] === 1 && stegParity(coefficients[startIndex + i]) === 0) {
				coefficients[startIndex + i]++;
			} else if (kCode[i] === 0 && stegParity(coefficients[startIndex + i]) !== 0) {
				coefficients[startIndex + i]--;
			}
		}
	}

	// Encode the actual data
	var n = Math.pow(2, k) - 1;
	var blocks = Math.ceil(inputBin.length / k);

	while (inputBin.length % k) inputBin.push(0);

	for (var i = 0; i < blocks; i++) {
		var inputBlock = inputBin.slice(i * k, (i * k) + k);
		var inputNumber = binArray2dec(inputBlock);
		var coverBlock = coefficients.slice(startIndex + 4 + i * n, startIndex + 4 + (i * n) + n);
		var parityBlock = coverBlock.map(stegParity);
		var hash = 0;
		for (var j = 1; j <= n; j++) hash = hash ^ (parityBlock[j - 1] * j);
		var outputNumber = inputNumber ^ hash;

		if (outputNumber) {
			if (type === 'jpeg') {
				if (coverBlock[outputNumber - 1] > 0) {
					if (coverBlock[outputNumber - 1] === 1) {
						if (minusones <= 0) {
							coefficients[startIndex + 3 + i * n + outputNumber] = -1;
							ones--;
							minusones++;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber] = 2;
							ones--;
						}
					} else if (coverBlock[outputNumber - 1] === 2) {
						if (ones <= 0) {
							coefficients[startIndex + 3 + i * n + outputNumber]--;
							ones++;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber]++;
						}
					} else {
						if (Math.random() > y) {
							coefficients[startIndex + 3 + i * n + outputNumber]--;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber]++;
						}
					}
				} else if (coverBlock[outputNumber - 1] < 0) {
					if (coverBlock[outputNumber - 1] === -1) {
						if (ones <= 0) {
							coefficients[startIndex + 3 + i * n + outputNumber] = 1;
							minusones--;
							ones++;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber] = -2;
							minusones--;
						}
					} else if (coverBlock[outputNumber - 1] === -2) {
						if (minusones <= 0) {
							coefficients[startIndex + 3 + i * n + outputNumber]++;
							minusones++;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber]--;
						}
					} else {
						if (Math.random() > y) {
							coefficients[startIndex + 3 + i * n + outputNumber]++;
						} else {
							coefficients[startIndex + 3 + i * n + outputNumber]--;
						}
					}
				}
			} else {
				if (coverBlock[outputNumber - 1] % 2) {
					coefficients[startIndex + 3 + i * n + outputNumber]--;
				} else {
					coefficients[startIndex + 3 + i * n + outputNumber]++;
				}
			}
		}
	}

	return startIndex + blocks * n + 3;
}

//matrix decode of allCoefficients, where k is extracted from the start of the message. Selectable for png or jpeg encoding.

function decodeFromCoefficients(type, startIndex, coefficients) {
	// 1. Extract k
	const length = (startIndex === 0)
		? coefficients.length - 222
		: coefficients.length - startIndex - 4;

	let kVal = 0;
	for (let i = 0; i < 4; i++) {
		const bit = stegParity(coefficients[startIndex + i]);
		kVal |= (bit << (3 - i)); // Inline binArray2dec
	}
	const k = kVal + 1;

	const n = Math.pow(2, k) - 1;
	const blocks = Math.floor(length / n);

	if (blocks === 0) {
		// Caller should handle cleanup of globals if needed
		return ['', 'This image does not contain anything, or perhaps the password is wrong', 0];
	}

	// 2. Decode the data into a bit-stream (Uint8Array of 0s and 1s)
	let outputBits = new Uint8Array(k * blocks);

	for (let i = 0; i < blocks; i++) {
		let hash = 0;
		const blockOffset = startIndex + 4 + (i * n);

		for (let j = 1; j <= n; j++) {
			const coeff = coefficients[blockOffset + (j - 1)];
			hash ^= (stegParity(coeff) * j);
		}

		// Store bits in outputBits
		for (let j = 0; j < k; j++) {
			outputBits[i * k + (k - 1 - j)] = (hash >> j) & 1;
		}
	}

	// DEBUG LOGS - Add this in decodeFromCoefficients
	console.log("--- Stego Debug ---");
	console.log("Extracted k:", k);
	console.log("Total blocks:", blocks);
	console.log("First 16 extracted bits:", outputBits.slice(0, 16));
	console.log("Expected EOF Bytes:", imgEOF);

	// NEW: Convert the entire bit-stream to bytes BEFORE searching for EOF
	let outputBytes = packBitsToBytes(outputBits);

	// 3. Subtract noise if applicable
	if (!skipEncrypt) {
		outputBytes = addNoise(outputBytes);
	}

	// 4. Find EOF marker (Searching FORWARD in the BYTE array)
	let found = false;
	let eofByteIndex = 0;
	const eofLen = imgEOF.length; // 6 bytes

	for (let i = 0; i <= outputBytes.length - eofLen; i++) {
		let match = true;
		for (let l = 0; l < eofLen; l++) {
			if (outputBytes[i + l] !== imgEOF[l]) {
				match = false;
				break;
			}
		}
		if (match) {
			found = true;
			eofByteIndex = i;
			break;
		}
	}

	if (!found) {
		return ['', 'This image does not contain anything, or perhaps the password is wrong', 0];
	}

	// 5. Finalize results
	const actualDataBytes = outputBytes.subarray(0, eofByteIndex);

	// Calculate how many blocks were actually used (for the return index)
	const bitsUsed = (actualDataBytes.length + eofLen) * 8;
	const blocksUsed = Math.ceil(bitsUsed / k);

	return [actualDataBytes, 'Reveal successful', startIndex + (blocksUsed * n) + 3];
}

//extract text from either tye of image

function decodeImage(imageElement, password, callback, skipEncrypt, iter, password2, callback2, iter2) {
	return new Promise((resolve, reject) => {
		const imgType = imageElement.src.slice(11, 15); // e.g., "png;" or "jpeg"

		const wrapCallback = (cb, resolveKey) => {
			return (data, msg) => {
				if (cb) cb(data, msg);
				if (resolveKey) {
					resolve({ [resolveKey]: { data, message: msg } });
				} else {
					resolve({ primary: { data, message: msg } });
				}
			};
		};

		if (imgType === 'png;') {
			decodePNG(
				imageElement,
				password,
				wrapCallback(callback, 'primary'),
				skipEncrypt,
				iter,
				password2,
				wrapCallback(callback2, 'secondary'),
				iter2
			).then(result => {
				resolve(result);
			}).catch(reject);
		} else if (imgType === 'jpeg') {
			// Fallback to callback for now until decodeJPG is modernized
			decodeJPG(
				imageElement,
				password,
				wrapCallback(callback, 'primary'),
				skipEncrypt,
				iter,
				password2,
				wrapCallback(callback2, 'secondary'),
				iter2
			);
		} else {
			const err = new Error("Unsupported image type for decoding");
			if (callback) callback(null, err.message);
			reject(err);
		}
	});
}

//remove transparency and turn background white
function transparent2white(imageElement) {
	var shadowCanvas = document.createElement('canvas'),
		shadowCtx = shadowCanvas.getContext('2d');
	shadowCanvas.style.display = 'none';

	shadowCanvas.width = imageElement.naturalWidth;
	shadowCanvas.height = imageElement.naturalHeight;
	shadowCtx.drawImage(imageElement, 0, 0, shadowCanvas.width, shadowCanvas.height);

	var imageData = shadowCtx.getImageData(0, 0, shadowCanvas.width, shadowCanvas.height),
		opaquePixels = 0;
	for (var i = 3; i < imageData.data.length; i += 4) {				//look at alpha channel values
		if (imageData.data[i] == 0) {
			for (var j = 0; j < 4; j++) imageData.data[i - j] = 255		//turn pure transparent to white
		} else {
			imageData.data[i] = 255									//if not pure transparent, turn opaque without changing color
		}
	}
	shadowCtx.putImageData(imageData, 0, 0);								//put in canvas so the dataURL can be produced
	imageElement.src = shadowCanvas.toDataURL()							//send to image element	
}

/**
 * Get a single bit from a Uint8Array at the specified bit index.
 * Bits are indexed from MSB (bit 7) of byte 0 onwards.
 *
 * @param {Uint8Array} uint8Array - The byte array to read from
 * @param {number} bitIndex - Zero-based index of the bit to get
 * @returns {number} The bit value (0 or 1)
 */
function getBit(uint8Array, bitIndex) {
	const byteIndex = Math.floor(bitIndex / 8);
	const bitPosition = 7 - (bitIndex % 8); // MSB is bit 7
	return (uint8Array[byteIndex] >> bitPosition) & 1;
}

/**
 * Set a single bit in a Uint8Array at the specified bit index.
 * Modifies the array in place.
 *
 * @param {Uint8Array} uint8Array - The byte array to modify
 * @param {number} bitIndex - Zero-based index of the bit to set
 * @param {number} value - The bit value to set (0 or 1)
 */
function setBit(uint8Array, bitIndex, value) {
	const byteIndex = Math.floor(bitIndex / 8);
	const bitPosition = 7 - (bitIndex % 8); // MSB is bit 7
	if (value) {
		uint8Array[byteIndex] |= (1 << bitPosition);
	} else {
		uint8Array[byteIndex] &= ~(1 << bitPosition);
	}
}

/**
 * Get a sequence of bits as a new Uint8Array.
 *
 * @param {Uint8Array} source - Source byte array
 * @param {number} startBit - Starting bit index (inclusive)
 * @param {number} lengthInBits - Number of bits to extract
 * @returns {Uint8Array} New byte array containing the extracted bits (zero-padded at end if needed)
 */
function getBits(source, startBit, lengthInBits) {
	const outLength = Math.ceil(lengthInBits / 8);
	const result = new Uint8Array(outLength);
	for (let i = 0; i < lengthInBits; i++) {
		const bit = getBit(source, startBit + i);
		setBit(result, i, bit);
	}
	return result;
}

/**
 * Set a sequence of bits from a Uint8Array into another.
 *
 * @param {Uint8Array} dest - Destination byte array
 * @param {number} startBit - Starting bit index in destination
 * @param {Uint8Array} sourceBits - Source bits as a byte array
 * @param {number} lengthInBits - Number of bits to copy
 */
function setBits(dest, startBit, sourceBits, lengthInBits) {
	for (let i = 0; i < lengthInBits; i++) {
		const bit = getBit(sourceBits, i);
		setBit(dest, startBit + i, bit);
	}
}

/**
 * Converts a Uint8Array of bits (0s and 1s) into a Uint8Array of bytes.
 * Matches the MSB-first order used in getBit.
 * 
 * @param {Uint8Array} bits - Array of 0s and 1s
 * @returns {Uint8Array} Array of actual bytes
 */
function packBitsToBytes(bits) {
	// bits is a Uint8Array of 0s and 1s
	const byteCount = Math.floor(bits.length / 8);
	const bytes = new Uint8Array(byteCount);
	for (let i = 0; i < byteCount; i++) {
		let byte = 0;
		for (let j = 0; j < 8; j++) {
			if (bits[i * 8 + j]) {
				byte |= (1 << (7 - j)); // Must match the 7-j logic above
			}
		}
		bytes[i] = byte;
	}
	return bytes;
}

// Converts Uint8Array to legacy [1,0,1,...] format
function uint8ArrayToLegacyBits(uint8Array) {
	const bits = [];
	for (let i = 0; i < uint8Array.length; i++) {
		for (let j = 7; j >= 0; j--) {
			bits.push((uint8Array[i] >> j) & 1);
		}
	}
	return bits;
}

// Converts legacy [1,0,1,...] back to Uint8Array
function legacyBitsToUint8Array(bits) {
	const byteCount = Math.floor(bits.length / 8);
	const bytes = new Uint8Array(byteCount);
	for (let i = 0; i < byteCount; i++) {
		let b = 0;
		for (let j = 0; j < 8; j++) {
			if (bits[i * 8 + j]) b |= (1 << (7 - j));
		}
		bytes[i] = b;
	}
	return bytes;
}