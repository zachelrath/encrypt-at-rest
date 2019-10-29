"use strict";

const crypto = require("crypto");
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
// uuid v4 implementation - https://gist.github.com/jed/982883
const uuidv4 = function b(a){return a?(a^Math.random()*16>>a/4).toString(16):([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,b)};

// A map of all possible master encryption keys to use,
// keyed by unique id
let keys = {};
// The encryption key to use for net-new encryption values
let currentKey;

/**
 * @public
 */
class Key {
	/**
	 * @constructor
	 * @param  {String} id - unique id for the key, defaults to a new v4 UUID
	 * @param  {String} value - base64 encoded key string
	 */
	constructor(id = uuidv4(), value = createKeyBuffer().toString("base64")) {
		if (keys[id]) {
			throw new Error("This key id has been previously used.");
		}
		this.id = id;
		this.value = value;
	}
	getId() {
		return this.id;
	}
	getValue() {
		return this.value;
	}
	/**
	 * Returns a buffer representation of the value
	 * @return {Buffer} [description]
	 */
	buffer() {
		return Buffer.from(this.value, "base64");
	}
	toString() {
		return JSON.stringify({
			id: this.id,
			value: this.value,
		});
	}
	/**
	 * Makes this the current key to use for net-new encryption events.
	 */
	makeCurrent() {
		currentKey = this;
	}
}

/**
 * @private
 * @param {String} keyId - unique id of a previously-loaded encryption key
 * @returns {Key} the matching Key
 * @throws {Error} if the specified key has not been loaded
 */
function getKey(keyId) {
	const key = keys[keyId];
	if (!key) {
		throw new Error("The specified encryption key id has not been loaded.");
	}
	return key;
}

/**
 * Returns the current encryption key which should be used
 * for net-new encryption events.
 * @private
 * @return {Key}
 */
function getCurrentEncryptionKey() {
	return currentKey;
}

/**
 * @public
 * @description Loads an encryption key available for use for encryption/decryption.
 * @param {Key|String} key - a Key instance, or serialized representation.
 * @returns {Key} the Key instance
 * @throws {Error} if the key has already been loaded into memory
 */
function loadKey(key) {
	let keyInstance;
	if (typeof key === "string") {
		let keyObject = JSON.parse(key);
		keyInstance = new Key(keyObject.id, keyObject.value);
	} else if (key instanceof Key) {
		keyInstance = key;
	}
	if (keys[keyInstance.getId()]) {
		throw new Error("This key has already been loaded.");
	}
	keys[keyInstance.getId()] = keyInstance;

	// Convenience: if there is no current key, make this the current one.
	if (!currentKey) currentKey = keyInstance;

	return keyInstance;
}

/**
 * @public
 * @param {String} value - clear text string of any length to be encrypted
 * @returns {String} base64-encoded encrypted hex string
 */
function encrypt(value) {
	const masterKey = getCurrentEncryptionKey();
	const masterKeyBuffer = masterKey.buffer();
	let iv = createKeyBuffer(12, masterKeyBuffer);
	let cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, masterKeyBuffer, iv);
	let encrypted = cipher.update(value, "utf8", "hex");
	encrypted += cipher.final("hex");
	return Buffer.from([
		// Embed id of the encryption key that was used
		Buffer.from(masterKey.getId()).toString("hex"),
		// Embed algorithm for decryption, to allow for algorithm to be modified in future
		Buffer.from(ENCRYPTION_ALGORITHM).toString("hex"),
		// Embed IV to allow for decryption
		iv.toString("hex"),
		cipher.getAuthTag().toString("hex"),
		encrypted,
	].join(":")).toString("base64");

}

/**
 * @public
 * @param {String} encryptedValue - base64-encoded, encrypted hex string
 * @returns {String} decrypted clear text string
 */
function decrypt(encryptedValue) {

	encryptedValue = Buffer.from(encryptedValue, "base64").toString("ascii");

	const encryptedArray = encryptedValue.split(":"),
		masterKeyId = Buffer.from(encryptedArray[0], "hex").toString(),
		algorithm = Buffer.from(encryptedArray[1], "hex").toString(),
		iv = Buffer.from(encryptedArray[2], "hex"),
		tag = Buffer.from(encryptedArray[3], "hex"),
		content = encryptedArray[4],
		decipher = crypto.createDecipheriv(algorithm, getKey(masterKeyId).buffer(), iv);

	decipher.setAuthTag(tag);
	let decryptedValue = decipher.update(content, "hex", "utf8");
	decryptedValue += decipher.final("utf8");
	return decryptedValue;
}

/**
 * Generates a Buffer of a desired byte length to be used as either an encryption key or an initialization vector.
 *
 * @private
 * @param {Integer} [numBytes = 32] - Optional, number of bytes to fill the Buffer with.
 * @param {String} [secret = <random bytes>] - Optional, a secret to use as a basis for the key generation algorithm.
 * @returns {Buffer}
 */
function createKeyBuffer(numBytes = 32, secret = crypto.randomBytes(128).toString("base64")) {
	return crypto.pbkdf2Sync(
		secret,
		crypto.randomBytes(128).toString(),
		// Random value, doesn't have to be high
		2412,
		numBytes,
		"sha512"
	);
}

/**
 * @public
 * @description Static alternative to "new Key()", creates a new Key.
 * @param {String} [id] - unique id for this key
 * @param {String} [value] - 32-byte key value
 * @return {Key}
 */
function createKey(id, value) {
	return new Key(id, value);
}

module.exports = {
	createKey,
	decrypt,
	encrypt,
	loadKey,
};