# encrypt-at-rest

Simple, secure, forward-proof encryption at rest for Node using AES 256 GCM, with support for multiple master encryption keys.

```javascript
let encrypted = encrypt("something"); // returns base64 string
decrypt(encrypted); // "something"
```

# Approach

- Secure: Uses AES 256 GCM (Galois Counter Mode) algorithm for encryption, an authenticated encryption mechanism, with a unique initialization vector (IV) for each encrypted value.

- Forward-proof: Each encrypted value contains all information needed to decrypt the value. The encryption key id, algorithm, IV, and authentication tag are all stored along with the encrypted value, so that `decrypt()` is able to work with multiple encryption keys.

- Simple: Both `encrypt()` / `decrypt()` only take one argument, making the library extremely simple to use.

# Installation

```bash
npm i 
```

# Usage

This master key will need to be populated on application startup using `setEncryptionKey(base64EncodedMasterKey)`. The master key must be 32 bytes in length.

## Create a master encryption key

```bash
npm run generate-encryption-key

{"id":"ee518f7a-d297-4130-9b71-c1b36e6de793","value":"poKsapwI6vBAA+gQdFrxbOauEL6yxYXjCmUPxtxdQ6k="}

```

## Load a key into memory on application startup

```javascript
const {
	loadKey,
} = require("encrypt-at-rest");

// example: the serialized encryption key is loaded via an environment variable
loadKey(process.env.MASTER_ENCRYPTION_KEY);

```

## Use the key to encrypt/decrypt values

```javascript
const {
	decrypt,
	encrypt,
} = require("encrypt-at-rest");
const {
	strictEqual,
} = require("assert");

// Encrypt a value, e.g. before storing in database
const inputValue = "some valuable piece of information";
const encryptedValue = encrypt(inputValue);

// Decrypt a value, e.g. when pulling out of database
strictEqual(inputValue, decrypt(encryptedValue));

```

## Load multiple keys, e.g. from KMS

```javascript
const {
	createKey,
	loadKey,
} = require("encrypt-at-rest");

// example: the serialized encryption key is loaded via an environment variable
let allKeys = await keysTable.fetchAll();
allKeys.forEach(keyRow => {
	const key = loadKey(createKey(keyRow.get("id"), keyRow.get("value"));
	if (keyRow.get("is_current")) {
		key.markCurrent();
	}
});

# Contributing

This repo intentionally has no dependencies to keep it as lightweight as possible, including dev dependencies. `npm i eslint -g` to lint. Tests are written using native node assertions.
