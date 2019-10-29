const {
	createKey,
	encrypt,
	decrypt,
	loadKey,
} = require(".");
const {
	ok,
	strictEqual,
} = require("assert");

const allEncryptedValues = [];

function runTests() {
	[
		"cheese:crackers",
		"asdjfasjdf2798q2397(*&(*&98q723984798980&()",
		"the quick brown fox jumped over the lazy brown dog",
	].forEach(t => {
		let encryptedValue = encrypt(t);
		ok(!encryptedValue.includes(t), "encrypted value should NOT contain our string");
		strictEqual(t, decrypt(encryptedValue), "verify encrypt/decrypt round trip");
		allEncryptedValues.push({
			encrypted: encryptedValue,
			original: t,
		});
	});
}

// Create an initial encryption key to use, and make it the current key
loadKey(createKey());

// Encrypt and decrypt some values using the key
runTests();

// Create a new key and switch to using that for new encryption.
// Simulate loading the key from a serialized representation, e.g. an environment variable,
// and making it the new key to be used.
loadKey(createKey().toString()).makeCurrent();

runTests();

// Verify that for all encrypted values, they are still decryptable
allEncryptedValues.forEach(({
	encrypted,
	original,
}) => {
	strictEqual(original, decrypt(encrypted), "verify value can still be decrypted even using previous key");
});