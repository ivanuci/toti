class Encoder {
    // Define constants for lengths used in crypto operations
    static SALT_LENGTH = 16;
    static IV_LENGTH = 12;
    static KEY_LENGTH = 32;

    constructor() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Web Crypto API not supported.");
        }
    }

    // Generate a cryptographically secure random salt
    generateSalt(length = Encoder.SALT_LENGTH) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // Encode Uint8Array to base64 string
    toBase64(bytes) {
        return btoa(String.fromCharCode(...bytes));
    }

    // Decode base64 string to Uint8Array
    fromBase64(str) {
        return new Uint8Array([...atob(str)].map(c => c.charCodeAt(0)));
    }

    // Derive a key from password and salt using Argon2id with default params
    async deriveKey(password, salt, options = {}) {
        const config = {
            pass: password,
            salt: salt,
            time: 65,
            mem: 65536,
            hashLen: Encoder.KEY_LENGTH,
            parallelism: 1,
            type: argon2.ArgonType.Argon2id,
            ...options
        };
        const result = await argon2.hash(config);
        return new Uint8Array(result.hash);
    }

    // Encrypt plaintext data using AES-GCM with given key
    async encryptData(data, key) {
        const iv = crypto.getRandomValues(new Uint8Array(Encoder.IV_LENGTH));
        const encoded = new TextEncoder().encode(data);
        const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);
        return this._concatArrays(iv, new Uint8Array(encrypted));
    }

    // Encrypt text with password; returns base64 encoded string of (salt + iv + ciphertext)
    async encryptText(text, password) {
        const salt = this.generateSalt();
        const key = await this.deriveKey(password, salt);
        const encrypted = await this.encryptData(text, key);
        const combined = this._concatArrays(salt, encrypted);
        this.wipeArray(salt);
        this.wipeArray(key);
        this.wipeArray(encrypted);
        return this.toBase64(combined);
    }

    // Decrypt ciphertext using AES-GCM with given key
    async decryptData(encrypted, key) {
        const iv = encrypted.slice(0, Encoder.IV_LENGTH);
        const ciphertext = encrypted.slice(Encoder.IV_LENGTH);
        const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext);
        // Note: cryptoKey cannot be wiped directly due to Web Crypto API limitations
        return new TextDecoder().decode(decrypted);
    }

    // Decrypt base64 encoded string using password; returns plaintext or throws on failure
    async decryptText(encodedText, password) {
        const data = this.fromBase64(encodedText);
        const salt = data.slice(0, Encoder.SALT_LENGTH);
        const encrypted = data.slice(Encoder.SALT_LENGTH);
        const key = await this.deriveKey(password, salt);
        try {
            const decrypted = await this.decryptData(encrypted, key);
            this.wipeArray(salt);
            this.wipeArray(key);
            this.wipeArray(encrypted);
            return decrypted;
        } catch (e) {
            // Log error and rethrow for caller to handle
            console.error("Decryption failed:", e);
            throw new Error("Decryption failed. Invalid password or corrupted data.");
        }
    }

    // Securely wipe contents of Uint8Array
    wipeArray(arr) {
        if (arr instanceof Uint8Array) {
            arr.fill(0);
        }
    }

    // Helper to concatenate multiple Uint8Arrays into one
    _concatArrays(...arrays) {
        let totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        let result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }
}
