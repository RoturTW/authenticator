window.CryptoUtils = {
    async deriveKey(passcode, saltHex, iterations) {
        const encoder = new TextEncoder();
        const saltBytes = this.hexToBytes(saltHex);

        const passcodeKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(passcode),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: iterations || 100000,
                hash: 'SHA-256'
            },
            passcodeKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        return key;
    },

    async encrypt(data, key) {
        const encoder = new TextEncoder();
        const nonce = crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            encoder.encode(JSON.stringify(data))
        );

        return {
            nonce: this.bytesToHex(nonce),
            ciphertext: this.bytesToHex(new Uint8Array(encrypted))
        };
    },

    async decrypt(encryptedData, key) {
        const nonce = this.hexToBytes(encryptedData.nonce);
        const ciphertext = this.hexToBytes(encryptedData.ciphertext);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decrypted));
    },

    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    },

    async hashKey(key) {
        const encoder = new TextEncoder();
        const hash = await crypto.subtle.digest('SHA-256', encoder.encode(key));
        return this.bytesToHex(new Uint8Array(hash));
    }
};
