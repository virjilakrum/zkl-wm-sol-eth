import * as secp256k1 from 'secp256k1';
import { webcrypto } from 'node:crypto';
import * as nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';
import { Buffer } from 'node:buffer';
import { Connection, PublicKey } from '@solana/web3.js';

const crypto = webcrypto as any;

export interface ECKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface EncryptedData {
    ephemeralPublicKey: Uint8Array;
    encryptedMessage: Uint8Array;
    mac: Uint8Array;
}

export class ECIES {
    public static programId = 'Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS';

    static async generateKeyPair(): Promise<ECKeyPair> {
        // secp256k1 anahtar çifti oluştur
        let privateKey: Uint8Array;
        do {
            privateKey = nacl.randomBytes(32);
        } while (!secp256k1.privateKeyVerify(privateKey));

        const publicKey = secp256k1.publicKeyCreate(privateKey, true);
        
        return {
            publicKey,
            privateKey
        };
    }

    static async encrypt(
        publicKey: Uint8Array | string,
        message: string | Uint8Array
    ): Promise<EncryptedData> {
        // Public key'i Uint8Array'e çevir
        const recipientPubKey = typeof publicKey === 'string' 
            ? Uint8Array.from(Buffer.from(publicKey.replace('0x', ''), 'hex'))
            : publicKey;
        
        // 1. Efemeral anahtar çifti oluştur
        let ephemeralPrivateKey: Uint8Array;
        do {
            ephemeralPrivateKey = nacl.randomBytes(32);
        } while (!secp256k1.privateKeyVerify(ephemeralPrivateKey));

        const ephemeralPublicKey = secp256k1.publicKeyCreate(ephemeralPrivateKey, true);

        // 3. ECDH ile paylaşılan gizli anahtarı hesapla
        const sharedSecret = secp256k1.ecdh(
            recipientPubKey,
            ephemeralPrivateKey,
            { hashfn: (x: Uint8Array, y: Uint8Array): Uint8Array => {
                const hash = new Uint8Array(32);
                crypto.subtle.digest('SHA-256', new Uint8Array([...x, ...y]))
                    .then((h: ArrayBuffer) => hash.set(new Uint8Array(h)));
                return hash;
            }}
        );

        // 4. KDF ile şifreleme ve MAC anahtarlarını türet
        const { encryptionKey, macKey } = await this.deriveKeys(sharedSecret);

        // 5. Mesajı şifrele
        const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        const iv = nacl.randomBytes(12);
        const encryptedData = await this.aesGcmEncrypt(encryptionKey, iv, messageBytes);
        const { ciphertext, authTag } = encryptedData;

        // 6. MAC hesapla
        const macData = new Uint8Array([...iv, ...ciphertext, ...authTag]);
        const mac = await crypto.subtle.sign(
            { name: 'HMAC', hash: 'SHA-256' },
            await this.importMacKey(macKey),
            macData
        );

        return {
            ephemeralPublicKey,
            encryptedMessage: new Uint8Array([...iv, ...ciphertext, ...authTag]),
            mac: new Uint8Array(mac)
        };
    }

    static async decrypt(
        privateKey: string | Uint8Array,
        encryptedData: EncryptedData
    ): Promise<Uint8Array> {
        // 1. Private key'i doğrula
        const privKey = typeof privateKey === 'string'
            ? Uint8Array.from(Buffer.from(privateKey.replace('0x', ''), 'hex'))
            : privateKey;

        if (!secp256k1.privateKeyVerify(privKey)) {
            throw new Error('Geçersiz private key');
        }

        // 2. Ephemeral public key'i doğrula
        if (!secp256k1.publicKeyVerify(encryptedData.ephemeralPublicKey)) {
            throw new Error('Geçersiz ephemeral public key');
        }

        // 3. ECDH ile paylaşılan gizli anahtarı hesapla
        const sharedSecret = secp256k1.ecdh(
            encryptedData.ephemeralPublicKey,
            privKey,
            { hashfn: (x: Uint8Array, y: Uint8Array): Uint8Array => {
                const hash = new Uint8Array(32);
                crypto.subtle.digest('SHA-256', new Uint8Array([...x, ...y]))
                    .then((h: ArrayBuffer) => hash.set(new Uint8Array(h)));
                return hash;
            }}
        );

        // 4. KDF ile şifreleme ve MAC anahtarlarını türet
        const { encryptionKey, macKey } = await this.deriveKeys(sharedSecret);

        // 5. MAC'i doğrula
        const { encryptedMessage, mac } = encryptedData;
        const calculatedMac = await crypto.subtle.sign(
            { name: 'HMAC', hash: 'SHA-256' },
            await this.importMacKey(macKey),
            encryptedMessage
        );

        if (!this.compareUint8Arrays(new Uint8Array(calculatedMac), mac)) {
            throw new Error('Geçersiz MAC - mesaj değiştirilmiş olabilir');
        }

        // 6. Mesajı çöz
        const iv = encryptedMessage.slice(0, 12);
        const authTag = encryptedMessage.slice(-16);
        const ciphertext = encryptedMessage.slice(12, -16);

        return await this.aesGcmDecrypt(encryptionKey, iv, ciphertext, authTag);
    }

    static async signMessage(
        message: string | Uint8Array,
        privateKey: string | Uint8Array
    ): Promise<Uint8Array> {
        // Private key'i doğru formata çevir
        const privKey = typeof privateKey === 'string'
            ? Uint8Array.from(Buffer.from(privateKey.replace('0x', ''), 'hex'))
            : privateKey;

        if (!secp256k1.privateKeyVerify(privKey)) {
            throw new Error('Geçersiz private key');
        }

        // Mesajı doğru formata çevir
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        const messageHash = await crypto.subtle.digest('SHA-256', messageBytes);
        const signature = secp256k1.ecdsaSign(new Uint8Array(messageHash), privKey);
        return signature.signature;
    }

    static async verifySignature(
        message: Uint8Array,
        signature: Uint8Array,
        publicKey: Uint8Array
    ): Promise<boolean> {
        if (!secp256k1.publicKeyVerify(publicKey)) {
            throw new Error('Geçersiz public key');
        }

        try {
            const messageHash = await crypto.subtle.digest('SHA-256', message);
            return secp256k1.ecdsaVerify(
                signature,
                new Uint8Array(messageHash),
                publicKey
            );
        } catch (error) {
            return false;
        }
    }

    // Yardımcı metodlar
    private static async deriveKeys(secret: Uint8Array): Promise<{
        encryptionKey: CryptoKey;
        macKey: Uint8Array;
    }> {
        const salt = nacl.randomBytes(32);
        const info = new TextEncoder().encode('ECIES_Keys');
        
        const masterKey = await crypto.subtle.importKey(
            'raw',
            secret,
            { name: 'HKDF' },
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-512',
                salt,
                info
            },
            masterKey,
            512
        );

        const derivedBytes = new Uint8Array(derivedBits);
        const encryptionKeyBytes = derivedBytes.slice(0, 32);
        const macKeyBytes = derivedBytes.slice(32);

        const encryptionKey = await crypto.subtle.importKey(
            'raw',
            encryptionKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        return {
            encryptionKey,
            macKey: macKeyBytes
        };
    }

    private static async importMacKey(keyData: Uint8Array): Promise<CryptoKey> {
        return await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify']
        );
    }

    private static async aesGcmEncrypt(
        key: CryptoKey,
        iv: Uint8Array,
        data: Uint8Array
    ): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            data
        );

        const ciphertext = new Uint8Array(encrypted);
        return {
            ciphertext: ciphertext.slice(0, -16),
            authTag: ciphertext.slice(-16)
        };
    }

    private static async aesGcmDecrypt(
        key: CryptoKey,
        iv: Uint8Array,
        ciphertext: Uint8Array,
        authTag: Uint8Array
    ): Promise<Uint8Array> {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            new Uint8Array([...ciphertext, ...authTag])
        );

        return new Uint8Array(decrypted);
    }

    private static compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        return a.every((val, i) => val === b[i]);
    }

    static encodeBase64(data: Uint8Array): string {
        return encodeBase64(data);
    }

    static decodeBase64(base64: string): Uint8Array {
        return decodeBase64(base64);
    }

    static async encryptToSolana(
        recipientSolanaPubkey: string,
        message: string | Uint8Array,
        solanaRpcUrl: string
    ): Promise<EncryptedData> {
        // 2. PublicKey oluştururken validasyon ekleyin
        try {
            new PublicKey(recipientSolanaPubkey);
        } catch (e) {
            throw new Error('Geçersiz Solana public key: ' + recipientSolanaPubkey);
        }

        const connection = new Connection(solanaRpcUrl);
        const ecPubkey = await this.getECPubkeyFromSolana(recipientSolanaPubkey, connection);
        return this.encrypt(ecPubkey, message);
    }

    public static async getECPubkeyFromSolana(
        solanaPubkey: string,
        connection: Connection
    ): Promise<Uint8Array> {
        const [pdaAddress] = PublicKey.findProgramAddressSync(
            [Buffer.from("key_registry"), new PublicKey(solanaPubkey).toBuffer()],
            new PublicKey(this.programId)
        );

        const pda = await connection.getAccountInfo(pdaAddress);
        if (!pda?.data) {
            throw new Error('EC public key not found for Solana address: ' + solanaPubkey);
        }

        return new Uint8Array(pda.data.slice(0, 33));
    }
} 