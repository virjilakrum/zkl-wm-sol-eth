import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import secp256k1 from 'secp256k1';
import { Buffer } from 'buffer';
import { Connection, PublicKey } from '@solana/web3.js';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';

// Web Crypto API için tip tanımları
declare global {
    var window: Window | undefined;
    
    interface CryptoKey {
        type: string;
        extractable: boolean;
        algorithm: any;
        usages: string[];
    }
    
    interface Window {
        crypto: {
            subtle: {
                importKey(
                    format: string,
                    keyData: ArrayBuffer,
                    algorithm: { name: string },
                    extractable: boolean,
                    keyUsages: string[]
                ): Promise<CryptoKey>;
                deriveBits(
                    algorithm: { name: string; hash: string; salt: Uint8Array; info: Uint8Array },
                    key: CryptoKey,
                    length: number
                ): Promise<ArrayBuffer>;
                encrypt(
                    algorithm: { name: string; iv: Uint8Array; tagLength: number },
                    key: CryptoKey,
                    data: Uint8Array
                ): Promise<ArrayBuffer>;
                decrypt(
                    algorithm: { name: string; iv: Uint8Array; tagLength: number },
                    key: CryptoKey,
                    data: Uint8Array
                ): Promise<ArrayBuffer>;
            };
        };
    }
}

// Node.js ortamında crypto modülünü kullan
const cryptoModule = typeof window === 'undefined' ? require('crypto').webcrypto : window.crypto;

export interface KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export function generateKeyPair(): KeyPair {
  let privateKey: Buffer;
  do {
    privateKey = randomBytes(32);
  } while (!secp256k1.privateKeyVerify(privateKey));

  const publicKey = Buffer.from(secp256k1.publicKeyCreate(privateKey));
  return { publicKey, privateKey };
}

export function deriveSharedSecret(privateKey: Buffer, publicKey: Buffer): Buffer {
  const sharedSecret = secp256k1.ecdh(publicKey, privateKey);
  return createHash('sha256').update(sharedSecret).digest();
}

export function encrypt(data: Buffer, recipientPublicKey: Buffer): { 
  ciphertext: Buffer; 
  ephemeralPublicKey: Buffer;
} {
  // Geçici anahtar çifti oluştur
  const ephemeralKeyPair = generateKeyPair();
  
  // Paylaşılan gizli anahtarı türet
  const sharedSecret = deriveSharedSecret(
    ephemeralKeyPair.privateKey,
    recipientPublicKey
  );

  // IV oluştur
  const iv = randomBytes(16);

  // AES-256-GCM ile şifrele
  const cipher = createCipheriv('aes-256-gcm', sharedSecret, iv);
  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);

  // Kimlik doğrulama etiketini al
  const authTag = cipher.getAuthTag();

  // Şifrelenmiş veriyi, IV ve kimlik doğrulama etiketini birleştir
  const ciphertext = Buffer.concat([
    iv,
    encrypted,
    authTag
  ]);

  return {
    ciphertext,
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  };
}

export function decrypt(
  ciphertext: Buffer,
  ephemeralPublicKey: Buffer,
  recipientPrivateKey: Buffer
): Buffer {
  // Paylaşılan gizli anahtarı türet
  const sharedSecret = deriveSharedSecret(
    recipientPrivateKey,
    ephemeralPublicKey
  );

  // IV, şifrelenmiş veri ve kimlik doğrulama etiketini ayır
  const iv = ciphertext.slice(0, 16);
  const authTag = ciphertext.slice(-16);
  const encryptedData = ciphertext.slice(16, -16);

  // AES-256-GCM ile deşifre et
  const decipher = createDecipheriv('aes-256-gcm', sharedSecret, iv);
  decipher.setAuthTag(authTag);

  // Deşifre et ve sonucu döndür
  return Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);
}

export const zklCrypto = {
  generateKeyPair,
  encrypt,
  decrypt
};

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
            privateKey = randomBytes(32);
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
            ephemeralPrivateKey = randomBytes(32);
        } while (!secp256k1.privateKeyVerify(ephemeralPrivateKey));

        const ephemeralPublicKey = secp256k1.publicKeyCreate(ephemeralPrivateKey, true);

        // 3. ECDH ile paylaşılan gizli anahtarı hesapla
        const sharedSecret = secp256k1.ecdh(
            recipientPubKey,
            ephemeralPrivateKey,
            { hashfn: (x: Uint8Array, y: Uint8Array): Uint8Array => {
                const hash = createHash('sha256').update(Buffer.from([...x, ...y])).digest();
                return hash;
            }}
        );

        // 4. KDF ile şifreleme ve MAC anahtarlarını türet
        const { encryptionKey, macKey } = await this.deriveKeys(sharedSecret);

        // 5. Mesajı şifrele
        const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        const iv = randomBytes(12);
        const encryptedData = await this.aesGcmEncrypt(encryptionKey, iv, messageBytes);
        const { ciphertext, authTag } = encryptedData;

        // 6. MAC hesapla
        const macData = Buffer.concat([iv, ciphertext, authTag]);
        const mac = createHash('sha256').update(macData).digest();

        return {
            ephemeralPublicKey,
            encryptedMessage: Buffer.from(ciphertext),
            mac: Buffer.from(mac)
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
                const hash = createHash('sha256').update(Buffer.from([...x, ...y])).digest();
                return hash;
            }}
        );

        // 4. KDF ile şifreleme ve MAC anahtarlarını türet
        const { encryptionKey, macKey } = await this.deriveKeys(sharedSecret);

        // 5. MAC'i doğrula
        const { encryptedMessage, mac } = encryptedData;
        const calculatedMac = createHash('sha256').update(encryptedMessage).digest();

        if (!Buffer.from(calculatedMac).equals(Buffer.from(mac))) {
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

        const messageHash = createHash('sha256').update(Buffer.from(messageBytes)).digest();
        const signature = secp256k1.ecdsaSign(messageHash, privKey);
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
            const messageHash = createHash('sha256').update(Buffer.from(message)).digest();
            return secp256k1.ecdsaVerify(
                signature,
                messageHash,
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
        const salt = randomBytes(32);
        const info = new TextEncoder().encode('ECIES_Keys');
        
        const masterKey = await cryptoModule.subtle.importKey(
            'raw',
            secret,
            { name: 'HKDF' },
            false,
            ['deriveBits']
        );

        const derivedBits = await cryptoModule.subtle.deriveBits(
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

        const encryptionKey = await cryptoModule.subtle.importKey(
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

    private static async aesGcmEncrypt(
        key: CryptoKey,
        iv: Uint8Array,
        data: Uint8Array
    ): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
        const encrypted = await cryptoModule.subtle.encrypt(
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
        const decrypted = await cryptoModule.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            new Uint8Array([...ciphertext, ...authTag])
        );

        return new Uint8Array(decrypted);
    }

    public static compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
        return Buffer.from(a).equals(Buffer.from(b));
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