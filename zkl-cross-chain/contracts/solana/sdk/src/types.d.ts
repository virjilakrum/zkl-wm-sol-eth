declare module '@zklx/crypto' {
  export const zklCrypto: {
    encryptAES(data: Uint8Array, key: Buffer): Buffer;
    decryptAES(encryptedData: Buffer, key: Buffer): Buffer;
    generateEphemeralECIES(): { publicKey: Uint8Array, secretKey: Uint8Array };
    eciesEncrypt(plaintext: Buffer, recipientEdPubKey: Uint8Array, ephemeral?: { publicKey: Uint8Array, secretKey: Uint8Array }): { ciphertext: Buffer, ephemeralPublicKey: Uint8Array };
    eciesDecrypt(ciphertext: Buffer, ephemeralPublicKey: Uint8Array, recipientEdPrivKey: Uint8Array): Buffer;
    sha512(data: Buffer | Uint8Array): string;
  };
} 