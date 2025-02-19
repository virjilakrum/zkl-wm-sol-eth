declare module 'tweetnacl' {
    export function randomBytes(length: number): Uint8Array;
    export const box: {
        keyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
        before(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
        after(sharedKey: Uint8Array): Uint8Array;
        open(
            encrypted: Uint8Array,
            nonce: Uint8Array,
            publicKey: Uint8Array,
            secretKey: Uint8Array
        ): Uint8Array | null;
    };
    export const secretbox: {
        open(
            encrypted: Uint8Array,
            nonce: Uint8Array,
            key: Uint8Array
        ): Uint8Array | null;
    };
} 