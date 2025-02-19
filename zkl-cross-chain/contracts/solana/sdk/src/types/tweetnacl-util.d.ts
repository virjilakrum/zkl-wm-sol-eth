declare module 'tweetnacl-util' {
    export function encodeBase64(input: Uint8Array): string;
    export function decodeBase64(input: string): Uint8Array;
    export function encodeUTF8(input: Uint8Array): string;
    export function decodeUTF8(input: string): Uint8Array;
} 