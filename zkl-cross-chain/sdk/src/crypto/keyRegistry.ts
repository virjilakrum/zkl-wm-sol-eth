import { 
    Connection, 
    TransactionInstruction, 
    PublicKey, 
    Transaction, 
    sendAndConfirmTransaction 
} from '@solana/web3.js';
import { ECIES, ECKeyPair } from './ecies';

export interface KeyPair {
    publicKey: string;
    privateKey: string;
}

export class KeyRegistry {
    private static instance: KeyRegistry;
    private _keys: Map<string, KeyPair>;
    public programId: PublicKey;
    public connection: Connection;

    private constructor(programId: string, connection: Connection) {
        this._keys = new Map();
        this.programId = new PublicKey(programId);
        this.connection = connection;
    }

    public static getInstance(programId?: string, connection?: Connection): KeyRegistry {
        if (!KeyRegistry.instance) {
            if (!programId || !connection) {
                throw new Error('Initial call must provide programId and connection');
            }
            KeyRegistry.instance = new KeyRegistry(programId, connection);
        }
        return KeyRegistry.instance;
    }

    public registerKey(id: string, keyPair: KeyPair): void {
        this._keys.set(id, keyPair);
    }

    public getKey(id: string): KeyPair | undefined {
        return this._keys.get(id);
    }

    private async signMessage(message: string, privateKey: Uint8Array): Promise<Uint8Array> {
        return ECIES.signMessage(Buffer.from(message), privateKey);
    }

    public async linkSolanaAddress(
        solanaPubkey: string,
        ecKeyPair: ECKeyPair,
        solanaSigner: any
    ): Promise<string> {
        const message = `Linking EC address ${ecKeyPair.publicKey} to ${solanaPubkey} with index 0`;
        const signature = await this.signMessage(message, ecKeyPair.privateKey);
        
        const instruction = new TransactionInstruction({
            keys: [
                { pubkey: new PublicKey(solanaPubkey), isSigner: true, isWritable: false },
            ],
            programId: this.programId,
            data: Buffer.from([...signature, ...ecKeyPair.publicKey]),
        });

        const transaction = new Transaction().add(instruction);
        return await sendAndConfirmTransaction(this.connection, transaction, [solanaSigner]);
    }

    public get keys(): Map<string, KeyPair> {
        return this._keys;
    }

    private findKeyPairByPublicKey(publicKey: string): KeyPair | undefined {
        for (const [id, keyPair] of this._keys) {
            if (keyPair.publicKey === publicKey) {
                return keyPair;
            }
        }
        return undefined;
    }
} 