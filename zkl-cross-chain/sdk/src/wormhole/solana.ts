import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair } from '@solana/web3.js';
import { VAA, CrossChainMessage } from '../index';

export interface WormholeMessageResult {
    encryptedMessage: Uint8Array;
    senderECKey: Uint8Array;
    sequence: number;
    emitterChain: number;
    emitterAddress: string;
}

export class WormholeSolana {
    public connection: Connection;
    private programId: PublicKey;
    private wormholeProgramId: PublicKey;
    private payer: Keypair;

    constructor(
        connection: Connection,
        programId: string,
        wormholeProgramId: string,
        payer: Keypair
    ) {
        this.connection = connection;
        this.programId = new PublicKey(programId);
        this.wormholeProgramId = new PublicKey(wormholeProgramId);
        this.payer = payer;
    }

    // Getter method for payer
    public getPayer(): Keypair {
        return this.payer;
    }

    async sendMessage(message: string): Promise<string> {
        const parsedMessage: CrossChainMessage = JSON.parse(message);
        
        const messageData = Buffer.from(JSON.stringify(parsedMessage));
        const instruction = new TransactionInstruction({
            programId: this.wormholeProgramId,
            keys: [
                { pubkey: this.programId, isSigner: false, isWritable: true }
            ],
            data: Buffer.concat([
                Buffer.from([0x01]), // Instruction index for publish
                messageData
            ])
        });

        const transaction = new Transaction().add(instruction);
        const { blockhash } = await this.connection.getRecentBlockhash();
        transaction.recentBlockhash = blockhash;
        transaction.feePayer = this.payer.publicKey;

        transaction.sign(this.payer);
        const rawTransaction = transaction.serialize();
        const txId = await this.connection.sendRawTransaction(rawTransaction);
        await this.connection.confirmTransaction(txId);

        return txId;
    }

    async receiveMessage(vaa: Buffer): Promise<WormholeMessageResult> {
        const instruction = new TransactionInstruction({
            programId: this.wormholeProgramId,
            keys: [
                { pubkey: this.programId, isSigner: false, isWritable: true }
            ],
            data: Buffer.concat([
                Buffer.from([0x02]), // Instruction index for verify
                vaa
            ])
        });

        const transaction = new Transaction().add(instruction);
        const { blockhash } = await this.connection.getRecentBlockhash();
        transaction.recentBlockhash = blockhash;
        transaction.feePayer = this.payer.publicKey;

        transaction.sign(this.payer);
        const rawTransaction = transaction.serialize();
        const txId = await this.connection.sendRawTransaction(rawTransaction);
        await this.connection.confirmTransaction(txId);

        const accountInfo = await this.connection.getAccountInfo(this.programId);
        if (!accountInfo?.data) {
            throw new Error('VAA verisi bulunamadı');
        }

        const parsedVAA = this.parseVAA(accountInfo.data);
        const message: CrossChainMessage = JSON.parse(Buffer.from(parsedVAA.payload).toString());

        return {
            encryptedMessage: Buffer.from(message.payload.ipfsHash, 'hex'),
            senderECKey: Buffer.from(message.sender, 'hex'),
            sequence: Number(parsedVAA.sequence),
            emitterChain: parsedVAA.emitterChain,
            emitterAddress: Buffer.from(parsedVAA.emitterAddress).toString('hex')
        };
    }

    async verifyVAA(vaa: Buffer): Promise<VAA> {
        const instruction = new TransactionInstruction({
            programId: this.wormholeProgramId,
            keys: [
                { pubkey: this.programId, isSigner: false, isWritable: false }
            ],
            data: Buffer.concat([
                Buffer.from([0x02]), // Instruction index for verify
                vaa
            ])
        });

        const transaction = new Transaction().add(instruction);
        const { blockhash } = await this.connection.getRecentBlockhash();
        transaction.recentBlockhash = blockhash;
        transaction.feePayer = this.payer.publicKey;

        transaction.sign(this.payer);
        const rawTransaction = transaction.serialize();
        const txId = await this.connection.sendRawTransaction(rawTransaction);
        await this.connection.confirmTransaction(txId);

        return this.parseVAA(vaa);
    }

    async registerECKey(
        wallet: any,
        publicKey: Uint8Array,
        signature: Uint8Array
    ): Promise<string> {
        const instruction = new TransactionInstruction({
            programId: this.programId,
            keys: [
                { pubkey: wallet.publicKey, isSigner: true, isWritable: true }
            ],
            data: Buffer.concat([
                Buffer.from([0x00]), // Instruction index for register
                publicKey,
                signature
            ])
        });

        const transaction = new Transaction().add(instruction);
        const { blockhash } = await this.connection.getRecentBlockhash();
        transaction.recentBlockhash = blockhash;
        transaction.feePayer = wallet.publicKey;

        const signedTx = await wallet.signTransaction(transaction);
        const rawTransaction = signedTx.serialize();
        const txId = await this.connection.sendRawTransaction(rawTransaction);
        await this.connection.confirmTransaction(txId);

        return txId;
    }

    private parseVAA(data: Buffer): VAA {
        let offset = 0;

        const version = data.readUInt8(offset);
        offset += 1;

        const guardianSetIndex = data.readUInt32BE(offset);
        offset += 4;

        const signatureCount = data.readUInt8(offset);
        offset += 1;

        const signatures = [];
        for (let i = 0; i < signatureCount; i++) {
            const guardianIndex = data.readUInt8(offset);
            offset += 1;

            const signature = data.slice(offset, offset + 65);
            offset += 65;

            signatures.push({
                guardianSetIndex: guardianIndex,
                signature
            });
        }

        const timestamp = data.readUInt32BE(offset);
        offset += 4;

        const nonce = data.readUInt32BE(offset);
        offset += 4;

        const emitterChain = data.readUInt16BE(offset);
        offset += 2;

        const emitterAddress = data.slice(offset, offset + 32);
        offset += 32;

        const sequence = data.readBigUInt64BE(offset);
        offset += 8;

        const consistencyLevel = data.readUInt8(offset);
        offset += 1;

        const payload = data.slice(offset);

        return {
            version,
            guardianSetIndex,
            signatures,
            timestamp,
            nonce,
            emitterChain,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        };
    }
} 