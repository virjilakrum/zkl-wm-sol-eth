export * from './crypto/ecies';
export * from './crypto/keyRegistry';
export * from './wormhole/eth';
export * from './wormhole/solana';
export * from './storage/ipfs';

import { ethers } from 'ethers';
import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair, VersionedTransaction, TransactionMessage } from '@solana/web3.js';
import { WormholeEth } from './wormhole/eth';
import { WormholeSolana, WormholeMessageResult } from './wormhole/solana';
import { ECIES, ECKeyPair, EncryptedData } from './crypto/ecies';
import { KeyRegistry, KeyPair } from './crypto/keyRegistry';
import { IPFSStorage, IPFSMetadata } from './storage/ipfs';
import * as argon2 from 'argon2-browser';
import { Buffer } from 'buffer';

declare module 'argon2-browser' {
    export interface ArgonHashOptions {
        pass: string;
        salt: Uint8Array;
        type: ArgonType;
        hashLen: number;
    }
    
    export enum ArgonType {
        Argon2d = 0,
        Argon2i = 1,
        Argon2id = 2
    }

    export function hash(options: ArgonHashOptions): Promise<{ hash: Uint8Array }>;
}

export interface FileTransferOptions {
    filename?: string;
    mimeType?: string;
    encrypt?: boolean;
    pin?: boolean;
}

export interface VAA {
    version: number;
    guardianSetIndex: number;
    signatures: {
        guardianSetIndex: number;
        signature: Uint8Array;
    }[];
    timestamp: number;
    nonce: number;
    emitterChain: number;
    emitterAddress: Uint8Array;
    sequence: bigint;
    consistencyLevel: number;
    payload: Uint8Array;
}

export interface CrossChainMessage {
    sender: string;
    recipient: string;
    payload: {
        ipfsHash: string;
        ephemeralPubkey: string;
        mac: string;
        timestamp: number;
    };
    signature: string;
}

export class CrossChainSDK {
    private static instance: CrossChainSDK;
    private ethClient?: WormholeEth;
    private solanaClient?: WormholeSolana;
    private keyRegistry: KeyRegistry;
    private ipfs: IPFSStorage;

    private constructor() {
        this.keyRegistry = KeyRegistry.getInstance();
        this.ipfs = new IPFSStorage();
    }

    public static getInstance(): CrossChainSDK {
        if (!CrossChainSDK.instance) {
            CrossChainSDK.instance = new CrossChainSDK();
        }
        return CrossChainSDK.instance;
    }

    // IPFS endpoint'ini ayarla
    public setIPFSEndpoint(url: string): void {
        this.ipfs = new IPFSStorage(url);
    }

    // Ethereum istemcisini başlat
    public initializeEthereum(
        provider: ethers.providers.Provider,
        contractAddress: string,
        abi: ethers.ContractInterface,
        signer: ethers.Signer
    ): void {
        this.ethClient = new WormholeEth(provider, contractAddress, abi, signer);
    }

    // Solana istemcisini başlat
    public initializeSolana(
        connection: Connection,
        programId: string,
        wormholeProgramId: string,
        payer: Keypair
    ): void {
        this.solanaClient = new WormholeSolana(
            connection,
            programId,
            wormholeProgramId,
            payer
        );
    }

    // EC anahtar çifti oluştur ve kaydet
    public async generateAndRegisterECKeyPair(
        id: string,
        chain: 'ethereum' | 'solana',
        wallet: any,
        password: string
    ): Promise<ECKeyPair> {
        const keyPair = await ECIES.generateKeyPair();
        const encryptedPrivateKey = await this.encryptPrivateKey(keyPair.privateKey, password);
        
        const message = Buffer.from(
            `Register EC public key: ${Buffer.from(keyPair.publicKey).toString('hex')}`
        );
        const signature = await ECIES.signMessage(message, keyPair.privateKey);
        
        if (chain === 'ethereum' && this.ethClient) {
            const tx = await this.ethClient.registerECKey(
                Buffer.from(keyPair.publicKey).toString('hex'),
                Buffer.from(signature).toString('hex')
            );
            await tx.wait();
        } else if (chain === 'solana' && this.solanaClient) {
            await this.solanaClient.registerECKey(
                wallet,
                keyPair.publicKey,
                signature
            );
        } else {
            throw new Error('Chain not initialized');
        }

        const localKeyPair: KeyPair = {
            publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
            privateKey: encryptedPrivateKey
        };
        this.keyRegistry.registerKey(id, localKeyPair);
        
        return keyPair;
    }

    // Public methods for accessing private properties safely
    public async getEthereumSigner(): Promise<ethers.Signer> {
        if (!this.ethClient) {
            throw new Error('Ethereum client not initialized');
        }
        return this.ethClient.getSigner();
    }

    public async getEthereumConnection(): Promise<{
        provider: ethers.providers.Provider;
        contract: ethers.Contract;
    }> {
        if (!this.ethClient) {
            throw new Error('Ethereum client not initialized');
        }
        return {
            provider: this.ethClient.getProvider(),
            contract: this.ethClient.getContract()
        };
    }

    public async getSolanaPayer(): Promise<Keypair> {
        if (!this.solanaClient) {
            throw new Error('Solana client not initialized');
        }
        return this.solanaClient.getPayer();
    }

    public async sendFile(
        fromChain: 'ethereum' | 'solana',
        toChain: 'ethereum' | 'solana',
        recipientId: string,
        file: Buffer,
        options: FileTransferOptions = {}
    ): Promise<SendFileResult> {
        const recipientKey = this.keyRegistry.getKey(recipientId);
        if (!recipientKey) {
            throw new Error('Recipient key not found');
        }

        const ipfsMetadata = await this.ipfs.uploadFile(file, {
            filename: options.filename,
            mimeType: options.mimeType
        });

        let txSignature: string;
        if (fromChain === 'ethereum' && this.ethClient) {
            txSignature = await this.ethClient.sendMessage(
                recipientKey.publicKey,
                Buffer.from(JSON.stringify({ ipfsHash: ipfsMetadata.ipfsHash })).toString('hex'),
                toChain === 'solana' ? 1 : 2
            );
        } else if (fromChain === 'solana' && this.solanaClient) {
            txSignature = await this.solanaClient.sendMessage(
                JSON.stringify({ ipfsHash: ipfsMetadata.ipfsHash })
            );
        } else {
            throw new Error('Chain not initialized');
        }

        return {
            messageId: txSignature,
            metadata: {
                ipfsHash: ipfsMetadata.ipfsHash,
                txSignature
            }
        };
    }

    // Receive file
    public async receiveFile(
        chain: 'ethereum' | 'solana',
        vaa: string,
        password: string
    ): Promise<{
        data: Buffer;
        metadata: IPFSMetadata;
    }> {
        let message: CrossChainMessage;
        let encryptedMetadata: Uint8Array;

        if (chain === 'ethereum' && this.ethClient) {
            const result = await this.ethClient.receiveMessage(vaa);
            message = JSON.parse(Buffer.from(result.message, 'hex').toString());
            encryptedMetadata = Buffer.from(message.payload.ipfsHash, 'hex');
        } else if (chain === 'solana' && this.solanaClient) {
            const result = await this.solanaClient.receiveMessage(Buffer.from(vaa, 'hex'));
            message = JSON.parse(Buffer.from(result.encryptedMessage).toString());
            encryptedMetadata = result.encryptedMessage;
        } else {
            throw new Error('Chain not initialized');
        }

        const keyPair = this.findKeyPairByPublicKey(message.recipient);
        if (!keyPair) {
            throw new Error('Decryption key not found');
        }

        const privateKey = await this.decryptPrivateKey(keyPair.privateKey, password);

        const decryptedMetadata = await ECIES.decrypt(privateKey, {
            ephemeralPublicKey: Buffer.from(message.payload.ephemeralPubkey, 'hex'),
            encryptedMessage: encryptedMetadata,
            mac: Buffer.from(message.payload.mac, 'hex')
        });

        const metadata: IPFSMetadata = JSON.parse(decryptedMetadata.toString());
        const fileData = await this.ipfs.downloadFile(metadata.ipfsHash);

        return {
            data: fileData,
            metadata
        };
    }

    // Private key şifreleme/çözme
    private async encryptPrivateKey(privateKey: Uint8Array, password: string): Promise<string> {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await argon2.hash({
            pass: password,
            salt,
            type: argon2.ArgonType.Argon2id,
            hashLen: 32
        });
        
        const encrypted = await ECIES.encrypt(key.hash, privateKey);
        return Buffer.concat([
            salt,
            encrypted.encryptedMessage,
            encrypted.mac
        ]).toString('base64');
    }

    private async decryptPrivateKey(encryptedKey: string, password: string): Promise<Buffer> {
        const data = Buffer.from(encryptedKey, 'base64');
        const salt = data.slice(0, 16);
        const encryptedData = data.slice(16, -32);
        const mac = data.slice(-32);

        const key = await argon2.hash({
            pass: password,
            salt,
            type: argon2.ArgonType.Argon2id,
            hashLen: 32
        });

        const decrypted = await ECIES.decrypt(key.hash, {
            ephemeralPublicKey: new Uint8Array(),
            encryptedMessage: encryptedData,
            mac
        });

        return Buffer.from(decrypted);
    }

    private findKeyPairByPublicKey(publicKey: string): KeyPair | undefined {
        for (const [_, keyPair] of this.keyRegistry.keys) {
            if (keyPair.publicKey === publicKey) {
                return keyPair;
            }
        }
        return undefined;
    }

    public async sendEncryptedFile(
        file: Buffer,
        recipientSolanaPubkey: string,
        options?: FileTransferOptions
    ): Promise<IPFSMetadata> {
        if (!this.solanaClient) {
            throw new Error('Solana client not initialized');
        }

        const ecPubkey = await this.getECPubkey(recipientSolanaPubkey);
        const encrypted = await ECIES.encrypt(ecPubkey, file);
        
        const bufferData = Buffer.from(encrypted.encryptedMessage);
        const metadata = await this.ipfs.uploadFile(bufferData, {
            filename: options?.filename,
            mimeType: options?.mimeType
        });
        
        const message: CrossChainMessage = {
            sender: '',
            recipient: recipientSolanaPubkey,
            payload: {
                ipfsHash: metadata.ipfsHash,
                ephemeralPubkey: Buffer.from(encrypted.ephemeralPublicKey).toString('hex'),
                mac: Buffer.from(encrypted.mac).toString('hex'),
                timestamp: Date.now()
            },
            signature: ''
        };

        await this.solanaClient.sendMessage(JSON.stringify(message));
        
        return metadata;
    }

    private async getECPubkey(solanaPubkey: string): Promise<Uint8Array> {
        if (!this.solanaClient) {
            throw new Error('Solana client not initialized');
        }

        const pubkey = new PublicKey(solanaPubkey);
        const keyPair = this.keyRegistry.getKey(solanaPubkey);
        if (!keyPair) {
            throw new Error('EC key not found for Solana address');
        }
        return Buffer.from(keyPair.publicKey, 'hex');
    }
}

// SDK Usage Example
async function initializeSDK(): Promise<CrossChainSDK> {
    const sdk = CrossChainSDK.getInstance();

    // Load environment variables
    const {
        ETH_RPC_URL,
        PRIVATE_KEY,
        ETH_CONTRACT_ADDRESS,
        SOLANA_RPC_URL,
        SOLANA_PRIVATE_KEY,
        SOLANA_PROGRAM_ID,
        WORMHOLE_PROGRAM_ID,
        IPFS_ENDPOINT
    } = process.env;

    // Validate required environment variables
    if (!ETH_RPC_URL || !PRIVATE_KEY || !ETH_CONTRACT_ADDRESS) {
        throw new Error('Missing required Ethereum configuration');
    }

    if (!SOLANA_RPC_URL || !SOLANA_PRIVATE_KEY || !SOLANA_PROGRAM_ID || !WORMHOLE_PROGRAM_ID) {
        throw new Error('Missing required Solana configuration');
    }

    // Initialize Ethereum client
    const provider = new ethers.providers.JsonRpcProvider(ETH_RPC_URL);
    const signer = new ethers.Wallet(PRIVATE_KEY, provider);
    
    const CrossChainMessagingArtifact = require('../artifacts/contracts/CrossChainMessaging.sol/CrossChainMessaging.json');
    
    sdk.initializeEthereum(
        provider,
        ETH_CONTRACT_ADDRESS,
        CrossChainMessagingArtifact.abi,
        signer
    );

    // Initialize Solana client
    const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
    const payer = Keypair.fromSecretKey(
        Buffer.from(SOLANA_PRIVATE_KEY, 'hex')
    );
    
    sdk.initializeSolana(
        connection,
        SOLANA_PROGRAM_ID,
        WORMHOLE_PROGRAM_ID,
        payer
    );

    // Initialize IPFS client
    if (IPFS_ENDPOINT) {
        sdk.setIPFSEndpoint(IPFS_ENDPOINT);
    }

    return sdk;
}

interface SendFileResult {
    messageId: string;
    metadata: {
        ipfsHash: string;
        txSignature: string;
    };
}

// Example: Send a cross-chain message with file
async function sendCrossChainMessage(
    senderKeyId: string,
    recipientKeyId: string,
    file: Buffer,
    options: FileTransferOptions = {}
): Promise<{ txId: string; ipfsHash: string }> {
    try {
        const sdk = await initializeSDK();
        
        // Generate and register EC key pair if not already registered
        const keyRegistry = KeyRegistry.getInstance();
        let senderKeyPair = keyRegistry.getKey(senderKeyId);
        
        if (!senderKeyPair) {
            console.log('Generating new EC key pair for sender...');
            const ethSigner = await sdk.getEthereumSigner();
            await sdk.generateAndRegisterECKeyPair(
                senderKeyId,
                'ethereum',
                ethSigner,
                process.env.KEY_PASSWORD || 'default-password'
            );
        }

        // Validate recipient's key
        const recipientKeyPair = keyRegistry.getKey(recipientKeyId);
        if (!recipientKeyPair) {
            throw new Error(`Recipient key ${recipientKeyId} not found in registry`);
        }

        // Send the file
        console.log('Sending file...');
        const result = await sdk.sendFile(
            'ethereum',
            'solana',
            recipientKeyId,
            file,
            {
                filename: options.filename || 'unnamed',
                mimeType: options.mimeType || 'application/octet-stream',
                encrypt: options.encrypt !== false,
                pin: options.pin !== false
            }
        );

        console.log('File sent successfully:', {
            ipfsHash: result.metadata.ipfsHash,
            txSignature: result.metadata.txSignature
        });

        return {
            txId: result.metadata.txSignature,
            ipfsHash: result.metadata.ipfsHash
        };
    } catch (error) {
        console.error('Error sending cross-chain message:', error);
        throw error;
    }
}

// Example: Receive a cross-chain message with file
async function receiveCrossChainMessage(
    recipientKeyId: string,
    vaa: string,
    password?: string
): Promise<{ data: Buffer; metadata: IPFSMetadata }> {
    try {
        const sdk = await initializeSDK();
        
        // Validate VAA format
        if (!vaa || !vaa.startsWith('0x')) {
            throw new Error('Invalid VAA format');
        }

        // Verify recipient key exists
        const keyRegistry = KeyRegistry.getInstance();
        const recipientKey = keyRegistry.getKey(recipientKeyId);
        if (!recipientKey) {
            throw new Error(`Recipient key ${recipientKeyId} not found in registry`);
        }

        console.log('Receiving file...');
        const result = await sdk.receiveFile(
            'solana',
            vaa,
            password || process.env.KEY_PASSWORD || 'default-password'
        );

        console.log('File received successfully:', {
            size: result.data.length,
            metadata: result.metadata
        });

        return result;
    } catch (error) {
        console.error('Error receiving cross-chain message:', error);
        throw error;
    }
}

// Example: Monitor for incoming messages
async function monitorIncomingMessages(
    recipientKeyId: string,
    callback: (message: { data: Buffer; metadata: IPFSMetadata }) => Promise<void>
): Promise<void> {
    const sdk = await initializeSDK();
    const keyRegistry = KeyRegistry.getInstance();
    
    // Validate recipient key
    const recipientKey = keyRegistry.getKey(recipientKeyId);
    if (!recipientKey) {
        throw new Error(`Recipient key ${recipientKeyId} not found in registry`);
    }

    console.log(`Starting message monitor for recipient ${recipientKeyId}...`);
    
    // Use public methods to get provider and contract
    const { provider, contract } = await sdk.getEthereumConnection();
    
    if (!provider || !contract) {
        throw new Error('Ethereum client not initialized');
    }

    contract.on('MessageReceived', async (payload: string, sender: string) => {
        try {
            if (sender === recipientKey.publicKey) {
                const vaa = payload;
                const message = await receiveCrossChainMessage(
                    recipientKeyId,
                    vaa,
                    process.env.KEY_PASSWORD
                );
                await callback(message);
            }
        } catch (error) {
            console.error('Error processing incoming message:', error);
        }
    });
}

// Example: Complete workflow
async function demonstrateWorkflow(): Promise<void> {
    try {
        const sdk = await initializeSDK();
        
        // Generate keys for sender and recipient
        const senderKeyId = 'sender-1';
        const recipientKeyId = 'recipient-1';
        
        const ethSigner = await sdk.getEthereumSigner();
        const solanaPayer = await sdk.getSolanaPayer();
        
        await sdk.generateAndRegisterECKeyPair(
            senderKeyId,
            'ethereum',
            ethSigner,
            'secure-password'
        );
        
        await sdk.generateAndRegisterECKeyPair(
            recipientKeyId,
            'solana',
            solanaPayer,
            'secure-password'
        );

        // Set up message monitoring
        await monitorIncomingMessages(recipientKeyId, async (message) => {
            console.log('New message received:', {
                size: message.data.length,
                metadata: message.metadata
            });
        });

        // Send a test message
        const testFile = Buffer.from('Hello, Cross-Chain World!');
        const result = await sendCrossChainMessage(
            senderKeyId,
            recipientKeyId,
            testFile,
            {
                filename: 'test-message.txt',
                mimeType: 'text/plain',
                encrypt: true,
                pin: true
            }
        );

        console.log('Test message sent:', result);
    } catch (error) {
        console.error('Error in workflow demonstration:', error);
        throw error;
    }
}

// Export example functions
export {
    initializeSDK,
    sendCrossChainMessage,
    receiveCrossChainMessage,
    monitorIncomingMessages,
    demonstrateWorkflow
};

async function testCrossChainFlow() {
    // Solana → Ethereum
    const solanaTx = await sendMessage(
        solanaConnection,
        wallet,
        ethRecipient,
        "Hello Ethereum!"
    );
    
    // Wormhole VAA'sını bekle
    const vaa = await waitForVAA(solanaTx);
    
    // Ethereum'da işle
    await receiveOnEth(vaa);
    
    // Ethereum → Solana
    const ethTx = await sendEthMessage(
        solanaRecipient,
        "Hello Solana!"
    );
    
    // Wormhole VAA'sını bekle
    const vaa2 = await waitForVAA(ethTx);
    
    // Solana'da işle
    await receiveOnSolana(vaa2);
}

// Eksik fonksiyon ve değişken tanımları
const solanaConnection = new Connection("https://api.devnet.solana.com");
const wallet = Keypair.generate();
const ethRecipient = "0x..."; // Ethereum alıcı adresi
const solanaRecipient = new PublicKey("..."); // Solana alıcı pubkey

async function sendMessage(
    connection: Connection,
    sender: Keypair,
    recipient: string,
    message: string
): Promise<string> {
    const transaction = new VersionedTransaction(
        new TransactionMessage({
            payerKey: sender.publicKey,
            recentBlockhash: (await connection.getLatestBlockhash()).blockhash,
            instructions: [
                new TransactionInstruction({
                    programId: new PublicKey(PROGRAM_ID),
                    keys: [],
                    data: Buffer.from(message)
                })
            ]
        }).compileToV0Message()
    );
    
    transaction.sign([sender]);
    return await connection.sendTransaction(transaction);
}

async function waitForVAA(txHash: string): Promise<string> {
    // VAA bekleyen mantık
    return "simulated-vaa";
}

async function receiveOnEth(vaa: string): Promise<void> {
    // Ethereum kontratını çağır
    const contract = new ethers.Contract(ETH_CONTRACT_ADDRESS, ABI, signer);
    await contract.receiveMessage(vaa);
}

async function sendEthMessage(
    recipient: PublicKey,
    message: string
): Promise<string> {
    const contract = new ethers.Contract(ETH_CONTRACT_ADDRESS, ABI, signer);
    const tx = await contract.sendMessage(
        recipient.toBuffer().toString('hex'),
        message
    );
    return tx.hash;
}

async function receiveOnSolana(vaa: string): Promise<void> {
    const transaction = new VersionedTransaction(
        new TransactionMessage({
            payerKey: wallet.publicKey,
            recentBlockhash: (await solanaConnection.getLatestBlockhash()).blockhash,
            instructions: [
                new TransactionInstruction({
                    programId: new PublicKey(PROGRAM_ID),
                    keys: [],
                    data: Buffer.from(vaa)
                })
            ]
        }).compileToV0Message()
    );
    
    await solanaConnection.sendTransaction(transaction);
}

// Test verilerini başlat
const setupTestEnvironment = async () => {
    const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");
    const signer = provider.getSigner();
    
    return {
        solanaConnection: new Connection("http://localhost:8899"),
        wallet: Keypair.generate(),
        ethRecipient: await signer.getAddress(),
        solanaRecipient: Keypair.generate().publicKey
    };
};

// Eksik çevre değişkenleri tanımla
const PROGRAM_ID = process.env.SOLANA_PROGRAM_ID!;
const ETH_CONTRACT_ADDRESS = process.env.ETH_CONTRACT_ADDRESS!;
const ABI = [
    // Güncel ABI tanımları
    "function receiveMessage(bytes calldata vaa)",
    "function sendMessage(bytes32 recipient, string message)"
];
const signer = new ethers.Wallet(process.env.PRIVATE_KEY!); 