import { expect } from 'chai';
import { ethers } from 'ethers';
import { Connection, Keypair } from '@solana/web3.js';
import { CrossChainSDK } from '../src';

describe('Cross Chain Messaging Tests', () => {
    let sdk: CrossChainSDK;
    let ethSigner: ethers.Wallet;
    let solanaKeypair: Keypair;

    before(async () => {
        // Test ortamını hazırla
        sdk = CrossChainSDK.getInstance();
        
        // Ethereum test yapılandırması
        const provider = new ethers.providers.JsonRpcProvider(process.env.ETH_RPC_URL);
        ethSigner = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
        
        // Solana test yapılandırması
        const connection = new Connection(process.env.SOLANA_RPC_URL!);
        solanaKeypair = Keypair.fromSecretKey(
            Buffer.from(process.env.SOLANA_PRIVATE_KEY!, 'hex')
        );

        // SDK'yı yapılandır
        await sdk.initializeEthereum(
            provider,
            process.env.ETH_CONTRACT_ADDRESS!,
            require('../artifacts/contracts/CrossChainMessaging.sol/CrossChainMessaging.json').abi,
            ethSigner
        );

        await sdk.initializeSolana(
            connection,
            process.env.SOLANA_PROGRAM_ID!,
            process.env.WORMHOLE_PROGRAM_ID!,
            solanaKeypair
        );
    });

    it('should generate and register EC key pair', async () => {
        const keyPair = await sdk.generateAndRegisterECKeyPair(
            'test-key',
            'ethereum',
            ethSigner,
            'test123'
        );

        expect(keyPair).to.have.property('publicKey');
        expect(keyPair).to.have.property('privateKey');
    });

    it('should send and receive file', async () => {
        // Test dosyası oluştur
        const testFile = Buffer.from('Test mesajı');
        
        // Dosyayı gönder
        const result = await sdk.sendFile(
            'ethereum',
            'solana',
            'test-key',
            testFile,
            {
                filename: 'test.txt',
                mimeType: 'text/plain'
            }
        );

        expect(result).to.have.property('ipfsHash');
        expect(result).to.have.property('txSignature');

        // VAA'yı al ve doğrula
        // Not: Gerçek testte Wormhole'un VAA üretmesini beklememiz gerekiyor
        const vaa = await new Promise<string>((resolve) => {
            // VAA'yı dinle ve al
            setTimeout(() => {
                resolve('test-vaa');
            }, 5000);
        });

        // Dosyayı al
        const received = await sdk.receiveFile(
            'solana',
            vaa,
            'test123'
        );

        expect(received.data.toString()).to.equal('Test mesajı');
    });
}); 