import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import {
  userOnboarding,
  linkUserKey,
  senderFileTransfer,
  recipientFileReceive,
  CONFIG,
  FileTransferConfig,
  initializeWormhole,
  CustomWormholeConfig,
  sendCrossChainMessage,
  receiveCrossChainMessage,
  fetchSignedVAA
} from './zklaArchitecture';
// import { networks } from '@wormhole-foundation/sdk';

jest.setTimeout(300000); // 5 dakika timeout

describe('Wormhole Integration Tests', () => {
  let connection: Connection;
  let solanaIdentity: Keypair;
  let wormholeConfig: CustomWormholeConfig;
  let wormholeInstance: any;
  let solanaChain: any;
  let ethereumChain: any;

  beforeAll(async () => {
    // Solana bağlantısı
    connection = new Connection(CONFIG.RPC_URL, 'confirmed');
    solanaIdentity = Keypair.generate();

    // Wormhole yapılandırması
    wormholeConfig = {
      network: "Testnet",
      solanaRPC: 'https://api.devnet.solana.com',
      evmRPC: 'https://eth-sepolia.g.alchemy.com/v2/27TriqbEWN_Yg2eFRslfsUp230O5cwgK',
      coreBridgeAddress: 'worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth',
      tokenBridgeAddress: 'wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb'
    };

    try {
      const result = await initializeWormhole(wormholeConfig);
      wormholeInstance = result.wh;
      solanaChain = result.solanaChain;
      ethereumChain = result.ethereumChain;
      
      console.log('Wormhole başarıyla başlatıldı');
    } catch (error) {
      console.error('Wormhole başlatma hatası:', error);
      throw error;
    }
  });

  describe('Wormhole Temel Testler', () => {
    test('Wormhole instance ve chain bağlantıları doğru oluşturulmalı', () => {
      expect(wormholeInstance).toBeDefined();
      expect(solanaChain).toBeDefined();
      expect(ethereumChain).toBeDefined();
    });

    test('Chain yapılandırmaları doğru olmalı', () => {
      expect(solanaChain.config).toBeDefined();
      expect(ethereumChain.config).toBeDefined();
      expect(solanaChain.config.rpc).toBe(wormholeConfig.solanaRPC);
      expect(ethereumChain.config.rpc).toBe(wormholeConfig.evmRPC);
    });
  });

  describe('Cross-Chain Mesaj Testleri', () => {
    let testMessagePayload: Buffer;
    let messageReceipt: string;
    let txHash: string;

    beforeEach(() => {
      testMessagePayload = Buffer.from(
        JSON.stringify({
          type: 'test',
          content: 'Cross-chain test message',
          timestamp: Date.now()
        })
      );
    });

    test('Solana -> Ethereum mesaj gönderimi', async () => {
      try {
        const recipient = '0x9502F71D9d37728C56175Fd9a0A5f1c1Fe472B61'; // Test alıcı adresi
        
        // Yeni SDK'ya göre mesaj gönderimi
        const coreBridge = await solanaChain.getWormholeCore();
        const publishTx = await coreBridge.publishMessage(
          solanaIdentity.publicKey.toString(),
          testMessagePayload,
          0, // nonce
          0  // consistency level
        );

        // Transaction'ı imzala ve gönder
        const signedTx = await publishTx.sign([solanaIdentity]);
        txHash = await connection.sendRawTransaction(signedTx.serialize());
        await connection.confirmTransaction(txHash);

        expect(txHash).toBeDefined();
        messageReceipt = txHash;
        
        console.log('Mesaj gönderildi, txHash:', txHash);
      } catch (error) {
        console.error('Mesaj gönderme hatası:', error);
        throw error;
      }
    });

    test('VAA oluşturulmasını bekle ve doğrula', async () => {
      // VAA oluşmasını bekle (60 saniye)
      await new Promise(resolve => setTimeout(resolve, 60000));

      try {
        const whm = await solanaChain.parseTransaction(txHash);
        expect(whm).toBeDefined();
        
        const vaa = await wormholeInstance.getVaa(
          whm[0],
          "Uint8Array",
          120_000
        );
        
        expect(vaa).toBeDefined();
        expect(vaa.payload).toBeDefined();
        
        // VAA içeriğini parse et ve kontrol et
        const parsedVAA = await wormholeInstance.parseVAA(vaa);
        expect(parsedVAA.emitterChain).toBe('Solana');
        expect(parsedVAA.payload).toBeDefined();
        
        console.log('VAA başarıyla alındı ve doğrulandı');
      } catch (error) {
        console.error('VAA doğrulama hatası:', error);
        throw error;
      }
    });

    test('Mesaj alımı ve içerik doğrulama', async () => {
      try {
        const whm = await solanaChain.parseTransaction(txHash);
        const vaa = await wormholeInstance.getVaa(
          whm[0],
          "Uint8Array",
          120_000
        );
        
        // Yeni SDK'ya göre mesaj alımı
        const coreBridge = await ethereumChain.getWormholeCore();
        const verifyTx = await coreBridge.verifyMessage(
          solanaIdentity.publicKey.toString(),
          vaa
        );

        expect(verifyTx).toBeDefined();

        // Alınan mesajı parse et ve kontrol et
        const parsedVAA = await wormholeInstance.parseVAA(vaa);
        const parsedMessage = JSON.parse(Buffer.from(parsedVAA.payload).toString());
        expect(parsedMessage.type).toBe('test');
        expect(parsedMessage.content).toBe('Cross-chain test message');
        expect(parsedMessage.timestamp).toBeDefined();
        
        console.log('Mesaj başarıyla alındı ve içerik doğrulandı');
      } catch (error) {
        console.error('Mesaj alım hatası:', error);
        throw error;
      }
    });
  });

  describe('Hata Durumu Testleri', () => {
    test('Geçersiz chain için hata vermeli', async () => {
      const invalidPayload = Buffer.from('test');
      await expect(
        sendCrossChainMessage(
          wormholeInstance,
          'InvalidChain' as any,
          'Ethereum',
          invalidPayload,
          '0x1234'
        )
      ).rejects.toThrow();
    });

    test('Geçersiz VAA için hata vermeli', async () => {
      const invalidVAA = new Uint8Array(32);
      await expect(
        receiveCrossChainMessage(
          wormholeInstance,
          'Ethereum',
          invalidVAA
        )
      ).rejects.toThrow();
    });
  });

  afterAll(async () => {
    // Temizlik işlemleri
    if (connection) {
      await connection.getLatestBlockhash();
    }
  });
}); 