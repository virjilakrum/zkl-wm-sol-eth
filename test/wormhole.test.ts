import { initializeWormhole, CustomWormholeConfig, sendCrossChainMessage } from '../src/wormhole/zklaArchitecture';
import { Buffer } from 'buffer';

describe('Wormhole Entegrasyonu Testleri', () => {
  let wormholeInstance: any;
  let solanaChain: any;
  let ethereumChain: any;

  beforeAll(async () => {
    const config: CustomWormholeConfig = {
      network: 'Testnet',
      solanaRPC: 'https://api.devnet.solana.com',
      evmRPC: 'https://eth-sepolia.g.alchemy.com/v2/27TriqbEWN_Yg2eFRslfsUp230O5cwgK',
    };

    const result = await initializeWormhole(config);
    wormholeInstance = result.wh;
    solanaChain = result.solanaChain;
    ethereumChain = result.ethereumChain;
  });

  test('Wormhole başarıyla başlatılmalı', () => {
    expect(wormholeInstance).toBeDefined();
    expect(solanaChain).toBeDefined();
    expect(ethereumChain).toBeDefined();
  });

  test('Solana ve Ethereum zincirleri arasında mesaj gönderilebilmeli', async () => {
    const testMessage = Buffer.from('Test mesajı');
    const recipientAddress = '0x9502F71D9d37728C56175Fd9a0A5f1c1Fe472B61';

    const txHash = await sendCrossChainMessage(
      wormholeInstance,
      'Solana',
      'Ethereum',
      testMessage,
      recipientAddress
    );

    expect(txHash).toBeDefined();
    expect(typeof txHash).toBe('string');
  });
}); 