import { ethers } from 'ethers';
import { ECIES } from '../crypto/ecies';
import { parseUnits } from 'ethers/lib/utils';
import { VAA, CrossChainMessage } from '../index';

export class WormholeEth {
    private provider: ethers.providers.Provider;
    private contract: ethers.Contract;
    private signer: ethers.Signer;

    constructor(
        provider: ethers.providers.Provider,
        contractAddress: string,
        abi: ethers.ContractInterface,
        signer: ethers.Signer
    ) {
        this.provider = provider;
        this.contract = new ethers.Contract(contractAddress, abi, signer);
        this.signer = signer;
    }

    // Getter methods for private properties
    public getSigner(): ethers.Signer {
        return this.signer;
    }

    public getProvider(): ethers.providers.Provider {
        return this.provider;
    }

    public getContract(): ethers.Contract {
        return this.contract;
    }

    async registerECKey(ecPublicKey: string, signature: string): Promise<ethers.ContractTransaction> {
        const tx = await this.contract.registerECKey(
            ethers.utils.arrayify(ecPublicKey),
            ethers.utils.arrayify(signature),
            { gasLimit: 200000 }
        );
        return tx;
    }

    async sendMessage(
        recipientECKey: string,
        message: string,
        targetChain: number = 1
    ): Promise<string> {
        const parsedMessage: CrossChainMessage = JSON.parse(message);
        
        const messageData = ethers.utils.defaultAbiCoder.encode(
            ['tuple(string sender, string recipient, tuple(string ipfsHash, string ephemeralPubkey, string mac, uint256 timestamp) payload, string signature)'],
            [parsedMessage]
        );

        const wormholeFee = await this.contract.messageFee();
        const tx = await this.contract.publishMessage(
            ethers.utils.hexlify(ethers.utils.toUtf8Bytes(messageData)),
            targetChain,
            { 
                value: wormholeFee,
                gasLimit: 500000
            }
        );
        
        await tx.wait();
        return tx.hash;
    }

    async receiveMessage(vaa: string): Promise<{
        message: string;
        sequence: number;
        emitterChain: number;
        emitterAddress: string;
    }> {
        const { vm, valid, reason } = await this.contract.parseAndVerifyVM(
            ethers.utils.arrayify(vaa)
        );

        if (!valid) {
            throw new Error(`VAA doğrulama hatası: ${reason}`);
        }

        const decodedPayload = ethers.utils.defaultAbiCoder.decode(
            ['tuple(string sender, string recipient, tuple(string ipfsHash, string ephemeralPubkey, string mac, uint256 timestamp) payload, string signature)'],
            vm.payload
        )[0];

        const message: CrossChainMessage = {
            sender: decodedPayload[0],
            recipient: decodedPayload[1],
            payload: {
                ipfsHash: decodedPayload[2][0],
                ephemeralPubkey: decodedPayload[2][1],
                mac: decodedPayload[2][2],
                timestamp: decodedPayload[2][3].toNumber()
            },
            signature: decodedPayload[3]
        };

        return {
            message: JSON.stringify(message),
            sequence: vm.sequence.toNumber(),
            emitterChain: vm.emitterChainId,
            emitterAddress: ethers.utils.hexlify(vm.emitterAddress)
        };
    }

    async verifyVAA(vaa: string): Promise<VAA> {
        const { vm, valid, reason } = await this.contract.parseAndVerifyVM(
            ethers.utils.arrayify(vaa)
        );

        if (!valid) {
            throw new Error(`VAA doğrulama hatası: ${reason}`);
        }

        return {
            version: vm.version,
            guardianSetIndex: vm.guardianSetIndex,
            signatures: vm.signatures.map((sig: any) => ({
                guardianSetIndex: sig.guardianSetIndex,
                signature: ethers.utils.arrayify(sig.signature)
            })),
            timestamp: vm.timestamp,
            nonce: vm.nonce,
            emitterChain: vm.emitterChainId,
            emitterAddress: ethers.utils.arrayify(vm.emitterAddress),
            sequence: vm.sequence,
            consistencyLevel: vm.consistencyLevel,
            payload: ethers.utils.arrayify(vm.payload)
        };
    }

    private async estimateGas(
        method: string,
        args: any[],
        value: ethers.BigNumber = ethers.constants.Zero
    ): Promise<ethers.BigNumber> {
        const gasEstimate = await this.contract.estimateGas[method](...args, { value });
        return gasEstimate.mul(120).div(100); // %20 buffer ekle
    }
} 