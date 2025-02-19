import { create, IPFSHTTPClient } from 'ipfs-http-client';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

export interface IPFSMetadata {
    ipfsHash: string;
    txSignature: string;
}

export class IPFSStorage {
    private client: IPFSHTTPClient;

    constructor(url: string = 'http://localhost:5001') {
        this.client = create({ url });
    }

    async uploadFile(data: Buffer, options?: { 
        filename?: string;
        mimeType?: string;
    }): Promise<IPFSMetadata> {
        // 1. Dosyayı IPFS'e yükle
        const result = await this.client.add(data, {
            pin: true, // Dosyayı pin'le
        });

        // 2. Dosya hash'ini hesapla
        const hash = await sha256.digest(data);

        // 3. Metadata oluştur
        const metadata: IPFSMetadata = {
            ipfsHash: result.cid.toString(),
            txSignature: hash.toString()
        };

        // 4. Metadata'yı da IPFS'e yükle
        const metadataBuffer = Buffer.from(JSON.stringify(metadata));
        await this.client.add(metadataBuffer, {
            pin: true
        });

        return metadata;
    }

    async downloadFile(cid: string): Promise<Buffer> {
        // 1. CID'yi parse et ve string'e çevir
        const parsedCid = CID.parse(cid).toString();

        // 2. Dosyayı indir
        const chunks: Uint8Array[] = [];
        for await (const chunk of this.client.cat(parsedCid)) {
            chunks.push(chunk);
        }

        // 3. Chunk'ları birleştir
        return Buffer.concat(chunks);
    }

    async getMetadata(cid: string): Promise<IPFSMetadata> {
        const data = await this.downloadFile(cid);
        return JSON.parse(data.toString());
    }

    async pinFile(cid: string): Promise<void> {
        const parsedCid = CID.parse(cid).toString();
        await this.client.pin.add(parsedCid);
    }

    async unpinFile(cid: string): Promise<void> {
        const parsedCid = CID.parse(cid).toString();
        await this.client.pin.rm(parsedCid);
    }

    async isFileAvailable(cid: string): Promise<boolean> {
        try {
            const stat = await this.client.files.stat(`/ipfs/${cid}`);
            return stat.size > 0;
        } catch {
            return false;
        }
    }
} 