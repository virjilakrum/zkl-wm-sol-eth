import { create } from 'ipfs-core';
import { AddResult } from 'ipfs-core-types/src/root';
import { Buffer } from 'buffer';

export class IPFSValidator {
    private static instance: IPFSValidator;
    private ipfs: any;
    private isRunning: boolean = false;

    private constructor() {}

    public static getInstance(): IPFSValidator {
        if (!IPFSValidator.instance) {
            IPFSValidator.instance = new IPFSValidator();
        }
        return IPFSValidator.instance;
    }

    public async start(port: number = 5001): Promise<void> {
        if (this.isRunning) {
            console.log('IPFS validator zaten çalışıyor.');
            return;
        }

        try {
            this.ipfs = await create({
                repo: './.ipfs-test',
                config: {
                    Addresses: {
                        Swarm: ['/ip4/127.0.0.1/tcp/4002'],
                        API: `/ip4/127.0.0.1/tcp/${port}`,
                        Gateway: '/ip4/127.0.0.1/tcp/9090'
                    }
                }
            });

            this.isRunning = true;
            console.log(`IPFS validator ${port} portunda başlatıldı.`);
        } catch (error) {
            console.error('IPFS validator başlatılamadı:', error);
            throw error;
        }
    }

    public async stop(): Promise<void> {
        if (!this.isRunning) {
            console.log('IPFS validator zaten durdurulmuş.');
            return;
        }

        try {
            await this.ipfs.stop();
            this.isRunning = false;
            console.log('IPFS validator durduruldu.');
        } catch (error) {
            console.error('IPFS validator durdurulamadı:', error);
            throw error;
        }
    }

    public async addFile(content: Buffer | string): Promise<AddResult> {
        if (!this.isRunning) {
            throw new Error('IPFS validator çalışmıyor. Önce start() metodunu çağırın.');
        }

        try {
            const result = await this.ipfs.add(content);
            console.log(`Dosya IPFS'e eklendi. CID: ${result.cid}`);
            await this.pinFile(result.cid.toString());
            return result;
        } catch (error) {
            console.error('Dosya IPFS\'e eklenemedi:', error);
            throw error;
        }
    }

    public async getFile(cid: string): Promise<Buffer> {
        if (!this.isRunning) {
            throw new Error('IPFS validator çalışmıyor. Önce start() metodunu çağırın.');
        }

        try {
            const chunks = [];
            for await (const chunk of this.ipfs.cat(cid)) {
                chunks.push(chunk);
            }
            return Buffer.concat(chunks);
        } catch (error) {
            console.error('Dosya IPFS\'den alınamadı:', error);
            throw error;
        }
    }

    public async pinFile(cid: string): Promise<void> {
        if (!this.isRunning) {
            throw new Error('IPFS validator çalışmıyor. Önce start() metodunu çağırın.');
        }

        try {
            await this.ipfs.pin.add(cid);
            console.log(`Dosya pinlendi. CID: ${cid}`);
        } catch (error) {
            console.error('Dosya pinlenemedi:', error);
            throw error;
        }
    }

    public async unpinFile(cid: string): Promise<void> {
        if (!this.isRunning) {
            throw new Error('IPFS validator çalışmıyor. Önce start() metodunu çağırın.');
        }

        try {
            await this.ipfs.pin.rm(cid);
            console.log(`Dosyanın pini kaldırıldı. CID: ${cid}`);
        } catch (error) {
            console.error('Dosyanın pini kaldırılamadı:', error);
            throw error;
        }
    }

    public async listPinnedFiles(): Promise<string[]> {
        if (!this.isRunning) {
            throw new Error('IPFS validator çalışmıyor. Önce start() metodunu çağırın.');
        }

        try {
            const pinnedFiles = [];
            for await (const { cid } of this.ipfs.pin.ls()) {
                pinnedFiles.push(cid.toString());
            }
            return pinnedFiles;
        } catch (error) {
            console.error('Pinlenmiş dosyalar listelenemiyor:', error);
            throw error;
        }
    }

    public isActive(): boolean {
        return this.isRunning;
    }

    public async reset(): Promise<void> {
        if (this.isRunning) {
            const pinnedFiles = await this.listPinnedFiles();
            for (const cid of pinnedFiles) {
                await this.unpinFile(cid);
            }
        }
    }
} 