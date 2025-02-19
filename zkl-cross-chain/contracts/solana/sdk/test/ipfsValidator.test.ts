import { IPFSValidator } from '../src/utils/ipfsValidator';
import { Buffer } from 'buffer';

describe('IPFS Validator Tests', () => {
    let ipfsValidator: IPFSValidator;
    const testPort = 5002;

    beforeAll(async () => {
        ipfsValidator = IPFSValidator.getInstance();
        await ipfsValidator.start(testPort);
    });

    afterAll(async () => {
        await ipfsValidator.stop();
    });

    it('dosya yükleme ve indirme işlemlerini doğru şekilde yapmalı', async () => {
        const testContent = 'Test içeriği';
        const buffer = Buffer.from(testContent);

        // Dosyayı yükle
        const result = await ipfsValidator.addFile(buffer);
        expect(result.cid).toBeDefined();

        // Dosyayı indir
        const retrievedContent = await ipfsValidator.getFile(result.cid.toString());
        expect(retrievedContent.toString()).toBe(testContent);
    });

    it('dosya pinleme ve pin kaldırma işlemlerini doğru şekilde yapmalı', async () => {
        const testContent = 'Pin test içeriği';
        const buffer = Buffer.from(testContent);

        // Dosyayı yükle ve pinle
        const result = await ipfsValidator.addFile(buffer);
        await ipfsValidator.pinFile(result.cid.toString());

        // Pinlenmiş dosyaları listele
        const pinnedFiles = await ipfsValidator.listPinnedFiles();
        expect(pinnedFiles).toContain(result.cid.toString());

        // Pin'i kaldır
        await ipfsValidator.unpinFile(result.cid.toString());
        const updatedPinnedFiles = await ipfsValidator.listPinnedFiles();
        expect(updatedPinnedFiles).not.toContain(result.cid.toString());
    });

    it('büyük dosyaları doğru şekilde işlemeli', async () => {
        // 1MB'lık rastgele veri oluştur
        const largeBuffer = Buffer.alloc(1024 * 1024);
        for (let i = 0; i < largeBuffer.length; i++) {
            largeBuffer[i] = Math.floor(Math.random() * 256);
        }

        // Büyük dosyayı yükle
        const result = await ipfsValidator.addFile(largeBuffer);
        expect(result.cid).toBeDefined();

        // Büyük dosyayı indir ve karşılaştır
        const retrievedContent = await ipfsValidator.getFile(result.cid.toString());
        expect(Buffer.compare(retrievedContent, largeBuffer)).toBe(0);
    });

    it('çoklu dosya işlemlerini paralel olarak yapabilmeli', async () => {
        const fileCount = 5;
        const uploadPromises: Promise<any>[] = [];
        const testContents: string[] = [];

        // Çoklu dosya yükleme
        for (let i = 0; i < fileCount; i++) {
            const content = `Test içeriği ${i}`;
            testContents.push(content);
            uploadPromises.push(ipfsValidator.addFile(Buffer.from(content)));
        }

        const results = await Promise.all(uploadPromises);
        expect(results.length).toBe(fileCount);

        // Çoklu dosya indirme
        const downloadPromises = results.map(result => 
            ipfsValidator.getFile(result.cid.toString())
        );

        const downloadedContents = await Promise.all(downloadPromises);
        downloadedContents.forEach((content, index) => {
            expect(content.toString()).toBe(testContents[index]);
        });
    });
}); 