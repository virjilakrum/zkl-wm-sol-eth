use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    clock::Clock,
    sysvar::Sysvar,
    program::invoke,
    system_instruction,
};

use sha2::{Sha256, Digest};
use sha3::Keccak512;
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;

use crate::{
    error::CrossChainError,
    state::{ZklAccount, ZklAccountData, InboxAccount, FileTxRecord, FileMetadata, TransferStatus, TransferMetrics, RateLimiter},
    wormhole::{post_message, verify_signature, VAA},
};

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use hex;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};

const WORMHOLE_SEED: &[u8] = b"wormhole";

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Payload {
    pub sender: [u8; 33],
    pub recipient: [u8; 20],
    pub message: Vec<u8>,
}

pub struct Processor;

impl Processor {
    pub fn process_instruction<'a>(
        program_id: &'a Pubkey,
        accounts: &'a [AccountInfo<'a>],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = instruction_data[0];
        let rest = &instruction_data[1..];

        match instruction {
            0 => Self::process_register_zkl_account(program_id, accounts, rest),
            1 => Self::process_send_file(program_id, accounts, rest),
            2 => Self::process_receive_file(program_id, accounts, rest),
            3 => Self::process_update_metrics(program_id, accounts, rest),
            _ => Err(CrossChainError::InvalidInstruction.into()),
        }
    }

    fn process_register_zkl_account(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let user_account = next_account_info(accounts_iter)?;
        let zkl_account = next_account_info(accounts_iter)?;
        let system_program = next_account_info(accounts_iter)?;
        let clock = next_account_info(accounts_iter)?;

        if !user_account.is_signer {
            return Err(CrossChainError::InvalidAuthority.into());
        }

        let current_time = Clock::from_account_info(clock)?.unix_timestamp;

        // Rate limiting
        let rate_limiter = RateLimiter::try_from_slice(&zkl_account.data.borrow())
            .map_err(|_| CrossChainError::InvalidMessageFormat)?;
            
        if !Self::check_rate_limit(&rate_limiter, current_time) {
            return Err(CrossChainError::RateLimitExceeded.into());
        }

        // Parse input data
        let ec_pubkey: [u8; 33] = data[..33]
            .try_into()
            .map_err(|_| CrossChainError::InvalidMessageFormat)?;
            
        let zkl_sm: [u8; 64] = data[33..97]
            .try_into()
            .map_err(|_| CrossChainError::InvalidMessageFormat)?;
            
        let solana_sm: [u8; 64] = data[97..161]
            .try_into()
            .map_err(|_| CrossChainError::InvalidMessageFormat)?;
            
        let index = u32::from_le_bytes(data[161..165]
            .try_into()
            .map_err(|_| CrossChainError::InvalidMessageFormat)?);

        // Verify PDA
        let seeds = &[
            user_account.key.as_ref(),
            &index.to_le_bytes(),
        ];
        let (pda, bump) = Pubkey::find_program_address(seeds, program_id);
        if pda != *zkl_account.key {
            return Err(CrossChainError::InvalidPDA.into());
        }

        // Verify signatures
        let zkl_message = format!(
            "ZklAccount: linking EC address {} to {} with index {}",
            hex::encode(ec_pubkey),
            user_account.key,
            index
        );
        Self::verify_ec_signature(&zkl_message, &zkl_sm, &ec_pubkey)?;
        Self::verify_solana_signature(&zkl_message, &solana_sm, user_account.key)?;

        // Create account data
        let zkl_data = ZklAccountData {
            ec_pubkey,
            zkl_sm,
            solana_sm,
            index,
            created_at: current_time,
            last_used: current_time,
            is_active: true,
        };

        let account_data = ZklAccount::new(
            *user_account.key,
            zkl_data,
            bump,
        );

        // Save account
        account_data.serialize(&mut *zkl_account.data.borrow_mut())?;

        Ok(())
    }

    fn process_send_file(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let sender = next_account_info(accounts_iter)?;
        let recipient_inbox = next_account_info(accounts_iter)?;
        let metrics_account = next_account_info(accounts_iter)?;
        let clock = next_account_info(accounts_iter)?;

        if !sender.is_signer {
            return Err(CrossChainError::InvalidAuthority.into());
        }

        let current_time = Clock::from_account_info(clock)?.unix_timestamp;

        // Parse file metadata
        let metadata = FileMetadata::try_from_slice(data)?;
        
        // Validate file metadata
        if metadata.file_size > FileMetadata::MAX_FILE_SIZE {
            return Err(CrossChainError::FileTooLarge.into());
        }

        if metadata.is_expired() {
            return Err(CrossChainError::FileExpired.into());
        }

        // Create transfer record
        let record = FileTxRecord::new(
            Self::get_sender_ec_pubkey(sender)?,
            metadata.ipfs_hash.clone(),
            metadata.ephemeral_pubkey.unwrap_or([0u8; 33]),
            current_time,
            TransferStatus::Pending,
            0,
            None,
            None,
            None
        );

        // Update inbox
        let mut inbox = InboxAccount::try_from_slice(&recipient_inbox.data.borrow())?;
        inbox.add_message(record.clone())?;
        inbox.serialize(&mut *recipient_inbox.data.borrow_mut())?;

        // Update metrics
        let mut metrics = TransferMetrics::try_from_slice(&metrics_account.data.borrow())?;
        metrics.total_transfers += 1;
        metrics.total_bytes_transferred += metadata.file_size;
        metrics.last_updated = current_time;
        metrics.serialize(&mut *metrics_account.data.borrow_mut())?;

        Ok(())
    }

    fn process_receive_file(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let recipient = next_account_info(accounts_iter)?;
        let inbox = next_account_info(accounts_iter)?;
        let metrics_account = next_account_info(accounts_iter)?;
        let clock = next_account_info(accounts_iter)?;

        if !recipient.is_signer {
            return Err(CrossChainError::InvalidAuthority.into());
        }

        let current_time = Clock::from_account_info(clock)?.unix_timestamp;

        // Verify inbox ownership
        let mut inbox_data = InboxAccount::try_from_slice(&inbox.data.borrow())?;
        if inbox_data.recipient_wallet != *recipient.key {
            return Err(CrossChainError::InvalidAuthority.into());
        }

        // Get message index from data
        let message_index = u32::from_le_bytes(data[..4].try_into()?);
        
        // Update message status
        if let Some(message) = inbox_data.messages.get_mut(message_index as usize) {
            message.update_status(TransferStatus::Completed);
            message.confirmation_time = Some(current_time);

            // Update metrics
            let mut metrics = TransferMetrics::try_from_slice(&metrics_account.data.borrow())?;
            metrics.successful_transfers += 1;
            metrics.serialize(&mut *metrics_account.data.borrow_mut())?;
        } else {
            return Err(CrossChainError::InvalidMessageIndex.into());
        }

        // Save updated inbox
        inbox_data.serialize(&mut *inbox.data.borrow_mut())?;

        Ok(())
    }

    fn process_update_metrics(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let metrics_account = next_account_info(accounts_iter)?;
        let authority = next_account_info(accounts_iter)?;
        let clock = next_account_info(accounts_iter)?;

        if !authority.is_signer {
            return Err(CrossChainError::InvalidAuthority.into());
        }

        let current_time = Clock::from_account_info(clock)?.unix_timestamp;

        // Update metrics
        let mut metrics = TransferMetrics::try_from_slice(&metrics_account.data.borrow())?;
        metrics.last_updated = current_time;
        
        // Calculate average transfer time
        if metrics.successful_transfers > 0 {
            let total_time = u64::from_le_bytes(data[..8].try_into()?);
            metrics.average_transfer_time = total_time / metrics.successful_transfers;
        }

        metrics.serialize(&mut *metrics_account.data.borrow_mut())?;

        Ok(())
    }

    fn check_rate_limit(
        rate_limiter: &RateLimiter,
        current_time: i64,
    ) -> bool {
        if current_time - rate_limiter.last_request_time > rate_limiter.cooldown_period as i64 {
            true
        } else {
            rate_limiter.request_count < rate_limiter.max_requests_per_minute
        }
    }

    fn verify_ec_signature(
        message: &str,
        signature: &[u8; 64],
        ec_pubkey: &[u8; 33],
    ) -> ProgramResult {
        let secp = Secp256k1::verification_only();
        let message_hash = Keccak512::digest(message.as_bytes());
        let msg = Message::from_digest_slice(&message_hash[..32])
            .map_err(|_| ProgramError::InvalidArgument)?;
        let sig = Signature::from_compact(signature)
            .map_err(|_| ProgramError::InvalidArgument)?;
        let pubkey = PublicKey::from_slice(ec_pubkey)
            .map_err(|_| ProgramError::InvalidArgument)?;

        secp.verify_ecdsa(&msg, &sig, &pubkey)
            .map_err(|_| CrossChainError::InvalidProof.into())
    }

    fn verify_solana_signature(
        _message: &str,
        _signature: &[u8; 64],
        _pubkey: &Pubkey,
    ) -> ProgramResult {
        // Solana imza doğrulama mantığı
        Ok(())
    }

    fn get_sender_ec_pubkey(sender_account: &AccountInfo) -> Result<[u8; 33], ProgramError> {
        let zkl_account = ZklAccount::try_from_slice(&sender_account.data.borrow())?;
        if !zkl_account.zkl_data.is_active {
            return Err(CrossChainError::AccountNotActive.into());
        }
        Ok(zkl_account.zkl_data.ec_pubkey)
    }
}

fn register_zkl_account(
    program_id: &Pubkey,
    accounts: &mut impl Iterator<Item = &AccountInfo>,
    instruction_data: &[u8],
) -> ProgramResult {
    let user_account = next_account_info(accounts)?;
    let zkl_account = next_account_info(accounts)?;
    let system_program = next_account_info(accounts)?;

    if !user_account.is_signer {
        return Err(CrossChainError::InvalidAuthority.into());
    }

    // Parse input data
    let ec_pubkey: [u8; 33] = instruction_data[..33].try_into()?;
    let zkl_sm: [u8; 64] = instruction_data[33..97].try_into()?;
    let solana_sm: [u8; 64] = instruction_data[97..161].try_into()?;
    let index = u32::from_le_bytes(instruction_data[161..165].try_into()?);

    // Verify PDA
    let seeds = &[
        user_account.key.as_ref(),
        &index.to_le_bytes(),
    ];
    let (pda, bump) = Pubkey::find_program_address(seeds, program_id);
    if pda != *zkl_account.key {
        return Err(CrossChainError::InvalidPDA.into());
    }

    // Verify signatures
    let zkl_message = format!(
        "ZklAccount: linking EC address {} to Solana identity {} with index {}",
        hex::encode(ec_pubkey),
        user_account.key,
        index
    );
    verify_ec_signature(&zkl_message, &zkl_sm, &ec_pubkey)?;
    verify_solana_signature(&zkl_message, &solana_sm, user_account.key)?;

    // Create and save ZklAccount
    let zkl_data = ZklAccountData {
        ec_pubkey,
        zkl_sm,
        solana_sm,
        index,
    };

    let account_data = ZklAccount::new(
        *user_account.key,
        zkl_data,
        bump,
    );

    account_data.serialize(&mut *zkl_account.data.borrow_mut())?;

    Ok(())
}

fn send_file(
    program_id: &Pubkey,
    accounts: &mut impl Iterator<Item = &AccountInfo>,
    instruction_data: &[u8],
) -> ProgramResult {
    let sender = next_account_info(accounts)?;
    let recipient_inbox = next_account_info(accounts)?;
    let system_program = next_account_info(accounts)?;

    if !sender.is_signer {
        return Err(CrossChainError::InvalidAuthority.into());
    }

    // Parse input data
    let recipient_ec_pubkey: [u8; 33] = instruction_data[..33].try_into()?;
    let encrypted_link = String::from_utf8(instruction_data[33..].to_vec())?;
    let ephemeral_pubkey: [u8; 33] = instruction_data[66..99].try_into()?;
    let file_hash: [u8; 64] = instruction_data[99..163].try_into()?;

    // Verify file transfer message
    let message = format!(
        "ZklFileTransfer: sending file with hash {} to {} from {}",
        hex::encode(file_hash),
        hex::encode(recipient_ec_pubkey),
        hex::encode(Self::get_sender_ec_pubkey(sender)?)
    );

    // Create and save FileTxRecord
    let mut inbox = InboxAccount::try_from_slice(&recipient_inbox.data.borrow())?;
    inbox.add_message(FileTxRecord {
        sender_ec_pubkey: Self::get_sender_ec_pubkey(sender)?,
        encrypted_link,
        ephemeral_pubkey,
        timestamp: Clock::get()?.unix_timestamp,
    });

    inbox.serialize(&mut *recipient_inbox.data.borrow_mut())?;

    Ok(())
}

fn receive_file(
    program_id: &Pubkey,
    accounts: &mut impl Iterator<Item = &AccountInfo>,
    instruction_data: &[u8],
) -> ProgramResult {
    let recipient = next_account_info(accounts)?;
    let inbox = next_account_info(accounts)?;

    if !recipient.is_signer {
        return Err(CrossChainError::InvalidAuthority.into());
    }

    // Verify inbox ownership
    let inbox_data = InboxAccount::try_from_slice(&inbox.data.borrow())?;
    if inbox_data.recipient_wallet != *recipient.key {
        return Err(CrossChainError::InvalidAuthority.into());
    }

    Ok(())
}

// Helper functions
fn verify_ec_signature(
    message: &str,
    signature: &[u8; 64],
    ec_pubkey: &[u8; 33],
) -> ProgramResult {
    let secp = Secp256k1::verification_only();
    let message_hash = Sha256::digest(message.as_bytes());
    let msg = Message::from_slice(&message_hash)
        .map_err(|_| ProgramError::InvalidArgument)?;
    let sig = Signature::from_compact(signature)
        .map_err(|_| ProgramError::InvalidArgument)?;
    let pubkey = PublicKey::from_slice(ec_pubkey)
        .map_err(|_| ProgramError::InvalidArgument)?;

    secp.verify_ecdsa(&msg, &sig, &pubkey)
        .map_err(|_| CrossChainError::InvalidProof.into())
}

fn verify_solana_signature(
    message: &str,
    signature: &[u8; 64],
    pubkey: &Pubkey,
) -> ProgramResult {
    // Solana imza doğrulama mantığı
    Ok(())
}

fn get_sender_ec_pubkey(sender_account: &AccountInfo) -> Result<[u8; 33], ProgramError> {
    let zkl_account = ZklAccount::try_from_slice(&sender_account.data.borrow())?;
    Ok(zkl_account.zkl_data.ec_pubkey)
}

fn compute_file_hash(file_data: &[u8]) -> [u8; 64] {
    let mut hasher = Keccak512::new();
    hasher.update(file_data);
    hasher.finalize().into()
}

fn send_wormhole_message(
    wormhole_bridge: &AccountInfo,
    sender: &AccountInfo,
    system_program: &AccountInfo,
    record: &FileTxRecord,
) -> Result<u64, ProgramError> {
    let nonce = 0;
    let payload = record.to_bytes();
    
    // Wormhole mesaj boyutunu kontrol et
    if payload.len() > 1024 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Wormhole köprüsüne mesaj gönder
    let sequence = post_message(
        wormhole_bridge,
        sender,
        system_program,
        nonce,
        payload,
        1, // Consistency level
    )?;

    Ok(sequence)
}

fn verify_vaa_signature(
    wormhole_bridge: &AccountInfo,
    vaa: &VAA,
) -> ProgramResult {
    // Wormhole VAA imzasını doğrula
    verify_signature(wormhole_bridge, vaa)
}

fn parse_vaa_to_record(vaa: &VAA) -> Result<FileTxRecord, ProgramError> {
    // VAA payload'ını FileTxRecord'a dönüştür
    FileTxRecord::try_from_slice(&vaa.payload)
        .map_err(|_| CrossChainError::InvalidMessageFormat.into())
}

fn verify_tx_proof(
    ipfs_hash: &str,
    sender_pubkey: &Pubkey,
    recipient_pubkey: &Pubkey,
    proof: &[u8; 64]
) -> ProgramResult {
    let mut hasher = Sha256::new();
    hasher.update(ipfs_hash.as_bytes());
    hasher.update(sender_pubkey.as_ref());
    hasher.update(recipient_pubkey.as_ref());
    let hash = hasher.finalize();

    let key_registry = get_key_registry(sender_pubkey)?;
    if !secp256k1_verify(&hash, proof, &key_registry.ec_pubkey) {
        return Err(CrossChainError::InvalidProof.into());
    }

    Ok(())
}

fn secp256k1_verify(
    message_hash: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, ProgramError> {
    let secp = Secp256k1::verification_only();
    let msg = Message::from_slice(message_hash).map_err(|_| ProgramError::InvalidArgument)?;
    let sig = Signature::from_der(signature).map_err(|_| ProgramError::InvalidArgument)?;
    let pubkey = PublicKey::from_slice(public_key).map_err(|_| ProgramError::InvalidArgument)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

fn verify_ipfs_hash(ipfs_hash: &str) -> ProgramResult {
    let decoded = base64::decode(ipfs_hash)
        .map_err(|_| CrossChainError::InvalidMessageFormat)?;
    
    if decoded.len() != 32 {
        return Err(CrossChainError::InvalidMessageFormat.into());
    }
    
    Ok(())
}

fn get_wormhole_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[WORMHOLE_SEED], program_id)
}

fn initialize_wormhole_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let (pda, bump) = get_wormhole_pda(program_id);
    // PDA kontrolü ve ilk konfigürasyon
    Ok(())
}

fn send_cross_chain_message(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Ethereum adresini ve mesajı al
    let eth_address: [u8; 20] = instruction_data[..20].try_into()?;
    let message = &instruction_data[20..];
    
    // Wormhole mesajını hazırla
    let payload = Payload {
        sender: Self::get_sender_ec_pubkey(accounts[0])?,
        recipient: eth_address,
        message: message.to_vec(),
    };
    
    // Wormhole'a gönder
    let sequence = post_message(
        accounts[1], // wormhole_bridge
        accounts[0], // sender
        accounts[2], // system_program
        0,           // nonce
        payload,
        1,           // consistency_level
    )?;
    
    Ok(())
}

fn compute_solana_pda(recipient: &[u8; 20]) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[b"inbox", recipient],
        program_id
    );
    pda
}

fn process_file_transfer(
    program_id: &Pubkey,
    accounts: &mut impl Iterator<Item = &AccountInfo>,
    file_metadata: &FileMetadata,
) -> ProgramResult {
    let sender = next_account_info(accounts)?;
    let recipient_inbox = next_account_info(accounts)?;
    let system_program = next_account_info(accounts)?;

    if !sender.is_signer {
        return Err(CrossChainError::InvalidAuthority.into());
    }

    // Dosya boyutu kontrolü
    if file_metadata.file_size > 100 * 1024 * 1024 { // 100MB limit
        return Err(CrossChainError::FileTooLarge.into());
    }

    // IPFS hash formatı kontrolü
    if !file_metadata.ipfs_hash.starts_with("Qm") {
        return Err(CrossChainError::InvalidMessageFormat.into());
    }

    // Inbox hesabını güncelle
    let mut inbox = InboxAccount::try_from_slice(&recipient_inbox.data.borrow())?;
    
    // Inbox kapasitesi kontrolü
    if inbox.messages.len() >= InboxAccount::MAX_MESSAGES {
        return Err(CrossChainError::InboxFull.into());
    }

    // Yeni mesaj kaydı oluştur
    let record = FileTxRecord::new(
        Self::get_sender_ec_pubkey(sender)?,
        file_metadata.ipfs_hash.clone(),
        file_metadata.ephemeral_pubkey.unwrap_or([0u8; 33]),
        Clock::get()?.unix_timestamp,
    );

    // Mesajı inbox'a ekle
    inbox.add_message(record);
    inbox.serialize(&mut *recipient_inbox.data.borrow_mut())?;

    Ok(())
}

fn verify_file_metadata(
    metadata: &FileMetadata,
    data: &[u8],
) -> ProgramResult {
    // Dosya hash'ini doğrula
    if !metadata.verify_hash(data) {
        return Err(CrossChainError::InvalidFileHash.into());
    }

    // Dosya boyutunu kontrol et
    if data.len() as u64 != metadata.file_size {
        return Err(CrossChainError::InvalidMessageFormat.into());
    }

    // Şifrelenmiş dosyalar için ek kontroller
    if metadata.encrypted {
        if metadata.ephemeral_pubkey.is_none() || metadata.mac.is_none() {
            return Err(CrossChainError::InvalidMessageFormat.into());
        }
    }

    Ok(())
}

fn process_encrypted_file(
    file_data: &[u8],
    recipient_ec_pubkey: &[u8; 33],
) -> Result<(String, [u8; 33], [u8; 32]), ProgramError> {
    // ECIES şifreleme
    let secp = Secp256k1::new();
    let ephemeral_keypair = secp256k1::KeyPair::new(&secp, &mut rand::thread_rng());
    let ephemeral_pubkey = ephemeral_keypair.public_key().serialize();
    
    // Şifreleme işlemi
    let encrypted_data = ecies_encrypt(
        file_data,
        recipient_ec_pubkey,
        &ephemeral_keypair
    )?;

    // IPFS'e yükle ve link al
    let ipfs_link = upload_to_ipfs(&encrypted_data)?;
    
    // MAC hesapla
    let mut mac = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(&encrypted_data);
    mac.copy_from_slice(&hasher.finalize());

    Ok((ipfs_link, ephemeral_pubkey, mac))
}

fn ecies_encrypt(
    data: &[u8],
    recipient_pubkey: &[u8; 33],
    ephemeral_keypair: &secp256k1::KeyPair,
) -> Result<Vec<u8>, ProgramError> {
    // ECDH ile paylaşılan gizli anahtarı hesapla
    let shared_secret = compute_shared_secret(
        ephemeral_keypair,
        recipient_pubkey
    )?;

    // KDF ile şifreleme anahtarı türet
    let encryption_key = derive_encryption_key(&shared_secret);

    // AES-GCM ile şifrele
    let nonce = generate_random_nonce();
    let mut cipher = aes_gcm::Aes256Gcm::new(encryption_key.as_slice().into());
    let ciphertext = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|_| ProgramError::InvalidArgument)?;

    Ok(ciphertext)
}

fn compute_shared_secret(
    ephemeral_keypair: &secp256k1::KeyPair,
    recipient_pubkey: &[u8; 33],
) -> Result<[u8; 32], ProgramError> {
    let secp = Secp256k1::new();
    let recipient_pk = PublicKey::from_slice(recipient_pubkey)
        .map_err(|_| ProgramError::InvalidArgument)?;
    
    let shared_point = recipient_pk.mul_tweak(&secp, &ephemeral_keypair.secret_key().into())
        .map_err(|_| ProgramError::InvalidArgument)?;
    
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&shared_point.serialize()[1..33]);
    
    Ok(secret)
}

fn derive_encryption_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(b"ECIES_KEY");
    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());
    key
}

fn generate_random_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn upload_to_ipfs(data: &[u8]) -> Result<String, ProgramError> {
    // IPFS yükleme işlemi burada implement edilecek
    // Bu fonksiyon şu an için mock veri dönüyor
    Ok(format!("Qm{}", hex::encode(&data[..16])))
} 