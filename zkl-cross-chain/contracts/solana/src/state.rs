use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;
use sha3::{Digest, Keccak512};
use secp256k1::{Secp256k1, PublicKey};
use solana_program::clock::Clock;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ZklAccountData {
    pub ec_pubkey: [u8; 33],      // compressed EC pubkey
    pub zkl_sm: [u8; 64],         // message signed with zkλ
    pub solana_sm: [u8; 64],      // message signed with Solana identity
    pub index: u32,               // Multi-key management index
    pub created_at: i64,          // Account creation timestamp
    pub last_used: i64,           // Last usage timestamp
    pub is_active: bool,          // Account status
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ZklAccount {
    pub discriminator: [u8; 8],    // Required by Solana
    pub authority: Pubkey,         // Account authority
    pub zkl_data: ZklAccountData,  // Account data
    pub bump: u8,                  // PDA bump
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct FileMetadata {
    pub ipfs_hash: String,         // IPFS CIDv1 (base32)
    pub file_size: u64,           // File size in bytes
    pub file_hash: [u8; 64],      // Keccak512 hash
    pub mime_type: String,        // File type
    pub created_at: i64,          // Unix timestamp
    pub encrypted: bool,          // Encryption status
    pub ephemeral_pubkey: Option<[u8; 33]>, // ECIES ephemeral pubkey
    pub mac: Option<[u8; 32]>,    // ECIES MAC
    pub compression_enabled: bool, // Compression status
    pub chunk_size: Option<u32>,  // For large files
    pub total_chunks: Option<u32>, // For large files
    pub allowed_viewers: Vec<[u8; 33]>, // List of EC pubkeys allowed to view
    pub expiration_time: Option<i64>, // Optional expiration
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct FileTxRecord {
    pub sender_ec_pubkey: [u8; 33],    // compressed EC pubkey
    pub encrypted_link: String,         // E(linkToFileOnDSP)
    pub ephemeral_pubkey: [u8; 33],    // for decrypting encrypted_link
    pub timestamp: i64,                 // Unix timestamp
    pub status: TransferStatus,        // Transfer status
    pub retry_count: u8,               // Number of retry attempts
    pub last_retry: Option<i64>,       // Last retry timestamp
    pub gas_used: Option<u64>,         // Gas used for transfer
    pub confirmation_time: Option<i64>, // When transfer was confirmed
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum TransferStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
    Expired,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct InboxAccount {
    pub recipient_ec_pubkey: [u8; 33],  // compressed EC pubkey
    pub recipient_wallet: Pubkey,        // recipient's Solana wallet
    pub messages: Vec<FileTxRecord>,     // Message records
    pub bump: u8,                        // PDA bump
    pub total_received: u64,             // Total messages received
    pub total_storage: u64,              // Total storage used
    pub last_pruned: i64,               // Last pruning timestamp
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct TransferMetrics {
    pub total_transfers: u64,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub total_bytes_transferred: u64,
    pub average_transfer_time: u64,
    pub last_updated: i64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct RateLimiter {
    pub last_request_time: i64,
    pub request_count: u32,
    pub max_requests_per_minute: u32,
    pub cooldown_period: u64,
}

impl ZklAccount {
    pub const DISCRIMINATOR: [u8; 8] = *b"zklaccnt";
    pub const SIZE: usize = 8 + 32 + std::mem::size_of::<ZklAccountData>() + 1;

    pub fn new(
        authority: Pubkey,
        zkl_data: ZklAccountData,
        bump: u8
    ) -> Self {
        Self {
            discriminator: Self::DISCRIMINATOR,
            authority,
            zkl_data,
            bump,
        }
    }

    pub fn is_expired(&self, current_time: i64) -> bool {
        current_time > self.zkl_data.last_used + (30 * 24 * 60 * 60) // 30 days
    }
}

impl FileMetadata {
    pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB
    pub const ALLOWED_MIME_TYPES: [&'static str; 4] = [
        "application/pdf",
        "image/jpeg",
        "image/png",
        "text/plain"
    ];

    pub fn new(
        ipfs_hash: String,
        file_size: u64,
        file_hash: [u8; 64],
        mime_type: String,
        created_at: i64,
        encrypted: bool,
        ephemeral_pubkey: Option<[u8; 33]>,
        mac: Option<[u8; 32]>,
        compression_enabled: bool,
    ) -> Result<Self, &'static str> {
        if file_size > Self::MAX_FILE_SIZE {
            return Err("File too large");
        }

        if !Self::ALLOWED_MIME_TYPES.contains(&mime_type.as_str()) {
            return Err("Unsupported file type");
        }

        Ok(Self {
            ipfs_hash,
            file_size,
            file_hash,
            mime_type,
            created_at,
            encrypted,
            ephemeral_pubkey,
            mac,
            compression_enabled,
            chunk_size: None,
            total_chunks: None,
            allowed_viewers: Vec::new(),
            expiration_time: None,
        })
    }

    pub fn verify_hash(&self, data: &[u8]) -> bool {
        let mut hasher = Keccak512::new();
        hasher.update(data);
        let computed_hash: [u8; 64] = hasher.finalize().into();
        computed_hash == self.file_hash
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.expiration_time {
            Clock::get().unwrap().unix_timestamp >= expiration
        } else {
            false
        }
    }

    pub fn can_view(&self, viewer_pubkey: &[u8; 33]) -> bool {
        self.allowed_viewers.is_empty() || self.allowed_viewers.contains(viewer_pubkey)
    }
}

impl FileTxRecord {
    pub fn new(
        sender_ec_pubkey: [u8; 33],
        encrypted_link: String,
        ephemeral_pubkey: [u8; 33],
        timestamp: i64,
        status: TransferStatus,
        retry_count: u8,
        last_retry: Option<i64>,
        gas_used: Option<u64>,
        confirmation_time: Option<i64>,
    ) -> Self {
        Self {
            sender_ec_pubkey,
            encrypted_link,
            ephemeral_pubkey,
            timestamp,
            status,
            retry_count,
            last_retry,
            gas_used,
            confirmation_time,
        }
    }

    pub fn update_status(&mut self, new_status: TransferStatus) {
        self.status = new_status;
        if matches!(new_status, TransferStatus::Completed) {
            self.confirmation_time = Some(Clock::get().unwrap().unix_timestamp);
        }
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < 3 && matches!(self.status, TransferStatus::Failed(_))
    }

    pub fn record_retry(&mut self) {
        self.retry_count += 1;
        self.last_retry = Some(Clock::get().unwrap().unix_timestamp);
        self.status = TransferStatus::Pending;
    }
}

impl InboxAccount {
    pub const MAX_MESSAGES: usize = 100;
    pub const PRUNING_THRESHOLD: usize = 90; // 90% full
    pub const MAX_STORAGE: u64 = 1024 * 1024 * 1024; // 1GB
    
    pub fn new(recipient_ec_pubkey: [u8; 33], recipient_wallet: Pubkey, bump: u8) -> Self {
        Self {
            recipient_ec_pubkey,
            recipient_wallet,
            messages: Vec::new(),
            bump,
            total_received: 0,
            total_storage: 0,
            last_pruned: Clock::get().unwrap().unix_timestamp,
        }
    }
    
    pub fn add_message(&mut self, record: FileTxRecord) -> Result<(), &'static str> {
        // Storage limit check
        if self.total_storage + record.encrypted_link.len() as u64 > Self::MAX_STORAGE {
            return Err("Storage limit exceeded");
        }

        // Auto-pruning if needed
        if self.messages.len() >= Self::MAX_MESSAGES * Self::PRUNING_THRESHOLD / 100 {
            self.prune_old_messages();
        }

        self.messages.push(record);
        self.total_received += 1;
        self.total_storage += record.encrypted_link.len() as u64;
        Ok(())
    }

    pub fn prune_old_messages(&mut self) {
        let current_time = Clock::get().unwrap().unix_timestamp;
        let one_month_ago = current_time - (30 * 24 * 60 * 60);

        self.messages.retain(|msg| {
            match msg.status {
                TransferStatus::Completed => msg.timestamp > one_month_ago,
                TransferStatus::Failed(_) => msg.timestamp > one_month_ago,
                _ => true
            }
        });

        self.last_pruned = current_time;
    }

    pub fn get_latest_messages(&self, count: usize) -> Vec<FileTxRecord> {
        let start = self.messages.len().saturating_sub(count);
        self.messages[start..].to_vec()
    }

    pub fn get_pending_messages(&self) -> Vec<FileTxRecord> {
        self.messages.iter()
            .filter(|msg| matches!(msg.status, TransferStatus::Pending))
            .cloned()
            .collect()
    }
} 