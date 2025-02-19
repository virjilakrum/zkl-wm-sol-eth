use solana_program::program_error::ProgramError;
use thiserror::Error;
use std::str::FromUtf8Error;
use std::slice::TryFromSliceError;

#[derive(Error, Debug)]
pub enum CrossChainError {
    #[error("Invalid instruction")]
    InvalidInstruction,

    #[error("Invalid authority")]
    InvalidAuthority,

    #[error("Invalid PDA")]
    InvalidPDA,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid message format")]
    InvalidMessageFormat,

    #[error("Inbox is full")]
    InboxFull,

    #[error("File too large")]
    FileTooLarge,

    #[error("Invalid file hash")]
    InvalidFileHash,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid IPFS hash")]
    InvalidIpfsHash,

    #[error("Invalid ephemeral key")]
    InvalidEphemeralKey,

    #[error("Invalid MAC")]
    InvalidMac,

    #[error("Storage error")]
    StorageError,

    #[error("Account not initialized")]
    AccountNotInitialized,

    #[error("Account already initialized")]
    AccountAlreadyInitialized,

    #[error("Invalid account owner")]
    InvalidAccountOwner,

    #[error("Invalid account data")]
    InvalidAccountData,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("File expired")]
    FileExpired,

    #[error("Invalid message index")]
    InvalidMessageIndex,

    #[error("Account not active")]
    AccountNotActive,
}

impl From<CrossChainError> for ProgramError {
    fn from(e: CrossChainError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl From<TryFromSliceError> for CrossChainError {
    fn from(_: TryFromSliceError) -> Self {
        CrossChainError::InvalidMessageFormat
    }
}

impl From<FromUtf8Error> for CrossChainError {
    fn from(_: FromUtf8Error) -> Self {
        CrossChainError::InvalidMessageFormat
    }
}

impl From<&str> for CrossChainError {
    fn from(_: &str) -> Self {
        CrossChainError::InvalidMessageFormat
    }
} 