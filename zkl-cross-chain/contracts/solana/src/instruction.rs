use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum CrossChainInstruction {
    /// Yeni bir ZKL hesabı kaydeder
    /// 
    /// Accounts:
    /// 0. `[signer]` Kullanıcı hesabı
    /// 1. `[writable]` ZKL hesap PDA'sı
    /// 2. `[]` System programı
    RegisterZklAccount {
        /// EC public key
        ec_pubkey: [u8; 33],
        /// ZKL imzası
        zkl_signature: [u8; 64],
        /// Solana imzası
        solana_signature: [u8; 64],
        /// Hesap indeksi
        index: u32,
    },

    /// Dosya gönderir
    ///
    /// Accounts:
    /// 0. `[signer]` Gönderen hesap
    /// 1. `[writable]` Alıcı inbox'ı
    /// 2. `[]` System programı
    SendFile {
        /// Alıcı EC public key
        recipient_ec_pubkey: [u8; 33],
        /// Şifrelenmiş dosya linki
        encrypted_link: String,
        /// Ephemeral public key
        ephemeral_pubkey: [u8; 33],
        /// Dosya hash'i
        file_hash: [u8; 64],
    },

    /// Dosya alır
    ///
    /// Accounts:
    /// 0. `[signer]` Alıcı hesabı
    /// 1. `[writable]` Inbox hesabı
    ReceiveFile,
}

impl CrossChainInstruction {
    /// Talimatı serialize eder
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1000);
        match self {
            Self::RegisterZklAccount { ec_pubkey, zkl_signature, solana_signature, index } => {
                buf.push(0x00);
                buf.extend_from_slice(ec_pubkey);
                buf.extend_from_slice(zkl_signature);
                buf.extend_from_slice(solana_signature);
                buf.extend_from_slice(&index.to_le_bytes());
            }
            Self::SendFile { recipient_ec_pubkey, encrypted_link, ephemeral_pubkey, file_hash } => {
                buf.push(0x01);
                buf.extend_from_slice(recipient_ec_pubkey);
                buf.extend_from_slice(encrypted_link.as_bytes());
                buf.extend_from_slice(ephemeral_pubkey);
                buf.extend_from_slice(file_hash);
            }
            Self::ReceiveFile => {
                buf.push(0x02);
            }
        }
        buf
    }
} 