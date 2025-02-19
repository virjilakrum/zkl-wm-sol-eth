use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    program_pack::Pack,
    program::invoke,
    system_instruction,
    sysvar::rent::Rent,
    sysvar::Sysvar,
    entrypoint::ProgramResult,
};
use sha3::{Digest, Keccak256};

// Wormhole sabit değerleri
pub const GUARDIAN_SET_SIZE: usize = 19;
pub const CONSISTENCY_LEVEL: u8 = 15; // Minimum tutarlılık seviyesi
pub const MAX_LEN_GUARDIAN_KEYS: usize = 19;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VAA {
    pub version: u8,
    pub guardian_set_index: u32,
    pub signatures: Vec<Signature>,
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub consistency_level: u8,
    pub payload: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Signature {
    pub guardian_set_index: u8,
    pub signature: [u8; 65],
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct WormholeConfig {
    pub guardian_set_index: u32,
    pub guardian_set_expiry: u32,
    pub message_fee: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct GuardianSet {
    pub index: u32,
    pub keys: Vec<[u8; 20]>,
    pub creation_time: u32,
    pub expiration_time: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct MessageData {
    pub vaa_version: u8,
    pub consistency_level: u8,
    pub vaa_time: u32,
    pub vaa_signature_account: Pubkey,
    pub submission_time: u32,
    pub nonce: u32,
    pub sequence: u64,
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub payload: Vec<u8>,
}

impl MessageData {
    pub fn new(
        vaa: &VAA,
        submission_time: u32,
        vaa_signature_account: Pubkey,
    ) -> Self {
        Self {
            vaa_version: vaa.version,
            consistency_level: vaa.consistency_level,
            vaa_time: vaa.timestamp,
            vaa_signature_account,
            submission_time,
            nonce: vaa.nonce,
            sequence: vaa.sequence,
            emitter_chain: vaa.emitter_chain,
            emitter_address: vaa.emitter_address,
            payload: vaa.payload.clone(),
        }
    }
}

pub fn post_message(
    bridge: &AccountInfo,
    message_acc: &AccountInfo,
    emitter: &AccountInfo,
    sequence_acc: &AccountInfo,
    payer: &AccountInfo,
    system_program: &AccountInfo,
    clock: &AccountInfo,
    rent: &AccountInfo,
    nonce: u32,
    payload: Vec<u8>,
    consistency_level: u8,
) -> Result<u64, ProgramError> {
    // Mesaj hesabı için gerekli alanı hesapla
    let message_size = 1 + payload.len();
    let rent = &Rent::from_account_info(rent)?;
    let lamports = rent.minimum_balance(message_size);

    // Mesaj hesabını oluştur
    invoke(
        &system_instruction::create_account(
            payer.key,
            message_acc.key,
            lamports,
            message_size as u64,
            bridge.key,
        ),
        &[
            payer.clone(),
            message_acc.clone(),
            system_program.clone(),
        ],
    )?;

    // Sequence numarasını artır
    let mut sequence = sequence_acc.try_borrow_mut_data()?;
    let current_sequence = u64::from_le_bytes(sequence[0..8].try_into().unwrap());
    let new_sequence = current_sequence.checked_add(1).ok_or(ProgramError::Overflow)?;
    sequence[0..8].copy_from_slice(&new_sequence.to_le_bytes());

    // Mesaj verilerini hazırla ve kaydet
    let mut message_data = message_acc.try_borrow_mut_data()?;
    message_data[0] = 0x01; // Mesaj tipi
    message_data[1..].copy_from_slice(&payload);

    Ok(new_sequence)
}

pub fn verify_signature(
    bridge: &AccountInfo,
    signature_set: &AccountInfo,
    guardian_set: &AccountInfo,
    vaa: &VAA,
) -> ProgramResult {
    // Guardian set'i doğrula
    if vaa.guardian_set_index != guardian_set.try_borrow_data()?[0] {
        return Err(ProgramError::InvalidArgument);
    }

    // İmza sayısını kontrol et
    let signature_count = vaa.signatures.len();
    if signature_count < (MAX_LEN_GUARDIAN_KEYS * 2 / 3) {
        return Err(ProgramError::InvalidArgument);
    }

    // İmzaları doğrula
    let mut signed_guardian_indices = vec![false; MAX_LEN_GUARDIAN_KEYS];
    for signature in &vaa.signatures {
        if signature.guardian_set_index as usize >= MAX_LEN_GUARDIAN_KEYS {
            return Err(ProgramError::InvalidArgument);
        }
        if signed_guardian_indices[signature.guardian_set_index as usize] {
            return Err(ProgramError::InvalidArgument);
        }
        signed_guardian_indices[signature.guardian_set_index as usize] = true;
    }

    Ok(())
}

pub fn verify_consistency_level(
    vaa: &VAA,
    required_level: u8,
) -> ProgramResult {
    if vaa.consistency_level < required_level {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

pub fn parse_and_verify_vaa(
    bridge: &AccountInfo,
    vaa_data: &[u8],
) -> Result<VAA, ProgramError> {
    let vaa = VAA::try_from_slice(vaa_data)?;
    
    // VAA versiyonunu kontrol et
    if vaa.version != 1 {
        return Err(ProgramError::InvalidArgument);
    }

    // Tutarlılık seviyesini kontrol et
    verify_consistency_level(&vaa, CONSISTENCY_LEVEL)?;

    Ok(vaa)
}

pub fn compute_vaa_hash(vaa: &VAA) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    
    // VAA alanlarını hash'e ekle
    hasher.update(&[vaa.version]);
    hasher.update(&vaa.guardian_set_index.to_be_bytes());
    hasher.update(&vaa.timestamp.to_be_bytes());
    hasher.update(&vaa.nonce.to_be_bytes());
    hasher.update(&vaa.emitter_chain.to_be_bytes());
    hasher.update(&vaa.emitter_address);
    hasher.update(&vaa.sequence.to_be_bytes());
    hasher.update(&[vaa.consistency_level]);
    hasher.update(&vaa.payload);

    hasher.finalize().into()
}

pub fn initialize_bridge(
    program_id: &Pubkey,
    bridge: &AccountInfo,
    guardian_set: &AccountInfo,
    payer: &AccountInfo,
    system_program: &AccountInfo,
    rent: &AccountInfo,
) -> ProgramResult {
    // Bridge hesabını oluştur
    let bridge_size = std::mem::size_of::<WormholeConfig>();
    let rent = &Rent::from_account_info(rent)?;
    let bridge_lamports = rent.minimum_balance(bridge_size);

    invoke(
        &system_instruction::create_account(
            payer.key,
            bridge.key,
            bridge_lamports,
            bridge_size as u64,
            program_id,
        ),
        &[
            payer.clone(),
            bridge.clone(),
            system_program.clone(),
        ],
    )?;

    // Guardian set hesabını oluştur
    let guardian_size = std::mem::size_of::<GuardianSet>();
    let guardian_lamports = rent.minimum_balance(guardian_size);

    invoke(
        &system_instruction::create_account(
            payer.key,
            guardian_set.key,
            guardian_lamports,
            guardian_size as u64,
            program_id,
        ),
        &[
            payer.clone(),
            guardian_set.clone(),
            system_program.clone(),
        ],
    )?;

    // İlk yapılandırmayı kaydet
    let config = WormholeConfig {
        guardian_set_index: 0,
        guardian_set_expiry: 86400 * 30, // 30 gün
        message_fee: 0,
    };

    config.serialize(&mut *bridge.try_borrow_mut_data()?)?;

    Ok(())
}

pub fn update_guardian_set(
    program_id: &Pubkey,
    bridge: &AccountInfo,
    new_guardian_set: &AccountInfo,
    payer: &AccountInfo,
    system_program: &AccountInfo,
    rent: &AccountInfo,
    guardian_set: GuardianSet,
) -> ProgramResult {
    // Yeni guardian set hesabını oluştur
    let size = std::mem::size_of::<GuardianSet>();
    let rent = &Rent::from_account_info(rent)?;
    let lamports = rent.minimum_balance(size);

    invoke(
        &system_instruction::create_account(
            payer.key,
            new_guardian_set.key,
            lamports,
            size as u64,
            program_id,
        ),
        &[
            payer.clone(),
            new_guardian_set.clone(),
            system_program.clone(),
        ],
    )?;

    // Yeni guardian set'i kaydet
    guardian_set.serialize(&mut *new_guardian_set.try_borrow_mut_data()?)?;

    // Bridge yapılandırmasını güncelle
    let mut bridge_data = bridge.try_borrow_mut_data()?;
    let mut config = WormholeConfig::try_from_slice(&bridge_data)?;
    config.guardian_set_index = guardian_set.index;
    config.serialize(&mut *bridge_data)?;

    Ok(())
} 