pub struct CrossChainMessage {
    pub sender: Pubkey,
    pub recipient: Pubkey,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub signature: [u8; 64]
}

pub fn verify_message(
    message: &CrossChainMessage,
    expected_sender: &Pubkey
) -> ProgramResult {
    let message_data = borsh::to_vec(&message)?;
    let hash = sha2::Sha256::digest(&message_data);
    
    zkl_crypto::ecdsa_verify(
        &hash,
        &message.signature,
        expected_sender
    )
}