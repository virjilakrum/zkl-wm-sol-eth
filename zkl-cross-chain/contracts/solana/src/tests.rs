#[test]
fn test_base64_ipfs_hash() {
    let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    let encoded = base64::encode(Sha256::digest(cid.as_bytes()));
    
    let decoded = base64::decode(&encoded).unwrap();
    assert_eq!(decoded.len(), 32);
    
    let record = FileTxRecord {
        sender: [0u8; 32],
        ipfs_hash: encoded,
        timestamp: 0,
        proof: [0u8; 64],
    };
    
    assert!(record.ipfs_hash.len() == 44); // Base64 string uzunluğu
}

#[test]
fn test_full_flow() {
    // 1. Key Registration
    let (ec_pubkey, ec_secret) = zkl_crypto::generate_keypair();
    let signature = zkl_crypto::sign_message(b"Linking message", &ec_secret);
    
    // 2. File Transfer
    let link = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    let (encrypted, ephemeral) = zkl_crypto::ecies_encrypt(&ec_pubkey, link.as_bytes());
    
    // 3. Inbox Check
    let inbox = get_inbox_account(program_id, &ec_pubkey);
    let decrypted = zkl_crypto::ecies_decrypt(
        &ec_secret, 
        &base64::decode(inbox.messages[0].encrypted_link).unwrap(),
        &inbox.messages[0].ephemeral_pubkey
    );
    
    assert_eq!(decrypted, link.as_bytes());
}

#[test]
fn test_full_ecies_flow() {
    // Key pair oluştur
    let (sender_pub, sender_priv) = zkl_crypto::generate_keypair();
    let (recipient_pub, recipient_priv) = zkl_crypto::generate_keypair();

    // Mesaj şifreleme
    let link = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    let (encrypted, ephemeral) = zkl_crypto::ecies_encrypt(&recipient_pub, link.as_bytes());

    // Şifre çözme
    let decrypted = zkl_crypto::ecies_decrypt(
        &recipient_priv,
        &encrypted,
        &ephemeral
    );

    assert_eq!(decrypted, link.as_bytes());
}

#[test]
fn test_inbox_circular_buffer() {
    let mut inbox = InboxAccount::new([1; 33], [2; 32]);
    
    for i in 0..150 {
        inbox.add_message(FileTxRecord {
            sender_ec_pubkey: [3; 33],
            encrypted_link: "test".to_string(),
            ephemeral_pubkey: [4; 33],
            timestamp: i as i64,
            proof: [0; 64],
        });
    }

    assert_eq!(inbox.messages.len(), 100);
    assert_eq!(inbox.message_count, 100);
} 