zkλ Architecture Rework
Version 1
Glossary
OTD: open to discussion
DSP: decentralized storage provider

Notes
The “index” used within user onboarding may or may not be used for EC keypair revocation, versioning, etc. For initial implementations, assume idx = 0.
The index can also be used to link multiple EC keypair identities to a single Solana identity; this function can come in handy when implementing PDA pda_inbox
Stream https://open.spotify.com/playlist/46KlhNJioNZh07IZjHw9as
About Wormhole’s NTT and doing multichain file transfers: currently Wormhole’s NTT implementation doesn’t focus on ERC-721, [8] and therefore we can’t serialize file information as an NFT with custom fields. However, it seems possible to do XCM with our custom built contracts by directly using [9]
Timestamps/nonces might be used where messages are signed
Document zkl-crypto, and ECIES in depth, here.

1- User Onboarding
User creates EC keypair, client-side. (userKeypair)
User sets an application password, this password will be used to derive the symmetric key to encrypt the private key from userKeypair. Encrypted private key will be stored in local storage, alongside necessary details for deriving the symmetric key. Employ Argon2id [1] for key derivation.
OTD: Allow private key to be exported in standard containers (PKCS#8 [2], PEM [3])
User links EC keypair to Solana address
Sign a message with format “Linking EC address ${userKeypair.pubkey} to ${userSolanaIdentity.pubkey} with index ${idx}”
Create PDA [4] “key_reg_pda” (see section PDAs) with a seed value “Buffer.from(`${userSolanaIdentity.pubkey}, ${idx}`)”
Do transaction and publish user’s EC keypair of index idx, ultimately linking it to their Solana identity userSolanaIdentity

2- File Transfer Flow

2.1- Notes
Ring signatures [10] was suggested by Baturalp, and “deniable signatures” [11] look applicable to our system, where we can also conceal the relation between the sender and the receiver, only revealing them as “peers”, but nothing more. While this feature is desirable, the underlying blockchain networks we employ break the concealment we achieve by our platform layer.

2.2- Sender Actions
Fetch recipient’s recipientKeypair.pubkey from PDA key_reg_pda
Find PDA address using program ID of register_key, and seed value “Buffer.from(`${recipientKeypair.pubkey}, ${idx}`)
Fetch signed_message field, and verify message validity. Employ TweetNaCl [5]
IF (step b) is unsuccessful, discard; ELSE continue
Use Elliptic Curve Integrated Encryption Scheme [6] to encrypt plaintext file filePlain. Employ zkl-crypto [7] (authored by me, implementation and tests are complete)
Upload ephemeral public key fileEphPubkey, ciphertext file fileCipher to DSP, get link to the file linkToFile
Sender transmits fileTxRecord to recipient’s inbox
Sign a message with format “Sending file with hash ${H(fileCipher)} to ${recipientKeypair.pubkey} from ${senderKeypair.pubkey}”
fileTxRecord := { signed_message, E(linkToFile, ephPubkey), ephPubkey }

2.3- Recipient Actions
Watch for emitted events OR poll PDA InboxAccount regularly
IF polling, go through transaction timestamps to find new ones (assuming InboxAccount uses the circular buffer account storage model)
WHEN a new transaction is found
Verify signed_message from fileTxRecord; If the check passes, this ultimately confirms that
The encrypted file to be downloaded from DSP is the file claimed to be uploaded to the DSP by the sender
The file was meant to be received by the receiver
The file was sent by a person with access to the sender’s private key from their EC keypair
The sender’s Solana identity owns and controls the EC keypair (via the check performed by program Inbox)
Perform decryption of E(linkToFile, ephPubkey) via D(E(linkToFile, ephPubkey), ephPubkey, recipientKeypair.privkey) to find linkToFile
Download fileCipher from DSP via linkToFile
Decrypt fileCipher using ECIES, where recipientKeypair.privkey is utilized again. Employ zkl-crypto, as it’s employed at (step 2.1.2)
The successful decryption of fileCipher yields filePlain while confirming that
The file was encrypted only for the recipient to decrypt it
The file was not tampered with
The file was not corrupted

Programs & PDAs
Key Registry
Address derived from seed [userKeypair.pubkey, index]
Note: Add pseudocode

Structures
struct key_reg_pda {
    ec_pubkey: 		[u8; 33], // compressed EC pubkey
    signed_message: 	[u8; 64], // message signed at (step a)
    index: 		u32
}

Inbox
Defines PDA “InboxAccount”: address derived from seed [userKeypair.pubkey, index]
OTD: A timestamp-based message expiration to pay less rent for account storage OR round-robin (circular buffer pattern)

Structures
struct FileTXRecord { 
    sender_ec_pubkey: [u8; 33], 	// compressed EC pubkey
    encrypted_link: 	string, 	// E(linkToFileOnDSP)
    ephemeral_pubkey: [u8; 33],	// for decrypting encrypted_link
    timestamp: 		i64
}

struct InboxAccount { 
    recipient_ec_pubkey: 	[u8, 33], 	// compressed EC pubkey
    recipient_wallet: 	Pubkey, 	// the recipient's Solana wallet 
    messages: 			Vec<FileTXRecord>
}

References
[1] https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[2] https://datatracker.ietf.org/doc/html/rfc5208
[3] https://datatracker.ietf.org/doc/html/rfc7468
[4] https://solana.com/tr/docs/core/pda
[5] https://tweetnacl.cr.yp.to/
[6] https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption
[7] https://github.com/fybx/zkl-crypto
[8] https://wormhole.com/docs/learn/messaging/native-token-transfers/overview/#supported-token-standards
[9] https://wormhole.com/docs/tutorials/by-product/contract-integrations/cross-chain-contracts/
[10] https://en.wikipedia.org/wiki/Ring_signature
[11] https://en.wikipedia.org/wiki/Ring_signature#Applications_and_modifications

