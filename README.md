# zkλ Architecture Documentation
*Version 2, Codename "sulli"*

## Project Overview

### Artistic & Philosophical Influences
> *"Featuring f(x), and Derrida destroying a shawarma."*

### Development Soundtrack
*Curated musical accompaniment for the project:*
- **Development Playlist**: [Development Soundtrack](https://open.spotify.com/playlist/46KlhNJioNZh07IZjHw9as)
- **Featured Album**: ["Pink Tape" by f(x)](https://open.spotify.com/album/62tuEHFtjk3L6Xjdkzyt4z)

---

## Core Terminology

### Essential Definitions

| Term | Definition | Additional Context |
|------|------------|-------------------|
| **OTD** | Open to Discussion | Marks areas requiring further team deliberation |
| **DSP** | Decentralized Storage Provider | Core infrastructure component |
| **userKeypair** | Platform-level user keypair | Also known as: zkλ keypair, system keypair, EC keypair |
| **userSolanaIdentity** | Solana blockchain keypair | User's primary blockchain identity |

### Keypair Components

#### userKeypair Specifications
- **Public Key**: `userKeypair.pubkey`
- **Private Key**: `userKeypair.privateKey`
- **Purpose**: Primary platform-level identification

#### userSolanaIdentity Specifications
- **Public Key**: `userSolanaIdentity.pubkey`
- **Private Key**: `userSolanaIdentity.privateKey`
- **Purpose**: Blockchain interaction authentication

---

## Architectural Notes

### Index Implementation
> *Important*: Initial implementations assume `idx = 0`

The index parameter serves multiple critical functions:
1. EC keypair revocation management
2. Version control implementation
3. Multiple identity linking capabilities
4. PDA pda_inbox implementation support

### Wormhole Integration Specifications

#### Current Limitations
- NTT implementation's limited ERC-721 focus
- Restrictions on NFT-based file information serialization

#### Alternative Solutions
- Custom contract implementation for cross-chain messaging
- Direct XCM implementation through dedicated pathways

---

## System Workflows

### User Onboarding Process

#### Initial Setup
1. *Client-Side Generation*
   - EC keypair creation
   - Platform identity establishment

2. *Security Implementation*
   - Application password configuration
   - Symmetric key derivation
   - Argon2id implementation
   - Private key encryption
   - Secure storage configuration

3. *Optional Security Features*
   > *Under Discussion*: Standard container export support
   - PKCS#8 container compatibility
   - PEM format support

#### Identity Linking Process
1. *Message Signing*
   - userKeypair.privateKey signature
   - userSolanaIdentity.privateKey verification

2. *PDA Creation*
   - Seed array implementation: [userSolanaIdentity.pubkey, idx]
   - Account initialization
   - Identity linkage confirmation

### File Transfer System

#### Security Architecture

##### Privacy Enhancement Methods
> *Proposed by Baturalp*: Ring signatures implementation

*Key Features*:
- Sender-receiver relationship concealment
- Peer relationship anonymization
- Platform-layer privacy protection

##### Implementation Considerations
- Blockchain transparency impact
- Network-level privacy limitations
- Platform-layer concealment strategies

#### Transfer Workflow

##### Sender Protocol
1. *Recipient Verification*
   - PDA ZkAccount retrieval
   - Public key validation
   - Message integrity verification

2. *File Processing*
   - ECIES encryption implementation
   - DSP upload procedure
   - Transaction record creation

3. *Transaction Completion*
   - Record transmission
   - Signature verification
   - Inbox synchronization

##### Recipient Protocol
1. *Transaction Monitoring*
   - Event emission tracking
   - PDA InboxAccount polling
   - Timestamp verification

2. *Security Verification*
   - DSP upload authenticity
   - Recipient validation
   - Sender key verification
   - Identity control confirmation

3. *File Retrieval*
   - Link decryption process
   - File download procedure
   - Content verification

---

## System Components

### Key Registry Architecture
*Program-Derived Address (PDA) Implementation*

#### ZklAccount Specifications
- *Address Derivation*: `[userKeypair.pubkey, idx]`
- *Data Structure*: Comprehensive account management
- *Security Features*: Authority control implementation

### Inbox System Design
*Enhanced Message Management*

#### Storage Optimization
> *Under Discussion*: Implementation options
- Timestamp-based expiration
- Circular buffer pattern
- Rent optimization strategies

---

## Message Protocol

### Account Connection
*Format*: 
> "ZklAccount: linking EC address ${userKeypair.pubkey} to Solana identity ${userSolanaIdentity.pubkey} with index ${idx}"

### File Transfer Communication
*Format*:
> "ZklFileTransfer: sending file with hash ${H(fileCipher)} to ${recipientKeypair.pubkey} from ${senderKeypair.pubkey}"

---

## Implementation Flow

### User Key Linking Process
*Detailed Workflow Sequence*

1. **Client-Side Operations**
   - PDA address calculation
   - Transaction preparation
   - Data validation

2. **Transaction Processing**
   - PDA verification
   - Account creation
   - Data initialization

3. **Registry Program Operations**
   - Derivation verification
   - Account initialization
   - Authority assignment

---

## Technical References

### Security Standards
1. [Password Storage Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
2. [PKCS#8 Protocol Specifications](https://datatracker.ietf.org/doc/html/rfc5208)
3. [PEM Format Documentation](https://datatracker.ietf.org/doc/html/rfc7468)

### Development Resources
4. [Solana PDA Guide](https://solana.com/tr/docs/core/pda)
5. [TweetNaCl Cryptography](https://tweetnacl.cr.yp.to/)
6. [ECIES Implementation Guide](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption)
7. [zkl-crypto Repository](https://github.com/fybx/zkl-crypto)

### Integration Documentation
8. [Wormhole Token Standards](https://wormhole.com/docs/learn/messaging/native-token-transfers/overview/#supported-token-standards)
9. [Cross-Chain Contract Guide](https://wormhole.com/docs/tutorials/by-product/contract-integrations/cross-chain-contracts/)

### Cryptographic References
10. [Ring Signature Fundamentals](https://en.wikipedia.org/wiki/Ring_signature)
11. [Advanced Signature Applications](https://en.wikipedia.org/wiki/Ring_signature#Applications_and_modifications)

---

## Future Considerations

### System Enhancement Opportunities
- Multi-chain support expansion
- Advanced privacy implementation
- Performance optimization strategies
- Security feature augmentation

### Maintenance Requirements
- Regular security audits
- Performance monitoring
- Documentation updates
- Community feedback integration

---

*Document Version: 2.0.0*
*Last Updated: February 2025*
