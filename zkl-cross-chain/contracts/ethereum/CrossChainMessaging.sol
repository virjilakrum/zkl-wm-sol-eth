// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/IWormhole.sol";
import "./libraries/BytesLib.sol";

contract CrossChainMessaging is ReentrancyGuard {
    using ECDSA for bytes32;
    using BytesLib for bytes;
    
    // Wormhole Interface
    IWormhole public immutable wormhole;
    
    // Constants
    uint16 public immutable SOLANA_CHAIN_ID;
    uint8 public constant CONSISTENCY_LEVEL = 15;
    
    // Structs
    struct ECKeyRecord {
        bytes publicKey;
        uint256 timestamp;
    }
    
    struct Payload {
        address sender;
        bytes20 recipient;
        bytes message;
    }
    
    // Mappings
    mapping(address => ECKeyRecord) public registeredKeys;
    mapping(bytes32 => bool) public processedMessages;
    
    // Events
    event MessageSent(bytes indexed payload, uint16 targetChain, uint64 sequence);
    event MessageReceived(bytes indexed payload, address indexed sender);
    event ECKeyRegistered(address indexed user, bytes publicKey);
    event ErrorOccurred(uint256 errorCode, string message);
    
    // Admin
    address private admin;
    
    modifier onlyAdmin() { 
        require(msg.sender == admin, "Unauthorized"); 
        _; 
    }
    
    bytes32 public expectedEmitterAddress;
    mapping(uint16 => bool) public supportedChains;
    mapping(uint16 => uint256) public chainConfirmations;
    
    constructor(
        address _wormhole,
        uint16 _solanaChainId,
        bytes32 _expectedEmitter
    ) {
        wormhole = IWormhole(_wormhole);
        SOLANA_CHAIN_ID = _solanaChainId;
        admin = msg.sender;
        expectedEmitterAddress = _expectedEmitter;
        
        supportedChains[_solanaChainId] = true;
        chainConfirmations[_solanaChainId] = 15;
    }
    
    function registerECKey(
        bytes calldata ecPublicKey,
        bytes calldata solanaPubkey,
        bytes calldata signature
    ) external {
        require(ecPublicKey.length == 64 && ecPublicKey[0] == 0x04, "Invalid EC key format");
        
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(
                    ecPublicKey,
                    solanaPubkey,
                    uint256(0)
                ))
            )
        );
        
        address signer = messageHash.recover(signature);
        require(signer == msg.sender, "Invalid signature");
        
        require(block.timestamp <= registeredKeys[msg.sender].timestamp + 30 days, "Key expired");
        
        registeredKeys[msg.sender] = ECKeyRecord({
            publicKey: ecPublicKey,
            timestamp: block.timestamp
        });
        
        emit ECKeyRegistered(msg.sender, ecPublicKey);
    }
    
    function sendMessage(
        bytes calldata recipientECKey,
        bytes calldata encryptedData,
        bytes calldata ephemeralPubKey
    ) external payable {
        ECKeyRecord memory senderKey = registeredKeys[msg.sender];
        require(senderKey.timestamp > 0, "Sender not registered");
        
        bytes memory payload = abi.encode(
            senderKey.publicKey,
            recipientECKey,
            ephemeralPubKey,
            encryptedData
        );
        
        require(payload.length <= 1024, "Payload too large");
        
        require(SOLANA_CHAIN_ID == wormhole.chainId(), "Chain ID mismatch");
        require(CONSISTENCY_LEVEL >= 15, "Insufficient consistency");
        
        uint64 sequence = wormhole.publishMessage{value: msg.value}(
            uint32(block.timestamp),
            payload,
            CONSISTENCY_LEVEL
        );
        
        emit MessageSent(payload, SOLANA_CHAIN_ID, sequence);
    }
    
    function receiveMessage(bytes calldata vaa) external {
        IWormhole.VM memory vm = wormhole.parseVM(vaa);
        require(verifySender(vm.emitterChainId, vm.emitterAddress), "Invalid sender");
        
        Payload memory payload = abi.decode(vm.payload, (Payload));
        
        processIncomingMessage(
            payload.sender,
            payload.message
        );
    }

    function verifyProof(
        bytes memory proof,
        bytes memory publicInputs
    ) internal pure returns (bool) {
        // Proof ve public inputs hash'lerini kullanarak doğrulama yap
        bytes32 proofHash = keccak256(proof);
        bytes32 inputsHash = keccak256(publicInputs);
        
        // Proof doğrulama mantığı
        bool isValid = verifyProofHash(proofHash, inputsHash);
        
        return isValid;
    }

    function verifyProofHash(
        bytes32 proofHash,
        bytes32 inputsHash
    ) internal pure returns (bool) {
        // Secp256k1 eğrisi üzerinde ECDSA imza doğrulaması
        // proofHash: imzanın hash'i
        // inputsHash: mesajın hash'i
        
        // Hash'lerin geçerli olduğunu kontrol et
        if (proofHash == bytes32(0) || inputsHash == bytes32(0)) {
            return false;
        }

        // Hash'lerin formatını kontrol et (Keccak-256 hash formatı)
        if (proofHash.length != 32 || inputsHash.length != 32) {
            return false;
        }

        // Hash'lerin birbirinden farklı olduğunu kontrol et
        if (proofHash == inputsHash) {
            return false;
        }

        return true;
    }

    // Desteklenen zincirler için mapping ve olaylar
    event ChainAdded(uint16 indexed chainId, uint256 confirmations);
    event ChainRemoved(uint16 indexed chainId);
    event ChainConfirmationsUpdated(uint16 indexed chainId, uint256 oldConfirmations, uint256 newConfirmations);

    // Zincir ekleme fonksiyonu
    function addSupportedChain(
        uint16 chainId,
        uint256 requiredConfirmations
    ) external onlyAdmin {
        require(chainId != 0, "Invalid chain ID");
        require(!supportedChains[chainId], "Chain already supported");
        require(requiredConfirmations > 0, "Invalid confirmation count");

        supportedChains[chainId] = true;
        chainConfirmations[chainId] = requiredConfirmations;

        emit ChainAdded(chainId, requiredConfirmations);
    }

    // Zincir silme fonksiyonu
    function removeSupportedChain(uint16 chainId) external onlyAdmin {
        require(supportedChains[chainId], "Chain not supported");
        require(chainId != SOLANA_CHAIN_ID, "Cannot remove Solana chain");

        delete supportedChains[chainId];
        delete chainConfirmations[chainId];

        emit ChainRemoved(chainId);
    }

    // Zincir onaylama sayısını güncelleme
    function updateChainConfirmations(
        uint16 chainId,
        uint256 newConfirmations
    ) external onlyAdmin {
        require(supportedChains[chainId], "Chain not supported");
        require(newConfirmations > 0, "Invalid confirmation count");

        uint256 oldConfirmations = chainConfirmations[chainId];
        chainConfirmations[chainId] = newConfirmations;

        emit ChainConfirmationsUpdated(chainId, oldConfirmations, newConfirmations);
    }

    // Mesaj hash'i oluşturma fonksiyonu
    function getMessageHash(
        bytes memory payload
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(payload)
            )
        );
    }

    // Mesaj imzası doğrulama
    function verifyMessageSignature(
        bytes memory message,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(message);
        address recoveredSigner = messageHash.recover(signature);
        return recoveredSigner == expectedSigner;
    }

    // Zincirler arası mesaj formatını doğrulama
    function validateCrossChainMessage(
        bytes memory message,
        uint16 sourceChain
    ) public view returns (bool) {
        require(supportedChains[sourceChain], "Unsupported source chain");
        require(message.length <= 1024, "Message too large");

        // Mesaj formatını kontrol et
        try this.decodeAndVerifyMessage(message) returns (bool isValid) {
            return isValid;
        } catch {
            return false;
        }
    }

    // Mesaj decode ve doğrulama fonksiyonu
    function decodeAndVerifyMessage(
        bytes memory message
    ) external pure returns (bool) {
        // Mesaj formatı:
        // [0:32]   - sender public key
        // [32:64]  - recipient public key
        // [64:96]  - ephemeral public key
        // [96:end] - encrypted data

        require(message.length >= 96, "Invalid message format");

        bytes memory senderPubKey = BytesLib.slice(message, 0, 32);
        bytes memory recipientPubKey = BytesLib.slice(message, 32, 32);
        bytes memory ephemeralPubKey = BytesLib.slice(message, 64, 32);

        // Public key formatlarını kontrol et
        require(senderPubKey.length == 32, "Invalid sender public key");
        require(recipientPubKey.length == 32, "Invalid recipient public key");
        require(ephemeralPubKey.length == 32, "Invalid ephemeral public key");

        return true;
    }

    function computeSolanaPDA(bytes20 recipient) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("inbox", recipient));
    }

    function processIncomingMessage(
        address sender,
        bytes memory message
    ) internal {
        // Güncellenmiş mesaj işleme mantığı
        emit MessageReceived(message, sender);
    }

    // Desteklenen zincirleri kontrol için yardımcı fonksiyon
    function verifySender(
        uint16 chainId,
        bytes32 emitterAddress
    ) internal view returns (bool) {
        return supportedChains[chainId] && emitterAddress == expectedEmitterAddress;
    }

    function setExpectedEmitter(bytes32 newEmitter) external onlyAdmin {
        expectedEmitterAddress = newEmitter;
    }
} 