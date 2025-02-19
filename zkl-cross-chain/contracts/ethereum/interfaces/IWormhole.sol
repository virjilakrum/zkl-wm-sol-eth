// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IWormhole {
    struct Signature {
        uint8 guardianIndex;
        bytes signature;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        Signature[] signatures;
        bytes32 hash;
    }

    struct GuardianSet {
        address[] keys;
        uint32 expirationTime;
    }

    event LogMessagePublished(
        address indexed sender,
        uint64 sequence,
        uint32 nonce,
        bytes payload,
        uint8 consistencyLevel
    );

    event GuardianSetUpdated(
        uint32 indexed index,
        address[] keys,
        uint32 expirationTime
    );

    function chainId() external view returns (uint16);

    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    function parseAndVerifyVM(
        bytes calldata encodedVM
    ) external view returns (
        VM memory vm,
        bool valid,
        string memory reason
    );

    function verifyVM(
        VM memory vm
    ) external view returns (bool valid, string memory reason);

    function verifySignatures(
        bytes32 hash,
        Signature[] memory signatures,
        GuardianSet memory guardianSet
    ) external pure returns (bool valid, string memory reason);

    function parseVM(bytes memory encodedVM) external pure returns (VM memory vm);

    function getGuardianSet(
        uint32 index
    ) external view returns (GuardianSet memory guardianSet);

    function getCurrentGuardianSetIndex() external view returns (uint32);

    function getGuardianSetExpiry() external view returns (uint32);

    function governanceActionIsConsumed(
        bytes32 hash
    ) external view returns (bool);

    function isInitialized(address emitter) external view returns (bool);

    function nextSequence(address emitter) external view returns (uint64);

    function messageFee() external view returns (uint256);

    function evmChainId() external view returns (uint256);

    function implementation() external view returns (address);

    function initialize() external;

    function submitContractUpgrade(
        bytes memory _vm
    ) external;

    function submitSetMessageFee(
        bytes memory _vm
    ) external;

    function submitNewGuardianSet(
        bytes memory _vm
    ) external;

    function submitSetGuardianSetExpiry(
        bytes memory _vm
    ) external;

    function submitTransferFees(
        bytes memory _vm
    ) external;

    function submitRecoverChainId(
        bytes memory _vm
    ) external;
} 