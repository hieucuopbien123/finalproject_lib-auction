// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.15;

library EthereumDecoder {
    struct BlockHeader {
        bytes32 hash;
        bytes32 parentHash;
        bytes32 sha3Uncles; // ommersHash
        address miner; // beneficiary
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        bytes logsBloom;
        uint256 difficulty;
        uint256 number;
        uint256 gasLimit;
        uint256 gasUsed;
        uint256 timestamp;
        bytes extraData;
        bytes32 mixHash;
        uint64 nonce;
        uint256 baseFeePerGas;
        bytes32 withdrawalsRoot;
        uint256 blobGasUsed;
        uint256 excessBlobGas;
        bytes32 parentBeaconBlockRoot;
        bytes32[5] backupForFuture; 
    }
}
