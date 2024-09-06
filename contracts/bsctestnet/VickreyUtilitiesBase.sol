// SPDX-License-Identifier: GPL-3.0-only

pragma solidity ^0.8.9;

import { RLPEncode } from "../RLPEncode.sol";
import { RLPDecode } from "../RLPDecode.sol";
import { MPT } from "../MPT.sol";
import { VerifyMPTBalance } from "../VerifyMPTBalance.sol";
import { EthereumDecoder } from "../EthereumDecoder.sol";

contract VickreyUtilitiesBase {
  using RLPDecode for RLPDecode.RLPItem;
  using RLPDecode for RLPDecode.Iterator;

  function getBlockHash(EthereumDecoder.BlockHeader memory header)
    internal
    pure
    returns (bytes32 hash)
  {
    return keccak256(getBlockRlpData(header));
  }

  // Encode BlockHeader thành bytes dạng RLP format
  function getBlockRlpData(EthereumDecoder.BlockHeader memory header)
    internal
    pure
    returns (bytes memory data)
  {
    bytes[] memory list = new bytes[](16);

    list[0] = RLPEncode.encodeBytes(abi.encodePacked(header.parentHash));
    list[1] = RLPEncode.encodeBytes(abi.encodePacked(header.sha3Uncles));
    list[2] = RLPEncode.encodeAddress(header.miner);
    list[3] = RLPEncode.encodeBytes(abi.encodePacked(header.stateRoot));
    list[4] = RLPEncode.encodeBytes(abi.encodePacked(header.transactionsRoot));
    list[5] = RLPEncode.encodeBytes(abi.encodePacked(header.receiptsRoot));
    list[6] = RLPEncode.encodeBytes(header.logsBloom);
    list[7] = RLPEncode.encodeUint(header.difficulty);
    list[8] = RLPEncode.encodeUint(header.number);
    list[9] = RLPEncode.encodeUint(header.gasLimit);
    list[10] = RLPEncode.encodeUint(header.gasUsed);
    list[11] = RLPEncode.encodeUint(header.timestamp);
    list[12] = RLPEncode.encodeBytes(header.extraData);
    list[13] = RLPEncode.encodeBytes(abi.encodePacked(header.mixHash));
    list[14] = RLPEncode.encodeBytes(abi.encodePacked(header.nonce));
    list[15] = RLPEncode.encodeUint(header.baseFeePerGas);

    data = RLPEncode.encodeList(list);
  }

  // Lấy lại BlockHeader từ bytes
  function toBlockHeader(bytes memory rlpHeader)
    external
    pure
    returns (EthereumDecoder.BlockHeader memory header)
  {
    RLPDecode.Iterator memory it = RLPDecode
      .toRlpItem(rlpHeader)
      .iterator();

    uint256 idx;
    while (it.hasNext()) {
      if (idx == 0) header.parentHash = bytes32(it.next().toUint());
      else if (idx == 1) header.sha3Uncles = bytes32(it.next().toUint());
      else if (idx == 2) header.miner = it.next().toAddress();
      else if (idx == 3) header.stateRoot = bytes32(it.next().toUint());
      else if (idx == 4) header.transactionsRoot = bytes32(it.next().toUint());
      else if (idx == 5) header.receiptsRoot = bytes32(it.next().toUint());
      else if (idx == 6) header.logsBloom = it.next().toBytes();
      else if (idx == 7) header.difficulty = it.next().toUint();
      else if (idx == 8) header.number = it.next().toUint();
      else if (idx == 9) header.gasLimit = it.next().toUint();
      else if (idx == 10) header.gasUsed = it.next().toUint();
      else if (idx == 11) header.timestamp = it.next().toUint();
      else if (idx == 12) header.extraData = it.next().toBytes();
      else if (idx == 13) header.mixHash = bytes32(it.next().toUint());
      else if (idx == 14) header.nonce = uint64(it.next().toUint());
      else if (idx == 15) header.baseFeePerGas = it.next().toUint();
      else it.next();
      idx++;
    }
    header.hash = keccak256(rlpHeader);
  }
  
  function verifyProof(
    EthereumDecoder.BlockHeader memory _header, 
    MPT.MerkleProof memory _accountDataProof,
    uint256 _balance, 
    address _expectedAddr,
    bytes32 _storedBlockHash
  ) external pure returns (bool) {
    return
      getBlockHash(_header) == _storedBlockHash &&
      VerifyMPTBalance.isValidEmptyAccountBalanceProof(
        _header,
        _accountDataProof,
        _balance,
        _expectedAddr
      );
  }
  function getAverageBlockTime() public pure returns (uint256) {
    return 3;
  }
}


