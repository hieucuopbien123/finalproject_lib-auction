// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.9;

import { EthereumDecoder } from "./EthereumDecoder.sol";
import { MPT } from "./MPT.sol";

interface IVickreyUtilities {
  function verifyProof(
    EthereumDecoder.BlockHeader memory _header, 
    MPT.MerkleProof memory _accountDataProof,
    uint256 _balance, 
    address _expectedAddr,
    bytes32 _storedBlockHash
  ) external view returns (bool);
  function getAverageBlockTime() external pure returns (uint256);
}