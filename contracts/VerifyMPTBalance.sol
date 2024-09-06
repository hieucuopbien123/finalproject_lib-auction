// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.15;

import { EthereumDecoder } from "./EthereumDecoder.sol";
import { MPT } from "./MPT.sol";
import { RLPEncode } from "./RLPEncode.sol";

library VerifyMPTBalance {
    using MPT for MPT.MerkleProof;

    uint256 internal constant _EMPTY_NONCE = 0;
    uint256 internal constant _EMPTY_STORAGE_HASH =
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;
    uint256 internal constant _EMPTY_CODE_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    function expandAddrToKey(address _addr)
        internal
        pure
        returns (bytes memory key)
    {
        // Tương đương hàm  ở FE: key = "0x" + expandkey(ethers.solidityPackedKeccak256(["address"], [create2Address])) trả ra 64-byte key từ keccak256 của address
        assembly {
            mstore(0x00, _addr) // Lưu địa chỉ vào bộ nhớ bắt đầu từ 0x00.
            let hashedAddr := keccak256(0x0c, 0x14) // Hash địa chỉ từ 0x0c là offset (vị trí bắt đầu) và 0x14 là độ dài (20 byte) của địa chỉ

            // alloc bytes
            key := mload(0x40) // trỏ key đến vùng nhớ trống tiếp theo
            mstore(0x40, add(key, 0x60)) // Cộng 0x60 (96 bytes) vào giá trị của key hiện tại vì key chiếm 96 bytes, 64 bytes giá trị, 32 bytes là length prefix -> rồi lưu vào ngay vị trí 0x40 là vùng nhớ trống, con trỏ sẽ tự động nhảy tới vùng nhớ trông sau đó 0x40 + 0x60

            // The length of the key (64 bytes) is stored at the beginning of the allocated memory.
            mstore(key, 0x40)

            // Initialize the offset for storing the key
            let keyOffset := add(key, 0x20)
            // Loop to fill the key with the hashed address, nibble by nibble
            for { let i := 0x40 } i { } {
                i := sub(i, 1) 
                mstore8(add(keyOffset, i), and(hashedAddr, 0xf))
                hashedAddr := shr(4, hashedAddr)
            }
        }
    }

    function isValidEmptyAccountBalanceProof(
        EthereumDecoder.BlockHeader memory _header,
        MPT.MerkleProof memory _accountDataProof,
        uint256 _balance,
        address _addr
    ) internal pure returns (bool) {
        if (_header.stateRoot != _accountDataProof.expectedRoot) return false;
        if (
            keccak256(_accountDataProof.key) !=
            keccak256(expandAddrToKey(_addr))
            // Path trong proof phải đúng với address create2 hiện tại
        ) return false;

        bytes[] memory accountTuple = new bytes[](4);
        accountTuple[0] = RLPEncode.encodeUint(_EMPTY_NONCE);
        accountTuple[1] = RLPEncode.encodeUint(_balance);
        accountTuple[2] = RLPEncode.encodeUint(_EMPTY_STORAGE_HASH);
        accountTuple[3] = RLPEncode.encodeUint(_EMPTY_CODE_HASH);

        if (
            keccak256(RLPEncode.encodeList(accountTuple)) !=
            keccak256(_accountDataProof.expectedValue)
            // Check balance phải trùng
        ) return false;

        // V là key path, stateroot và balance trong proof đều chuẩn. Cần verify accountproof nữa là xong

        return _accountDataProof.verifyTrieProof();
    }
}