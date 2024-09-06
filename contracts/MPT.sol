// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { RLPDecode } from "./RLPDecode.sol";

library MPT {
    using RLPDecode for RLPDecode.RLPItem;
    using RLPDecode for RLPDecode.Iterator;

    struct MerkleProof {
        bytes32 expectedRoot;
        bytes key;
        bytes[] proof;
        uint256 keyIndex;
        uint256 proofIndex;
        bytes expectedValue;
    }

    function verifyTrieProof(MerkleProof memory data)
        internal
        pure
        returns (bool)
    {
        // Extract the current node, gọi đệ quy hàm này chạy dần từ root tới leaf
        bytes memory node = data.proof[data.proofIndex];
        RLPDecode.Iterator memory dec = RLPDecode.toRlpItem(node).iterator();

        // Expectedroot là hash value của node hiện tại 

        if (data.keyIndex == 0) {
            // Là root node
            require(
                keccak256(node) == data.expectedRoot,
                "verifyTrieProof root node hash invalid"
            );
        } else if (node.length < 32) {
            // Trong ethereum mà nodes < 32 bytes sẽ k được hash vì size bé mà giá trị được lưu luôn trên parent node (node ở level cao hơn, như ta đã biết là lưu hash nhưng đôi khi nó lưu trực tiếp luôn). Lấy RLPItem tiếp theo sau khi decode là mảng thì lần phẩn tử tiếp theo và ss thôi
            bytes32 root = bytes32(dec.next().toUint());
            require(root == data.expectedRoot, "verifyTrieProof < 32");
        } else {
            // Default case handle mọi node length >= 32 bytes
            require(
                keccak256(node) == data.expectedRoot,
                "verifyTrieProof else"
            );
        }

        uint256 numberItems = RLPDecode.numItems(dec.item);

        // branch
        if (numberItems == 17) {
            return verifyTrieProofBranch(data);
        }
        // leaf / extension
        else if (numberItems == 2) {
            return verifyTrieProofLeafOrExtension(dec, data);
        }

        // Empty node 
        if (data.expectedValue.length == 0) return true;
        else return false;
    }

    function verifyTrieProofBranch(MerkleProof memory data)
        internal
        pure
        returns (bool)
    {
        // Extract current node
        bytes memory node = data.proof[data.proofIndex];

        if (data.keyIndex >= data.key.length) {
            // Nếu keyIndex >= key length thì ta đã traverse tới điểm cuối của key mà lại là 1 branch node thì cần ss với giá trị tại phần tử thứ 17 là xong.
            bytes memory item = RLPDecode
            .toRlpItem(node)
            .toList()[16].toBytes();
            if (keccak256(item) == keccak256(data.expectedValue)) {
                return true;
            }
        } else {
            // Nếu kp điểm cuối thì đang ở 1 branch node ở giữa. proofIndex cho ta biết cái proof hiện tại đang nằm ở phần tử thứ mấy trong mảng proof, còn key index cho biết ta đã traverse đến vị trí nào của key path rồi
            // Như ta đã biết thì branch node có giá trị lưu RLP([16 phần tử])
            
            // lấy ra giá trị chữ cái ở vị trí keyIndex mà branch node lưu, convert ra số chính là thứ tự trong [16 phần tử]
            uint256 index = uint256(uint8(data.key[data.keyIndex]));
            // decode node hiện tại và lấy ra đúng giá trị tại vị trí keyIndex, hiện là hash giá trị của node tiếp theo mà nó trỏ tới (tưởng tượng cái hình khá dễ).
            bytes memory _newExpectedRoot = RLPDecode
            .toRlpItem(node)
            .toList()[index].toBytes();

            if (!(_newExpectedRoot.length == 0)) {
                data.expectedRoot = b2b32(_newExpectedRoot);
                data.keyIndex += 1;
                data.proofIndex += 1;
                // Gọi lại verify tiếp thôi, proof tiếp theo trên path, key tăng 1 chữ cái
                return verifyTrieProof(data);
            }
        }

        // Final check, nếu expectedValue length = 0 tức chả verify gì cả thì return true, k thì false.
        if (data.expectedValue.length == 0) return true;
        else return false;
    }

    function verifyTrieProofLeafOrExtension(
        RLPDecode.Iterator memory dec,
        MerkleProof memory data
    ) internal pure returns (bool) {
        bytes memory nodekey = dec.next().toBytes();
        bytes memory nodevalue = dec.next().toBytes();
        uint256 prefix;
        assembly {
            let first := shr(248, mload(add(nodekey, 32)))
            prefix := shr(4, first)
        }
        // Extract byte đầu tiên để check type of node. Ethereum dùng 2 bites đầu của byte này để xác định loại node làm giảm thiểu việc phải decode rõ ra mà xác định, 6 bits còn lại biểu diễn các thông tin khác.
        // 2: Leaf node with even-length path.
        // 3: Leaf node with odd-length path.
        // 0: Extension node with even-length path.
        // 1: Extension node with odd-length path.

        if (prefix == 2) {
            // leaf even
            uint256 length = nodekey.length - 1;

            // bit đầu tiên dùng xác định type rồi nên check tiếp từ bit 1 để extract value của key
            bytes memory actualKey = sliceTransform(nodekey, 1, length, false);

            // Lấy phần key còn lại trong data truyền vào
            bytes memory restKey = sliceTransform(
                data.key,
                data.keyIndex,
                length,
                false
            );

            // Nếu trùng value và key thì return true vì đúng node lá này rồi
            if (keccak256(data.expectedValue) == keccak256(nodevalue)) {
                // Check cả 2 case khi cần expand hay liền
                if (keccak256(actualKey) == keccak256(restKey)) return true;
                if (keccak256(expandKeyEven(actualKey)) == keccak256(restKey))
                    return true;
            }
        } else if (prefix == 3) {
            // leaf odd
            bytes memory actualKey = sliceTransform(
                nodekey,
                0,
                nodekey.length,
                true
            );
            bytes memory restKey = sliceTransform(
                data.key,
                data.keyIndex,
                data.key.length - data.keyIndex,
                false
            );
            if (keccak256(data.expectedValue) == keccak256(nodevalue)) {
                if (keccak256(actualKey) == keccak256(restKey)) return true;
                if (keccak256(expandKeyOdd(actualKey)) == keccak256(restKey))
                    return true;
            }
        } else if (prefix == 0) {
            // extension even
            uint256 extensionLength = nodekey.length - 1;
            bytes memory shared_nibbles = sliceTransform(
                nodekey,
                1,
                extensionLength,
                false
            );
            bytes memory restKey = sliceTransform(
                data.key,
                data.keyIndex,
                extensionLength,
                false
            );

            // Check phần extension value trong extension node trùng với key và tiếp tục verify tiếp. Nó k thể dừng ở 1 extension node được
            if (
                keccak256(shared_nibbles) == keccak256(restKey) ||
                keccak256(expandKeyEven(shared_nibbles)) == keccak256(restKey)
            ) {
                data.expectedRoot = b2b32(nodevalue);
                data.keyIndex += extensionLength;
                data.proofIndex += 1;
                return verifyTrieProof(data);
            }
        } else if (prefix == 1) {
            // extension odd
            uint256 extensionLength = nodekey.length;
            bytes memory shared_nibbles = sliceTransform(
                nodekey,
                0,
                extensionLength,
                true
            );
            bytes memory restKey = sliceTransform(
                data.key,
                data.keyIndex,
                extensionLength,
                false
            );
            if (
                keccak256(shared_nibbles) == keccak256(restKey) ||
                keccak256(expandKeyEven(shared_nibbles)) == keccak256(restKey)
            ) {
                data.expectedRoot = b2b32(nodevalue);
                data.keyIndex += extensionLength;
                data.proofIndex += 1;
                return verifyTrieProof(data);
            }
        } else {
            revert("Invalid proof");
        }
        if (data.expectedValue.length == 0) return true;
        else return false;
    }

    function b2b32(bytes memory data) internal pure returns (bytes32 part) {
        // Convert dynamic size bytes to fixed sizesize bytes32
        assembly {
            part := mload(add(data, 32))
        }
    }

    function sliceTransform(
        bytes memory data,
        uint256 start,
        uint256 length,
        bool removeFirstNibble
    )
    pure internal returns(bytes memory)
    {
        uint256 slots = length / 32;
        uint256 rest = 256 - (length % 32) * 8;
        uint256 pos = 32;
        uint256 si = 0;
        uint256 source;
        bytes memory newdata = new bytes(length);
        assembly {
            source := add(start, data)

            if removeFirstNibble {
                mstore(
                    add(newdata, pos),
                    shr(4, shl(4, mload(add(source, pos))))
                )
                si := 1
                pos := add(pos, 32)
            }

            for {let i := si} lt(i, slots) {i := add(i, 1)} {
                mstore(add(newdata, pos), mload(add(source, pos)))
                pos := add(pos, 32)
            }
            mstore(add(newdata, pos), shl(
                rest,
                shr(rest, mload(add(source, pos)))
            ))
        }
        return newdata;
    }

    function getNibbles(bytes1 b)
        internal
        pure
        returns (bytes1 nibble1, bytes1 nibble2)
    {
        assembly {
            nibble1 := shr(4, b) // dịch b sang phải 4 bits
            nibble2 := shr(4, shl(4, b)) // dịch b sang trái 4 bit rồi dịch sang phải tiếp thì 4 bit bên trái thành 0, 4 bits phải giữ nguyên 
            // => Lấy được 2 nibbles
        }
    }

    function expandKeyEven(bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        // Tách từng phần tử là 1 byte thành 2 nibbles rồi mỗi nibble lại cho chiếm 1 bytes
        uint256 length = data.length * 2;
        bytes memory expanded = new bytes(length);

        for (uint256 i = 0; i < data.length; i++) {
            (bytes1 nibble1, bytes1 nibble2) = getNibbles(data[i]);
            expanded[i * 2] = nibble1;
            expanded[i * 2 + 1] = nibble2;
        }
        return expanded;
    }

    function expandKeyOdd(bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        // Tương tự nhưng byte đầu bỏ qua, thành ra 2 byte sau giống như chẵn
        uint256 length = data.length * 2 - 1;
        bytes memory expanded = new bytes(length);
        expanded[0] = data[0];

        for (uint256 i = 1; i < data.length; i++) {
            (bytes1 nibble1, bytes1 nibble2) = getNibbles(data[i]);
            expanded[i * 2 - 1] = nibble1;
            expanded[i * 2] = nibble2;
        }
        return expanded;
    }
}
