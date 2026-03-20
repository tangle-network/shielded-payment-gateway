// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test, console } from "forge-std/Test.sol";
import { BatchVerifier, ISP1Verifier } from "../src/BatchVerifier.sol";

/// @notice Mock SP1 verifier that accepts all proofs
contract MockSP1Verifier is ISP1Verifier {
    bool public shouldRevert;

    function setRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function verifyProof(
        bytes32,
        bytes calldata,
        bytes calldata
    ) external view {
        if (shouldRevert) {
            revert("MockSP1Verifier: proof invalid");
        }
        // Accept all proofs
    }
}

contract BatchVerifierTest is Test {
    BatchVerifier public verifier;
    MockSP1Verifier public mockSp1;
    bytes32 constant PROGRAM_VKEY = bytes32(uint256(0xdeadbeef));

    function setUp() public {
        mockSp1 = new MockSP1Verifier();
        verifier = new BatchVerifier(address(mockSp1), PROGRAM_VKEY);
    }

    /// @dev Encode a valid batch with the given nullifiers and commitments
    function _encodeBatch(
        uint32 txCount,
        bytes32[] memory nullifiers,
        bytes32[] memory commitments
    ) internal pure returns (bytes memory) {
        return abi.encode(
            txCount,
            nullifiers,
            commitments,
            bytes32(uint256(0x1111)), // publicAmountsHash
            bytes32(uint256(0x2222))  // extDataHash
        );
    }

    function test_processBatch_basic() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = bytes32(uint256(0xaa));
        nullifiers[1] = bytes32(uint256(0xbb));

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(0xcc));
        commitments[1] = bytes32(uint256(0xdd));

        bytes memory publicValues = _encodeBatch(1, nullifiers, commitments);
        bytes memory proofBytes = hex"1234";

        verifier.processBatch(proofBytes, publicValues);

        assertEq(verifier.totalProcessed(), 1);
        assertEq(verifier.batchCount(), 1);
        assertTrue(verifier.isSpent(nullifiers[0]));
        assertTrue(verifier.isSpent(nullifiers[1]));
        assertTrue(verifier.hasCommitment(commitments[0]));
        assertTrue(verifier.hasCommitment(commitments[1]));
    }

    function test_processBatch_multiTx() public {
        bytes32[] memory nullifiers = new bytes32[](4);
        nullifiers[0] = bytes32(uint256(1));
        nullifiers[1] = bytes32(uint256(2));
        nullifiers[2] = bytes32(uint256(3));
        nullifiers[3] = bytes32(uint256(4));

        bytes32[] memory commitments = new bytes32[](4);
        commitments[0] = bytes32(uint256(10));
        commitments[1] = bytes32(uint256(20));
        commitments[2] = bytes32(uint256(30));
        commitments[3] = bytes32(uint256(40));

        bytes memory publicValues = _encodeBatch(2, nullifiers, commitments);
        verifier.processBatch(hex"abcd", publicValues);

        assertEq(verifier.totalProcessed(), 2);
        assertEq(verifier.batchCount(), 1);

        for (uint256 i = 0; i < 4; i++) {
            assertTrue(verifier.isSpent(nullifiers[i]));
            assertTrue(verifier.hasCommitment(commitments[i]));
        }
    }

    function test_revert_duplicateNullifier_withinBatch() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = bytes32(uint256(0xaa));
        nullifiers[1] = bytes32(uint256(0xaa)); // duplicate

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(0xcc));
        commitments[1] = bytes32(uint256(0xdd));

        bytes memory publicValues = _encodeBatch(1, nullifiers, commitments);

        vm.expectRevert(
            abi.encodeWithSelector(
                BatchVerifier.NullifierAlreadySpent.selector,
                bytes32(uint256(0xaa))
            )
        );
        verifier.processBatch(hex"1234", publicValues);
    }

    function test_revert_duplicateNullifier_acrossBatches() public {
        bytes32 sharedNullifier = bytes32(uint256(0xff));

        // First batch
        bytes32[] memory nullifiers1 = new bytes32[](1);
        nullifiers1[0] = sharedNullifier;
        bytes32[] memory commitments1 = new bytes32[](1);
        commitments1[0] = bytes32(uint256(0xc1));

        verifier.processBatch(
            hex"1234",
            _encodeBatch(1, nullifiers1, commitments1)
        );
        assertTrue(verifier.isSpent(sharedNullifier));

        // Second batch reusing the same nullifier
        bytes32[] memory nullifiers2 = new bytes32[](1);
        nullifiers2[0] = sharedNullifier;
        bytes32[] memory commitments2 = new bytes32[](1);
        commitments2[0] = bytes32(uint256(0xc2));

        vm.expectRevert(
            abi.encodeWithSelector(
                BatchVerifier.NullifierAlreadySpent.selector,
                sharedNullifier
            )
        );
        verifier.processBatch(
            hex"5678",
            _encodeBatch(1, nullifiers2, commitments2)
        );
    }

    function test_revert_emptyBatch() public {
        bytes32[] memory nullifiers = new bytes32[](0);
        bytes32[] memory commitments = new bytes32[](0);

        bytes memory publicValues = _encodeBatch(0, nullifiers, commitments);

        vm.expectRevert(BatchVerifier.EmptyBatch.selector);
        verifier.processBatch(hex"1234", publicValues);
    }

    function test_revert_invalidProof() public {
        mockSp1.setRevert(true);

        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = bytes32(uint256(0xaa));
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = bytes32(uint256(0xcc));

        bytes memory publicValues = _encodeBatch(1, nullifiers, commitments);

        vm.expectRevert("MockSP1Verifier: proof invalid");
        verifier.processBatch(hex"1234", publicValues);
    }

    function test_batchCount_increments() public {
        for (uint256 i = 0; i < 3; i++) {
            bytes32[] memory nullifiers = new bytes32[](1);
            nullifiers[0] = bytes32(i + 1);
            bytes32[] memory commitments = new bytes32[](1);
            commitments[0] = bytes32(i + 100);

            verifier.processBatch(
                hex"1234",
                _encodeBatch(1, nullifiers, commitments)
            );
        }

        assertEq(verifier.batchCount(), 3);
        assertEq(verifier.totalProcessed(), 3);
    }

    function test_unspentNullifier_returnsFalse() public view {
        assertFalse(verifier.isSpent(bytes32(uint256(0x999))));
    }

    function test_missingCommitment_returnsFalse() public view {
        assertFalse(verifier.hasCommitment(bytes32(uint256(0x999))));
    }
}
