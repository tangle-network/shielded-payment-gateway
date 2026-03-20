// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice Interface for Succinct's SP1 on-chain verifier
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title BatchVerifier
/// @notice Processes batches of shielded pool transactions verified by SP1.
///         One SP1 proof covers N transactions → ~270k gas total instead of N × 270k.
///
/// @dev The SP1 program verifies N individual Groth16 proofs (from the existing
///      circom VAnchor circuits) inside the zkVM. This contract only verifies the
///      SP1 wrapper proof and processes the batch output (nullifiers + commitments).
contract BatchVerifier is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Succinct's SP1 verifier contract
    ISP1Verifier public immutable sp1Verifier;

    /// @notice The SP1 program verification key (identifies the batch verifier program)
    bytes32 public immutable programVKey;

    /// @notice Merkle tree for output commitments (simplified — production would use
    ///         the same MerkleTreeWithHistory from protocol-solidity)
    mapping(bytes32 => bool) public commitments;

    /// @notice Spent nullifiers — prevents double-spend
    mapping(bytes32 => bool) public nullifierHashes;

    /// @notice Total transactions processed
    uint256 public totalProcessed;

    /// @notice Total batches processed
    uint256 public batchCount;

    event BatchProcessed(
        uint256 indexed batchId,
        uint32 txCount,
        uint256 nullifierCount,
        uint256 commitmentCount
    );

    event NullifierSpent(bytes32 indexed nullifier);
    event CommitmentInserted(bytes32 indexed commitment);

    error NullifierAlreadySpent(bytes32 nullifier);
    error InvalidBatchOutput();
    error EmptyBatch();

    constructor(address _sp1Verifier, bytes32 _programVKey) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
    }

    /// @notice Process a batch of shielded transactions.
    ///         The SP1 proof verifies all N Groth16 proofs inside the zkVM.
    ///         This function only processes the public outputs.
    /// @param proofBytes The SP1 Groth16 wrapper proof
    /// @param publicValues The batch output (tx_count, nullifiers, commitments, hashes)
    function processBatch(
        bytes calldata proofBytes,
        bytes calldata publicValues
    ) external nonReentrant {
        // Verify the SP1 proof on-chain (~270k gas regardless of batch size)
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);

        // Decode the batch output
        (
            uint32 txCount,
            bytes32[] memory allNullifiers,
            bytes32[] memory allCommitments,
            bytes32 publicAmountsHash,
            bytes32 extDataHash
        ) = abi.decode(publicValues, (uint32, bytes32[], bytes32[], bytes32, bytes32));

        if (txCount == 0) revert EmptyBatch();

        // Mark nullifiers as spent
        for (uint256 i = 0; i < allNullifiers.length; i++) {
            bytes32 nf = allNullifiers[i];
            if (nullifierHashes[nf]) revert NullifierAlreadySpent(nf);
            nullifierHashes[nf] = true;
            emit NullifierSpent(nf);
        }

        // Insert commitments
        for (uint256 i = 0; i < allCommitments.length; i++) {
            commitments[allCommitments[i]] = true;
            emit CommitmentInserted(allCommitments[i]);
        }

        totalProcessed += txCount;
        batchCount++;

        emit BatchProcessed(batchCount, txCount, allNullifiers.length, allCommitments.length);
    }

    /// @notice Check if a nullifier has been spent
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifierHashes[nullifier];
    }

    /// @notice Check if a commitment exists
    function hasCommitment(bytes32 commitment) external view returns (bool) {
        return commitments[commitment];
    }
}
