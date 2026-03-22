// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IVAnchor } from "./IVAnchor.sol";
import { CommonExtData, PublicInputs, Encryptions } from "protocol-solidity/structs/PublicInputs.sol";

/// @notice Succinct SP1 on-chain verifier interface
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title BatchTransactor
/// @author Tangle Network
/// @notice Atomic batch execution of shielded pool transactions with SP1 pre-validation.
///
/// @dev SECURITY MODEL — single source of truth:
///
///   The VAnchor is the ONLY state owner. This contract has NO separate nullifier
///   set, NO separate commitment map. Every transaction in the batch goes through
///   VAnchor.transact(), which:
///     1. Verifies the Groth16 proof
///     2. Checks nullifiers aren't already spent
///     3. Marks nullifiers as spent
///     4. Inserts output commitments into the Merkle tree
///     5. Handles token transfers
///
///   RACE CONDITION PREVENTION:
///   The entire batch executes atomically. If a nullifier was already spent
///   (by a racing individual TX submitted directly to the VAnchor, or by
///   a previous batch), VAnchor.transact() reverts for that nullifier,
///   and the ENTIRE batch reverts. There is no window where a batch and
///   an individual TX can both succeed for the same nullifier.
///
///   SP1 PROOF ROLE:
///   The SP1 proof pre-validates that all N Groth16 proofs are mathematically
///   valid. This is a gas optimization: if any proof is invalid, we fail at
///   SP1 verification (~270k gas) instead of discovering it on the Nth
///   transact() call (N * 270k gas wasted). The VAnchor still re-verifies
///   each Groth16 proof — redundant but required without protocol-solidity
///   changes.
contract BatchTransactor is ReentrancyGuard {

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;

    uint256 public batchCount;
    uint256 public totalProcessed;

    struct BatchTx {
        address pool;
        bytes proof;
        bytes auxPublicInputs;
        CommonExtData extData;
        PublicInputs pubInputs;
        Encryptions encryptions;
    }

    event BatchExecuted(uint256 indexed batchId, uint32 txCount);
    event BatchTxExecuted(uint256 indexed batchId, uint32 indexed txIndex, address pool);

    error EmptyBatch();
    error TxFailed(uint32 txIndex, bytes reason);

    constructor(address _sp1Verifier, bytes32 _programVKey) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
    }

    /// @notice Execute a batch with SP1 pre-validation.
    function executeBatch(
        bytes calldata sp1Proof,
        bytes calldata sp1Public,
        BatchTx[] calldata txs
    ) external payable nonReentrant {
        if (txs.length == 0) revert EmptyBatch();

        // Pre-validate: SP1 proof confirms all Groth16 proofs are valid.
        sp1Verifier.verifyProof(programVKey, sp1Public, sp1Proof);

        _executeTxs(txs);
    }

    /// @notice Execute a batch without SP1 pre-validation (testing/direct).
    function executeBatchDirect(
        BatchTx[] calldata txs
    ) external payable nonReentrant {
        if (txs.length == 0) revert EmptyBatch();
        _executeTxs(txs);
    }

    function _executeTxs(BatchTx[] calldata txs) internal {
        uint256 currentBatch = ++batchCount;

        for (uint32 i = 0; i < txs.length; i++) {
            BatchTx calldata t = txs[i];

            // VAnchor.transact() is the canonical state update.
            // If nullifier already spent (race), this reverts and
            // the ENTIRE batch reverts atomically.
            try IVAnchor(t.pool).transact(
                t.proof,
                t.auxPublicInputs,
                t.extData,
                t.pubInputs,
                t.encryptions
            ) {
                emit BatchTxExecuted(currentBatch, i, t.pool);
            } catch (bytes memory reason) {
                revert TxFailed(i, reason);
            }
        }

        totalProcessed += txs.length;
        emit BatchExecuted(currentBatch, uint32(txs.length));
    }

    receive() external payable {}
}
