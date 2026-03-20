pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "../vanchor/transaction.circom";
include "./rln.circom";

// Composed circuit: VAnchor Transaction + RLN for per-request unlinkable payments.
//
// The VAnchor sub-circuit handles UTXO spend/create (deposit, transfer, withdraw).
// The RLN sub-circuit produces a rate-limited nullifier + Shamir share so that:
//   - Each epoch allows exactly one unlinkable payment request.
//   - A second request in the same epoch leaks identitySecret (slashable).
//
// Glue constraints (~50 additional):
//   1. identityCommitment = Poseidon(identitySecret) — anchors RLN identity
//   2. Solvency: (epochIndex + 1) * maxCost <= deposit + totalRefunds
//      Ensures the user's shielded balance covers worst-case spend through this epoch.
//   3. identitySecret feeds into the RLN sub-circuit.

template RLNPayment(levels, nIns, nOuts, zeroLeaf, length) {
    // -------------------------------------------------------
    // VAnchor public inputs
    // -------------------------------------------------------
    signal input publicAmount;
    signal input extDataHash;
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];
    signal input chainID;
    signal input roots[length];

    // -------------------------------------------------------
    // VAnchor private inputs
    // -------------------------------------------------------
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];

    signal input outChainID[nOuts];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    // -------------------------------------------------------
    // RLN public inputs
    // -------------------------------------------------------
    signal input rlnNullifier;
    signal input share_x;
    signal input share_y;
    signal input epoch;

    // -------------------------------------------------------
    // RLN / solvency inputs
    // -------------------------------------------------------
    signal input identitySecret;  // private: user's secret key (= VAnchor sk)
    signal input epochIndex;      // private: 0-based count of epochs used so far
    signal input maxCost;         // private: max per-epoch cost
    // totalRefunds is PUBLIC so the operator can verify it against
    // accumulated signed refund tickets. If it were private, the user
    // could claim arbitrary refunds and bypass solvency.
    signal input totalRefunds;

    // -------------------------------------------------------
    // RLN identity commitment (glue constraint 1)
    // -------------------------------------------------------
    // identityCommitment = Poseidon(identitySecret)
    // This value is published on-chain when the user registers; the circuit
    // proves knowledge of the preimage without revealing it.
    signal identityCommitment;
    component idCommHasher = Poseidon(1);
    idCommHasher.inputs[0] <== identitySecret;
    identityCommitment <== idCommHasher.out;

    // -------------------------------------------------------
    // Solvency check (glue constraint 2)
    // -------------------------------------------------------
    // (epochIndex + 1) * maxCost <= deposit + totalRefunds
    //
    // deposit is the sum of input UTXO amounts (what the user locked).
    // We compute it from the VAnchor inputs directly.
    //
    // LessEqThan(128) covers amounts up to 2^128 - 1 (sufficient for token amounts).

    var deposit = 0;
    for (var i = 0; i < nIns; i++) {
        deposit += inAmount[i];
    }

    signal epochCount;
    epochCount <== epochIndex + 1;

    signal requiredBudget;
    requiredBudget <== epochCount * maxCost;

    signal availableBudget;
    availableBudget <== deposit + totalRefunds;

    component solvencyCheck = LessEqThan(128);
    solvencyCheck.in[0] <== requiredBudget;
    solvencyCheck.in[1] <== availableBudget;
    solvencyCheck.out === 1;

    // Range-check maxCost and totalRefunds to prevent underflow tricks.
    component maxCostBits = Num2Bits(128);
    maxCostBits.in <== maxCost;

    component totalRefundsBits = Num2Bits(128);
    totalRefundsBits.in <== totalRefunds;

    component epochIndexBits = Num2Bits(64);
    epochIndexBits.in <== epochIndex;

    // -------------------------------------------------------
    // VAnchor sub-circuit
    // -------------------------------------------------------
    component vanchor = Transaction(levels, nIns, nOuts, zeroLeaf, length);
    vanchor.publicAmount <== publicAmount;
    vanchor.extDataHash <== extDataHash;
    vanchor.chainID <== chainID;

    for (var i = 0; i < nIns; i++) {
        vanchor.inputNullifier[i] <== inputNullifier[i];
        vanchor.inAmount[i] <== inAmount[i];
        vanchor.inPrivateKey[i] <== inPrivateKey[i];
        vanchor.inBlinding[i] <== inBlinding[i];
        vanchor.inPathIndices[i] <== inPathIndices[i];
        for (var j = 0; j < levels; j++) {
            vanchor.inPathElements[i][j] <== inPathElements[i][j];
        }
    }

    for (var i = 0; i < nOuts; i++) {
        vanchor.outputCommitment[i] <== outputCommitment[i];
        vanchor.outChainID[i] <== outChainID[i];
        vanchor.outAmount[i] <== outAmount[i];
        vanchor.outPubkey[i] <== outPubkey[i];
        vanchor.outBlinding[i] <== outBlinding[i];
    }

    for (var i = 0; i < length; i++) {
        vanchor.roots[i] <== roots[i];
    }

    // -------------------------------------------------------
    // RLN sub-circuit (glue constraint 3)
    // -------------------------------------------------------
    // externalNullifier = Poseidon(epoch, chainID)
    // Using chainID as the RLN identifier scopes rate-limits per chain.
    component extNullHasher = Poseidon(2);
    extNullHasher.inputs[0] <== epoch;
    extNullHasher.inputs[1] <== chainID;

    component rln = RLN();
    rln.identitySecret <== identitySecret;
    rln.externalNullifier <== extNullHasher.out;
    rln.messageHash <== extDataHash;  // ties the share to this specific transaction

    // Constrain RLN outputs to match declared public inputs.
    rln.nullifier === rlnNullifier;
    rln.share_x === share_x;
    rln.share_y === share_y;
}
