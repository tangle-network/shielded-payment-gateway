pragma circom 2.0.0;

include "../rln-payment/rln_payment.circom";

// RLN Payment circuit: 2-input 2-output, 8-edge (8 bridge roots).
// Merkle tree depth = 30, matching VAnchor defaults.
// zeroLeaf = Poseidon(zero, zero) where zero = keccak256("tornado") % FIELD_SIZE
//          = 11850551329423159860688778991827824730037759162201783566284850822760196767874

component main {public [
    publicAmount,
    extDataHash,
    inputNullifier,
    outputCommitment,
    chainID,
    roots,
    rlnNullifier,
    share_x,
    share_y,
    epoch,
    operatorPubKeyX,
    operatorPubKeyY
]} = RLNPayment(30, 2, 2, 11850551329423159860688778991827824730037759162201783566284850822760196767874, 8);
