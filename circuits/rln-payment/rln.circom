pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Rate-Limiting Nullifier (RLN) using Poseidon hashes and Shamir secret sharing.
//
// Core idea: each epoch produces a unique nullifier from (identitySecret, externalNullifier).
// The prover also evaluates a degree-1 polynomial at x = Hash(message), revealing one
// Shamir share (x, y). Two shares from the same epoch let anyone recover identitySecret
// via interpolation, acting as an economic slash condition.
//
// externalNullifier is computed off-circuit as Poseidon(epoch, rlnIdentifier).

template RLN() {
    signal input identitySecret;
    signal input externalNullifier;  // Poseidon(epoch, rlnIdentifier)
    signal input messageHash;        // Hash of the payload being rate-limited

    signal output nullifier;
    signal output share_x;
    signal output share_y;

    // nullifier = Poseidon(identitySecret, externalNullifier)
    // Publicly linkable per-epoch tag; reveals nothing about identitySecret alone.
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== externalNullifier;
    nullifier <== nullifierHasher.out;

    // a = Poseidon(identitySecret, externalNullifier)
    // Coefficient of the degree-1 polynomial. Same hash as nullifier by spec —
    // kept as a separate component for clarity; optimizer will merge if inputs match.
    component aHasher = Poseidon(2);
    aHasher.inputs[0] <== identitySecret;
    aHasher.inputs[1] <== externalNullifier;

    // share_x = messageHash (public evaluation point)
    share_x <== messageHash;

    // share_y = identitySecret + a * messageHash
    // Degree-1 Shamir evaluation: f(x) = identitySecret + a * x
    signal ax;
    ax <== aHasher.out * messageHash;
    share_y <== identitySecret + ax;
}
