// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IRLNSettlement
/// @notice Rate-Limiting Nullifier settlement for shielded payments.
///
/// @dev Users deposit tokens against an identity commitment. Each epoch, the user
///      generates an RLN proof off-chain; the operator verifies it and later batch-claims.
///      If a user double-signals within an epoch, anyone can submit two Shamir shares
///      to slash the deposit.
interface IRLNSettlement {
    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event Deposited(bytes32 indexed identityCommitment, address indexed token, uint256 amount);
    event BatchClaimed(address indexed operator, uint256 count, uint256 totalAmount);
    event Slashed(bytes32 indexed identityCommitment, address indexed slasher, uint256 amount);
    event SlashFinalized(
        bytes32 indexed slashId, bytes32 indexed identityCommitment, address indexed slasher, uint256 amount
    );
    event Withdrawn(bytes32 indexed identityCommitment, address indexed recipient, uint256 amount);
    event OperatorRegistered(address indexed operator);
    event OperatorRemoved(address indexed operator);
    event PolicyStakeBurned(
        bytes32 indexed identityCommitment, address indexed operator, uint256 amount, bytes32 reason
    );

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error NullifierUsed(bytes32 nullifier);
    error InsufficientDeposit(uint256 available, uint256 requested);
    error InvalidSlash();
    error SlashFailed();

    // ═══════════════════════════════════════════════════════════════════════
    // FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Deposit tokens against an identity commitment.
    /// @param token ERC20 token address
    /// @param amount Amount to deposit
    /// @param identityCommitment PoseidonT2(identitySecret) — the circuit/SDK identity scheme
    function deposit(address token, uint256 amount, bytes32 identityCommitment) external;

    /// @notice Operator batch-claims payments for verified nullifiers.
    /// @dev Every claim debits the deposit of the identity it was served under:
    ///      claims against unknown, drained, or wrong-token deposits revert, so
    ///      total claimed per deposit can never exceed total funded. The payout
    ///      goes to `msg.sender` (the authorized operator) — never to a
    ///      caller-supplied address.
    /// @param token ERC20 token address for this batch
    /// @param nullifiers Array of nullifier hashes (verified off-chain by operator)
    /// @param identityCommitments Deposit identity each nullifier was served under
    /// @param amounts Corresponding payment amounts
    function batchClaim(
        address token,
        bytes32[] calldata nullifiers,
        bytes32[] calldata identityCommitments,
        uint256[] calldata amounts
    )
        external;

    /// @notice Slash a double-signaler by providing two Shamir shares on the same nullifier.
    /// @dev Recovers identitySecret = (y2 - y1) / (x2 - x1) mod p, verifies
    ///      PoseidonT2(secret) == commitment (matching the RLN circuit and SDK).
    /// @param nullifier The nullifier used twice
    /// @param x1 First share x-coordinate
    /// @param y1 First share y-coordinate
    /// @param x2 Second share x-coordinate
    /// @param y2 Second share y-coordinate
    /// @param identityCommitment The commitment to slash
    function slash(
        bytes32 nullifier,
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2,
        bytes32 identityCommitment
    )
        external;

    /// @notice Withdraw remaining deposit. Proof parameter reserved for future on-chain ZK verification.
    /// @param identityCommitment The commitment to withdraw from
    /// @param amount Amount to withdraw
    /// @param proof Placeholder for withdrawal proof (unused in RLN Mode)
    function withdraw(bytes32 identityCommitment, uint256 amount, bytes calldata proof) external;

    /// @notice Deposit both RLN deposit (D) and policy stake (S).
    /// @param token ERC20 token address
    /// @param rlnAmount Amount for the RLN deposit (D — slashable by math)
    /// @param policyAmount Amount for the policy stake (S — burnable by operator)
    /// @param identityCommitment PoseidonT2(identitySecret) — the circuit/SDK identity scheme
    function depositWithPolicy(
        address token,
        uint256 rlnAmount,
        uint256 policyAmount,
        bytes32 identityCommitment
    )
        external;

    /// @notice Burn policy stake. Operator can burn S but CANNOT claim it.
    /// @dev Tokens are sent to address(0xdead) — operator receives nothing.
    /// @param identityCommitment The commitment whose policy stake to burn
    /// @param amount Amount of policy stake to burn
    /// @param reason Application-specific reason hash
    function burnPolicyStake(bytes32 identityCommitment, uint256 amount, bytes32 reason) external;
}
