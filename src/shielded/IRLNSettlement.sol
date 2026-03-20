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
    event Withdrawn(bytes32 indexed identityCommitment, address indexed recipient, uint256 amount);

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
    /// @param identityCommitment keccak256(identitySecret)
    function deposit(address token, uint256 amount, bytes32 identityCommitment) external;

    /// @notice Operator batch-claims payments for verified nullifiers.
    /// @param token ERC20 token address for this batch
    /// @param nullifiers Array of nullifier hashes (verified off-chain by operator)
    /// @param amounts Corresponding payment amounts
    /// @param operator Address to receive the claimed tokens
    function batchClaim(
        address token,
        bytes32[] calldata nullifiers,
        uint256[] calldata amounts,
        address operator
    )
        external;

    /// @notice Slash a double-signaler by providing two Shamir shares on the same nullifier.
    /// @dev Recovers identitySecret = (y2 - y1) / (x2 - x1) mod p, verifies keccak256(secret) == commitment.
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
}
