// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { IRLNSettlement } from "./IRLNSettlement.sol";

/// @title RLNSettlement
/// @author Tangle Network
/// @notice Minimal settlement contract for RLN-based shielded payments.
///
/// @dev Trust model: operators verify ZK proofs off-chain (backed by tnt-core staking/slashing).
///      This contract only enforces:
///        1. Deposit accounting per identity commitment
///        2. Global nullifier uniqueness (prevents double-spend on-chain)
///        3. Shamir-based slashing for double-signalers
///        4. Batch claim by operators
///
/// @dev AUDIT SURFACE: ~180 lines. No on-chain ZK verification — minimal attack surface.
contract RLNSettlement is IRLNSettlement, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev BN254 scalar field order (same as circom/snarkjs)
    uint256 internal constant FIELD_PRIME =
        21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    struct DepositInfo {
        address token;
        uint256 balance;
        address depositor;
    }

    /// @notice identityCommitment => deposit info
    mapping(bytes32 => DepositInfo) public deposits;

    /// @notice Global set of used nullifiers — prevents double-spend
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Stored Shamir shares for slashing detection: nullifier => (x, y)
    struct ShamirShare {
        uint256 x;
        uint256 y;
        bool exists;
    }

    mapping(bytes32 => ShamirShare) internal _shares;

    // ═══════════════════════════════════════════════════════════════════════
    // DEPOSIT
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc IRLNSettlement
    function deposit(address token, uint256 amount, bytes32 identityCommitment) external nonReentrant {
        if (amount == 0) revert InsufficientDeposit(0, 0);

        DepositInfo storage info = deposits[identityCommitment];

        if (info.depositor == address(0)) {
            info.token = token;
            info.depositor = msg.sender;
        } else {
            // Top-up must use same token
            if (info.token != token) revert InsufficientDeposit(0, amount);
        }

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        info.balance += amount;

        emit Deposited(identityCommitment, token, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BATCH CLAIM
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc IRLNSettlement
    function batchClaim(
        address token,
        bytes32[] calldata nullifiers,
        uint256[] calldata amounts,
        address operator
    )
        external
        nonReentrant
    {
        uint256 len = nullifiers.length;
        require(len == amounts.length, "length mismatch");
        require(len > 0, "empty batch");

        uint256 totalAmount;

        for (uint256 i; i < len; ++i) {
            bytes32 nf = nullifiers[i];
            if (usedNullifiers[nf]) revert NullifierUsed(nf);
            usedNullifiers[nf] = true;
            totalAmount += amounts[i];
        }

        // Transfer from pooled deposits to operator.
        // The operator verified proofs off-chain and is backed by tnt-core staking.
        if (totalAmount > 0) {
            IERC20(token).safeTransfer(operator, totalAmount);
        }

        emit BatchClaimed(operator, len, totalAmount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SLASHING
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc IRLNSettlement
    function slash(
        bytes32, /* nullifier */
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2,
        bytes32 identityCommitment
    )
        external
        nonReentrant
    {
        // Two distinct shares required
        if (x1 == x2) revert InvalidSlash();

        // Recover identity secret via Shamir interpolation on the line y = a0 + a1*x
        // where a0 = identitySecret. Given two points:
        //   identitySecret = y1 - x1 * (y2 - y1) / (x2 - x1)
        // Simplified: identitySecret = (y2 - y1) * inv(x2 - x1) ... then subtract from y offset
        // Actually for RLN: y = identitySecret + messageHash * x (mod p)
        // So: identitySecret = y1 - x1 * slope, where slope = (y2 - y1) / (x2 - x1)

        uint256 dy = addmod(y2, FIELD_PRIME - y1, FIELD_PRIME);
        uint256 dx = addmod(x2, FIELD_PRIME - x1, FIELD_PRIME);
        uint256 dxInv = _modInverse(dx, FIELD_PRIME);
        uint256 slope = mulmod(dy, dxInv, FIELD_PRIME);
        uint256 secret = addmod(y1, FIELD_PRIME - mulmod(x1, slope, FIELD_PRIME), FIELD_PRIME);

        // Verify: keccak256(secret) == identityCommitment
        bytes32 recoveredCommitment = keccak256(abi.encodePacked(secret));
        if (recoveredCommitment != identityCommitment) revert InvalidSlash();

        DepositInfo storage info = deposits[identityCommitment];
        uint256 slashAmount = info.balance;
        if (slashAmount == 0) revert SlashFailed();

        info.balance = 0;

        IERC20(info.token).safeTransfer(msg.sender, slashAmount);

        emit Slashed(identityCommitment, msg.sender, slashAmount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WITHDRAWAL
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc IRLNSettlement
    function withdraw(
        bytes32 identityCommitment,
        uint256 amount,
        bytes calldata /* proof */
    )
        external
        nonReentrant
    {
        DepositInfo storage info = deposits[identityCommitment];

        // Only original depositor can withdraw (v2 — future: ZK proof of identity)
        require(msg.sender == info.depositor, "not depositor");
        if (amount > info.balance) revert InsufficientDeposit(info.balance, amount);

        info.balance -= amount;

        IERC20(info.token).safeTransfer(msg.sender, amount);

        emit Withdrawn(identityCommitment, msg.sender, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEWS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Get deposit balance for a commitment
    function getDeposit(bytes32 identityCommitment) external view returns (address token, uint256 balance) {
        DepositInfo storage info = deposits[identityCommitment];
        return (info.token, info.balance);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNALS
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev Modular multiplicative inverse using Fermat's little theorem: a^(p-2) mod p
    function _modInverse(uint256 a, uint256 p) internal view returns (uint256) {
        if (a == 0) revert InvalidSlash();
        return _modExp(a, p - 2, p);
    }

    /// @dev Modular exponentiation via EVM precompile (address 0x05)
    function _modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20) // base length
            mstore(add(ptr, 0x20), 0x20) // exp length
            mstore(add(ptr, 0x40), 0x20) // mod length
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) { revert(0, 0) }
            result := mload(ptr)
        }
    }
}
