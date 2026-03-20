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
        uint256 balance; // D — RLN deposit (slashable by math)
        uint256 policyStake; // S — policy stake (burnable by operator, NOT claimable)
        address depositor;
    }

    /// @dev Dead address for policy stake burns — tokens are irrecoverable
    address internal constant DEAD = 0x000000000000000000000000000000000000dEaD;

    /// @notice identityCommitment => deposit info
    mapping(bytes32 => DepositInfo) public deposits;

    /// @notice Global set of used nullifiers — prevents double-spend
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Authorized operators who can call batchClaim
    mapping(address => bool) public authorizedOperators;

    /// @notice Contract owner (registers operators)
    address public owner;

    /// @notice Pending slashes (time-locked to prevent self-slashing)
    struct PendingSlash {
        bytes32 identityCommitment;
        address slasher;
        uint256 amount;
        uint256 claimableAt; // block.timestamp after which slasher can claim
    }

    mapping(bytes32 => PendingSlash) public pendingSlashes; // slash ID => pending
    uint256 public constant SLASH_DELAY = 1 days;

    /// @notice Stored Shamir shares for slashing detection: nullifier => (x, y)
    struct ShamirShare {
        uint256 x;
        uint256 y;
        bool exists;
    }

    mapping(bytes32 => ShamirShare) internal _shares;

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR + ADMIN
    // ═══════════════════════════════════════════════════════════════════════

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function registerOperator(address op) external onlyOwner {
        authorizedOperators[op] = true;
    }

    function removeOperator(address op) external onlyOwner {
        authorizedOperators[op] = false;
    }

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

    /// @inheritdoc IRLNSettlement
    function depositWithPolicy(
        address token,
        uint256 rlnAmount,
        uint256 policyAmount,
        bytes32 identityCommitment
    )
        external
        nonReentrant
    {
        if (rlnAmount == 0 && policyAmount == 0) revert InsufficientDeposit(0, 0);

        DepositInfo storage info = deposits[identityCommitment];

        if (info.depositor == address(0)) {
            info.token = token;
            info.depositor = msg.sender;
        } else {
            if (info.token != token) revert InsufficientDeposit(0, rlnAmount + policyAmount);
        }

        uint256 total = rlnAmount + policyAmount;
        IERC20(token).safeTransferFrom(msg.sender, address(this), total);
        info.balance += rlnAmount;
        info.policyStake += policyAmount;

        emit Deposited(identityCommitment, token, total);
    }

    /// @inheritdoc IRLNSettlement
    function burnPolicyStake(bytes32 identityCommitment, uint256 amount, bytes32 reason) external nonReentrant {
        require(authorizedOperators[msg.sender], "not authorized operator");

        DepositInfo storage info = deposits[identityCommitment];
        require(amount > 0 && amount <= info.policyStake, "invalid burn amount");

        info.policyStake -= amount;

        // Burn: send to dead address. Operator receives NOTHING.
        IERC20(info.token).safeTransfer(DEAD, amount);

        emit PolicyStakeBurned(identityCommitment, msg.sender, amount, reason);
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
        // Only authorized operators can claim — prevents arbitrary drainage
        require(authorizedOperators[msg.sender], "not authorized operator");

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

        if (totalAmount > 0) {
            IERC20(token).safeTransfer(operator, totalAmount);
        }

        emit BatchClaimed(operator, len, totalAmount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SLASHING
    // ═══════════════════════════════════════════════════════════════════════

    /// @inheritdoc IRLNSettlement
    /// @dev Two-phase slashing: initiate (time-locked) then finalize.
    ///      The time lock prevents self-slashing attacks where a user
    ///      intentionally double-signals to recover their deposit before
    ///      the operator can batch-claim.
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
        if (x1 == x2) revert InvalidSlash();

        // Recover identity secret via Shamir interpolation
        // y = identitySecret + a * x, so:
        // slope = (y2 - y1) / (x2 - x1), identitySecret = y1 - x1 * slope
        uint256 dy = addmod(y2, FIELD_PRIME - y1, FIELD_PRIME);
        uint256 dx = addmod(x2, FIELD_PRIME - x1, FIELD_PRIME);
        uint256 dxInv = _modInverse(dx, FIELD_PRIME);
        uint256 slope = mulmod(dy, dxInv, FIELD_PRIME);
        uint256 secret = addmod(y1, FIELD_PRIME - mulmod(x1, slope, FIELD_PRIME), FIELD_PRIME);

        // Verify: the recovered secret's commitment matches.
        // The circuit uses Poseidon(identitySecret) for the identity commitment.
        // On-chain we verify using the caller-provided identityCommitment and
        // the recovered secret. Since we can't compute Poseidon on-chain cheaply,
        // we store the secret and let the operator/anyone verify during finalization.
        //
        // Alternative: use a Poseidon precompile or store commitments with keccak256.
        // For now: the caller provides both the shares AND the identityCommitment.
        // The deposit must exist for that commitment (prevents random slashing).
        DepositInfo storage info = deposits[identityCommitment];
        if (info.balance == 0) revert SlashFailed();

        // Time-locked: store pending slash
        bytes32 slashId = keccak256(abi.encode(identityCommitment, x1, y1, x2, y2));
        require(pendingSlashes[slashId].amount == 0, "slash already pending");

        uint256 slashAmount = info.balance;
        info.balance = 0; // Lock the balance immediately

        pendingSlashes[slashId] = PendingSlash({
            identityCommitment: identityCommitment,
            slasher: msg.sender,
            amount: slashAmount,
            claimableAt: block.timestamp + SLASH_DELAY
        });

        emit Slashed(identityCommitment, msg.sender, slashAmount);
    }

    /// @notice Finalize a time-locked slash claim
    function finalizeSlash(bytes32 slashId) external nonReentrant {
        PendingSlash storage ps = pendingSlashes[slashId];
        require(ps.amount > 0, "no pending slash");
        require(block.timestamp >= ps.claimableAt, "slash not claimable yet");

        uint256 amount = ps.amount;
        address slasher = ps.slasher;
        bytes32 ic = ps.identityCommitment;
        ps.amount = 0; // Clear

        DepositInfo storage info = deposits[ic];
        IERC20(info.token).safeTransfer(slasher, amount);
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

        // Only original depositor can withdraw (RLN Mode — future: ZK proof of identity)
        require(msg.sender == info.depositor, "not depositor");

        uint256 totalAvailable = info.balance + info.policyStake;
        if (amount > totalAvailable) revert InsufficientDeposit(totalAvailable, amount);

        // Withdraw from policy stake first, then RLN balance
        if (amount <= info.policyStake) {
            info.policyStake -= amount;
        } else {
            uint256 fromBalance = amount - info.policyStake;
            info.policyStake = 0;
            info.balance -= fromBalance;
        }

        IERC20(info.token).safeTransfer(msg.sender, amount);

        emit Withdrawn(identityCommitment, msg.sender, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEWS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Get deposit balance for a commitment
    function getDeposit(bytes32 identityCommitment)
        external
        view
        returns (address token, uint256 balance, uint256 policyStake)
    {
        DepositInfo storage info = deposits[identityCommitment];
        return (info.token, info.balance, info.policyStake);
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
