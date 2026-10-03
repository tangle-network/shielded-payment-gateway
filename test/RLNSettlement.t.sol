// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "./MockERC20.sol";
import { PoseidonT2Fixture } from "./PoseidonT2Fixture.sol";
import { RLNSettlement } from "../src/shielded/RLNSettlement.sol";
import { IRLNSettlement } from "../src/shielded/IRLNSettlement.sol";

contract RLNSettlementTest is PoseidonT2Fixture {
    RLNSettlement public settlement;
    MockERC20 public token;

    address public depositor = address(0xD1);
    address public operator = address(0x0A);
    address public slasher = address(0x5A);

    uint256 internal constant FIELD_PRIME =
        21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

    // Identity secret and commitment for testing — the on-chain scheme is
    // PoseidonT2(identitySecret), matching the RLN circuit and the SDK.
    uint256 internal identitySecret = 42;
    bytes32 internal identityCommitment;

    function setUp() public {
        settlement = new RLNSettlement();
        token = new MockERC20();
        identityCommitment = _poseidonT2(identitySecret);

        // Register operator
        settlement.registerOperator(operator);

        // Fund the depositor
        token.mint(depositor, 1000 ether);
        vm.prank(depositor);
        token.approve(address(settlement), type(uint256).max);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DEPOSIT
    // ═══════════════════════════════════════════════════════════════════════

    function test_deposit() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (address t, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(t, address(token));
        assertEq(bal, 100 ether);
        assertEq(token.balanceOf(address(settlement)), 100 ether);
    }

    function test_deposit_topUp() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 50 ether, identityCommitment);

        vm.prank(depositor);
        settlement.deposit(address(token), 30 ether, identityCommitment);

        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 80 ether);
    }

    function test_deposit_zeroAmount_reverts() public {
        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 0, 0));
        settlement.deposit(address(token), 0, identityCommitment);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BATCH CLAIM
    // ═══════════════════════════════════════════════════════════════════════

    function _claim(
        bytes32 n1,
        bytes32 n2,
        bytes32 ic1,
        bytes32 ic2,
        uint256 a1,
        uint256 a2
    )
        internal
        pure
        returns (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts)
    {
        nullifiers = new bytes32[](2);
        nullifiers[0] = n1;
        nullifiers[1] = n2;
        ics = new bytes32[](2);
        ics[0] = ic1;
        ics[1] = ic2;
        amounts = new uint256[](2);
        amounts[0] = a1;
        amounts[1] = a2;
    }

    function _claim1(
        bytes32 n,
        bytes32 ic,
        uint256 a
    )
        internal
        pure
        returns (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts)
    {
        nullifiers = new bytes32[](1);
        nullifiers[0] = n;
        ics = new bytes32[](1);
        ics[0] = ic;
        amounts = new uint256[](1);
        amounts[0] = a;
    }

    function test_batchClaim() public {
        // Deposit first
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim(keccak256("nf1"), keccak256("nf2"), identityCommitment, identityCommitment, 10 ether, 20 ether);

        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);

        assertEq(token.balanceOf(operator), 30 ether);
        assertTrue(settlement.usedNullifiers(nullifiers[0]));
        assertTrue(settlement.usedNullifiers(nullifiers[1]));
    }

    /// @notice H-1: every claim debits the deposit it was served under.
    function test_batchClaim_debitsDeposit() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim(keccak256("nf1"), keccak256("nf2"), identityCommitment, identityCommitment, 10 ether, 20 ether);

        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);

        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 70 ether);
        assertEq(token.balanceOf(address(settlement)), 70 ether);
    }

    /// @notice H-1: a user cannot withdraw funds an operator already claimed.
    function test_withdraw_afterClaim_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), identityCommitment, 60 ether);

        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 40 ether, 100 ether));
        settlement.withdraw(identityCommitment, 100 ether, "");

        // The remaining 40 is still withdrawable
        vm.prank(depositor);
        settlement.withdraw(identityCommitment, 40 ether, "");
        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 0);
    }

    /// @notice H-1: claims exceeding the funded deposit revert.
    function test_batchClaim_exceedsDeposit_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), identityCommitment, 150 ether);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 100 ether, 150 ether));
        settlement.batchClaim(address(token), nullifiers, ics, amounts);
    }

    /// @notice H-1: claims against an unknown deposit revert (no free drainage).
    function test_batchClaim_unknownDeposit_reverts() public {
        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), _poseidonT2(999), 1 ether);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 0, 1 ether));
        settlement.batchClaim(address(token), nullifiers, ics, amounts);
    }

    /// @notice H-1: claims against a drained deposit revert.
    function test_batchClaim_drainedDeposit_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), identityCommitment, 100 ether);
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);

        (bytes32[] memory nullifiers2, bytes32[] memory ics2, uint256[] memory amounts2) =
            _claim1(keccak256("nf2"), identityCommitment, 1 ether);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 0, 1 ether));
        settlement.batchClaim(address(token), nullifiers2, ics2, amounts2);
    }

    /// @notice H-1: a claim naming a token other than the deposit's token reverts.
    function test_batchClaim_wrongTokenDeposit_reverts() public {
        MockERC20 otherToken = new MockERC20();
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), identityCommitment, 10 ether);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 0, 10 ether));
        settlement.batchClaim(address(otherToken), nullifiers, ics, amounts);
    }

    /// @notice H-1: payout goes to the calling operator, never a supplied address.
    function test_batchClaim_payoutGoesToCallingOperator() public {
        address operator2 = address(0x0B);
        settlement.registerOperator(operator2);

        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim1(keccak256("nf1"), identityCommitment, 10 ether);

        vm.prank(operator2);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);

        assertEq(token.balanceOf(operator2), 10 ether);
        assertEq(token.balanceOf(operator), 0);
    }

    function test_batchClaim_duplicateNullifier_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        // Use a nullifier first
        bytes32[] memory nullifiers1 = new bytes32[](1);
        nullifiers1[0] = keccak256("nf1");
        bytes32[] memory ics1 = new bytes32[](1);
        ics1[0] = identityCommitment;
        uint256[] memory amounts1 = new uint256[](1);
        amounts1[0] = 10 ether;
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers1, ics1, amounts1);

        // Try to use the same nullifier again
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.NullifierUsed.selector, nullifiers1[0]));
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers1, ics1, amounts1);
    }

    function test_batchClaim_duplicateInSameBatch_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        (bytes32[] memory nullifiers, bytes32[] memory ics, uint256[] memory amounts) =
            _claim(keccak256("nf1"), keccak256("nf1"), identityCommitment, identityCommitment, 5 ether, 5 ether);

        // The second iteration marks the same nullifier — should revert
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.NullifierUsed.selector, nullifiers[0]));
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, ics, amounts);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SLASHING
    // ═══════════════════════════════════════════════════════════════════════

    function test_slash_twoShares() public {
        // Deposit
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        // Construct two Shamir shares on the line y = secret + slope * x
        // where secret = identitySecret = 42
        // Line: y = 42 + 7 * x (slope = 7)
        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        bytes32 nullifier = keccak256("double-signal");

        vm.prank(slasher);
        settlement.slash(nullifier, x1, y1, x2, y2, identityCommitment);
        // Slash is time-locked
        bytes32 slashId = keccak256(abi.encode(identityCommitment, x1, y1, x2, y2));
        assertEq(token.balanceOf(slasher), 0); // Not yet claimable

        // Warp past delay
        vm.warp(block.timestamp + settlement.SLASH_DELAY() + 1);
        settlement.finalizeSlash(slashId);

        assertEq(token.balanceOf(slasher), 100 ether);
        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 0);
    }

    function test_slash_sameX_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.InvalidSlash.selector);
        settlement.slash(keccak256("nf"), 1, 10, 1, 20, identityCommitment);
    }

    function test_slash_wrongCommitment_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        // Genuine shares, but the recovered secret does not hash to this commitment
        bytes32 wrongCommitment = _poseidonT2(999);

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.InvalidSlash.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, wrongCommitment);
    }

    /// @notice M-2: the slash binding is PoseidonT2(secret) — pin the linked library
    ///         against the circomlibjs known answer so the fixture cannot silently drift
    ///         from the circuit/SDK Poseidon implementation.
    function test_poseidonT2_knownAnswer() public pure {
        // circomlibjs poseidon([42n]) — same generator as scripts/deploy-poseidon.mjs
        assertEq(_poseidonT2(42), bytes32(0x1b408dafebeddf0871388399b1e53bd065fd70f18580be5cdde15d7eb2c52743));
    }

    /// @notice M-2 round-trip: a circuit-native (Poseidon) identity double-signals;
    ///         the recovered secret Poseidon-hashes to the on-chain commitment and
    ///         the slash pays out. This is the flow that was impossible under the
    ///         keccak binding.
    function test_slash_poseidonIdentity_roundTrip() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        // Two shares from the same identity (y = secret + slope * x)
        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        vm.prank(slasher);
        settlement.slash(keccak256("double-signal"), x1, y1, x2, y2, identityCommitment);
        bytes32 slashId = keccak256(abi.encode(identityCommitment, x1, y1, x2, y2));

        vm.warp(block.timestamp + settlement.SLASH_DELAY() + 1);
        settlement.finalizeSlash(slashId);
        assertEq(token.balanceOf(slasher), 100 ether);
    }

    /// @notice M-2 regression: deposits under the OLD keccak scheme are no longer
    ///         slashable — poseidon(secret) != keccak256(secret), so the recovered
    ///         secret fails the binding. Scheme is unified on Poseidon end-to-end.
    function test_slash_keccakCommitment_reverts() public {
        bytes32 keccakCommitment = keccak256(abi.encodePacked(identitySecret));
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, keccakCommitment);

        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.InvalidSlash.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, keccakCommitment);
    }

    /// @notice Regression: previously ANY funded deposit could be slashed with
    ///         fabricated shares (any x1 != x2 interpolates to some "secret").
    ///         The recovered secret must now hash to the identity commitment.
    function test_slash_fabricatedShares_cannotDrainDeposit() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        // Attacker fabricates arbitrary shares — no knowledge of identitySecret
        uint256 x1 = 1;
        uint256 y1 = 100;
        uint256 x2 = 2;
        uint256 y2 = 200;

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.InvalidSlash.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, identityCommitment);

        // Deposit untouched, no pending slash recorded
        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 100 ether);
        bytes32 slashId = keccak256(abi.encode(identityCommitment, x1, y1, x2, y2));
        (, , uint256 amount,) = settlement.pendingSlashes(slashId);
        assertEq(amount, 0);
    }

    function test_slash_noDeposit_reverts() public {
        // Shares and commitment are consistent, but nothing was ever deposited
        uint256 secret = 777;
        bytes32 commitment = _poseidonT2(secret);
        uint256 x1 = 1;
        uint256 y1 = addmod(secret, mulmod(3, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 2;
        uint256 y2 = addmod(secret, mulmod(3, x2, FIELD_PRIME), FIELD_PRIME);

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.SlashFailed.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, commitment);
    }

    function test_slash_blocksDoubleSignaledNullifier() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        bytes32 nullifier = keccak256("double-signal");
        vm.prank(slasher);
        settlement.slash(nullifier, x1, y1, x2, y2, identityCommitment);

        assertTrue(settlement.usedNullifiers(nullifier));

        // Operator can no longer claim payment for the fraudulent signal
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bytes32[] memory ics = new bytes32[](1);
        ics[0] = identityCommitment;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.NullifierUsed.selector, nullifier));
        settlement.batchClaim(address(token), nullifiers, ics, amounts);
    }

    function test_finalizeSlash_emitsEvent() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        uint256 x1 = 1;
        uint256 y1 = addmod(identitySecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(identitySecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        vm.prank(slasher);
        settlement.slash(keccak256("double-signal"), x1, y1, x2, y2, identityCommitment);
        bytes32 slashId = keccak256(abi.encode(identityCommitment, x1, y1, x2, y2));

        vm.warp(block.timestamp + settlement.SLASH_DELAY() + 1);
        vm.expectEmit(true, true, true, true);
        emit IRLNSettlement.SlashFinalized(slashId, identityCommitment, slasher, 100 ether);
        settlement.finalizeSlash(slashId);
    }

    function test_registerRemoveOperator_emitEvents() public {
        address op = address(0x0B);
        vm.expectEmit(true, false, false, false);
        emit IRLNSettlement.OperatorRegistered(op);
        settlement.registerOperator(op);
        assertTrue(settlement.authorizedOperators(op));

        vm.expectEmit(true, false, false, false);
        emit IRLNSettlement.OperatorRemoved(op);
        settlement.removeOperator(op);
        assertFalse(settlement.authorizedOperators(op));
    }

    function test_slash_otherIdentitySecret_reverts() public {
        // Shares from a DIFFERENT identity (secret 777) cannot slash secret 42's deposit
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        uint256 otherSecret = 777;
        uint256 x1 = 1;
        uint256 y1 = addmod(otherSecret, mulmod(7, x1, FIELD_PRIME), FIELD_PRIME);
        uint256 x2 = 3;
        uint256 y2 = addmod(otherSecret, mulmod(7, x2, FIELD_PRIME), FIELD_PRIME);

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.InvalidSlash.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, identityCommitment);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WITHDRAWAL
    // ═══════════════════════════════════════════════════════════════════════

    function test_withdraw() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        vm.prank(depositor);
        settlement.withdraw(identityCommitment, 40 ether, "");

        (, uint256 bal,) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 60 ether);
        assertEq(token.balanceOf(depositor), 940 ether); // 1000 - 100 + 40
    }

    function test_withdraw_insufficientBalance_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 10 ether, identityCommitment);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.InsufficientDeposit.selector, 10 ether, 20 ether));
        settlement.withdraw(identityCommitment, 20 ether, "");
    }

    function test_withdraw_notDepositor_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        vm.prank(address(0xBEEF));
        vm.expectRevert("not depositor");
        settlement.withdraw(identityCommitment, 50 ether, "");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUAL STAKING — POLICY STAKE
    // ═══════════════════════════════════════════════════════════════════════

    function test_depositWithPolicy() public {
        vm.prank(depositor);
        settlement.depositWithPolicy(address(token), 80 ether, 20 ether, identityCommitment);

        (address t, uint256 bal, uint256 policy) = settlement.getDeposit(identityCommitment);
        assertEq(t, address(token));
        assertEq(bal, 80 ether);
        assertEq(policy, 20 ether);
        assertEq(token.balanceOf(address(settlement)), 100 ether);
    }

    function test_burnPolicyStake_byOperator() public {
        vm.prank(depositor);
        settlement.depositWithPolicy(address(token), 80 ether, 20 ether, identityCommitment);

        bytes32 reason = keccak256("spam");
        vm.prank(operator);
        settlement.burnPolicyStake(identityCommitment, 10 ether, reason);

        (, uint256 bal, uint256 policy) = settlement.getDeposit(identityCommitment);
        assertEq(bal, 80 ether); // RLN balance untouched
        assertEq(policy, 10 ether); // 20 - 10
    }

    function test_burnPolicyStake_notOperator_reverts() public {
        vm.prank(depositor);
        settlement.depositWithPolicy(address(token), 80 ether, 20 ether, identityCommitment);

        vm.prank(address(0xBEEF));
        vm.expectRevert("not authorized operator");
        settlement.burnPolicyStake(identityCommitment, 10 ether, keccak256("reason"));
    }

    function test_burnPolicyStake_doesNotTransferToOperator() public {
        vm.prank(depositor);
        settlement.depositWithPolicy(address(token), 80 ether, 20 ether, identityCommitment);

        uint256 operatorBalBefore = token.balanceOf(operator);
        address dead = 0x000000000000000000000000000000000000dEaD;
        uint256 deadBalBefore = token.balanceOf(dead);

        vm.prank(operator);
        settlement.burnPolicyStake(identityCommitment, 15 ether, keccak256("abuse"));

        // Operator balance unchanged — receives nothing
        assertEq(token.balanceOf(operator), operatorBalBefore);
        // Dead address received the burned tokens
        assertEq(token.balanceOf(dead), deadBalBefore + 15 ether);
    }

    function test_withdraw_includesPolicy() public {
        vm.prank(depositor);
        settlement.depositWithPolicy(address(token), 60 ether, 40 ether, identityCommitment);

        // Withdraw 50 ether — should drain policy stake first (40), then 10 from balance
        vm.prank(depositor);
        settlement.withdraw(identityCommitment, 50 ether, "");

        (, uint256 bal, uint256 policy) = settlement.getDeposit(identityCommitment);
        assertEq(policy, 0); // Policy fully drained
        assertEq(bal, 50 ether); // 60 - 10
        assertEq(token.balanceOf(depositor), 950 ether); // 1000 - 100 + 50
    }
}
