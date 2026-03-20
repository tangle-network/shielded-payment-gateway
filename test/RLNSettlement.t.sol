// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "./MockERC20.sol";
import { RLNSettlement } from "../src/shielded/RLNSettlement.sol";
import { IRLNSettlement } from "../src/shielded/IRLNSettlement.sol";

contract RLNSettlementTest is Test {
    RLNSettlement public settlement;
    MockERC20 public token;

    address public depositor = address(0xD1);
    address public operator = address(0x0A);
    address public slasher = address(0x5A);

    uint256 internal constant FIELD_PRIME =
        21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

    // Identity secret and commitment for testing
    uint256 internal identitySecret = 42;
    bytes32 internal identityCommitment;

    function setUp() public {
        settlement = new RLNSettlement();
        token = new MockERC20();
        identityCommitment = keccak256(abi.encodePacked(identitySecret));

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

    function test_batchClaim() public {
        // Deposit first
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("nf1");
        nullifiers[1] = keccak256("nf2");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10 ether;
        amounts[1] = 20 ether;

        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, amounts, operator);

        assertEq(token.balanceOf(operator), 30 ether);
        assertTrue(settlement.usedNullifiers(nullifiers[0]));
        assertTrue(settlement.usedNullifiers(nullifiers[1]));
    }

    function test_batchClaim_duplicateNullifier_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        // Use a nullifier first
        bytes32[] memory nullifiers1 = new bytes32[](1);
        nullifiers1[0] = keccak256("nf1");
        uint256[] memory amounts1 = new uint256[](1);
        amounts1[0] = 10 ether;
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers1, amounts1, operator);

        // Try to use the same nullifier again
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.NullifierUsed.selector, nullifiers1[0]));
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers1, amounts1, operator);
    }

    function test_batchClaim_duplicateInSameBatch_reverts() public {
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);

        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256("nf1");
        nullifiers[1] = keccak256("nf1"); // duplicate

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 5 ether;
        amounts[1] = 5 ether;

        // The second iteration marks the same nullifier — should revert
        vm.expectRevert(abi.encodeWithSelector(IRLNSettlement.NullifierUsed.selector, nullifiers[0]));
        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, amounts, operator);
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

        // Wrong commitment
        bytes32 wrongCommitment = keccak256(abi.encodePacked(uint256(999)));

        vm.prank(slasher);
        vm.expectRevert(IRLNSettlement.SlashFailed.selector);
        settlement.slash(keccak256("nf"), x1, y1, x2, y2, wrongCommitment);
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
