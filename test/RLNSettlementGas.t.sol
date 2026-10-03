// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "./MockERC20.sol";
import { RLNSettlement } from "../src/shielded/RLNSettlement.sol";

/// @notice Gas benchmark for batched RLN settlement.
///         Run: forge test --match-contract RLNSettlementGas -vv
///         Per-test gas shows how batchClaim scales with batch size.
contract RLNSettlementGasTest is Test {
    RLNSettlement public settlement;
    MockERC20 public token;

    address public depositor = address(0xD1);
    address public operator = address(0x0A);

    bytes32 internal identityCommitment = keccak256(abi.encodePacked(uint256(42)));

    function setUp() public {
        settlement = new RLNSettlement();
        token = new MockERC20();

        settlement.registerOperator(operator);

        token.mint(depositor, 1000 ether);
        vm.prank(depositor);
        token.approve(address(settlement), type(uint256).max);

        // Pre-fund the deposit so per-test gas measures batchClaim alone.
        vm.prank(depositor);
        settlement.deposit(address(token), 100 ether, identityCommitment);
    }

    function _batchClaim(uint256 n) internal {
        bytes32[] memory nullifiers = new bytes32[](n);
        uint256[] memory amounts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("nf-gas", i));
            amounts[i] = 1 ether;
        }

        vm.prank(operator);
        settlement.batchClaim(address(token), nullifiers, amounts, operator);
    }

    function test_gas_batchClaim_1() public {
        _batchClaim(1);
    }

    function test_gas_batchClaim_10() public {
        _batchClaim(10);
    }

    function test_gas_batchClaim_50() public {
        _batchClaim(50);
    }
}
