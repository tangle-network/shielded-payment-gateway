// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { ShieldedGateway } from "../../src/shielded/ShieldedGateway.sol";
import { IShieldedGateway } from "../../src/shielded/IShieldedGateway.sol";

contract ShieldedGatewayTest is Test {
    ShieldedGateway public gateway;

    address public admin = address(0xAD);
    address public tangle = address(0x7A);
    address public credits = address(0xCC);

    function setUp() public {
        gateway = new ShieldedGateway(tangle, credits, admin);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // rescueETH
    // ═══════════════════════════════════════════════════════════════════════

    function test_rescueETH() public {
        vm.deal(address(gateway), 1 ether);
        address payable recipient = payable(address(0x81));

        vm.prank(admin);
        gateway.rescueETH(recipient);

        assertEq(address(gateway).balance, 0);
        assertEq(recipient.balance, 1 ether);
    }

    function test_rescueETH_zeroRecipient_reverts() public {
        vm.deal(address(gateway), 1 ether);

        vm.prank(admin);
        vm.expectRevert(IShieldedGateway.InvalidRecipient.selector);
        gateway.rescueETH(payable(address(0)));

        assertEq(address(gateway).balance, 1 ether);
    }

    function test_rescueETH_notOwner_reverts() public {
        vm.deal(address(gateway), 1 ether);

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        gateway.rescueETH(payable(address(0xBEEF)));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // shieldedFundRLN — settlement address validation
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice An EOA settlement address would silently "succeed" the low-level
    ///         deposit call, stranding the withdrawn tokens in the gateway.
    function test_shieldedFundRLN_eoaSettlement_reverts() public {
        IShieldedGateway.VAnchorProof memory proof;

        vm.expectRevert(abi.encodeWithSelector(IShieldedGateway.InvalidSettlementAddress.selector, address(0xE0A)));
        gateway.shieldedFundRLN(proof, keccak256("identity"), address(0xE0A));
    }
}
