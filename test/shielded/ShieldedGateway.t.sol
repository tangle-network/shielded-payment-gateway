// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "../MockERC20.sol";
import { MockVAnchor } from "../MockVAnchor.sol";
import { ShieldedCredits } from "../../src/shielded/ShieldedCredits.sol";
import { ShieldedGateway } from "../../src/shielded/ShieldedGateway.sol";
import { IShieldedGateway } from "../../src/shielded/IShieldedGateway.sol";
import { CommonExtData, PublicInputs, Encryptions } from "protocol-solidity/structs/PublicInputs.sol";

/// @title ShieldedGatewayTest
/// @notice Tests the VAnchor → gateway → credits atomic funding path,
///         with focus on proof-bound field enforcement (recipient, relayer)
///         that protects against mempool front-running, plus gateway admin
///         (rescueETH) and RLN settlement-address validation.
contract ShieldedGatewayTest is Test {
    ShieldedGateway public gateway;
    ShieldedCredits public credits;
    MockVAnchor public pool;
    MockERC20 public token;

    address public owner = makeAddr("owner");
    address public tangle = makeAddr("tangle"); // unused by shieldedFundCredits
    address public victim = makeAddr("victim"); // user's ephemeral submission key
    address public attacker = makeAddr("attacker");

    bytes32 public commitment = keccak256("credit-account");
    address public spendingKey = makeAddr("spendingKey");

    uint256 public constant POOL_BALANCE = 1000 ether;
    uint256 public constant WITHDRAW_AMOUNT = 100 ether;

    function setUp() public {
        token = new MockERC20();
        pool = new MockVAnchor(address(token));
        credits = new ShieldedCredits();
        gateway = new ShieldedGateway(tangle, address(credits), owner);

        vm.prank(owner);
        gateway.registerPool(address(token), address(pool));

        // MockVAnchor pays withdrawals out of its own balance
        token.mint(address(pool), POOL_BALANCE);
    }

    function _anchorProof(
        address relayer,
        int256 extAmount,
        address recipient
    )
        internal
        view
        returns (IShieldedGateway.VAnchorProof memory)
    {
        CommonExtData memory extData = CommonExtData({
            recipient: recipient, extAmount: extAmount, relayer: relayer, fee: 0, refund: 0, token: address(token)
        });
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = uint256(keccak256(abi.encodePacked("nf0", relayer)));
        nullifiers[1] = uint256(keccak256(abi.encodePacked("nf1", relayer)));
        PublicInputs memory pubInputs = PublicInputs({
            roots: "",
            extensionRoots: "",
            inputNullifiers: nullifiers,
            outputCommitments: [uint256(0), uint256(0)],
            publicAmount: 0,
            extDataHash: 0 // MockVAnchor doesn't check extDataHash
        });
        Encryptions memory enc = Encryptions("", "");
        return IShieldedGateway.VAnchorProof({
            proof: new bytes(256),
            auxPublicInputs: "",
            externalData: abi.encode(extData),
            publicInputs: abi.encode(pubInputs),
            encryptions: abi.encode(enc)
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HAPPY PATH
    // ═══════════════════════════════════════════════════════════════════════

    function test_shieldedFundCredits() public {
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, -int256(WITHDRAW_AMOUNT), address(gateway));

        vm.prank(victim);
        gateway.shieldedFundCredits(proof, commitment, spendingKey);

        assertEq(credits.getAccount(commitment).balance, WITHDRAW_AMOUNT);
        assertEq(credits.getAccount(commitment).spendingKey, spendingKey);
        // Atomic flow: gateway holds nothing afterwards
        assertEq(token.balanceOf(address(gateway)), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RELAYER BINDING (front-run protection)
    // ═══════════════════════════════════════════════════════════════════════

    function test_shieldedFundCredits_relayerMismatch_reverts() public {
        // extData names the victim as relayer but the attacker submits
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, -int256(WITHDRAW_AMOUNT), address(gateway));

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IShieldedGateway.InvalidRelayer.selector, victim, attacker));
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
    }

    function test_frontRun_cannotRedirectDestination() public {
        // The victim's proof is visible in the mempool. The attacker copies it
        // verbatim and swaps ONLY the unbound destination params (commitment,
        // spendingKey) for their own. With relayer binding this reverts —
        // previously it would have funded the attacker's credit account and
        // burned the victim's nullifiers.
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, -int256(WITHDRAW_AMOUNT), address(gateway));

        bytes32 attackerCommitment = keccak256("attacker-account");
        address attackerKey = makeAddr("attackerKey");

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IShieldedGateway.InvalidRelayer.selector, victim, attacker));
        gateway.shieldedFundCredits(proof, attackerCommitment, attackerKey);

        // Victim's transaction still lands: nullifiers were NOT burned
        vm.prank(victim);
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
        assertEq(credits.getAccount(commitment).balance, WITHDRAW_AMOUNT);
        assertEq(credits.getAccount(attackerCommitment).balance, 0);
    }

    function test_shieldedFundCredits_zeroRelayer_reverts() public {
        // A proof with no named relayer can never be relayed through the gateway
        IShieldedGateway.VAnchorProof memory proof =
            _anchorProof(address(0), -int256(WITHDRAW_AMOUNT), address(gateway));

        vm.prank(victim);
        vm.expectRevert(abi.encodeWithSelector(IShieldedGateway.InvalidRelayer.selector, address(0), victim));
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXISTING INVARIANTS (regression)
    // ═══════════════════════════════════════════════════════════════════════

    function test_shieldedFundCredits_wrongRecipient_reverts() public {
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, -int256(WITHDRAW_AMOUNT), victim);

        vm.prank(victim);
        vm.expectRevert(IShieldedGateway.InvalidRecipient.selector);
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
    }

    function test_shieldedFundCredits_positiveExtAmount_reverts() public {
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, int256(WITHDRAW_AMOUNT), address(gateway));

        vm.prank(victim);
        vm.expectRevert(IShieldedGateway.InvalidSpendAmount.selector);
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
    }

    function test_shieldedFundCredits_unregisteredPool_reverts() public {
        MockERC20 otherToken = new MockERC20();
        IShieldedGateway.VAnchorProof memory proof = _anchorProof(victim, -int256(WITHDRAW_AMOUNT), address(gateway));
        // Re-encode extData with an unregistered token
        CommonExtData memory extData = CommonExtData({
            recipient: address(gateway),
            extAmount: -int256(WITHDRAW_AMOUNT),
            relayer: victim,
            fee: 0,
            refund: 0,
            token: address(otherToken)
        });
        proof.externalData = abi.encode(extData);

        vm.prank(victim);
        vm.expectRevert(abi.encodeWithSelector(IShieldedGateway.PoolNotRegistered.selector, address(otherToken)));
        gateway.shieldedFundCredits(proof, commitment, spendingKey);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACCESS CONTROL
    // ═══════════════════════════════════════════════════════════════════════

    function test_registerPool_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        gateway.registerPool(makeAddr("token2"), makeAddr("pool2"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // rescueETH
    // ═══════════════════════════════════════════════════════════════════════

    function test_rescueETH() public {
        vm.deal(address(gateway), 1 ether);
        address payable recipient = payable(address(0x81));

        vm.prank(owner);
        gateway.rescueETH(recipient);

        assertEq(address(gateway).balance, 0);
        assertEq(recipient.balance, 1 ether);
    }

    function test_rescueETH_zeroRecipient_reverts() public {
        vm.deal(address(gateway), 1 ether);

        vm.prank(owner);
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
