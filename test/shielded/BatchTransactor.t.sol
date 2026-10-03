// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Test } from "forge-std/Test.sol";
import { BatchTransactor } from "../../src/shielded/BatchTransactor.sol";
import { MockVAnchor } from "../MockVAnchor.sol";
import { MockERC20 } from "../MockERC20.sol";
import { CommonExtData, PublicInputs, Encryptions } from "protocol-solidity/structs/PublicInputs.sol";

contract BatchTransactorTest is Test {
    BatchTransactor public transactor;
    MockVAnchor public pool;
    MockERC20 public token;

    address public submitter = address(0x5B);

    function setUp() public {
        transactor = new BatchTransactor(address(0x51), bytes32(uint256(1)));
        token = new MockERC20();
        pool = new MockVAnchor(address(token));
        vm.deal(submitter, 10 ether);
    }

    function _singleTx() internal view returns (BatchTransactor.BatchTx[] memory txs) {
        txs = new BatchTransactor.BatchTx[](1);
        CommonExtData memory extData = CommonExtData({
            recipient: address(0x8E),
            extAmount: int256(0),
            relayer: address(0),
            fee: 0,
            refund: 0,
            token: address(token)
        });
        PublicInputs memory pubInputs = PublicInputs({
            roots: "",
            extensionRoots: "",
            inputNullifiers: new uint256[](0),
            outputCommitments: [uint256(0), uint256(0)],
            publicAmount: 0,
            extDataHash: 0
        });
        txs[0] = BatchTransactor.BatchTx({
            pool: address(pool),
            proof: "",
            auxPublicInputs: "",
            extData: extData,
            pubInputs: pubInputs,
            encryptions: Encryptions("", "")
        });
    }

    function test_executeBatchDirect() public {
        vm.prank(submitter);
        transactor.executeBatchDirect(_singleTx());

        assertEq(transactor.batchCount(), 1);
        assertEq(transactor.totalProcessed(), 1);
    }

    /// @notice msg.value is never forwarded to the VAnchor in batch mode, so it
    ///         must be refunded — previously it was locked in the contract forever.
    function test_executeBatchDirect_refundsMsgValue() public {
        uint256 balBefore = submitter.balance;

        vm.prank(submitter);
        transactor.executeBatchDirect{ value: 1 ether }(_singleTx());

        assertEq(submitter.balance, balBefore);
        assertEq(address(transactor).balance, 0);
    }
}
