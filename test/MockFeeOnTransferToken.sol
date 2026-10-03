// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { MockERC20 } from "./MockERC20.sol";

/// @title MockFeeOnTransferToken
/// @notice ERC20 that skims a fee on every transfer, to test that credit
///         accounting tracks the amount actually received.
contract MockFeeOnTransferToken is MockERC20 {
    uint256 public feeBps;
    address public constant FEE_SINK = address(0xFEE);

    function setFeeBps(uint256 _feeBps) external {
        feeBps = _feeBps;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        return super.transfer(to, _netOfFee(msg.sender, amount));
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        return super.transferFrom(from, to, _netOfFee(from, amount));
    }

    /// @dev Moves the skimmed fee out of the sender and returns the net amount
    ///      the recipient should receive.
    function _netOfFee(address from, uint256 amount) internal returns (uint256) {
        uint256 fee = (amount * feeBps) / 10_000;
        if (fee > 0) {
            _burn(from, fee);
            _mint(FEE_SINK, fee);
        }
        return amount - fee;
    }
}
