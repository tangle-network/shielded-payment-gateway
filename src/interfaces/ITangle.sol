// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Minimal interface for tnt-core's Tangle contract.
///         Only includes functions called by ShieldedGateway.
interface ITangle {
    enum ConfidentialityPolicy { Any, TeeRequired, StandardRequired, TeePreferred }

    function requestService(
        uint64 blueprintId,
        address[] calldata operators,
        bytes calldata config,
        address[] calldata permittedCallers,
        uint64 ttl,
        address paymentToken,
        uint256 paymentAmount,
        ConfidentialityPolicy confidentiality
    ) external payable returns (uint64 requestId);

    function fundService(uint64 serviceId, uint256 amount) external payable;

    function submitJob(uint64 serviceId, uint8 jobIndex, bytes calldata inputs) external payable returns (uint64 callId);
}
