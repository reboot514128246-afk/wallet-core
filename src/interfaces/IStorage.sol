// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

interface IStorage {
    // EVENTS
    event NonceConsumed(uint256 utilisedNonce);
    event ValidatorStatusUpdated(address validator, bool status);
    event SessionRevoked(uint256 id);

    // FUNCTIONS
    function readAndUpdateNonce(address validator) external returns (uint256);

    function setValidatorStatus(address validator, bool isValid) external;

    function revokeSession(uint256 id) external;

    function getOwner() external view returns (address);

    function getNonce() external view returns (uint256);

    function validateValidator(address validator) external view;

    function validateSession(uint256 id, address validator) external view;
}
