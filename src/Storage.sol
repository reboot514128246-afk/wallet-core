// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {IStorage} from "./interfaces/IStorage.sol";

import {WalletCoreLib} from "./lib/WalletCoreLib.sol";
import {Errors} from "./lib/Errors.sol";

contract Storage is IStorage {
    //mutable storage
    uint256 private _nonce;
    mapping(address => bool) private _validValidator;
    mapping(uint256 => bool) private _invalidSessionId;

    /**
     * @notice Restricts function access to the wallet owner only
     * @dev Reverts with INVALID_OWNER if caller is not the owner
     */
    modifier onlyOwner() {
        if (msg.sender != getOwner()) {
            revert Errors.InvalidOwner();
        }
        _;
    }

    /**
     * @notice Reads the current nonce and increments it for the next transaction
     * @dev Only callable by wallet owner. Uses unchecked math for gas optimization
     * @param validator The address of the validator contract
     * @return uint256 The current nonce before increment
     */
    function readAndUpdateNonce(
        address validator
    ) external onlyOwner returns (uint256) {
        validateValidator(validator);
        unchecked {
            uint256 currentNonce = _nonce++;
            emit NonceConsumed(currentNonce);
            return currentNonce;
        }
    }

    /**
     * @notice Sets a validator's whitelist status
     * @dev Only callable by wallet owner
     * @param validator Address of the validator
     * @param isValid True to whitelist, false to remove
     */
    function setValidatorStatus(
        address validator,
        bool isValid
    ) external onlyOwner {
        _validValidator[validator] = isValid;
        emit ValidatorStatusUpdated(validator, isValid);
    }

    /**
     * @notice Revokes the specified session ID, marking it as invalid.
     * @dev Only callable by wallet owner
     * @param id The session ID to be revoked
     */
    function revokeSession(uint256 id) external onlyOwner {
        _invalidSessionId[id] = true;
        emit SessionRevoked(id);
    }

    /**
     * @notice Returns the owner address of the wallet
     * @dev Decodes the owner address from the proxy contract's initialization data
     * @return address The owner address of the wallet
     */
    function getOwner() public view returns (address) {
        return abi.decode(Clones.fetchCloneArgs(address(this)), (address));
    }

    /**
     * @notice Returns the current nonce value
     * @dev Can be called by anyone
     * @return uint256 The current nonce value
     */
    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    /**
     * @notice Checks if a validator is whitelisted
     * @dev Reverts if validator is not whitelisted
     * @param validator Address of the validator to check
     */
    function validateValidator(address validator) public view {
        if (
            validator != WalletCoreLib.SELF_VALIDATION_ADDRESS &&
            !_validValidator[validator]
        ) revert Errors.InvalidValidator(validator);
    }

    /**
     * @notice Validates a session and its associated validator
     * @dev Reverts if:
     *      - Session is invalid (blacklisted)
     *      - Validator is not activated
     * @param id The ID of the session to validate
     * @param validator The validator address (0x0 to skip validator check)
     */
    function validateSession(uint256 id, address validator) external view {
        if (_invalidSessionId[id]) revert Errors.InvalidSessionId();
        validateValidator(validator);
    }
}
