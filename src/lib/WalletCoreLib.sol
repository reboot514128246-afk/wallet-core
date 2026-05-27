// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IValidator} from "../interfaces/IValidator.sol";

library WalletCoreLib {
    using ECDSA for bytes32;
    using Clones for address;
    /**
     * @notice new storage should have a different salt
     */
    bytes32 public constant STORAGE_SALT =
        keccak256(abi.encodePacked("storage"));

    bytes32 public constant VALIDATOR_SALT =
        keccak256(abi.encodePacked("validator"));

    address public constant SELF_VALIDATION_ADDRESS = address(1);

    /**
     * @notice Computes the deterministic address of the wallet's storage contract
     * @dev Uses OpenZeppelin's Clones library to predict the address before deployment
     * @param storageImpl The implementation address of the storage contract
     * @return address The deterministic address where the storage clone will be deployed
     * @custom:args The immutable arguments encoded are:
     *  - address(this): The wallet address that owns this storage
     * @custom:salt A unique salt derived from STORAGE_SALT
     */
    function _getStorage(address storageImpl) internal view returns (address) {
        return
            storageImpl.predictDeterministicAddressWithImmutableArgs(
                abi.encode(address(this)),
                STORAGE_SALT,
                address(this)
            );
    }

    /**
     * @notice Validates a transaction or operation using either ECDSA signatures or an external validator contract
     * @dev Two validation methods are supported:
     *      1. ECDSA validation (when validator == address(1)): Recovers signer from signature and verifies it matches the wallet address
     *      2. External validator (any other address): Calls the validator contract and checks if it's authorized to validate
     * @param validator Address of the validator to use (address(1) for ECDSA signature validation)
     * @param typedDataHash EIP-712 typed data hash of the data to be validated
     * @param validationData For ECDSA: the 65-byte signature; For external validators: custom validation data
     * @return bool True if validation succeeds, false otherwise
     * @custom:security Ensure validator contracts are properly verified and authorized before use
     */
    function validate(
        address validator,
        bytes32 typedDataHash,
        bytes calldata validationData
    ) internal view returns (bool) {
        if (validator == SELF_VALIDATION_ADDRESS) {
            return _validateSelf(typedDataHash, validationData);
        } else {
            try IValidator(validator).validate(typedDataHash, validationData) {
                return true;
            } catch {
                return false;
            }
        }
    }

    /**
     * @notice Validates that a signature was signed by this contract
     * @param typedDataHash The hash of the data that was signed
     * @param signature The ECDSA signature to verify
     * @return bool True if the validation passes, false otherwise
     * @dev Reverts with INVALID_SIGNATURE if the signer is not account itself
     */
    function _validateSelf(
        bytes32 typedDataHash,
        bytes calldata signature
    ) internal view returns (bool) {
        (address recoveredSigner, , ) = typedDataHash.tryRecover(signature);
        return recoveredSigner == address(this);
    }

    /**
     * @notice Creates a unique deployment salt by combining validator implementation and init code
     * @param validatorImpl The validator implementation address
     * @param initHash Hash of the validator's initialization code
     * @return bytes32 The computed salt for deterministic deployment
     */
    function _computeCreationSalt(
        address validatorImpl,
        bytes32 initHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(validatorImpl, initHash));
    }

    /**
     * @notice Computes the deterministic address of a validator contract before deployment
     * @param validatorImpl The implementation address of the validator
     * @param immutableArgs The initialization data for the validator
     * @param creationSalt A unique salt for deterministic deployment
     * @param deployer The address that will deploy the validator
     * @return The predicted address where the validator will be deployed
     */
    function _computeValidatorAddress(
        address validatorImpl,
        bytes calldata immutableArgs,
        bytes32 creationSalt,
        address deployer
    ) internal pure returns (address) {
        return
            validatorImpl.predictDeterministicAddressWithImmutableArgs(
                immutableArgs,
                creationSalt,
                deployer
            );
    }
}
