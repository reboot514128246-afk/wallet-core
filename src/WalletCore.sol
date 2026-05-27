// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {IWalletCore} from "./interfaces/IWalletCore.sol";
import {IStorage} from "./interfaces/IStorage.sol";

import {WalletCoreBase} from "./base/WalletCoreBase.sol";
import {ECDSA, WalletCoreLib} from "./lib/WalletCoreLib.sol";
import {ValidationLogic} from "./ValidationLogic.sol";
import {ExecutionLogic} from "./ExecutionLogic.sol";
import {ExecutorLogic} from "./ExecutorLogic.sol";
import {FallbackHandler} from "./FallbackHandler.sol";
import {Call, Session} from "./Types.sol";
import {Errors} from "./lib/Errors.sol";

// Do not set any states in this contract
contract WalletCore is
    IWalletCore,
    ValidationLogic,
    ExecutionLogic,
    ExecutorLogic,
    FallbackHandler,
    EIP712
{
    using Clones for address;

    // EIP-1271
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant INVALID_VALUE = 0xffffffff;

    address public immutable ADDRESS_THIS;
    address public immutable MAIN_STORAGE_IMPL;

    constructor(
        address mainStorageImpl,
        string memory name,
        string memory version
    ) EIP712(name, version) {
        // Check name/version lengths, assure remain stateless
        if (bytes(name).length >= 32) {
            revert Errors.NameTooLong();
        }
        if (bytes(version).length >= 32) {
            revert Errors.VersionTooLong();
        }
        ADDRESS_THIS = address(this);
        MAIN_STORAGE_IMPL = mainStorageImpl;
    }

    /**
     * @dev Modifier to make a function callable by the account itself or EOA address under 7702
     */
    modifier onlySelf() {
        if (msg.sender != address(this)) revert Errors.NotFromSelf();
        _;
    }

    /**
     * @notice Initializes the wallet core
     * @dev Can only be called once during account creation with each storage version
     */
    function initialize() external {
        if (WalletCoreLib._getStorage(MAIN_STORAGE_IMPL).code.length != 0) {
            emit StorageInitialized();
            return;
        }

        // immutable args
        bytes memory owner = abi.encode(address(this));

        address createdAddress = MAIN_STORAGE_IMPL
            .cloneDeterministicWithImmutableArgs(
                owner,
                WalletCoreLib.STORAGE_SALT
            );

        emit StorageCreated(createdAddress);
    }

    /**
     * @notice Executes multiple contract calls in a single transaction
     * @dev Only callable by the account itself
     * @param calls Array of Call structs containing destination address, value, and calldata
     */
    function executeFromSelf(Call[] calldata calls) external onlySelf {
        _batchCall(calls);
    }

    /**
     * @notice Executes a batch of calls after validation by a designated validator contract
     * @dev The validator must be previously registered and the validation data must be valid
     * @dev If validator address == 1, uses default built-in ECDSA ecrecover for signature verification
     * @param calls Array of Call structs to be executed, each containing destination address, value, and calldata
     * @param validator Address of the validator contract that will verify this transaction (use address(1) for ECDSA)
     * @param validationData Encoded data required by the validator for transaction verification. For ECDSA, this is the signature
     */
    function executeWithValidator(
        Call[] calldata calls,
        address validator,
        bytes calldata validationData
    ) external onlyValidator(calls, validator, validationData) {
        _batchCall(calls);
    }

    /**
     * @notice Executes a batch of calls through a registered executor using a valid session
     * @dev Only callable by pre-signed sessions with valid signatures
     * @dev Executes hooks before and after the batch call if specified in the session
     * @param calls Array of Call structs to be executed, each containing destination address, value, and calldata
     * @param session Session struct containing executor details, permissions, and hook configurations
     */
    function executeFromExecutor(
        Call[] calldata calls,
        Session calldata session
    ) external onlyValidSession(session, calls) {
        _batchCall(calls);
    }

    /**
     * @notice Registers a new validator contract for transaction validation
     * @dev Only callable by the wallet itself
     * @param validatorImpl The implementation address of the validator contract to be registered
     * @param immutableArgs Initialization data for the validator contract (can be empty)
     */
    function addValidator(
        address validatorImpl,
        bytes calldata immutableArgs
    ) external onlySelf {
        _addValidator(validatorImpl, immutableArgs);
    }

    /**
     * @notice Implements EIP-1271 signature validation standard
     * @dev There are two types of signatures:
     *      1. 65 bytes: ECDSA signature
     *      2. >20 bytes: (validator, signature) pair
     * @param _hash The hash of the data to be validated
     * @param signature The signature to be validated
     * @return bytes4 Returns MAGIC_VALUE (0x1626ba7e) if valid, INVALID_VALUE (0xffffffff) if invalid
     */
    function isValidSignature(
        bytes32 _hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        // 7702 Post upgrade compatibility: try validate signature for EOA sigs
        // Make sure the _signature can be decoded
        if (signature.length == 65) {
            (address recovered, , ) = ECDSA.tryRecover(_hash, signature);
            if (recovered == address(this)) return MAGIC_VALUE;
        }

        if (signature.length < 20) return INVALID_VALUE;

        return
            isValidSignature(
                address(bytes20(signature[:20])),
                _hash,
                signature[20:]
            )
                ? MAGIC_VALUE
                : INVALID_VALUE;
    }

    /**
     * @notice Returns the address of the wallet's storage contract
     * @dev Uses deterministic deployment to calculate the storage contract address.
     *      This contract only stores core wallet states. For additional states,
     *      create and query new dedicated storage contracts instead of modifying
     *      this one.
     * @return address The deployed storage contract address for this wallet
     * @custom:architecture New features requiring additional storage should:
     *      1. Deploy a new dedicated storage contract
     *      2. Implement separate getter methods for the new storage
     */
    function getMainStorage()
        public
        view
        override(IWalletCore, WalletCoreBase)
        returns (IStorage)
    {
        return IStorage(WalletCoreLib._getStorage(MAIN_STORAGE_IMPL));
    }

    /**
     * @notice Creates a typed data hash following EIP-712 standard
     * @param structHash The hash of the struct data to be signed
     * @return The final EIP-712 typed data hash that can be signed by a wallet
     */
    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view override(EIP712, WalletCoreBase) returns (bytes32) {
        return EIP712._hashTypedDataV4(structHash);
    }

    /**
     * @notice Returns the address of the current wallet implementation
     * @dev This function is used in the proxy pattern to identify the implementation contract
     * @return ADDRESS_THIS The address of this contract, which serves as the implementation
     */
    function _walletImplementation() internal view override returns (address) {
        return ADDRESS_THIS;
    }
}
