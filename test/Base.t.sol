// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {IStorage} from "src/interfaces/IStorage.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IValidation} from "src/interfaces/IValidation.sol";
import {ValidationLogic} from "src/ValidationLogic.sol";
import {WalletCore} from "src/WalletCore.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {WalletCoreLib} from "src/lib/WalletCoreLib.sol";
import {Call} from "src/Types.sol";
import {Errors} from "src/lib/Errors.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";

contract Base is Test {
    string public constant NAME = "wallet-core";
    string public constant VERSION = "1.0.0";

    address internal _alice;
    uint256 internal _alicePk;
    address internal _bob;
    uint256 internal _bobPk;
    IStorage internal _storageImpl;
    ECDSAValidator internal _ecdsaValidatorImpl;
    WalletCore internal _walletCore;
    DeployFactory public deployFactory;
    bytes32 constant _STORAGE_SALT = WalletCoreLib.STORAGE_SALT;

    function setUp() public virtual {
        (_alice, _alicePk) = makeAddrAndKey("alice");
        (_bob, _bobPk) = makeAddrAndKey("bob");

        deployFactory = new DeployFactory();
        bytes32 deployFactorySalt = vm.envBytes32("DEPLOY_FACTORY_SALT");

        (
            address _storageAddr,
            address _ecdsaValidatorAddr,
            address _walletCoreAddr
        ) = DeployInitHelper.deployContracts(
                deployFactory,
                deployFactorySalt,
                NAME,
                VERSION
            );

        _storageImpl = IStorage(_storageAddr);
        _ecdsaValidatorImpl = ECDSAValidator(_ecdsaValidatorAddr);
        _walletCore = WalletCore(payable(_walletCoreAddr));

        _setCodeToEOA(address(_walletCore), _alice);

        deal(_alice, 10 ether);

        // Alice initializes the account
        vm.prank(_alice);
        IWalletCore(_alice).initialize();
        vm.stopPrank();
    }

    function _getEdcsaValidatorAddress(
        address eoa,
        address signer,
        address validatorImpl
    ) internal view returns (address) {
        bytes memory initCode = abi.encode(signer);
        return
            IValidation(eoa).computeValidatorAddress(validatorImpl, initCode);
    }

    function _setCodeToEOA(address contractCode, address eoa) internal {
        bytes memory code = address(contractCode).code;
        vm.etch(eoa, code);
    }

    function _construct_signature(
        uint256 privateKey,
        uint256 nonce,
        Call[] memory calls,
        address validator
    ) public view returns (bytes memory) {
        bytes32 hash = _getValidationTypedHash(nonce, calls, validator);
        return _signHash(privateKey, hash);
    }

    function _construct_calls_data() public view returns (Call[] memory) {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _bob, value: 1 ether, data: ""});
        return calls;
    }

    function _getNonce(address account) internal view returns (uint256) {
        return
            IStorage(WalletCore(payable(account)).getMainStorage()).getNonce();
    }

    function _getValidationTypedHash(
        uint256 nonce,
        Call[] memory calls,
        address validator
    ) internal view returns (bytes32) {
        return
            ValidationLogic(_alice).getValidationTypedHash(
                nonce,
                calls,
                validator
            );
    }

    function _signHash(
        uint256 privateKey,
        bytes32 hash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function _addValidator(address signer) internal returns (address) {
        // Validator signer
        bytes memory initCode = abi.encode(signer);

        // Compute validator address
        address validator = _getEdcsaValidatorAddress(
            signer,
            signer,
            address(_ecdsaValidatorImpl)
        );

        // Add validator
        vm.startPrank(signer);
        IWalletCore(signer).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );
        vm.stopPrank();

        return validator;
    }
}
