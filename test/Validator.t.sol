// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IValidation} from "src/interfaces/IValidation.sol";
import "src/lib/Errors.sol";

contract ValidatorTest is Base {
    using Clones for address;
    address internal _charlie;
    uint256 internal _charliePk;

    event ValidatorAdded(address validator);
    event ValidatorRemoved(address validator);
    event ValidatorStatusUpdated(address validator, bool status);
    error FailedDeployment();

    function setUp() public override {
        (_charlie, _charliePk) = makeAddrAndKey("charlie");
        super.setUp();
    }

    function test_addValidator_reverts_for_non_owner() public {
        vm.prank(_bob);
        bytes memory initCode = abi.encode(_charlie);

        // Expect not from self revert
        vm.expectRevert(abi.encodeWithSelector(Errors.NotFromSelf.selector));
        IWalletCore(_alice).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );
    }

    function test_addValidator_reverts_for_invalid_implementation() public {
        vm.prank(_alice);
        address dave = vm.addr(2);
        bytes memory initCode = abi.encode(_charlie);

        // Expect invalid validator implementation revert
        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidValidatorImpl.selector, dave)
        );
        IWalletCore(_alice).addValidator(
            address(dave), // Invalid validatorImpl
            initCode
        );
    }

    function test_addValidator_reverts_for_duplicate() public {
        vm.prank(_alice);
        bytes memory initCode = abi.encode(_alice); // duplicate validator

        IWalletCore(_alice).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );

        // Expect failed if duplicate validator
        vm.prank(_alice);
        vm.expectRevert(abi.encodeWithSelector(FailedDeployment.selector));
        IWalletCore(_alice).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );
    }

    function test_fraudulent_validator_reverts() public {
        // Create a fraudulent validator with impersonated signer
        bytes memory initCode = abi.encode(_alice);
        bytes32 salt = WalletCoreLib._computeCreationSalt(
            address(_ecdsaValidatorImpl),
            keccak256(initCode)
        );
        address fraudulentValidator = address(
            address(_ecdsaValidatorImpl).cloneDeterministicWithImmutableArgs(
                initCode,
                salt
            )
        );

        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );

        vm.prank(_alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.InvalidValidator.selector,
                fraudulentValidator
            )
        );
        IWalletCore(_alice).executeWithValidator(
            calls,
            fraudulentValidator,
            signature
        );
    }

    function test_validator_can_be_added() public {
        bytes memory initCode = abi.encode(_charlie);

        // Compute validator address
        address charlieValidator = _getEdcsaValidatorAddress(
            _alice,
            _charlie,
            address(_ecdsaValidatorImpl)
        );

        // Expect validator added event
        vm.expectEmit();
        emit ValidatorAdded(charlieValidator);

        // Add validator
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );

        assertEq(ECDSAValidator(charlieValidator).getSigner(), _charlie);
    }

    function test_new_validator_can_validate_transactions() public {
        vm.prank(_alice);
        bytes memory initCode = abi.encode(_charlie);

        // Add validator
        IWalletCore(_alice).addValidator(
            address(_ecdsaValidatorImpl),
            initCode
        );

        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        address charlieValidator = _getEdcsaValidatorAddress(
            _alice,
            _charlie,
            address(_ecdsaValidatorImpl)
        );
        bytes memory signature = _construct_signature(
            _charliePk,
            nonce,
            calls,
            charlieValidator
        );

        // Relayer executes with Charlie signature
        vm.prank(_bob);
        IWalletCore(_alice).executeWithValidator(
            calls,
            charlieValidator,
            signature
        );

        assertEq(address(_bob).balance, 1 ether);
    }

    function test_pause_reverts_for_non_owner() public {
        IStorage storageContract = IStorage(
            WalletCore(payable(_alice)).getMainStorage()
        );
        vm.prank(_bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.InvalidOwner.selector));
        storageContract.setValidatorStatus(address(0), false);
    }

    function test_pause_validator_succeeds() public {
        // First to add a valid validator
        address aliceECDSAValidator = _addValidator(_alice);

        vm.startPrank(_alice);
        vm.expectEmit();
        emit ValidatorStatusUpdated(aliceECDSAValidator, true);
        IStorage(WalletCore(payable(_alice)).getMainStorage())
            .setValidatorStatus(aliceECDSAValidator, true);

        emit ValidatorStatusUpdated(aliceECDSAValidator, false);
        IStorage(WalletCore(payable(_alice)).getMainStorage())
            .setValidatorStatus(aliceECDSAValidator, false);
    }
}
