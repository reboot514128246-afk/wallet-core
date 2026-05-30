// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {DailyLimitValidator} from "src/test/DailyLimitValidator.sol";
import {IValidation} from "src/interfaces/IValidation.sol";

contract ValidatorConfusionPoC is Base {
    DailyLimitValidator limitValidator;

    function setUp() public override {
        super.setUp();

        // 1. Alice adds a DailyLimitValidator
        limitValidator = new DailyLimitValidator(_alice);
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(address(limitValidator), "");
    }

    function test_validator_confusion_bypass() public {
        // 2. Alice wants to send 5 ether.
        // She expects this to FAIL if she uses her DailyLimitValidator (limit is 1 ether).
        // But she signs the transaction data.

        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _bob, value: 5 ether, data: ""});

        // Alice signs the hash. The hash includes the validator address she INTENDS to use.
        bytes32 hash = IValidation(_alice).getValidationTypedHash(
            nonce,
            calls,
            address(limitValidator)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // 3. Bob (the relayer) sees Alice's signature.
        // Bob attempts to execute using the BUILT-IN validator (address(1)), bypassing Alice's intended validator.
        // This SHOULD FAIL because the signature was bound to address(limitValidator).

        console.log("Alice balance before:", _alice.balance);

        vm.prank(_bob);
        vm.expectRevert(Errors.InvalidSignature.selector);
        IWalletCore(_alice).executeWithValidator(
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            signature
        );

        console.log("Alice balance after:", _alice.balance);
        assertEq(_alice.balance, 10 ether, "Alice's funds should be safe");
        assertEq(_bob.balance, 0, "Bob should not have received funds");

        console.log("FIX VERIFIED: Validator confusion bypass prevented.");
    }
}
