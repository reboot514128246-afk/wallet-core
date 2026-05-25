// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {MockExecutor} from "src/test/MockExecutor.sol";
import {Call, Session} from "src/Types.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import {IStorage} from "src/interfaces/IStorage.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";

contract BypassPoC is Base {
    MockExecutor mockExecutor;
    address attacker;
    uint256 attackerPk;

    function setUp() public override {
        super.setUp();
        (attacker, attackerPk) = makeAddrAndKey("attacker");

        vm.prank(_alice);
        mockExecutor = new MockExecutor(IWalletCore(_alice));
    }

    function test_bypass_onlySelf() public {
        // 1. Alice grants a limited session to an executor (mockExecutor)
        Session memory session = Session({
            id: 1,
            executor: address(mockExecutor),
            validator: address(1),
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook: "",
            postHook: "",
            signature: ""
        });

        bytes32 hash = IExecutor(_alice).getSessionTypedHash(session);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);
        session.signature = abi.encodePacked(r, s, v);

        // 2. The malicious executor wants to escalate privileges by adding a new validator
        // that the attacker controls.

        address maliciousValidatorSigner = attacker;
        bytes memory initCode = abi.encode(maliciousValidatorSigner);

        // Target: Alice's wallet
        // Data: addValidator(ecdsaValidatorImpl, initCode)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: _alice,
            value: 0,
            data: abi.encodeWithSelector(IWalletCore.addValidator.selector, address(_ecdsaValidatorImpl), initCode)
        });

        // 3. Execute the malicious call via executeFromExecutor
        // This should fail with NotFromSelf() because target is the wallet itself.
        vm.prank(address(mockExecutor));
        vm.expectRevert(Errors.NotFromSelf.selector);
        mockExecutor.execute(calls, session);

        // 4. Verify privilege escalation attempt failed: the new validator is NOT active
        address predictedMaliciousValidator = _getEdcsaValidatorAddress(_alice, maliciousValidatorSigner, address(_ecdsaValidatorImpl));
        IStorage store = IWalletCore(_alice).getMainStorage();

        // This call MUST revert because the validator was NOT added
        vm.expectRevert(abi.encodeWithSelector(Errors.InvalidValidator.selector, predictedMaliciousValidator));
        store.validateValidator(predictedMaliciousValidator);

        // The vulnerability is fixed.
        // To be absolutely sure, we can try to use it for a simple transfer.
        uint256 nonce = store.getNonce();
        Call[] memory attackerCalls = new Call[](1);
        attackerCalls[0] = Call({
            target: _bob,
            value: 1 ether,
            data: ""
        });

        bytes32 validationHash = ValidationLogic(_alice).getValidationTypedHash(nonce, attackerCalls);
        (v, r, s) = vm.sign(attackerPk, validationHash);
        bytes memory attackerSig = abi.encodePacked(r, s, v);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Errors.InvalidValidator.selector, predictedMaliciousValidator));
        IWalletCore(_alice).executeWithValidator(attackerCalls, predictedMaliciousValidator, attackerSig);

        assertEq(_bob.balance, 0 ether);
    }
}
