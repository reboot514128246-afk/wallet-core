// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MockERC20} from "src/test/MockERC20.sol";
import {MockExecutor} from "src/test/MockExecutor.sol";
import {Call, Session} from "src/Types.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import "./Base.t.sol";

contract ReplayExecutorPoC is Base {
    using ECDSA for bytes32;

    MockERC20 mockToken;
    MockExecutor mockExecutor;

    function setUp() public override {
        super.setUp();
        vm.prank(_alice);
        mockToken = new MockERC20();
        mockExecutor = new MockExecutor(IWalletCore(_alice));
    }

    function test_executor_replay_vulnerability() public {
        // 1. Alice authorizes a session for the executor
        Session memory session = Session({
            id: 123,
            nonce: 0,
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

        // 2. The executor executes a transfer of 10 tokens to Bob
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", _bob, 10)
        });

        console.log("Bob balance before execution:", mockToken.balanceOf(_bob));

        vm.prank(address(mockExecutor));
        IWalletCore(_alice).executeFromExecutor(calls, session);

        console.log("Bob balance after 1st execution:", mockToken.balanceOf(_bob));
        assertEq(mockToken.balanceOf(_bob), 10);

        // 3. REPLAY: The executor calls it again with the SAME session and calls.
        // This SHOULD NOW REVERT because the nonce 0 was already used.

        vm.prank(address(mockExecutor));
        vm.expectRevert();
        IWalletCore(_alice).executeFromExecutor(calls, session);

        console.log("Bob balance after replay attempt:", mockToken.balanceOf(_bob));
        assertEq(mockToken.balanceOf(_bob), 10, "Replay should have failed!");
    }

    function test_executor_multiple_transactions_with_new_sessions() public {
        // To execute multiple times, we need new sessions (or a way to authorize multiple nonces).
        // Since the current signature binds the nonce, each execution needs a new signed session.

        for (uint256 i = 0; i < 3; i++) {
            Session memory session = Session({
                id: 123,
                nonce: i,
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

            Call[] memory calls = new Call[](1);
            calls[0] = Call({
                target: address(mockToken),
                value: 0,
                data: abi.encodeWithSignature("transfer(address,uint256)", _bob, 10)
            });

            vm.prank(address(mockExecutor));
            IWalletCore(_alice).executeFromExecutor(calls, session);
        }

        assertEq(mockToken.balanceOf(_bob), 30);
        console.log("Multiple valid transactions with unique nonces succeeded");
    }
}
