// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IStorage} from "src/interfaces/IStorage.sol";
import {IExecutor} from "src/interfaces/IExecutor.sol";
import {WalletCore} from "src/WalletCore.sol";
import {Session, Call} from "src/Types.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Errors} from "src/lib/Errors.sol";

contract CodelessBypassPoC is Base {
    using Clones for address;

    function test_codeless_storage_bypass() public {
        // 1. Setup a WalletCore with a codeless storage implementation.
        address codelessStorageImpl = makeAddr("codeless_storage_impl");
        WalletCore walletCore = new WalletCore(
            codelessStorageImpl,
            "test",
            "1"
        );

        address aliceWallet = makeAddr("alice_wallet");
        _setCodeToEOA(address(walletCore), aliceWallet);

        // 2. Initialize it. This should now REVERT because we check for implementation existence.
        vm.prank(aliceWallet);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.InvalidStorageImpl.selector,
                codelessStorageImpl
            )
        );
        IWalletCore(aliceWallet).initialize();

        console.log("Fix verified: Codeless storage initialization blocked!");
    }

    function test_codeless_validator_bypass() public {
        // 1. Alice is properly initialized.
        // 2. An EOA is used as a validator address.
        address eoaValidator = makeAddr("eoa_validator");

        // 3. Normally, isValidSignature would use try-catch to call the EOA.
        // In Solidity 0.8.x, a high-level call to an EOA reverts.
        // Our fix explicitly checks code length to return false.

        bytes32 hash = keccak256("data");
        bytes memory sig = abi.encodePacked(eoaValidator, hex"1234");

        // Manually authorize it (simulating it was added when it had code)
        address store = address(IWalletCore(_alice).getMainStorage());
        vm.prank(_alice);
        IStorage(store).setValidatorStatus(eoaValidator, true);

        // 4. Check signature. Should return INVALID_VALUE (0xffffffff) because it has no code.
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, sig);
        assertEq(
            result,
            bytes4(0xffffffff),
            "EOA validator should be rejected"
        );

        console.log("Fix verified: Codeless validator rejected!");
    }
}
