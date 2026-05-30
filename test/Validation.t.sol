// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./Base.t.sol";

contract ValidationTest is Base {
    event NonceConsumed(uint256 nonce);

    function setUp() public override {
        super.setUp();
    }

    function test_executeWithValidator_succeeds_as_owner() public {
        vm.prank(_alice);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );

        IWalletCore(_alice).executeWithValidator(
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            signature
        );

        assertEq(address(_bob).balance, 1 ether);
    }

    function test_executeWithValidator_succeeds_as_relayer() public {
        vm.prank(_bob);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );

        IWalletCore(_alice).executeWithValidator(
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            signature
        );

        assertEq(address(_bob).balance, 1 ether);
    }

    function test_executeWithValidator_reverts_for_default_validator_invalid_signer()
        public
    {
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _bobPk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );

        vm.prank(_alice);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidSignature.selector)
        );
        IWalletCore(_alice).executeWithValidator(
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            signature
        );
        assertEq(address(_bob).balance, 0 ether);
    }

    function test_executeWithValidator_reverts_for_invalid_signature() public {
        vm.startPrank(_alice);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _bobPk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );
        address validatorAddress = _addValidator(_alice);

        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidSignature.selector)
        );
        IWalletCore(_alice).executeWithValidator(
            calls,
            validatorAddress,
            signature
        );

        assertEq(address(_bob).balance, 0 ether);
    }

    function test_executeWithValidator_reverts_for_invalid_nonce() public {
        vm.prank(_bob);
        uint256 nonce = _getNonce(_alice) + 99;
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );
        address validatorAddress = _getEdcsaValidatorAddress(
            _alice,
            _alice,
            address(_ecdsaValidatorImpl)
        );

        vm.expectRevert();
        IWalletCore(_alice).executeWithValidator(
            calls,
            validatorAddress,
            signature
        );

        assertEq(address(_bob).balance, 0 ether);
    }

    function test_executeWithValidator_reverts_for_invalid_validator() public {
        vm.prank(_bob);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );
        address validatorAddress = _bob; // invalid validator

        vm.expectRevert();
        IWalletCore(_alice).executeWithValidator(
            calls,
            validatorAddress,
            signature
        );

        assertEq(address(_bob).balance, 0 ether);
    }

    function test_executeWithValidator_reverts_for_validator_paused() public {
        vm.startPrank(_alice);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );
        address validatorAddress = _addValidator(_alice);

        IStorage storageContract = IStorage(
            WalletCore(payable(_alice)).getMainStorage()
        );
        vm.prank(_alice);
        storageContract.setValidatorStatus(validatorAddress, false);

        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.InvalidValidator.selector,
                validatorAddress
            )
        );
        IWalletCore(_alice).executeWithValidator(
            calls,
            validatorAddress,
            signature
        );

        assertEq(address(_bob).balance, 0 ether);
    }

    function test_executeWithValidator_emits_nonce_consumed() public {
        vm.prank(_alice);
        uint256 nonce = _getNonce(_alice);
        Call[] memory calls = _construct_calls_data();
        bytes memory signature = _construct_signature(
            _alicePk,
            nonce,
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS
        );

        vm.expectEmit();
        emit NonceConsumed(nonce);

        IWalletCore(_alice).executeWithValidator(
            calls,
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            signature
        );

        assertEq(address(_bob).balance, 1 ether);
    }

    function test_isValidSignature_fails_with_invalid_signer() public view {
        bytes32 hash = keccak256("test");

        // Wrong signer
        bytes memory signature = abi.encodePacked(
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            _signDigest(hash, _bobPk)
        );

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_fails_with_invalid_validator() public view {
        bytes32 hash = keccak256("test");
        // Wrong validator
        bytes memory signature = abi.encodePacked(
            _bob,
            _signDigest(hash, _alicePk)
        );

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_reverts_for_paused_validator() public {
        // Add validator
        address validator = _addValidator(_alice);

        // Pause validator
        vm.startPrank(_alice);
        IStorage(WalletCore(payable(_alice)).getMainStorage())
            .setValidatorStatus(validator, false);
        vm.stopPrank();

        bytes32 hash = keccak256("test");
        bytes memory signature = abi.encodePacked(
            validator,
            _signDigest(hash, _alicePk)
        );

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_fails_with_short_signature() public view {
        bytes32 hash = keccak256("test");

        // signature shorter than 20 bytes
        bytes memory signature = bytes("");

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_fails_with_longer_than_85_bytes_signature()
        public
        view
    {
        bytes32 hash = keccak256("test");

        // signature have 100 bytes
        bytes memory signature = bytes(new bytes(100));

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_succeeds_with_default_validator()
        public
        view
    {
        bytes32 hash = keccak256("test");
        bytes memory signature = abi.encodePacked(
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            _signDigest(hash, _alicePk)
        );

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_succeeds_with_valid_validator_signer()
        public
    {
        // Add validator
        address validator = _addValidator(_alice);

        bytes32 hash = keccak256("test");
        bytes memory signature = abi.encodePacked(
            validator,
            _signDigest(hash, _alicePk)
        );

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(hash, signature);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_for_premit() public view {
        bytes32 hash = keccak256("721 struct data");
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, hash);

        // Signature
        bytes memory validationData = abi.encodePacked(r, s, v);

        // Call isValidSignature
        bytes4 result = IWalletCore(_alice).isValidSignature(
            hash,
            validationData
        );
        assertEq(result, bytes4(0x1626ba7e));
    }

    function _signDigest(
        bytes32 hash,
        uint256 signerPk
    ) internal view returns (bytes memory) {
        bytes32 boundHash = keccak256(
            abi.encode(bytes32(block.chainid), address(_alice), hash)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", boundHash));

        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        return abi.encodePacked(r, s, v);
    }
}
