// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

library Errors {
    // Storage related
    error InvalidExecutor();
    error InvalidSession();
    error InvalidSessionId();
    error InvalidOwner();

    // Account related
    error NotFromSelf();

    // Call related
    error CallFailed(uint256 index, bytes returnData);

    // ValidationLogic related
    error InvalidValidator(address validator);
    error InvalidValidatorImpl(address validatorImpl);

    // ECDSAValidator related
    error InvalidSignature();

    // WalletCoreBase related
    error NameTooLong();
    error VersionTooLong();
}
