// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

struct Call {
    address target;
    uint256 value;
    bytes data;
}

struct Session {
    uint256 id;
    uint256 nonce;
    address executor;
    address validator;
    uint256 validUntil;
    uint256 validAfter;
    bytes preHook;
    bytes postHook;
    bytes signature;
}
