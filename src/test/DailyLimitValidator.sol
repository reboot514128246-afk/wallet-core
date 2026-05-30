// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "../interfaces/IValidator.sol";
import "../Types.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DailyLimitValidator is IValidator {
    using ECDSA for bytes32;

    address public immutable signer;
    uint256 public constant LIMIT = 1 ether;
    uint256 public spentToday;

    constructor(address _signer) {
        signer = _signer;
    }

    function validate(
        bytes32 msgHash,
        bytes calldata validationData
    ) external view override {
        // In a real implementation, we'd check the limit here.
        // For this PoC, we just verify the signer.
        address recovered = msgHash.recover(validationData);
        if (recovered != signer) revert("Invalid signature");
    }
}
