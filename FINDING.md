# Critical Vulnerability Report: Privilege Escalation via `executeFromExecutor` Bypass

## Summary
The `WalletCore` implementation allows authorized executors to bypass `onlySelf` restrictions and session hook limitations. This is achieved by including calls targeting the wallet itself (e.g., `addValidator`) within an `executeFromExecutor` transaction. Since the wallet executes these calls via `call()`, the `msg.sender` for the internal call is the wallet itself, satisfying the `onlySelf` modifier and allowing executors to permanently escalate their privileges.

## Vulnerability Details
The `WalletCore.executeFromExecutor` function allows an authorized executor (with a valid session) to execute a batch of calls.

```solidity
function executeFromExecutor(
    Call[] calldata calls,
    Session calldata session
) external onlyValidSession(session, calls) {
    _batchCall(calls);
}
```

The `_batchCall` function iterates through the calls and executes them:

```solidity
function _batchCall(
    Call[] calldata calls
) internal returns (bytes[] memory results) {
    results = new bytes[](calls.length);
    for (uint256 i; i < calls.length; i++) {
        (bool success, bytes memory returnData) = calls[i].target.call{
            value: calls[i].value
        }(calls[i].data);
        if (!success) revert Errors.CallFailed(i, returnData);
        results[i] = returnData;
    }
}
```

If one of the `calls[i].target` is the wallet address itself (`address(this)`), the `call` will be executed as if it came from the wallet. Administrative functions like `addValidator` are protected by the `onlySelf` modifier:

```solidity
modifier onlySelf() {
    if (msg.sender != address(this)) revert Errors.NotFromSelf();
    _;
}
```

An executor can include a call to `addValidator(maliciousValidator, ...)` in the `calls` array. When executed, `msg.sender` will be `address(this)`, the check will pass, and the malicious validator will be added. This gives the attacker full control over the wallet.

## Impact
- **Permanent Privilege Escalation**: An executor with limited permissions can grant themselves (or an accomplice) full owner-level access by adding a new validator.
- **Bypass of Session Hooks**: Hooks intended to restrict an executor's actions can be bypassed if the executor can reconfigure the wallet's security settings.

## Proof of Concept
A reproduction test case is provided in `test/BypassPoC.t.sol`. It demonstrates:
1. Alice grants a limited session to an executor.
2. The executor calls `addValidator` on Alice's wallet via `executeFromExecutor`.
3. The malicious validator is successfully added.
4. The attacker uses the malicious validator to drain Alice's funds.

## Recommendation
Add a check in the `onlyValidSession` modifier or within `executeFromExecutor` to ensure that none of the calls in the batch target the wallet itself.

```solidity
modifier onlyValidSession(Session calldata session, Call[] calldata calls) {
    validateSession(session);
    for (uint256 i = 0; i < calls.length; i++) {
        if (calls[i].target == address(this)) revert Errors.NotFromSelf();
    }
    // ... rest of the modifier
}
```
