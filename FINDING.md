# [CRITICAL] Privilege Escalation and Hook Bypass via Self-Calling in `executeFromExecutor`

## Vulnerable Code
`src/WalletCore.sol:84` — `executeFromExecutor()`
`src/ExecutionLogic.sol:20` — `_batchCall()`

## Root Cause
The `executeFromExecutor` function allows an authorized executor to perform a batch of calls on behalf of the wallet. These calls are executed via `_batchCall`, which uses a low-level `call` from the wallet's own context.

The security-critical functions in `WalletCore` (like `addValidator` and `executeFromSelf`) are protected by the `onlySelf` modifier, which ensures `msg.sender == address(this)`.

When an executor includes a call that targets the wallet itself in an `executeFromExecutor` transaction, the `msg.sender` for that internal call becomes the wallet itself. This allows the executor to successfully call `onlySelf` protected functions, bypassing the intended restriction that only the wallet owner (via a direct 7702 transaction or a validated relayer transaction) should be able to perform these actions.

## Attack Path
1.  **Preparation**: Alice (the wallet owner) authorizes Mallory as an executor with a session. This session might be restricted with hooks (e.g., only allowing specific tokens or limited amounts).
2.  **Privilege Escalation**: Mallory calls `executeFromExecutor` with a malicious `Call` targeting the wallet's `addValidator` function.
3.  **Execution**: The wallet calls itself. The `onlySelf` check passes because `msg.sender` is the wallet. A new validator controlled by Mallory is added to the wallet's storage.
4.  **Result**: Mallory now has permanent, unrestricted access to the wallet as a validator, even after her session expires or if it was initially restricted by hooks.
5.  **Hook Bypass**: Alternatively, Mallory can call `executeFromSelf` on the wallet via `executeFromExecutor`. This allows her to execute arbitrary transactions that completely bypass any `preHook` or `postHook` defined in her session, as those hooks only apply to the outer `executeFromExecutor` call.

## PoC
```bash
./run_poc.sh
# Expected output:
# [PASS] test_executor_hook_bypass() (gas: 147229)
# Logs:
#   --- Hook Bypass Attack ---
#   Direct transfer of 100 MTK blocked by hook as expected.
#   Mallory successfully bypassed onlySelf and transferred 100 MTK!
#
# [PASS] test_executor_privilege_escalation() (gas: 132384)
# Logs:
#   --- Privilege Escalation Attack ---
#   Mallory successfully added herself as a permanent validator!
```

## Impact
**Critical**. Any authorized executor, regardless of how restricted their session is intended to be via hooks, can gain full and permanent control over the wallet. They can drain all funds, change wallet settings, and add themselves as permanent owners (validators).

## Fix
In `executeFromExecutor`, the code should prevent any of the `calls` from targeting the wallet itself (`address(this)`).

```solidity
    function _batchCall(
        Call[] calldata calls
    ) internal returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; i++) {
            // Prevent self-calls that could bypass onlySelf modifiers
            if (calls[i].target == address(this)) revert Errors.NotFromSelf();

            (bool success, bytes memory returnData) = calls[i].target.call{
                value: calls[i].value
            }(calls[i].data);
            if (!success) revert Errors.CallFailed(i, returnData);
            results[i] = returnData;
        }
    }
```
Alternatively, the `onlySelf` modifier could be strengthened to distinguish between top-level 7702 transactions and internal calls made during executor/relayer flows, but blocking self-calls in `_batchCall` is the most direct fix for this architecture.

## Status
CONFIRMED
