# Critical Vulnerability Report: Session Replay Attack in `executeFromExecutor`

## Summary
The `executeFromExecutor` function in `WalletCore.sol` is vulnerable to session replay attacks. Once a session and a batch of calls are authorized by the wallet owner's signature, an authorized executor can reuse that same signature to execute the same batch of calls multiple times. The system lacks any nonce-based protection or "one-time-use" mechanism for executions triggered via an executor.

## Vulnerability Details
In `ExecutorLogic.sol`, the `onlyValidSession` modifier validates the session:

```solidity
function validateSession(Session calldata session) public view {
    // ... validation of executor, time bounds, storage existence ...

    // Check invalidSessionId & validValidator in storage
    getMainStorage().validateSession(session.id, session.validator);

    // Validate signature
    bytes32 hash = getSessionTypedHash(session);
    bool isValid = WalletCoreLib.validate(
        session.validator,
        hash,
        session.signature
    );
    if (!isValid) revert Errors.InvalidSignature();
}
```

The `Storage.sol` contract's `validateSession` function only checks if the session ID has been manually revoked:

```solidity
function validateSession(uint256 id, address validator) external view {
    if (_invalidSessionId[id]) revert Errors.InvalidSessionId();
    validateValidator(validator);
}
```

There is no check for a nonce, and the session is not marked as "used" after execution. As long as the session's `validUntil` timestamp is in the future and the owner hasn't called `revokeSession(id)`, the executor can call `executeFromExecutor` repeatedly with the exact same `calls` and `session` signature.

## Impact
A malicious or compromised executor can replay a transaction (e.g., a token transfer) multiple times, draining the wallet's funds. Even if hooks are used to limit the executor's power, the lack of replay protection at the core execution level allows the executor to reach those limits repeatedly across different transactions if the hooks themselves don't maintain persistent state to prevent such replays.

## Proof of Concept
The Foundry-based PoC `test/ReplayExecutorPoC.t.sol` demonstrates that an executor can execute the same transfer multiple times using a single session signature.

## Recommendation
Implement a nonce-based protection mechanism for session-based executions:
1. Add a `nonce` field to the `Session` struct.
2. In `Storage.sol`, maintain a mapping of used nonces per session (or a global nonce per session).
3. In `ExecutorLogic.sol`, verify that the provided nonce has not been used and mark it as used in storage during execution.
