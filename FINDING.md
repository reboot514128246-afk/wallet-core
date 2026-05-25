# Critical Vulnerability Report: Security Bypass via Codeless Proxy Implementations

## Summary
The `WalletCore` implementation is vulnerable to a complete security bypass when using EIP-1167 clones (proxies) that delegate to addresses with no deployed code. This can happen if the wallet is uninitialized, misconfigured, or if a validator contract self-destructs. In these cases, high-level and low-level calls to the proxy return success and no data, which the wallet misinterprets as successful security validation.

## Vulnerability Details

### 1. Zombie Storage Bypass
The `WalletCore` uses a deterministic storage clone. Administrative checks like `validateSession` and `validateValidator` are performed by calling this storage contract. If the wallet has not been properly initialized or if the `MAIN_STORAGE_IMPL` address is codeless, the storage proxy becomes a "zombie". Any call to a void function (like `validateSession`) on this zombie proxy will succeed silently because the underlying `delegatecall` to a codeless address returns success.

### 2. Zombie Validator Bypass
In `WalletCoreLib.validate`, the wallet verifies signatures by calling an external validator's `validate` function.

```solidity
try IValidator(validator).validate(typedDataHash, validationData) {
    return true;
} catch {
    return false;
}
```

If `validator` is an EIP-1167 proxy delegating to a codeless address, the high-level call `IValidator(validator).validate(...)` succeeds because the proxy's `delegatecall` returns success. This allows an attacker to bypass signature verification entirely by providing a "zombie" validator address.

## Impact
- **Complete Wallet Takeover**: Attackers can execute arbitrary transactions from any uninitialized wallet or any wallet that authorizes a "zombie" validator.
- **Unauthorized Execution**: The `executeFromExecutor` function can be called with any session data and any signature, bypassing all permission checks.
- **Signature Spoofing**: `isValidSignature` will return `MAGIC_VALUE` for any hash and signature combination if the validator is codeless.

## Proof of Concept
A reproduction test case is provided in `test/CodelessBypassPoC.t.sol`.
Run it using:
```bash
DEPLOY_FACTORY_SALT=0x0000000000000000000000000000000000000000000000000000000000000000 forge test --mt test_codeless -vvv
```
It demonstrates:
1. Attempting to initialize a wallet with a codeless implementation (now blocked by fix).
2. Attempting to use a codeless EOA as a validator (now blocked by fix).

## Recommendation
1. **Check Implementation Existence**: In `initialize()`, verify that `MAIN_STORAGE_IMPL` has code before deploying the clone.
2. **Contract Existence Checks**: Before calling security-critical contracts (storage and validators), explicitly check that the target address has code (`code.length > 0`).
3. **Validate Session Storage**: Ensure that `validateSession` and `validateValidator` checks in `ValidationLogic.sol` and `ExecutorLogic.sol` verify that the storage contract itself exists.

```solidity
if (address(getMainStorage()).code.length == 0) revert Errors.InvalidSession();
```
