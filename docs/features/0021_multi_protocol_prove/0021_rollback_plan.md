# 0021 Multi-Protocol Prove — Rollback Plan

## Backward Compatibility

All changes are backward compatible. New fields have safe defaults:
- `ProofPlan.protocol = ProbeProtocol.HTTP`
- `ProofPlan.rpc_method = ""`
- `ProofPlan.rpc_params = None`
- `AttemptRecord.protocol = "http"`
- `ExecutionResult.protocol_used = ""`

## Rollback Steps

1. **Remove protocols/ package**: `rm -rf agents/prove/prove_agent/protocols/`
2. **Revert base.py**: Remove ProbeProtocol enum, PROTOCOL_ERROR, new fields
3. **Revert runner.py**: Remove capabilities parameter, ws/wss validation, fallback logic
4. **Revert agent.py**: Restore `_check_reachability()`, remove `detect_capabilities()`
5. **Revert strategies**: Remove capabilities parameter from execute()
6. **Revert plugins**: Remove WS JSON-RPC probing, actual WS connections
7. **Revert learning_store.py**: Remove target_protocols, primary_protocol fields
8. **Revert event_emitter.py**: Remove protocol parameter from proof events
9. **Revert pyproject.toml**: Remove websockets dependency
10. **Remove test files**: `rm agents/prove/tests/unit/test_protocols.py agents/prove/tests/e2e/test_multi_protocol.py`

## Risk Assessment

- **Low risk**: All new functionality is additive. HTTP-only targets work identically.
- **Dependency**: `websockets>=13.0` is the only new dependency. Well-maintained, MIT licensed.
