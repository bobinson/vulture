# 0021 Multi-Protocol Support for Prove Agent

## Overview

Adds WebSocket and JSON-RPC protocol support to the prove agent, enabling verification of findings against targets that speak WebSocket and/or JSON-RPC — specifically blockchain nodes like Substrate/Polkadot.

## Architecture

```
                    ProofPlan.protocol
                          |
                    execute_plan()  <-- dispatcher
                   /      |        \
                  v        v         v
execute_and_analyze()  execute_ws()  execute_jsonrpc()
   (existing httpx)     (websockets)   (httpx POST or websockets)
```

## Key Components

1. **ProbeProtocol enum** (HTTP, WEBSOCKET, JSONRPC) on ProofPlan
2. **TargetCapabilities** detected once at startup via `detect_capabilities()`
3. **Protocol dispatcher** routes plans to correct executor
4. **WebSocket executor** — connects, sends, collects messages, analyzes
5. **JSON-RPC executor** — auto-selects HTTP/WS transport, parses RPC responses
6. **Fallback chain** — retries with alternative protocol on CONNECTION_ERROR/PROTOCOL_ERROR

## Files Modified

- `agents/prove/prove_agent/strategies/base.py` — ProbeProtocol enum, PROTOCOL_ERROR, new fields
- `agents/prove/prove_agent/runner.py` — ws/wss validation, capabilities threading, fallback logic
- `agents/prove/prove_agent/agent.py` — detect_capabilities replaces _check_reachability
- `agents/prove/prove_agent/strategies/shared.py` — protocol in context builders
- `agents/prove/prove_agent/strategies/{owasp,cwe,chaos,soc2}.py` — execute_plan dispatcher
- `agents/prove/prove_agent/plugins/rpc.py` — WS JSON-RPC discovery
- `agents/prove/prove_agent/plugins/websocket.py` — actual WS connection probing
- `agents/prove/prove_agent/learning_store.py` — protocol persistence
- `agents/prove/pyproject.toml` — websockets dependency
- `agents/shared/shared/transport/event_emitter.py` — protocol field on events

## Files Created

- `agents/prove/prove_agent/protocols/__init__.py`
- `agents/prove/prove_agent/protocols/detection.py`
- `agents/prove/prove_agent/protocols/dispatcher.py`
- `agents/prove/prove_agent/protocols/ws_executor.py`
- `agents/prove/prove_agent/protocols/jsonrpc_executor.py`
- `agents/prove/prove_agent/protocols/fallback.py`
- `agents/prove/tests/unit/test_protocols.py`
- `agents/prove/tests/e2e/test_multi_protocol.py`
