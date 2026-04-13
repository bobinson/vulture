# 0020 — Rollback Plan

## Risk Assessment: LOW
All changes are additive. No existing behavior is modified — only extended.

## Rollback Steps

### Full Rollback
```bash
git revert <commit-hash>
```

### Partial Rollback by Feature

#### A: Obfuscation Detection
- Remove `agents/shared/shared/tools/obfuscation.py`
- Remove `check_obfuscation` call from `cwe/skills/injection_check.py`

#### B: False Positive Suppression
- Remove `agents/shared/shared/tools/suppression.py`
- Remove `should_suppress` calls from `info_exposure_check.py` and `auth_check.py`

#### E: Hierarchical Check IDs
- Remove `check_id` field from models (Finding, AuditFinding, Go, TS)
- Revert `_dedup_key` / `_deduplicate_findings` to title-only logic

#### F-J: Prove Hardening
- Remove loop detector, backoff, body guard, timeout evidence changes from runner.py/shared.py
- Remove PAYLOAD_TOO_LARGE from FailureReason

#### M, P: Safety Margins + Char Budget
- Revert safe_estimate_tokens usage to estimate_tokens
- Remove max_chars param from build_prior_context

#### N: Prove State Machine
- Remove ProvePhase enum and proof_phase_event calls
- Remove proof_phase from translator and event constants

## Verification After Rollback
```bash
cd agents/shared && python3 -m pytest tests/ -v
cd agents/prove && python3 -m pytest tests/ -v
cd backend && go test ./...
```
