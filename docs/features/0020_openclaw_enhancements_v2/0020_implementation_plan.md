# 0020 — reference implementation-Inspired Enhancements (A-R)

## Overview
Ports 13 patterns from the reference implementation codebase to Vulture's scan and prove agents, enhancing scanning accuracy, prove agent robustness, and observability.

## Enhancements Implemented

| ID | Enhancement | Category |
|----|-------------|----------|
| A | Obfuscation Detection | Scan Skills |
| B | False Positive Suppression | Scan Skills |
| C | Port-Aware Filtering | Shared |
| D | Resource-Bounded Scanning | Shared |
| E | Hierarchical Check IDs | Cross-cutting |
| F | Loop Detection (Prove) | Prove Hardening |
| G | Backoff Schedule (Prove) | Prove Hardening |
| H | Context Budget (Prove) | Prove Hardening |
| I | Request Body Guards | Prove Hardening |
| J | Synthetic Result Synthesis | Prove Hardening |
| M | Compaction Safety Margins | Shared |
| N | Prove State Machine | Prove Observability |
| P | Memory Char Budget | Shared |

## Skipped (Premature)
- K: Plugin Registry — only 4 strategies, premature abstraction
- L: Hook System — no consumers, logging sufficient
- O: Thinking Block Support — SDK/LiteLLM handles transparently
- Q: Plugin Config UI Hints — no frontend consumer
- R: Persistent Dedupe — title-dedup sufficient, full fingerprint flow deferred

## Architecture Impact
- No new services or dependencies
- All changes are additive (new fields, new optional parameters)
- Backward compatible: check_id defaults to empty string
