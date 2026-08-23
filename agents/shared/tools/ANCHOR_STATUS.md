# Anchor verifier — outcome attestation

<!-- GENERATED FILE — do NOT edit by hand. Regenerate: agents/.venv/bin/python agents/shared/tools/report_anchor_status.py --write -->

**N = 17 claims** over 13 distinct cited paths, drawn from 1 manifest fragment. 9 of the 9 anchor statuses are exercised, and 17 of 17 observations agree with the manifest's expectation.

Every figure above and below is COMPUTED from `manifest.d/` and the fixture tree at `agents/shared/tests/fixtures/anchor/`; none is a maintained literal. The run pins every `VULTURE_LLM_QUOTE_*` knob to its documented default, so this table is a property of the code and the fixtures, not of the shell that regenerated it. No model is called and no socket is opened.

## Outcomes

One row per hand-authored claim. `re-anchor` is the line the verifier would move to under `VULTURE_LLM_QUOTE_REANCHOR=true`; at the shipped default it is recorded and not applied. `found in` is `found_elsewhere`'s candidate — recorded in `other_path`, never written back to `file_path` (AC31).

| claim | cited path | line | quote chars | quote tokens | expected | observed | agrees | reason | re-anchor | delta | candidates | found in |
| ----- | ---------- | ---: | ----------: | -----------: | -------- | -------- | ------ | ------ | --------: | ----: | ---------: | -------- |
| `exact_copy` | `exact.ts` | 3 | 39 | 5 | exact | **exact** | yes | `-` | 3 | 0 | 1 | `-` |
| `exact_echoed_listing` | `elided.ts` | 6 | 77 | 11 | exact | **exact** | yes | `-` | 6 | 0 | 1 | `-` |
| `reanchored_signature` | `signature.ts` | 54 | 114 | 17 | reanchored | **reanchored** | yes | `-` | 55 | 1 | 1 | `-` |
| `reanchored_nearest_wins` | `near.ts` | 22 | 81 | 14 | reanchored | **reanchored** | yes | `-` | 20 | -2 | 2 | `-` |
| `reanchored_dupe_first` | `dupe3.ts` | 18 | 55 | 7 | reanchored | **reanchored** | yes | `-` | 15 | -3 | 1 | `-` |
| `reanchored_dupe_second` | `dupe3.ts` | 18 | 55 | 7 | reanchored | **reanchored** | yes | `-` | 15 | -3 | 1 | `-` |
| `exact_dupe_third` | `dupe3.ts` | 15 | 55 | 7 | exact | **exact** | yes | `-` | 15 | 0 | 1 | `-` |
| `ambiguous_tie` | `ambig.ts` | 70 | 78 | 12 | ambiguous | **ambiguous** | yes | `not_unique` | - | - | 2 | `-` |
| `near_miss_retyped` | `nearmiss.ts` | 7 | 26 | 4 | near_miss | **near_miss** | yes | `similar` | - | - | 0 | `-` |
| `found_elsewhere_sibling` | `elsewhere/cited.ts` | 5 | 57 | 9 | found_elsewhere | **found_elsewhere** | yes | `cross_file` | - | - | 0 | `elsewhere/sibling.ts` |
| `absent_invented` | `fabricated.ts` | 5 | 51 | 4 | absent | **absent** | yes | `not_found` | - | - | 0 | `-` |
| `unquoted_missing` | `exact.ts` | 3 | 0 | 0 | unquoted | **unquoted** | yes | `missing` | - | - | 0 | `-` |
| `unquoted_paraphrase` | `paraphrase.ts` | 5 | 20 | 2 | unquoted | **unquoted** | yes | `below_floor` | - | - | 0 | `-` |
| `unquoted_below_floor` | `floor.ts` | 6 | 3 | 0 | unquoted | **unquoted** | yes | `below_floor` | - | - | 0 | `-` |
| `unquoted_line_too_long` | `longline.ts` | 4 | 900 | 182 | unquoted | **unquoted** | yes | `line_too_long` | - | - | 0 | `-` |
| `unreadable_unresolved` | `../../../etc/passwd` | 12 | 45 | 7 | unreadable | **unreadable** | yes | `no_path` | - | - | 0 | `-` |
| `oversize_four_lines` | `exact.ts` | 2 | 108 | 14 | oversize | **oversize** | yes | `truncated:exact` | 2 | 0 | 1 | `-` |

## Status histogram

`weight` is what the `anchor` ValidationCheck carries at the shipped default; `armed` is the same weight with `VULTURE_LLM_QUOTE_DEMOTE_ABSENT=true`. No status may ever be POSITIVE: on the adjudicated population the best-quoting rows are the best-quoting FALSE POSITIVES, so promotion is declined outright (AC27). Only `absent` may go negative, and only when armed.

| status | claims | share | weight | armed | exercised |
| ------ | -----: | ----: | -----: | ----: | --------- |
| `absent` | 1 | 5.9% | 0.0 | -1.0 | yes |
| `ambiguous` | 1 | 5.9% | 0.0 | 0.0 | yes |
| `exact` | 3 | 17.6% | 0.0 | 0.0 | yes |
| `found_elsewhere` | 1 | 5.9% | 0.0 | 0.0 | yes |
| `near_miss` | 1 | 5.9% | 0.0 | 0.0 | yes |
| `oversize` | 1 | 5.9% | 0.0 | 0.0 | yes |
| `reanchored` | 4 | 23.5% | 0.0 | 0.0 | yes |
| `unquoted` | 4 | 23.5% | 0.0 | 0.0 | yes |
| `unreadable` | 1 | 5.9% | 0.0 | 0.0 | yes |

## Fragments

Fragments are globbed from `manifest.d/`. A basename beginning with `_` is EXCLUDED from that glob and loadable only by explicit name, so the unit-test slice can never enter the count above (T5.3, mirroring the CWE corpus).

| fragment | claims |
| -------- | -----: |
| `anchor` | 17 |

## What this table does and does not attest

- It attests the VERIFIER, not the detector. Every claim here was authored by hand; none came from a model. A green table means `verify_anchor` still labels the nine measured causes the way the fixtures say it should — it says nothing about how often a live model produces each cause.
- `absent` is the only demoting status, and it is inert until `VULTURE_LLM_QUOTE_DEMOTE_ABSENT` is armed. `unquoted`, `ambiguous`, `near_miss`, `found_elsewhere`, `unreadable` and `oversize` exist precisely so that a real defect described imprecisely is never mistaken for a fabricated one.
- A stale copy of this file fails the unit suite. Regenerate with:

      agents/.venv/bin/python agents/shared/tools/report_anchor_status.py --write
