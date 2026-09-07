---
id: generate/json_fenced
# SYSTEM+USER_MIRROR as of item 4.7 (LLD rule 2, "the output contract" half;
# 52 tokens, which is the ~40 the rule budgets). GENERATE's user turn states
# the FIELD list and nothing about the wire shape, so a dropped system turn
# leaves the model asked for eight fields with no instruction to emit JSON at
# all. Rules 4+5 run BEFORE the mirror, so an endpoint that enforces the shape
# itself still gets this sentence from neither turn.
role: SYSTEM+USER_MIRROR
stance: [REQUIRES_FENCE]
# Deliberately declares NO fields. Until item 4.4 it spelled out the same eight
# names `generate/field_contract` states in the USER turn, and
# `audit_runner._quote_contract_suffix` called that pair "one policy written
# twice, in two places that are edited independently". This fragment now states
# the WIRE SHAPE only; the field list has exactly one author.
---
IMPORTANT: Return findings as a JSON array - one object per finding, carrying exactly the fields the task asks for and no others. Wrap the array in a ```json fenced block and write nothing outside the fences.