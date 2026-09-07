---
id: validate/output_contract
# SYSTEM+USER_MIRROR as of item 4.7 — rule 2's own worked example: "the judge's
# strict-JSON retry nudge is appended to the user message while the schema it
# refers to lives system-only". DECLARED BUT NOT YET SHIPPED: `llm_judge`
# renders TRANSCRIBE, which mirrors nothing, and that flip belongs to item 4.1.
# So no byte of the judge prompt moves in this item and no cached verdict is
# invalidated by it.
role: SYSTEM+USER_MIRROR
stance: [BLESSES_ABSTENTION_AFTER_LOOKING, FORBIDS_FENCE, FORBIDS_PROSE]
declares_fields: [id, exploitable, window_sufficient, evidence_line, evidence_file, reasoning]
references: []
# This is the LAST section of `prompts/validate_judge.txt`, and that file's
# own terminating newline is part of the no-tools system turn: `_call_llm`
# sends what `_read_prompt` returned, terminator included. Without this the
# render of the tool-free spec is one byte short of the shipped prompt.
# `validate/tool_discipline` declares `seam: tight` so the byte kept here is
# the first of the seam's three newlines rather than a fourth.
keep_trailing: true
---
Your FINAL message must be STRICT JSON only — no prose, no markdown, no
code fences. Tool calls before it are expected and are not a violation:
{"verdicts":[{"id":"<finding_id>","exploitable":<float 0..1>,"window_sufficient":<true|false>,"evidence_line":<int or null>,"evidence_file":<string or null>,"reasoning":"<up to 60 words>"}]}

Every finding in the batch must appear in the response by id. If you
cannot judge a specific finding from the code shown, spend a tool call on it
before answering; if it is still undecidable, set exploitable=0.5 and explain
why in reasoning.
