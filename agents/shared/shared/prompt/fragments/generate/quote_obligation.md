---
id: generate/quote_obligation
role: USER
# USER, not SYSTEM+USER_MIRROR, as of item 4.4. The live builder emitted
# this sentence twice per call - user turn via `_field_contract()`, system
# turn via `_quote_contract_suffix()` - and the system copy existed ONLY on
# the unstructured branch, so the count depended on `supports_structured_
# output()`. It is now stated once, in the turn no gateway drops, which is
# the protection the mirror role existed to buy.
seam: tight
---
evidence_quote: copy the 1-{quote_max_lines} source lines your finding is about, VERBATIM from the numbered listing above (you may include the "NN: " prefix). A finding without a quote will be reported as unverified.