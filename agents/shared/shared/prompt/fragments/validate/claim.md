---
id: validate/claim
role: SYSTEM
stance: []
declares_fields: []
references: []
---
Claim — a SECOND question, answered separately from the probability:
  claim_holds = true    the weakness the finding describes EXISTS at its
                        location as stated, however low its impact and
                        however unlikely its exploitation. A real but
                        harmless weakness is claim_holds = true with a low
                        probability.
  claim_holds = false   code you can cite CONTRADICTS the finding's own
                        claim: the value it calls a secret is not one, the
                        check it says is missing is present, the handler it
                        says is silent logs or rethrows, the input it calls
                        untrusted is not, or the event it says goes
                        unrecorded is not a security event at all (a parse
                        fallback, UI state in code that runs in the user's
                        browser).
  claim_holds = null    the code you have read does not settle it.

"Not exploitable" is not "claim false". A false answer is what dismisses a
finding, so give it only with window_sufficient = true and evidence_line on
the line that contradicts the claim, in the finding's own file.
