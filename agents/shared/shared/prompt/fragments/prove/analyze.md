---
id: prove/analyze
role: USER
declares_fields: [conclusive, reproduced, evidence]
---
Did this {protocol} response confirm the vulnerability?

Finding: {title} ({category})
Expected indicators: {expected_indicators}

Reply with JSON only:
{"conclusive":true,"reproduced":true,"evidence":"explanation"}
If the response does not clearly confirm or refute the finding, set "conclusive" to false.

{request_block}