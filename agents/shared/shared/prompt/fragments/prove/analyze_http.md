---
id: prove/analyze_http
role: USER
declares_fields: [conclusive, reproduced, evidence]
---
Did this HTTP response confirm the vulnerability?

Finding: {title} ({category})
Request: {method} {url}
Status: {status_code}
Response headers: {response_headers}
Response (truncated): {response_snippet}
Expected indicators: {expected_indicators}

Reply with JSON only:
{"conclusive":true,"reproduced":true,"evidence":"explanation"}