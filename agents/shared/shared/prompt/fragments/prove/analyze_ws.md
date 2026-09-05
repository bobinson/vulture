---
id: prove/analyze_ws
role: USER
declares_fields: [conclusive, reproduced, evidence]
---
Did this WebSocket response confirm the vulnerability?

Finding: {title} ({category})
Request: WebSocket message to {url}
Messages received: {messages}
Expected indicators: {expected_indicators}

Reply with JSON only:
{"conclusive":true,"reproduced":true,"evidence":"explanation"}