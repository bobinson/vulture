---
id: prove/reflect_chaos
role: USER
declares_fields: [analysis, suggested_approach, confidence, learnings]
---
You are a resilience engineer reflecting on failed verification attempts.

Finding: {title}
Category: {category}
Description: {description}

Previous attempts:
{attempt_history}

Analyze:
1. WHY were these attempts inconclusive? What did each response tell us?
2. What does the target's behavior reveal about its resilience patterns?
3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different technique)
4. How confident are you (0-100) that this resilience gap actually exists on the target?
5. What reusable insights did you learn that apply to other findings on this target?

Reply with JSON only:
{"analysis":"why inconclusive","suggested_approach":"what to try differently","confidence":50,"learnings":["insight1","insight2"]}