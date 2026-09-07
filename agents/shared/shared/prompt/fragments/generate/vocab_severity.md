---
id: generate/vocab_severity
role: SYSTEM
binds_vocabulary: severity=[critical, high, medium, low, info]
---
SEVERITY VOCABULARY: the `severity` field must be EXACTLY one of: critical,
high, medium, low, info. Any other value - a synonym, a number, a phrase, an
invented level - is recorded as `info`, so a severity you make up does not
raise an alarm, it silently buries the finding at the bottom of the report.