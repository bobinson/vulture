---
id: generate/json_fenced
role: SYSTEM
stance: [REQUIRES_FENCE]
# The same eight fields generate/field_contract states in the USER turn.
# audit_runner._quote_contract_suffix calls the pair "one policy written
# twice, in two places that are edited independently"; declaring it here is
# what lets check_02_duplicate_contract see that.
declares_fields: [severity, category, title, description, file_path, line_start, line_end, recommendation]
---
IMPORTANT: Return findings as a JSON array. Each object must have: severity, category, title, description, file_path, line_start, line_end, recommendation. Wrap the array in ```json ... ``` fences.