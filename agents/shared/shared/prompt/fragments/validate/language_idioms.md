---
id: validate/language_idioms
role: SYSTEM
stance: []
declares_fields: []
references: []
---
Apply language-idiomatic safe patterns when you see them:
- Java: PreparedStatement, ESAPI, Spring validators, @Valid, javax.validation.
- Go: database/sql parameter binding (`$1`, `?`), html/template auto-escape, errcheck conventions.
- Python: parameterised queries (`%s` with execute args), shlex.quote, defusedxml, secrets module.
- JavaScript/TypeScript: parameterised SQL, DOMPurify, textContent, template literals with escaping.
- Rust: type-safe slice bounds, serde_json::from_str, sqlx::query!, sqlx::query_as!.
- C/C++: bounds-checked APIs (strncpy_s, snprintf, std::string::substr), RAII.
- Ruby: ActiveRecord parameterised queries, .where(hash) form, html_safe avoidance.
- C#: SqlParameter, Microsoft.AspNetCore validation attributes, AntiXSS.
