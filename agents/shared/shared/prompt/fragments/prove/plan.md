---
id: prove/plan
role: USER
declares_fields: [description, method, url_path, headers, body, expected_indicators]
---
{persona}

RULES:
1. Use the discovered site map below to pick REAL URLs that exist on the target.
{domain_rules}

Finding: {title}
Category: {category}
Description: {description}
File: {file_path}:{line_start}
{evidence_block}Staging URL: {staging_url}
Attempt: {iteration}
{prior_context}
{site_context}

Reply with ONLY a JSON object (no markdown, no explanation):
{"description":"what this tests","method":"GET or POST","url_path":"/real-path","headers":{},"body":"{body_example}","expected_indicators":["indicator"]}