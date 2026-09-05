---
id: prove/plan_cwe
role: USER
declares_fields: [description, method, url_path, headers, body, expected_indicators, filename]
---
You are a vulnerability researcher. Given this CWE finding, create an HTTP request to verify the vulnerability on the staging server.

RULES:
1. Use the discovered site map below to pick REAL URLs that exist on the target.
2. Do NOT use "/" as the url_path — pick a specific endpoint.
3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.
4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.
5. Each attempt MUST target a DIFFERENT endpoint or use a different payload.
6. For injection: craft payloads specific to the CWE type (SQL, XSS, command, path traversal).
7. For hardcoded credentials: check config endpoints and API responses (NOT .js files).
8. For file upload: target upload endpoints with malicious filenames.

Finding: {title}
Category: {category}
Description: {description}
File: {file_path}:{line_start}
Code: {code_snippet}
Hints: {verification_hints}
Staging URL: {staging_url}
Attempt: {iteration}
{prior_context}
{site_context}

Reply with ONLY a JSON object (no markdown, no explanation):
{"description":"what this tests","method":"GET or POST","url_path":"/real-path","headers":{},"body":"payload if POST","expected_indicators":["indicator"]}