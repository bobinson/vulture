# XSS Scanner Agent — Skills

## Overview

The XSS Scanner agent detects cross-site scripting vulnerabilities across 5 categories covering reflected, stored, and DOM-based XSS, plus template injection and header injection vectors.

## Skills

### 1. `reflected_xss_check` — Reflected XSS (CWE-79)

Detects user input reflected in HTTP responses without proper encoding.

**Patterns detected:**
- Template unsafe rendering: `|safe`, `mark_safe()`, `{!! !!}` (Blade), `<%- %>` (EJS)
- Direct DOM writes: `innerHTML`, `outerHTML`, `document.write()` with variables
- React: `dangerouslySetInnerHTML`
- Go: `fmt.Fprintf(w, ...)` with request params
- Flask/Django: `Response(user_input)`, `HttpResponse(user_input)`
- Express: `res.send(req.query...)`, `res.write(req.body...)`
- PHP: `echo $_GET[...]`, `<?= $var ?>`

**Safe exclusions (context-aware ±5 lines):**
- `html.EscapeString`, `bleach.clean`, `DOMPurify`, `encodeURIComponent`
- `htmlspecialchars`, `textContent`, `innerText`, `createTextNode`
- `Content-Type: application/json`

### 2. `stored_xss_check` — Stored XSS (CWE-79)

Detects database/store reads rendered unsafely in templates or DOM.

**Patterns detected:**
- DB result → template `|safe` / `innerHTML` within ±10 lines
- ORM model fields in unsafe template contexts
- Markdown/rich text rendered as raw HTML (`markdown.markdown()` + `|safe`)
- User uploads served as `text/html`

**Safe exclusions:**
- `bleach.clean`, `DOMPurify`, output encoding, JSON-only APIs

### 3. `dom_xss_check` — DOM-based XSS (CWE-79)

Detects JavaScript/TypeScript source→sink data flows.

**Sources:** `location.hash/search/href`, `document.URL/referrer`, `window.name`, `postMessage`, `URLSearchParams`

**Sinks:** `.innerHTML`, `.outerHTML`, `document.write/ln()`, `eval()`, `setTimeout/setInterval(string)`, `new Function()`, `$.html()`, `insertAdjacentHTML()`, `v-html`, `[innerHTML]`

**Safe exclusions:**
- `textContent`, `innerText`, `DOMPurify.sanitize`, `createTextNode`, `encodeURIComponent`

**Scope:** Only scans `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.vue`, `.svelte` files.

### 4. `template_injection_check` — SSTI / Template XSS (CWE-1336)

Detects server-side template injection patterns.

**Patterns detected:**
- Jinja2: `Template(user_input)`, `from_string(user_input)`
- Django: `Template(user_input).render()`
- Handlebars: triple-stache `{{{var}}}`, `compile(user_input)`
- EJS: `ejs.render(user_input)`, `ejs.compile(user_input)`
- Go: `template.HTML(user_input)`, dynamic `template.Parse()`

**Safe exclusions:**
- Static template files: `render_template("file.html")`, `get_template("file.html")`
- Hardcoded strings in Template()

### 5. `header_injection_check` — Header Injection (CWE-113/CWE-644)

Detects HTTP header injection and missing security headers.

**Patterns detected:**
- User input in `Content-Type`, `Content-Disposition`, `Location` headers
- Missing/weak CSP: `unsafe-inline`, `unsafe-eval`, wildcards
- Meta refresh with user-controlled URLs

**Safe exclusions:**
- `nonce-`, `strict-dynamic`, validated/sanitized input

## Finding Format

All findings follow the ticket-ready format:

```python
{
    "severity": "critical|high|medium|low|info",
    "category": "CWE-79|CWE-113|CWE-644|CWE-1336",
    "title": "Short descriptive title",
    "description": "Detailed description with line number and data flow",
    "file_path": "/absolute/path/to/file",
    "line_start": 42,
    "line_end": 42,
    "recommendation": "Specific fix with function names",
}
```

## CWE Coverage

| CWE ID | Name | Skills |
|--------|------|--------|
| CWE-79 | Cross-site Scripting | reflected, stored, dom |
| CWE-113 | HTTP Response Splitting | header_injection |
| CWE-644 | Improper Neutralization of HTTP Headers | header_injection |
| CWE-1336 | Improper Neutralization of Special Elements in Template Engine | template_injection |
