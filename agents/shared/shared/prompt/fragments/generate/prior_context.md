---
id: generate/prior_context
role: USER
# `keep_trailing`: the substituted value is the LAST thing in this fragment and
# the live builder never strips it — `_build_llm_prompt` puts the block in a
# plain `"\n".join(parts)`, so whatever newlines the memory summary ends with
# are prompt bytes. Without this the renderer would drop them.
keep_trailing: true
---
Context from prior audits:
{prior_context}