---
id: core/language
# Feature 0089 item 4.8, LLD rule 9: admitted only where the model profile's
# `output_language_pin` is set — qwen, glm, kimi and seed, whose measured
# failure is answering in Chinese under pressure (LLD §2, "language drift").
# `render._rule_language` drops it for the other six families, so a model that
# does not drift is not spent budget telling it not to.
#
# ONE clause, in every prompt that emits free text, rather than a sentence per
# tier: `check_12_language_pin` fired on eighteen specs because no fragment in
# the library carried this stance at all, and a policy transcribed into four
# tiers is four places it can drift from the next fix.
#
# role: SYSTEM, not SYSTEM+USER_MIRROR. Rule 2 mirrors what the RESPONSE
# STRUCTURE depends on — the output contract, the distrust policy — because a
# gateway that silently drops the system turn drops those unrecoverably. A
# dropped language pin degrades to the behaviour of the day before this
# fragment existed, which is a strictly smaller loss, and mirroring would
# spend a second copy of the clause in the user turn of every spec that lists
# it.
#
# The quotation exception is load-bearing, not politeness: feature 0076 checks
# `evidence_quote` by searching the cited file for those bytes, so a model
# told to write everything in English without it would translate its own
# evidence and every quote would verify as `absent`.
role: SYSTEM
stance: [BINDS_LANGUAGE]
declares_fields: []
references: []
---
OUTPUT LANGUAGE. Write English. Every free-text field you emit — a title, a
description, a recommendation, a reason — is English, whatever language the
code you are reading, its comments and its identifiers are written in.

Quoted material is the exception and is never translated: an identifier, a
path, a line of source or an error string you cite is copied exactly as it
appears. A translated quotation no longer matches the file it came from, so
it stops being evidence.