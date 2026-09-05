---
id: validate/evidence_citation
role: SYSTEM
stance: [BLESSES_ABSTENTION_AFTER_LOOKING]
declares_fields: []
references: [numbered_snippet]
---
Evidence citation:
  evidence_line = the ONE line number (from the numbered snippet) your
  verdict most rests on. Cite the line that DECIDES it — a guard clause,
  a parameter binding, the raw concatenation itself. If no single visible
  line decides it, set evidence_line = null; never repeat the finding's
  own line just to fill the field. Assuming an unseen mitigation is ABSENT
  is the same error as assuming an unseen helper is safe — with the sign
  flipped. If your reasoning is "nothing sanitises this" and you cannot
  point at the code that would have to do it, READ THE FILE and look for it
  first; only if it is still not there is that window_sufficient = false and
  evidence_line = null, not a confident verdict.
