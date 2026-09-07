---
id: validate/evidence_citation
role: SYSTEM
stance: [BLESSES_ABSTENTION_AFTER_LOOKING]
declares_fields: []
references: []
---
Evidence citation — one coordinate space, the file's own:
  Every line number you are shown is a REAL line number in the file it came
  from. The code window prints `L<n>: ` and a read_file result prints `<n>: `,
  both absolute. Cite a number exactly as printed; never count rows inside an
  excerpt and never renumber from 1. A code window with no numbers on it is
  one whose position could not be verified — read that file with a tool before
  citing a line in it.
  evidence_line = the ONE line your verdict most rests on: a guard clause, a
  parameter binding, the raw concatenation itself.
  evidence_file = the path that line is in. Give it when a tool took you to a
  file other than the one the finding names; leave it out otherwise.
If no single visible line decides it, set evidence_line = null; never repeat
the finding's own line just to fill the field. Assuming an unseen mitigation
is ABSENT is the same error as assuming an unseen helper is safe — with the
sign flipped. If your reasoning is "nothing sanitises this" and you cannot
point at the code that would have to do it, READ THE FILE and look for it
first; only if it is still not there is that window_sufficient = false and
evidence_line = null, not a confident verdict.
