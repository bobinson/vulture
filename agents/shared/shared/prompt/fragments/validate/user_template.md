---
id: validate/user_template
role: USER
verbatim: true
# Item 4.7. `verbatim` alone did not keep this template's terminator: `render`
# passes a lone verbatim user fragment through untouched, but the moment a
# MIRRORED fragment is prepended the turn is assembled by `_seam_join`, which
# strips trailing newlines unless they are declared content. The byte IS
# content here — `_render_user_message` sends what `.format()` returned,
# terminator included — so the mirror is what makes this declaration
# load-bearing. Byte-neutral today (TRANSCRIBE takes the verbatim path).
keep_trailing: true
stance: []
declares_fields: []
references: []
---
Audit ID: {audit_id}
Findings to review ({n} in this batch):

{findings_block}
