// paraphrase.ts -- 0076 AC7. The defect on line 5 is REAL. The model's quote
// ("!property === userId") is a PARAPHRASE of it, not a copy of it.
// A verifier that equates 'not found' with 'fabricated' deletes this finding.
export function canEdit(issues_by_pk: Issue | null, userId: string) {
  if(!issues_by_pk?.creatorId === userId) {
    return true;
  }
  return false;
}
