// cited.ts -- 0076 AC31. The model cited THIS file. Its quote is real code,
// but it lives in the sibling module. found_elsewhere is NON-DEMOTING, and
// it must never rewrite file_path: the candidate goes in other_path only.
export function renderHeader(title: string) {
  return "<h1>" + escapeHtml(title) + "</h1>";
}
