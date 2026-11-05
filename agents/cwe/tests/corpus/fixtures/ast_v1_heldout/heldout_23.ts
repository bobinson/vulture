// held-out heldout_23 (CWE-78): RegExp.exec of a module-level global pattern in a while loop over a text parameter
const LINK_PATTERN = /\[([^\]]+)\]\(([^)]+)\)/g;

export function collectLinks(text: string): { links: TextLink[]; plain: string } {
  const links: TextLink[] = [];

  LINK_PATTERN.lastIndex = 0;

  let match: RegExpExecArray | null;
  while ((match = LINK_PATTERN.exec(text)) !== null) {
    links.push({
      text: match[1],
      target: match[2],
    });
  }

  const plain = text.replace(LINK_PATTERN, "$1");

  return { links, plain };
}

export interface TextLink {
  text: string;
  target: string;
}
