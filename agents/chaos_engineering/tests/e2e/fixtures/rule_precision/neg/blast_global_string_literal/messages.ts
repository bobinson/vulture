export const HELP_TEXT = "the global default applies when no flag is given";

export function describe(flag: string | undefined): string {
  return flag ? `flag ${flag} overrides the global default` : HELP_TEXT;
}
