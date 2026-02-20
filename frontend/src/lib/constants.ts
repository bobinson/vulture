export const ROUTES = {
  DASHBOARD: "/",
  AUDIT: "/audit",
  AUDIT_RESULTS: (id: string) => `/audit/${id}`,
  MEMORIES: "/memories",
  SETTINGS: "/settings",
} as const;

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};


export const AGENT_TYPES = ["chaos", "owasp", "soc2"] as const;

/** Resolve agent type to i18n display name with fallback to capitalized raw key */
export function agentLabel(type: string, t: (key: string) => string): string {
  const key = `agents.${type}`;
  const label = t(key);
  return label === key ? type.charAt(0).toUpperCase() + type.slice(1) : label;
}

