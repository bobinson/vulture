import { Link, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";

const TITLES: Record<string, string> = {
  "/": "dashboard.title",
  "/audit": "audit.title",
  "/memories": "memories.title",
  "/settings": "settings.title",
};

export function Header() {
  const location = useLocation();
  const { t } = useTranslation();

  const segments = location.pathname.split("/").filter(Boolean);
  const titleKey = TITLES[location.pathname] ?? (
    segments.length > 1 && segments[0] === "audit" ? "results.title" : "app.name"
  );

  const crumbs = [{ label: t("nav.home"), path: "/" }];
  if (segments.length > 0) {
    if (segments[0] === "audit") {
      crumbs.push({ label: t("nav.audit"), path: "/audit" });
      if (segments[1]) {
        crumbs.push({
          label: segments[1].slice(0, 8) + "...",
          path: `/audit/${segments[1]}`,
        });
      }
    } else if (segments[0] === "memories") {
      crumbs.push({ label: t("nav.memories"), path: "/memories" });
    } else if (segments[0] === "settings") {
      crumbs.push({ label: t("nav.settings"), path: "/settings" });
    }
  }

  return (
    <header className="mb-6" data-testid="header">
      {/* Breadcrumbs — subtle, Linear-style */}
      <nav className="flex items-center gap-1 text-[12px] text-muted-light mb-1.5">
        {crumbs.map((crumb, i) => (
          <span key={crumb.path} className="flex items-center gap-1">
            {i > 0 && <span className="text-border-dark select-none">/</span>}
            <Link
              to={crumb.path}
              className="hover:text-foreground transition-colors duration-100"
            >
              {crumb.label}
            </Link>
          </span>
        ))}
      </nav>

      {/* Title — bold, tight tracking like Linear */}
      <h1 className="text-[22px] font-semibold text-foreground tracking-[-0.02em] leading-tight">
        {t(titleKey)}
      </h1>
    </header>
  );
}
