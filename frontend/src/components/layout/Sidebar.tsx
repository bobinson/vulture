import { useCallback, useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ROUTES } from "@/lib/constants.ts";
import { useAuth } from "@/lib/auth.tsx";

const NAV_ITEMS = [
  { path: ROUTES.DASHBOARD, icon: "dashboard", labelKey: "nav.dashboard" },
  { path: ROUTES.AUDIT, icon: "audit", labelKey: "nav.audit" },
  { path: ROUTES.MEMORIES, icon: "memories", labelKey: "nav.memories" },
  { path: "/settings", icon: "settings", labelKey: "nav.settings" },
] as const;

const COLLAPSE_KEY = "vulture_sidebar_pinned";
const COLLAPSE_DELAY = 2000;
const NAV_CLICK_DELAY = 2500;

function NavIcon({ type, className }: { type: string; className?: string }) {
  const cn = className ?? "w-4 h-4";
  switch (type) {
    case "dashboard":
      return (
        <svg className={cn} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      );
    case "audit":
      return (
        <svg className={cn} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      );
    case "memories":
      return (
        <svg className={cn} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
        </svg>
      );
    case "settings":
      return (
        <svg className={cn} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      );
    default:
      return null;
  }
}

export function Sidebar() {
  const [pinned, setPinned] = useState(() => {
    const stored = localStorage.getItem(COLLAPSE_KEY);
    return stored === null ? true : stored === "true";
  });
  const [hovered, setHovered] = useState(false);
  const collapseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { t } = useTranslation();
  const location = useLocation();
  const { user, logout } = useAuth();

  const expanded = pinned || hovered;

  useEffect(() => {
    localStorage.setItem(COLLAPSE_KEY, String(pinned));
    window.dispatchEvent(new Event("sidebar-pin-change"));
  }, [pinned]);

  useEffect(() => {
    return () => {
      if (collapseTimer.current) clearTimeout(collapseTimer.current);
    };
  }, []);

  const handleMouseEnter = useCallback(() => {
    if (collapseTimer.current) {
      clearTimeout(collapseTimer.current);
      collapseTimer.current = null;
    }
    setHovered(true);
  }, []);

  const handleMouseLeave = useCallback(() => {
    if (collapseTimer.current) clearTimeout(collapseTimer.current);
    collapseTimer.current = setTimeout(() => {
      setHovered(false);
      collapseTimer.current = null;
    }, COLLAPSE_DELAY);
  }, []);

  const handleNavClick = useCallback(() => {
    // When unpinned, keep sidebar visible briefly after nav click
    if (!pinned) {
      if (collapseTimer.current) clearTimeout(collapseTimer.current);
      collapseTimer.current = setTimeout(() => {
        setHovered(false);
        collapseTimer.current = null;
      }, NAV_CLICK_DELAY);
    }
  }, [pinned]);

  const togglePin = useCallback(() => {
    setPinned((p) => !p);
  }, []);

  return (
    <aside
      data-testid="sidebar"
      className={`fixed left-0 top-0 h-full bg-surface border-r border-border z-40 flex flex-col transition-all duration-300 ease-in-out ${expanded ? "w-[220px]" : "w-[52px]"}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {/* Logo */}
      <div className="h-[52px] flex items-center justify-between px-4 border-b border-border">
        <div className="flex items-center min-w-0">
          <span className="text-lg font-extrabold tracking-tight text-accent shrink-0">V</span>
          <span
            className={`text-[13px] font-semibold text-foreground overflow-hidden transition-all duration-300 ${expanded ? "ml-0.5 w-[70px] opacity-100" : "w-0 opacity-0"}`}
          >
            ulture
          </span>
        </div>
        <button
          type="button"
          data-testid="sidebar-toggle"
          className={`w-6 h-6 flex items-center justify-center rounded-md text-muted-light hover:text-foreground hover:bg-cream-dark transition-all duration-300 cursor-pointer shrink-0 ${expanded ? "opacity-100" : "opacity-0 w-0 overflow-hidden"}`}
          onClick={togglePin}
          title={pinned ? t("nav.unpin") : t("nav.pin")}
        >
          <svg
            className={`w-3 h-3 transition-transform duration-200 ${pinned ? "rotate-0" : "-rotate-90"}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 flex flex-col gap-px py-2 px-2">
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.path === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.path);
          return (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={handleNavClick}
              className={`flex items-center gap-2.5 h-8 rounded-lg transition-all duration-100 ${
                isActive
                  ? "bg-accent/8 text-accent"
                  : "text-muted hover:bg-cream-dark hover:text-foreground"
              } ${expanded ? "px-2.5" : "justify-center px-0"}`}
            >
              <NavIcon type={item.icon} className={`w-[18px] h-[18px] shrink-0 ${isActive ? "text-accent" : ""}`} />
              <span
                className={`text-[13px] font-medium whitespace-nowrap overflow-hidden transition-all duration-300 ${expanded ? "opacity-100 w-auto" : "opacity-0 w-0"}`}
              >
                {t(item.labelKey)}
              </span>
            </NavLink>
          );
        })}
      </nav>

      {/* User */}
      <div className="border-t border-border px-2 py-2">
        {user && (
          <div
            className={`flex items-center gap-2 transition-all duration-300 ${expanded ? "px-2" : "justify-center"}`}
          >
            <div className="w-7 h-7 rounded-full bg-accent/8 text-accent flex items-center justify-center text-[11px] font-bold shrink-0">
              {user.name.charAt(0).toUpperCase()}
            </div>
            <div
              className={`overflow-hidden transition-all duration-300 ${expanded ? "opacity-100 w-auto" : "opacity-0 w-0"}`}
            >
              <p className="text-[12px] font-medium text-foreground truncate max-w-[130px]">
                {user.name}
              </p>
              <button
                type="button"
                className="text-[11px] text-muted hover:text-danger transition-colors cursor-pointer"
                onClick={logout}
              >
                {t("auth.logout")}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Version */}
      <div
        className={`px-4 py-2.5 border-t border-border text-[11px] text-muted-light transition-opacity duration-300 ${expanded ? "opacity-60" : "opacity-0"}`}
      >
        v1.0.0
      </div>
    </aside>
  );
}
