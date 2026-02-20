import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar.tsx";
import { Header } from "./Header.tsx";

const COLLAPSE_KEY = "vulture_sidebar_pinned";

export function Layout() {
  const [pinned, setPinned] = useState(() => {
    const stored = localStorage.getItem(COLLAPSE_KEY);
    return stored === null ? true : stored === "true";
  });

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === COLLAPSE_KEY) setPinned(e.newValue === "true");
    };
    window.addEventListener("storage", onStorage);

    const onPinChange = () => setPinned(localStorage.getItem(COLLAPSE_KEY) === "true");
    window.addEventListener("sidebar-pin-change", onPinChange);

    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("sidebar-pin-change", onPinChange);
    };
  }, []);

  return (
    <div className="min-h-screen bg-cream">
      <Sidebar />
      <main
        className={`min-h-screen px-8 py-6 transition-[margin-left] duration-200 ease-in-out ${pinned ? "ml-[220px]" : "ml-[52px]"}`}
        data-testid="main-content"
      >
        <Header />
        <Outlet />
      </main>
    </div>
  );
}
