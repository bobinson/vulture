import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

// VULTURE_PROXY_TARGET is server-side only (not leaked to the browser bundle).
// VITE_API_URL is kept as fallback for backwards-compat / production builds.
const backendURL =
  process.env.VULTURE_PROXY_TARGET ??
  process.env.VITE_API_URL ??
  "http://localhost:28080";
const devPort = parseInt(process.env.VITE_DEV_PORT ?? "23000", 10);

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "src"),
    },
  },
  server: {
    // Loopback only. This server proxies /api to a backend that, in local
    // mode, serves the local user without a password; on 0.0.0.0 that handed
    // the whole API to anyone on the network. IPv4 rather than "localhost" so
    // the bind is the same on every OS (macOS resolves localhost to ::1 first;
    // browsers and tools fall back to 127.0.0.1).
    host: "127.0.0.1",
    port: devPort,
    // Fail if the port is taken instead of quietly moving to the next one,
    // which left a stale — possibly outdated — server answering on the port.
    strictPort: true,
    // xfwd: record each client's address (X-Forwarded-For) so the backend can
    // refuse a request relayed for another machine even if this server is
    // ever exposed again (e.g. `npm run dev -- --host`).
    proxy: {
      // SSE audit streams stay open for the full length of an audit — a slow
      // local model (LM Studio/Ollama) can run well past 10 minutes. The dev
      // proxy's default socket timeouts would tear the stream down mid-audit,
      // cancelling the backend request context ("context canceled"). Disable
      // both timeouts (0 = no timeout) so the proxy holds the stream open for
      // as long as the backend does. Dev-only; production serves the built SPA
      // without this proxy.
      "/api": { target: backendURL, timeout: 0, proxyTimeout: 0, xfwd: true },
      "/health": {
        target: backendURL,
        timeout: 0,
        proxyTimeout: 0,
        xfwd: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split vendor code into stable, cache-friendly chunks. React +
        // router seldom change between releases; i18n only loads when
        // the user changes language. Splitting keeps the main bundle
        // small and lets the browser cache vendor chunks across deploys
        // when only application code changed.
        //
        // Function form (vite 8 / rollup narrowed `manualChunks` to a
        // ManualChunksFunction; the object-map form no longer type-checks).
        // Match i18n FIRST so `react-i18next` lands in the i18n chunk, not react.
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/[\\/]node_modules[\\/](react-i18next|i18next|i18next-browser-languagedetector)[\\/]/.test(id)) {
            return "i18n";
          }
          if (/[\\/]node_modules[\\/](react-router-dom|react-router|react-dom|react)[\\/]/.test(id)) {
            return "react";
          }
          return undefined;
        },
      },
    },
  },
});
