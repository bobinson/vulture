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
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: devPort,
    proxy: {
      "/api": backendURL,
      "/health": backendURL,
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
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          i18n: ["react-i18next", "i18next", "i18next-browser-languagedetector"],
        },
      },
    },
  },
});
