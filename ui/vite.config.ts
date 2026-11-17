import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dev server proxies API and WebSocket calls to the Rust backend,
// so `npm run dev` (hot reload, :5173) and `cargo run` (:8080) work
// side by side. Production embeds dist/ into the binary instead.
//
// If the backend runs with `[tls].enabled` (HTTPS only, no plain-HTTP
// listener), start the dev server with LIZARD_BACKEND=https://127.0.0.1:8080.
// `secure: false` lets the proxy accept the backend's certificate, which is
// issued by lizard's own (locally untrusted) root.
const backend = process.env.LIZARD_BACKEND ?? "http://127.0.0.1:8080";
const wsBackend = backend.replace(/^http/, "ws");

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: backend, changeOrigin: true, secure: false },
      "/ws": { target: wsBackend, ws: true, secure: false },
    },
  },
  test: {
    environment: "jsdom",
    environmentOptions: {
      jsdom: { url: "http://localhost:3000/" },
    },
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
  },
});
