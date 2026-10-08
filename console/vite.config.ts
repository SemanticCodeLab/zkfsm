import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

// Fixed asset names: the Zig server embeds dist/ by name (console/assets.zig).
export default defineConfig({
  plugins: [preact()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: (info) => (info.names?.[0]?.endsWith(".css") ? "app.css" : "[name][extname]"),
        inlineDynamicImports: true,
      },
    },
  },
  server: { proxy: { "/api": "http://127.0.0.1:9001" } },
  test: { environment: "happy-dom", include: ["src/**/*.test.ts", "src/**/*.test.tsx"] },
});
