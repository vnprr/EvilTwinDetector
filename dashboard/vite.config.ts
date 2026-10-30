import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173 },
  build: {
    rollupOptions: {
      // Keep the charting library in its own cacheable chunk.
      output: { manualChunks: { charts: ["recharts"] } },
    },
  },
  test: { environment: "jsdom" },
});
