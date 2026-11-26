import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const repositoryName = process.env.GITHUB_REPOSITORY?.split("/")[1];

export default defineConfig({
  base: process.env.VITE_BASE_PATH || (process.env.GITHUB_ACTIONS && repositoryName ? `/${repositoryName}/` : "/"),
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:3001",
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("/node_modules/reactflow/")) return "relationship-graph";
          if (id.includes("/node_modules/recharts/") || id.includes("/node_modules/d3-")) return "charts";
          if (/\/node_modules\/(react|react-dom|scheduler)\//.test(id)) return "react-vendor";
        },
      },
    },
  },
});
