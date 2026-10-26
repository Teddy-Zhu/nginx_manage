import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import AutoImport from "unplugin-auto-import/vite";
import Components from "unplugin-vue-components/vite";
import { NaiveUiResolver } from "unplugin-vue-components/resolvers";
import { VueRouterAutoImports } from "vue-router/unplugin";
import VueRouter from "vue-router/vite";
import { routeOptions } from "./routing.config.ts";

export default defineConfig({
  plugins: [
    VueRouter(routeOptions),
    vue(),
    AutoImport({
      imports: ["vue", "pinia", VueRouterAutoImports],
      dts: "src/auto-imports.d.ts",
    }),
    Components({ resolvers: [NaiveUiResolver()], dts: "src/components.d.ts" }),
  ],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:8080", ws: true } },
  },
  build: { sourcemap: false },
});
