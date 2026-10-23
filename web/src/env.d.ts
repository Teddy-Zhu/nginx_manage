/// <reference types="vite/client" />
/// <reference types="vue-router/auto-routes" />

import "vue-router";

declare module "vue-router" {
  interface RouteMeta {
    public?: boolean;
    localOnly?: boolean;
    title?: string;
    subtitle?: string;
    nav?: boolean;
    order?: number;
    symbol?: string;
    group?: string;
    parent?: string;
    software?: "nginx" | "fail2ban";
  }
}
