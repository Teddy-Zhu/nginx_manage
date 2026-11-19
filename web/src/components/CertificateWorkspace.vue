<script setup lang="ts">
import { useRoute } from "vue-router";
const route = useRoute();
const sections = [
  { path: "/certificates", title: "我的证书" },
  { path: "/certificate-requests", title: "申请与续期" },
  { path: "/certificate-deployments", title: "网站证书" },
  { path: "/acme", title: "申请设置" },
];
function destination(path: string) {
  return {
    path,
    query:
      (path === "/certificates" || path === "/certificate-deployments") &&
      typeof route.query.certificate === "string"
        ? { certificate: route.query.certificate }
        : {},
  };
}
</script>

<template>
  <div class="certificate-workspace">
    <nav class="certificate-nav" aria-label="证书管理">
      <router-link
        v-for="section in sections"
        :key="section.path"
        :to="destination(section.path)"
        :class="{ active: route.path === section.path }"
        :aria-current="route.path === section.path ? 'page' : undefined"
      >
        {{ section.title }}
      </router-link>
    </nav>
    <slot />
  </div>
</template>

<style>
.certificate-workspace {
  display: grid;
  gap: 20px;
  min-width: 0;
}
.certificate-nav {
  display: flex;
  gap: 4px;
  overflow-x: auto;
  border-bottom: 1px solid var(--border-color);
}
.certificate-nav a {
  flex-shrink: 0;
  padding: 10px 20px 12px;
  color: var(--text-muted);
  border-bottom: 2px solid transparent;
  font-weight: 500;
}
.certificate-nav a:hover {
  color: #087f68;
  background: var(--surface-soft);
}
.certificate-nav a.active {
  color: #087f68;
  border-color: #087f68;
}
.certificate-workspace .cert-section {
  display: grid;
  gap: 18px;
  min-width: 0;
}
.certificate-workspace .cert-heading {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  flex-wrap: wrap;
}
.certificate-workspace .cert-heading p {
  margin-top: 4px;
}
.certificate-workspace .cert-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.certificate-workspace .cert-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: 24px;
}
.certificate-workspace .cert-form-footer {
  display: flex;
  gap: 12px;
  padding-top: 8px;
  flex-wrap: wrap;
}
.certificate-workspace .cert-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 20px;
}
.certificate-workspace .cert-stats dt {
  color: var(--text-muted);
  font-size: 13px;
}
.certificate-workspace .cert-stats dd {
  margin: 6px 0 0;
  overflow-wrap: anywhere;
}
.certificate-workspace .cert-empty {
  padding: 28px 12px;
}
.certificate-workspace .cert-notice {
  display: grid;
  gap: 10px;
}
.certificate-workspace .cert-record {
  padding: 16px 0;
  border-bottom: 1px solid var(--border-color);
  display: grid;
  gap: 10px;
  overflow-wrap: anywhere;
}
@media (max-width: 700px) {
  .certificate-nav a {
    padding: 10px 12px;
  }
  .certificate-workspace .cert-form-grid,
  .certificate-workspace .cert-stats {
    grid-template-columns: minmax(0, 1fr);
    gap: 16px;
  }
}
</style>
