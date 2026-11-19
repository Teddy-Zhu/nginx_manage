<script setup lang="ts">
import { NTag } from "naive-ui";
withDefaults(
  defineProps<{
    name: string;
    description: string;
    category: string;
    status: string;
    statusType?: "default" | "success" | "warning" | "error" | "info";
    accent?: "green" | "blue" | "amber";
  }>(),
  { statusType: "default", accent: "green" },
);
</script>
<template>
  <article class="store-card">
    <div class="store-card-heading">
      <span class="store-card-icon" :class="accent" aria-hidden="true">{{
        name.trim().slice(0, 1).toUpperCase()
      }}</span>
      <div class="store-card-title">
        <h3>{{ name }}</h3>
        <span class="muted">{{ category }}</span>
      </div>
      <NTag :type="statusType" :bordered="false" size="small">
        {{
          status
        }}
      </NTag>
    </div>
    <p class="store-card-description">
      {{ description }}
    </p>
    <div class="store-card-meta">
      <slot />
    </div>
    <div class="store-card-actions">
      <slot name="actions" />
    </div>
  </article>
</template>
<style scoped>
.store-card {
  display: flex;
  flex-direction: column;
  min-width: 0;
  padding: 22px;
  gap: 18px;
  border: 1px solid var(--border-color);
  border-radius: 14px;
  background: var(--bg-surface);
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}
.store-card:hover,
.store-card:focus-within {
  border-color: #b0d4c5;
  box-shadow: 0 4px 16px #1b644908;
}
.store-card-heading {
  display: flex;
  align-items: center;
  gap: 12px;
}
.store-card-heading :deep(.n-tag) {
  flex-shrink: 0;
}
.store-card-title {
  min-width: 0;
  flex: 1;
}
.store-card-title h3 {
  font-size: 16px;
  overflow-wrap: anywhere;
  margin-bottom: 3px;
}
.store-card-icon {
  display: grid;
  place-items: center;
  flex: 0 0 46px;
  height: 46px;
  border-radius: 12px;
  font-size: 24px;
  font-weight: 700;
}
.green {
  background: #e9f5ef;
  color: #078260;
}
.blue {
  background: #ebf1fc;
  color: #4369ad;
}
.amber {
  background: #fcf2df;
  color: #a47725;
}
.store-card-description {
  min-height: 44px;
  color: var(--text-muted);
  line-height: 1.7;
  overflow-wrap: anywhere;
}
.store-card-meta {
  min-height: 22px;
  color: var(--text-muted);
  font-size: 12px;
  overflow-wrap: anywhere;
}
.store-card-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
}
</style>
