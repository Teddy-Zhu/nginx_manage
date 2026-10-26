<script setup lang="ts">
import { ref, watch } from "vue";
import UnitInput from "./UnitInput.vue";
import EndpointInput from "./EndpointInput.vue";
import { NButton, NInputNumber, NSwitch } from "naive-ui";
const props = defineProps<{ value: string; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
type Member = {
  address: string;
  weight: number | null;
  maxFails: number | null;
  failTimeout: string;
  backup: boolean;
};
const blank = (): Member => ({
  address: "",
  weight: 1,
  maxFails: 1,
  failTimeout: "",
  backup: false,
});
const rows = ref<Member[]>([]);
function text() {
  return rows.value
    .filter((row) => row.address.trim())
    .map((row) =>
      [
        row.address.trim(),
        `weight=${row.weight ?? 1}`,
        `max_fails=${row.maxFails ?? 1}`,
        row.failTimeout ? `fail_timeout=${row.failTimeout}` : "",
        row.backup ? "backup" : "",
      ]
        .filter(Boolean)
        .join(" "),
    )
    .join("\n");
}
watch(
  () => props.value,
  (value) => {
    if (value === text()) return;
    rows.value = value
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => {
        const [address = "", ...options] = line.trim().split(/\s+/);
        const row = { ...blank(), address };
        for (const option of options) {
          const [key, value] = option.split("=");
          if (key === "weight") row.weight = Number(value);
          if (key === "max_fails") row.maxFails = Number(value);
          if (key === "fail_timeout") row.failTimeout = value ?? "";
          if (key === "backup") row.backup = true;
        }
        return row;
      });
  },
  { immediate: true },
);
function update() {
  emit("update:value", text());
}
function remove(index: number) {
  rows.value.splice(index, 1);
  update();
}
</script>

<template>
  <div class="field-list">
    <div v-for="(row, index) in rows" :key="index" class="upstream-member field-row">
      <div class="member-address"><EndpointInput v-model:value="row.address" :disabled="disabled" @update:value="update" /></div>
      <label class="field-label"
        >权重<n-input-number
          v-model:value="row.weight"
          :min="1"
          :max="256"
          :disabled="disabled"
          @update:value="update"
      /></label>
      <label class="field-label"
        >失败次数<n-input-number
          v-model:value="row.maxFails"
          :min="0"
          :max="100"
          :disabled="disabled"
          @update:value="update"
      /></label>
      <label class="field-label member-interval"
        >重试间隔<UnitInput v-model:value="row.failTimeout" kind="time" :disabled="disabled" @update:value="update" /></label>
      <label class="field-label member-backup"
        >备用<span class="field-toggle"><n-switch
          v-model:value="row.backup"
          :disabled="disabled"
          @update:value="update"
      /></span></label>
      <n-button class="member-remove" attr-type="button" :disabled="disabled" @click="remove(index)">移除</n-button>
    </div>
    <n-button
      class="field-add"
      attr-type="button"
      dashed
      :disabled="disabled || rows.length >= 128"
      @click="rows.push(blank())"
      >添加后端</n-button
    >
  </div>
</template>

<style scoped>
.upstream-member {
  grid-template-columns: minmax(88px, 1fr) minmax(100px, 1fr) minmax(180px, 1.4fr) 56px auto;
  padding: 16px;
  background: var(--surface-soft);
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.member-address { grid-column: 1 / -1; }
@container (max-width: 680px) {
  .upstream-member {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .member-interval { grid-column: 1 / -1; }
}
</style>
