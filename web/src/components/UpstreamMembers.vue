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
  <div class="upstream-members">
    <div v-for="(row, index) in rows" :key="index" class="upstream-member">
      <div class="member-address"><EndpointInput v-model:value="row.address" :disabled="disabled" @update:value="update" /></div>
      <label
        >权重<n-input-number
          v-model:value="row.weight"
          :min="1"
          :max="256"
          :disabled="disabled"
          @update:value="update"
      /></label>
      <label
        >失败次数<n-input-number
          v-model:value="row.maxFails"
          :min="0"
          :max="100"
          :disabled="disabled"
          @update:value="update"
      /></label>
      <label
        >重试间隔<UnitInput v-model:value="row.failTimeout" kind="time" :disabled="disabled" @update:value="update" /></label>
      <label class="member-backup"
        >备用<n-switch
          v-model:value="row.backup"
          :disabled="disabled"
          @update:value="update"
      /></label>
      <n-button :disabled="disabled" @click="remove(index)">移除</n-button>
    </div>
    <n-button
      :disabled="disabled || rows.length >= 128"
      @click="rows.push(blank())"
      >添加后端</n-button
    >
  </div>
</template>

<style scoped>
.upstream-members {
  width: 100%;
  display: grid;
  gap: 12px;
}
.upstream-member {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr)) auto auto;
  gap: 10px;
  align-items: end;
  padding: 14px;
  background: var(--surface-soft, rgba(128, 128, 128, 0.05));
  border-radius: 10px;
}
.member-address { grid-column: 1 / -1; }
label {
  display: grid;
  gap: 6px;
  font-size: 13px;
}
.member-backup {
  align-self: center;
}
@media (max-width: 1000px) {
  .upstream-member {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .member-address {
    grid-column: 1 / -1;
  }
}
</style>
