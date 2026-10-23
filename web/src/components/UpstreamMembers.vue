<script setup lang="ts">
import { ref, watch } from "vue";
import { NButton, NInput, NInputNumber, NSwitch } from "naive-ui";
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
      <label class="member-address"
        >后端地址<n-input
          v-model:value="row.address"
          placeholder="127.0.0.1:3000 或 app.example.com:80"
          :disabled="disabled"
          @update:value="update"
      /></label>
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
        >重试间隔<n-input
          v-model:value="row.failTimeout"
          placeholder="10s"
          :disabled="disabled"
          @update:value="update"
      /></label>
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
  grid-template-columns: minmax(180px, 2fr) repeat(
      3,
      minmax(95px, 1fr)
    ) auto auto;
  gap: 10px;
  align-items: end;
  padding: 14px;
  background: var(--surface-soft, rgba(128, 128, 128, 0.05));
  border-radius: 10px;
}
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
