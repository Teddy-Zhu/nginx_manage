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
  details: boolean;
};
const blank = (): Member => ({
  address: "",
  weight: 1,
  maxFails: 1,
  failTimeout: "",
  backup: false,
  details: false,
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
        row.details =
          row.weight !== 1 ||
          row.maxFails !== 1 ||
          !!row.failTimeout ||
          row.backup;
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
    <div v-for="(row, index) in rows" :key="index" class="upstream-member">
      <div class="member-heading">
        <div>
          <strong>服务器 {{ index + 1 }}</strong><span v-if="!row.details" class="section-note">权重 {{ row.weight ?? 1 }}{{ row.backup ? " · 备用" : "" }}</span>
        </div>
        <n-button
          size="small"
          attr-type="button"
          :disabled="disabled"
          :aria-label="`移除服务器 ${index + 1}`"
          @click="remove(index)"
        >
          移除
        </n-button>
      </div>
      <EndpointInput
        v-model:value="row.address"
        :disabled="disabled"
        @update:value="update"
      />
      <div class="member-heading">
        <n-button
          text
          attr-type="button"
          :aria-expanded="row.details"
          @click="row.details = !row.details"
        >
          {{ row.details ? "收起负载与重试设置" : "负载与重试设置" }}
        </n-button>
      </div>
      <div v-show="row.details" class="member-options field-row">
        <label class="field-label">权重<n-input-number
          v-model:value="row.weight"
          :min="1"
          :max="256"
          :disabled="disabled"
          @update:value="update"
        /></label>
        <label class="field-label">失败次数<n-input-number
          v-model:value="row.maxFails"
          :min="0"
          :max="100"
          :disabled="disabled"
          @update:value="update"
        /></label>
        <label class="field-label member-interval">重试间隔<UnitInput
          v-model:value="row.failTimeout"
          kind="time"
          :disabled="disabled"
          @update:value="update"
        /></label>
        <label class="field-label member-backup">备用<span class="field-toggle"><n-switch
          v-model:value="row.backup"
          :disabled="disabled"
          @update:value="update"
        /></span></label>
      </div>
    </div>
    <n-button
      class="field-add"
      attr-type="button"
      dashed
      :disabled="disabled || rows.length >= 128"
      @click="rows.push(blank())"
    >
      ＋ 添加服务器
    </n-button>
  </div>
</template>

<style scoped>
.upstream-member {
  display: grid;
  gap: 16px;
  min-width: 0;
  padding: 16px;
  background: var(--surface-soft);
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.member-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.member-heading > div {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 16px;
}
.member-options {
  grid-template-columns: minmax(80px, 1fr) minmax(100px, 1fr) minmax(
      180px,
      1.4fr
    ) 56px;
}
@container (max-width: 680px) {
  .member-options {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .member-interval {
    grid-column: 1 / -1;
  }
}
</style>
