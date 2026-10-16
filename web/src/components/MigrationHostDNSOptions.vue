<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { NAlert, NFormItem, NInput, NSelect } from "naive-ui";
import type { MigrationHostDNSInput } from "../api/client";
const props = withDefaults(
  defineProps<{
    modelValue: MigrationHostDNSInput;
    disabled?: boolean;
    allowMap?: boolean;
  }>(),
  { allowMap: true },
);
const emit = defineEmits<{
  "update:modelValue": [value: MigrationHostDNSInput];
  "update:valid": [value: boolean];
}>();
const text = ref(JSON.stringify(props.modelValue.mappings ?? {}, null, 2));
const error = ref("");
let canonical = JSON.stringify(props.modelValue.mappings ?? {});
const options = computed(() => [
  { label: "保留目标主机 DNS", value: "preserve" },
  { label: "映射并保存 DNS 迁移材料", value: "map", disabled: !props.allowMap },
]);
watch(
  () => props.modelValue.mappings,
  (value) => {
    const next = JSON.stringify(value ?? {});
    if (canonical !== next) {
      canonical = next;
      text.value = JSON.stringify(value ?? {}, null, 2);
      error.value = "";
      emit("update:valid", true);
    }
  },
);
function setMode(mode: MigrationHostDNSInput["mode"]) {
  text.value = canonical = "{}";
  error.value = "";
  emit("update:modelValue", { mode, mappings: {} });
  emit("update:valid", true);
}
function setMapping(value: string) {
  text.value = value;
  try {
    const mapping: unknown = JSON.parse(value);
    if (
      !mapping ||
      typeof mapping !== "object" ||
      Array.isArray(mapping) ||
      Object.keys(mapping).length > 64 ||
      Object.values(mapping).some(
        (item) =>
          !item ||
          typeof item !== "object" ||
          Array.isArray(item) ||
          typeof item.target !== "string" ||
          Object.keys(item).some((key) => !["target", "config"].includes(key)),
      )
    )
      throw new Error();
    const mappings = mapping as NonNullable<MigrationHostDNSInput["mappings"]>;
    canonical = JSON.stringify(mappings);
    error.value = "";
    emit("update:modelValue", { ...props.modelValue, mappings });
    emit("update:valid", true);
  } catch {
    error.value = "请输入源目标到 {target, config?} 的 JSON 映射，最多 64 项";
    emit("update:valid", false);
  }
}
</script>
<template>
  <div>
    <NFormItem label="主机 DNS 迁入方式">
      <NSelect
        :value="modelValue.mode"
        :options="options"
        :disabled="disabled"
        @update:value="setMode"
      />
    </NFormItem>
    <template v-if="modelValue.mode === 'map'">
      <NFormItem
        label="DNS 目标映射"
        :validation-status="error ? 'error' : undefined"
        :feedback="error"
      >
        <NInput
          :value="text"
          type="textarea"
          :autosize="{ minRows: 3, maxRows: 10 }"
          :disabled="disabled"
          placeholder='{"":{"target":""}}'
          @update:value="setMapping"
        />
      </NFormItem>
      <NAlert type="warning"
        >每个源目标须明确映射；空目标表示受管
        resolv.conf，连接目标使用目标节点的连接与网卡标识。跨配置类型或带接口区域的地址须提供目标
        config。迁移保存材料后，须在目标生成 DNS 计划并确认。</NAlert
      >
    </template>
  </div>
</template>
