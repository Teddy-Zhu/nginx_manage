<script setup lang="ts">
import { computed, ref, watch, toRaw } from "vue";
import { NAlert, NButton, NFormItem, NSelect, NSwitch } from "naive-ui";
import type { MigrationHostDNSInput } from "../api/client";
import ValueListInput from "./ValueListInput.vue";
import DNSTargetInput from "./DNSTargetInput.vue";
import { cleanList } from "../utils/form";
const props = withDefaults(defineProps<{ modelValue: MigrationHostDNSInput; disabled?: boolean; allowMap?: boolean }>(), { allowMap: true });
const emit = defineEmits<{ "update:modelValue": [value: MigrationHostDNSInput]; "update:valid": [value: boolean] }>();
type Mappings = NonNullable<MigrationHostDNSInput["mappings"]>;
type Config = NonNullable<Mappings[string]["config"]>;
type DNSRow = { source: string; target: string; override: boolean; config: Config };
const rows = ref<DNSRow[]>([]), error = ref("");
const options = computed(() => [{ label: "保留目标主机 DNS", value: "preserve" }, { label: "迁移 DNS 配置", value: "map", disabled: !props.allowMap }]);
const connectionDNS = (target: string) => !!target && !target.startsWith("networkd:");
const validTarget = (target: string) => !target || /^(networkd:[a-zA-Z0-9_.:-]{1,15}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}@[a-zA-Z0-9_.:-]{1,15})$/.test(target);
const emptyConfig = (): Config => ({ servers: [], search: [], ipv4: null, ipv6: null });
const familyKeys = ["ipv4", "ipv6"] as const;
let canonical = "";
watch(() => props.modelValue.mappings, (value) => {
  const next = JSON.stringify(value ?? {});
  if (next === canonical) return;
  canonical = next;
  rows.value = Object.entries(value ?? {}).map(([source, item]) => ({ source, target: item.target, override: !!item.config, config: item.config ? structuredClone(toRaw(item.config)) : emptyConfig() }));
  error.value = ""; emit("update:valid", true);
}, { immediate: true });
function setMode(mode: MigrationHostDNSInput["mode"]) {
  rows.value = []; canonical = "{}"; error.value = "";
  emit("update:modelValue", { mode, mappings: {} }); emit("update:valid", true);
}
function toggleFamily(row: DNSRow, key: "ipv4" | "ipv6", enabled: boolean) {
  row.config[key] = enabled ? { servers: [], search: [], automatic: false } : null; update();
}
function update() {
  try {
    const mappings: Mappings = Object.create(null);
    for (const row of rows.value) {
      const source = row.source.trim(), target = row.target.trim();
      if (!validTarget(source) || !validTarget(target)) throw new Error("请填写完整的连接 UUID 和网卡名称");
      if (Object.hasOwn(mappings, source)) throw new Error("来源 DNS 不能重复");
      const config = row.override ? {
        servers: connectionDNS(target) ? [] : cleanList(row.config.servers), search: connectionDNS(target) ? [] : cleanList(row.config.search),
        ipv4: connectionDNS(target) && row.config.ipv4 ? { ...row.config.ipv4, servers: cleanList(row.config.ipv4.servers), search: cleanList(row.config.ipv4.search) } : null,
        ipv6: connectionDNS(target) && row.config.ipv6 ? { ...row.config.ipv6, servers: cleanList(row.config.ipv6.servers), search: cleanList(row.config.ipv6.search) } : null,
      } : undefined;
      mappings[source] = { target, ...(config ? { config } : {}) };
    }
    canonical = JSON.stringify(mappings); error.value = "";
    emit("update:modelValue", { ...props.modelValue, mappings }); emit("update:valid", true);
  } catch (cause) { error.value = (cause as Error).message; emit("update:valid", false); }
}
function add() {
  rows.value.push({ source: "", target: "", override: false, config: emptyConfig() }); update();
}
function remove(index: number) { rows.value.splice(index, 1); update(); }
</script>
<template>
  <div>
    <NFormItem label="主机 DNS 迁入方式"><NSelect :value="modelValue.mode" :options="options" :disabled="disabled" @update:value="setMode" /></NFormItem>
    <div v-if="modelValue.mode === 'map'" class="dns-mappings">
      <div v-for="(row, index) in rows" :key="index" class="dns-mapping">
        <div class="mapping-targets">
          <NFormItem label="来源 DNS"><DNSTargetInput v-model:value="row.source" :disabled="disabled" @update:value="update" /></NFormItem>
          <NFormItem label="目标 DNS"><DNSTargetInput v-model:value="row.target" :disabled="disabled" @update:value="update" /></NFormItem>
          <NButton attr-type="button" :disabled="disabled" @click="remove(index)">移除</NButton>
        </div>
        <NFormItem label="自定义目标 DNS 配置"><NSwitch v-model:value="row.override" :disabled="disabled" @update:value="update" /></NFormItem>
        <template v-if="row.override">
          <template v-if="!connectionDNS(row.target)">
          <NFormItem label="DNS 服务器"><ValueListInput v-model:value="row.config.servers" item-label="DNS 地址" :max="3" placeholder="DNS 服务器地址" :disabled="disabled" @update:value="update" /></NFormItem>
          <NFormItem label="搜索域"><ValueListInput v-model:value="row.config.search" item-label="搜索域" :max="6" placeholder="example.com" :disabled="disabled" @update:value="update" /></NFormItem>
          </template>
          <template v-else>
          <template v-for="key in familyKeys" :key="key">
            <NFormItem :label="`单独设置 ${key === 'ipv4' ? 'IPv4' : 'IPv6'}`"><NSwitch :value="!!row.config[key]" :disabled="disabled" @update:value="toggleFamily(row, key, $event)" /></NFormItem>
            <div v-if="row.config[key]" class="family-config">
              <NFormItem label="自动获取 DNS"><NSwitch v-model:value="row.config[key]!.automatic" :disabled="disabled" @update:value="update" /></NFormItem>
              <NFormItem label="DNS 服务器"><ValueListInput v-model:value="row.config[key]!.servers" item-label="DNS 地址" :max="3" placeholder="DNS 服务器地址" :disabled="disabled" @update:value="update" /></NFormItem>
              <NFormItem label="搜索域"><ValueListInput v-model:value="row.config[key]!.search" item-label="搜索域" :max="6" placeholder="example.com" :disabled="disabled" @update:value="update" /></NFormItem>
            </div>
          </template>
          </template>
        </template>
      </div>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NButton attr-type="button" dashed :disabled="disabled || rows.length >= 64" @click="add">＋ 添加 DNS 映射</NButton>
      <NAlert type="warning">请为每个来源设置目标。跨 DNS 类型迁移时，请自定义目标配置。迁移后需在目标 DNS 页面确认应用。</NAlert>
    </div>
  </div>
</template>
<style scoped>
.dns-mappings { display: grid; gap: 14px; margin-bottom: 18px; }
.dns-mapping { border: 1px solid var(--border-color, #e4e7ec); border-radius: 10px; padding: 16px; }
.mapping-targets { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; gap: 12px; align-items: start; }
.mapping-targets > button { margin-top: 26px; }
.family-config { padding-left: 16px; border-left: 2px solid var(--border-color, #e4e7ec); }
.dns-mappings > button { justify-self: start; }
@media (max-width: 680px) { .mapping-targets { grid-template-columns: 1fr; } .mapping-targets > button { margin: 0 0 14px; justify-self: start; } }
</style>
