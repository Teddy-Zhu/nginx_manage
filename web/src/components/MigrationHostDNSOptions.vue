<script setup lang="ts">
import { computed, ref, watch, toRaw, onUnmounted } from "vue";
import { NAlert, NButton, NFormItem, NSelect, NSwitch } from "naive-ui";
import {
  useNodeAPI,
  type HostDNSOverview,
  type MigrationHostDNSInput,
} from "../api/client";
import ValueListInput from "./ValueListInput.vue";
import DNSTargetInput from "./DNSTargetInput.vue";
import { cleanList, dnsLocationLabel } from "../utils/form";
const props = withDefaults(
  defineProps<{
    modelValue: MigrationHostDNSInput;
    disabled?: boolean;
    allowMap?: boolean;
    sources?: string[];
  }>(),
  { allowMap: true, sources: () => [] },
);
const emit = defineEmits<{
  "update:modelValue": [value: MigrationHostDNSInput];
  "update:valid": [value: boolean];
}>();
type Mappings = NonNullable<MigrationHostDNSInput["mappings"]>;
type Config = NonNullable<Mappings[string]["config"]>;
type DNSRow = {
  source: string;
  target: string | null;
  override: boolean;
  config: Config;
};
const rows = ref<DNSRow[]>([]),
  error = ref("");
const options = computed(() => [
  { label: "保留目标主机 DNS", value: "preserve" },
  {
    label: "迁移 DNS 配置",
    value: "map",
    disabled: !props.allowMap || !props.sources.length,
  },
]);
const connectionDNS = (target: string | null) =>
  !!target && !target.startsWith("networkd:");
const emptyConfig = (): Config => ({
  servers: [],
  search: [],
  ipv4: null,
  ipv6: null,
});
const familyKeys = ["ipv4", "ipv6"] as const;
let canonical = "";
watch(
  () => props.modelValue.mappings,
  (value) => {
    const next = JSON.stringify(value ?? {});
    if (next === canonical) return;
    canonical = next;
    rows.value = Object.entries(value ?? {}).map(([source, item]) => ({
      source,
      target: item.target,
      override: !!item.config,
      config: item.config ? structuredClone(toRaw(item.config)) : emptyConfig(),
    }));
    error.value = "";
    emit("update:valid", true);
  },
  { immediate: true },
);
function setMode(mode: MigrationHostDNSInput["mode"]) {
  rows.value =
    mode === "map"
      ? props.sources.map((source) => ({
          source,
          target: null,
          override: false,
          config: emptyConfig(),
        }))
      : [];
  canonical = "{}";
  error.value = "";
  emit("update:modelValue", { mode, mappings: {} });
  if (mode === "map") update();
  else emit("update:valid", true);
}
function toggleFamily(row: DNSRow, key: "ipv4" | "ipv6", enabled: boolean) {
  row.config[key] = enabled
    ? { servers: [], search: [], automatic: false }
    : null;
  update();
}
function update() {
  try {
    const mappings: Mappings = Object.create(null);
    const targets = new Set<string>();
    for (const row of rows.value) {
      if (row.target === null) throw new Error("请为每个来源选择目标网络");
      const source = row.source,
        target = row.target;
      if (targets.has(target)) throw new Error("不同来源不能选择同一目标网络");
      targets.add(target);
      if (Object.hasOwn(mappings, source)) throw new Error("来源 DNS 不能重复");
      const config = row.override
        ? {
            servers: connectionDNS(target) ? [] : cleanList(row.config.servers),
            search: connectionDNS(target) ? [] : cleanList(row.config.search),
            ipv4:
              connectionDNS(target) && row.config.ipv4
                ? {
                    ...row.config.ipv4,
                    servers: cleanList(row.config.ipv4.servers),
                    search: cleanList(row.config.ipv4.search),
                  }
                : null,
            ipv6:
              connectionDNS(target) && row.config.ipv6
                ? {
                    ...row.config.ipv6,
                    servers: cleanList(row.config.ipv6.servers),
                    search: cleanList(row.config.ipv6.search),
                  }
                : null,
          }
        : undefined;
      mappings[source] = { target, ...(config ? { config } : {}) };
    }
    canonical = JSON.stringify(mappings);
    error.value = "";
    emit("update:modelValue", { ...props.modelValue, mappings });
    emit("update:valid", true);
  } catch (cause) {
    error.value = (cause as Error).message;
    emit("update:valid", false);
  }
}
const api = useNodeAPI();
const network = ref<HostDNSOverview | null>(null),
  loading = ref(false),
  loadError = ref("");
const controller = new AbortController();
const targetOptions = computed(() => {
  const observed = network.value?.observed;
  if (!observed) return [];
  const result = [
    ...observed.links
      .filter((link) => link.writable)
      .map((link) => ({ label: `网卡 ${link.interface}`, value: link.target })),
    ...observed.connections
      .filter((connection) => connection.writable)
      .map((connection) => ({
        label: `${connection.name} · ${connection.interface}`,
        value: connection.target,
      })),
  ];
  if (
    observed.writable &&
    !["networkmanager", "networkd", "netplan"].includes(observed.owner)
  )
    result.unshift({ label: "系统 DNS", value: "" });
  return result;
});
async function loadNetwork() {
  if (loading.value) return;
  loading.value = true;
  loadError.value = "";
  try {
    network.value = await api.hostDNS(controller.signal);
  } catch {
    if (!controller.signal.aborted)
      loadError.value = "无法读取网络设置，请刷新重试。";
  } finally {
    loading.value = false;
  }
}
watch(
  () => props.modelValue.mode,
  (mode) => {
    if (mode === "map" && !network.value) void loadNetwork();
  },
  { immediate: true },
);
watch(
  () => JSON.stringify(props.sources),
  () => {
    if (
      props.modelValue.mode === "map" &&
      rows.value.some((row) => !props.sources.includes(row.source))
    )
      setMode("preserve");
  },
);
onUnmounted(() => controller.abort());
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
    <p v-if="allowMap && !sources.length" class="muted">
      预检配置后，可选择需要迁移 DNS 的网卡。
    </p>
    <div v-if="modelValue.mode === 'map'" class="dns-mappings">
      <div class="toolbar">
        <span class="muted">选择当前服务器上接收 DNS 配置的网络。</span>
        <NButton :loading="loading" :disabled="disabled" @click="loadNetwork">
          刷新网卡
        </NButton>
      </div>
      <NAlert v-if="loadError" type="warning">
        {{ loadError }}
      </NAlert>
      <NAlert v-else-if="!loading && !targetOptions.length" type="warning">
        当前没有可修改的网络，请先在网络设置中检查 DNS 配置。
      </NAlert>
      <div v-for="row in rows" :key="row.source" class="dns-mapping">
        <div class="mapping-targets">
          <NFormItem label="来源 DNS">
            <span>{{ dnsLocationLabel(row.source) }}</span>
          </NFormItem>
          <NFormItem label="目标 DNS">
            <DNSTargetInput
              v-model:value="row.target"
              :options="targetOptions"
              :loading="loading"
              :disabled="disabled"
              @update:value="update"
            />
          </NFormItem>
        </div>
        <NFormItem label="自定义目标 DNS 配置">
          <NSwitch
            v-model:value="row.override"
            :disabled="disabled || row.target === null"
            @update:value="update"
          />
        </NFormItem>
        <template v-if="row.override">
          <template v-if="!connectionDNS(row.target)">
            <NFormItem label="DNS 服务器">
              <ValueListInput
                v-model:value="row.config.servers"
                item-label="DNS 地址"
                :max="3"
                placeholder="DNS 服务器地址"
                :disabled="disabled"
                @update:value="update"
              />
            </NFormItem>
            <NFormItem label="搜索域">
              <ValueListInput
                v-model:value="row.config.search"
                item-label="搜索域"
                :max="6"
                placeholder="example.com"
                :disabled="disabled"
                @update:value="update"
              />
            </NFormItem>
          </template>
          <template v-else>
            <template v-for="key in familyKeys" :key="key">
              <NFormItem :label="`单独设置 ${key === 'ipv4' ? 'IPv4' : 'IPv6'}`">
                <NSwitch
                  :value="!!row.config[key]"
                  :disabled="disabled"
                  @update:value="toggleFamily(row, key, $event)"
                />
              </NFormItem>
              <div v-if="row.config[key]" class="family-config">
                <NFormItem label="自动获取 DNS">
                  <NSwitch
                    v-model:value="row.config[key]!.automatic"
                    :disabled="disabled"
                    @update:value="update"
                  />
                </NFormItem>
                <NFormItem label="DNS 服务器">
                  <ValueListInput
                    v-model:value="row.config[key]!.servers"
                    item-label="DNS 地址"
                    :max="3"
                    placeholder="DNS 服务器地址"
                    :disabled="disabled"
                    @update:value="update"
                  />
                </NFormItem>
                <NFormItem label="搜索域">
                  <ValueListInput
                    v-model:value="row.config[key]!.search"
                    item-label="搜索域"
                    :max="6"
                    placeholder="example.com"
                    :disabled="disabled"
                    @update:value="update"
                  />
                </NFormItem>
              </div>
            </template>
          </template>
        </template>
      </div>
      <NAlert v-if="error" type="error">
        {{ error }}
      </NAlert>
      <NAlert type="warning">
        请为每个来源选择目标网络。需要调整 DNS
        地址时，打开自定义配置。迁移后仍需到网络设置中应用并确认。
      </NAlert>
    </div>
  </div>
</template>
<style scoped>
.dns-mappings {
  display: grid;
  gap: 14px;
  margin-bottom: 18px;
}
.dns-mapping {
  border: 1px solid var(--border-color, #e4e7ec);
  border-radius: 10px;
  padding: 16px;
}
.mapping-targets {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 24px;
  align-items: start;
}
.family-config {
  padding-left: 16px;
  border-left: 2px solid var(--border-color, #e4e7ec);
}
@media (max-width: 680px) {
  .mapping-targets {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
