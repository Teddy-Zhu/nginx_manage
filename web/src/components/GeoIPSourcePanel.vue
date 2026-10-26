<script setup lang="ts">
import { computed, ref, watch, toRaw } from "vue";
import {
  NAlert,
  NForm,
  NModal,
  NTag,
  NButton,
  NFormItem,
  NInput,
  NSelect,
  NSpace,
  NSwitch,
} from "naive-ui";
import { useNodeAPI, type GeoIPState, type GeoIPSource } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import AdvancedDetails from "./AdvancedDetails.vue";
import { countryOptions } from "../utils/countries";
const props = defineProps<{
  state: GeoIPState | null;
  writable: boolean;
  countries: string[];
}>();
const emit = defineEmits<{ changed: [state: GeoIPState]; updated: [] }>();
const api = useNodeAPI(),
  { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const settingsOpen = ref(false);
const draft = ref<GeoIPSource>({
  name: "",
  format: "mmdb",
  url: "",
  ipv6_url: "",
  allow_private_network: false,
});
const selected = ref<string[]>(["CN"]);
watch(
  () => props.state,
  (value) => {
    if (value) draft.value = structuredClone(toRaw(value.source));
  },
  { immediate: true },
);
watch(
  () => props.countries,
  (value) => {
    if (value.length) selected.value = [...new Set(value)];
  },
  { immediate: true },
);
const dirty = computed(
  () =>
    !!props.state &&
    JSON.stringify(draft.value) !== JSON.stringify(props.state.source),
);
const formats = [
  { label: "MaxMind MMDB", value: "mmdb" },
  { label: "国家 CIDR 列表", value: "cidr" },
];
function preset(format: "mmdb" | "cidr") {
  draft.value =
    format === "mmdb"
      ? {
          name: "Loyalsoldier GeoIP",
          format,
          url: "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
          ipv6_url: "",
          allow_private_network: false,
        }
      : {
          name: "IPdeny",
          format,
          url: "https://www.ipdeny.com/ipblocks/data/aggregated/{country}-aggregated.zone",
          ipv6_url:
            "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{country}-aggregated.zone",
          allow_private_network: false,
        };
}
function openSettings() {
  if (!props.state) return;
  draft.value = structuredClone(toRaw(props.state.source));
  settingsOpen.value = true;
}
async function save() {
  if (!props.state) return;
  await run(async () => {
    const data = { base_version: props.state!.version, source: draft.value };
    const value = await api.saveFirewallGeoIP(data, keyFor(data));
    emit("changed", value);
    settingsOpen.value = false;
    message.success("数据源已保存");
  });
}
async function update() {
  if (!props.state) return;
  await run(async () => {
    const data = { version: props.state!.version, countries: selected.value };
    const value = await api.updateFirewallGeoIP(data, keyFor(data));
    emit("changed", value);
    emit("updated");
    message.success("GeoIP 数据已更新");
  });
}
</script>
<template>
  <div class="geoip-source">
    <div class="source-toolbar">
      <div>
        <div class="source-title">
          <h2>国家 IP 数据</h2>
          <n-tag
            v-if="state"
            size="small"
            :type="state.ready ? 'success' : 'warning'"
            :bordered="false"
            >{{ state.ready ? "已就绪" : "待更新" }}</n-tag
          >
        </div>
        <p class="muted">为国家和地区黑白名单提供 IP 地址数据。</p>
      </div>
      <n-space :size="12">
        <slot name="actions" />
        <n-button :disabled="busy || !writable || !state" @click="openSettings"
          >修改数据源</n-button
        >
        <n-button
          type="primary"
          :loading="busy"
          :disabled="
            !writable ||
            !state ||
            (state.source.format === 'cidr' && !selected.length)
          "
          @click="update"
          >更新数据</n-button
        >
      </n-space>
    </div>
    <dl class="source-info">
      <div>
        <dt>当前数据源</dt>
        <dd>{{ state?.source.name || "正在加载…" }}</dd>
      </div>
      <div>
        <dt>文件格式</dt>
        <dd>
          {{
            state
              ? state.source.format === "mmdb"
                ? "MaxMind MMDB"
                : "CIDR 地址列表"
              : "—"
          }}
        </dd>
      </div>
      <div>
        <dt>国家和地区</dt>
        <dd>
          {{
            state?.ready
              ? Object.keys(state.countries).length + " 个"
              : "待更新"
          }}
        </dd>
      </div>
      <div>
        <dt>最近更新</dt>
        <dd>
          {{
            state?.ready
              ? new Date(state.updated_at * 1000).toLocaleString()
              : "尚未更新"
          }}
        </dd>
      </div>
    </dl>
    <n-form-item
      v-if="state?.source.format === 'cidr'"
      label="更新的国家和地区"
      class="country-selection"
    >
      <n-select
        v-model:value="selected"
        multiple
        filterable
        :options="countryOptions"
        :disabled="busy || !writable"
      />
    </n-form-item>
    <n-alert v-if="state && !state.ready" type="info" :show-icon="false"
      >请先更新数据，再添加国家黑白名单。</n-alert
    >
    <p v-if="countries.length" class="muted">
      国家名单更新后，保存并应用规则即可生效。
    </p>
  </div>
  <n-modal
    v-model:show="settingsOpen"
    preset="card"
    title="数据源设置"
    style="width: min(680px, 94vw)"
    :mask-closable="!busy"
    :closable="!busy"
    :close-on-esc="!busy"
  >
    <n-form :show-feedback="false" label-placement="top" class="source-form">
      <n-form-item label="常用数据源" class="full-width">
        <n-space>
          <n-button :disabled="busy || !writable" @click="preset('mmdb')"
            >GitHub MMDB</n-button
          >
          <n-button :disabled="busy || !writable" @click="preset('cidr')"
            >IPdeny CIDR</n-button
          >
        </n-space>
      </n-form-item>
      <n-form-item label="数据源名称"
        ><n-input
          v-model:value="draft.name"
          :disabled="busy || !writable"
          maxlength="128"
      /></n-form-item>
      <n-form-item label="文件格式"
        ><n-select
          v-model:value="draft.format"
          :options="formats"
          :disabled="busy || !writable"
      /></n-form-item>
      <n-form-item
        :label="draft.format === 'mmdb' ? '数据库下载地址' : 'IPv4 下载地址'"
        class="full-width"
        ><n-input
          v-model:value="draft.url"
          :disabled="busy || !writable"
          placeholder="https://"
      /></n-form-item>
      <template v-if="draft.format === 'cidr'">
        <n-form-item label="IPv6 下载地址（可选）" class="full-width"
          ><n-input
            v-model:value="draft.ipv6_url"
            :disabled="busy || !writable"
            placeholder="https://"
        /></n-form-item>
        <p class="muted full-width">
          地址中的 {country} 会替换为国家代码，例如 cn。支持每行一个 IP 或 CIDR
          的地址列表。
        </p>
      </template>
      <AdvancedDetails class="full-width" title="高级设置">
        <n-form-item label="允许从内网镜像下载"
          ><n-switch
            v-model:value="draft.allow_private_network"
            :disabled="busy || !writable"
        /></n-form-item>
      </AdvancedDetails>
    </n-form>
    <template #footer>
      <n-space justify="end" :size="12">
        <n-button :disabled="busy" @click="settingsOpen = false">取消</n-button>
        <n-button
          type="primary"
          :loading="busy"
          :disabled="!writable || !dirty"
          @click="save"
          >保存数据源</n-button
        >
      </n-space>
    </template>
  </n-modal>
</template>
<style scoped>
.geoip-source {
  display: grid;
  gap: 24px;
  padding: 8px 0 0;
}
.source-toolbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
}
.source-title {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.source-info {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
  margin: 0;
  padding: 20px;
  background: var(--surface-soft);
  border-radius: 8px;
}
.source-info dt {
  color: #7b8680;
  font-size: 13px;
  margin-bottom: 8px;
}
.source-info dd {
  color: #34483c;
  font-size: 14px;
  margin: 0;
  overflow-wrap: anywhere;
}
.country-selection {
  max-width: 680px;
}
.source-form {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
}
.full-width {
  grid-column: 1 / -1;
}
.source-form :deep(.n-form-item) {
  margin-bottom: 0;
}
.source-form .advanced-details {
  margin: 0;
}
@media (max-width: 800px) {
  .source-info {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 20px;
  }
}
@media (max-width: 500px) {
  .source-form {
    grid-template-columns: minmax(0, 1fr);
  }
  .source-info {
    padding: 18px;
  }
}
</style>
