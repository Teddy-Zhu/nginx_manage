<route lang="json">
{
  "meta": {
    "title": "基础 WAF",
    "subtitle": "站点防护策略、限流与路径规则",
    "nav": true,
    "order": 3,
    "symbol": "◇"
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, toRaw } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NAlert,
  NButton,
  NDataTable,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NSwitch,
  type DataTableColumns,
} from "naive-ui";
import {
  api,
  type Tree,
  type WAFConfig,
  type WAFPolicy,
  type NginxFeatures,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";

function emptyConfig(): WAFConfig {
  return {
    metadata: { name: "", notes: "", enabled: false },
    rate: 0,
    rate_unit: "r/s",
    burst: 0,
    connections: 0,
    reject_status: 429,
    observe: false,
    body_size: "",
    methods: [],
    denied_paths: [],
    exempt_paths: [],
  };
}
const { run, busy } = useAction(),
  keyFor = useIdempotency();
const tree = ref<Tree | null>(null),
  features = ref<NginxFeatures | null>(null),
  capabilityError = ref("");
const selected = ref<WAFPolicy | null>(null),
  editing = ref(false),
  form = ref<WAFConfig>(emptyConfig()),
  baseline = ref("");
const serialized = computed(() => JSON.stringify(form.value));
const dirty = computed(
  () => editing.value && serialized.value !== baseline.value,
);
const locked = computed(() => busy.value || selected.value?.editable === false);
function has(name: string) {
  return (
    features.value?.available === true &&
    features.value.features[name]?.available === true
  );
}
function unavailable(name: string) {
  return (
    features.value?.features[name]?.reason ||
    capabilityError.value ||
    features.value?.reason ||
    "尚未确认模块能力"
  );
}
const coreAvailable = computed(() =>
  ["http", "map", "map_volatile", "rewrite"].every(has),
);
const canObserve = computed(
  () =>
    (form.value.rate === 0 || has("limit_req_observe")) &&
    (form.value.connections === 0 || has("limit_conn_observe")),
);
const affected = computed(
  () =>
    selected.value?.resources.map(
      (id) =>
        tree.value?.resources.find((item) => item.id === id)?.metadata.name ||
        id.slice(0, 8),
    ) ?? [],
);
const columns: DataTableColumns<WAFPolicy> = [
  {
    title: "名称",
    key: "id",
    render: (row) => row.config.metadata.name || row.id.slice(0, 8),
  },
  {
    title: "状态",
    key: "enabled",
    render: (row) => (row.config.metadata.enabled ? "启用" : "停用"),
  },
  {
    title: "关联代理",
    key: "resources",
    render: (row) => row.resources.length,
  },
  {
    title: "编辑",
    key: "editable",
    render: (row) => (row.editable ? "可编辑" : "仅原生编辑"),
  },
];
const methodOptions = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "CONNECT",
  "TRACE",
].map((value) => ({ label: value, value }));
const pathModes = [
  { label: "精确路径", value: "exact" },
  { label: "路径前缀", value: "prefix" },
];
function open(policy: WAFPolicy | null) {
  if (dirty.value && !window.confirm("修改尚未保存，确认切换？")) return;
  selected.value = policy;
  form.value = policy ? structuredClone(toRaw(policy.config)) : emptyConfig();
  editing.value = true;
  baseline.value = serialized.value;
}
async function load() {
  if (dirty.value && !window.confirm("修改尚未保存，确认重新加载？")) return;
  await run(async () => {
    const [current, report] = await Promise.all([
      api.tree(),
      api
        .nginxFeatures()
        .then((data) => ({ data, error: "" }))
        .catch((error: unknown) => ({
          data: null,
          error: error instanceof Error ? error.message : "无法查询 Nginx 能力",
        })),
    ]);
    tree.value = current;
    features.value = report.data;
    capabilityError.value = report.error;
    selected.value = null;
    editing.value = false;
  });
}
async function save() {
  if (!tree.value || locked.value) return;
  const id = selected.value?.id ?? null,
    previous = new Set(tree.value.waf_policies.map((item) => item.id));
  const input = {
    ...structuredClone(toRaw(form.value)),
    base_version: tree.value.version,
  };
  if (
    affected.value.length &&
    !window.confirm(
      `保存将影响 ${affected.value.join("、")}，配置应用后生效。确认保存？`,
    )
  )
    return;
  await run(async () => {
    const out = await api.saveWAF(id, input, keyFor({ id, ...input }));
    tree.value = out.tree;
    baseline.value = serialized.value;
    const updated = out.tree.waf_policies.find((item) =>
      id ? item.id === id : !previous.has(item.id),
    );
    if (updated) open(updated);
  }, "WAF 策略已保存，尚未应用");
}
async function remove() {
  if (
    !tree.value ||
    !selected.value ||
    locked.value ||
    dirty.value ||
    selected.value.resources.length
  )
    return;
  const id = selected.value.id,
    version = tree.value.version;
  if (
    !window.confirm(`确认删除 ${selected.value.config.metadata.name || id}？`)
  )
    return;
  await run(async () => {
    const out = await api.deleteWAF(
      id,
      version,
      keyFor({ action: "delete-waf", id, version }),
    );
    tree.value = out.tree;
    selected.value = null;
    editing.value = false;
  }, "WAF 策略已移除");
}
function rateChanged(value: number | null) {
  form.value.rate = value ?? 0;
  if (form.value.rate === 0) form.value.burst = 0;
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("修改尚未保存，确认离开？"),
);
onMounted(() => {
  void load();
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => window.removeEventListener("beforeunload", beforeUnload));
</script>

<template>
  <div class="toolbar">
    <span class="muted">{{
      tree?.version ? `期望修订 #${tree.version}` : "尚未保存"
    }}</span>
    <div class="inline-gap">
      <router-link :to="{ path: '/logs', query: { events: '1' } }"
        >防护事件</router-link
      >
      <n-button :loading="busy" @click="load">刷新</n-button
      ><n-button type="primary" :disabled="busy" @click="open(null)"
        >新建策略</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >策略需在
    <router-link to="/nginx">Nginx 配置</router-link> 中绑定站点并应用。IP
    黑白名单复用
    <router-link to="/access-lists">访问列表</router-link
    >。同一策略的站点共享每来源限流额度；使用 CDN
    或前置代理时，先配置可信代理来源和真实 IP 头。</n-alert
  >
  <n-alert
    v-if="!coreAvailable"
    type="warning"
    :bordered="false"
    style="margin-bottom: 20px"
    >{{
      capabilityError ||
      features?.reason ||
      ["http", "map", "map_volatile", "rewrite"]
        .filter((name) => !has(name))
        .map(unavailable)
        .join("；")
    }}。可保存停用策略，启用前须确认模块能力。</n-alert
  >
  <div class="two-columns">
    <section class="surface">
      <div class="section-heading"><h2>防护策略</h2></div>
      <n-data-table
        :columns="columns"
        :data="tree?.waf_policies ?? []"
        :bordered="false"
        :row-props="
          (row: WAFPolicy) => ({
            onClick: () => {
              if (!busy) open(row);
            },
            style: 'cursor: pointer',
          })
        "
      />
    </section>
    <section class="surface">
      <template v-if="editing">
        <div class="section-heading">
          <h2>{{ selected ? "编辑策略" : "新建策略" }}</h2>
          <n-button
            v-if="selected"
            type="error"
            :disabled="locked || dirty || !!selected.resources.length"
            @click="remove"
            >删除</n-button
          >
        </div>
        <n-alert
          v-if="selected && !selected.editable"
          type="warning"
          :bordered="false"
          style="margin-bottom: 20px"
          >{{ selected.reason }}</n-alert
        >
        <n-form label-placement="top" :disabled="locked" @submit.prevent="save">
          <n-form-item label="名称"
            ><n-input v-model:value="form.metadata.name" :maxlength="128"
          /></n-form-item>
          <n-form-item label="备注"
            ><n-input
              v-model:value="form.metadata.notes"
              type="textarea"
              :maxlength="2048"
          /></n-form-item>
          <n-form-item label="启用策略"
            ><n-switch
              v-model:value="form.metadata.enabled"
              :disabled="locked || (!coreAvailable && !form.metadata.enabled)"
          /></n-form-item>
          <n-form-item
            label="每来源请求速率（0 表示关闭）"
            :feedback="
              !has('limit_req_status') ? unavailable('limit_req_status') : ''
            "
            ><div class="inline-gap">
              <n-input-number
                :value="form.rate"
                :min="0"
                :max="100000"
                :precision="0"
                :disabled="locked || !has('limit_req_status')"
                @update:value="rateChanged"
              /><n-select
                v-model:value="form.rate_unit"
                :options="[
                  { label: '每秒', value: 'r/s' },
                  { label: '每分钟', value: 'r/m' },
                ]"
                :disabled="locked || !has('limit_req_status')"
                style="width: 120px"
              /></div
          ></n-form-item>
          <n-form-item label="突发额度（不延迟转发，超额拒绝）"
            ><n-input-number
              :value="form.burst"
              :min="0"
              :max="10000"
              :precision="0"
              :disabled="locked || !has('limit_req_status') || form.rate === 0"
              @update:value="(value) => (form.burst = value ?? 0)"
          /></n-form-item>
          <n-form-item
            label="每来源并发上限（0 表示关闭）"
            :feedback="
              !has('limit_conn_status') ? unavailable('limit_conn_status') : ''
            "
            ><n-input-number
              :value="form.connections"
              :min="0"
              :max="65535"
              :precision="0"
              :disabled="locked || !has('limit_conn_status')"
              @update:value="(value) => (form.connections = value ?? 0)"
          /></n-form-item>
          <p class="muted">
            HTTP/1 仅统计正在处理且已读完请求头的连接；HTTP/2、HTTP/3
            按并发请求计数。
          </p>
          <n-form-item label="限流拒绝状态"
            ><n-select
              v-model:value="form.reject_status"
              :options="[
                { label: '429 请求过多', value: 429 },
                { label: '503 服务不可用', value: 503 },
              ]"
          /></n-form-item>
          <n-form-item label="限流观察模式"
            ><n-switch
              v-model:value="form.observe"
              :disabled="locked || (!canObserve && !form.observe)"
          /></n-form-item>
          <p v-if="form.observe" class="muted">
            仅记录限速和并发超额，方法、路径和请求体限制继续执行。
          </p>
          <n-form-item label="最大请求体（留空继承，0 表示不限制）"
            ><n-input v-model:value="form.body_size" placeholder="10m"
          /></n-form-item>
          <n-form-item label="允许的方法（留空表示不限制）"
            ><n-select
              v-model:value="form.methods"
              multiple
              tag
              :options="methodOptions"
          /></n-form-item>
          <template
            v-for="section in [
              { key: 'denied_paths' as const, title: '拒绝路径' },
              { key: 'exempt_paths' as const, title: '豁免路径' },
            ]"
            :key="section.key"
          >
            <div class="section-heading">
              <h3>{{ section.title }}</h3>
              <n-button
                size="small"
                :disabled="locked || form[section.key].length >= 128"
                @click="form[section.key].push({ match: 'exact', path: '' })"
                >添加</n-button
              >
            </div>
            <div
              v-for="(item, index) in form[section.key]"
              :key="index"
              class="inline-gap"
              style="margin-bottom: 12px"
            >
              <n-select
                v-model:value="item.match"
                :options="pathModes"
                style="width: 130px"
              /><n-input
                v-model:value="item.path"
                placeholder="/admin/"
                :maxlength="512"
              /><n-button
                :disabled="locked"
                @click="form[section.key].splice(index, 1)"
                >移除</n-button
              >
            </div>
          </template>
          <p class="muted">
            路径按规范化后的 URI
            区分大小写匹配。豁免仅跳过方法检查、请求限速和并发限制；ACL、明确拒绝路径和请求体限制仍生效。
          </p>
          <p class="muted">关联代理：{{ affected.join("、") || "无" }}</p>
          <n-button
            type="primary"
            attr-type="submit"
            :loading="busy"
            :disabled="locked || (!!selected && !dirty)"
            >保存策略</n-button
          >
        </n-form> </template
      ><n-empty v-else description="选择或新建防护策略" />
    </section>
  </div>
</template>
