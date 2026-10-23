<route lang="json">
{
  "meta": {
    "title": "防火墙",
    "subtitle": "管理端口和 IP 黑白名单",
    "nav": true,
    "order": 5,
    "symbol": "≡",
    "group": "网站与安全"
  }
}
</route>
<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref, toRaw } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSelect,
  NSpace,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import AdvancedDetails from "../components/AdvancedDetails.vue";
import GeoIPSourcePanel from "../components/GeoIPSourcePanel.vue";
import {
  useNodeAPI,
  apiError,
  type FirewallRule,
  type FirewallPolicy,
  type FirewallPolicyView,
  type FirewallObservation,
  type FirewallPreview,
  type GeoIPState,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import { randomUUID } from "../utils/crypto";
import { countryOptions, countryName } from "../utils/countries";
const api = useNodeAPI(),
  session = useSession(),
  dialog = useDialog();
const { run, busy, message } = useAction(),
  keyFor = useIdempotency();
const stored = ref<FirewallPolicyView | null>(null),
  policy = ref<FirewallPolicy>({ backend: "direct-nftables", rules: [] });
const geoip = ref<GeoIPState | null>(null),
  observation = ref<FirewallObservation | null>(null),
  preview = ref<FirewallPreview | null>(null);
const activeTab = ref("rules"),
  editing = ref<FirewallRule | null>(null),
  kind = ref("port"),
  portsText = ref("80,443"),
  sourcesText = ref(""),
  formError = ref("");
const formBusy = ref(false);
const controller = new AbortController();
onUnmounted(() => controller.abort());
const canWrite = computed(
  () => session.me?.scopes.includes("security.write") ?? false,
);
const dirty = computed(
  () =>
    !!stored.value &&
    JSON.stringify(policy.value) !== JSON.stringify(stored.value.policy),
);
const countries = computed(() => [
  ...new Set(policy.value.rules.flatMap((rule) => rule.countries || [])),
]);
const kinds = [
  { label: "端口规则", value: "port" },
  { label: "IP 黑白名单", value: "address" },
  { label: "国家和地区名单", value: "country" },
];
const backends = [
  { label: "nftables", value: "direct-nftables" },
  { label: "iptables (nft)", value: "iptables-nft" },
  { label: "iptables (legacy)", value: "iptables-legacy" },
  { label: "firewalld", value: "firewalld" },
  { label: "UFW", value: "ufw" },
];
const protocols = computed(() => [
  { label: "TCP", value: "tcp" },
  { label: "UDP", value: "udp" },
  ...(kind.value !== "port" && policy.value.backend === "direct-nftables"
    ? [{ label: "全部协议和端口", value: "any" }]
    : []),
]);
const actions = [
  { label: "放行（白名单）", value: "allow" },
  { label: "屏蔽（黑名单）", value: "deny" },
  { label: "拒绝连接", value: "reject" },
];
const ruleKind = (rule: FirewallRule) =>
  rule.countries?.length
    ? "country"
    : rule.sources.length || rule.protocol === "any"
      ? "address"
      : "port";
const familySources = (sources: string[], family: string) =>
  family === "both"
    ? sources
    : sources.filter((source) => source.includes(":") === (family === "ipv6"));
const portsLabel = (rule: FirewallRule) =>
  rule.protocol === "any"
    ? "全部端口"
    : `${rule.protocol.toUpperCase()} ${rule.ports.map((p) => (p.from === p.to ? p.from : `${p.from}-${p.to}`)).join(", ")}`;
function reorder(rules: FirewallRule[]) {
  rules.forEach((rule, index) => {
    rule.priority = index * 10;
  });
  policy.value.rules = rules;
  preview.value = null;
}
function add() {
  kind.value = "port";
  portsText.value = "80,443";
  sourcesText.value = "";
  formError.value = "";
  editing.value = {
    id: randomUUID(),
    name: "",
    enabled: true,
    scope: "host_input",
    family: "both",
    protocol: "tcp",
    ports: [{ from: 80, to: 80 }],
    sources: [],
    action: "allow",
    priority: 0,
    interface: "",
    comment: "",
    countries: [],
  };
}
function edit(rule: FirewallRule) {
  editing.value = structuredClone(toRaw(rule));
  kind.value = ruleKind(rule);
  portsText.value = rule.ports
    .map((p) => (p.from === p.to ? String(p.from) : `${p.from}-${p.to}`))
    .join(",");
  sourcesText.value = kind.value === "country" ? "" : rule.sources.join("\n");
  formError.value = "";
}
function changeKind(value: string) {
  kind.value = value;
  if (!editing.value) return;
  editing.value.countries = [];
  editing.value.sources = [];
  editing.value.geoip_updated_at = undefined;
  editing.value.protocol =
    value === "port" || policy.value.backend !== "direct-nftables"
      ? "tcp"
      : "any";
}
async function commitRule() {
  if (!editing.value || formBusy.value) return;
  const value = structuredClone(toRaw(editing.value));
  formError.value = "";
  if (!value.name.trim()) {
    formError.value = "请填写规则名称";
    return;
  }
  if (value.protocol === "any") value.ports = [{ from: 1, to: 65535 }];
  else {
    const parts = portsText.value
      .trim()
      .split(/[,，\s]+/)
      .filter(Boolean);
    if (!parts.length || parts.length > 16) {
      formError.value = "请填写 1–16 个端口或端口范围";
      return;
    }
    const ports = parts.map((part) => {
      const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
      return match
        ? { from: Number(match[1]), to: Number(match[2] || match[1]) }
        : { from: 0, to: 0 };
    });
    if (ports.some((p) => p.from < 1 || p.to > 65535 || p.to < p.from)) {
      formError.value = "端口须为 1–65535，例如 80,443,8000-8010";
      return;
    }
    value.ports = ports;
  }
  if (kind.value === "country") {
    if (value.scope !== "host_input") {
      formError.value = "国家名单仅支持服务器入站访问";
      return;
    }
    if (!value.countries?.length) {
      formError.value = "请选择国家或地区";
      return;
    }
    if (policy.value.backend !== "direct-nftables") {
      formError.value = "当前环境暂不支持国家地址集合";
      return;
    }
    const old = policy.value.rules.find((rule) => rule.id === value.id);
    if (
      !old?.sources.length ||
      JSON.stringify([...(old.countries || [])].sort()) !==
        JSON.stringify([...value.countries].sort())
    ) {
      if (!geoip.value?.ready) {
        formError.value = "请先在 GeoIP 数据中更新数据源";
        return;
      }
      formBusy.value = true;
      try {
        const result = await api.resolveFirewallGeoIP({
          version: geoip.value.version,
          countries: value.countries,
        });
        value.sources = result.sources;
        value.geoip_updated_at = result.updated_at;
      } catch (error) {
        formError.value = apiError(error).message;
        return;
      } finally {
        formBusy.value = false;
      }
    }
    value.sources = familySources(value.sources, value.family);
    if (!value.sources.length) {
      formError.value = "所选国家没有当前地址类型的数据";
      return;
    }
  } else {
    value.countries = [];
    value.geoip_updated_at = undefined;
    value.sources =
      kind.value === "address"
        ? [...new Set(sourcesText.value.split(/[,，\s]+/).filter(Boolean))]
        : [];
    if (kind.value === "address" && !value.sources.length) {
      formError.value = "请输入 IP 地址或网段，每行一个";
      return;
    }
  }
  reorder([
    value,
    ...policy.value.rules.filter((rule) => rule.id !== value.id),
  ]);
  editing.value = null;
}
function remove(rule: FirewallRule) {
  dialog.warning({
    title: "删除规则",
    content: `删除“${rule.name}”？保存并应用后生效。`,
    positiveText: "删除",
    negativeText: "取消",
    onPositiveClick: () =>
      reorder(policy.value.rules.filter((item) => item.id !== rule.id)),
  });
}
const columns: DataTableColumns<FirewallRule> = [
  { title: "名称", key: "name", minWidth: 150, ellipsis: { tooltip: true } },
  {
    title: "访问范围",
    key: "sources",
    minWidth: 230,
    ellipsis: { tooltip: true },
    render: (rule) =>
      rule.countries?.length
        ? `${rule.countries.map(countryName).join("、")}（${rule.sources.length} 个网段）`
        : rule.sources.length
          ? `${rule.sources.slice(0, 2).join("、")}${rule.sources.length > 2 ? ` 等 ${rule.sources.length} 个地址` : ""}`
          : "所有来源",
  },
  { title: "端口", key: "ports", minWidth: 160, render: portsLabel },
  {
    title: "处理方式",
    key: "action",
    width: 110,
    render: (rule) =>
      h(
        NTag,
        {
          type: rule.action === "allow" ? "success" : "error",
          bordered: false,
        },
        { default: () => (rule.action === "allow" ? "放行" : "屏蔽") },
      ),
  },
  {
    title: "启用",
    key: "enabled",
    width: 80,
    render: (rule) =>
      h(NSwitch, {
        value: rule.enabled,
        disabled: busy.value || !canWrite.value,
        "onUpdate:value": (value: boolean) => {
          rule.enabled = value;
          preview.value = null;
        },
      }),
  },
  {
    title: "操作",
    key: "operations",
    width: 160,
    fixed: "right",
    render: (rule) =>
      h(
        NSpace,
        { size: 14, wrap: false },
        {
          default: () => [
            h(
              NButton,
              {
                size: "small",
                text: true,
                disabled: busy.value || !canWrite.value,
                type: "primary",
                onClick: () => edit(rule),
              },
              { default: () => "编辑" },
            ),
            h(
              NButton,
              {
                size: "small",
                text: true,
                disabled:
                  busy.value ||
                  !canWrite.value ||
                  policy.value.rules[0]?.id === rule.id,
                onClick: () =>
                  reorder([
                    rule,
                    ...policy.value.rules.filter((item) => item.id !== rule.id),
                  ]),
              },
              { default: () => "置顶" },
            ),
            h(
              NButton,
              {
                size: "small",
                text: true,
                disabled: busy.value || !canWrite.value,
                type: "error",
                onClick: () => remove(rule),
              },
              { default: () => "删除" },
            ),
          ],
        },
      ),
  },
];
async function load() {
  await run(async () => {
    const [saved, observed, runtime, data] = await Promise.allSettled([
      api.firewallPolicy(controller.signal),
      api.firewall(controller.signal),
      api.firewallRuntime(controller.signal),
      canWrite.value
        ? api.firewallGeoIP(controller.signal)
        : Promise.resolve(null),
    ]);
    if (saved.status === "rejected") throw saved.reason;
    stored.value = saved.value;
    policy.value = structuredClone(saved.value.policy);
    if (observed.status === "fulfilled") observation.value = observed.value;
    if (
      !saved.value.version &&
      runtime.status === "fulfilled" &&
      backends.some((backend) => backend.value === runtime.value.backend)
    )
      policy.value.backend = runtime.value.backend;
    if (data.status === "fulfilled") geoip.value = data.value;
    else if (canWrite.value)
      message.error(`GeoIP 配置读取失败：${apiError(data.reason).message}`);
    preview.value = null;
  });
}
function refresh() {
  if (dirty.value)
    dialog.warning({
      title: "放弃未保存修改",
      content: "重新读取会放弃当前修改。",
      positiveText: "重新读取",
      negativeText: "取消",
      onPositiveClick: () => void load(),
    });
  else void load();
}
async function save(confirmConflicts = false) {
  await run(async () => {
    const data = {
      base_version: stored.value?.version || 0,
      policy: policy.value,
      confirm_conflicts: confirmConflicts,
    };
    try {
      const saved = await api.saveFirewallPolicy(data, keyFor(data));
      stored.value = saved;
      policy.value = structuredClone(saved.policy);
      preview.value = null;
      message.success("规则已保存，应用变更后生效");
    } catch (error) {
      const failure = apiError(error);
      if (!confirmConflicts && failure.code === "FIREWALL_RULE_CONFLICT") {
        dialog.warning({
          title: "确认规则覆盖",
          content: failure.message,
          positiveText: "确认覆盖",
          negativeText: "取消",
          onPositiveClick: () => void save(true),
        });
        return;
      }
      throw error;
    }
  });
}
async function updateCountryRules() {
  if (!geoip.value?.ready) return;
  await run(async () => {
    const results = new Map<
      string,
      Awaited<ReturnType<typeof api.resolveFirewallGeoIP>>
    >();
    for (const rule of policy.value.rules) {
      if (!rule.countries?.length) continue;
      const key = [...rule.countries].sort().join(",");
      let result = results.get(key);
      if (!result) {
        result = await api.resolveFirewallGeoIP({
          version: geoip.value!.version,
          countries: rule.countries,
        });
        results.set(key, result);
      }
    }
    for (const rule of policy.value.rules) {
      if (!rule.countries?.length) continue;
      const result = results.get([...rule.countries].sort().join(","))!;
      const sources = familySources(result.sources, rule.family);
      if (!sources.length)
        throw new Error(`“${rule.name}”没有当前地址类型的数据`);
    }
    for (const rule of policy.value.rules) {
      if (!rule.countries?.length) continue;
      const result = results.get([...rule.countries].sort().join(","))!;
      rule.sources = familySources(result.sources, rule.family);
      rule.geoip_updated_at = result.updated_at;
    }
    preview.value = null;
    if (results.size) message.success("国家名单已更新，请保存并应用变更");
  });
}
async function check() {
  if (stored.value?.version)
    await run(async () => {
      preview.value = await api.previewFirewall(
        stored.value!.version,
        controller.signal,
      );
    });
}
onMounted(load);
</script>
<template>
  <Teleport defer to="#page-heading-actions">
    <n-space align="center" :size="12">
      <n-button quaternary :disabled="busy" @click="refresh">刷新</n-button>
      <n-button
        v-if="activeTab === 'rules'"
        :disabled="busy || !canWrite || !dirty"
        @click="save()"
        >保存修改</n-button
      >
      <RouterLink v-if="activeTab === 'rules' && canWrite" to="/firewall-apply">
        <n-button type="primary" :disabled="busy || !stored?.version || dirty"
          >应用变更</n-button
        >
      </RouterLink>
    </n-space>
  </Teleport>
  <n-alert v-if="dirty" type="warning" :show-icon="false"
    >有未保存的规则修改，保存并应用后生效。<n-button
      v-if="activeTab !== 'rules'"
      text
      type="primary"
      style="margin-left: 12px"
      @click="activeTab = 'rules'"
      >前往规则管理</n-button
    ></n-alert
  >
  <div class="firewall-card">
    <n-tabs v-model:value="activeTab" type="line" animated>
      <n-tab-pane name="rules" tab="规则管理">
        <div class="section-toolbar">
          <div>
            <div class="section-title">
              <h2>访问规则</h2>
              <n-tag size="small" :bordered="false"
                >{{ policy.rules.length }} 条</n-tag
              >
            </div>
            <p class="muted">从上到下依次匹配，首条命中的规则生效。</p>
          </div>
          <n-button
            type="primary"
            secondary
            :disabled="busy || !canWrite"
            @click="add"
            >添加规则</n-button
          >
        </div>
        <n-data-table
          :columns="columns"
          :data="policy.rules"
          :row-key="(rule: FirewallRule) => rule.id"
          :scroll-x="900"
        >
          <template #empty>
            <div class="rules-empty">
              <span class="empty-symbol" aria-hidden="true">≡</span>
              <strong>还没有防火墙规则</strong>
              <p>点击“添加规则”，设置端口或 IP 黑白名单。</p>
            </div>
          </template>
        </n-data-table>
        <AdvancedDetails title="高级设置">
          <n-form-item label="防火墙管理方式"
            ><n-select
              v-model:value="policy.backend"
              :options="backends"
              :disabled="busy || !canWrite || !!stored?.version"
          /></n-form-item>
          <p class="muted">
            本工具管理的规则与系统已有规则共同生效。其他防火墙或云安全组中的限制需要在对应位置调整。
          </p>
          <n-space align="center" class="advanced-actions"
            ><RouterLink to="/firewall">查看系统已有规则</RouterLink>
            <n-button
              :disabled="busy || dirty || !stored?.version"
              @click="check"
              >检查已保存规则</n-button
            >
          </n-space>
          <n-alert
            v-for="error in preview?.errors || []"
            :key="error"
            type="error"
            >{{ error }}</n-alert
          >
          <p v-if="preview">
            {{ preview.compiled ? "规则检查通过" : "规则检查未通过" }}
          </p>
          <p v-if="observation && !observation.writable">
            {{ observation.reason }}
          </p>
        </AdvancedDetails>
      </n-tab-pane>
      <n-tab-pane v-if="canWrite" name="geoip" tab="GeoIP 数据源"
        ><GeoIPSourcePanel
          :state="geoip"
          :writable="canWrite"
          :countries="countries"
          @changed="geoip = $event"
          @updated="updateCountryRules"
      /></n-tab-pane>
    </n-tabs>
  </div>
  <n-modal
    :show="!!editing"
    preset="card"
    title="防火墙规则"
    style="width: min(680px, 94vw)"
    :mask-closable="false"
    :closable="!formBusy"
    @update:show="
      (value: boolean) => {
        if (!value) editing = null;
      }
    "
  >
    <n-form v-if="editing" :disabled="formBusy">
      <n-alert v-if="formError" type="error">{{ formError }}</n-alert>
      <n-form-item label="规则类型"
        ><n-select
          :value="kind"
          :options="kinds"
          :disabled="busy"
          @update:value="changeKind"
      /></n-form-item>
      <n-form-item label="名称"
        ><n-input
          v-model:value="editing.name"
          maxlength="128"
          placeholder="例如：网站访问、办公网络、地区屏蔽"
      /></n-form-item>
      <n-form-item label="处理方式"
        ><n-select v-model:value="editing.action" :options="actions"
      /></n-form-item>
      <n-form-item v-if="kind === 'country'" label="国家和地区"
        ><n-select
          v-model:value="editing.countries"
          multiple
          filterable
          :options="countryOptions"
      /></n-form-item>
      <n-alert v-if="kind === 'country' && !geoip?.ready" type="info"
        >请先在“GeoIP 数据”中更新国家地址数据。</n-alert
      >
      <n-form-item v-if="kind === 'address'" label="IP 地址或网段"
        ><n-input
          v-model:value="sourcesText"
          type="textarea"
          :autosize="{ minRows: 4, maxRows: 12 }"
          placeholder="每行一个 IP 或 CIDR，例如 192.168.1.10、192.168.1.0/24"
      /></n-form-item>
      <n-form-item label="协议"
        ><n-select v-model:value="editing.protocol" :options="protocols"
      /></n-form-item>
      <n-form-item v-if="editing.protocol !== 'any'" label="端口"
        ><n-input v-model:value="portsText" placeholder="例如 80,443,8000-8010"
      /></n-form-item>
      <AdvancedDetails title="更多设置">
        <n-form-item label="地址类型"
          ><n-select
            v-model:value="editing.family"
            :options="[
              { label: 'IPv4 和 IPv6', value: 'both' },
              { label: 'IPv4', value: 'ipv4' },
              { label: 'IPv6', value: 'ipv6' },
            ]"
        /></n-form-item>
        <n-form-item label="流量范围"
          ><n-select
            v-model:value="editing.scope"
            :options="[
              { label: '服务器入站', value: 'host_input' },
              { label: 'Docker 发布端口', value: 'docker_published' },
            ]"
        /></n-form-item>
        <n-form-item label="网卡（可选）"
          ><n-input
            v-model:value="editing.interface"
            maxlength="15"
            placeholder="所有网卡"
        /></n-form-item>
        <n-form-item label="备注"
          ><n-input v-model:value="editing.comment" maxlength="512"
        /></n-form-item>
      </AdvancedDetails>
      <n-space justify="end"
        ><n-button :disabled="busy || formBusy" @click="editing = null"
          >取消</n-button
        ><n-button
          type="primary"
          :loading="formBusy"
          :disabled="busy || formBusy"
          @click="commitRule"
          >确定</n-button
        ></n-space
      >
    </n-form>
  </n-modal>
</template>
<style scoped>
.firewall-card {
  padding: 8px 24px 24px;
  border: 1px solid #e5eae7;
  border-radius: 12px;
  background: #fff;
}
.section-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
  margin: 16px 0 20px;
}
.section-title {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.rules-empty {
  display: grid;
  justify-items: center;
  gap: 10px;
  padding: 36px 16px;
  color: #7b8680;
}
.rules-empty strong {
  color: #4d5f54;
  font-size: 14px;
  font-weight: 500;
}
.rules-empty p {
  font-size: 13px;
}
.empty-symbol {
  display: grid;
  place-items: center;
  width: 48px;
  height: 48px;
  margin-bottom: 4px;
  border-radius: 50%;
  background: #f0f6f2;
  color: #88a697;
  font-size: 28px;
}
.advanced-actions {
  margin-top: 16px;
}
:deep(.n-alert) {
  margin-bottom: 16px;
}
@media (max-width: 600px) {
  .firewall-card {
    padding: 4px 14px 16px;
  }
}
</style>
