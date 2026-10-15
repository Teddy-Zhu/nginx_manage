<route lang="json">
{
  "meta": {
    "title": "ACME 签发",
    "subtitle": "DNS-01 证书申请与订单恢复",
    "nav": false
  }
}
</route>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { onBeforeRouteLeave } from "vue-router";
import {
  NAlert,
  NButton,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NTag,
} from "naive-ui";
import {
  api,
  type ACMEAccount,
  type ACMEProfile,
  type ACMEProfileInput,
  type ACMEOrder,
  type DNSCredential,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";

const { busy, run } = useAction(),
  keyFor = useIdempotency();
const profiles = ref<ACMEProfile[]>([]),
  accounts = ref<ACMEAccount[]>([]),
  credentials = ref<DNSCredential[]>([]);
const offset = ref(0);
const editing = ref(false),
  domainsText = ref(""),
  baseline = ref("");
const emptyForm = (): ACMEProfileInput => ({
  name: "",
  notes: "",
  account_id: "",
  credential_id: "",
  domains: [],
});
const form = ref(emptyForm()),
  selected = ref(""),
  orders = ref<ACMEOrder[]>([]),
  now = ref(Date.now());
const formJSON = computed(() =>
  JSON.stringify([form.value, domainsText.value]),
);
const dirty = computed(
  () => editing.value && formJSON.value !== baseline.value,
);
const domains = computed(() =>
  domainsText.value
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean),
);
const valid = computed(
  () =>
    form.value.name.trim() &&
    form.value.account_id &&
    form.value.credential_id &&
    domains.value.length > 0 &&
    domains.value.length <= 64,
);
const accountOptions = computed(() =>
  accounts.value
    .filter((item) => item.state === "ready")
    .map((item) => ({
      label: `${item.name} · ${item.environment === "production" ? "正式" : "测试"}`,
      value: item.id,
    })),
);
const credentialOptions = computed(() =>
  credentials.value.map((item) => ({ label: item.name, value: item.id })),
);
const profileStates: Record<ACMEProfile["state"], string> = {
  idle: "未申请",
  issuing: "签发中",
  issued: "已签发",
  failed: "申请失败",
  recovery_required: "待恢复",
  archived: "已停用",
};
const taskStates: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  succeeded: "已完成",
  failed: "失败",
  recovery_required: "待恢复",
  cancelled: "已取消",
};
const dnsStates: Record<string, string> = {
  preparing: "准备发布",
  present: "已发布",
  cleaned: "已清理",
  blocked: "清理待确认",
};
const date = (value: number) => new Date(value * 1000).toLocaleString();
const canIssue = (item: ACMEProfile) =>
  !busy.value &&
  item.state !== "issuing" &&
  item.state !== "archived" &&
  item.retry_after * 1000 <= now.value;
let timer: ReturnType<typeof setInterval> | undefined;

async function load() {
  await run(async () => {
    const [p, a, c] = await Promise.all([
      api.acmeProfiles(offset.value),
      api.acmeAccounts(),
      api.dnsCredentials(),
    ]);
    profiles.value = p;
    accounts.value = a;
    credentials.value = c;
    if (selected.value) orders.value = await api.acmeOrders(selected.value);
  });
}
async function changePage(delta: number) {
  if (busy.value) return;
  const next = Math.max(0, offset.value + delta * 100);
  await run(async () => {
    const result = await api.acmeProfiles(next);
    profiles.value = result;
    offset.value = next;
    selected.value = "";
    orders.value = [];
  });
}
function start() {
  if (
    busy.value ||
    (dirty.value && !window.confirm("签发配置尚未保存，确认重新填写？"))
  )
    return;
  form.value = emptyForm();
  domainsText.value = "";
  baseline.value = formJSON.value;
  editing.value = true;
}
function close() {
  if (
    busy.value ||
    (dirty.value && !window.confirm("签发配置尚未保存，确认取消？"))
  )
    return;
  editing.value = false;
  form.value = emptyForm();
  domainsText.value = "";
}
async function create() {
  if (busy.value || !valid.value) return;
  const input = { ...form.value, domains: domains.value };
  await run(async () => {
    const result = await api.createACMEProfile(
      input,
      keyFor({ action: "create-acme-profile", input }),
    );
    if (!result.profile) throw new Error("未返回有效签发配置");
    editing.value = false;
    form.value = emptyForm();
    domainsText.value = "";
    offset.value = 0;
    selected.value = "";
    orders.value = [];
    profiles.value = await api.acmeProfiles();
  }, "签发配置已创建");
}
async function issue(item: ACMEProfile, newOrder: boolean) {
  if (!canIssue(item)) return;
  const uncertain = item.state === "recovery_required";
  const prompt = newOrder
    ? uncertain
      ? "原任务存在未确认结果，CA 可能已经接受订单。确认承担重复申请的限制，并建立新订单？"
      : "确认建立新订单并申请证书新版本？新版本签发后需另行绑定站点并应用。"
    : item.current_order_id
      ? "确认恢复原订单？将使用该订单原有的密钥和 DNS 凭据，核对签发结果并清理验证记录。"
      : "确认向所选 CA 申请证书并临时添加 DNS TXT 验证记录？";
  if (!window.confirm(prompt)) return;
  const input = {
    base_version: item.version,
    new_order: newOrder,
    acknowledge_uncertain: uncertain && newOrder,
  };
  await run(async () => {
    const result = await api.issueACMEProfile(
      item.id,
      input,
      keyFor({ action: "issue-acme-profile", id: item.id, input }),
    );
    if (!result.profile || !result.task_id)
      throw new Error("未返回有效签发任务");
    profiles.value = profiles.value.map((value) =>
      value.id === item.id ? result.profile! : value,
    );
    if (selected.value === item.id)
      orders.value = await api.acmeOrders(item.id);
  }, "签发任务已排队");
}
async function archive(item: ACMEProfile) {
  if (busy.value || item.state === "issuing" || item.state === "archived")
    return;
  const uncertain = item.state === "recovery_required";
  if (
    !window.confirm(
      uncertain
        ? "确认停止恢复未确认的远端订单并停用配置？证书和订单历史会保留；未清理的验证记录会阻止此操作。"
        : "确认停用此签发配置？证书及历史订单会保留。",
    )
  )
    return;
  const input = {
    base_version: item.version,
    acknowledge_uncertain: uncertain,
  };
  await run(async () => {
    const result = await api.archiveACMEProfile(
      item.id,
      input,
      keyFor({ action: "archive-acme-profile", id: item.id, input }),
    );
    if (!result.profile) throw new Error("未返回有效签发配置");
    profiles.value = profiles.value.map((value) =>
      value.id === item.id ? result.profile! : value,
    );
    if (selected.value === item.id)
      orders.value = await api.acmeOrders(item.id);
  }, "签发配置已停用");
}
async function showOrders(item: ACMEProfile) {
  if (busy.value) return;
  if (selected.value === item.id) {
    selected.value = "";
    orders.value = [];
    return;
  }
  await run(async () => {
    const result = await api.acmeOrders(item.id);
    orders.value = result;
    selected.value = item.id;
  });
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("签发配置有未保存内容，确认离开？"),
);
onMounted(() => {
  void load();
  timer = setInterval(() => {
    now.value = Date.now();
    if (!busy.value && profiles.value.some((item) => item.state === "issuing"))
      void run(async () => {
        profiles.value = await api.acmeProfiles(offset.value);
        if (selected.value) orders.value = await api.acmeOrders(selected.value);
      });
  }, 10000);
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
  window.removeEventListener("beforeunload", beforeUnload);
});
</script>

<template>
  <div class="toolbar">
    <div class="inline-gap">
      <router-link to="/certificates">返回证书</router-link
      ><router-link to="/acme">账户与 DNS 凭据</router-link
      ><router-link to="/tasks">查看任务</router-link>
    </div>
    <div class="inline-gap">
      <n-button :loading="busy" @click="load">刷新</n-button
      ><n-button
        type="primary"
        :disabled="busy || !accountOptions.length || !credentialOptions.length"
        @click="start"
        >添加签发配置</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" class="notice"
    >DNS-01 支持普通及通配域名。测试证书不受浏览器信任。签发后需在
    <router-link to="/nginx">Nginx 配置</router-link>
    中绑定证书版本、保存并应用；自动续期尚未启用。</n-alert
  >
  <n-alert
    v-if="!accountOptions.length || !credentialOptions.length"
    type="warning"
    :bordered="false"
    class="notice"
    >请先添加就绪的 ACME 账户及对应域名的 DNS 凭据。</n-alert
  >
  <section v-if="editing" class="surface notice">
    <n-form label-placement="top" :disabled="busy" @submit.prevent="create">
      <n-form-item label="名称"
        ><n-input v-model:value="form.name" :maxlength="128"
      /></n-form-item>
      <n-form-item label="备注"
        ><n-input v-model:value="form.notes" :maxlength="2048"
      /></n-form-item>
      <n-form-item label="ACME 账户与环境"
        ><n-select v-model:value="form.account_id" :options="accountOptions"
      /></n-form-item>
      <n-form-item label="DNS 凭据"
        ><n-select
          v-model:value="form.credential_id"
          :options="credentialOptions"
      /></n-form-item>
      <n-form-item label="申请域名（每行一项，最多 64 项）"
        ><n-input
          v-model:value="domainsText"
          type="textarea"
          :maxlength="16384"
          placeholder="example.com&#10;*.example.com"
      /></n-form-item>
      <div class="inline-gap">
        <n-button
          type="primary"
          attr-type="submit"
          :loading="busy"
          :disabled="!valid"
          >保存配置</n-button
        ><n-button :disabled="busy" @click="close">取消</n-button>
      </div>
    </n-form>
  </section>
  <n-empty v-if="!profiles.length && !editing" description="尚未添加签发配置" />
  <section v-for="item in profiles" :key="item.id" class="surface notice">
    <div class="section-heading">
      <div>
        <h2>{{ item.name }}</h2>
        <p class="muted">{{ item.notes }}</p>
      </div>
      <div class="inline-gap">
        <n-tag
          :bordered="false"
          :type="item.environment === 'production' ? 'warning' : 'default'"
          >{{ item.environment === "production" ? "正式" : "测试" }}</n-tag
        ><n-tag
          :bordered="false"
          :type="
            item.state === 'issued'
              ? 'success'
              : item.state === 'failed' || item.state === 'recovery_required'
                ? 'error'
                : 'default'
          "
          >{{ profileStates[item.state] }}</n-tag
        >
      </div>
    </div>
    <p class="domains">{{ item.domains.join("、") }}</p>
    <p v-if="item.last_error" class="error">{{ item.last_error }}</p>
    <p v-if="item.retry_after * 1000 > now" class="muted">
      允许重试时间：{{ date(item.retry_after) }}
    </p>
    <p v-if="item.certificate_id">
      <router-link to="/certificates">查看已签发证书</router-link>
    </p>
    <div class="inline-gap">
      <n-button
        v-if="item.state === 'idle'"
        type="primary"
        :disabled="!canIssue(item)"
        @click="issue(item, false)"
        >申请证书</n-button
      >
      <n-button
        v-if="
          item.current_order_id &&
          (item.state === 'failed' || item.state === 'recovery_required')
        "
        type="primary"
        :disabled="!canIssue(item)"
        @click="issue(item, false)"
        >恢复原订单</n-button
      >
      <n-button
        v-if="item.current_order_id && item.state !== 'archived'"
        :disabled="!canIssue(item)"
        @click="issue(item, true)"
        >申请新版本</n-button
      >
      <n-button :disabled="busy" @click="showOrders(item)">{{
        selected === item.id ? "收起订单" : "查看订单"
      }}</n-button>
      <n-button
        v-if="item.state !== 'archived'"
        type="error"
        :disabled="busy || item.state === 'issuing'"
        @click="archive(item)"
        >停用配置</n-button
      >
    </div>
    <div v-if="selected === item.id" class="orders">
      <n-empty v-if="!orders.length" description="尚无申请订单" />
      <article v-for="order in orders" :key="order.id" class="order">
        <div class="section-heading">
          <span>{{ date(order.created_at) }}</span
          ><n-tag :bordered="false">{{
            taskStates[order.state] ?? order.state
          }}</n-tag>
        </div>
        <p class="muted mono domains">订单 {{ order.id }}</p>
        <p v-if="order.last_error" class="error">{{ order.last_error }}</p>
        <p v-if="order.certificate_version_id" class="muted domains">
          已保存证书版本 {{ order.certificate_version_id }}
        </p>
        <p
          v-for="(record, index) in order.dns_records"
          :key="`${record.fqdn}:${index}`"
          class="domains"
        >
          {{ record.fqdn }} · {{ dnsStates[record.state] ?? record.state
          }}<span v-if="record.last_error" class="error">
            · {{ record.last_error }}</span
          >
        </p>
      </article>
    </div>
  </section>
  <div class="toolbar">
    <n-button :disabled="busy || offset === 0" @click="changePage(-1)"
      >上一页</n-button
    ><span class="muted">第 {{ offset / 100 + 1 }} 页</span
    ><n-button :disabled="busy || profiles.length < 100" @click="changePage(1)"
      >下一页</n-button
    >
  </div>
</template>

<style scoped>
.notice {
  margin-bottom: 20px;
}
.domains {
  overflow-wrap: anywhere;
}
.orders {
  margin-top: 20px;
}
.order {
  border-top: 1px solid #e8ecea;
  padding: 16px 0;
}
a {
  color: #246e54;
}
</style>
