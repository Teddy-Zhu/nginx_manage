<route lang="json">
{
  "meta": {
    "title": "申请证书",
    "subtitle": "申请、续期与签发记录",
    "nav": false,
    "parent": "/certificates"
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
  NModal,
  NCheckbox,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  type ACMEAccount,
  type ACMEProfile,
  type ACMEProfileInput,
  type ACMEPolicyInput,
  type ACMEOrder,
  type DNSCredential,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();

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
  challenge_type: "dns-01",
  http01_confirmed: false,
  domains: [],
});
const form = ref(emptyForm()),
  selected = ref(""),
  orders = ref<ACMEOrder[]>([]),
  now = ref(Date.now());
const formJSON = computed(() =>
  JSON.stringify([form.value, domainsText.value]),
);
const policyID = ref(""),
  policyName = ref("");
const policy = ref<ACMEPolicyInput>({
  base_version: 0,
  auto_renew: false,
  auto_deploy: false,
  reset_failures: false,
});
const policyBaseline = ref("");
const policyDirty = computed(
  () =>
    !!policyID.value && JSON.stringify(policy.value) !== policyBaseline.value,
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
    (form.value.challenge_type === "dns-01"
      ? !!form.value.credential_id
      : form.value.http01_confirmed &&
        !domains.value.some((domain) => domain.startsWith("*."))) &&
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
function changeChallengeType(value: unknown) {
  if (value !== "dns-01" && value !== "http-01") return;
  form.value.challenge_type = value;
  form.value.credential_id = "";
  form.value.http01_confirmed = false;
}
const http01States: Record<ACMEOrder["http01_state"], string> = {
  none: "尚未发布",
  unknown: "发布待确认",
  active: "验证材料有效",
  cleaned: "已清理",
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
function openPolicy(item: ACMEProfile) {
  policyID.value = item.id;
  policyName.value = item.name;
  policy.value = {
    base_version: item.version,
    auto_renew: item.auto_renew,
    auto_deploy: item.auto_deploy,
    reset_failures: false,
  };
  policyBaseline.value = JSON.stringify(policy.value);
}
function closePolicy() {
  if (
    busy.value ||
    (policyDirty.value && !window.confirm("调度策略尚未保存，确认取消？"))
  )
    return;
  policyID.value = "";
}
async function savePolicy() {
  if (busy.value || !policyID.value) return;
  const item = profiles.value.find((value) => value.id === policyID.value);
  const input = { ...policy.value };
  if (
    input.auto_deploy &&
    !item?.auto_deploy &&
    !window.confirm(
      "启用后将自动替换该证书的全部现有 TLS 绑定并应用 Nginx。测试证书仍不受浏览器信任。确认开启？",
    )
  )
    return;
  await run(async () => {
    await api.updateACMEPolicy(
      policyID.value,
      input,
      keyFor({ action: "acme-policy", id: policyID.value, input }),
    );
    policyID.value = "";
    profiles.value = await api.acmeProfiles(offset.value);
  }, "调度策略已保存");
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
  const uncertain =
    item.state === "recovery_required" || item.order_unconfirmed;
  const prompt = newOrder
    ? uncertain
      ? "原任务存在未确认结果，CA 可能已经接受订单。确认承担重复申请的限制，并建立新订单？"
      : "确认建立新订单并申请证书新版本？新版本签发后需另行绑定站点并应用。"
    : item.current_order_id
      ? "确认恢复原订单？将使用原订单密钥与验证方式，核对签发结果并清理临时验证材料。"
      : item.challenge_type === "http-01"
        ? "确认向所选 CA 申请证书并发布临时 HTTP 验证材料？验证期间暂不能执行 Nginx 配置操作。"
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
  const uncertain =
    item.state === "recovery_required" || item.order_unconfirmed;
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
  if (dirty.value || policyDirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () =>
    (!dirty.value && !policyDirty.value) ||
    window.confirm("签发配置有未保存内容，确认离开？"),
);
onMounted(() => {
  void load();
  timer = setInterval(() => {
    now.value = Date.now();
    if (
      !busy.value &&
      !policyID.value &&
      profiles.value.some(
        (item) =>
          item.state === "issuing" || item.auto_renew || item.auto_deploy,
      )
    )
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
        :disabled="busy || !accountOptions.length"
        @click="start"
        >添加签发配置</n-button
      >
    </div>
  </div>
  <n-alert type="info" :bordered="false" class="notice"
    >支持 DNS-01 和 HTTP-01；通配域名须使用
    DNS-01。测试证书不受浏览器信任。签发后需在
    <router-link to="/nginx">Nginx 配置</router-link>
    中建立初始绑定。可为每项配置启用自动续期与自动部署；签发与部署状态分别记录。</n-alert
  >
  <n-alert
    v-if="!accountOptions.length"
    type="warning"
    :bordered="false"
    class="notice"
    >请先添加并完成 ACME 账户注册。</n-alert
  >
  <n-modal
    :show="!!policyID"
    preset="card"
    :title="`${policyName} · 调度策略`"
    style="width: 560px; max-width: 94vw"
    :mask-closable="false"
    :close-on-esc="false"
    :closable="false"
  >
    <n-form label-placement="top" :disabled="busy" @submit.prevent="savePolicy">
      <n-form-item
        ><n-checkbox v-model:checked="policy.auto_renew"
          >自动续期</n-checkbox
        ></n-form-item
      >
      <p class="muted">
        优先采用 CA
        建议窗口，无法获取时按证书实际寿命调度。连续失败六次或结果不确定时暂停，保留原证书。
      </p>
      <n-form-item
        ><n-checkbox v-model:checked="policy.auto_deploy"
          >签发后自动部署到现有绑定</n-checkbox
        ></n-form-item
      >
      <p class="muted">
        首次绑定须手动完成。有待应用配置时等待处理；应用失败后须检查任务并人工恢复。
      </p>
      <p class="muted">关闭策略仅停止后续调度，已排队任务继续执行。</p>
      <n-form-item
        ><n-checkbox v-model:checked="policy.reset_failures"
          >重置续期失败次数并恢复调度</n-checkbox
        ></n-form-item
      >
      <div class="inline-gap">
        <n-button type="primary" attr-type="submit" :loading="busy"
          >保存策略</n-button
        ><n-button :disabled="busy" @click="closePolicy">取消</n-button>
      </div>
    </n-form>
  </n-modal>
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
      <n-form-item label="验证方式">
        <n-select
          :value="form.challenge_type"
          :options="[
            { label: 'DNS-01', value: 'dns-01' },
            { label: 'HTTP-01', value: 'http-01' },
          ]"
          @update:value="changeChallengeType"
        />
      </n-form-item>
      <n-alert
        v-if="form.challenge_type === 'http-01'"
        type="info"
        :bordered="false"
        class="notice"
      >
        请先在
        <router-link to="/nginx">Nginx 配置</router-link> 中为全部申请域名启用
        80 端口和 HTTP-01 验证入口，并保存、应用。公网 A/AAAA 应指向本节点，80
        端口须可达；存在多个入口时每个入口均须响应验证。实际可达性由 CA 验证。
      </n-alert>
      <n-form-item v-if="form.challenge_type === 'http-01'">
        <n-checkbox v-model:checked="form.http01_confirmed"
          >已确认公网 80 端口可达及域名指向</n-checkbox
        >
      </n-form-item>
      <n-form-item v-if="form.challenge_type === 'dns-01'" label="DNS 凭据"
        ><n-select
          v-model:value="form.credential_id"
          :options="credentialOptions"
      /></n-form-item>
      <n-form-item label="申请域名（每行一项，最多 64 项）"
        ><n-input
          v-model:value="domainsText"
          type="textarea"
          :maxlength="16384"
          :placeholder="
            form.challenge_type === 'dns-01'
              ? 'example.com\n*.example.com'
              : 'example.com\nwww.example.com'
          "
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
        <p class="muted">{{ item.challenge_type.toUpperCase() }}</p>
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
    <p class="muted">
      自动续期：{{
        item.auto_renew ? (item.renewal.paused ? "已暂停" : "已启用") : "已关闭"
      }}
      · 自动部署：{{ item.auto_deploy ? "已启用" : "已关闭" }}
    </p>
    <p v-if="item.renewal.renew_at" class="muted">
      {{ item.auto_renew ? "计划续期" : "续期窗口参考" }}：{{
        date(item.renewal.renew_at)
      }}（{{ item.renewal.source === "ari" ? "CA 建议" : "实际寿命" }}）
    </p>
    <p
      v-if="
        item.auto_renew && !item.renewal.paused && item.renewal.next_check_at
      "
      class="muted"
    >
      下次 ARI 检查：{{ date(item.renewal.next_check_at) }}
    </p>
    <p v-if="item.renewal.last_error" class="muted">
      {{ item.renewal.last_error }}
    </p>
    <p v-if="item.renewal.failures" class="muted">
      连续续期失败：{{ item.renewal.failures }} 次{{
        item.renewal.paused ? "，须检查原因并恢复调度" : ""
      }}
    </p>
    <p v-if="item.renewal.explanation_url">
      <a
        :href="item.renewal.explanation_url"
        target="_blank"
        rel="noopener noreferrer"
        >CA 续期窗口说明</a
      >
    </p>
    <p v-if="item.deployment_error" class="error">
      自动部署：{{ item.deployment_error }}
    </p>
    <p v-if="item.certificate_id" class="inline-gap">
      <router-link to="/certificates">查看已签发证书</router-link>
      <router-link
        :to="{
          path: '/certificate-deployments',
          query: { certificate: item.certificate_id },
        }"
        >部署与绑定状态</router-link
      >
    </p>
    <div class="inline-gap">
      <n-button
        v-if="item.state !== 'archived'"
        :disabled="busy"
        @click="openPolicy(item)"
        >调度策略</n-button
      >
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
        <p v-if="order.terminal" class="muted">
          CA
          已确认订单失效；若有未清理材料，请先恢复原任务完成清理，再创建新订单。
        </p>
        <p v-if="order.challenge_type === 'http-01'" class="muted">
          HTTP-01 · {{ http01States[order.http01_state]
          }}<span v-if="order.http01_expires_at">
            · 到期时间 {{ date(order.http01_expires_at) }}</span
          >
        </p>
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
