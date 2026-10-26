<route lang="json">
{
  "meta": {
    "title": "申请与续期",
    "subtitle": "申请、续期与签发记录",
    "nav": false,
    "parent": "/certificates"
  }
}
</route>

<script setup lang="ts">
import CertificateWorkspace from "../components/CertificateWorkspace.vue";
import { inspectTask } from "../stores/operation";
import { useRoute, useRouter } from "vue-router";
import { useLiveRefresh } from "../composables/live";
import ValueListInput from "../components/ValueListInput.vue";
import { cleanList } from "../utils/form";
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
const route = useRoute(),
  router = useRouter();
const loaded = ref(false);
const visibleProfiles = computed(() =>
  typeof route.query.certificate === "string"
    ? profiles.value.filter(
        (item) => item.certificate_id === route.query.certificate,
      )
    : profiles.value,
);
const selectedAccount = computed(() =>
  accounts.value.find((item) => item.id === form.value.account_id),
);

const { busy, run } = useAction(),
  keyFor = useIdempotency();
const profiles = ref<ACMEProfile[]>([]),
  accounts = ref<ACMEAccount[]>([]),
  credentials = ref<DNSCredential[]>([]);
const offset = ref(0);
const editing = ref(false),
  domainEntries = ref<string[]>([]),
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
  JSON.stringify([form.value, domainEntries.value]),
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
const domains = computed(() => cleanList(domainEntries.value));
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
    loaded.value = true;
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
    (policyDirty.value && !window.confirm("续期设置尚未保存，确认取消？"))
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
  }, "续期设置已保存");
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
    (dirty.value && !window.confirm("证书申请尚未提交，确认重新填写？"))
  )
    return;
  form.value = emptyForm();
  form.value.account_id =
    accounts.value.find(
      (item) => item.state === "ready" && item.environment === "production",
    )?.id ??
    accountOptions.value[0]?.value ??
    "";
  form.value.credential_id =
    credentials.value.length === 1 ? credentials.value[0]!.id : "";
  domainEntries.value = [];
  baseline.value = formJSON.value;
  editing.value = true;
  void router.replace({
    query: { ...route.query, new: undefined, certificate: undefined },
  });
}
function close() {
  if (
    busy.value ||
    (dirty.value && !window.confirm("证书申请尚未提交，确认取消？"))
  )
    return;
  editing.value = false;
  form.value = emptyForm();
  domainEntries.value = [];
}
async function create() {
  if (busy.value || !valid.value) return;
  const input = { ...form.value, domains: domains.value };
  await run(async () => {
    const result = await api.createACMEProfile(
      input,
      keyFor({ action: "create-acme-profile", input }),
    );
    if (!result.profile) throw new Error("未返回有效申请信息");
    const profile = result.profile;
    editing.value = false;
    form.value = emptyForm();
    domainEntries.value = [];
    offset.value = 0;
    selected.value = "";
    orders.value = [];
    profiles.value = [
      profile,
      ...profiles.value.filter((item) => item.id !== profile.id),
    ].slice(0, 100);
    const issueInput = {
      base_version: profile.version,
      new_order: false,
      acknowledge_uncertain: false,
    };
    const issued = await api.issueACMEProfile(
      profile.id,
      issueInput,
      keyFor({
        action: "issue-acme-profile",
        id: profile.id,
        input: issueInput,
      }),
    );
    if (!issued.profile || !issued.task_id)
      throw new Error("申请未返回有效任务，可在记录中继续申请");
    profiles.value = profiles.value.map((item) =>
      item.id === profile.id ? issued.profile! : item,
    );
  }, "证书申请已提交，可查看日志和申请进度");
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
    window.confirm("证书申请有未保存内容，确认离开？"),
);
onMounted(() => {
  void load().then(() => {
    if (loaded.value && route.query.new === "1" && accountOptions.value.length)
      start();
  });
  timer = setInterval(() => {
    now.value = Date.now();
  }, 10000);
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
  window.removeEventListener("beforeunload", beforeUnload);
});
useLiveRefresh(api, ["tasks"], () => {
  if (!busy.value && !policyID.value)
    return run(async () => {
      profiles.value = await api.acmeProfiles(offset.value);
      if (selected.value) orders.value = await api.acmeOrders(selected.value);
    });
});
</script>

<template>
  <CertificateWorkspace>
    <div class="cert-heading">
      <div>
        <h2>申请与续期</h2>
        <p class="muted">申请免费证书，并设置到期前自动续期。</p>
      </div>
      <div class="cert-actions">
        <n-button :loading="busy" @click="load">刷新</n-button
        ><n-button
          type="primary"
          :disabled="busy || !accountOptions.length || editing"
          @click="start"
          >申请证书</n-button
        >
      </div>
    </div>
    <section
      v-if="loaded && !accountOptions.length"
      class="surface cert-section"
    >
      <h2>先添加申请账户</h2>
      <p class="muted">
        填写联系邮箱并注册账户后，即可申请证书。已有证书可以直接导入。
      </p>
      <div class="cert-actions">
        <router-link
          :to="{ path: '/acme', query: { tab: 'accounts', from: 'request' } }"
          ><n-button type="primary">添加申请账户</n-button></router-link
        ><router-link to="/certificates">导入已有证书</router-link>
      </div>
    </section>
    <section
      v-else-if="loaded && !editing && !profiles.length"
      class="surface cert-section"
    >
      <h2>申请准备已就绪</h2>
      <p class="muted">
        填写域名并选择验证方式后提交申请。通配域名需要 DNS 授权。
      </p>
      <div v-if="!credentials.length" class="cert-actions">
        <router-link
          :to="{
            path: '/acme',
            query: { tab: 'credentials', from: 'request' },
          }"
          >添加 DNS 授权</router-link
        ><span class="muted">也可在申请时选择网站验证。</span>
      </div>
    </section>
    <section v-if="editing" class="surface cert-section">
      <div>
        <h2>申请新证书</h2>
        <p class="muted">提交后开始验证域名，申请结果会显示在下方记录中。</p>
      </div>
      <n-form label-placement="top" :disabled="busy" @submit.prevent="create">
        <div class="cert-form-grid">
          <n-form-item label="证书名称" required
            ><n-input
              v-model:value="form.name"
              :maxlength="128"
              placeholder="便于识别，例如：公司网站"
          /></n-form-item>
          <n-form-item label="申请账户" required
            ><n-select
              v-model:value="form.account_id"
              :options="accountOptions"
          /></n-form-item>
        </div>
        <n-alert
          v-if="selectedAccount?.environment === 'staging'"
          type="warning"
          :bordered="false"
          class="form-notice"
          >此账户用于测试，申请的证书不受浏览器信任。正式网站请选择正式账户。</n-alert
        >
        <n-form-item label="验证方式"
          ><n-select
            :value="form.challenge_type"
            :options="[
              { label: 'DNS 验证（支持通配域名）', value: 'dns-01' },
              { label: '网站验证（需要公网 80 端口）', value: 'http-01' },
            ]"
            @update:value="changeChallengeType"
        /></n-form-item>
        <template v-if="form.challenge_type === 'dns-01'">
          <n-form-item label="DNS 授权" required
            ><n-select
              v-model:value="form.credential_id"
              :options="credentialOptions"
              placeholder="选择域名所在服务商的授权"
          /></n-form-item>
          <n-alert
            v-if="!credentialOptions.length"
            type="warning"
            :bordered="false"
            class="form-notice"
            >尚未添加 DNS 授权，请先前往
            <router-link
              :to="{
                path: '/acme',
                query: { tab: 'credentials', from: 'request' },
              }"
              >申请设置</router-link
            >
            添加，或改用网站验证。</n-alert
          >
          <p v-else class="muted form-notice">
            申请时会临时添加域名验证记录，完成后自动清理。
          </p>
        </template>
        <template v-else>
          <n-alert type="info" :bordered="false" class="form-notice"
            >域名需指向这台服务器，公网 80 端口需可访问，并在
            <router-link to="/nginx">网站与代理</router-link>
            中启用域名验证入口。通配域名请改用 DNS 验证。</n-alert
          >
          <n-form-item
            ><n-checkbox v-model:checked="form.http01_confirmed"
              >已配置网站验证入口，并确认域名指向及公网 80
              端口可访问</n-checkbox
            ></n-form-item
          >
        </template>
        <n-form-item label="申请域名" required
          ><ValueListInput
            v-model:value="domainEntries"
            item-label="域名"
            :max="64"
            :maxlength="253"
            :placeholder="
              form.challenge_type === 'dns-01'
                ? 'example.com 或 *.example.com'
                : 'example.com'
            "
        /></n-form-item>
        <n-form-item label="备注（选填）"
          ><n-input v-model:value="form.notes" :maxlength="2048"
        /></n-form-item>
        <div class="cert-form-footer">
          <n-button
            type="primary"
            attr-type="submit"
            :loading="busy"
            :disabled="!valid"
            >提交申请</n-button
          ><n-button :disabled="busy" @click="close">取消</n-button>
        </div>
      </n-form>
    </section>
    <div class="cert-heading">
      <h2>申请记录</h2>
      <router-link v-if="route.query.certificate" to="/certificate-requests"
        >查看全部申请</router-link
      >
    </div>
    <n-empty
      v-if="!visibleProfiles.length"
      class="surface cert-empty"
      :description="
        route.query.certificate
          ? '本页没有此证书的申请记录'
          : '还没有证书申请记录'
      "
    />
    <section
      v-for="item in visibleProfiles"
      :key="item.id"
      class="surface cert-section"
    >
      <div class="cert-heading">
        <div>
          <h2>{{ item.name }}</h2>
          <p v-if="item.notes" class="muted">{{ item.notes }}</p>
        </div>
        <div class="cert-actions">
          <n-tag
            :bordered="false"
            :type="item.environment === 'staging' ? 'warning' : 'default'"
            >{{
              item.environment === "production" ? "正式证书" : "测试证书"
            }}</n-tag
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
      <div class="cert-actions">
        <n-tag v-for="domain in item.domains" :key="domain" size="small">{{
          domain
        }}</n-tag>
      </div>
      <p v-if="item.last_error" class="error">{{ item.last_error }}</p>
      <p v-if="item.retry_after * 1000 > now" class="muted">
        可重试时间：{{ date(item.retry_after) }}
      </p>
      <div class="cert-notice">
        <p class="muted">
          {{ item.challenge_type === "dns-01" ? "DNS 验证" : "网站验证" }} ·
          自动续期{{
            item.auto_renew
              ? item.renewal.paused
                ? "已暂停"
                : "已开启"
              : "未开启"
          }}
          · 续期后更新网站{{ item.auto_deploy ? "已开启" : "未开启" }}
        </p>
        <p v-if="item.auto_renew && item.renewal.renew_at" class="muted">
          预计续期：{{ date(item.renewal.renew_at) }}
        </p>
        <p v-if="item.renewal.last_error" class="error">
          续期：{{ item.renewal.last_error }}
        </p>
        <p v-if="item.renewal.paused" class="muted">
          自动续期已暂停，请查看日志，处理后在续期设置中恢复。
        </p>
        <p v-if="item.deployment_error" class="error">
          网站证书更新：{{ item.deployment_error }}
        </p>
      </div>
      <div class="cert-actions">
        <n-button
          v-if="
            item.state === 'idle' ||
            item.state === 'failed' ||
            item.state === 'recovery_required'
          "
          type="primary"
          :disabled="!canIssue(item)"
          @click="issue(item, false)"
          >{{
            item.state === "idle"
              ? "继续申请"
              : item.current_order_id
                ? "继续原申请"
                : "重试申请"
          }}</n-button
        >
        <router-link
          v-if="item.certificate_id"
          :to="{
            path: '/certificates',
            query: { certificate: item.certificate_id },
          }"
          ><n-button>查看证书</n-button></router-link
        >
        <router-link
          v-if="item.certificate_id"
          :to="{
            path: '/certificate-deployments',
            query: { certificate: item.certificate_id },
          }"
          ><n-button>用于网站</n-button></router-link
        >
        <n-button
          v-if="item.state !== 'archived'"
          :disabled="busy"
          @click="openPolicy(item)"
          >续期设置</n-button
        >
        <n-button
          v-if="item.current_order_id && item.state !== 'archived'"
          :disabled="!canIssue(item)"
          @click="issue(item, true)"
          >重新申请</n-button
        >
        <n-button :disabled="busy" @click="showOrders(item)">{{
          selected === item.id ? "收起记录" : "申请详情"
        }}</n-button>
        <n-button
          v-if="item.state !== 'archived'"
          quaternary
          type="error"
          :disabled="busy || item.state === 'issuing'"
          @click="archive(item)"
          >停用申请</n-button
        >
      </div>
      <div v-if="selected === item.id">
        <n-empty v-if="!orders.length" description="尚无执行记录" />
        <article v-for="order in orders" :key="order.id" class="cert-record">
          <div class="cert-heading">
            <span>{{ date(order.created_at) }}</span
            ><n-tag :bordered="false">{{
              taskStates[order.state] ?? "处理中"
            }}</n-tag>
          </div>
          <p v-if="order.last_error" class="error">{{ order.last_error }}</p>
          <p v-if="order.terminal" class="muted">
            本次验证已结束，未完成清理时请继续原申请。
          </p>
          <p v-if="order.certificate_version_id" class="muted">
            证书已保存，可前往“我的证书”查看。
          </p>
          <n-button
            v-if="order.task_id"
            quaternary
            @click="inspectTask(order.task_id, '证书申请日志')"
            >查看日志</n-button
          >
        </article>
      </div>
    </section>
    <div v-if="offset || profiles.length >= 100" class="cert-heading">
      <n-button :disabled="busy || offset === 0" @click="changePage(-1)"
        >上一页</n-button
      ><span class="muted">第 {{ offset / 100 + 1 }} 页</span
      ><n-button
        :disabled="busy || profiles.length < 100"
        @click="changePage(1)"
        >下一页</n-button
      >
    </div>
    <n-modal
      :show="!!policyID"
      preset="card"
      :title="`${policyName} · 续期设置`"
      style="width: 560px; max-width: 94vw"
      :mask-closable="false"
      :close-on-esc="false"
      :closable="false"
    >
      <n-form
        label-placement="top"
        :disabled="busy"
        @submit.prevent="savePolicy"
      >
        <n-form-item
          ><n-checkbox v-model:checked="policy.auto_renew"
            >到期前自动续期</n-checkbox
          ></n-form-item
        >
        <p class="muted form-notice">
          按证书到期时间自动申请续期；连续失败时暂停并保留原证书。
        </p>
        <n-form-item
          ><n-checkbox v-model:checked="policy.auto_deploy"
            >续期后自动更新已使用此证书的网站</n-checkbox
          ></n-form-item
        >
        <p class="muted form-notice">
          首次使用需在网站设置中选择证书并应用。关闭后，网站证书需手动更新。
        </p>
        <n-form-item
          ><n-checkbox v-model:checked="policy.reset_failures"
            >清除失败记录并恢复自动续期</n-checkbox
          ></n-form-item
        >
        <div class="cert-form-footer">
          <n-button type="primary" attr-type="submit" :loading="busy"
            >保存设置</n-button
          ><n-button :disabled="busy" @click="closePolicy">取消</n-button>
        </div>
      </n-form>
    </n-modal>
  </CertificateWorkspace>
</template>
<style scoped>
.form-notice {
  margin-bottom: 18px;
}
</style>
