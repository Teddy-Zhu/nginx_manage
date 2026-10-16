<route lang="json">
{
  "meta": {
    "title": "ACME 设置",
    "subtitle": "账户注册与 DNS 验证凭据",
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
  NCheckbox,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NTabPane,
  NTabs,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  type ACMEAccount,
  type ACMEAccountInput,
  type DNSCredential,
  type DNSCredentialInput,
  type DNSProvider,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();

const { busy, run, message } = useAction(),
  keyFor = useIdempotency();
const accounts = ref<ACMEAccount[]>([]),
  credentials = ref<DNSCredential[]>([]),
  providers = ref<DNSProvider[]>([]);
const accountEditing = ref(false),
  accountForm = ref<ACMEAccountInput>({
    name: "",
    email: "",
    environment: "staging",
    terms_agreed: false,
  });
const accountBaseline = ref("");
const accountDirty = computed(
  () =>
    accountEditing.value &&
    JSON.stringify(accountForm.value) !== accountBaseline.value,
);
const credentialEditing = ref(false),
  originalCredential = ref<DNSCredential | null>(null),
  credentialName = ref("");
const provider = ref<DNSCredentialInput["provider"]>("cloudflare"),
  secrets = ref<Record<string, string>>({}),
  replaceSecrets = ref(true),
  credentialBaseline = ref("");
const credentialFormJSON = computed(() =>
  JSON.stringify([
    credentialName.value,
    provider.value,
    replaceSecrets.value,
    secrets.value,
  ]),
);
const credentialDirty = computed(
  () =>
    credentialEditing.value &&
    credentialFormJSON.value !== credentialBaseline.value,
);
const dirty = computed(() => accountDirty.value || credentialDirty.value);
const fields = computed(
  () =>
    providers.value.find((item) => item.id === provider.value)?.fields ?? [],
);
const providerOptions = computed(() =>
  providers.value.map((item) => ({ label: item.name, value: item.id })),
);
const validCredential = computed(
  () =>
    credentialName.value.trim() &&
    fields.value.length &&
    (!replaceSecrets.value ||
      fields.value.every(
        (field) => !field.required || !!secrets.value[field.key]?.trim(),
      )),
);
const now = ref(Date.now());
let timer: ReturnType<typeof setInterval> | undefined;
const states: Record<ACMEAccount["state"], string> = {
  pending: "待注册",
  registering: "正在核对",
  ready: "已就绪",
  failed: "注册失败",
};
const date = (value: number) => new Date(value * 1000).toLocaleString();
const activeAccount = (item: ACMEAccount) =>
  item.state === "pending" || item.state === "registering";
const providerName = (id: string) =>
  providers.value.find((item) => item.id === id)?.name ?? id;

async function load() {
  await run(async () => {
    const [a, c, p] = await Promise.all([
      api.acmeAccounts(),
      api.dnsCredentials(),
      api.dnsProviders(),
    ]);
    accounts.value = a;
    credentials.value = c;
    providers.value = p;
  });
}
function startAccount() {
  if (
    busy.value ||
    (accountDirty.value && !window.confirm("账户信息尚未保存，确认重新填写？"))
  )
    return;
  accountForm.value = {
    name: "",
    email: "",
    environment: "staging",
    terms_agreed: false,
  };
  accountBaseline.value = JSON.stringify(accountForm.value);
  accountEditing.value = true;
}
function closeAccount() {
  if (
    busy.value ||
    (accountDirty.value && !window.confirm("账户信息尚未保存，确认取消？"))
  )
    return;
  accountEditing.value = false;
  accountForm.value = {
    name: "",
    email: "",
    environment: "staging",
    terms_agreed: false,
  };
}
async function createAccount() {
  if (busy.value || !accountForm.value.terms_agreed) return;
  const input = { ...accountForm.value };
  await run(async () => {
    const out = await api.createACMEAccount(
      input,
      keyFor({ action: "create-acme-account", input }),
    );
    if (!out.account || !out.task_id) throw new Error("账户注册未返回有效任务");
    accounts.value.push(out.account);
    accountEditing.value = false;
    accountForm.value = {
      name: "",
      email: "",
      environment: "staging",
      terms_agreed: false,
    };
  }, "账户注册已排队，可在任务中查看结果");
}
async function retryAccount(item: ACMEAccount) {
  if (
    busy.value ||
    item.state !== "failed" ||
    item.retry_after * 1000 > now.value
  )
    return;
  if (
    !window.confirm(
      "确认已阅读并同意 Let's Encrypt 当前服务条款，并使用原账户密钥重试？",
    )
  )
    return;
  await run(async () => {
    const out = await api.registerACMEAccount(
      item.id,
      item.version,
      keyFor({
        action: "register-acme-account",
        id: item.id,
        version: item.version,
      }),
    );
    if (!out.account) throw new Error("账户核对未返回有效资源");
    accounts.value = accounts.value.map((value) =>
      value.id === item.id ? out.account! : value,
    );
  }, "账户核对已排队");
}
async function removeAccount(item: ACMEAccount) {
  if (
    busy.value ||
    activeAccount(item) ||
    !window.confirm(
      `确认移除 ${item.name} 的本机账户记录和密钥？此操作不会注销 CA 端账户。`,
    )
  )
    return;
  await run(async () => {
    await api.deleteACMEAccount(
      item.id,
      item.version,
      keyFor({
        action: "delete-acme-account",
        id: item.id,
        version: item.version,
      }),
    );
    accounts.value = accounts.value.filter((value) => value.id !== item.id);
  }, "本机账户记录已移除");
}
function startCredential(item: DNSCredential | null) {
  if (
    busy.value ||
    (credentialDirty.value &&
      !window.confirm("凭据修改尚未保存，确认重新填写？"))
  )
    return;
  const id = item?.provider ?? "cloudflare";
  if (id !== "cloudflare" && id !== "alidns" && id !== "tencentcloud") {
    message.error("此 DNS 提供商暂不支持编辑");
    return;
  }
  originalCredential.value = item;
  credentialName.value = item?.name ?? "";
  provider.value = id;
  replaceSecrets.value = !item;
  secrets.value = {};
  credentialBaseline.value = credentialFormJSON.value;
  credentialEditing.value = true;
}
function clearCredential() {
  credentialEditing.value = false;
  secrets.value = {};
  credentialName.value = "";
  originalCredential.value = null;
  credentialBaseline.value = "";
}
function closeCredential() {
  if (
    busy.value ||
    (credentialDirty.value && !window.confirm("凭据修改尚未保存，确认取消？"))
  )
    return;
  clearCredential();
}
function changeProvider() {
  secrets.value = {};
}
function changeReplace(value: boolean) {
  if (!value) secrets.value = {};
}
async function saveCredential() {
  if (busy.value || !validCredential.value) return;
  const id = originalCredential.value?.id ?? null;
  const input: DNSCredentialInput = {
    base_version: originalCredential.value?.version ?? 0,
    name: credentialName.value,
    provider: provider.value,
  };
  if (replaceSecrets.value)
    input.secrets = Object.fromEntries(
      fields.value
        .filter((field) => !!secrets.value[field.key])
        .map((field) => [field.key, secrets.value[field.key]!]),
    );
  await run(async () => {
    const bytes = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(JSON.stringify(input)),
    );
    const digest = Array.from(new Uint8Array(bytes), (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
    const out = await api.saveDNSCredential(
      id,
      input,
      keyFor({ action: "save-dns-credential", id, digest }),
    );
    if (!out.credential) throw new Error("凭据保存未返回有效资源");
    credentials.value = [
      ...credentials.value.filter((item) => item.id !== out.credential!.id),
      out.credential,
    ];
    clearCredential();
  }, "DNS 凭据已保存");
}
async function removeCredential(item: DNSCredential) {
  if (busy.value || !window.confirm(`确认删除 DNS 凭据 ${item.name}？`)) return;
  await run(async () => {
    await api.deleteDNSCredential(
      item.id,
      item.version,
      keyFor({
        action: "delete-dns-credential",
        id: item.id,
        version: item.version,
      }),
    );
    credentials.value = credentials.value.filter(
      (value) => value.id !== item.id,
    );
    if (originalCredential.value?.id === item.id) clearCredential();
  }, "DNS 凭据已删除");
}
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value) event.preventDefault();
};
onBeforeRouteLeave(
  () => !dirty.value || window.confirm("ACME 设置有未保存内容，确认离开？"),
);
onMounted(() => {
  void load();
  timer = setInterval(() => {
    now.value = Date.now();
    if (
      !busy.value &&
      !accountEditing.value &&
      !credentialEditing.value &&
      accounts.value.some(activeAccount)
    )
      void run(async () => {
        accounts.value = await api.acmeAccounts();
      });
  }, 10000);
  window.addEventListener("beforeunload", beforeUnload);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
  secrets.value = {};
  window.removeEventListener("beforeunload", beforeUnload);
});
</script>

<template>
  <div class="toolbar">
    <router-link to="/certificates">返回证书</router-link>
    <div class="inline-gap">
      <router-link to="/certificate-requests">ACME 签发</router-link>
      <router-link to="/tasks">查看任务</router-link
      ><n-button :loading="busy" @click="load">刷新</n-button>
    </div>
  </div>
  <n-tabs type="line" animated>
    <n-tab-pane name="accounts" tab="ACME 账户">
      <n-alert type="info" :bordered="false"
        >测试与正式环境使用独立账户。测试环境证书不受浏览器信任。<a
          href="https://letsencrypt.org/repository/"
          target="_blank"
          rel="noopener noreferrer"
          >查看 Let's Encrypt 服务条款</a
        ></n-alert
      >
      <div class="toolbar" style="margin-top: 20px">
        <span class="muted">{{ accounts.length }} 个账户</span
        ><n-button type="primary" :disabled="busy" @click="startAccount"
          >添加账户</n-button
        >
      </div>
      <section
        v-if="accountEditing"
        class="surface"
        style="margin-bottom: 20px"
      >
        <n-form
          label-placement="top"
          :disabled="busy"
          @submit.prevent="createAccount"
        >
          <n-form-item label="名称"
            ><n-input v-model:value="accountForm.name" :maxlength="128"
          /></n-form-item>
          <n-form-item label="邮箱"
            ><n-input
              v-model:value="accountForm.email"
              :maxlength="254"
              :input-props="{ type: 'email', autocomplete: 'email' }"
          /></n-form-item>
          <n-form-item label="CA 环境"
            ><n-select
              v-model:value="accountForm.environment"
              :options="[
                { label: 'Let’s Encrypt Staging（测试）', value: 'staging' },
                {
                  label: 'Let’s Encrypt Production（正式）',
                  value: 'production',
                },
              ]"
          /></n-form-item>
          <n-form-item
            ><n-checkbox v-model:checked="accountForm.terms_agreed"
              >已阅读并同意 Let's Encrypt 当前服务条款</n-checkbox
            ></n-form-item
          >
          <div class="inline-gap">
            <n-button
              type="primary"
              attr-type="submit"
              :loading="busy"
              :disabled="
                !accountForm.name.trim() ||
                !accountForm.email.trim() ||
                !accountForm.terms_agreed
              "
              >注册账户</n-button
            ><n-button :disabled="busy" @click="closeAccount">取消</n-button>
          </div>
        </n-form>
      </section>
      <n-empty
        v-if="!accounts.length && !accountEditing"
        description="尚未添加 ACME 账户"
      />
      <section
        v-for="item in accounts"
        :key="item.id"
        class="surface account-card"
      >
        <div class="section-heading">
          <div>
            <h2>{{ item.name }}</h2>
            <p class="muted">{{ item.email }}</p>
          </div>
          <div class="inline-gap">
            <n-tag
              :bordered="false"
              :type="item.environment === 'production' ? 'warning' : 'default'"
              >{{ item.environment === "production" ? "正式" : "测试" }}</n-tag
            ><n-tag
              :bordered="false"
              :type="
                item.state === 'ready'
                  ? 'success'
                  : item.state === 'failed'
                    ? 'error'
                    : 'default'
              "
              >{{ states[item.state] }}</n-tag
            >
          </div>
        </div>
        <p v-if="item.last_error" class="error">{{ item.last_error }}</p>
        <p
          v-if="item.state === 'failed' && item.retry_after * 1000 > now"
          class="muted"
        >
          允许重试时间：{{ date(item.retry_after) }}
        </p>
        <p class="muted mono fingerprint">
          公钥 SHA-256：{{ item.key_fingerprint }}
        </p>
        <p v-if="item.account_url" class="muted fingerprint">
          账户：{{ item.account_url }}
        </p>
        <div class="inline-gap">
          <n-button
            v-if="item.state === 'failed'"
            :disabled="busy || item.retry_after * 1000 > now"
            @click="retryAccount(item)"
            >重试注册</n-button
          ><n-button
            type="error"
            :disabled="busy || activeAccount(item)"
            @click="removeAccount(item)"
            >移除本机账户</n-button
          >
        </div>
      </section>
    </n-tab-pane>
    <n-tab-pane name="credentials" tab="DNS 凭据">
      <n-alert type="info" :bordered="false"
        >凭据字段保存后不回显。保存仅核对字段，DNS API
        权限及域名访问需在验证任务中确认。</n-alert
      >
      <div class="toolbar" style="margin-top: 20px">
        <span class="muted">{{ credentials.length }} 组凭据</span
        ><n-button
          type="primary"
          :disabled="busy || !providers.length"
          @click="startCredential(null)"
          >添加凭据</n-button
        >
      </div>
      <section
        v-if="credentialEditing"
        class="surface"
        style="margin-bottom: 20px"
      >
        <n-form
          label-placement="top"
          :disabled="busy"
          @submit.prevent="saveCredential"
        >
          <n-form-item label="名称"
            ><n-input v-model:value="credentialName" :maxlength="128"
          /></n-form-item>
          <n-form-item label="DNS 提供商"
            ><n-select
              v-model:value="provider"
              :options="providerOptions"
              :disabled="!!originalCredential || busy"
              @update:value="changeProvider"
          /></n-form-item>
          <n-form-item v-if="originalCredential"
            ><n-checkbox
              v-model:checked="replaceSecrets"
              @update:checked="changeReplace"
              >替换凭据全部字段</n-checkbox
            ></n-form-item
          >
          <template v-if="replaceSecrets"
            ><n-form-item
              v-for="field in fields"
              :key="field.key"
              :label="field.label"
              :required="field.required"
              ><n-input
                v-model:value="secrets[field.key]"
                type="password"
                show-password-on="click"
                :maxlength="2048"
                :input-props="{
                  autocomplete: 'new-password',
                  spellcheck: false,
                }" /></n-form-item
          ></template>
          <p v-else class="muted">保留已保存的凭据字段。</p>
          <div class="inline-gap">
            <n-button
              type="primary"
              attr-type="submit"
              :loading="busy"
              :disabled="!validCredential"
              >保存凭据</n-button
            ><n-button :disabled="busy" @click="closeCredential">取消</n-button>
          </div>
        </n-form>
      </section>
      <n-empty
        v-if="!credentials.length && !credentialEditing"
        description="尚未添加 DNS 凭据"
      />
      <section
        v-for="item in credentials"
        :key="item.id"
        class="surface account-card"
      >
        <div class="section-heading">
          <div>
            <h2>{{ item.name }}</h2>
            <p class="muted">
              {{ providerName(item.provider) }} · 版本 {{ item.version }}
            </p>
          </div>
          <div class="inline-gap">
            <n-button :disabled="busy" @click="startCredential(item)"
              >编辑</n-button
            ><n-button
              type="error"
              :disabled="busy"
              @click="removeCredential(item)"
              >删除</n-button
            >
          </div>
        </div>
        <p class="muted">
          已配置字段：{{
            item.field_names
              .map(
                (key) =>
                  providers
                    .find((value) => value.id === item.provider)
                    ?.fields.find((field) => field.key === key)?.label ?? key,
              )
              .join("、")
          }}
        </p>
      </section>
    </n-tab-pane>
  </n-tabs>
</template>

<style scoped>
.account-card {
  margin-bottom: 16px;
}
.fingerprint {
  overflow-wrap: anywhere;
}
a {
  color: #246e54;
}
</style>
