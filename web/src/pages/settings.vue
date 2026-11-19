<route lang="json">
{
  "meta": {
    "title": "面板设置",
    "nav": true,
    "localOnly": true,
    "order": 53,
    "symbol": "⚙",
    "group": "面板管理"
  }
}
</route>

<script setup lang="ts">
import SettingsSection from "../components/SettingsSection.vue";
import { copyText } from "../utils/copy";
import FormDialog from "../components/FormDialog.vue";
import { permissionLabel } from "../utils/permissions";
import ValueListInput from "../components/ValueListInput.vue";
import { cleanList } from "../utils/form";
import { RouterLink, useRouter } from "vue-router";
import { computed, h, ref, onMounted } from "vue";
import {
  NButton,
  NPopconfirm,
  NInput,
  NInputNumber,
  NFormItem,
  NModal,
  NSelect,
  NTag,
  NAlert,
  NDataTable,
  type DataTableColumns,
} from "naive-ui";
import { useNodeAPI, type SystemVersion } from "../api/client";
import type { components } from "../api/schema";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";
const api = useNodeAPI();
const { request } = api;

interface Credential {
  id: string;
  name: string;
  scopes: string[];
  allowed_sources: string[];
  expires_at: number;
  revoked: boolean;
}
const { run, busy, message } = useAction(),
  session = useSession(),
  router = useRouter();
const credentials = ref<Credential[]>([]);
const systemVersion = ref<SystemVersion | null>(null);

type PanelAccess = components["schemas"]["PanelAccessInput"];
const access = ref<PanelAccess | null>(null);
const accessOpen = ref(false);
const pendingAccessURL = ref("");
const port = ref<number | null>(null);
const protocol = ref<PanelAccess["protocol"]>("https");
const accessChanged = computed(
  () =>
    port.value !== access.value?.port ||
    protocol.value !== access.value?.protocol,
);
const accountOpen = ref(false);
const username = ref("");
const password = ref("");
const passwordConfirmation = ref("");
const accountChanged = computed(
  () =>
    username.value.trim() !== session.localMe?.username ||
    !!password.value ||
    !!passwordConfirmation.value,
);
const accountValid = computed(
  () =>
    !!username.value.trim() &&
    new TextEncoder().encode(username.value.trim()).length <= 64 &&
    (!password.value || [...password.value].length >= 6) &&
    passwordConfirmation.value === password.value,
);
const credentialVisible = ref(false),
  tokenVisible = ref(false),
  name = ref(""),
  scopes = ref<string[]>(["read"]),
  sources = ref<string[]>([]),
  token = ref("");
const credentialColumns: DataTableColumns<Credential> = [
  { title: "名称", key: "name" },
  {
    title: "权限",
    key: "scopes",
    render: (r) => r.scopes.map(permissionLabel).join("、"),
  },
  {
    title: "到期时间",
    key: "expires_at",
    render: (r) => new Date(r.expires_at * 1000).toLocaleDateString(),
  },
  {
    title: "状态",
    key: "state",
    render: (r) =>
      h(
        NTag,
        {
          size: "small",
          type: r.revoked
            ? "default"
            : r.expires_at <= Date.now() / 1000
              ? "warning"
              : "success",
          bordered: false,
        },
        () =>
          r.revoked
            ? "已撤销"
            : r.expires_at <= Date.now() / 1000
              ? "已过期"
              : "有效",
      ),
  },
  {
    title: "允许来源",
    key: "allowed_sources",
    render: (r) => r.allowed_sources.join("、") || "不限来源",
  },
  {
    title: "操作",
    key: "actions",
    width: 90,
    render: (r) =>
      h(
        NPopconfirm,
        {
          disabled: busy.value || r.revoked,
          onPositiveClick: () => revokeCredential(r.id),
          positiveText: "撤销密钥",
          negativeText: "取消",
        },
        {
          trigger: () =>
            h(
              NButton,
              {
                size: "small",
                type: "error",
                disabled: busy.value || r.revoked,
              },
              () => "撤销",
            ),
          default: () =>
            `撤销 ${r.name} 后，使用此密钥的连接和调用将无法继续。`,
        },
      ),
  },
];

async function load() {
  await run(async () => {
    const result = await Promise.all([
      request<Credential[]>({ url: "/credentials" }),
      api.systemVersion(),
    ]);
    credentials.value = result[0];
    systemVersion.value = result[1];
    if (systemVersion.value.runtime === "native") {
      access.value = await request<PanelAccess>({
        url: "/system/panel-access",
      });
    }
  });
}
async function createCredential() {
  await run(async () => {
    const result = await request<{ id: string; token: string }>({
      method: "POST",
      url: "/credentials",
      data: {
        name: name.value,
        scopes: scopes.value,
        allowed_sources: cleanList(sources.value),
        expires_at: Math.floor(Date.now() / 1000) + 90 * 86400,
      },
    });
    token.value = result.token;
    name.value = "";
    scopes.value = ["read"];
    sources.value = [];
    credentialVisible.value = false;
    tokenVisible.value = true;
    credentials.value = await request<Credential[]>({ url: "/credentials" });
  });
}
async function revokeCredential(id: string) {
  await run(async () => {
    await request({ method: "DELETE", url: `/credentials/${id}` });
    credentials.value = await request<Credential[]>({ url: "/credentials" });
  }, "API 密钥已撤销");
}
function openAccess() {
  if (!access.value) return;
  port.value = access.value.port;
  protocol.value = access.value.protocol;
  accessOpen.value = true;
}
async function updateAccess() {
  if (port.value == null) return;
  const next: PanelAccess = { port: port.value, protocol: protocol.value };
  await run(async () => {
    await request({ method: "PUT", url: "/system/panel-access", data: next });
    const url = new URL(window.location.origin);
    url.protocol = next.protocol + ":";
    url.port = String(next.port);
    pendingAccessURL.value = url.origin;
    accessOpen.value = false;
  });
}
function openAccount() {
  username.value = session.localMe?.username ?? "";
  accountOpen.value = true;
}
function closeAccount() {
  accountOpen.value = false;
  password.value = passwordConfirmation.value = "";
}
async function updateAccount() {
  const nextUsername = username.value.trim();
  await run(async () => {
    await request({
      method: "PUT",
      url: "/account",
      data: {
        username:
          nextUsername === session.localMe?.username ? undefined : nextUsername,
        password: password.value || undefined,
      },
    });
    closeAccount();
    session.clear();
    await router.push("/login");
  }, "管理员账户已更新，请重新登录");
}
async function revokeSessions() {
  await run(async () => {
    await request({ method: "POST", url: "/sessions/revoke-all" });
    session.clear();
    await router.push("/login");
  }, "所有浏览器会话已撤销");
}
async function copyToken() {
  try {
    await copyText(token.value);
    message.success("已复制");
  } catch {
    message.error("无法访问剪贴板，请手动复制");
  }
}
onMounted(load);
</script>

<template>
  <div class="page-stack">
    <section v-if="systemVersion" class="surface">
      <div class="section-heading">
        <h2>系统信息</h2>
        <RouterLink to="/panel-updates">
          检查更新
        </RouterLink>
      </div>
      <dl class="detail-list">
        <dt>应用版本</dt>
        <dd>{{ systemVersion.version }}</dd>
      </dl>
    </section>
    <section v-if="access" class="surface">
      <div class="section-heading">
        <h2>面板访问</h2>
        <NButton :disabled="busy" @click="openAccess">
          修改访问设置
        </NButton>
      </div>
      <dl class="detail-list">
        <dt>访问协议</dt>
        <dd>{{ access.protocol.toUpperCase() }}</dd>
        <dt>面板端口</dt>
        <dd>{{ access.port }}</dd>
      </dl>
      <NAlert v-if="pendingAccessURL" type="info">
        面板正在切换访问地址。请稍候打开<a :href="pendingAccessURL">新地址</a>。
        如果启动失败，面板会尝试恢复原地址。
      </NAlert>
      <FormDialog
        :show="accessOpen"
        title="修改访问设置"
        width="440px"
        :busy="busy"
        :dirty="accessChanged"
        :submit-disabled="
          !accessChanged || port == null || port < 1024 || port > 65535
        "
        @submit="updateAccess"
        @cancel="accessOpen = false"
      >
        <NFormItem label="访问协议">
          <NSelect
            v-model:value="protocol"
            :options="[
              { label: 'HTTPS', value: 'https' },
              { label: 'HTTP', value: 'http' },
            ]"
          />
        </NFormItem>
        <NFormItem label="面板端口">
          <NInputNumber
            v-model:value="port"
            :min="1024"
            :max="65535"
            :precision="0"
          />
        </NFormItem>
        <p class="muted">
          保存后面板会重启。请确保防火墙和安全组允许访问新端口。
        </p>
      </FormDialog>
    </section>
    <section class="surface">
      <h2>管理设置</h2>
      <div class="shortcut-grid">
        <RouterLink to="/management-listener">
          <strong>安全管理入口</strong>
          <span class="muted">管理附加入口和允许访问的地址</span>
        </RouterLink>
        <RouterLink to="/modules">
          <strong>功能开关</strong><span class="muted">管理可选功能</span>
        </RouterLink>
        <RouterLink to="/panel-updates">
          <strong>系统更新</strong><span class="muted">检查版本与更新记录</span>
        </RouterLink>
        <RouterLink to="/history">
          <strong>清理存储</strong><span class="muted">清理不再使用的历史文件</span>
        </RouterLink>
      </div>
      <section>
        <h3>其他管理</h3>
        <div class="inline-gap">
          <RouterLink to="/firewall">
            防火墙状态
          </RouterLink>
        </div>
      </section>
    </section>
    <section class="surface">
      <h2>管理员账户</h2>
      <dl class="detail-list">
        <dt>用户名</dt>
        <dd>{{ session.localMe?.username }}</dd>
      </dl>
      <div class="form-actions">
        <n-button :disabled="busy" @click="openAccount">
          修改账号与密码
        </n-button>
        <n-popconfirm
          positive-text="退出全部设备"
          negative-text="取消"
          @positive-click="revokeSessions"
        >
          <template #trigger>
            <n-button :disabled="busy">
              退出全部设备
            </n-button>
          </template>其他设备与当前设备均需重新登录。确认继续？
        </n-popconfirm>
      </div>
      <FormDialog
        :show="accountOpen"
        title="修改管理员账户"
        width="440px"
        :busy="busy"
        :dirty="accountChanged"
        :submit-disabled="!accountChanged || !accountValid"
        @submit="updateAccount"
        @cancel="closeAccount"
      >
        <n-form-item label="用户名">
          <n-input v-model:value="username" autocomplete="username" />
        </n-form-item>
        <n-form-item label="新密码（至少 6 个字符）">
          <n-input
            v-model:value="password"
            type="password"
            placeholder="留空则保留现有密码"
            autocomplete="new-password"
            show-password-on="click"
          />
        </n-form-item>
        <n-form-item v-if="password || passwordConfirmation" label="确认新密码">
          <n-input
            v-model:value="passwordConfirmation"
            type="password"
            autocomplete="new-password"
          />
        </n-form-item>
        <p class="muted">
          保存后需要重新登录。
        </p>
      </FormDialog>
    </section>
    <section class="surface">
      <div class="section-heading">
        <div>
          <h2>API 密钥</h2>
          <p class="muted">
            密钥仅在创建时显示一次，有效期为 90 天。
          </p>
        </div>
        <div class="inline-gap">
          <n-button type="primary" @click="credentialVisible = true">
            创建密钥
          </n-button>
        </div>
      </div>
      <n-data-table
        :columns="credentialColumns"
        :data="credentials"
        :bordered="false"
        :scroll-x="900"
      />
    </section>
    <FormDialog
      :show="credentialVisible"
      title="创建API 密钥"
      :busy="busy"
      :draft="[name, scopes, sources]"
      :submit-disabled="!name.trim() || !scopes.length"
      submit-text="创建"
      @submit="createCredential"
      @cancel="
        credentialVisible = false;
        name = '';
        scopes = ['read'];
        sources = [];
      "
    >
      <div class="settings-stack">
        <SettingsSection title="密钥信息">
          <n-form-item label="名称" :show-feedback="false">
            <n-input
              v-model:value="name"
              :maxlength="100"
              placeholder="例如 备用服务器"
            />
          </n-form-item><n-form-item label="允许的操作" :show-feedback="false">
            <n-select
              v-model:value="scopes"
              multiple
              :options="
                (session.localMe?.scopes ?? []).map((scope) => ({
                  label: permissionLabel(scope),
                  value: scope,
                }))
              "
            />
          </n-form-item>
        </SettingsSection><SettingsSection
          title="访问限制（可选）"
          description="留空允许从任意地址使用此密钥。"
        >
          <ValueListInput
            v-model:value="sources"
            item-label="来源地址或网段"
            :max="32"
            placeholder="例如 192.168.1.0/24"
            :maxlength="64"
          />
        </SettingsSection>
      </div>
    </FormDialog>
    <n-modal
      v-model:show="tokenVisible"
      preset="card"
      title="保存API 密钥"
      style="width: 500px; max-width: 94vw"
      @after-leave="token = ''"
    >
      <n-alert type="warning" :bordered="false" style="margin-bottom: 20px">
        关闭后无法再次读取此密钥，请妥善保存。
      </n-alert><n-input
        :value="token"
        readonly
        type="textarea"
        :autosize="{ minRows: 2 }"
      /><n-button
        block
        type="primary"
        style="margin-top: 20px"
        @click="copyToken"
      >
        复制密钥
      </n-button>
    </n-modal>
  </div>
</template>
<style scoped>
.account-form {
  max-width: 560px;
}
</style>
