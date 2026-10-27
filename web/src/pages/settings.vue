<route lang="json">
{
  "meta": {
    "title": "设置",
    "subtitle": "管理账户、访问入口与系统更新",
    "nav": true,
    "localOnly": true,
    "order": 53,
    "symbol": "⚙",
    "group": "数据与设置"
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
import { h, ref, onMounted } from "vue";
import {
  NButton,
  NPopconfirm,
  NInput,
  NFormItem,
  NModal,
  NSelect,
  NTag,
  NAlert,
  NDataTable,
  type DataTableColumns,
} from "naive-ui";
import { useNodeAPI, type SystemVersion } from "../api/client";
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

const passwordOpen = ref(false);
const credentialVisible = ref(false),
  tokenVisible = ref(false),
  name = ref(""),
  scopes = ref<string[]>(["read"]),
  sources = ref<string[]>([]),
  token = ref(""),
  password = ref("");
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
async function changePassword() {
  if (!window.confirm("修改密码会撤销全部浏览器会话，确认继续？")) return;
  await run(async () => {
    await request({
      method: "PUT",
      url: "/account/password",
      data: { password: password.value },
    });
    password.value = "";
    passwordOpen.value = false;
    session.clear();
    await router.push("/login");
  }, "密码已修改，请重新登录");
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
    <section class="surface">
      <h2>管理设置</h2>
      <div class="shortcut-grid">
        <RouterLink to="/management-listener">
          <strong>安全管理入口</strong><span class="muted">设置面板端口和允许访问的地址</span>
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
      <div class="section-heading">
        <h2>管理员账户</h2>
        <n-tag size="small" :bordered="false">
          单管理员
        </n-tag>
      </div>
      <dl class="detail-list">
        <dt>用户名</dt>
        <dd>{{ session.localMe?.username }}</dd>
      </dl>
      <div class="form-actions">
        <n-button :disabled="busy" @click="passwordOpen = true">
          修改密码
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
        :show="passwordOpen"
        title="修改密码"
        :busy="busy"
        :dirty="!!password"
        :submit-disabled="[...password].length < 6"
        @submit="changePassword"
        @cancel="
          passwordOpen = false;
          password = '';
        "
      >
        <n-form-item label="新密码（至少 6 个字符）">
          <n-input
            v-model:value="password"
            type="password"
            autocomplete="new-password"
            show-password-on="click"
          />
        </n-form-item>
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
