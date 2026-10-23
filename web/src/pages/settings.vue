<route lang="json">
{
  "meta": {
    "title": "设置",
    "subtitle": "管理账户、访问入口与系统维护",
    "nav": true,
    "localOnly": true,
    "order": 25,
    "symbol": "⚙",
    "group": "数据与设置"
  }
}
</route>

<script setup lang="ts">
import AdvancedDetails from "../components/AdvancedDetails.vue";
import { RouterLink, useRouter } from "vue-router";
import { ref, onMounted } from "vue";
import {
  NButton,
  NInput,
  NForm,
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

const credentialVisible = ref(false),
  tokenVisible = ref(false),
  name = ref(""),
  scopes = ref<string[]>(["read"]),
  sources = ref(""),
  token = ref(""),
  password = ref("");
const credentialColumns: DataTableColumns<Credential> = [
  { title: "名称", key: "name" },
  { title: "权限", key: "scopes", render: (r) => r.scopes.join(", ") },
  {
    title: "到期时间",
    key: "expires_at",
    render: (r) => new Date(r.expires_at * 1000).toLocaleDateString(),
  },
];
const selectedCredential = ref<string | null>(null);
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
        allowed_sources: sources.value.trim()
          ? sources.value.trim().split(/\s+/)
          : [],
        expires_at: Math.floor(Date.now() / 1000) + 90 * 86400,
      },
    });
    token.value = result.token;
    credentialVisible.value = false;
    tokenVisible.value = true;
    credentials.value = await request<Credential[]>({ url: "/credentials" });
  });
}
async function revokeCredential() {
  if (
    !selectedCredential.value ||
    !window.confirm("撤销后此凭据将立即停止接受新操作，确认撤销？")
  )
    return;
  await run(async () => {
    await request({
      method: "DELETE",
      url: `/credentials/${selectedCredential.value}`,
    });
    selectedCredential.value = null;
    credentials.value = await request<Credential[]>({ url: "/credentials" });
  }, "凭据已撤销");
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
    await navigator.clipboard.writeText(token.value);
    message.success("已复制");
  } catch {
    message.error("无法访问剪贴板，请手动复制");
  }
}
onMounted(load);
</script>

<template>
  <section v-if="systemVersion" class="surface">
    <div class="section-heading">
      <h2>系统信息</h2>
      <RouterLink to="/panel-updates">检查更新</RouterLink>
    </div>
    <dl class="detail-list">
      <dt>应用版本</dt>
      <dd>{{ systemVersion.version }}</dd>
    </dl>
  </section>
  <section class="surface" style="margin: 20px 0">
    <h2>管理设置</h2>
    <div class="shortcut-grid" style="margin-top: 16px">
      <RouterLink to="/management-listener"><strong>安全管理入口</strong><span class="muted">连接确认和访问限制</span></RouterLink>
      <RouterLink to="/modules"><strong>功能开关</strong><span class="muted">管理可选功能</span></RouterLink>
      <RouterLink to="/panel-updates"><strong>系统更新</strong><span class="muted">检查版本与更新记录</span></RouterLink>
      <RouterLink to="/history"><strong>清理存储</strong><span class="muted">清理不再使用的历史文件</span></RouterLink>
    </div>
    <AdvancedDetails title="高级维护"><div class="inline-gap"><RouterLink to="/maintenance">维护模式</RouterLink><RouterLink to="/agent-upgrades">管理服务更新</RouterLink><RouterLink to="/panel-images">运行环境更新</RouterLink><RouterLink to="/firewall">网络诊断</RouterLink></div></AdvancedDetails>
  </section>
  <div class="two-columns">
    <section class="surface">
      <div class="section-heading">
        <h2>管理员账户</h2>
        <n-tag size="small" :bordered="false">单管理员</n-tag>
      </div>
      <dl class="detail-list">
        <dt>用户名</dt>
        <dd>{{ session.localMe?.username }}</dd>
      </dl>
      <n-form @submit.prevent="changePassword"
        ><n-form-item label="新密码（至少 6 个字符）"
          ><n-input
            v-model:value="password"
            type="password"
            autocomplete="new-password"
            show-password-on="click"
        /></n-form-item>
        <div class="inline-gap">
          <n-button
            attr-type="submit"
            type="primary"
            :loading="busy"
            :disabled="[...password].length < 6"
            >修改密码</n-button
          ><n-button :disabled="busy" @click="revokeSessions"
            >撤销全部会话</n-button
          >
        </div></n-form
      >
    </section>
  </div>
  <section class="surface">
    <div class="section-heading">
      <div>
        <h2>机器凭据</h2>
        <p class="muted">
          仅保存不可逆校验值，创建时展示一次。默认 90 天有效。
        </p>
      </div>
      <div class="inline-gap">
        <n-button
          :disabled="!selectedCredential || busy"
          type="error"
          @click="revokeCredential"
          >撤销所选凭据</n-button
        ><n-button type="primary" @click="credentialVisible = true"
          >创建凭据</n-button
        >
      </div>
    </div>
    <n-data-table
      :columns="credentialColumns"
      :data="credentials"
      :bordered="false"
      :row-props="
        (row: Credential) => ({
          onClick: () => (selectedCredential = row.id),
          style: `cursor: pointer; background: ${selectedCredential === row.id ? '#eef7f3' : 'transparent'}`,
        })
      "
    />
  </section>
  <n-modal
    v-model:show="credentialVisible"
    preset="card"
    title="创建机器凭据"
    style="width: 500px; max-width: 94vw"
    ><n-form @submit.prevent="createCredential"
      ><n-form-item label="名称"
        ><n-input v-model:value="name" :maxlength="100" /></n-form-item
      ><n-form-item label="权限范围"
        ><n-select
          v-model:value="scopes"
          multiple
          :options="
            (session.localMe?.scopes ?? []).map((scope) => ({
              label: scope,
              value: scope,
            }))
          " /></n-form-item
      ><n-form-item label="允许来源（可选，CIDR 使用空格分隔）"
        ><n-input
          v-model:value="sources"
          placeholder="192.0.2.0/24 2001:db8::/32" /></n-form-item
      ><n-button
        attr-type="submit"
        block
        type="primary"
        :loading="busy"
        :disabled="!name || !scopes.length"
        >创建</n-button
      ></n-form
    ></n-modal
  >
  <n-modal
    v-model:show="tokenVisible"
    preset="card"
    title="保存机器凭据"
    style="width: 500px; max-width: 94vw"
    @after-leave="token = ''"
    ><n-alert type="warning" :bordered="false" style="margin-bottom: 20px"
      >关闭后无法再次读取此 Token，请保存到安全位置。</n-alert
    ><n-input
      :value="token"
      readonly
      type="textarea"
      :autosize="{ minRows: 2 }"
    /><n-button block type="primary" style="margin-top: 20px" @click="copyToken"
      >复制 Token</n-button
    ></n-modal
  >
</template>
