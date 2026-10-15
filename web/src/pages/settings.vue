<route lang="json">
{
  "meta": {
    "title": "设置",
    "subtitle": "账户、凭据与功能模块",
    "nav": true,
    "order": 5,
    "symbol": "⚙"
  }
}
</route>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";
import {
  NButton,
  NInput,
  NForm,
  NFormItem,
  NModal,
  NSelect,
  NTag,
  NSwitch,
  NAlert,
  NDataTable,
  type DataTableColumns,
} from "naive-ui";
import { api, request, type Module } from "../api/client";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";

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
const modules = ref<Module[]>([]),
  credentials = ref<Credential[]>([]);
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
      api.modules(),
      request<Credential[]>({ url: "/credentials" }),
    ]);
    modules.value = result[0];
    credentials.value = result[1];
  });
}
async function toggle(module: Module, enabled: boolean) {
  if (!window.confirm(`${enabled ? "启用" : "停用"}${module.name}的面板管理？`))
    return;
  await run(async () => {
    await api.setModule(module.id, enabled);
    modules.value = await api.modules();
  }, "模块设置已更新");
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
  <div class="two-columns">
    <section class="surface">
      <div class="section-heading">
        <h2>管理员账户</h2>
        <n-tag size="small" :bordered="false">单管理员</n-tag>
      </div>
      <dl class="detail-list">
        <dt>用户名</dt>
        <dd>{{ session.me?.username }}</dd>
      </dl>
      <n-form @submit.prevent="changePassword"
        ><n-form-item label="新密码（12–256 字节）"
          ><n-input
            v-model:value="password"
            type="password"
            autocomplete="new-password"
            show-password-on="click"
            :maxlength="256"
        /></n-form-item>
        <div class="inline-gap">
          <n-button
            attr-type="submit"
            type="primary"
            :loading="busy"
            :disabled="!password"
            >修改密码</n-button
          ><n-button :disabled="busy" @click="revokeSessions"
            >撤销全部会话</n-button
          >
        </div></n-form
      >
    </section>
    <section class="surface">
      <div class="section-heading">
        <h2>功能模块</h2>
        <n-button text :loading="busy" @click="load">刷新</n-button>
      </div>
      <div v-for="module in modules" :key="module.id" class="module-row">
        <div>
          <strong>{{ module.name }}</strong>
          <p v-if="module.reason" class="muted">{{ module.reason }}</p>
        </div>
        <n-switch
          :value="module.enabled"
          :disabled="!module.available || busy"
          :on-update:value="(value: boolean) => toggle(module, value)"
        />
      </div>
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
            (session.me?.scopes ?? []).map((scope) => ({
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
