<route lang="json">
{ "meta": { "public": true } }
</route>

<script setup lang="ts">
import { ref, computed } from "vue";
import { useRouter } from "vue-router";
import { NButton, NInput, NForm, NFormItem, NAlert } from "naive-ui";
import { useSession } from "../stores/session";
import { api } from "../api/client";
import { useAction } from "../composables/action";

const session = useSession(),
  router = useRouter();
const { run, busy } = useAction();
const username = ref(""),
  password = ref(""),
  token = ref("");
const bootstrap = computed(() => session.me?.bootstrap_required ?? false);
async function submit() {
  await run(async () => {
    if (!session.me) await session.restore();
    if (bootstrap.value) {
      await api.bootstrap(token.value.trim(), username.value, password.value);
      token.value = "";
      await session.restore();
    }
    await session.login(username.value, password.value);
    password.value = "";
    await router.push("/");
  });
}
</script>

<template>
  <div class="login-page">
    <div class="login-decoration">
      <span class="brand-mark large">N</span>
      <h1>让配置<br />清晰可控。</h1>
      <p>代理、配置与服务器，统一管理。</p>
      <div class="decoration-grid" />
    </div>
    <div class="login-panel">
      <div class="login-card">
        <div class="eyebrow">NGINXPANEL</div>
        <h1>{{ bootstrap ? "初始化管理员" : "欢迎回来" }}</h1>
        <p class="muted">
          {{
            bootstrap
              ? "使用安装时生成的一次性令牌设置账户。"
              : "登录以管理当前节点。"
          }}
        </p>
        <n-alert
          v-if="!session.me"
          type="warning"
          :bordered="false"
          style="margin: 20px 0"
          >暂时无法连接管理服务，请稍后重试。</n-alert
        >
        <n-form style="margin-top: 28px" @submit.prevent="submit">
          <n-form-item v-if="bootstrap" label="一次性引导令牌"
            ><n-input
              v-model:value="token"
              type="password"
              autocomplete="off"
              :maxlength="100"
          /></n-form-item>
          <n-form-item label="用户名"
            ><n-input
              v-model:value="username"
              autofocus
              autocomplete="username"
              :maxlength="64"
              placeholder="输入管理员用户名"
          /></n-form-item>
          <n-form-item :label="bootstrap ? '设置密码（至少 12 字节）' : '密码'"
            ><n-input
              v-model:value="password"
              type="password"
              show-password-on="click"
              :autocomplete="bootstrap ? 'new-password' : 'current-password'"
              :maxlength="256"
              placeholder="输入密码"
          /></n-form-item>
          <n-button
            type="primary"
            size="large"
            block
            attr-type="submit"
            :loading="busy"
            :disabled="!username || !password || (bootstrap && !token)"
            >{{ bootstrap ? "创建管理员并登录" : "登录" }}
            <span style="margin-left: auto">→</span></n-button
          >
        </n-form>
        <p class="login-note">仅一个管理员账户 · 凭据由当前节点保管</p>
      </div>
    </div>
  </div>
</template>
