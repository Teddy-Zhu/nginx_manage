<route lang="json">
{
  "meta": {
    "title": "安全管理入口",
    "nav": false,
    "localOnly": true,
    "order": 8.5,
    "symbol": "⇄",
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import SettingsSection from "../components/SettingsSection.vue";
import FormDialog from "../components/FormDialog.vue";
import { useLiveRefresh } from "../composables/live";
import ValueListInput from "../components/ValueListInput.vue";
import { cleanList } from "../utils/form";
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import {
  NAlert,
  NButton,
  NFormItem,
  NInput,
  NInputNumber,
  NPopconfirm,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ManagementListenerInput,
  type ManagementListenerView,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const protocol = window.location.protocol;
const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
const editing = ref(false);
const editBaseline = ref("");
const editSnapshot = computed(() => JSON.stringify(form));
const view = ref<ManagementListenerView | null>(null),
  error = ref(""),
  uncertain = ref(false),
  publicURL = ref(""),
  version = ref(-1);
const canManage = computed(() =>
  ["read", "system.write"].every((scope) =>
    session.localMe?.scopes.includes(scope),
  ),
);
const recommendedListen = `0.0.0.0:${49152 + (crypto.getRandomValues(new Uint16Array(1))[0]! % 16384)}`;
const form = reactive({
  listen: recommendedListen,
  sources: ["0.0.0.0/0", "::/0"],
  certificate: "",
  key: "",
  rotate: false,
});
let keyFor = useIdempotency(),
  timer: ReturnType<typeof setInterval> | undefined,
  closed = false;
const listenPort = computed({
  get: () =>
    Number(form.listen.slice(form.listen.lastIndexOf(":") + 1)) || null,
  set: (port: number | null) => {
    form.listen = `${form.listen.slice(0, form.listen.lastIndexOf(":") + 1)}${port ?? ""}`;
  },
});
const operation = computed(() => view.value?.operation);
const pending = computed(
  () => operation.value?.state === "waiting_confirmation",
);
const remaining = ref(0);
const states = {
  waiting_confirmation: "等待新连接确认",
  succeeded: "已完成",
  rolled_back: "已恢复",
  recovery_required: "需要本机恢复",
};
const confirmURL = computed(() => {
  try {
    const url = new URL(publicURL.value);
    if (
      url.protocol !== window.location.protocol ||
      url.username ||
      url.password
    )
      return "";
    url.pathname = "/management-listener";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "";
  }
});
function date(value: number) {
  return value ? new Date(value * 1000).toLocaleString() : "—";
}
function resetForm() {
  if (!view.value) return;
  version.value = view.value.version;
  form.listen = view.value.confirmed.listen || recommendedListen;
  form.sources = view.value.confirmed.allowed_sources.length
    ? [...view.value.confirmed.allowed_sources]
    : ["0.0.0.0/0", "::/0"];
  form.certificate = form.key = "";
  form.rotate = false;
  keyFor = useIdempotency();
  uncertain.value = false;
}
function openSettings() {
  resetForm();
  editBaseline.value = editSnapshot.value;
  editing.value = true;
}
async function load() {
  if (!canManage.value || closed) return;
  try {
    const result = await api.managementListener();
    if (closed) return;
    view.value = result;
    error.value = "";
    remaining.value = Math.max(
      0,
      (result.operation?.deadline ?? 0) - Math.floor(Date.now() / 1000),
    );
    if (version.value < 0) resetForm();
  } catch (cause) {
    if (!closed) error.value = apiError(cause).message;
  }
}
async function apply(enabled: boolean) {
  if (!view.value) return;
  const input: ManagementListenerInput = {
    version: version.value,
    enabled,
    listen: enabled ? form.listen.trim() : "",
    allowed_sources: enabled ? cleanList(form.sources) : [],
    certificate_pem: enabled ? form.certificate : "",
    key_pem: enabled ? form.key : "",
    rotate_certificate: enabled && form.rotate,
  };
  await run(async () => {
    if (enabled) {
      const port = form.listen.slice(form.listen.lastIndexOf(":") + 1);
      if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)
        throw new Error("请输入 1 至 65535 之间的监听端口。");
      const url = new URL(window.location.origin);
      url.port = port;
      publicURL.value = url.origin;
    }
    uncertain.value = true;
    try {
      const result = await api.applyManagementListener(input, keyFor(input));
      if (view.value)
        view.value = {
          ...view.value,
          operation: result,
          version: result.version,
        };
    } catch (cause) {
      const failure = apiError(cause);
      if (failure.status >= 400 && failure.status < 500)
        uncertain.value = false;
      throw cause;
    }
    uncertain.value = false;
    editing.value = false;
    form.certificate = form.key = "";
    form.rotate = false;
    keyFor = useIdempotency();
  });
  await load();
}
async function decide(action: "confirm" | "rollback") {
  const id = operation.value?.id;
  if (!id) return;
  await run(async () => {
    const result = await api.decideManagementListener(id, action);
    if (view.value) view.value = { ...view.value, operation: result };
    uncertain.value = false;
  });
  await load();
}
onMounted(async () => {
  await load();
  if (closed) return;
  timer = setInterval(() => {
    remaining.value = Math.max(
      0,
      (operation.value?.deadline ?? 0) - Math.floor(Date.now() / 1000),
    );
  }, 1000);
});
onUnmounted(() => {
  closed = true;
  if (timer) clearInterval(timer);
  form.key = form.certificate = "";
});
useLiveRefresh(api, ["listener"], load);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="!canManage" type="warning">
      当前账户没有修改入口设置的权限。
    </NAlert>
    <template v-else>
      <NAlert v-if="error" type="error">
        {{ error }}
      </NAlert>
      <NAlert v-if="uncertain" type="warning">
        暂未确认操作结果，请刷新查看进度。
      </NAlert>
      <section class="panel page-stack">
        <div class="toolbar">
          <h2>入口状态</h2>
          <NButton :disabled="busy" @click="load">
            刷新状态
          </NButton>
        </div>
        <p>
          用于确认防火墙等网络变更后的连接状态。启用后，请通过新地址访问面板；未按时确认会自动恢复。
        </p>
        <template v-if="view">
          <NAlert v-if="view.reason" type="warning">
            {{ view.reason }}
          </NAlert>
          <p>
            <NTag
              :type="
                view.confirmed.enabled && view.serving && view.attached
                  ? 'success'
                  : 'default'
              "
            >
              {{
                !view.confirmed.enabled
                  ? "未开启"
                  : view.serving && view.attached
                    ? "已开启"
                    : "连接异常"
              }}
            </NTag>
          </p>
          <p v-if="view.confirmed.enabled">
            已确认地址 {{ view.confirmed.listen }} · 来源
            {{ view.confirmed.allowed_sources.join("、") }}
          </p>
        </template>
      </section>
      <section v-if="operation" class="panel page-stack">
        <div class="toolbar">
          <h2>最近操作</h2>
          <NTag
            :type="operation.state === 'succeeded' ? 'success' : 'warning'"
          >
            {{ states[operation.state] }}
          </NTag>
        </div>

        <p v-if="operation.config.enabled">
          候选地址 {{ operation.config.listen }} · 来源
          {{ operation.config.allowed_sources.join("、") }}
        </p>

        <NAlert v-if="operation.error" type="warning">
          {{
            operation.error
          }}
        </NAlert>
        <p v-if="operation.confirmed_source">
          已确认来源
          {{
            operation.confirmed_source
          }}。此结果仅证明该来源到当前入口的连接可达。
        </p>
        <template v-if="pending">
          <NAlert type="warning">
            请在 {{ date(operation.deadline) }} 前通过新入口确认（约
            {{ remaining }} 秒）。超时或应用通道断开后自动恢复。
          </NAlert>
          <NFormItem label="新入口地址">
            <NInput
              v-model:value="publicURL"
              :placeholder="`${protocol}//node.example.com:9444`"
            />
          </NFormItem>
          <p v-if="confirmURL">
            <a :href="confirmURL" target="_blank" rel="noopener noreferrer">打开新入口确认页面</a>
          </p>
          <div class="toolbar">
            <NButton type="primary" :disabled="busy" @click="decide('confirm')">
              确认当前新连接
            </NButton>
            <NPopconfirm
              positive-text="恢复"
              @positive-click="decide('rollback')"
            >
              <template #trigger>
                <NButton :disabled="busy">
                  恢复原入口
                </NButton>
              </template>恢复后候选入口的连接将关闭。
            </NPopconfirm>
          </div>
        </template>
      </section>
      <section v-if="view?.available" class="panel page-stack">
        <div class="toolbar">
          <h2>入口设置</h2>
          <div class="inline-gap">
            <NButton
              :disabled="busy || pending || !view.attached"
              @click="openSettings"
            >
              修改设置
            </NButton>
            <NPopconfirm
              positive-text="停用"
              @positive-click="
                resetForm();
                apply(false);
              "
            >
              <template #trigger>
                <NButton :disabled="busy || pending || !view.confirmed.enabled">
                  停用远程入口
                </NButton>
              </template>
              停用须通过主入口执行，不会关闭主入口。
            </NPopconfirm>
          </div>
        </div>
        <p class="muted">
          修改端口或允许访问的地址后，需从新入口确认连接。
        </p>
      </section>
      <FormDialog
        :show="editing"
        title="修改安全管理入口"
        :busy="busy"
        :dirty="editSnapshot !== editBaseline"
        :submit-disabled="
          pending ||
            !view ||
            version !== view.version ||
            !view.attached ||
            !cleanList(form.sources).length
        "
        submit-text="应用并等待确认"
        @submit="apply(true)"
        @cancel="
          editing = false;
          form.key = form.certificate = '';
        "
      >
        <div class="settings-stack">
          <NAlert
            v-if="view && version !== view.version && !pending"
            type="warning"
          >
            管理入口设置已变化，请重新载入。
          </NAlert>
          <NAlert type="info" :bordered="false">
            保存后，请在 120
            秒内打开新入口并确认；未确认将自动恢复原设置。
          </NAlert>
          <SettingsSection title="访问端口">
            <NFormItem label="面板端口" :show-feedback="false">
              <NInputNumber
                v-model:value="listenPort"
                :disabled="busy || pending"
                :min="1"
                :max="65535"
                :precision="0"
              />
            </NFormItem>
          </SettingsSection>
          <SettingsSection
            title="允许访问的地址"
            description="仅允许列表中的 IP 地址或网段连接管理入口。"
          >
            <ValueListInput
              v-model:value="form.sources"
              item-label="来源地址或网段"
              :max="32"
              placeholder="例如 192.168.1.0/24"
              :maxlength="64"
              :disabled="busy || pending"
            />
          </SettingsSection>
          <p class="section-note">
            新端口和来源地址也需要在防火墙中放行；使用云服务器时，请同时检查安全组。
          </p>
        </div>
      </FormDialog>
    </template>
  </div>
</template>
