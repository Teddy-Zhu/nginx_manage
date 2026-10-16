<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { NAlert, NButton, NFormItem, NInput, NPopconfirm } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banAddressInput,
  type Fail2banAddressStatus,
  type Fail2banAddressTaskStatus,
} from "../api/client";
import { useSession } from "../stores/session";

const props = defineProps<{ jail: string; moduleEnabled: boolean }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const ip = ref(""),
  status = ref<Fail2banAddressStatus | null>(null);
const tasks = ref<Fail2banAddressTaskStatus[]>([]);
const error = ref(""),
  historyError = ref(""),
  notice = ref("");
const checking = ref(false),
  busy = ref(false),
  reading = ref(false),
  loaded = ref(false);
const pending = ref<{ input: Fail2banAddressInput; key: string } | null>(null);
const activeStates = new Set([
  "queued",
  "running",
  "compensating",
  "recovery_required",
]);
const active = computed(() =>
  tasks.value.some((task) => activeStates.has(task.state)),
);
const history = computed(() =>
  tasks.value.filter((task) => task.input.jail === props.jail),
);
const writable = computed(
  () => !!session.me?.scopes.includes("security.write") && props.moduleEnabled,
);
const ready = computed(
  () =>
    writable.value &&
    loaded.value &&
    !active.value &&
    !pending.value &&
    !busy.value &&
    !checking.value &&
    !!status.value?.available,
);
const stateNames: Record<string, string> = {
  queued: "排队中",
  running: "处理中",
  compensating: "恢复中",
  recovery_required: "等待恢复确认",
  succeeded: "引擎状态已确认",
  failed: "未完成",
  cancelled: "已取消",
};
const engineNames = { unknown: "未知", banned: "已封禁", clear: "未封禁" };
const backendNames: Record<string, string> = {
  "nginx-client": "Nginx 受管拒绝集合",
  "host-input": "宿主机入口规则",
};
const submissionNames = {
  not_sent: "尚未派发",
  not_needed: "已封禁，无需重复操作",
  unknown: "客户端回执未确认",
  acknowledged: "客户端已返回回执",
};
let closed = false,
  timer: ReturnType<typeof setTimeout> | undefined,
  queryVersion = 0;
watch(ip, () => {
  status.value = null;
  queryVersion++;
});
function expiry(expires: number, permanent: boolean) {
  return permanent
    ? "永久"
    : expires > 0
      ? new Date(expires * 1000).toLocaleString()
      : "—";
}
async function inspect() {
  if (closed || checking.value || busy.value || !ip.value.trim()) return;
  const value = ip.value.trim(),
    version = ++queryVersion;
  checking.value = true;
  error.value = "";
  status.value = null;
  try {
    const result = await api.fail2banAddress(
      props.jail,
      value,
      controller.signal,
    );
    if (!closed && version === queryVersion) status.value = result;
  } catch (e) {
    if (!closed && version === queryVersion) error.value = apiError(e).message;
  } finally {
    if (!closed) checking.value = false;
  }
}
async function refresh() {
  if (closed || reading.value) return;
  if (timer) clearTimeout(timer);
  reading.value = true;
  const previouslyActive = new Set(
    tasks.value
      .filter((task) => activeStates.has(task.state))
      .map((task) => task.id),
  );
  try {
    const result = await api.fail2banAddressTasks(controller.signal);
    if (closed) return;
    tasks.value = result;
    loaded.value = true;
    historyError.value = "";
    if (
      result.some(
        (task) =>
          previouslyActive.has(task.id) &&
          !activeStates.has(task.state) &&
          task.input.jail === props.jail,
      )
    )
      await inspect();
  } catch (e) {
    if (!closed) {
      historyError.value = apiError(e).message;
      loaded.value = false;
    }
  } finally {
    if (!closed) {
      reading.value = false;
      if (active.value || pending.value)
        timer = setTimeout(() => {
          void refresh();
        }, 3000);
    }
  }
}
async function change(action: "ban" | "unban") {
  if (closed || busy.value) return;
  if (!pending.value) {
    if (
      !ready.value ||
      !status.value ||
      (action === "ban" && !status.value.can_ban)
    )
      return;
    pending.value = {
      input: {
        jail: props.jail,
        ip: status.value.ip,
        action,
        target: status.value.target,
      },
      key: crypto.randomUUID(),
    };
  }
  busy.value = true;
  error.value = "";
  try {
    const result = await api.changeFail2banAddress(
      pending.value.input,
      pending.value.key,
    );
    if (closed) return;
    pending.value = null;
    notice.value = `操作任务已创建：${result.task_id}`;
    status.value = null;
    await refresh();
  } catch (e) {
    if (!closed) {
      const failure = apiError(e);
      error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500) pending.value = null;
    }
  } finally {
    if (!closed) busy.value = false;
  }
}
onMounted(() => {
  void refresh();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
  if (timer) clearTimeout(timer);
});
</script>

<template>
  <section class="surface page-stack">
    <h4>手动封禁与解封</h4>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <NAlert v-if="pending" type="warning"
      >提交结果待确认，可继续原操作。</NAlert
    >
    <NFormItem label="IP 地址">
      <NInput
        v-model:value="ip"
        :maxlength="45"
        :disabled="busy || !!pending"
        placeholder="单个 IPv4 或 IPv6 地址"
      />
    </NFormItem>
    <div class="toolbar">
      <NButton
        :loading="checking"
        :disabled="busy || !!pending || !ip.trim()"
        @click="inspect"
        >查询地址状态</NButton
      >
      <NButton
        v-if="pending"
        :loading="busy"
        @click="change(pending.input.action)"
        >继续原操作</NButton
      >
    </div>
    <template v-if="status">
      <NAlert
        v-if="status.reason"
        :type="status.available ? 'info' : 'warning'"
        >{{ status.reason }}</NAlert
      >
      <template v-if="status.available">
        <p>
          地址 {{ status.ip }} · 采样
          {{ new Date(status.at * 1000).toLocaleString() }}
        </p>
        <p>
          当前 jail：{{ engineNames[status.engine_state] }} · 到期时间：{{
            expiry(status.expires_at, status.permanent)
          }}
        </p>
        <p>
          {{ backendNames[status.backend] || "动作后端" }}：{{
            status.action_state === "denied"
              ? "已包含此地址"
              : status.action_state === "clear"
                ? "未包含此地址"
                : "未知"
          }}
        </p>
        <p v-if="status.generation">动作代次：{{ status.generation }}</p>
        <p>
          封禁沿用当前 jail 时长（{{
            status.ban_time === -1 ? "永久" : `${status.ban_time} 秒`
          }}）。解封仅影响当前 jail；其他 jail 可能继续拒绝此地址。
        </p>
        <div v-if="writable" class="toolbar">
          <NPopconfirm
            :disabled="!ready || !status.can_ban"
            @positive-click="change('ban')"
          >
            <template #trigger
              ><NButton type="warning" :disabled="!ready || !status.can_ban"
                >封禁地址</NButton
              ></template
            >
            确认在 {{ jail }} 封禁
            {{ status.ip }}？已封禁的地址不会重复封禁或续期。
          </NPopconfirm>
          <NPopconfirm :disabled="!ready" @positive-click="change('unban')">
            <template #trigger
              ><NButton :disabled="!ready">解封地址</NButton></template
            >
            确认从 {{ jail }} 解封 {{ status.ip }}？此操作同时清除此 jail
            的对应持久封禁记录。
          </NPopconfirm>
        </div>
      </template>
    </template>
    <p v-if="!moduleEnabled">Fail2ban 管理模块未启用，当前仅可查询。</p>
    <div class="toolbar">
      <h4>手动操作记录</h4>
      <NButton size="small" :loading="reading" @click="refresh"
        >刷新记录</NButton
      >
    </div>
    <NAlert v-if="historyError" type="error">{{ historyError }}</NAlert>
    <p v-if="active">存在尚未结束的手动操作，完成后可提交新操作。</p>
    <p v-if="loaded && !history.length">
      最近的手动操作中没有当前 jail 的记录。
    </p>
    <article v-for="task in history" :key="task.id" class="surface page-stack">
      <p>
        {{ task.input.action === "ban" ? "封禁" : "解封" }}
        {{ task.input.ip }} · {{ stateNames[task.state] || "状态未知" }} ·
        {{ new Date(task.created_at * 1000).toLocaleString() }}
      </p>
      <p>任务 {{ task.id }}</p>
      <NAlert v-if="task.error" type="warning">{{ task.error }}</NAlert>
      <template v-if="task.result">
        <p>
          {{ submissionNames[task.result.submission] }} · 引擎{{
            engineNames[task.result.engine_state]
          }}
        </p>
        <p v-if="task.result.observed_at">
          观测 {{ new Date(task.result.observed_at * 1000).toLocaleString() }} ·
          到期时间：{{ expiry(task.result.expires_at, task.result.permanent) }}
        </p>
      </template>
    </article>
    <p>
      记录保留最近 16 次手动操作中的当前 jail
      项。引擎观测是任务快照，动作后端的当前状态需单独查询。
    </p>
  </section>
</template>
