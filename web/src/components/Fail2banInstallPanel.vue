<script setup lang="ts">
import { computed, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NProgress, NTag } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentTask,
  type Fail2banLifecyclePreviewInput,
} from "../api/client";
import { useSession } from "../stores/session";
import { randomUUID } from "../utils/crypto";
import TaskLogButton from "./TaskLogButton.vue";

const emit = defineEmits<{ changed: []; busy: [value: boolean] }>();
const api = useNodeAPI(),
  session = useSession(),
  controller = new AbortController();
const busy = ref(false),
  done = ref(false),
  error = ref(""),
  step = ref(0),
  logsOpen = ref(false);
const log = ref<string[]>([]),
  records = ref<Array<{ id: string; title: string; state: string }>>([]);
const steps = ["检查安装条件", "下载软件", "安装并启动"];
const allowed = computed(() =>
  ["read", "components.manage", "security.write", "system.write"].every(
    (scope) => session.me?.scopes.includes(scope),
  ),
);
type Job = { id: string; state: string; error: string };
class TaskStopped extends Error {}
let retry: (() => Promise<unknown>) | null = null;
const stateNames: Record<string, string> = {
  queued: "等待执行",
  running: "正在执行",
  succeeded: "已完成",
  failed: "未完成",
  recovery_required: "需要处理",
  compensating: "正在恢复",
  cancelled: "已取消",
};
function note(text: string) {
  log.value.push(`${new Date().toLocaleTimeString()} ${text}`);
}
function cancelled() {
  if (controller.signal.aborted) throw new Error("页面已关闭");
}
function waitFor<T extends Job>(
  id: string,
  read: () => Promise<T[]>,
): Promise<T> {
  cancelled();
  return new Promise((resolve, reject) => {
    let reading = false,
      again = false,
      settled = false;
    let release = () => {};
    const finish = (value?: T, failure?: unknown) => {
      if (settled) return;
      settled = true;
      release();
      controller.signal.removeEventListener("abort", abort);
      if (failure) reject(failure);
      else resolve(value!);
    };
    const abort = () => finish(undefined, new Error("页面已关闭"));
    const refresh = async () => {
      if (settled) return;
      again = true;
      if (reading) return;
      reading = true;
      try {
        while (again && !settled) {
          again = false;
          const task = (await read()).find((item) => item.id === id);
          if (!task) throw new Error("暂时无法读取安装任务，请重试以确认进度");
          const record = records.value.find((item) => item.id === id);
          if (record) record.state = task.state;
          if (task.state === "succeeded") finish(task);
          else if (
            !["queued", "running", "compensating"].includes(task.state)
          ) {
            note(task.error || "任务未完成，请查看任务日志");
            finish(
              undefined,
              new TaskStopped("安装未完成，请查看日志后重试。"),
            );
          }
        }
      } catch (failure) {
        finish(undefined, failure);
      } finally {
        reading = false;
      }
    };
    release = api.subscribe(["tasks"], () => void refresh());
    controller.signal.addEventListener("abort", abort, { once: true });
    void refresh();
  });
}
async function task<T extends Job>(
  title: string,
  submit: () => Promise<{ id?: string; task_id?: string }>,
  read: () => Promise<T[]>,
) {
  let id = "";
  const execute = async () => {
    cancelled();
    if (!id) {
      try {
        const accepted = await submit();
        id = accepted.task_id ?? accepted.id ?? "";
        if (!id)
          throw new Error("暂时无法确认安装任务，请在操作日志中检查进度");
      } catch (failure) {
        const status = apiError(failure).status;
        if (status >= 400 && status < 500 && status !== 408) retry = null;
        throw failure;
      }
      records.value.push({ id, title, state: "queued" });
    }
    return waitFor(id, read);
  };
  retry = execute;
  try {
    const result = await execute();
    retry = null;
    note(`${title}已完成`);
    return result;
  } catch (failure) {
    if (failure instanceof TaskStopped) retry = null;
    throw failure;
  }
}
async function lifecycle(
  action: Fail2banLifecyclePreviewInput["action"],
  title: string,
  prepared?: ComponentTask,
) {
  const release = prepared?.result?.release;
  const asset = release?.assets.find(
    (item) =>
      item.component === "fail2ban" && release.selected.includes(item.id),
  );
  const plan = await api.previewFail2banLifecycle(
    {
      engine_owner: "managed",
      action,
      plan_id: action === "install" ? release!.plan_id : "",
      asset_id: action === "install" ? asset!.id : "",
      prerelease: action === "install" && !!prepared?.result?.input.prerelease,
    },
    controller.signal,
  );
  cancelled();
  const key = randomUUID();
  return task(
    title,
    () => api.changeFail2banLifecycle(plan.input, key),
    () => api.fail2banLifecycleTasks(controller.signal),
  );
}
async function install() {
  if (busy.value || !allowed.value) return;
  busy.value = true;
  emit("busy", true);
  error.value = "";
  done.value = false;
  try {
    if (retry) {
      try {
        await retry();
        retry = null;
      } catch (failure) {
        if (failure instanceof TaskStopped) retry = null;
        throw failure;
      }
    }
    cancelled();
    step.value = 0;
    note("开始检查安装条件");
    let [view, modules, source] = await Promise.all([
      api.fail2ban(controller.signal),
      api.modules(controller.signal),
      api.components(controller.signal),
    ]);
    if (!view.available)
      throw new Error(view.reason || "暂时无法读取服务器状态");
    if (
      view.binding.engine.owner === "existing" ||
      (view.managed.state !== "installed" &&
        view.tools.some((tool) => tool.present))
    )
      throw new Error("服务器已有 Fail2ban，请先连接已有安装");
    if (!modules.some((item) => item.id === "fail2ban" && item.enabled)) {
      await api.setModule("fail2ban", true);
      cancelled();
    }
    if (view.python.standard_library !== true) {
      note("正在准备安装所需的软件");
      let key = randomUUID();
      const check = await task(
        "检查安装条件",
        () =>
          api.changeFail2banPython(
            { action: "plan", plan_id: "", refresh: true },
            key,
          ),
        () => api.fail2banPythonTasks(controller.signal),
      );
      const plan = check.result?.plan;
      if (!plan)
        throw new Error(check.result?.error || "未能获取可用的安装方案");
      key = randomUUID();
      await task(
        "准备运行环境",
        () =>
          api.changeFail2banPython(
            { action: "install", plan_id: plan.id, refresh: false },
            key,
          ),
        () => api.fail2banPythonTasks(controller.signal),
      );
      view = await api.fail2ban(controller.signal);
      if (view.python.standard_library !== true)
        throw new Error(view.python.reason || "安装条件尚未满足");
    }
    if (view.managed.state !== "installed") {
      if (["reserved", "ready", "interrupted"].includes(view.managed.state)) {
        step.value = 2;
        await lifecycle("resume", "继续安装 Fail2ban");
      } else {
        step.value = 1;
        note("正在下载 Fail2ban");
        const available = (await api.componentTasks(controller.signal)).find(
          (item) =>
            item.action === "prepare" &&
            item.state === "succeeded" &&
            item.result?.runtime_ready &&
            item.result.release &&
            item.result.release.expires_at * 1000 > Date.now() &&
            item.result.release.selected.length === 1 &&
            item.result.release.assets.some(
              (asset) =>
                asset.component === "fail2ban" &&
                item.result!.release!.selected.includes(asset.id),
            ),
        );
        let prepared = available;
        if (!prepared) {
          if (!source.available)
            throw new Error(source.reason || "安装源暂不可用");
          let key = randomUUID();
          const checked = await task(
            "查找可用版本",
            () =>
              api.createComponentTask(
                {
                  check_task_id: "",
                  input: {
                    action: "check",
                    tag: "",
                    prerelease: false,
                    components: ["fail2ban"],
                    plan_id: "",
                    manifest_sha256: "",
                    trust_sha256: "",
                  },
                },
                key,
              ),
            () => api.componentTasks(controller.signal),
          );
          const release = checked.result?.release;
          if (!release || !checked.result?.runtime_ready)
            throw new Error(
              checked.result?.runtime_reason || "没有可安装的 Fail2ban 版本",
            );
          key = randomUUID();
          prepared = await task(
            "下载 Fail2ban",
            () =>
              api.createComponentTask(
                {
                  check_task_id: checked.id,
                  input: {
                    action: "prepare",
                    tag: release.tag,
                    prerelease: checked.result!.input.prerelease,
                    assets: release.selected,
                    plan_id: release.plan_id,
                    manifest_sha256: release.manifest_sha256,
                    trust_sha256: release.trust_sha256,
                  },
                },
                key,
              ),
            () => api.componentTasks(controller.signal),
          );
        }
        step.value = 2;
        await lifecycle("install", "安装 Fail2ban", prepared);
      }
    }
    view = await api.fail2ban(controller.signal);
    const service = () =>
      view.services.find((item) => item.id === "nginxpanel-fail2ban.service");
    if (service()?.active !== "active") {
      await lifecycle("start", "启动登录防护");
      view = await api.fail2ban(controller.signal);
    }
    if (!["enabled", "enabled-runtime"].includes(service()?.unit_file ?? "")) {
      await lifecycle("enable", "开启开机启动");
      view = await api.fail2ban(controller.signal);
    }
    if (
      view.managed.state !== "installed" ||
      service()?.active !== "active" ||
      !["enabled", "enabled-runtime"].includes(service()?.unit_file ?? "")
    )
      throw new Error("安装已执行，但服务状态尚未确认，请查看日志");
    done.value = true;
    step.value = 3;
    note("Fail2ban 已安装，登录防护服务已启动");
    emit("changed");
  } catch (failure) {
    if (!controller.signal.aborted) {
      note(apiError(failure).message);
      error.value = "安装未完成，请查看安装日志后重试。";
      logsOpen.value = true;
    }
  } finally {
    if (!controller.signal.aborted) {
      busy.value = false;
      emit("busy", false);
    }
  }
}
onUnmounted(() => controller.abort());
</script>

<template>
  <section class="panel page-stack">
    <div class="section-heading">
      <h2>安装 Fail2ban</h2>
      <NTag :type="done ? 'success' : busy ? 'info' : 'default'">{{
        done ? "已安装" : busy ? steps[step] : "待安装"
      }}</NTag>
    </div>
    <p class="muted">
      自动封禁多次登录失败的
      IP，保护服务器和面板。安装完成后自动启动，并随服务器开机运行。安装过程中请保持本页打开。
    </p>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="done" type="success">安装完成，可以开始添加防护规则。</NAlert>
    <NProgress
      v-if="busy || done"
      type="line"
      :percentage="done ? 100 : Math.round(((step + 1) / 4) * 100)"
      :show-indicator="false"
    />
    <div class="button-row">
      <RouterLink v-if="done" to="/fail2ban"
        ><NButton type="primary">设置登录防护</NButton></RouterLink
      ><NButton
        v-else
        type="primary"
        :loading="busy"
        :disabled="!allowed"
        @click="install"
        >{{ busy ? steps[step] : error ? "继续安装" : "立即安装" }}</NButton
      ><NButton v-if="log.length" @click="logsOpen = !logsOpen">{{
        logsOpen ? "收起安装日志" : "查看安装日志"
      }}</NButton>
    </div>
    <p v-if="!allowed" class="muted">请联系管理员安装此软件。</p>
    <pre v-if="logsOpen" class="installation-log">{{ log.join("\n") }}</pre>
    <div v-for="record in records" :key="record.id" class="record-card">
      <div class="record-heading">
        <strong>{{ record.title }}</strong
        ><NTag
          :type="
            record.state === 'succeeded'
              ? 'success'
              : ['failed', 'recovery_required'].includes(record.state)
                ? 'warning'
                : 'info'
          "
          >{{ stateNames[record.state] || "正在处理" }}</NTag
        ><TaskLogButton :task-id="record.id" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.installation-log {
  max-height: 18rem;
  overflow: auto;
  padding: 1rem;
  border-radius: 8px;
  background: var(--surface-soft);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 0.85rem;
}
</style>
