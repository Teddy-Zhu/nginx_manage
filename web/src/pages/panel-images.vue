<route lang="json">
{
  "meta": {
    "title": "运行环境更新",
    "subtitle": "更新面板运行环境",
    "nav": false,
    "order": 7.24,
    "symbol": "◇",
    "parent": "/settings"
  }
}
</route>
<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NCheckbox, NFormItem, NPopconfirm, NSelect, NTag } from "naive-ui";
import { useNodeAPI, apiError, type ImageUpgradeTask, type ComponentTask, type MaintenanceView } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";

const api = useNodeAPI(), session = useSession(), { run, busy } = useAction();
let keyFor = useIdempotency();
const preparations = ref<ComponentTask[]>([]), tasks = ref<ImageUpgradeTask[]>([]), maintenance = ref<MaintenanceView | null>(null), selected = ref(""), error = ref("");
const canWrite = computed(() => !!session.me?.scopes.includes("components.manage") && !!session.me?.scopes.includes("system.write"));
const held = computed(() => maintenance.value?.phase === "held" && maintenance.value.agent.phase === "held" && maintenance.value.agent.id === maintenance.value.session?.task_id && maintenance.value.agent.epoch === maintenance.value.session?.root_epoch);
const prepared = computed(() => preparations.value.filter((t) => t.action === "prepare" && t.state === "succeeded" && t.result?.runtime_ready && t.result.panel && t.result.release?.images?.some((image) => image.id === "panel-launcher")));
const allowDowntime = ref(false);
const chosen = computed(() => prepared.value.find((t) => t.id === selected.value));
const active = computed(() => tasks.value.some((t) => t.stage !== "restore_isolated" && !["succeeded", "failed", "rolled_back", "cancelled"].includes(t.state)));
const canCreate = computed(() => canWrite.value && held.value && !!chosen.value && allowDowntime.value && !active.value && !busy.value);
const states: Record<string, string> = { queued: "排队中", running: "升级中", compensating: "恢复原版本", recovery_required: "待恢复", succeeded: "升级完成", failed: "升级未完成", rolled_back: "已恢复原版本", cancelled: "已取消" };
const stages: Record<string, string> = { queued: "等待受理", control_pending: "等待续办", agent_submit_pending: "正在提交", authorized: "已授权", stopping: "停止原容器", removing: "移除原容器", selecting: "切换镜像", creating: "创建新容器", starting: "启动新容器", checking: "检查运行状态", committed: "镜像替换完成", rollback_stopping: "停止候选容器", rollback_selecting: "恢复原镜像", rollback_creating: "创建原镜像容器", rollback_starting: "启动原镜像容器", rollback_checking: "检查恢复状态", compensated: "原镜像已恢复", authorization_expired: "授权已过期", maintenance_unconfirmed: "等待维护确认", epoch_changed: "维护授权已变化", agent_unconfirmed: "等待执行状态", preflight_rejected: "准备检查未通过", preflight_unconfirmed: "准备结果待核对", control_rejected: "续办未受理", operation_missing: "原操作缺失", operation_mismatch: "原操作待核对", intent_mismatch: "原意图待核对", control_mismatch: "续办授权待核对", control_unconfirmed: "续办结果待核对", restore_isolated: "源任务已隔离" };
function date(value: number) { return new Date(value * 1000).toLocaleString(); }
function canResume(t: ImageUpgradeTask) {
  const result = t.result;
  return canWrite.value && held.value && maintenance.value?.agent.id === t.input.maintenance_id && !busy.value && t.state === "recovery_required" && !["operation_missing", "operation_mismatch", "intent_mismatch", "control_mismatch", "restore_isolated"].includes(t.stage) && (result ? !result.active && !result.finalized && result.sequence < 32 : ["epoch_changed", "maintenance_unconfirmed"].includes(t.stage));
}
let controller: AbortController | null = null, reading = false, closed = false;
async function load() {
  if (reading || closed) return;
  reading = true; controller = new AbortController();
  try {
    const [sources, items, view] = await Promise.all([api.componentTasks(controller.signal), api.panelImageUpgrades(controller.signal), canWrite.value ? api.maintenance(controller.signal) : Promise.resolve(null)]);
    preparations.value = sources; tasks.value = items; maintenance.value = view; error.value = "";
    if (!prepared.value.some((t) => t.id === selected.value)) selected.value = prepared.value[0]?.id ?? "";
  } catch (e) { if (!closed) error.value = apiError(e).message; } finally { reading = false; }
}
async function upgrade() {
  if (!canCreate.value || !maintenance.value) return;
  const input = { maintenance_id: maintenance.value.agent.id, prepare_task_id: selected.value, allow_downtime: allowDowntime.value };
  await run(async () => { const t = await api.createPanelImageUpgrade(input, keyFor(input)); tasks.value = [t, ...tasks.value.filter((item) => item.id !== t.id)]; keyFor = useIdempotency(); }, "面板镜像替换任务已受理");
  await load();
}
async function resume(t: ImageUpgradeTask) {
  if (!canResume(t)) return;
  await run(async () => { await api.resumePanelImageUpgrade(t.id, keyFor({ id: t.id, sequence: t.result?.sequence ?? 0, command: "resume" })); keyFor = useIdempotency(); }, "原镜像替换续办请求已受理");
  await load();
}
onMounted(() => { void load(); });
onUnmounted(() => { closed = true; controller?.abort(); });
useLiveRefresh(api, ["tasks", "maintenance"], load);
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar"><h2>更换运行镜像</h2><NButton @click="load">刷新</NButton></div>
      <p>在<RouterLink to="/components">组件准备</RouterLink>完成目标发行版的面板准备与镜像拉取，再在<RouterLink to="/maintenance">配置维护</RouterLink>进入维护后更换运行镜像。</p>
      <NAlert type="info">仅适用于容器部署。替换期间管理页面会暂时中断；失败时恢复原镜像。</NAlert>
      <p class="muted">镜像须已存在于目标节点。当前应用版本、数据库及配置保持不变。</p>
      <NAlert v-if="canWrite && !held" type="warning">尚未进入配置维护，请先确认维护状态。</NAlert>
      <NFormItem label="已准备版本"><NSelect v-model:value="selected" :options="prepared.map((t) => ({ label: `${t.result?.release?.version} · ${date(t.created_at)}`, value: t.id }))" placeholder="选择面板准备任务" :disabled="!canWrite || busy" /></NFormItem>
      <NCheckbox v-if="canWrite" v-model:checked="allowDowntime" :disabled="busy">允许替换期间管理服务短暂中断</NCheckbox>
      <div v-if="canWrite"><NPopconfirm :disabled="!canCreate" positive-text="更换镜像" @positive-click="upgrade"><template #trigger><NButton type="primary" :disabled="!canCreate" :loading="busy">更换镜像</NButton></template>确认更换为版本 {{ chosen?.result?.release?.version }}？</NPopconfirm></div>
    </section>
    <section class="panel page-stack">
      <h2>替换任务</h2>
      <p v-if="!tasks.length" class="muted">暂无替换任务</p>
      <article v-for="task in tasks" :key="task.id" class="panel page-stack">
        <div class="toolbar"><strong>{{ states[task.state] ?? task.state }}</strong><NTag :type="task.state === 'succeeded' ? 'success' : ['failed', 'recovery_required'].includes(task.state) ? 'warning' : 'info'">{{ stages[task.stage] ?? task.stage }}</NTag></div>
        <p class="muted">{{ date(task.created_at) }} · 操作编号 {{ task.operation_id }}</p>
        <p v-if="task.result">目标版本 {{ task.result.target_version }} · {{ task.result.active ? "服务执行中" : task.result.finalized ? "事务已结束" : "服务未运行" }}</p>
        <p v-if="task.result" class="muted" style="overflow-wrap: anywhere">{{ task.result.target_image }}</p>
        <NAlert v-if="task.error" :type="task.state === 'rolled_back' ? 'info' : 'warning'">{{ task.error }}</NAlert>
        <p v-if="task.result?.finalized">镜像事务已结束。<template v-if="task.state === 'succeeded'">可继续<RouterLink to="/panel-updates">更新面板与 Agent</RouterLink>，或</template>前往<RouterLink to="/maintenance">配置维护</RouterLink>释放维护锁。</p>
        <div v-if="canResume(task)"><NPopconfirm positive-text="续办原替换" @positive-click="resume(task)"><template #trigger><NButton :loading="busy">续办原替换</NButton></template>确认继续此镜像替换事务？系统将按原进度完成替换或恢复原镜像。</NPopconfirm></div>
      </article>
    </section>
  </div>
</template>
