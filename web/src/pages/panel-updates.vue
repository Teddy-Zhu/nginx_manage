<route lang="json">
{
  "meta": {
    "title": "面板更新",
    "subtitle": "版本更新与任务恢复",
    "nav": true,
    "order": 7.22,
    "symbol": "◇"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton, NCheckbox, NFormItem, NPopconfirm, NSelect, NTag } from "naive-ui";
import { useNodeAPI, apiError, type ComponentTask, type MaintenanceView, type PanelUpdateTask } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const session = useSession(), { run, busy } = useAction();
let keyFor = useIdempotency();
const preparations = ref<ComponentTask[]>([]), tasks = ref<PanelUpdateTask[]>([]), maintenance = ref<MaintenanceView | null>(null), selected = ref(""), error = ref("");
const coordinateAgent = ref(false), allowDowntime = ref(false);
const canWrite = computed(() => !!session.me?.scopes.includes("components.manage") && !!session.me?.scopes.includes("system.write"));
const held = computed(() => maintenance.value?.phase === "held" && maintenance.value.agent.phase === "held" && maintenance.value.agent.id === maintenance.value.session?.task_id && maintenance.value.agent.epoch === maintenance.value.session?.root_epoch);
const prepared = computed(() => preparations.value.filter((t) => t.action === "prepare" && t.state === "succeeded" && t.result?.runtime_ready && t.result.panel && t.result.release));
const chosen = computed(() => prepared.value.find((t) => t.id === selected.value));
const needsCoordination = computed(() => !!chosen.value?.result?.panel?.requires_coordination);
watch([selected, needsCoordination], () => { coordinateAgent.value = needsCoordination.value; allowDowntime.value = false; });
const active = computed(() => tasks.value.some((t) => t.stage !== "restore_isolated" && !["succeeded", "failed", "rolled_back", "cancelled"].includes(t.state)));
const cleanupPending = computed(() => tasks.value.some((t) => t.result?.release_acknowledged && (t.result.cleanup.state !== "done" || t.result.active)));
const cleanupStates: Record<string, string> = { pending: "等待清理", running: "清理中", blocked: "清理待处理", done: "已清理" };
const canCreate = computed(() => canWrite.value && held.value && !!chosen.value?.result?.panel?.automatic_rollback && (!coordinateAgent.value || allowDowntime.value) && !active.value && !busy.value);
const states: Record<string, string> = { queued: "排队中", running: "更新中", compensating: "恢复原版本", waiting_confirmation: "确认维护释放", recovery_required: "待恢复", succeeded: "更新完成", failed: "更新未完成", rolled_back: "已恢复原版本", cancelled: "已取消" };
const stages: Record<string, string> = { restore_isolated: "源任务已隔离", queued: "等待执行", capturing: "保存一致性快照", stopping: "停止原版本", selecting: "切换版本", starting: "启动新版本", checking: "确认就绪", rollback_stopping: "停止更新进程", rollback_selecting: "选择原版本", restoring: "恢复匹配数据", rollback_starting: "启动原版本", rollback_checking: "确认原版本就绪", committed: "更新已提交", compensated: "原版本已恢复", aborted: "更新已中止", agent_submit_pending: "提交更新", control_pending: "提交续办授权", maintenance_unconfirmed: "等待原维护会话", epoch_changed: "需要重新授权", authorization_expired: "启动授权已过期", agent_unconfirmed: "等待独立事务确认", control_unconfirmed: "等待续办确认", control_rejected: "续办未受理", preflight_unconfirmed: "等待执行条件确认", preflight_rejected: "未通过执行条件检查", operation_missing: "独立记录待本机恢复", operation_mismatch: "独立记录待本机核对", intent_mismatch: "原更新意图待本机核对", control_mismatch: "续办记录待本机核对" };
function date(value: number) { return new Date(value * 1000).toLocaleString(); }
function canResume(t: PanelUpdateTask) {
  const result = t.result;
  return canWrite.value && held.value && maintenance.value?.agent.id === t.input.maintenance_id && !busy.value && t.state === "recovery_required" && !["operation_missing", "operation_mismatch", "intent_mismatch", "control_mismatch", "restore_isolated"].includes(t.stage) && (result ? !result.active && !result.finalized && result.sequence < 32 : ["epoch_changed", "maintenance_unconfirmed"].includes(t.stage));
}
let controller: AbortController | null = null, timer: ReturnType<typeof setInterval> | undefined, reading = false, closed = false;
async function load() {
  if (reading || closed) return;
  reading = true; controller = new AbortController();
  try {
    const [sources, items, view] = await Promise.all([api.componentTasks(controller.signal), api.panelUpdates(controller.signal), canWrite.value ? api.maintenance(controller.signal) : Promise.resolve(null)]);
    preparations.value = sources; tasks.value = items; maintenance.value = view; error.value = "";
    if (!prepared.value.some((t) => t.id === selected.value)) selected.value = prepared.value[0]?.id ?? "";
  } catch (e) { if (!closed) error.value = apiError(e).message; } finally { reading = false; }
}
async function update() {
  if (!canCreate.value || !maintenance.value) return;
  const input = { maintenance_id: maintenance.value.agent.id, prepare_task_id: selected.value, coordinate_agent: coordinateAgent.value, allow_downtime: coordinateAgent.value && allowDowntime.value };
  await run(async () => { const t = await api.createPanelUpdate(input, keyFor(input)); tasks.value = [t, ...tasks.value.filter((item) => item.id !== t.id)]; keyFor = useIdempotency(); }, "面板更新任务已受理");
  await load();
}
async function resume(t: PanelUpdateTask) {
  if (!canResume(t)) return;
  await run(async () => { await api.resumePanelUpdate(t.id, keyFor({ id: t.id, sequence: t.result?.sequence ?? 0, command: "resume" })); keyFor = useIdempotency(); }, "原更新续办请求已受理");
  await load();
}
onMounted(async () => { await load(); if (!closed) timer = setInterval(() => { if (active.value || cleanupPending.value || maintenance.value?.phase !== "open") void load(); }, 3000); });
onUnmounted(() => { closed = true; controller?.abort(); if (timer) clearInterval(timer); });
</script>
<template>
  <div class="page-stack">
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar"><h2>更新面板版本</h2><NButton @click="load">刷新</NButton></div>
      <p>在<RouterLink to="/components">组件准备</RouterLink>完成面板准备，并在<RouterLink to="/maintenance">配置维护</RouterLink>进入维护后开始更新。</p>
      <NAlert type="info">更新期间面板暂时不可用。提交前失败时，将恢复原版本及匹配数据。</NAlert>
      <NAlert v-if="canWrite && !held" type="warning">尚未进入配置维护，请先确认维护状态。</NAlert>
      <NFormItem label="已准备面板"><NSelect v-model:value="selected" :options="prepared.map((t) => ({ label: `${t.result?.release?.version} · ${date(t.created_at)}`, value: t.id }))" placeholder="选择面板准备任务" :disabled="!canWrite || busy" /></NFormItem>
      <p v-if="chosen?.result?.panel">版本 {{ chosen.result.release?.version }} · 数据库版本 {{ chosen.result.panel.database_schema }}</p>
      <NAlert v-if="chosen?.result?.panel && !chosen.result.panel.automatic_rollback" type="warning">此发布未开放自动回滚，无法使用自动更新。</NAlert>
      <NCheckbox v-if="canWrite" v-model:checked="coordinateAgent" :disabled="needsCoordination || busy">同时更新 Agent</NCheckbox>
      <NAlert v-if="coordinateAgent" type="warning">协调更新会停止面板并重启 Agent。失败时恢复原 Agent、面板程序与匹配的数据快照；现有 Nginx 流量继续运行。</NAlert>
      <NCheckbox v-if="coordinateAgent" v-model:checked="allowDowntime" :disabled="busy">允许本次面板与 Agent 暂时中断</NCheckbox>
      <div v-if="canWrite"><NPopconfirm :disabled="!canCreate" positive-text="开始更新" @positive-click="update"><template #trigger><NButton type="primary" :disabled="!canCreate" :loading="busy">开始更新</NButton></template>确认更新到 {{ chosen?.result?.release?.version }}？{{ coordinateAgent ? "将同时更新 Agent，面板与 Agent 暂时不可用。" : "更新期间面板暂时不可用。" }}</NPopconfirm></div>
    </section>
    <section class="panel page-stack">
      <h2>更新任务</h2>
      <p v-if="!tasks.length" class="muted">暂无更新任务</p>
      <article v-for="task in tasks" :key="task.id" class="panel page-stack">
        <div class="toolbar"><strong>{{ states[task.state] ?? task.state }}</strong><NTag :type="task.state === 'succeeded' ? 'success' : ['failed', 'recovery_required'].includes(task.state) ? 'warning' : 'info'">{{ stages[task.stage] ?? task.stage }}</NTag></div>
        <p class="muted">{{ date(task.created_at) }} · {{ task.input.coordinate_agent ? "面板与 Agent 协调更新" : "面板更新" }} · 操作编号 {{ task.operation_id }}</p>
        <p v-if="task.result">数据库版本 {{ task.result.before_schema }} → {{ task.result.target_schema }} · {{ task.result.active ? "服务执行中" : task.result.finalized ? "事务已结束" : "服务未运行" }}</p>
        <NAlert v-if="task.error" :type="task.state === 'rolled_back' ? 'info' : 'warning'">{{ task.error }}</NAlert>
        <NAlert v-if="task.result?.finalized && !task.result.release_acknowledged" type="info">更新结果已保存，正在确认维护释放。</NAlert>
        <template v-if="task.result?.release_acknowledged">
          <p class="muted">恢复材料：{{ cleanupStates[task.result.cleanup.state] ?? task.result.cleanup.state }}<span v-if="task.result.cleanup.completed_at"> · {{ date(task.result.cleanup.completed_at) }}</span></p>
          <NAlert v-if="task.result.cleanup.error" type="warning">{{ task.result.cleanup.error }}</NAlert>
        </template>
        <div v-if="canResume(task)"><NPopconfirm positive-text="续办原更新" @positive-click="resume(task)"><template #trigger><NButton :loading="busy">续办原更新</NButton></template>确认继续此更新事务？系统将按原进度完成更新或恢复原版本。</NPopconfirm></div>
      </article>
    </section>
  </div>
</template>
