<route lang="json">
{
  "meta": {
    "title": "任务与审计",
    "subtitle": "查看执行阶段和操作记录",
    "nav": true,
    "order": 5,
    "symbol": "☷"
  }
}
</route>

<script setup lang="ts">
import { ref, reactive, onMounted } from "vue";
import {
  NButton,
  NDataTable,
  NTabs,
  NFormItem,
  NInput,
  NTabPane,
  NAlert,
  type DataTableColumns,
} from "naive-ui";
import {
  useNodeAPI,
  type Task,
  type AuditRow,
  type AuditPage,
  type AuditFilter,
} from "../api/client";
import { useAction } from "../composables/action";
const api = useNodeAPI();
const { request } = api;

const { run, busy } = useAction(),
  tasks = ref<Task[]>([]);
const audits = ref<AuditPage | null>(null),
  offset = ref(0),
  tab = ref("tasks");
function localTime(value: number) {
  const date = new Date(value);
  return new Date(value - date.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}
const filter = reactive({
  from: localTime(Date.now() - 24 * 3600_000),
  until: localTime(Date.now()),
  principal: "",
  action: "",
  resource_id: "",
  outcome: "",
  request_id: "",
});
const applied = ref<AuditFilter | null>(null),
  cursors = ref<string[]>([""]),
  auditPage = ref(0);
function queryFilter(): AuditFilter {
  const from = new Date(filter.from).getTime() / 1000;
  const until = new Date(filter.until).getTime() / 1000 + 59;
  if (
    !Number.isFinite(from) ||
    !Number.isFinite(until) ||
    from <= 0 ||
    until < from ||
    until - from > 90 * 24 * 3600 ||
    until > Date.now() / 1000 + 60
  )
    throw new Error("请选择有效起止时间，范围最多九十天");
  return {
    from: Math.floor(from),
    until: Math.floor(until),
    principal: filter.principal,
    action: filter.action,
    resource_id: filter.resource_id,
    outcome: filter.outcome,
    request_id: filter.request_id,
  };
}
const taskKinds: Record<string, string> = {
  "component.install": "Nginx 首次安装",
  "component.switch": "Nginx 组件切换",
  "nginx.validate": "配置校验",
  "nginx.apply": "配置应用",
  "nginx.restore": "受管配置恢复",
  "acme.account.register": "ACME 账户注册",
  "acme.issue": "ACME 证书签发",
};
const taskStates: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  compensating: "回滚中",
  succeeded: "已完成",
  failed: "失败",
  rolled_back: "已回滚",
  recovery_required: "需要恢复",
  cancelled: "已取消",
};
const taskStages: Record<string, string> = {
  queued: "等待执行",
  account_reconciling: "核对 CA 账户",
  account_registering: "注册 CA 账户",
  account_ready: "账户已就绪",
  account_registration_failed: "账户注册失败",
  order_reconciling: "核对原订单",
  order_creating: "创建 CA 订单",
  order_rejected: "CA 拒绝订单",
  order_create_unconfirmed: "订单创建待确认",
  order_invalid: "订单无效",
  order_finalizing: "提交证书申请",
  order_finalization_unconfirmed: "签发提交待确认",
  order_timeout: "等待订单完成",
  http01_preflight: "预检 HTTP-01 入口",
  http01_unavailable: "HTTP-01 入口不可用",
  http01_dns_failed: "HTTP-01 域名解析失败",
  http01_publishing: "发布 HTTP 验证材料",
  http01_publish_failed: "HTTP 验证材料发布或本机验证失败",
  http01_validating: "CA 验证 HTTP 入口",
  http01_validation_failed: "HTTP-01 验证失败",
  http01_cleaning: "清理 HTTP 验证材料",
  http01_cleanup_unconfirmed: "HTTP 验证材料清理待确认",
  dns_publishing: "发布 DNS 验证记录",
  dns_propagating: "检查 TXT 传播",
  dns_validating: "CA 验证域名",
  dns_cleaning: "清理验证记录",
  dns_cleanup_unconfirmed: "验证记录清理待确认",
  dns_credentials_failed: "DNS 凭据读取失败",
  dns_publish_failed: "验证记录发布失败",
  dns_propagation_failed: "TXT 传播或验证失败",
  authorization_failed: "域名授权失败",
  account_load_failed: "签发账户读取失败",
  ca_unavailable: "CA 通信失败",
  csr_invalid: "申请材料校验失败",
  certificate_download_failed: "证书下载未完成",
  certificate_store_failed: "证书版本保存失败",
  certificate_issued: "证书已签发",
  issuance_failed: "证书签发失败",
  explicit_recovery: "已交由恢复任务处理",
  profile_archived: "签发配置已停用",
  submit_unconfirmed: "提交待确认",
  operation_missing: "执行记录缺失",
  agent_submit_pending: "等待接收",
  preparing: "生成候选配置",
  prepared: "候选配置就绪",
  testing: "校验配置",
  nginx_tested: "校验通过",
  switch_pending: "准备切换",
  switched: "确认运行状态",
  runtime_confirmed: "已确认生效",
  rollback_pending: "恢复上一修订",
  rollback_confirmed: "已确认恢复",
  rollback_unconfirmed: "恢复待确认",
  nginx_test_failed: "配置校验失败",
  external_conflict: "外部修改冲突",
  runtime_unconfirmed: "运行状态待确认",
  runtime_mismatch: "运行修订不一致",
  agent_unreachable: "等待连接",
  reconciling: "核对执行结果",
  agent_rejected: "操作未被接受",
  agent_not_ready: "执行环境未就绪",
  superseded: "修订已被替换",
  interrupted_before_switch: "切换前中断",
  prepare_failed: "候选配置生成失败",
  candidate_changed: "恢复候选已变化",
  previous_load_failed: "快照基础修订读取失败",
  module_prepare_failed: "受信模块准备失败",
  restore_switch_pending: "准备切换恢复候选",
  restore_switched: "确认恢复运行状态",
  restore_confirmed: "已确认受管恢复",
  restore_unconfirmed: "受管恢复待确认",
};
const taskColumns: DataTableColumns<Task> = [
  { title: "任务 ID", key: "id", render: (r) => r.id.slice(0, 8) },
  { title: "类型", key: "kind", render: (r) => taskKinds[r.kind] ?? r.kind },
  {
    title: "状态",
    key: "state",
    render: (r) => taskStates[r.state] ?? r.state,
  },
  {
    title: "目标修订",
    key: "revision_id",
    render: (r) => r.revision_id?.slice(0, 8) || "—",
  },
  {
    title: "确认修订",
    key: "observed_revision",
    render: (r) => r.observed_revision?.slice(0, 8) || "—",
  },
  {
    title: "阶段",
    key: "stage",
    render: (r) => taskStages[r.stage] ?? r.stage,
  },
  { title: "错误", key: "last_error", render: (r) => r.last_error || "—" },
  {
    title: "创建时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
const auditColumns: DataTableColumns<AuditRow> = [
  { title: "操作", key: "action" },
  { title: "请求标识", key: "request_id" },
  { title: "操作者", key: "principal" },
  { title: "资源", key: "resource_id" },
  { title: "结果", key: "outcome" },
  {
    title: "时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
async function loadTasks() {
  await run(async () => {
    tasks.value = await request<Task[]>({
      url: "/tasks",
      params: { offset: offset.value },
    });
  });
}
async function searchAudit() {
  await run(async () => {
    const input = queryFilter();
    const result = await api.audit({ ...input, limit: 30 });
    applied.value = input;
    audits.value = result;
    cursors.value = [result.start_cursor];
    auditPage.value = 0;
  });
}
async function load() {
  if (tab.value === "audit") await searchAudit();
  else await loadTasks();
}
async function changeTab(value: string) {
  if (busy.value) return;
  tab.value = value;
  if (value === "audit" && !audits.value) await searchAudit();
}
async function page(delta: number) {
  if (tab.value === "tasks") {
    offset.value = Math.max(0, offset.value + delta * 30);
    await loadTasks();
    return;
  }
  if (!applied.value || !audits.value) return;
  await run(async () => {
    const next = auditPage.value + delta;
    if (next < 0 || (delta > 0 && !audits.value?.more)) return;
    const cursor = delta > 0 ? audits.value!.cursor : cursors.value[next];
    const result = await api.audit({ ...applied.value!, limit: 30, cursor });
    if (delta > 0) cursors.value[next] = cursor;
    audits.value = result;
    auditPage.value = next;
  });
}
async function exportAudit() {
  await run(async () => {
    const input = queryFilter();
    const blob = await api.exportAudit(input);
    const url = URL.createObjectURL(blob),
      link = document.createElement("a");
    link.href = url;
    link.download = `audit-${new Date().toISOString().slice(0, 10)}.jsonl`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}
onMounted(loadTasks);
</script>
<template>
  <div class="toolbar">
    <span class="muted">每页最多 30 条记录</span
    ><n-button :loading="busy" @click="load">刷新</n-button>
  </div>
  <n-alert type="info" :bordered="false" style="margin-bottom: 20px"
    >配置校验不改变运行修订。配置应用通过运行确认后才标记完成，失败时显示回滚或恢复状态。</n-alert
  >
  <section class="surface">
    <n-tabs type="line" :value="tab" @update:value="changeTab"
      ><n-tab-pane name="tasks" tab="执行任务"
        ><n-data-table
          :columns="taskColumns"
          :data="tasks"
          :bordered="false"
          :scroll-x="900" /></n-tab-pane
      ><n-tab-pane name="audit" tab="操作审计">
        <div class="page-stack">
          <div class="grid-2">
            <NFormItem label="开始时间"
              ><input v-model="filter.from" type="datetime-local"
            /></NFormItem>
            <NFormItem label="结束时间"
              ><input v-model="filter.until" type="datetime-local"
            /></NFormItem>
            <NFormItem label="操作者"
              ><NInput
                v-model:value="filter.principal"
                placeholder="精确匹配，留空为全部"
                :maxlength="128"
            /></NFormItem>
            <NFormItem label="操作"
              ><NInput
                v-model:value="filter.action"
                placeholder="如 nginx.apply"
                :maxlength="128"
            /></NFormItem>
            <NFormItem label="资源标识"
              ><NInput
                v-model:value="filter.resource_id"
                placeholder="精确匹配，留空为全部"
                :maxlength="128"
            /></NFormItem>
            <NFormItem label="执行结果"
              ><NInput
                v-model:value="filter.outcome"
                placeholder="如 succeeded"
                :maxlength="128"
            /></NFormItem>
            <NFormItem label="请求标识"
              ><NInput
                v-model:value="filter.request_id"
                placeholder="精确匹配，留空为全部"
                :maxlength="128"
            /></NFormItem>
          </div>
          <div class="toolbar">
            <NButton type="primary" :disabled="busy" @click="searchAudit"
              >查询</NButton
            >
            <NButton :disabled="busy" @click="exportAudit"
              >导出审计记录</NButton
            >
          </div>
          <p class="muted">
            导出包含节点、查询范围、记录总数与完整记录摘要，源记录保留。单次最多扫描一万条、输出
            8 MiB，超出时请缩小时间范围。
          </p>
          <NAlert v-if="audits?.notice" type="info">{{ audits.notice }}</NAlert>
          <n-data-table
            :columns="auditColumns"
            :data="audits?.rows ?? []"
            :bordered="false"
            :scroll-x="1000"
          /></div></n-tab-pane
    ></n-tabs>
    <div class="pagination">
      <NButton
        :disabled="busy || (tab === 'tasks' ? !offset : !auditPage)"
        @click="page(-1)"
        >上一页</NButton
      >
      <span class="muted"
        >第 {{ tab === "tasks" ? offset / 30 + 1 : auditPage + 1 }} 页</span
      >
      <NButton
        :disabled="
          busy || (tab === 'tasks' ? tasks.length < 30 : !audits?.more)
        "
        @click="page(1)"
        >下一页</NButton
      >
    </div>
  </section>
</template>

<style scoped>
input[type="datetime-local"] {
  width: 100%;
  min-height: 34px;
  padding: 6px 10px;
  border: 1px solid #d8dee8;
  border-radius: 3px;
  background: transparent;
  color: inherit;
  font: inherit;
  box-sizing: border-box;
}
</style>
