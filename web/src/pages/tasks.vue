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
import { ref, onMounted } from "vue";
import {
  NButton,
  NDataTable,
  NTabs,
  NTabPane,
  NAlert,
  type DataTableColumns,
} from "naive-ui";
import { useNodeAPI, type Task } from "../api/client";
import { useAction } from "../composables/action";
const api = useNodeAPI();
const { request } = api;

const { run, busy } = useAction(),
  tasks = ref<Task[]>([]);
interface Audit {
  id: string;
  action: string;
  principal: string;
  resource_id: string;
  outcome: string;
  created_at: number;
}
const audits = ref<Audit[]>([]),
  offset = ref(0);
const taskKinds: Record<string, string> = {
  "component.install": "Nginx 首次安装",
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
const auditColumns: DataTableColumns<Audit> = [
  { title: "操作", key: "action" },
  { title: "操作者", key: "principal" },
  { title: "资源", key: "resource_id" },
  { title: "结果", key: "outcome" },
  {
    title: "时间",
    key: "created_at",
    render: (r) => new Date(r.created_at * 1000).toLocaleString(),
  },
];
async function load() {
  await run(async () => {
    const result = await Promise.all([
      request<Task[]>({ url: "/tasks", params: { offset: offset.value } }),
      request<Audit[]>({ url: "/audit", params: { offset: offset.value } }),
    ]);
    tasks.value = result[0];
    audits.value = result[1];
  });
}
async function page(delta: number) {
  offset.value = Math.max(0, offset.value + delta);
  await load();
}
onMounted(load);
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
    <n-tabs type="line"
      ><n-tab-pane name="tasks" tab="执行任务"
        ><n-data-table
          :columns="taskColumns"
          :data="tasks"
          :bordered="false"
          :scroll-x="900" /></n-tab-pane
      ><n-tab-pane name="audit" tab="操作审计"
        ><n-data-table
          :columns="auditColumns"
          :data="audits"
          :bordered="false"
          :scroll-x="800" /></n-tab-pane
    ></n-tabs>
    <div class="pagination">
      <n-button :disabled="!offset || busy" @click="page(-30)">上一页</n-button
      ><span class="muted">第 {{ offset / 30 + 1 }} 页</span
      ><n-button
        :disabled="busy || (tasks.length < 30 && audits.length < 30)"
        @click="page(30)"
        >下一页</n-button
      >
    </div>
  </section>
</template>
