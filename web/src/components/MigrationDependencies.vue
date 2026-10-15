<script setup lang="ts">
import { NTag } from "naive-ui";
import type { MigrationDependencyStatus } from "../api/client";
defineProps<{ status: MigrationDependencyStatus }>();
const states: Record<string, string> = {
  queued: "已排队",
  running: "处理中",
  succeeded: "处理完成",
  failed: "处理失败",
  recovery_required: "需要恢复",
};
const stages: Record<string, string> = {
  checking: "检查可信组件",
  preparing: "准备签名资产",
  prepared: "资产已准备",
  not_required: "已有组件",
  unavailable: "当前部署不可准备",
  runtime_recovery: "原实例需要恢复",
  system_dependencies: "缺少系统运行依赖",
  capability_missing: "资产能力不匹配",
  release_expired: "发行检查已过期",
  grant_expired: "准备授权已过期",
  target_changed: "目标状态已变化",
  check_unconfirmed: "检查结果待核对",
  prepare_unconfirmed: "准备结果待核对",
  child_missing: "组件记录缺失",
  preparation_blocked: "准备未获准",
  input_invalid: "准备授权待核对",
  maintenance: "等待独占维护",
  installing: "首次安装中",
  installed: "首次安装完成",
  releasing: "恢复写入中",
  installation_unavailable: "安装服务不可用",
  installation_wait: "等待安装服务",
  installation_failed: "首次安装失败",
  installation_blocked: "首次安装未获准",
  installation_recovery: "安装结果需要恢复",
  install_missing: "安装记录缺失",
  install_mismatch: "安装结果待核对",
  maintenance_blocked: "维护未获准",
  maintenance_missing: "维护记录缺失",
  maintenance_mismatch: "维护归属待核对",
  maintenance_recovery: "维护结果需要恢复",
  maintenance_lost: "维护已结束",
  release_blocked: "维护释放待核对",
  preflight_blocked: "重新预检未获准",
};
</script>
<template>
  <div class="dependency-status">
    <p>
      <strong>依赖处理</strong>
      <NTag>{{ states[status.state] || status.state }}</NTag>
      {{ stages[status.stage] || status.stage }}
    </p>
    <p v-if="status.stage === 'prepared'">
      可信资产已准备；请核对实例安装与运行状态后重新预检。
    </p>
    <p v-if="status.error">{{ status.error }}</p>
    <dl>
      <dt>准备任务</dt>
      <dd>{{ status.task_id }}</dd>
      <template v-if="status.check_task_id"
        ><dt>组件检查任务</dt>
        <dd>{{ status.check_task_id }}</dd></template
      ><template v-if="status.prepare_task_id"
        ><dt>资产准备任务</dt>
        <dd>{{ status.prepare_task_id }}</dd></template
      >
      <template v-if="status.maintenance_task_id"
        ><dt>维护任务</dt>
        <dd>{{ status.maintenance_task_id }}</dd></template
      >
      <template v-if="status.install_task_id"
        ><dt>首次安装任务</dt>
        <dd>{{ status.install_task_id }}</dd></template
      >
    </dl>
  </div>
</template>
<style scoped>
.dependency-status {
  margin: 16px 0;
  padding: 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
}
dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 8px 16px;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
</style>
