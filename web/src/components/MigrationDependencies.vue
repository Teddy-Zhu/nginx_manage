<script setup lang="ts">
import TaskLogButton from "./TaskLogButton.vue";
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
  preparing: "下载软件",
  prepared: "软件下载完成",
  not_required: "已有组件",
  target_dependencies: "目标缺少配置依赖",
  unavailable: "当前部署不可准备",
  runtime_recovery: "原实例需要恢复",
  system_dependencies: "缺少系统运行依赖",
  capability_missing: "所选软件不满足迁移要求",
  release_expired: "发行检查已过期",
  grant_expired: "准备授权已过期",
  target_changed: "目标状态已变化",
  check_unconfirmed: "检查结果待核对",
  prepare_unconfirmed: "准备结果待核对",
  child_missing: "组件记录缺失",
  preparation_blocked: "准备未获准",
  input_invalid: "准备授权待核对",
  maintenance: "准备安装",
  installing: "首次安装中",
  installed: "首次安装完成",
  releasing: "恢复配置修改中",
  installation_unavailable: "安装服务不可用",
  installation_wait: "等待安装服务",
  installation_failed: "首次安装失败",
  installation_blocked: "首次安装未获准",
  installation_recovery: "安装结果需要恢复",
  install_missing: "安装记录缺失",
  install_mismatch: "安装结果待核对",
  maintenance_blocked: "安装准备未完成",
  maintenance_missing: "安装准备记录缺失",
  maintenance_mismatch: "安装状态待核对",
  maintenance_recovery: "安装准备需要恢复",
  maintenance_lost: "操作已结束",
  release_blocked: "安装收尾待核对",
  preflight_blocked: "重新预检未获准",
};
</script>
<template>
  <div class="dependency-status">
    <p>
      <strong>Nginx 依赖处理</strong>
      <NTag>{{ states[status.state] || status.state }}</NTag>
      {{ stages[status.stage] || status.stage }}
    </p>
    <p v-if="status.stage === 'prepared'">
      可信软件下载完成；请核对实例安装与运行状态后重新预检。
    </p>
    <p v-if="status.error">
      {{ status.error }}
    </p>
    <div class="button-row">
      <TaskLogButton
        v-if="status.check_task_id"
        :task-id="status.check_task_id"
        title="检查安装条件"
      /><TaskLogButton
        v-if="status.prepare_task_id"
        :task-id="status.prepare_task_id"
        title="下载软件"
      /><TaskLogButton
        v-if="status.install_task_id"
        :task-id="status.install_task_id"
        title="安装 Nginx"
      />
    </div>
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
