<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDescriptions,
  NDescriptionsItem,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banHostInputPreview,
} from "../api/client";

const api = useNodeAPI(),
  controller = new AbortController();
const view = ref<Fail2banHostInputPreview | null>(null),
  busy = ref(false),
  error = ref("");
let closed = false;
const managers: Record<string, string> = {
  "direct-candidate": "直接管理候选",
  unknown: "未确认",
  firewalld: "firewalld",
  ufw: "UFW",
  mixed: "多个管理器",
};
const registrations: Record<string, string> = {
  unavailable: "未确认",
  unregistered: "未登记",
  registered: "所有权已核对",
  released: "已释放",
  missing: "登记对象缺失",
  drifted: "登记对象发生变化",
  recovery_required: "原操作待恢复",
};
const protections: Record<string, string> = {
  unavailable: "未确认",
  unapproved: "未批准",
  approved: "已核对",
  stale: "原批准已失效",
  revoked: "已撤销",
};
const sources: Record<string, string> = {
  unavailable: "未完整采集",
  unapproved: "未批准",
  stale: "原批准已失效",
  revoked: "已撤销",
  ready: "已完整采集",
};
const runtimes: Record<string, string> = {
  unavailable: "未确认",
  uninitialized: "尚无运行操作",
  empty: "仅保留空表",
  applied: "已安装动作规则",
  recovery_required: "原操作待恢复",
  missing: "运行对象缺失",
  drifted: "运行对象发生变化",
};
const syncStates: Record<string, string> = {
  unavailable: "未确认",
  disabled: "未启用",
  waiting: "等待核对",
  collecting: "正在采集",
  current: "最近采样已同步",
  stopping: "正在停用",
  paused: "已暂停",
  failed: "同步失败",
  recovery_required: "原事务待核对",
  recovering: "正在恢复启动范围",
};
async function load() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  view.value = null;
  try {
    const result = await api.fail2banHostInput(controller.signal);
    if (!closed) view.value = result;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) busy.value = false;
  }
}
onMounted(() => {
  void load();
});
onUnmounted(() => {
  closed = true;
  controller.abort();
});
</script>
<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h3>宿主机入口动作</h3>
      <NButton :loading="busy" :disabled="busy" @click="load">
        刷新状态
      </NButton>
    </div>
    <NAlert type="warning">
      宿主机入口动作适用于本机直连流量。代理和 Docker 转发须单独核对。
    </NAlert>
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <template v-if="view">
      <NAlert
        v-if="view.sync.reason"
        :type="view.sync.state === 'waiting' ? 'info' : 'warning'"
      >
        {{ view.sync.reason }}
      </NAlert>
      <div class="toolbar">
        <NTag :type="view.can_prepare ? 'info' : 'warning'">
          {{
            view.can_prepare ? "候选计划已生成" : "准备条件不满足"
          }}
        </NTag><span class="muted">采样 {{ new Date(view.at * 1000).toLocaleString() }}</span>
      </div>
      <NAlert v-if="view.reason" type="warning">
        {{ view.reason }}
      </NAlert>
      <NAlert
        v-if="
          view.registration.reason && view.registration.reason !== view.reason
        "
        type="warning"
      >
        {{ view.registration.reason }}
      </NAlert>
      <NAlert
        v-if="view.protection.reason && view.protection.reason !== view.reason"
        type="warning"
      >
        {{ view.protection.reason }}
      </NAlert>
      <NAlert
        v-if="view.sources.reason && view.sources.reason !== view.reason"
        type="warning"
      >
        {{ view.sources.reason }}
      </NAlert>
      <NAlert
        v-if="view.runtime.reason && view.runtime.reason !== view.reason"
        :type="view.runtime.verified ? 'info' : 'warning'"
      >
        {{ view.runtime.reason }}
      </NAlert>
      <NDescriptions label-placement="left" :column="2" bordered>
        <NDescriptionsItem label="持续同步">
          {{
            syncStates[view.sync.state] || "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="等待同步">
          {{
            view.sync.queued ? "是" : "否"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem v-if="view.sync.retirement_id" label="退役操作">
          {{
            view.sync.retirement_id
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="重启恢复">
          {{
            view.sync.recover_on_boot ? "已批准" : "未启用"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem v-if="view.sync.recovery_id" label="启动恢复操作">
          {{
            view.sync.recovery_id
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="同步采样时间">
          {{
            view.sync.collected_at
              ? new Date(view.sync.collected_at * 1000).toLocaleString()
              : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="同步核对时间">
          {{
            view.sync.confirmed_at
              ? new Date(view.sync.confirmed_at * 1000).toLocaleString()
              : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="观测范围">
          {{
            view.scope === "host" ? "宿主机" : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="目标后端">
          直接 nftables
        </NDescriptionsItem>
        <NDescriptionsItem label="已发现管理器">
          {{
            managers[view.manager] || view.manager
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="管理器采样">
          {{
            view.manager_observed_at
              ? new Date(view.manager_observed_at * 1000).toLocaleString()
              : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="独立目标表">
          inet {{ view.table }}
        </NDescriptionsItem>
        <NDescriptionsItem label="流量入口">
          INPUT · 优先级 {{ view.priority }}
        </NDescriptionsItem>
        <NDescriptionsItem label="现有目标表">
          {{
            view.kernel.available
              ? view.kernel.table_exists
                ? view.registration.verified
                  ? view.kernel.chains
                    ? "已登记动作表"
                    : "已登记空表"
                  : "已存在，禁止接管"
                : "未发现"
              : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="本机所有权">
          {{
            registrations[view.registration.state] || "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="管理与代理来源">
          {{
            protections[view.protection.state] || "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="来源批准时间">
          {{
            view.protection.approved_at
              ? new Date(view.protection.approved_at * 1000).toLocaleString()
              : "未批准"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="内核代次">
          {{
            view.kernel.available ? view.kernel.generation : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="受管宿主机来源">
          {{
            view.sources.managed ? "已授权" : "未授权"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="官方封禁来源">
          {{
            sources[view.sources.state] || "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="封禁采样时间">
          {{
            view.sources.collected_at
              ? new Date(view.sources.collected_at * 1000).toLocaleString()
              : "未完整采集"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="候选封禁地址">
          {{
            view.sources.state === "ready" ? view.sources.banned_count : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="保护排除地址">
          {{
            view.sources.state === "ready"
              ? view.sources.protected_count
              : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="当前运行规则">
          {{
            runtimes[view.runtime.state] || "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="已核对的规则封禁地址">
          {{
            view.runtime.verified ? view.runtime.banned_count : "未确认"
          }}
        </NDescriptionsItem>
        <NDescriptionsItem label="最近运行操作时间">
          {{
            view.runtime.updated_at
              ? new Date(view.runtime.updated_at * 1000).toLocaleString()
              : "无"
          }}
        </NDescriptionsItem>
      </NDescriptions>
      <NDescriptions
        v-if="view.sources.jails.length"
        label-placement="left"
        :column="1"
        bordered
      >
        <NDescriptionsItem label="已批准的 jail">
          {{
            view.sources.jails.join("、")
          }}
        </NDescriptionsItem>
      </NDescriptions>
      <NDescriptions
        v-if="view.protection.id && view.protection.state !== 'revoked'"
        label-placement="left"
        :column="1"
        bordered
      >
        <NDescriptionsItem label="管理来源">
          <code v-for="source in view.protection.admin_sources" :key="source">{{ source }}
          </code>
        </NDescriptionsItem>
        <NDescriptionsItem label="前置代理来源">
          <template v-if="view.protection.proxy_sources.length">
            <code v-for="source in view.protection.proxy_sources" :key="source">{{ source }}
            </code>
          </template>
          <span v-else>无</span>
        </NDescriptionsItem>
      </NDescriptions>
      <template v-if="view.can_prepare">
        <p class="muted">
          候选计划包含 {{ view.sources.banned_count }} 个封禁地址、
          {{ view.protected_sources.length }} 项本地、管理与代理来源保护、{{
            view.generated_rules
          }}
          条规则，事务
          {{ view.transaction_bytes }}
          字节。本次候选计划尚未提交，当前规则另见运行状态。
        </p>
        <details>
          <summary>查看保护来源</summary>
          <p>{{ view.protected_sources.join("、") }}</p>
        </details>
      </template>
    </template>
  </section>
</template>
