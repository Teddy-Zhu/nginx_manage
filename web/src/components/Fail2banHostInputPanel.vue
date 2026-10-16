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
  registered: "空表登记已核对",
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
      <h3>宿主机入口动作预检</h3>
      <NButton :loading="busy" :disabled="busy" @click="load">刷新预检</NButton>
    </div>
    <NAlert type="warning"
      >当前仅提供基础准备计划，自动封禁尚不可用。宿主机入口适用于本机直连流量；代理和
      Docker 转发须单独核对。</NAlert
    >
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <template v-if="view">
      <div class="toolbar">
        <NTag :type="view.can_prepare ? 'info' : 'warning'">{{
          view.can_prepare ? "可生成基础计划" : "准备条件不满足"
        }}</NTag
        ><span class="muted"
          >采样 {{ new Date(view.at * 1000).toLocaleString() }}</span
        >
      </div>
      <NAlert v-if="view.reason" type="warning">{{ view.reason }}</NAlert>
      <NAlert
        v-if="
          view.registration.reason && view.registration.reason !== view.reason
        "
        type="warning"
        >{{ view.registration.reason }}</NAlert
      >
      <NAlert
        v-if="view.protection.reason && view.protection.reason !== view.reason"
        type="warning"
        >{{ view.protection.reason }}</NAlert
      >
      <NDescriptions label-placement="left" :column="2" bordered>
        <NDescriptionsItem label="观测范围">{{
          view.scope === "host" ? "宿主机" : "未确认"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="目标后端">直接 nftables</NDescriptionsItem>
        <NDescriptionsItem label="已发现管理器">{{
          managers[view.manager] || view.manager
        }}</NDescriptionsItem>
        <NDescriptionsItem label="管理器采样">{{
          view.manager_observed_at
            ? new Date(view.manager_observed_at * 1000).toLocaleString()
            : "未确认"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="独立目标表"
          >inet {{ view.table }}</NDescriptionsItem
        >
        <NDescriptionsItem label="流量入口"
          >INPUT · 优先级 {{ view.priority }}</NDescriptionsItem
        >
        <NDescriptionsItem label="现有目标表">{{
          view.kernel.available
            ? view.kernel.table_exists
              ? view.registration.verified
                ? "已登记空表"
                : "已存在，禁止接管"
              : "未发现"
            : "未确认"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="本机所有权">{{
          registrations[view.registration.state] || "未确认"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="管理与代理来源">{{
          protections[view.protection.state] || "未确认"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="来源批准时间">{{
          view.protection.approved_at
            ? new Date(view.protection.approved_at * 1000).toLocaleString()
            : "未批准"
        }}</NDescriptionsItem>
        <NDescriptionsItem label="内核代次">{{
          view.kernel.available ? view.kernel.generation : "未确认"
        }}</NDescriptionsItem>
      </NDescriptions>
      <NDescriptions
        v-if="view.protection.id && view.protection.state !== 'revoked'"
        label-placement="left"
        :column="1"
        bordered
      >
        <NDescriptionsItem label="管理来源">
          <code v-for="source in view.protection.admin_sources" :key="source"
            >{{ source }}
          </code>
        </NDescriptionsItem>
        <NDescriptionsItem label="前置代理来源">
          <template v-if="view.protection.proxy_sources.length">
            <code v-for="source in view.protection.proxy_sources" :key="source"
              >{{ source }}
            </code>
          </template>
          <span v-else>无</span>
        </NDescriptionsItem>
      </NDescriptions>
      <template v-if="view.can_prepare">
        <p class="muted">
          基础计划包含
          {{ view.protected_sources.length }} 项本地地址及保留网段保护、{{
            view.generated_rules
          }}
          条规则，事务
          {{ view.transaction_bytes }}
          字节。当前不包含封禁地址或待批准的代理、管理来源。
        </p>
        <details>
          <summary>查看保护来源</summary>
          <p>{{ view.protected_sources.join("、") }}</p>
        </details>
      </template>
    </template>
  </section>
</template>
