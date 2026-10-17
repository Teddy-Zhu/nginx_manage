<script setup lang="ts">
import { NAlert, NDataTable, type DataTableColumns } from "naive-ui";
import type { FirewallObservation } from "../api/client";

defineProps<{ value: FirewallObservation["docker"] }>();
type Port = FirewallObservation["docker"]["runtime"]["ports"][number];
type Capability = FirewallObservation["docker"]["capabilities"][number];
const familyName = (value: string) =>
  value === "ipv4" ? "IPv4" : value === "ipv6" ? "IPv6" : "未报告";
const registrationNames: Record<string, string> = {
  unavailable: "未核对",
  unregistered: "未授权",
  registered: "已授权",
  released: "已释放",
  drifted: "待重新核对",
  recovery_required: "待恢复",
};
const registrationName = (state: string) => registrationNames[state] ?? state;
const ports: DataTableColumns<Port> = [
  { title: "容器", key: "container_id", width: 150, ellipsis: { tooltip: true } },
  { title: "地址族", key: "family", width: 100, render: (r) => familyName(r.family) },
  {
    title: "协议",
    key: "protocol",
    width: 80,
    render: (r) => r.protocol.toUpperCase(),
  },
  {
    title: "主机发布地址",
    key: "host_ip",
    width: 190,
    render: (r) => r.host_ip || "未报告",
  },
  {
    title: "主机端口",
    key: "host_port",
    width: 110,
    render: (r) => r.host_port || "未报告",
  },
  { title: "容器端口", key: "container_port", width: 100 },
  {
    title: "路径观察",
    key: "path",
    width: 160,
    render: (r) =>
      r.path === "bridge_nat_candidate" ? "bridge/NAT 候选" : "未确认",
  },
  { title: "原因", key: "reason", minWidth: 290, ellipsis: { tooltip: true } },
];
const capabilities: DataTableColumns<Capability> = [
  { title: "策略后端", key: "backend", width: 150 },
  { title: "地址族", key: "family", width: 90, render: (r) => familyName(r.family) },
  { title: "挂接点", key: "hook", width: 145, render: (r) => r.hook || "未确认" },
  {
    title: "挂接观察",
    key: "observed",
    width: 115,
    render: (r) => (r.observed ? "已观察到" : "未确认"),
  },
  {
    title: "可配置",
    key: "supported",
    width: 95,
    render: (r) => (r.supported ? "是" : "否"),
  },
  { title: "原因", key: "reason", minWidth: 300, ellipsis: { tooltip: true } },
];
</script>

<template>
  <div>
    <h4>Docker 转发本机授权</h4>
    <dl>
      <dt>授权状态</dt><dd>{{ registrationName(value.registration.registration.state) }}</dd>
      <template v-if="value.registration.backend">
        <dt>授权后端</dt><dd>{{ value.registration.backend }}</dd>
        <dt>授权实例摘要</dt><dd class="digest">{{ value.registration.engine_hash }}</dd>
        <dt>原宿主机登记</dt><dd>{{ value.registration.parent_operation_id }}</dd>
      </template>
    </dl>
    <n-alert :type="value.registration.registration.verified ? 'info' : 'warning'" :bordered="false">
      {{ value.registration.registration.reason }}
    </n-alert>
    <n-alert :type="value.runtime.available ? 'info' : 'warning'" :bordered="false">
      {{ value.runtime.reason }}
    </n-alert>
    <template v-if="value.runtime.available">
      <dl>
        <dt>Docker 版本 / API</dt>
        <dd>{{ value.runtime.version }} / {{ value.runtime.api_version }}</dd>
        <dt>观察时间</dt>
        <dd>{{ new Date(value.runtime.observed_at * 1000).toLocaleString() }}</dd>
        <dt>运行容器 / 网络</dt>
        <dd>{{ value.runtime.containers }} / {{ value.runtime.networks }}</dd>
        <dt>主机端口映射</dt>
        <dd>{{ value.runtime.published_ports }}</dd>
        <dt>rootless / Swarm</dt>
        <dd>
          {{ value.runtime.rootless ? "是" : "否" }} / {{ value.runtime.swarm }}
        </dd>
      </dl>
      <h4>主机端口映射</h4>
      <p class="muted">
        0.0.0.0 和 :: 表示通配绑定。容器暴露端口、主机映射和转发保护需分别核对；
        此清单不证明端口可达或已经受保护。
      </p>
      <p v-if="value.runtime.truncated" class="muted">
        仅展示前 128 项，全部映射均参与数量及前后报告核对。
      </p>
      <n-data-table
        :columns="ports"
        :data="value.runtime.ports"
        :pagination="{ pageSize: 20 }"
        :scroll-x="1300"
      />
    </template>
    <template v-if="value.capabilities.length">
      <h4>发布端口规则能力</h4>
      <n-data-table
        :columns="capabilities"
        :data="value.capabilities"
        :scroll-x="1000"
      />
    </template>
  </div>
</template>

<style scoped>
.digest { overflow-wrap: anywhere; }
</style>
