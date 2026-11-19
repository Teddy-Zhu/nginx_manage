<script setup lang="ts">
import { RouterLink } from "vue-router";
import { dnsLocationLabel } from "../utils/form";
import type { MigrationHostDNSPlan, HostDNSPlanInput } from "../api/client";
defineProps<{ info: MigrationHostDNSPlan; planId?: string }>();
const stateLabels = {
  preserved: "保留目标配置",
  pending_import: "待保存迁移材料",
  staged: "已保存迁移材料，DNS 尚未应用",
};
const readinessLabels = {
  preserved: "保留",
  ready: "可生成变更计划",
  blocked: "需要处理",
};
function describe(config: HostDNSPlanInput["config"]) {
  if (!config.ipv4 && !config.ipv6)
    return `${config.servers.join("、")}；搜索域：${config.search.join("、") || "无"}`;
  return [config.ipv4, config.ipv6]
    .map((family, index) =>
      family
        ? `${index === 0 ? "IPv4" : "IPv6"}：${family.servers.join("、") || "无手动地址"}；${family.automatic ? "自动获取" : "手动 DNS"}；搜索域：${family.search.join("、") || "无"}`
        : "",
    )
    .filter(Boolean)
    .join(" / ");
}
</script>
<template>
  <div class="surface">
    <h3>主机 DNS</h3>
    <p>{{ stateLabels[info.state] }}</p>
    <p v-if="!info.entries.length">
      来源服务器没有已保存的 DNS 配置。
    </p>
    <dl v-for="item in info.entries" :key="item.source" class="details">
      <dt>来源网络</dt>
      <dd>{{ dnsLocationLabel(item.source) }}</dd>
      <dt>源配置</dt>
      <dd>{{ describe(item.source_config) }}</dd>
      <template v-if="item.target !== null && item.config">
        <dt>目标</dt>
        <dd>{{ dnsLocationLabel(item.target) }}</dd>
        <dt>目标配置</dt>
        <dd>{{ describe(item.config) }}</dd>
      </template>
      <dt>状态</dt>
      <dd>
        {{ readinessLabels[item.readiness]
        }}<span v-if="item.reason">：{{ item.reason }}</span>
      </dd>
      <template
        v-if="planId && info.state === 'staged' && item.target !== null"
      >
        <dt>操作</dt>
        <dd>
          <RouterLink
            :to="{
              path: '/host-dns',
              query: { migration: planId, source: item.source },
            }"
          >
            在目标 DNS 页面配置
          </RouterLink>
        </dd>
      </template>
    </dl>
    <p v-if="info.mode === 'map'">
      迁移完成后，请到网络设置中应用 DNS 配置并确认连接正常。
    </p>
  </div>
</template>
