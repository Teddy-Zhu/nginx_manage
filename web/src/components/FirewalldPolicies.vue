<script setup lang="ts">
import { NAlert, NCollapse, NCollapseItem, NEmpty, NTag } from "naive-ui";
import type { FirewallObservation } from "../api/client";

type Inventory = FirewallObservation["firewalld"]["policy_inventory"];
type Policy = Inventory["policies"][number];
defineProps<{
  inventory: Inventory;
  registration: FirewallObservation["firewalld"]["registration"];
}>();
const registrationNames: Record<string, string> = {
  unavailable: "无法核对",
  unregistered: "未登记",
  registered: "已登记空策略",
  managed: "已登记受管策略",
  released: "已释放登记",
  missing: "登记策略缺失",
  drifted: "登记对象变化",
  recovery_required: "待本机恢复",
};

function comparison(policy: Policy) {
  if (!policy.runtime) return "仅永久配置";
  if (!policy.permanent) return "仅运行配置";
  return policy.runtime.hash === policy.permanent.hash
    ? "返回配置一致"
    : "返回配置存在差异";
}
function variants(policy: Policy) {
  return [
    { label: "运行配置", settings: policy.runtime },
    { label: "永久配置", settings: policy.permanent },
  ];
}
const flag = (value: boolean | null) =>
  value === null ? "未知" : value ? "是" : "否";
</script>

<template>
  <h4>独立登记</h4>
  <dl>
    <dt>状态 / 完整设置核对</dt>
    <dd>
      {{ registrationNames[registration.state] }} /
      {{ registration.verified ? "通过" : "未通过" }}
    </dd>
    <dt v-if="registration.operation_id">
      操作编号
    </dt>
    <dd v-if="registration.operation_id">
      {{ registration.operation_id }}
    </dd>
  </dl>
  <n-alert v-if="registration.reason" type="warning" :bordered="false">
    {{ registration.reason }}
  </n-alert>
  <h4>Policy 配置</h4>
  <n-alert v-if="!inventory.available" type="warning" :bordered="false">
    {{ inventory.reason }}
  </n-alert>
  <template v-else>
    <p class="muted">
      运行与永久配置分别读取。摘要比较仅针对返回配置，不证明内核规则一致或外部可达。
    </p>
    <n-empty v-if="!inventory.policies.length" description="未观察到 policy" />
    <n-collapse v-else>
      <n-collapse-item
        v-for="policy in inventory.policies"
        :key="policy.name"
        :name="policy.name"
        :title="policy.name"
      >
        <template #header-extra>
          <span class="tags">
            <n-tag size="small">{{ policy.active ? "活动" : "非活动" }}</n-tag>
            <n-tag
              size="small"
              :type="
                policy.runtime &&
                  policy.permanent &&
                  policy.runtime.hash === policy.permanent.hash
                  ? 'default'
                  : 'warning'
              "
            >{{ comparison(policy) }}</n-tag>
          </span>
        </template>
        <dl v-if="policy.active">
          <dt>活动策略入口 zone</dt>
          <dd>{{ policy.active_ingress_zones.join("、") }}</dd>
          <dt>活动策略出口 zone</dt>
          <dd>{{ policy.active_egress_zones.join("、") }}</dd>
        </dl>
        <div
          v-for="variant in variants(policy)"
          :key="variant.label"
          class="variant"
        >
          <strong>{{ variant.label }}</strong>
          <p v-if="!variant.settings" class="muted">
            未观察到
          </p>
          <dl v-else>
            <dt>目标 / 优先级</dt>
            <dd>
              {{ variant.settings.target || "未知" }} /
              {{ variant.settings.priority ?? "未知" }}
            </dd>
            <dt>入口 zone</dt>
            <dd>{{ variant.settings.ingress_zones.join("、") || "无" }}</dd>
            <dt>出口 zone</dt>
            <dd>{{ variant.settings.egress_zones.join("、") || "无" }}</dd>
            <dt>配置条目 / rich rules</dt>
            <dd>
              {{ variant.settings.entries }} / {{ variant.settings.rich_rules }}
            </dd>
            <dt>地址伪装</dt>
            <dd>{{ flag(variant.settings.masquerade) }}</dd>
            <dt>配置摘要</dt>
            <dd>
              <code>{{ variant.settings.hash }}</code>
            </dd>
          </dl>
        </div>
      </n-collapse-item>
    </n-collapse>
  </template>
</template>

<style scoped>
h4 {
  margin: 20px 0 12px;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.variant {
  margin-top: 14px;
}
dl {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 8px;
}
dt {
  color: #6d7772;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
</style>
