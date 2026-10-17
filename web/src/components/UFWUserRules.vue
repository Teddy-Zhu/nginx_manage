<script setup lang="ts">
import { NAlert, NCollapse, NCollapseItem, NEmpty } from "naive-ui";
import type { FirewallObservation } from "../api/client";

defineProps<{
  inventory: FirewallObservation["ufw"]["rule_inventory"];
}>();
</script>

<template>
  <n-alert v-if="!inventory.available" type="warning" :bordered="false">
    {{ inventory.reason }}
  </n-alert>
  <template v-else>
    <dl>
      <dt>用户规则报告</dt>
      <dd>{{ inventory.rules }} 条命令记录</dd>
      <dt>完整报告摘要</dt>
      <dd>
        <code>{{ inventory.hash }}</code>
      </dd>
    </dl>
    <p class="muted">
      报告可能合并双栈显示，顺序由 UFW 汇总；不代表实际内核规则数量、受管所有权或流量已受保护。
    </p>
    <n-empty v-if="!inventory.rules" description="未配置用户规则" />
    <n-collapse v-else>
      <n-collapse-item title="查看用户规则报告" name="commands">
        <pre>{{ inventory.commands.join("\n") }}</pre>
      </n-collapse-item>
    </n-collapse>
    <p v-if="inventory.truncated" class="muted">
      仅展示前 128 条且最多 64 KiB，全部报告已参与格式检查、计数和摘要。
    </p>
  </template>
</template>

<style scoped>
dl {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: 8px 16px;
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
pre {
  max-height: 360px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
