<script setup lang="ts">
import { NAlert, NTag } from "naive-ui";
import type { MigrationFirewallPlan } from "../api/client";
defineProps<{ info: MigrationFirewallPlan }>();
const modes: Record<string, string> = {
  preserve: "保留目标",
  merge: "合并期望规则",
  replace: "替换期望规则",
};
const states: Record<string, string> = {
  preserved: "目标保持原状",
  pending_import: "待导入",
  saved_unapplied: "已保存，未应用",
  restored: "已补偿恢复",
  recovery_required: "需要恢复",
};
const actions: Record<string, string> = {
  allow: "允许",
  deny: "丢弃",
  reject: "拒绝",
};
</script>

<template>
  <div class="stack">
    <div class="toolbar">
      <h3>防火墙规则</h3>
      <NTag
        >{{ modes[info.mode] || info.mode }} ·
        {{ states[info.state] || info.state }}</NTag
      >
    </div>
    <p>
      源后端 {{ info.source_backend }} · 源规则 {{ info.source_rules }} 条<span
        v-if="info.mode !== 'preserve'"
      >
        · 目标后端 {{ info.target_backend }} · 基础版本 {{ info.base_version
        }}<span v-if="info.saved_version">
          · 保存版本 {{ info.saved_version }}</span
        ></span
      >
    </p>
    <p v-if="info.mode !== 'preserve'">
      保留 {{ info.preserved_rules }} 条，替换
      {{ info.replaced_rules }} 条，迁入后共 {{ info.total_rules }} 条。Nginx
      应用不触发防火墙应用。
    </p>
    <NAlert
      v-for="(warning, index) in info.warnings"
      :key="index"
      type="warning"
      >{{ warning }}</NAlert
    >
    <div v-if="info.interfaces.length" class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>源接口</th>
            <th>目标接口</th>
            <th>目标核对</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in info.interfaces" :key="item.source">
            <td>{{ item.source }}</td>
            <td>
              {{
                info.mode === "preserve"
                  ? "保留目标"
                  : item.resolved
                    ? item.target || "解除绑定"
                    : "缺少映射"
              }}
            </td>
            <td>
              {{
                info.mode === "preserve"
                  ? "不迁入"
                  : !item.resolved
                    ? "待映射"
                    : !item.target
                      ? "无需绑定"
                      : item.observed
                        ? "已发现"
                        : "尚未确认可用"
              }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="info.entries.length" class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>规则</th>
            <th>状态</th>
            <th>范围 / 顺序</th>
            <th>地址族 / 协议</th>
            <th>端口</th>
            <th>来源</th>
            <th>接口</th>
            <th>动作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="rule in info.entries" :key="rule.id">
            <td>{{ rule.name }}</td>
            <td>{{ rule.enabled ? "启用期望" : "停用期望" }}</td>
            <td>
              {{
                rule.scope === "host_input" ? "主机入站" : "Docker 发布端口"
              }}
              / {{ rule.priority }}
            </td>
            <td>{{ rule.family }} / {{ rule.protocol }}</td>
            <td>
              {{
                rule.ports
                  .map((port) =>
                    port.from === port.to
                      ? `${port.from}`
                      : `${port.from}–${port.to}`,
                  )
                  .join(", ") || "全部"
              }}
            </td>
            <td>{{ rule.sources.join(", ") || "全部" }}</td>
            <td>{{ rule.interface || "全部" }}</td>
            <td>{{ actions[rule.action] || rule.action }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="info.truncated" class="muted">
      仅展示前
      {{
        info.entries.length
      }}
      条源规则预览；导入后的完整期望规则可在目标防火墙页面查看。
    </p>
  </div>
</template>
