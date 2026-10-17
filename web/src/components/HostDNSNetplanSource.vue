<script setup lang="ts">
import { NAlert, NTag } from "naive-ui";
import type { HostNetplanSource } from "../api/client";
defineProps<{ source: HostNetplanSource }>();
function state(value: boolean | null, yes: string, no: string) {
  return value === null ? "未显式设置" : value ? yes : no;
}
</script>

<template>
  <div class="page-stack">
    <div class="actions">
      <h4>netplan 上游配置</h4>
      <NTag type="info">{{
        source.state === "associated" ? "已关联来源 · 只读" : "来源待确认"
      }}</NTag>
    </div>
    <dl>
      <template v-if="source.definition">
        <dt>定义 / 设备类型</dt>
        <dd>{{ source.definition }} · {{ source.device_type }}</dd>
      </template>
      <dt>渲染后端</dt>
      <dd>{{ source.renderer }}</dd>
      <dt>合并源文件</dt>
      <dd>{{ source.sources.join("、") || "未确认" }}</dd>
      <template v-if="source.settings">
        <dt>配置的 DNS</dt>
        <dd>{{ source.settings.servers.join("、") || "无显式地址" }}</dd>
        <dt>搜索域</dt>
        <dd>{{ source.settings.search.join("、") || "无" }}</dd>
        <dt>路由域</dt>
        <dd>{{ source.settings.routing_domains.join("、") || "无" }}</dd>
        <dt>DHCPv4 / 自动 DNS 设置</dt>
        <dd>
          {{ state(source.settings.dhcp4, "启用 DHCP", "停用 DHCP") }} ·
          {{
            state(source.settings.use_dns4, "允许 DHCP DNS", "忽略 DHCP DNS")
          }}
        </dd>
        <dt>DHCPv6 / 自动 DNS 设置</dt>
        <dd>
          {{ state(source.settings.dhcp6, "启用 DHCP", "停用 DHCP") }} ·
          {{
            state(source.settings.use_dns6, "允许 DHCP DNS", "忽略 DHCP DNS")
          }}
        </dd>
        <dt>IPv6 RA</dt>
        <dd>{{ state(source.settings.accept_ra, "允许", "忽略") }}</dd>
      </template>
      <template v-else
        ><dt>源 DNS 字段</dt>
        <dd>无法完整确认</dd></template
      >
    </dl>
    <NAlert v-if="source.reason" type="warning">{{ source.reason }}</NAlert>
  </div>
</template>
