<route lang="json">
{
  "meta": {
    "title": "FRP 服务端",
    "subtitle": "管理客户端连接、端口映射和网站转发",
    "nav": true,
    "order": 21,
    "symbol": "⇄",
    "group": "应用管理"
  }
}
</route>
<script setup lang="ts">
import FrpsInstallPanel from "../components/FrpsInstallPanel.vue";
</script>
<template>
  <div class="page-stack"><FrpsInstallPanel /></div>
</template>
