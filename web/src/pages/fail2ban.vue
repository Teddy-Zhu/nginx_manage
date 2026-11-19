<route lang="json">
{
  "meta": {
    "title": "登录防护",
    "nav": true,
    "order": 31,
    "symbol": "◈",
    "group": "安全防护",
    "software": "fail2ban"
  }
}
</route>
<script setup lang="ts">
import Fail2banSettings from "../components/Fail2banSettings.vue";
</script>
<template>
  <Fail2banSettings />
</template>
