<script setup lang="ts">
import { computed } from "vue";
import { NAutoComplete, NInput, NInputNumber, NSelect } from "naive-ui";
import ValueListInput from "./ValueListInput.vue";
import NginxListeners from "./NginxListeners.vue";
import NginxHeaders from "./NginxHeaders.vue";
import UnitInput from "./UnitInput.vue";
import EndpointInput from "./EndpointInput.vue";
import { cleanList, nginxArgs, nginxQuote } from "../utils/form";
const props = defineProps<{ value: string; name: string; format: string; kind: string; resourceId: string; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
const values = computed({
  get: () => props.value ? props.value.split(props.format === "tokens" ? /\s+/ : "\n") : [],
  set: (value: string[]) => emit("update:value", value.join(props.format === "tokens" ? " " : "\n")),
});
const protocols = computed({ get: () => cleanList(values.value), set: (value: string[]) => { values.value = value; } });
const numeric = computed({ get: () => props.value === "" ? null : Number(props.value), set: (value: number | null) => emit("update:value", value === null ? "" : String(value)) });
const logParts = computed(() => nginxArgs(props.value));
const logMode = computed({
  get: () => !props.value ? "inherit" : logParts.value[0] === "off" || logParts.value[0] === "/dev/null" ? "off" : "enabled",
  set: (value: string) => {
    const path = `logs/${props.kind === "http" ? "nginx" : "stream"}/${props.resourceId}/${props.name === "error_log" ? "error" : "access"}.log`;
    emit("update:value", value === "inherit" ? "" : value === "off" ? (props.name === "access_log" ? "off" : "/dev/null crit") : `${path} ${props.name === "error_log" ? "warn" : props.kind === "http" ? "nginxpanel_http" : "nginxpanel_stream"}`);
  },
});
function updateLog(index: number, value: string) {
  const args = [...logParts.value]; args[index] = value;
  emit("update:value", args.filter((value, index) => index === 0 || value !== "").map(nginxQuote).join(" "));
}
</script>
<template>
  <NginxListeners v-if="name === 'listeners'" :value="value" :kind="kind" :disabled="disabled" @update:value="emit('update:value', $event)" />
  <EndpointInput v-else-if="name === 'upstream' && kind === 'stream'" :value="value" :disabled="disabled" @update:value="emit('update:value', $event)" />
  <ValueListInput v-else-if="name === 'domains' || name === 'trusted_sources'" v-model:value="values" :item-label="name === 'domains' ? '域名' : '来源地址'" :placeholder="name === 'domains' ? 'example.com 或 *.example.com' : '192.0.2.1 或 192.0.2.0/24'" :disabled="disabled" :maxlength="name === 'domains' ? 253 : 64" />
  <NginxHeaders v-else-if="name === 'request_headers' || name === 'response_headers'" :value="value" :response="name === 'response_headers'" :disabled="disabled" @update:value="emit('update:value', $event)" />
  <NSelect v-else-if="name === 'tls_protocols'" v-model:value="protocols" multiple :options="[{ label: 'TLS 1.2', value: 'TLSv1.2' }, { label: 'TLS 1.3', value: 'TLSv1.3' }]" :disabled="disabled" placeholder="继承默认协议" />
  <NSelect v-else-if="name === 'http_version'" :value="value" :options="[{ label: '继承默认', value: '' }, { label: 'HTTP/1.0', value: '1.0' }, { label: 'HTTP/1.1', value: '1.1' }]" :disabled="disabled" @update:value="emit('update:value', $event)" />
  <UnitInput v-else-if="name.endsWith('_timeout') || name === 'body_size'" :value="value" :kind="name === 'body_size' ? 'size' : 'time'" :disabled="disabled" @update:value="emit('update:value', $event)" />
  <NInputNumber v-else-if="name === 'responses' || name === 'https_redirect'" v-model:value="numeric" :min="name === 'responses' ? 0 : 1" :max="name === 'responses' ? 1024 : 65535" :precision="0" :disabled="disabled" :placeholder="name === 'responses' ? '继承默认' : '未开启跳转'" />
  <NAutoComplete v-else-if="name === 'real_ip_header'" :value="value" :options="['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP']" :disabled="disabled" placeholder="选择或输入请求头名称" @update:value="emit('update:value', $event)" />
  <div v-else-if="name === 'access_log' || name === 'error_log'" class="field-list">
    <NSelect v-model:value="logMode" :options="[{ label: '继承默认', value: 'inherit' }, { label: '开启日志', value: 'enabled' }, { label: '关闭日志', value: 'off' }]" :disabled="disabled" />
    <template v-if="logMode === 'enabled'">
      <label class="field-label">日志位置<NInput :value="logParts[0]" :disabled="disabled" placeholder="日志路径" @update:value="updateLog(0, $event)" /></label>
      <label class="field-label">{{ name === 'error_log' ? '日志级别' : '日志格式' }}<NSelect :value="logParts[1] || ''" :options="(name === 'error_log' ? ['', 'debug', 'info', 'notice', 'warn', 'error', 'crit', 'alert', 'emerg'] : kind === 'http' ? ['', 'nginxpanel_http', 'combined'] : ['nginxpanel_stream']).map((value) => ({ label: value || '继承默认', value }))" :disabled="disabled" @update:value="updateLog(1, $event)" /></label>
    </template>
  </div>
  <ValueListInput v-else-if="format === 'lines' || format === 'tokens'" v-model:value="values" :disabled="disabled" />
  <NInput v-else :value="value" :disabled="disabled" :placeholder="name === 'upstream' ? 'http://127.0.0.1:3000 或 https://example.com' : name === 'location_prefix' ? '/' : '未设置'" @update:value="emit('update:value', $event)" />
</template>
