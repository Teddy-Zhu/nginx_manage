<script setup lang="ts">
import { ref, watch } from "vue";
import { NAlert, NButton, NInput, NSwitch } from "naive-ui";
import { nginxArgs, nginxQuote } from "../utils/form";
const props = defineProps<{ value: string; response?: boolean; disabled?: boolean }>();
const emit = defineEmits<{ "update:value": [value: string] }>();
type Header = { name: string; value: string; always: boolean };
const rows = ref<Header[]>([]), error = ref("");
let emitted: string | undefined;
watch(() => props.value, (value) => {
  if (value === emitted) return;
  try {
    rows.value = value.split("\n").filter((line) => line.trim()).map((line) => {
      const args = nginxArgs(line);
      if (args.length < 2 || args.length > 3 || (args[2] && args[2] !== "always")) throw new Error();
      return { name: args[0]!, value: args[1]!, always: args[2] === "always" };
    });
    error.value = "";
  } catch { error.value = `此${props.response ? "响应头" : "请求头"}包含复杂参数，请通过高级源文件编辑调整。`; }
}, { immediate: true });
function update() {
  emitted = rows.value.filter((row) => row.name || row.value).map((row) => `${nginxQuote(row.name.trim())} ${nginxQuote(row.value)}${props.response && row.always ? " always" : ""}`).join("\n");
  emit("update:value", emitted);
}
function remove(index: number) { rows.value.splice(index, 1); update(); }
</script>
<template>
  <NAlert v-if="error" type="warning">{{ error }}</NAlert>
  <div v-else class="headers-input">
    <div v-for="(row, index) in rows" :key="index" class="header-row">
      <label>名称<NInput v-model:value="row.name" :placeholder="response ? '例如 X-Content-Type-Options' : '例如 X-Forwarded-For'" :maxlength="64" :disabled="disabled" @update:value="update" /></label>
      <label>值<NInput v-model:value="row.value" :placeholder="`${response ? '响应头' : '请求头'}值，可使用 Nginx 变量`" :maxlength="2048" :disabled="disabled" @update:value="update" /></label>
      <label v-if="response" class="always">所有响应<NSwitch v-model:value="row.always" :disabled="disabled" @update:value="update" /></label>
      <NButton attr-type="button" :disabled="disabled" :aria-label="`移除${response ? '响应头' : '请求头'} ${index + 1}`" @click="remove(index)">移除</NButton>
    </div>
    <NButton attr-type="button" dashed :disabled="disabled || rows.length >= 128" @click="rows.push({ name: '', value: '', always: false })">＋ 添加{{ response ? '响应头' : '请求头' }}</NButton>
  </div>
</template>
<style scoped>
.headers-input { width: 100%; display: grid; gap: 12px; }
.header-row { display: flex; align-items: end; gap: 10px; flex-wrap: wrap; }
label { display: grid; gap: 6px; font-size: 13px; min-width: 0; flex: 1; }
label.always { flex: 0 0 auto; align-self: center; }
.header-row > label:not(.always) { min-width: 150px; }
.headers-input > :last-child { justify-self: start; }
</style>
