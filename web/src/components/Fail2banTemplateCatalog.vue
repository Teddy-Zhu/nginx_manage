<script setup lang="ts">
import { computed, onUnmounted, ref } from "vue";
import { NAlert, NButton, NTag } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type Fail2banTemplate,
  type Fail2banTemplateCheck,
} from "../api/client";

const props = defineProps<{
  templates: Fail2banTemplate[];
  checks?: Fail2banTemplateCheck[];
}>();
const api = useNodeAPI(),
  controller = new AbortController();
const checking = ref(false),
  error = ref(""),
  local = ref<Fail2banTemplateCheck[]>([]);
let closed = false;
const latest = computed(() => {
  const out = new Map<string, Fail2banTemplateCheck>();
  for (const item of [...(props.checks || []), ...local.value]) {
    const definition = props.templates.find(
      (template) => template.id === item.template,
    );
    if (
      !definition ||
      definition.filter_sha256 !== item.filter_sha256 ||
      definition.samples_sha256 !== item.samples_sha256
    )
      continue;
    const prior = out.get(item.template);
    if (!prior || item.at >= prior.at) out.set(item.template, item);
  }
  return out;
});
async function check() {
  if (checking.value || !props.templates.length) return;
  checking.value = true;
  error.value = "";
  try {
    const value = await api.checkFail2banTemplates(
      { templates: props.templates.map((template) => template.id) },
      controller.signal,
    );
    if (!closed) local.value = value;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    if (!closed) checking.value = false;
  }
}
onUnmounted(() => {
  closed = true;
  controller.abort();
});
</script>
<template>
  <div class="page-stack">
    <div class="toolbar">
      <h4>内置过滤器与样例</h4>
      <NButton
        size="small"
        :disabled="!templates.length"
        :loading="checking"
        @click="check"
      >
        验证内置模板
      </NButton>
    </div>
    <NAlert v-if="error" type="error">
      {{ error }}
    </NAlert>
    <div
      v-for="template in templates"
      :key="template.id"
      class="surface page-stack"
    >
      <div class="toolbar">
        <strong>{{ template.name }}</strong>
        <NTag
          :type="
            latest.get(template.id)?.passed
              ? 'success'
              : latest.get(template.id)?.available
                ? 'error'
                : 'default'
          "
        >
          {{
            latest.get(template.id)?.passed
              ? "样例检查通过"
              : latest.get(template.id)?.available
                ? "样例检查失败"
                : "尚未验证通过"
          }}
        </NTag>
      </div>
      <p>{{ template.description }}</p>
      <template v-if="latest.get(template.id)">
        <p class="muted">
          检查时间
          {{ new Date(latest.get(template.id)!.at * 1000).toLocaleString() }}
        </p>

        <NAlert v-if="latest.get(template.id)!.reason" type="warning">
          {{
            latest.get(template.id)!.reason
          }}
        </NAlert>
        <p v-if="latest.get(template.id)!.available" class="muted">
          实际匹配地址：{{
            latest.get(template.id)!.matched_ips.join(", ") || "无"
          }}
        </p>
      </template>
    </div>
  </div>
</template>
<style scoped>
.sample-log {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 12px;
}
</style>
