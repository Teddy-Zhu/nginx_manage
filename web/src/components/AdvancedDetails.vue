<script setup lang="ts">
import { ref } from "vue";

withDefaults(defineProps<{ title?: string }>(), { title: "高级设置" });
const expanded = ref(false);
function toggle(event: Event) {
  expanded.value = (event.currentTarget as HTMLDetailsElement).open;
}
</script>

<template>
  <details class="advanced-details" @toggle="toggle">
    <summary>{{ title }}</summary>
    <div v-if="expanded" class="advanced-content"><slot /></div>
  </details>
</template>
