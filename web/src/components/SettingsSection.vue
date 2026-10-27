<script setup lang="ts">
withDefaults(defineProps<{ title: string; description?: string }>(), {
  description: "",
});
</script>
<template>
  <section class="settings-section">
    <div class="section-heading">
      <h3>{{ title }}</h3>
      <slot name="actions" />
    </div>
    <p v-if="description" class="section-note">
      {{ description }}
    </p>
    <slot />
  </section>
</template>
<style scoped>
.settings-section {
  display: grid;
  gap: 16px;
  min-width: 0;
  padding: 20px;
  border: 1px solid var(--border-color);
  border-radius: 10px;
}
.settings-section > .section-heading {
  margin: 0;
}
.settings-section h3,
.settings-section p {
  margin: 0;
}
@container (max-width:540px) {
  .settings-section {
    padding: 16px;
  }
}
</style>
