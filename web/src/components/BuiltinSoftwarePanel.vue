<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { NSwitch } from "naive-ui";
import type { ComponentTask, ComponentVersion } from "../api/client";
import type {
  BuiltinSoftwareView,
  SoftwareRuntimeSettings,
} from "../software/builtin";
import { useSoftwareOperations } from "../composables/software";
import { useSession } from "../stores/session";
import {
  softwareConfirmation,
  type SoftwareOperation,
} from "../utils/software";
import FormDialog from "./FormDialog.vue";
import SoftwareManagementPanel from "./SoftwareManagementPanel.vue";
import ComponentVersionDialog from "./ComponentVersionDialog.vue";
const props = defineProps<{ app: BuiltinSoftwareView; active: boolean }>();
const emit = defineEmits<{
  changed: [];
  task: [task: ComponentTask];
  busy: [value: boolean];
}>();
const router = useRouter(),
  session = useSession();
const { api, run, busy, submit } = useSoftwareOperations(() => emit("changed"));
const installerBusy = ref(false),
  showInstaller = ref(false),
  editing = ref(false);
const draft = ref<SoftwareRuntimeSettings | null>(null);
const versionAction = ref<"install" | "update" | null>(null);
const permitted = computed(() =>
  props.app.scopes.every((scope) => session.me?.scopes.includes(scope)),
);
const processing = computed(
  () => busy.value || installerBusy.value || props.active,
);
watch([busy, installerBusy], () =>
  emit("busy", busy.value || installerBusy.value),
);
function settings() {
  if (!props.app.settings || processing.value || !permitted.value) return;
  draft.value = {
    image: props.app.settings.image,
    auto_start: props.app.settings.auto_start,
  };
  editing.value = true;
}
async function send(
  action: SoftwareOperation | "configure",
  settings?: SoftwareRuntimeSettings,
  version?: string,
) {
  const request = await run(async () => {
    if (!props.app.request) throw new Error("此软件暂不支持该操作");
    if (action === "install" && props.app.module) {
      const modules = await api.modules();
      if (!modules.some((item) => item.id === props.app.module && item.enabled))
        await api.setModule(props.app.module, true);
    }
    return {
      ...props.app.request(action, settings),
      ...(version ? { version } : {}),
    };
  });
  if (!request) return;
  const task = await submit(request, `${props.app.name} 操作日志`);
  if (task) emit("task", task);
  return task;
}
async function operate(action: SoftwareOperation) {
  if (processing.value || !permitted.value) return;
  if (action === "install" && props.app.installTo) {
    await router.push(props.app.installTo);
    return;
  }
  if (props.app.installer && (action === "install" || action === "update")) {
    showInstaller.value = true;
    return;
  }
  if (action === "install" || action === "update") {
    versionAction.value = action;
    return;
  }
  const prompt =
    action === "uninstall"
      ? `卸载 ${props.app.name}？服务将停止，已有配置和数据会保留。`
      : softwareConfirmation(action, props.app.name);
  if (prompt && !window.confirm(prompt)) return;
  await send(action);
}
async function chooseVersion(version: ComponentVersion) {
  if (!versionAction.value) return;
  const task = await send(
    versionAction.value,
    versionAction.value === "install" ? props.app.settings : undefined,
    version.id,
  );
  if (task) versionAction.value = null;
}
async function save() {
  if (!draft.value || processing.value || !permitted.value) return;
  const settings = await run(async () => {
    const image = draft.value!.image.trim();
    if (!image) throw new Error("请填写软件下载来源");
    return { image, auto_start: draft.value!.auto_start };
  });
  if (settings && (await send("configure", settings))) editing.value = false;
}
</script>
<template>
  <SoftwareManagementPanel
    :app="app"
    :runtime="app.runtime"
    :actions="app.actions"
    :permitted="permitted"
    :busy="processing"
    :task="app.task"
    :error="app.error"
    :settings-available="app.installed && !!app.settings"
    @operate="operate"
    @settings="settings()"
  >
    <component
      :is="app.installer"
      v-if="showInstaller && app.installer"
      v-bind="app.installerProps"
      @busy="installerBusy = $event"
      @task="emit('task', $event)"
    />
  </SoftwareManagementPanel>
  <ComponentVersionDialog
    :show="!!versionAction"
    :name="app.name"
    source-id="builtin"
    :app-id="app.id"
    :submit-text="versionAction === 'install' ? '安装此版本' : '切换版本'"
    :busy="processing"
    @choose="chooseVersion"
    @cancel="versionAction = null"
  />
  <FormDialog
    :show="editing"
    :title="`${app.name} 运行设置`"
    :busy="busy"
    :form-disabled="processing || !permitted"
    :submit-disabled="processing || !permitted"
    :draft="draft"
    submit-text="保存"
    width="560px"
    @submit="save"
    @cancel="editing = false"
  >
    <div v-if="draft" class="page-stack">
      <div class="runtime-setting">
        <span>开机自动启动</span><NSwitch
          v-model:value="draft.auto_start"
          aria-label="开机自动启动"
          :disabled="processing || !permitted"
        />
      </div>
    </div>
    <template #actions>
      <span v-if="app.installed" class="muted">应用设置时，服务连接可能短暂中断。</span>
    </template>
  </FormDialog>
</template>
<style scoped>
.runtime-setting {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
</style>
