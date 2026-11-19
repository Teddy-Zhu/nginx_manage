<script setup lang="ts">
import { computed, ref } from "vue";
import { RouterLink } from "vue-router";
import { NButton, NSwitch, useDialog } from "naive-ui";
import {
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
  type SoftwareRequest,
} from "../api/client";
import { useSession } from "../stores/session";
import { useAction } from "../composables/action";
import { inspectTask } from "../stores/operation";
import type { BuiltinSoftwareView } from "../software/builtin";
import { randomUUID } from "../utils/crypto";
import {
  softwareConfirmation,
  softwareTaskInput,
  type SoftwareOperation,
} from "../utils/software";
import ComponentVersionDialog from "./ComponentVersionDialog.vue";
import DetailDialog from "./DetailDialog.vue";
import SoftwareManagementPanel from "./SoftwareManagementPanel.vue";
import ServiceLogsDialog from "./ServiceLogsDialog.vue";

const props = defineProps<{
  app: BuiltinSoftwareView;
  overview: ComponentOverview | null;
  active: boolean;
  initialAction: "manage" | "install" | "update";
}>();
const emit = defineEmits<{
  task: [task: ComponentTask];
  changed: [];
  close: [];
  navigate: [action: "install" | "update"];
}>();
const session = useSession();
const api = useNodeAPI();
const dialog = useDialog();
const { run, message } = useAction();
type View = "manage" | "install" | "update" | "logs";
const view = ref<View>(props.initialAction);
const showLogs = computed({
  get: () => view.value === "logs",
  set: (show: boolean) => {
    if (!show) view.value = "manage";
  },
});
const installerBusy = ref(false);
const versionOperation = computed(() =>
  view.value === "install" || view.value === "update" ? view.value : null,
);
const autoStart = ref(true);
const permitted = computed(() =>
  props.app.scopes.every((scope) => session.me?.scopes.includes(scope)),
);
const logsPermitted = computed(
  () => session.me?.scopes.includes("read") === true &&
    session.me.scopes.includes("components.manage"),
);
function closeVersion() {
  if (props.initialAction === "manage") view.value = "manage";
  else emit("close");
}
async function submit(request: SoftwareRequest, title: string) {
  installerBusy.value = true;
  try {
    await run(async () => {
      if (request.app_id === "fail2ban" && request.action === "install") {
        const modules = await api.modules();
        if (!modules.some((item) => item.id === "fail2ban" && item.enabled))
          await api.setModule("fail2ban", true);
      }
      const task = await api.createComponentTask(
        softwareTaskInput(request),
        randomUUID(),
        false,
      );
      emit("task", task);
      emit("close");
      inspectTask(task.id, title);
    });
  } finally {
    installerBusy.value = false;
  }
}
async function control(request: SoftwareRequest) {
  if (props.active || installerBusy.value) return;
  installerBusy.value = true;
  try {
    await run(async () => {
      const result = await api.controlSoftware(request);
      message.success(result.message);
    });
  } finally {
    emit("changed");
    installerBusy.value = false;
  }
}
async function chooseVersion(
  choice: Pick<SoftwareRequest, "version" | "image_tag">,
) {
  const action = versionOperation.value;
  const appID = props.app.id;
  if (!action || !permitted.value) return;
  if (appID === "nginx") {
    if (action === "install" && props.overview?.bundled_nginx && choice.version)
      await submit({ action: "install-nginx", version: choice.version }, "安装 Nginx");
    return;
  }
  const request: SoftwareRequest = {
    action,
    app_id: appID,
    ...choice,
  };
  if (action === "install" && appID === "fail2ban")
    request.auto_start = autoStart.value;
  await submit(request, props.app.name + " · " + (action === "install" ? "安装" : "切换版本"));
}
function operate(action: SoftwareOperation) {
  const appID = props.app.id;
  if (action === "logs") {
    if (logsPermitted.value && appID !== "nginx") view.value = "logs";
    return;
  }
  if (!permitted.value || props.active || installerBusy.value) return;
  if (action === "install" || action === "update") {
    if (
      (appID === "nginx" && (action === "update" || !props.overview?.bundled_nginx)) ||
      (appID === "frps" && action === "install")
    ) {
      emit("navigate", action);
      return;
    }
    view.value = action;
  } else if (appID !== "nginx") {
    const request = { action, app_id: appID };
    const execute = () =>
      action === "uninstall"
        ? submit(request, props.app.name + "卸载日志")
        : control(request);
    const confirmation = softwareConfirmation(action, props.app.name);
    if (!confirmation) {
      void execute();
      return;
    }
    dialog.warning({
      title: props.app.name,
      content: confirmation,
      positiveText: "确认",
      negativeText: "取消",
      onPositiveClick: async () => {
        await execute();
      },
    });
  }
}
</script>

<template>
  <ComponentVersionDialog
    :show="!!versionOperation"
    :name="app.name"
    :app-id="app.id"
    :busy="installerBusy || active"
    :allow-image-tag="app.id !== 'nginx'"
    :start-with-image-tag="versionOperation === 'install' && app.id !== 'nginx'"
    :submit-text="versionOperation === 'install' ? '安装' : '切换版本'"
    @choose="chooseVersion({ version: $event.id })"
    @choose-tag="chooseVersion({ image_tag: $event })"
    @cancel="closeVersion"
  >
    <label
      v-if="versionOperation === 'install' && app.id === 'fail2ban'"
      class="button-row"
    >
      <NSwitch v-model:value="autoStart" />
      开机启动
    </label>
  </ComponentVersionDialog>
  <ServiceLogsDialog
    v-if="app.id !== 'nginx'"
    v-model:show="showLogs"
    :app="app.id"
    :name="app.name"
  />
  <DetailDialog
    :show="view === 'manage'"
    :title="'软件管理 · ' + app.name"
    :busy="installerBusy"
    @update:show="$emit('close')"
  >
    <SoftwareManagementPanel
      :app="app"
      :runtime="app.runtime"
      :actions="app.actions"
      :permitted="permitted"
      :logs-permitted="logsPermitted"
      :busy="installerBusy || active"
      :task="app.task"
      :error="app.error"
      @operate="operate"
    />
    <template #actions>
      <RouterLink v-if="app.installed && app.entry" :to="app.entry.to">
        <NButton :disabled="installerBusy">
          打开功能页面
        </NButton>
      </RouterLink>
    </template>
  </DetailDialog>
</template>
