<script setup lang="ts">
import { computed, ref } from "vue";
import { useRouter } from "vue-router";
import { NSwitch, useDialog } from "naive-ui";
import {
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
  type ComponentVersion,
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
import NginxInstallPanel from "./NginxInstallPanel.vue";
import SoftwareManagementPanel from "./SoftwareManagementPanel.vue";

const props = defineProps<{
  app: BuiltinSoftwareView;
  overview: ComponentOverview | null;
  tasks: ComponentTask[];
  active: boolean;
}>();
const emit = defineEmits<{
  task: [task: ComponentTask];
  busy: [value: boolean];
}>();
const session = useSession();
const api = useNodeAPI();
const dialog = useDialog();
const router = useRouter();
const { run } = useAction();
const showInstaller = ref(false);
const bundledInstall = computed(
  () => props.overview?.bundled_nginx && !props.app.installed,
);
const installerBusy = ref(false);
const versionOperation = ref<"install" | "update" | null>(null);
const autoStart = ref(true);
const permitted = computed(() =>
  props.app.scopes.every((scope) => session.me?.scopes.includes(scope)),
);
function setBusy(value: boolean) {
  installerBusy.value = value;
  emit("busy", value);
}
async function submit(request: SoftwareRequest, title: string) {
  setBusy(true);
  try {
    return await run(async () => {
      if (request.app_id === "fail2ban" && request.action === "install") {
        const modules = await api.modules();
        if (!modules.some((item) => item.id === "fail2ban" && item.enabled))
          await api.setModule("fail2ban", true);
      }
      const task = await api.createComponentTask(
        softwareTaskInput(request),
        randomUUID(),
      );
      emit("task", task);
      inspectTask(task.id, title);
      return task;
    });
  } finally {
    setBusy(false);
  }
}
async function chooseVersion(version: ComponentVersion) {
  const action = versionOperation.value;
  const appID = props.app.id;
  if (!action || !permitted.value || appID === "nginx") return;
  const request: SoftwareRequest = {
    action,
    app_id: appID,
    version: version.id,
  };
  if (action === "install" && appID === "fail2ban")
    request.auto_start = autoStart.value;
  if (await submit(request, props.app.name + "版本操作日志"))
    versionOperation.value = null;
}
function operate(action: SoftwareOperation) {
  if (!permitted.value || props.active || installerBusy.value) return;
  const appID = props.app.id;
  if (appID === "nginx") {
    showInstaller.value = true;
  } else if (action === "install" && appID === "frps") {
    void router.push({ path: "/frps", query: { install: "1" } });
  } else if (action === "install" || action === "update") {
    versionOperation.value = action;
  } else {
    const execute = () =>
      submit({ action, app_id: appID }, props.app.name + "操作日志");
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
    :submit-text="versionOperation === 'install' ? '安装' : '切换版本'"
    @choose="chooseVersion"
    @cancel="versionOperation = null"
  >
    <label
      v-if="versionOperation === 'install' && app.id === 'fail2ban'"
      class="button-row"
    >
      <NSwitch v-model:value="autoStart" />
      开机启动
    </label>
  </ComponentVersionDialog>
  <SoftwareManagementPanel
    :app="app"
    :runtime="app.runtime"
    :actions="bundledInstall ? [] : app.actions"
    :permitted="permitted"
    :busy="installerBusy || active"
    :task="app.task"
    :error="app.error"
    @operate="operate"
  >
    <NginxInstallPanel
      v-if="app.id === 'nginx' && (showInstaller || bundledInstall)"
      :overview="overview"
      :tasks="tasks"
      :active="active"
      @busy="setBusy"
      @task="emit('task', $event)"
    />
  </SoftwareManagementPanel>
</template>
