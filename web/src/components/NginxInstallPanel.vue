<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { NAlert, NButton } from "naive-ui";
import {
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
  type ComponentCreateInput,
  type ComponentVersion,
} from "../api/client";
import { useSession } from "../stores/session";
import { useAction, useIdempotency } from "../composables/action";
import { nginxEngineVersion } from "../utils/component-version";
import TaskLogButton from "./TaskLogButton.vue";
import ComponentVersionDialog from "./ComponentVersionDialog.vue";
const props = defineProps<{
  overview: ComponentOverview | null;
  tasks: ComponentTask[];
  active: boolean;
  openVersionPicker?: boolean;
}>();
const emit = defineEmits<{
  task: [task: ComponentTask];
  busy: [busy: boolean];
}>();
const api = useNodeAPI(),
  session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const prerelease = ref(false);
const choosingVersion = ref(false),
  targetVersion = ref<ComponentVersion | null>(null);
const updatePath = "/nginx-images";
const permitted = computed(
  () => !!session.me?.scopes.includes("components.manage"),
);
const installAllowed = computed(
  () => permitted.value && !!session.me?.scopes.includes("system.write"),
);
const firstInstall = computed(
  () => !!props.overview?.bundled_nginx && !props.overview.installation,
);
watch(
  () => props.openVersionPicker,
  (show) => {
    if (show && firstInstall.value && installAllowed.value)
      choosingVersion.value = true;
  },
  { immediate: true },
);
function hasNginxImage(task: ComponentTask) {
  const release = task.result?.release;
  if (!release) return false;
  return (
    release.selected.includes("image-nginx") &&
    release.images.some((image) => image.id === "nginx")
  );
}
const checked = computed(
  () =>
    props.tasks.find(
      (task) =>
        task.action === "check" &&
        task.state === "succeeded" &&
        task.result?.input.prerelease === prerelease.value &&
        (!targetVersion.value ||
          task.result?.input.tag === targetVersion.value.id) &&
        hasNginxImage(task),
    ) ?? null,
);
const release = computed(() => checked.value?.result?.release);
const engineVersion = computed(() => nginxEngineVersion(release.value?.notes));
const engineMismatch = computed(
  () =>
    !!release.value &&
    !!targetVersion.value?.software_version &&
    targetVersion.value.software_version !== engineVersion.value,
);
const prepared = computed(() =>
  props.tasks.filter((item) => {
    const release = item.result?.release;
    return (
      item.action === "prepare" &&
      item.state === "succeeded" &&
      item.result?.runtime_ready &&
      hasNginxImage(item) &&
      !!release &&
      release.expires_at * 1000 > Date.now()
    );
  }),
);
watch(busy, (value) => emit("busy", value));
async function submit(input: ComponentCreateInput) {
  await run(async () => {
    const item = await (input.input.action === "pull"
      ? api.pullComponentImage(input, keyFor(input))
      : api.createComponentTask(input, keyFor(input)));
    emit("task", item);
    keyFor = useIdempotency();
  });
}
function check() {
  return submit({
    check_task_id: "",
    input: {
      action: "check",
      tag: targetVersion.value?.id ?? "",
      prerelease: prerelease.value,
      components: ["nginx"],
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
    },
  });
}
function prepare() {
  const item = checked.value,
    source = item?.result?.release;
  if (!source || !item?.result?.runtime_ready || engineMismatch.value) return;
  return submit({
    check_task_id: item.id,
    input: {
      action: "prepare",
      offline_id: item.result.input.offline_id,
      tag: source.tag,
      prerelease: item.result.input.prerelease,
      assets: source.selected,
      plan_id: source.plan_id,
      manifest_sha256: source.manifest_sha256,
      trust_sha256: source.trust_sha256,
    },
  });
}
function pull(item: ComponentTask, imageID: string) {
  const source = item.result;
  if (!source?.release) return;
  return submit({
    check_task_id: "",
    prepare_task_id: item.id,
    input: {
      action: "pull",
      image_id: imageID,
      offline_id: source.input.offline_id,
      tag: source.release.tag,
      assets: source.release.selected,
      prerelease: source.input.prerelease,
      plan_id: source.release.plan_id,
      manifest_sha256: source.release.manifest_sha256,
      trust_sha256: source.release.trust_sha256,
    },
  });
}
async function chooseVersion(version: ComponentVersion) {
  if (firstInstall.value) {
    if (!installAllowed.value) return;
    choosingVersion.value = false;
    await submit({
      input: {
        action: "software",
        tag: "",
        prerelease: false,
        plan_id: "",
        manifest_sha256: "",
        trust_sha256: "",
        software: { action: "install-nginx", version: version.id },
      },
    });
    return;
  }
  targetVersion.value = version;
  prerelease.value = version.channel === "beta";
  choosingVersion.value = false;
  await check();
}
</script>
<template>
  <ComponentVersionDialog
    :show="choosingVersion"
    name="Nginx"
    app-id="nginx"
    :busy="busy || active"
    :submit-text="firstInstall ? '安装此版本' : '检查此版本'"
    @choose="chooseVersion"
    @cancel="choosingVersion = false"
  />
  <div
    v-if="firstInstall"
    class="button-row"
  >
    <NButton
      type="primary"
      :loading="busy || active"
      :disabled="!installAllowed || active"
      @click="choosingVersion = true"
    >
      安装 Nginx
    </NButton>
  </div>
  <div v-else class="page-stack">
    <NAlert v-if="overview && !overview.available" type="warning">
      安装源暂不可用，请稍后重试或查看操作日志。
    </NAlert>
    <div v-if="overview?.installation" class="button-row">
      <RouterLink :to="updatePath">
        <NButton>应用已下载的更新</NButton>
      </RouterLink>
    </div>
    <div class="section-heading">
      <h3>{{ overview?.installation ? "下载更新" : "选择安装版本" }}</h3>
    </div>
    <div class="button-row">
      <NButton
        type="primary"
        :loading="busy"
        :disabled="!permitted || !overview?.available || active"
        @click="choosingVersion = true"
      >
        选择版本
      </NButton><TaskLogButton v-if="checked" :task-id="checked.id" />
    </div>
    <template v-if="release">
      <p>
        组件 {{ release.version
        }}<template v-if="engineVersion">
          · Nginx {{ engineVersion }}
        </template>
      </p>
      <NAlert v-if="engineMismatch" type="error">
        发行中的 Nginx 版本与所选版本不一致，请刷新版本列表后重新选择。
      </NAlert>
      <NAlert v-if="release.expires_at * 1000 <= Date.now()" type="info">
        版本信息已过期，请重新查找可用版本。
      </NAlert>
      <NAlert v-if="!checked?.result?.runtime_ready" type="warning">
        当前服务器暂不满足此版本的安装条件，请查看检查日志。
      </NAlert>
      <NButton
        :loading="busy"
        :disabled="
          !permitted ||
            busy ||
            active ||
            engineMismatch ||
            !checked?.result?.runtime_ready ||
            release.expires_at * 1000 <= Date.now()
        "
        @click="prepare"
      >
        准备镜像
      </NButton>
    </template>
    <section
      v-for="item in prepared"
      :key="item.id"
      class="record-card page-stack"
    >
      <div class="section-heading">
        <strong>{{ item.result?.release?.version }} 已准备</strong><TaskLogButton :task-id="item.id" />
      </div>
      <div class="button-row">
        <RouterLink
          :to="{
            path: updatePath,
            query: { prepare: item.id },
          }"
        >
          <NButton type="primary" :disabled="busy || active || !permitted">
            {{ "应用更新" }}
          </NButton>
        </RouterLink>
        <template
          v-for="image in item.result?.release?.images ?? []"
          :key="image.id"
        >
          <NButton
            v-if="image.id === 'nginx' && !overview?.installation"
            :disabled="
              busy || active || !session.me?.scopes.includes('system.write')
            "
            @click="pull(item, image.id)"
          >
            下载运行环境
          </NButton>
        </template>
      </div>
    </section>
  </div>
</template>
