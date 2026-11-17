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
import { inspectTask } from "../stores/operation";
import TaskLogButton from "./TaskLogButton.vue";
import ComponentVersionDialog from "./ComponentVersionDialog.vue";
const props = defineProps<{
  overview: ComponentOverview | null;
  tasks: ComponentTask[];
  active: boolean;
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
    inspectTask(item.id, "Nginx 更新日志");
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
  if (!source || !item?.result?.runtime_ready) return;
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
    source-id="builtin"
    app-id="nginx"
    :busy="busy || active"
    submit-text="检查此版本"
    @choose="chooseVersion"
    @cancel="choosingVersion = false"
  />
  <div class="page-stack">
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
      <p>可用版本 {{ release.version }}</p>
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
            {{
              "应用更新"
            }}
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
