<route lang="json">
{
  "meta": {
    "title": "软件商店",
    "subtitle": "安装和管理所需软件",
    "nav": true,
    "order": 13,
    "symbol": "◇",
    "group": "服务器管理"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { NAlert, NButton, NCheckbox, NFormItem, NSelect, NTag } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentOverview,
  type ComponentTask,
  type ComponentCreateInput,
  type Fail2banObservation,
  type Fail2banInstance,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useLiveRefresh } from "../composables/live";
import { useSession } from "../stores/session";
import { nginxState, fail2banState } from "../utils/software";
import Fail2banInstallPanel from "../components/Fail2banInstallPanel.vue";
import Fail2banLifecyclePanel from "../components/Fail2banLifecyclePanel.vue";
import Fail2banExistingPanel from "../components/Fail2banExistingPanel.vue";
import TaskLogButton from "../components/TaskLogButton.vue";

const api = useNodeAPI(),
  route = useRoute(),
  session = useSession(),
  { run, busy } = useAction();
const software =
  route.query.software === "nginx" || route.query.software === "fail2ban"
    ? route.query.software
    : "";
const overview = ref<ComponentOverview | null>(null),
  tasks = ref<ComponentTask[]>([]),
  fail2ban = ref<Fail2banObservation | null>(null),
  instance = ref<Fail2banInstance | null>(null);
const moduleEnabled = ref(false),
  installing = ref(false),
  reading = ref(false),
  error = ref("");
const selection = ref<"nginx" | "fail2ban" | "panel" | "web">(
    software || "panel",
  ),
  prerelease = ref(false);
const controller = new AbortController();
let keyFor = useIdempotency();
const nginxStatus = computed(() => nginxState(overview.value)),
  fail2banStatus = computed(() => fail2banState(fail2ban.value));
const stateNames = {
  installed: "已安装",
  missing: "未安装",
  unbound: "待连接",
  recovery: "安装未完成",
  unavailable: "暂时无法读取",
};
const names = {
  nginx: "Nginx",
  fail2ban: "Fail2ban",
  panel: "管理面板",
  web: "面板界面",
};
const permitted = computed(() =>
  session.me?.scopes.includes("components.manage"),
);
const active = computed(() =>
  tasks.value.some(
    (task) =>
      task.stage !== "restore_isolated" &&
      ["queued", "running", "recovery_required"].includes(task.state),
  ),
);
const checked = computed(() =>
  tasks.value.find(
    (task) =>
      task.action === "check" &&
      task.state === "succeeded" &&
      task.result?.input.prerelease === prerelease.value &&
      task.result?.release?.assets.some(
        (asset) =>
          asset.component === selection.value &&
          task.result!.release!.selected.includes(asset.id),
      ),
  ),
);
const release = computed(() => checked.value?.result?.release);
const stateLabels: Record<string, string> = {
  queued: "等待执行",
  running: "正在执行",
  succeeded: "已完成",
  failed: "未完成",
  recovery_required: "需要处理",
};
async function load() {
  if (reading.value || controller.signal.aborted) return;
  reading.value = true;
  try {
    const [source, items, observation, modules] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
      api.fail2ban(controller.signal),
      api.modules(controller.signal),
    ]);
    if (controller.signal.aborted) return;
    overview.value = source;
    tasks.value = [
      ...tasks.value.filter(
        (task) => !items.some((item) => item.id === task.id),
      ),
      ...items,
    ].sort((a, b) => b.created_at - a.created_at);
    fail2ban.value = observation;
    moduleEnabled.value = modules.some(
      (item) => item.id === "fail2ban" && item.enabled,
    );
    if (software === "fail2ban" && observation.binding.state === "bound")
      instance.value = await api.fail2banInstance(controller.signal);
    error.value = "";
  } catch (failure) {
    if (!controller.signal.aborted) error.value = apiError(failure).message;
  } finally {
    if (!controller.signal.aborted) reading.value = false;
  }
}
async function submit(input: ComponentCreateInput) {
  await run(async () => {
    const item = await (input.input.action === "activate"
      ? api.activateFrontend(input, keyFor(input))
      : input.input.action === "pull"
        ? api.pullComponentImage(input, keyFor(input))
        : api.createComponentTask(input, keyFor(input)));
    tasks.value = [item, ...tasks.value.filter((task) => task.id !== item.id)];
    keyFor = useIdempotency();
  });
}
function check() {
  return submit({
    check_task_id: "",
    input: {
      action: "check",
      tag: "",
      prerelease: prerelease.value,
      components: [selection.value],
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
function activate(item: ComponentTask) {
  const source = item.result,
    frontend = overview.value?.frontend;
  if (!source?.release || !frontend) return;
  return submit({
    check_task_id: "",
    prepare_task_id: item.id,
    input: {
      action: "activate",
      offline_id: source.input.offline_id,
      tag: source.release.tag,
      assets: source.release.selected,
      prerelease: source.input.prerelease,
      plan_id: source.release.plan_id,
      manifest_sha256: source.release.manifest_sha256,
      trust_sha256: source.release.trust_sha256,
      frontend_base_id: frontend.base_id,
      expected_frontend_id: frontend.current_id,
    },
  });
}
const prepared = computed(() =>
  tasks.value.filter(
    (item) =>
      item.result?.release?.assets.some(
        (asset) =>
          asset.component === selection.value &&
          item.result!.release!.selected.includes(asset.id),
      ) &&
      item.action === "prepare" &&
      item.state === "succeeded" &&
      item.result?.runtime_ready &&
      (item.result.release?.expires_at ?? 0) * 1000 > Date.now(),
  ),
);
onMounted(load);
onUnmounted(() => controller.abort());
useLiveRefresh(api, ["tasks"], load);
</script>
<template>
  <div class="page-stack">
    <div class="section-heading">
      <h2>{{ software ? names[software] : "软件商店" }}</h2>
      <RouterLink v-if="software" to="/components">返回软件列表</RouterLink
      ><NButton v-else :loading="reading" @click="load">刷新状态</NButton>
    </div>
    <NAlert v-if="error" type="error"
      >软件状态读取失败，请稍后刷新或查看服务日志。</NAlert
    >
    <div v-if="!software" class="software-grid">
      <section class="panel software-card">
        <div class="section-heading">
          <h3>Nginx</h3>
          <NTag :type="nginxStatus === 'installed' ? 'success' : 'default'">{{
            stateNames[nginxStatus]
          }}</NTag>
        </div>
        <p class="muted">创建网站、配置反向代理和管理站点访问。</p>
        <p v-if="overview?.installation">
          {{ overview.installation.version }} ·
          {{ overview.running ? "运行中" : "已停止" }}
        </p>
        <div class="button-row">
          <RouterLink v-if="nginxStatus === 'installed'" to="/nginx"
            ><NButton type="primary">管理网站</NButton></RouterLink
          ><RouterLink
            v-else
            :to="{ path: '/components', query: { software: 'nginx' } }"
            ><NButton type="primary">安装 Nginx</NButton></RouterLink
          ><RouterLink
            v-if="nginxStatus === 'installed'"
            :to="
              overview?.installation?.owner === 'docker'
                ? '/nginx-images'
                : '/component-switches'
            "
            >检查更新</RouterLink
          >
        </div>
      </section>
      <section class="panel software-card">
        <div class="section-heading">
          <h3>Fail2ban</h3>
          <NTag
            :type="fail2banStatus === 'installed' ? 'success' : 'default'"
            >{{ stateNames[fail2banStatus] }}</NTag
          >
        </div>
        <p class="muted">自动封禁多次登录失败的 IP，保护服务器和面板。</p>
        <div class="button-row">
          <RouterLink v-if="fail2banStatus === 'installed'" to="/fail2ban"
            ><NButton type="primary">设置登录防护</NButton></RouterLink
          ><RouterLink
            :to="{ path: '/components', query: { software: 'fail2ban' } }"
            ><NButton
              :type="fail2banStatus === 'installed' ? 'default' : 'primary'"
              >{{
                fail2banStatus === "installed"
                  ? "服务设置"
                  : fail2banStatus === "unbound"
                    ? "连接已有安装"
                    : fail2banStatus === "recovery"
                      ? "继续安装"
                      : "安装 Fail2ban"
              }}</NButton
            ></RouterLink
          >
        </div>
      </section>
    </div>
    <template v-if="software === 'fail2ban'">
      <Fail2banExistingPanel
        v-if="fail2banStatus === 'unbound' || route.query.existing === '1'"
        :module-enabled="moduleEnabled"
        @changed="load"
      />
      <Fail2banInstallPanel
        v-else-if="fail2banStatus !== 'installed' || installing"
        @busy="installing = $event"
        @changed="load"
      />
      <template v-else
        ><Fail2banLifecyclePanel
          :module-enabled="moduleEnabled"
          :binding="fail2ban?.binding ?? null"
          :instance="instance"
          :managed="fail2ban?.managed ?? null"
          :service="
            fail2ban?.services.find(
              (item) => item.id === 'nginxpanel-fail2ban.service',
            ) ?? null
          "
          :observed-at="fail2ban?.at ?? 0"
          @changed="load"
        /><RouterLink to="/fail2ban"
          ><NButton type="primary">设置登录防护规则</NButton></RouterLink
        ></template
      >
    </template>
    <section v-if="software !== 'fail2ban'" class="panel page-stack">
      <h3>
        {{
          software === "nginx" && nginxStatus !== "installed"
            ? "安装 Nginx"
            : "检查软件更新"
        }}
      </h3>
      <NAlert v-if="overview && !overview.available" type="warning"
        >安装源暂不可用，请稍后重试或查看服务日志。</NAlert
      >
      <div class="form-grid">
        <NFormItem v-if="!software" label="选择软件"
          ><NSelect
            v-model:value="selection"
            :options="
              Object.entries(names).map(([value, label]) => ({ value, label }))
            "
            :disabled="busy || active" /></NFormItem
        ><NCheckbox v-model:checked="prerelease" :disabled="busy || active"
          >包含预览版本</NCheckbox
        >
      </div>
      <div class="button-row">
        <NButton
          type="primary"
          :loading="busy || active"
          :disabled="!permitted || !overview?.available || active"
          @click="check"
          >{{ active ? "正在处理" : "查找可用版本" }}</NButton
        ><RouterLink to="/logs">查看服务日志</RouterLink>
      </div>
      <template v-if="release"
        ><p>
          可用版本：{{ release.tag }} · 下载大小
          {{ (release.archive_bytes / 1048576).toFixed(1) }} MB
        </p>
        <NAlert v-if="!checked?.result?.runtime_ready" type="warning"
          >当前服务器暂不满足此版本的安装条件，请查看检查日志。</NAlert
        ><NButton
          :loading="busy"
          :disabled="
            busy ||
            active ||
            !checked?.result?.runtime_ready ||
            release.expires_at * 1000 <= Date.now()
          "
          @click="prepare"
          >下载软件</NButton
        ><TaskLogButton v-if="checked" :task-id="checked.id"
      /></template>
    </section>
    <section v-for="item in prepared" :key="item.id" class="panel page-stack">
      <div class="section-heading">
        <h3>{{ item.result?.release?.tag }} 已下载</h3>
        <TaskLogButton :task-id="item.id" />
      </div>
      <div class="button-row">
        <RouterLink
          v-if="
            item.result?.release?.assets.some(
              (asset) =>
                asset.component === 'nginx' &&
                item.result!.release!.selected.includes(asset.id),
            )
          "
          :to="{
            path: '/component-installations',
            query: { prepare: item.id },
          }"
          ><NButton type="primary">安装 Nginx</NButton></RouterLink
        ><RouterLink v-if="item.result?.panel" to="/panel-updates"
          ><NButton type="primary">更新管理面板</NButton></RouterLink
        ><RouterLink
          v-if="
            item.result?.release?.assets.some(
              (asset) =>
                asset.component === 'fail2ban' &&
                item.result!.release!.selected.includes(asset.id),
            )
          "
          :to="{ path: '/components', query: { software: 'fail2ban' } }"
          ><NButton type="primary">{{
            fail2banStatus === "installed" ? "管理 Fail2ban" : "安装 Fail2ban"
          }}</NButton></RouterLink
        ><NButton
          v-if="item.result?.frontend"
          :disabled="
            busy ||
            active ||
            !overview?.frontend.available ||
            overview.frontend.current_id === item.result.frontend.release_id
          "
          @click="activate(item)"
          >更新面板界面</NButton
        ><NButton
          v-for="image in item.result?.release?.images ?? []"
          :key="image.id"
          :disabled="
            busy ||
            active ||
            !session.me?.scopes.includes('system.write') ||
            (!!item.result?.panel?.requires_coordination &&
              image.id !== 'panel-launcher')
          "
          @click="pull(item, image.id)"
          >下载{{ image.id === "nginx" ? "Nginx" : "面板" }}运行环境</NButton
        >
      </div>
    </section>
    <section v-if="tasks.length" class="panel page-stack">
      <h3>最近操作</h3>
      <article
        v-for="item in tasks.slice(0, 8)"
        :key="item.id"
        class="record-card"
      >
        <div class="record-heading">
          <strong>{{
            item.action === "check"
              ? "检查版本"
              : item.action === "prepare"
                ? "下载软件"
                : item.action === "pull"
                  ? "下载运行环境"
                  : "更新界面"
          }}</strong
          ><NTag
            :type="
              item.state === 'succeeded'
                ? 'success'
                : item.state === 'failed'
                  ? 'error'
                  : 'info'
            "
            >{{ stateLabels[item.state] || "正在处理" }}</NTag
          ><TaskLogButton :task-id="item.id" />
        </div>
        <p class="muted">
          {{ new Date(item.created_at * 1000).toLocaleString() }}
        </p>
      </article>
    </section>
  </div>
</template>
