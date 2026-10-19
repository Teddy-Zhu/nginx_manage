<route lang="json">
{
  "meta": {
    "title": "组件准备",
    "subtitle": "面板与受信任组件的准备任务",
    "nav": true,
    "order": 7.2,
    "symbol": "◇"
  }
}
</route>
<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import ComponentOfflineUpload from "../components/ComponentOfflineUpload.vue";
import ComponentReleaseDetails from "../components/ComponentReleaseDetails.vue";
import {
  NAlert,
  NButton,
  NCheckbox,
  NFormItem,
  NInput,
  NPopconfirm,
  NSelect,
  NTag,
} from "naive-ui";
import {
  useNodeAPI,
  apiError,
  type ComponentOverview,
  type ComponentTask,
  type ComponentCreateInput,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();

const session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const overview = ref<ComponentOverview | null>(null),
  tasks = ref<ComponentTask[]>([]),
  error = ref("");
const tag = ref(""),
  prerelease = ref(false),
  components = ref<Array<"nginx" | "fail2ban" | "panel" | "web">>(["nginx"]),
  assets = ref(""),
  selection = ref("components");
const checkID = ref(""),
  clock = ref(Date.now());
const permitted = computed(
  () => session.me?.scopes.includes("components.manage") ?? false,
);
const active = computed(() =>
  tasks.value.some((t) =>
    ["queued", "running", "recovery_required"].includes(t.state),
  ),
);
const checks = computed(() =>
  tasks.value.filter(
    (t) => t.action === "check" && t.state === "succeeded" && t.result?.release,
  ),
);
const checked = computed(() =>
  checks.value.find((t) => t.id === checkID.value),
);
const release = computed(() => checked.value?.result?.release);
const canPrepare = computed(
  () =>
    !!release.value &&
    !!checked.value?.result?.runtime_ready &&
    release.value.expires_at * 1000 > clock.value &&
    overview.value?.available &&
    !active.value &&
    !busy.value,
);
const stateLabels: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  succeeded: "完成",
  failed: "失败",
  recovery_required: "待本机恢复",
};
function chooseComponents(value: Array<"nginx" | "fail2ban" | "panel" | "web">) {
  const added = value.find((item) => (item === "panel" || item === "web") && !components.value.includes(item));
  components.value = added ? [added] : value.filter((item) => item !== "panel" && item !== "web");
}
function taskLabel(t: ComponentTask) {
  if (t.state === "succeeded")
    return t.action === "activate" ? "激活完成" : t.action === "prepare" ? "准备完成" : "检查完成";
  return stateLabels[t.state] ?? t.state;
}
function bytes(n: number) {
  return `${(n / 1048576).toFixed(1)} MiB`;
}
function date(n: number) {
  return new Date(n * 1000).toLocaleString();
}
let controller: AbortController | null = null,
  timer: ReturnType<typeof setInterval> | undefined,
  reading = false,
  closed = false;
async function load() {
  if (reading || closed) return;
  reading = true;
  controller = new AbortController();
  try {
    const [source, items] = await Promise.all([
      api.components(controller.signal),
      api.componentTasks(controller.signal),
    ]);
    overview.value = source;
    tasks.value = items;
    error.value = "";
    if (!checks.value.some((t) => t.id === checkID.value))
      checkID.value = checks.value[0]?.id ?? "";
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
  } finally {
    reading = false;
  }
}
async function submit(input: ComponentCreateInput) {
  await run(async () => {
    const task = await (input.input.action === "activate" ? api.activateFrontend(input, keyFor(input)) : api.createComponentTask(input, keyFor(input)));
    tasks.value = [task, ...tasks.value.filter((t) => t.id !== task.id)];
    keyFor = useIdempotency();
  }, "组件任务已排队");
  await load();
}
async function check() {
  await submit({
    check_task_id: "",
    input: {
      action: "check",
      tag: tag.value.trim(),
      prerelease: prerelease.value,
      ...(selection.value === "assets"
        ? { assets: assets.value.split(/[\s,]+/).filter(Boolean) }
        : { components: components.value }),
      plan_id: "",
      manifest_sha256: "",
      trust_sha256: "",
    },
  });
}
async function prepare() {
  const r = release.value,
    t = checked.value;
  if (!r || !t || !canPrepare.value) return;
  await submit({
    check_task_id: t.id,
    input: {
      action: "prepare",
      offline_id: t.result?.input.offline_id,
      tag: r.tag,
      prerelease: !!t.result?.input.prerelease,
      assets: r.selected,
      plan_id: r.plan_id,
      manifest_sha256: r.manifest_sha256,
      trust_sha256: r.trust_sha256,
    },
  });
}
function canActivate(t: ComponentTask) {
  return permitted.value && !!session.me?.scopes.includes("system.write") && t.action === "prepare" && t.state === "succeeded" && !!t.result?.frontend &&
    (t.result.release?.expires_at ?? 0) * 1000 > clock.value && overview.value?.frontend.available && overview.value.frontend.current_id !== t.result.frontend.release_id && !active.value && !busy.value;
}
async function activate(t: ComponentTask) {
  const source = t.result, frontend = overview.value?.frontend;
  if (!canActivate(t) || !source?.release || !frontend) return;
  await submit({ check_task_id: "", prepare_task_id: t.id, input: {
    action: "activate", offline_id: source.input.offline_id, tag: source.release.tag, assets: source.release.selected,
    prerelease: source.input.prerelease, plan_id: source.release.plan_id, manifest_sha256: source.release.manifest_sha256,
    trust_sha256: source.release.trust_sha256, frontend_base_id: frontend.base_id, expected_frontend_id: frontend.current_id,
  } });
}
onMounted(async () => {
  await load();
  if (!closed)
    timer = setInterval(() => {
      clock.value = Date.now();
      if (
        tasks.value.some((t) =>
          ["queued", "running", "recovery_required"].includes(t.state),
        )
      )
        void load();
    }, 3000);
});
onUnmounted(() => {
  closed = true;
  controller?.abort();
  if (timer) clearInterval(timer);
});
</script>
<template>
  <div class="page-stack">
    <ComponentOfflineUpload :available="overview?.available === true" :blocked="active || busy" @changed="load" />
    <section v-if="overview" class="panel page-stack">
      <h2>节点前端版本</h2>
      <p v-if="overview.frontend.available">{{ overview.frontend.version }} · {{ overview.frontend.current_id }}</p>
      <NAlert v-else type="warning">{{ overview.frontend.reason }}</NAlert>
      <p class="muted">独立前端准备完成后可单独激活。激活保留上一版资源，已打开页面可选择重新载入。</p>
    </section>
    <section v-if="overview?.installation" class="panel page-stack">
      <div class="toolbar">
        <h2>
          {{
            overview.installation.owner === "docker"
              ? "容器 Nginx"
              : "原生 Nginx"
          }}
        </h2>
        <NTag :type="overview.running ? 'success' : 'warning'">{{
          overview.running ? "运行已确认" : "运行未确认"
        }}</NTag>
      </div>
      <p>
        {{ overview.installation.version }} ·
        {{
          overview.installation.owner === "managed"
            ? "签名托管组件"
            : overview.installation.owner === "docker"
              ? "固定模块镜像"
              : "本机批准程序"
        }}
        · {{ date(overview.installation.bound_at) }}
      </p>
      <p class="muted">内容散列：{{ overview.installation.sha256 }}</p>
      <p v-if="overview.installation.owner === 'docker'" class="muted">
        镜像：{{ overview.installation.source_url }}
      </p>
      <p v-if="overview.installation.asset_id">
        资产：{{ overview.installation.asset_id }} ·
        {{ overview.installation.license }}
        <a
          v-if="overview.installation.source_url"
          :href="overview.installation.source_url"
          target="_blank"
          rel="noreferrer"
          >上游来源</a
        >
      </p>
      <NAlert v-if="overview.runtime_reason" type="warning">{{
        overview.runtime_reason
      }}</NAlert>
    </section>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <section class="panel page-stack">
      <div class="toolbar">
        <h2>发行来源</h2>
        <NButton @click="load">刷新</NButton>
      </div>
      <NAlert v-if="overview && !overview.available" type="warning">{{
        overview.reason
      }}</NAlert>
      <p v-if="overview?.repository">
        仓库：{{ overview.repository }} · 信任密钥：{{
          overview.key_ids.join("、")
        }}
      </p>
      <NAlert type="info"
        >准备操作校验并下载组件产物。安装与启用需另行执行。Docker 的 Nginx
        模块由镜像提供。面板须单独选择。</NAlert
      >
      <div v-if="permitted" class="grid-2">
        <NFormItem label="选择方式"
          ><NSelect
            v-model:value="selection"
            :options="[
              { label: '按组件匹配', value: 'components' },
              { label: '指定资产 ID', value: 'assets' },
            ]"
        /></NFormItem>
        <NFormItem v-if="selection === 'components'" label="组件"
          ><NSelect
            :value="components"
            @update:value="chooseComponents"
            multiple
            :options="[
              { label: 'Nginx', value: 'nginx' },
              { label: 'Fail2ban', value: 'fail2ban' },
              { label: '面板', value: 'panel' },
              { label: '独立前端', value: 'web' },
            ]"
        /></NFormItem>
        <NFormItem v-else label="资产 ID"
          ><NInput
            v-model:value="assets"
            placeholder="多个 ID 用逗号分隔"
            maxlength="256"
        /></NFormItem>
        <NFormItem label="发行标签"
          ><NInput
            v-model:value="tag"
            placeholder="留空使用最新稳定版，例如 v0.1.0"
            maxlength="128"
        /></NFormItem>
        <NFormItem label="发行渠道"
          ><NCheckbox v-model:checked="prerelease"
            >允许指定标签的预发布版本</NCheckbox
          ></NFormItem
        >
      </div>
      <NButton
        v-if="permitted"
        type="primary"
        :loading="busy"
        :disabled="!overview?.available || active"
        @click="check"
        >检查发行与系统依赖</NButton
      >
    </section>
    <section v-if="checks.length" class="panel page-stack">
      <h2>检查结果</h2>
      <NSelect
        v-model:value="checkID"
        :options="
          checks.map((t) => ({
            label: `${t.result?.input.offline_id ? '离线' : '在线'} · ${t.result?.release?.tag} · ${date(t.created_at)}`,
            value: t.id,
          }))
        "
      />
      <template v-if="release && checked">
        <p>
          {{ release.tag }} · {{ release.channel }} · {{ release.repository }} ·
          签名密钥 {{ release.key_id }}
        </p>
        <p>
          {{ checked.result?.input.offline_id ? '归档' : '下载' }} {{ bytes(release.archive_bytes) }} · 展开
          {{ bytes(release.unpacked_bytes) }} · 有效期至
          {{ date(release.expires_at) }}
        </p>
        <ComponentReleaseDetails :details="release" />
        <NAlert v-if="!checked.result?.runtime_ready" type="warning"
          >系统依赖未就绪：{{ checked.result?.runtime_reason }}</NAlert
        >
        <NAlert v-if="release.expires_at * 1000 <= clock" type="warning"
          >检查结果已过期，请重新检查。</NAlert
        >
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>资产 / 版本</th>
                <th>平台与 ABI</th>
                <th>许可与来源</th>
                <th>模块与依赖</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="asset in release.assets" :key="asset.id">
                <td>
                  {{ asset.id }}<br />{{ asset.component }}
                  {{ asset.version }} · {{ asset.maintenance }}
                </td>
                <td>
                  {{ asset.architecture }} · {{ asset.distribution }}
                  {{ asset.distribution_version }}<br />{{ asset.abi }}
                </td>
                <td>
                  {{ asset.license }}<br /><a
                    :href="asset.source_url"
                    target="_blank"
                    rel="noreferrer"
                    >上游来源</a
                  >
                </td>
                <td>
                  {{ (asset.features ?? []).join("、") || "无模块声明"
                  }}<br />{{
                    (asset.dependencies ?? []).join("、") || "无组件依赖"
                  }}
                  · {{ asset.runtime_files }} 个系统运行文件
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <NPopconfirm v-if="permitted" @positive-click="prepare"
          ><template #trigger
            ><NButton type="primary" :disabled="!canPrepare"
              >准备已检查的组件</NButton
            ></template
          >{{ checked.result?.input.offline_id ? '校验并解包此离线检查结果对应的组件产物？' : '下载并校验此检查结果对应的组件产物？' }}</NPopconfirm
        >
      </template>
    </section>
    <section class="panel page-stack">
      <h2>准备任务</h2>
      <p v-if="!tasks.length" class="muted">暂无组件任务</p>
      <div v-for="task in tasks" :key="task.id" class="component-task">
        <div class="toolbar">
          <strong>{{
            task.action === "activate" ? "前端激活" : task.action === "check" ? "发行检查" : "组件准备"
          }}</strong
          ><NTag
            :type="
              task.state === 'failed' || task.state === 'recovery_required'
                ? 'error'
                : task.state === 'succeeded'
                  ? 'success'
                  : 'info'
            "
            >{{ taskLabel(task) }}</NTag
          >
        </div>
        <p class="muted">
          {{ date(task.updated_at) }} ·
          {{ task.result?.release?.tag || task.id }}
        </p>
        <NAlert v-if="task.error" type="warning">{{ task.error }}</NAlert>
        <template v-if="task.result?.announcement">
          <p>{{ task.result.announcement.repository }} · {{ task.result.announcement.tag }} · 签名密钥 {{ task.result.announcement.key_id }}</p>
          <ComponentReleaseDetails :details="task.result.announcement" />
          <NAlert type="warning">
            <p v-for="issue in task.result.announcement.incompatibilities" :key="issue">{{ issue }}</p>
            <p v-if="task.result.announcement.requirements.api_major !== task.result.announcement.receiver.api_major">请选择与当前面板 API 主版本匹配的发行。</p>
            <p v-if="task.result.announcement.requirements.minimum_agent_protocol > task.result.announcement.receiver.agent_protocol || task.result.announcement.requirements.minimum_launcher > task.result.announcement.receiver.launcher">请由节点管理员按部署文档更新 Agent 或 launcher 后重新检查；容器部署需要替换受信任镜像。</p>
          </NAlert>
        </template>
        <template v-if="task.action === 'prepare' && task.result?.frontend">
          <p>独立前端 {{ task.result.frontend.version }} · {{ task.result.frontend.release_id }}</p>
          <NPopconfirm :disabled="!canActivate(task)" @positive-click="activate(task)">
            <template #trigger><NButton :disabled="!canActivate(task)">激活此前端</NButton></template>
            确认将此节点的前端切换到 {{ task.result.frontend.version }}？现有页面将在重新载入后使用新版本。
          </NPopconfirm>
        </template>
      </div>
    </section>
  </div>
</template>
<style scoped>
.page-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.panel {
  padding: 20px;
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  background: var(--panel-bg, #fff);
}
.grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 0 16px;
}
.component-task {
  padding: 12px 0;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
}
.table-wrap {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}
th,
td {
  padding: 10px;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
  vertical-align: top;
}
h2,
p {
  margin: 0;
}
</style>
