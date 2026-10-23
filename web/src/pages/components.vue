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
import AdvancedDetails from "../components/AdvancedDetails.vue";
import Fail2banPythonPanel from "../components/Fail2banPythonPanel.vue";
import Fail2banLifecyclePanel from "../components/Fail2banLifecyclePanel.vue";
import Fail2banExistingPanel from "../components/Fail2banExistingPanel.vue";
import { nginxState, fail2banState } from "../utils/software";
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
  type Fail2banObservation,
  type Fail2banInstance,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
const api = useNodeAPI();
const route = useRoute();
const software = route.query.software === "nginx" || route.query.software === "fail2ban" ? route.query.software : "";
const fail2ban = ref<Fail2banObservation | null>(null), instance = ref<Fail2banInstance | null>(null);
const moduleEnabled = ref(false), fail2banError = ref("");
const nginxStatus = computed(() => nginxState(overview.value));
const fail2banStatus = computed(() => fail2banState(fail2ban.value));
const stateNames = { installed: "已安装", missing: "未安装", unbound: "待连接", recovery: "安装未完成", unavailable: "状态不可用" };
const prepared = computed(() => tasks.value.find((task) => task.action === "prepare" && task.state === "succeeded" && task.result?.runtime_ready && (task.result.release?.expires_at ?? 0) * 1000 > clock.value && task.result.release?.assets.some((asset) => asset.component === software && task.result!.release!.selected.includes(asset.id))));
async function loadFail2ban() {
  const result = await Promise.allSettled([api.fail2ban(), api.modules()]);
  if (closed) return;
  if (result[0].status === "fulfilled") { fail2ban.value = result[0].value; fail2banError.value = ""; }
  else { fail2ban.value = null; fail2banError.value = apiError(result[0].reason).message; }
  if (result[1].status === "fulfilled") moduleEnabled.value = result[1].value.some((item) => item.id === "fail2ban" && item.enabled);
  if (software === "fail2ban" && fail2ban.value?.binding.state === "bound") {
    try { instance.value = await api.fail2banInstance(); }
    catch (cause) { fail2banError.value = apiError(cause).message; }
  }
}
async function enableFail2ban() {
  await run(async () => {
    await api.setModule("fail2ban", true);
    await loadFail2ban();
  });
}

const session = useSession(),
  { run, busy } = useAction();
let keyFor = useIdempotency();
const overview = ref<ComponentOverview | null>(null),
  tasks = ref<ComponentTask[]>([]),
  error = ref("");
const tag = ref(""),
  prerelease = ref(false),
  components = ref<Array<"nginx" | "fail2ban" | "panel" | "web">>([software || "nginx"]),
  assets = ref(""),
  selection = ref("components");
const checkID = ref(""),
  clock = ref(Date.now());
const permitted = computed(
  () => session.me?.scopes.includes("components.manage") ?? false,
);
const active = computed(() =>
  tasks.value.some((t) =>
    t.stage !== "restore_isolated" && ["queued", "running", "recovery_required"].includes(t.state),
  ),
);
const checks = computed(() =>
  tasks.value.filter(
    (t) => t.action === "check" && t.state === "succeeded" && t.result?.release && (!software || t.result.release.assets.some((asset) => asset.component === software && t.result!.release!.selected.includes(asset.id))),
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
    return t.action === "activate" ? "激活完成" : t.action === "pull" ? "镜像已就绪" : t.action === "prepare" ? "准备完成" : "检查完成";
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
    const task = await (input.input.action === "activate" ? api.activateFrontend(input, keyFor(input)) : input.input.action === "pull" ? api.pullComponentImage(input, keyFor(input)) : api.createComponentTask(input, keyFor(input)));
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
function canPull(t: ComponentTask, imageID: string) {
  return permitted.value && !!session.me?.scopes.includes("system.write") && t.action === "prepare" && t.state === "succeeded" && !!t.result?.panel && !!t.result.runtime_ready && (!t.result.panel.requires_coordination || imageID === "panel-launcher") &&
    (t.result.release?.expires_at ?? 0) * 1000 > clock.value && !active.value && !busy.value;
}
async function pull(t: ComponentTask, imageID: string) {
  const source = t.result;
  if (!canPull(t, imageID) || !source?.release || !source.release.images.some((image) => image.id === imageID)) return;
  await submit({ check_task_id: "", prepare_task_id: t.id, input: {
    action: "pull", image_id: imageID, offline_id: source.input.offline_id, tag: source.release.tag, assets: source.release.selected,
    prerelease: source.input.prerelease, plan_id: source.release.plan_id, manifest_sha256: source.release.manifest_sha256,
    trust_sha256: source.release.trust_sha256,
  } });
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
  await Promise.all([load(), loadFail2ban()]);
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
    <div class="toolbar"><h2>已安装与可选软件</h2><NButton :loading="busy" @click="() => { load(); loadFail2ban(); }">刷新</NButton></div>
    <NAlert v-if="error" type="error">软件状态读取失败：{{ error }}</NAlert>
    <div class="software-grid">
      <section class="panel software-card">
        <div class="toolbar"><h3>Nginx</h3><NTag :type="nginxStatus === 'installed' ? 'success' : 'default'">{{ stateNames[nginxStatus] }}</NTag></div>
        <p class="muted">网站和反向代理服务，支持 HTTPS、访问控制与基础防护。</p>
        <p v-if="overview?.installation">{{ overview.installation.version }} · {{ overview.running ? '运行中' : '未运行' }}</p>
        <div class="toolbar">
          <RouterLink v-if="nginxStatus === 'installed'" to="/nginx"><NButton type="primary">管理</NButton></RouterLink>
          <RouterLink v-else-if="nginxStatus === 'missing'" :to="{ path: '/components', query: { software: 'nginx' } }"><NButton type="primary">安装</NButton></RouterLink>
          <RouterLink v-if="nginxStatus === 'installed'" :to="overview?.installation?.owner === 'docker' ? '/nginx-images' : '/component-switches'"><NButton>更新</NButton></RouterLink>
        </div>
      </section>
      <section class="panel software-card">
        <div class="toolbar"><h3>Fail2ban</h3><NTag :type="fail2banStatus === 'installed' ? 'success' : 'default'">{{ stateNames[fail2banStatus] }}</NTag></div>
        <p class="muted">登录保护服务，可自动封禁多次认证失败的 IP。</p>
        <div class="toolbar">
          <RouterLink v-if="fail2banStatus === 'installed'" to="/fail2ban"><NButton type="primary">管理</NButton></RouterLink>
          <RouterLink v-else-if="fail2banStatus !== 'unavailable'" :to="{ path: '/components', query: { software: 'fail2ban', ...(fail2banStatus === 'unbound' ? { existing: '1' } : {}) } }"><NButton type="primary">{{ fail2banStatus === 'unbound' ? '连接已有安装' : fail2banStatus === 'recovery' ? '继续安装' : '安装' }}</NButton></RouterLink>
          <RouterLink v-if="fail2banStatus === 'installed'" :to="{ path: '/components', query: { software: 'fail2ban' } }"><NButton>软件设置</NButton></RouterLink>
        </div>
        <AdvancedDetails v-if="fail2banError" title="读取失败详情"><p>{{ fail2banError }}</p></AdvancedDetails>
      </section>
    </div>
    <template v-if="software">
      <section class="panel page-stack">
        <div class="toolbar"><h2>{{ software === 'nginx' ? '安装 Nginx' : '安装与管理 Fail2ban' }}</h2><RouterLink to="/components">返回软件列表</RouterLink></div>
        <template v-if="software === 'fail2ban' && !moduleEnabled">
          <p>开启登录防护功能后即可安装或连接软件。</p><NButton type="primary" :loading="busy" @click="enableFail2ban">开启登录防护</NButton>
        </template>
        <template v-else-if="route.query.existing !== '1' && (software === 'nginx' ? nginxStatus !== 'installed' : fail2banStatus !== 'installed')">
          <NAlert v-if="overview && !overview.available" type="warning" title="安装源暂不可用">无法获取可安装的软件，请联系管理员配置安装源，或使用下方的离线安装。<AdvancedDetails title="查看原因"><p>{{ overview.reason }}</p></AdvancedDetails></NAlert>
          <p class="muted">自动匹配当前服务器的可用版本。</p>
          <NButton v-if="permitted" type="primary" :loading="busy || active" :disabled="!overview?.available || active" @click="check">{{ active ? '正在处理，请稍候…' : '查找可用版本' }}</NButton>
          <div v-if="release && checked" class="page-stack">
            <p>可安装版本：<strong>{{ release.tag }}</strong> · 下载大小 {{ bytes(release.archive_bytes) }}</p>
            <NAlert v-if="!checked.result?.runtime_ready" type="warning">当前服务器尚缺少运行依赖，请先完成下方的依赖安装。<AdvancedDetails title="依赖详情"><p>{{ checked.result?.runtime_reason }}</p></AdvancedDetails></NAlert>
            <NButton v-if="permitted && !prepared" type="primary" :loading="busy || active" :disabled="!canPrepare" @click="prepare">下载安装包</NButton>
          </div>
          <NAlert v-if="prepared" type="success">安装包已就绪。</NAlert>
          <RouterLink v-if="software === 'nginx' && prepared" :to="{ path: '/component-installations', query: { prepare: prepared.id } }"><NButton type="primary">开始安装</NButton></RouterLink>
          <RouterLink v-if="software === 'nginx'" to="/component-installations">查看安装进度与历史记录</RouterLink>
        </template>
        <div v-for="task in tasks.filter((item) => ['queued', 'running', 'failed', 'recovery_required'].includes(item.state)).slice(0, 5)" :key="task.id" class="component-row">
          <span>{{ task.action === 'check' ? '检查版本' : task.action === 'prepare' ? '下载安装包' : '更新软件' }}</span><NTag :type="task.state === 'failed' ? 'error' : 'info'">{{ taskLabel(task) }}</NTag>
          <AdvancedDetails v-if="task.error" title="任务详情"><p>{{ task.error }}</p></AdvancedDetails>
        </div>
      </section>
      <template v-if="software === 'fail2ban' && moduleEnabled">
        <Fail2banPythonPanel v-if="fail2ban && fail2ban.python.standard_library !== true" :module-enabled="moduleEnabled" :python="fail2ban.python" :observed-at="fail2ban.at" @changed="loadFail2ban" />
        <Fail2banExistingPanel v-if="route.query.existing === '1'" :module-enabled="moduleEnabled" @changed="loadFail2ban" />
        <Fail2banLifecyclePanel v-else :key="prepared?.id ?? 'no-package'" :module-enabled="moduleEnabled" :binding="fail2ban?.binding ?? null" :instance="instance" :managed="fail2ban?.managed ?? null" :service="fail2ban?.services.find((item) => item.id === 'nginxpanel-fail2ban.service') ?? null" :observed-at="fail2ban?.at ?? 0" @changed="loadFail2ban" />
      </template>
    </template>
    <AdvancedDetails title="离线安装与高级选项">

    <ComponentOfflineUpload :available="overview?.available === true" :blocked="active || busy" :initial-component="software || 'nginx'" @changed="load" />
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
            task.action === "activate" ? "前端激活" : task.action === "pull" ? "镜像拉取" : task.action === "check" ? "发行检查" : "组件准备"
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
        <NAlert v-if="task.result?.release?.staging_only || task.result?.panel?.requires_coordination" type="warning" title="需要协调部署">
          Agent 协议变化可选择协调更新；launcher 协议变化需先拉取面板运行镜像并完成替换，再更新面板与 Agent。
        </NAlert>
        <p v-if="task.result?.panel" class="muted">目标 Agent 协议 {{ task.result.panel.agent_protocol }} · launcher 协议 {{ task.result.panel.launcher_version }}</p>
        <template v-if="task.action === 'prepare' && task.state === 'succeeded' && task.result?.release?.images.length">
          <div v-for="image in task.result.release.images" :key="image.id" class="page-stack">
            <strong>{{ image.id === 'nginx' ? 'Nginx 镜像' : '面板运行镜像' }} · {{ image.architecture }}</strong>
            <p class="muted" style="overflow-wrap: anywhere">{{ image.reference }}</p>
            <NPopconfirm :disabled="!canPull(task, image.id)" @positive-click="pull(task, image.id)">
              <template #trigger><NButton :disabled="!canPull(task, image.id)">拉取镜像</NButton></template>
              确认下载此签名镜像？下载完成后可单独执行运行版本切换。
            </NPopconfirm>
          </div>
        </template>
        <template v-if="task.result?.image">
          <p class="muted" style="overflow-wrap: anywhere">{{ task.result.image.choice.reference }}</p>
          <p v-if="task.state === 'succeeded'">{{ task.result.image.reused ? '已核对本地镜像' : '镜像下载与核对完成' }}</p>
        </template>
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
    </AdvancedDetails>
  </div>
</template>
