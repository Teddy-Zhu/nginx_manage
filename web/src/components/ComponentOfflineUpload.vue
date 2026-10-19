<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { NAlert, NButton, NCheckbox, NFormItem, NInput, NPopconfirm, NSelect } from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentCreateInput,
  type ComponentOfflineInput,
  type ComponentOfflineUpload,
} from "../api/client";
import { useSession } from "../stores/session";
import ComponentReleaseDetails from "./ComponentReleaseDetails.vue";

const props = defineProps<{ available: boolean; blocked: boolean }>();
const emit = defineEmits<{ changed: [] }>();
const api = useNodeAPI(), session = useSession(), controller = new AbortController();
const manifest = ref<File | null>(null), signature = ref<File | null>(null);
const archives = ref<File[]>([]), uploads = ref<ComponentOfflineUpload[]>([]);
const selected = ref(""), component = ref<"nginx" | "fail2ban" | "panel" | "web">("nginx");
const selection = ref("components"), assetIDs = ref("");
const prerelease = ref(false), busy = ref(false), reading = ref(false), uploading = ref(false);
const error = ref(""), notice = ref(""), paused = ref(false), clock = ref(Date.now());
const pendingStart = ref<{ input: ComponentOfflineInput; key: string } | null>(null);
const pendingCheck = ref<{ input: ComponentCreateInput; key: string } | null>(null);
const permitted = computed(() => session.me?.scopes.includes("components.manage") ?? false);
const chosen = computed(() => uploads.value.find((item) => item.id === selected.value));
const options = computed(() => uploads.value.map((item) => ({
  value: item.id,
  label: `${item.release.tag} · ${item.release.assets.map((asset) => asset.component).join("、")} · ${new Date(item.created_at * 1000).toLocaleString()}${item.discarded ? " · 已清除" : item.expires_at * 1000 <= clock.value ? " · 已过期" : ""}`,
})));
const writable = computed(() => permitted.value && props.available && !props.blocked && !busy.value && !reading.value);
const sourceReady = computed(() => !!chosen.value && !chosen.value.discarded && chosen.value.expires_at * 1000 > clock.value);
const canClear = computed(() => writable.value && !!chosen.value &&
  (!chosen.value.discarded || chosen.value.assets.some((asset) => asset.received > 0)),
);
let closed = false;
function bytes(value: number) { return `${(value / 1048576).toFixed(1)} MiB`; }
function file(event: Event, kind: "manifest" | "signature") {
  const value = (event.target as HTMLInputElement).files?.[0] ?? null;
  if (kind === "manifest") manifest.value = value;
  else signature.value = value;
}
function files(event: Event) {
  archives.value = Array.from((event.target as HTMLInputElement).files ?? []);
}
function base64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("读取所选文件失败"));
    reader.onload = () => {
      if (typeof reader.result !== "string" || !reader.result.includes(","))
        reject(new Error("读取所选文件失败"));
      else resolve(reader.result.slice(reader.result.indexOf(",") + 1));
    };
    reader.readAsDataURL(blob);
  });
}
function save(value: ComponentOfflineUpload) {
  uploads.value = [value, ...uploads.value.filter((item) => item.id !== value.id)]
    .sort((a, b) => b.created_at - a.created_at);
  clock.value = Date.now();
}
async function load() {
  if (closed || reading.value) return false;
  reading.value = true;
  try {
    const result = await api.componentOfflineUploads(controller.signal);
    if (closed) return false;
    uploads.value = result.sort((a, b) => b.created_at - a.created_at);
    clock.value = Date.now();
    if (!uploads.value.some((item) => item.id === selected.value))
      selected.value = uploads.value.find((item) => !item.discarded)?.id ?? "";
    error.value = "";
    return true;
  } catch (e) {
    if (!closed) error.value = apiError(e).message;
    return false;
  }
  finally { if (!closed) reading.value = false; }
}
async function start() {
  if (!writable.value || pendingCheck.value) return;
  busy.value = true; error.value = ""; notice.value = "";
  try {
    if (!pendingStart.value) {
      if (!manifest.value || manifest.value.size === 0 || manifest.value.size > 2 * 1048576 ||
          !signature.value || signature.value.size === 0 || signature.value.size > 4096)
        throw new Error("请选择不超过 2 MiB 的清单和不超过 4 KiB 的签名文件");
      const input: ComponentOfflineInput = {
        manifest: await base64(manifest.value),
        signature: await base64(signature.value),
        components: selection.value === "components" ? [component.value] : [],
        assets: selection.value === "assets" ? assetIDs.value.split(/[\s,]+/).filter(Boolean) : [],
        prerelease: prerelease.value,
      };
      if (closed) return;
      pendingStart.value = { input, key: crypto.randomUUID() };
    }
    const result = await api.createComponentOfflineUpload(pendingStart.value.input, pendingStart.value.key);
    if (closed) return;
    pendingStart.value = null; selected.value = result.id; save(result);
    notice.value = result.discarded
      ? "原上传已清除，请创建新上传。"
      : result.expires_at * 1000 <= Date.now()
        ? "原上传已过期，请创建新上传。"
        : "清单验签完成，请选择列出的原始归档文件。";
  } catch (e) {
    if (!closed) {
      const failure = apiError(e); error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500) pendingStart.value = null;
    }
  } finally { if (!closed) busy.value = false; }
}
async function upload() {
  if (!writable.value || !sourceReady.value || pendingStart.value || pendingCheck.value || !chosen.value) return;
  const id = chosen.value.id;
  busy.value = true; uploading.value = true;
  error.value = ""; notice.value = ""; paused.value = false;
  try {
    if (!(await load())) throw new Error("无法核对最新上传进度，请刷新后继续");
    const source = uploads.value.find((item) => item.id === id);
    if (!source || source.discarded || source.expires_at * 1000 <= Date.now())
      throw new Error("上传已清除或过期，请重新创建上传");
    const names = new Set(archives.value.map((item) => item.name));
    if (names.size !== archives.value.length || archives.value.length > 2)
      throw new Error("每次最多选择两个名称唯一的归档文件");
    for (const asset of source.assets) {
      if (asset.received === asset.size) continue;
      const input = archives.value.find((item) => item.name === asset.archive);
      if (!input || input.size !== asset.size)
        throw new Error(`请选择长度为 ${bytes(asset.size)} 的原始文件 ${asset.archive}`);
    }
    for (const asset of source.assets) {
      let offset = asset.received;
      const input = archives.value.find((item) => item.name === asset.archive);
      while (offset < asset.size) {
        if (closed || paused.value) return;
        if (!input) throw new Error(`缺少文件 ${asset.archive}`);
        const end = Math.min(offset + 256 * 1024, asset.size);
        const data = await base64(input.slice(offset, end));
        if (closed || paused.value) return;
        const result = await api.writeComponentOfflineChunk(id, asset.id, { offset, data });
        if (closed) return;
        const received = result.assets.find((item) => item.id === asset.id)?.received;
        if (result.id !== id || received === undefined || received < end)
          throw new Error("上传回执未确认完整分块，请刷新进度后继续");
        save(result); offset = received;
      }
    }
    paused.value = false;
    notice.value = "归档接收完成，可以检查目标依赖，再确认准备。";
  } catch (e) { if (!closed) error.value = apiError(e).message; }
  finally { if (!closed) { busy.value = false; uploading.value = false; } }
}
async function check() {
  if (!writable.value || pendingStart.value) return;
  if (!pendingCheck.value) {
    const source = chosen.value;
    if (!sourceReady.value || !source?.complete) return;
    pendingCheck.value = { key: crypto.randomUUID(), input: {
      check_task_id: "",
      input: { action: "check", offline_id: source.id, tag: source.release.tag,
        assets: source.release.selected, prerelease: source.prerelease,
        plan_id: "", manifest_sha256: "", trust_sha256: "" },
    } };
  }
  busy.value = true; error.value = "";
  try {
    const task = await api.createComponentTask(pendingCheck.value.input, pendingCheck.value.key);
    if (closed) return;
    pendingCheck.value = null; notice.value = `检查任务已创建：${task.id}`;
    emit("changed");
  } catch (e) {
    if (!closed) {
      const failure = apiError(e); error.value = failure.message;
      if (failure.status >= 400 && failure.status < 500) pendingCheck.value = null;
    }
  } finally { if (!closed) busy.value = false; }
}
async function clear() {
  if (!canClear.value || !chosen.value || pendingStart.value || pendingCheck.value) return;
  const id = chosen.value.id;
  busy.value = true; error.value = "";
  try {
    const result = await api.discardComponentOfflineUpload(id);
    if (closed) return;
    save(result); notice.value = "上传归档已清除，已准备版本不受影响。";
  } catch (e) { if (!closed) error.value = apiError(e).message; }
  finally { if (!closed) busy.value = false; }
}
onMounted(() => { if (permitted.value) void load(); });
onUnmounted(() => { closed = true; paused.value = true; controller.abort(); });
</script>

<template>
  <section class="panel page-stack">
    <div class="toolbar">
      <h2>离线签名包</h2>
      <NButton :loading="reading" :disabled="busy || !permitted" @click="load">刷新上传</NButton>
    </div>
    <p>上传发布清单、签名及原始归档。接收完成后检查目标依赖，并在组件准备区确认准备。</p>
    <NAlert v-if="!available" type="warning">离线接收器当前不可用。</NAlert>
    <NFormItem label="选择方式">
      <NSelect v-model:value="selection" :options="[
        { value: 'components', label: '按组件匹配' }, { value: 'assets', label: '指定资产 ID' },
      ]" :disabled="busy || !!pendingStart" />
    </NFormItem>
    <NFormItem v-if="selection === 'components'" label="组件">
      <NSelect v-model:value="component" :options="[
        { value: 'nginx', label: 'Nginx' }, { value: 'fail2ban', label: 'Fail2ban' }, { value: 'panel', label: '面板' }, { value: 'web', label: '独立前端' },
      ]" :disabled="busy || !!pendingStart" />
    </NFormItem>
    <NFormItem v-else label="资产 ID">
      <NInput v-model:value="assetIDs" :disabled="busy || !!pendingStart" maxlength="512" placeholder="最多两个资产 ID，以逗号分隔" />
    </NFormItem>
    <NFormItem label="发布清单">
      <input type="file" accept=".json" :disabled="busy || !!pendingStart" @change="file($event, 'manifest')" />
    </NFormItem>
    <NFormItem label="签名文件">
      <input type="file" accept=".json" :disabled="busy || !!pendingStart" @change="file($event, 'signature')" />
    </NFormItem>
    <NCheckbox v-model:checked="prerelease" :disabled="busy || !!pendingStart">允许预发布版本</NCheckbox>
    <NButton :loading="busy && !!pendingStart" :disabled="!writable || !!pendingCheck || (!pendingStart && (!manifest || !signature))" @click="start">
      {{ pendingStart ? '重试原清单请求' : '验签并创建上传' }}
    </NButton>
    <NAlert v-if="error" type="error">{{ error }}</NAlert>
    <NAlert v-if="notice" type="info">{{ notice }}</NAlert>
    <NFormItem v-if="options.length" label="上传记录">
      <NSelect v-model:value="selected" :options="options" :disabled="busy || !!pendingStart || !!pendingCheck" />
    </NFormItem>
    <section v-if="chosen" class="surface page-stack">
      <p>{{ chosen.release.repository }} · {{ chosen.release.tag }} · {{ chosen.id }}</p>
      <ComponentReleaseDetails :details="chosen.release" />
      <p>有效期至 {{ new Date(chosen.expires_at * 1000).toLocaleString() }}</p>
      <article v-for="asset in chosen.assets" :key="asset.id">
        <p>{{ asset.archive }} · {{ bytes(asset.received) }} / {{ bytes(asset.size) }}</p>
        <p class="muted">SHA-256：{{ asset.sha256 }}</p>
      </article>
      <NFormItem label="归档文件">
        <input type="file" multiple accept=".tar.gz" :disabled="busy || !sourceReady || !!pendingStart || !!pendingCheck" @change="files" />
      </NFormItem>
      <div class="toolbar">
        <NButton :disabled="!writable || !sourceReady || chosen.complete || !!pendingStart || !!pendingCheck" @click="upload">上传 / 继续</NButton>
        <NButton v-if="uploading" :disabled="paused" @click="paused = true">暂停上传</NButton>
        <NButton :disabled="!writable || !!pendingStart || (!pendingCheck && (!sourceReady || !chosen.complete))" @click="check">{{ pendingCheck ? '重试原检查请求' : '检查目标依赖' }}</NButton>
        <NPopconfirm :disabled="!canClear || !!pendingStart || !!pendingCheck" @positive-click="clear">
          <template #trigger><NButton :disabled="!canClear || !!pendingStart || !!pendingCheck">清除上传归档</NButton></template>
          清除后此上传不能再用于准备，已准备或已安装的版本不受影响。
        </NPopconfirm>
      </div>
      <p v-if="paused">{{ uploading ? '正在暂停上传…' : '上传已暂停，可按保存进度继续。' }}</p>
      <p v-if="chosen.complete">字节接收完成；归档散列与内容将在确认准备时核对。</p>
    </section>
  </section>
</template>
