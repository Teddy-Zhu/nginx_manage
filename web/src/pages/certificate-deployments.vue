<route lang="json">
{
  "meta": {
    "title": "证书部署",
    "subtitle": "更新网站使用的 SSL 证书",
    "nav": false,
    "parent": "/certificates",
    "software": "nginx"
  }
}
</route>

<script setup lang="ts">
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { NAlert, NButton, NEmpty, NSelect, NTag } from "naive-ui";
import {
  useNodeAPI,
  type Certificate,
  type CertificateDeploymentStatus,
  type CertificateDeployPreview,
} from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
const api = useNodeAPI();

const route = useRoute(),
  router = useRouter();
const { busy, run } = useAction(),
  keyFor = useIdempotency();
const items = ref<Certificate[]>([]),
  certificate = ref<Certificate | null>(null);
const status = ref<CertificateDeploymentStatus | null>(null),
  preview = ref<CertificateDeployPreview | null>(null);
const selected = computed(() =>
  typeof route.query.certificate === "string" ? route.query.certificate : "",
);
const options = computed(() =>
  items.value.map((item) => ({ label: item.name, value: item.id })),
);
const states: Record<CertificateDeploymentStatus["state"], string> = {
  unbound: "尚未绑定",
  pending: "最新版本待应用",
  partial: "部分绑定已应用最新版本",
  applied: "已应用绑定均为最新版本",
};
const taskStates: Record<string, string> = {
  queued: "排队中",
  running: "执行中",
  compensating: "补偿中",
  succeeded: "已完成",
  failed: "失败",
  rolled_back: "已回滚",
  recovery_required: "待恢复",
  cancelled: "已取消",
};
const date = (value: number) => new Date(value * 1000).toLocaleString();
let pendingSelection = false;

async function loadSelected() {
  const id = selected.value;
  preview.value = null;
  if (!id) {
    certificate.value = null;
    status.value = null;
    return;
  }
  const [c, s] = await Promise.all([
    api.certificate(id),
    api.certificateDeployments(id),
  ]);
  if (selected.value !== id) return;
  certificate.value = c;
  status.value = s;
}
async function load() {
  await run(async () => {
    items.value = await api.certificates();
    await loadSelected();
  });
}
function choose(id: string | null) {
  if (busy.value) return;
  void router.replace({
    query: { ...route.query, certificate: id || undefined },
  });
}
async function prepare() {
  if (busy.value || !selected.value) return;
  await run(async () => {
    const id = selected.value;
    const result = await api.previewCertificateDeploy(id);
    if (selected.value === id) preview.value = result;
  });
}
async function deploy() {
  if (busy.value || !preview.value?.changes.length) return;
  const plan = preview.value;
  const input = {
    base_version: plan.base_version,
    version_id: plan.version_id,
  };
  await run(async () => {
    await api.deployCertificate(
      plan.certificate_id,
      input,
      keyFor({ action: "deploy-certificate", id: plan.certificate_id, input }),
    );
    await loadSelected();
  }, "部署任务已排队，请查看实际应用结果");
}
watch(selected, () => {
  certificate.value = null;
  status.value = null;
  preview.value = null;
  pendingSelection = true;
  if (!busy.value) {
    pendingSelection = false;
    void run(loadSelected);
  }
});
watch(busy, (working) => {
  if (!working && pendingSelection) {
    pendingSelection = false;
    void run(loadSelected);
  }
});
onMounted(() => {
  void load();
});
useLiveRefresh(api, ["tasks"], () => {
  if (!busy.value && !preview.value) return run(loadSelected);
});
</script>

<template>
  <div class="toolbar">
    <div class="inline-gap">
      <router-link to="/certificates">证书管理</router-link
      ><router-link to="/certificate-requests">ACME 签发与续期</router-link
      ><router-link to="/nginx">Nginx 配置</router-link
      ><router-link to="/tasks">任务与审计</router-link>
    </div>
    <n-button :loading="busy" @click="load">刷新</n-button>
  </div>
  <n-select
    :value="selected || null"
    :options="options"
    :disabled="busy"
    placeholder="选择证书"
    filterable
    clearable
    @update:value="choose"
    class="notice"
  />
  <n-empty v-if="!selected" description="选择证书查看部署与绑定状态" />
  <template v-if="certificate && status">
    <section class="surface notice">
      <div class="section-heading">
        <h2>{{ certificate.name }}</h2>
        <n-tag
          :bordered="false"
          :type="status.state === 'applied' ? 'success' : 'warning'"
          >{{ states[status.state] }}</n-tag
        >
      </div>
      <p class="muted">最新版本：{{ status.version_id }}</p>
      <p>
        已应用最新版本的绑定：{{ status.applied_bindings }} /
        {{ status.current_bindings }}；期望配置中的最新版本绑定：{{
          status.desired_bindings
        }}
      </p>
      <p class="muted">
        绑定状态以已确认生效的 Nginx 配置为准，包含停用站点的配置引用。
      </p>
      <n-alert
        v-if="certificate.versions[0]?.environment === 'staging'"
        type="warning"
        :bordered="false"
        class="notice"
        >当前为测试证书，浏览器不会信任。</n-alert
      >
      <n-button :disabled="busy" @click="prepare">预览部署最新版本</n-button>
    </section>
    <section v-if="preview" class="surface notice">
      <h2>部署预览</h2>
      <p class="muted">目标证书：{{ preview.version_id }}</p>
      <p v-if="!preview.changes.length">
        现有绑定已使用最新版本，无需再次部署。
      </p>
      <template v-else>
        <p>
          将替换 {{ preview.changes.length }} 处证书链或私钥引用，并应用新的
          Nginx 配置。
        </p>
        <div
          v-for="(change, index) in preview.changes"
          :key="index"
          class="change"
        >
          <span
            >{{ change.file_id }} · {{ change.resource_id || "共享配置" }} ·
            {{ change.purpose === "ssl_certificate" ? "证书链" : "私钥" }}</span
          ><small class="muted">原版本：{{ change.previous_version_id }}</small>
        </div>
        <p class="muted">
          校验或应用失败会保留任务及候选配置，请在 Nginx 配置中检查并处理。
        </p>
        <div class="inline-gap">
          <n-button type="primary" :loading="busy" @click="deploy"
            >确认部署</n-button
          ><n-button :disabled="busy" @click="preview = null">取消</n-button>
        </div>
      </template>
    </section>
    <section class="surface notice">
      <h2>当前绑定</h2>
      <n-empty
        v-if="!certificate.bindings.length"
        description="尚无已保存的绑定"
      />
      <div
        v-for="(binding, index) in certificate.bindings"
        :key="index"
        class="change"
      >
        <span
          >{{ binding.resource_id || "共享配置" }} · {{ binding.file_id }} ·
          {{ binding.purpose }}</span
        ><small class="muted"
          >证书版本 {{ binding.version_id }} ·
          {{
            binding.revision_state === "desired_applied"
              ? "期望及已应用"
              : binding.revision_state === "applied"
                ? "已应用"
                : "待应用"
          }}</small
        >
      </div>
      <p v-if="certificate.bindings_truncated" class="muted">
        仅展示前 100 条引用，完整配置请在 Nginx 配置中查看。
      </p>
    </section>
    <section class="surface">
      <h2>最近部署任务</h2>
      <n-empty v-if="!status.history.length" description="尚无证书部署任务" />
      <article
        v-for="task in status.history"
        :key="task.task_id"
        class="change"
      >
        <div class="section-heading">
          <span
            >{{ task.automatic ? "自动部署" : "手动部署" }} ·
            {{ date(task.created_at) }}</span
          ><n-tag :bordered="false">{{
            taskStates[task.state] ?? task.state
          }}</n-tag>
        </div>
        <small class="muted"
          >证书版本：{{ task.version_id }} · 任务：{{ task.task_id }}</small
        >
        <p v-if="task.last_error" class="error">{{ task.last_error }}</p>
      </article>
    </section>
  </template>
</template>

<style scoped>
.notice {
  margin-bottom: 20px;
}
.section-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
}
.change {
  display: grid;
  gap: 8px;
  padding: 14px 0;
  border-bottom: 1px solid var(--line);
  overflow-wrap: anywhere;
}
</style>
