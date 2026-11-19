<route lang="json">
{
  "meta": {
    "title": "网站证书",
    "nav": false,
    "parent": "/certificates",
    "software": "nginx"
  }
}
</route>

<script setup lang="ts">
import DetailDialog from "../components/DetailDialog.vue";
import CertificateWorkspace from "../components/CertificateWorkspace.vue";
import { inspectTask } from "../stores/operation";
import { useLiveRefresh } from "../composables/live";
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { NAlert, NButton, NEmpty, NSelect, NTag } from "naive-ui";
import {
  useNodeAPI,
  type Certificate,
  type Tree,
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
const tree = ref<Tree | null>(null);
const bindingGroups = computed(() => {
  const groups = new Map<
    string,
    { name: string; configured: boolean; applied: boolean; current: boolean }
  >();
  for (const binding of certificate.value?.bindings ?? []) {
    const key = binding.resource_id || binding.file_id;
    let group = groups.get(key);
    if (!group) {
      group = {
        name: siteName(binding.resource_id),
        configured: false,
        applied: false,
        current: true,
      };
      groups.set(key, group);
    }
    group.configured ||= binding.revision_state !== "applied";
    group.applied ||= binding.revision_state !== "desired";
    group.current &&=
      binding.version_id === certificate.value?.latest_version_id;
  }
  return [...groups.values()];
});
const showUsage = ref(false);
const changedSites = computed(() => [
  ...new Set(
    preview.value?.changes.map((change) => siteName(change.resource_id)) ?? [],
  ),
]);
function siteName(id: string) {
  const site = tree.value?.resources.find((item) => item.id === id);
  return (
    site?.metadata.name ||
    site?.fields.domains?.values.join("、") ||
    (id ? "网站配置（已保存）" : "自定义网站配置")
  );
}
const status = ref<CertificateDeploymentStatus | null>(null),
  preview = ref<CertificateDeployPreview | null>(null);
const selected = computed(() =>
  typeof route.query.certificate === "string" ? route.query.certificate : "",
);
const options = computed(() =>
  items.value.map((item) => ({ label: item.name, value: item.id })),
);
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
    const [certificates, config] = await Promise.all([
      api.certificates(),
      api.tree(),
    ]);
    items.value = certificates;
    tree.value = config;
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
    preview.value = null;
    await loadSelected();
  }, "网站证书更新已提交");
}
watch(selected, () => {
  certificate.value = null;
  status.value = null;
  preview.value = null;
  showUsage.value = false;
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
useLiveRefresh(api, ["tasks"], load, () => busy.value || !!preview.value);
</script>

<template>
  <CertificateWorkspace>
    <div class="cert-heading">
      <div>
        <h2>网站证书</h2>
      </div>
      <n-button :loading="busy" @click="load">
        刷新
      </n-button>
    </div>
    <section class="surface cert-section">
      <div>
        <h2>选择证书</h2>
      </div>
      <n-select
        :value="selected || null"
        :options="options"
        :disabled="busy"
        placeholder="选择需要查看或更新的证书"
        filterable
        clearable
        @update:value="choose"
      />
      <n-empty v-if="!items.length && !busy" description="还没有可用证书">
        <template #extra>
          <router-link to="/certificates">
            前往获取证书
          </router-link>
        </template>
      </n-empty>
    </section>
    <template v-if="certificate && status">
      <section class="surface cert-section">
        <div class="cert-heading">
          <h2>{{ certificate.name }}</h2>
          <n-tag
            :bordered="false"
            :type="status.state === 'applied' ? 'success' : 'warning'"
          >
            {{
              status.state === "applied"
                ? "网站已使用当前证书"
                : status.state === "unbound"
                  ? "尚未用于网站"
                  : status.state === "partial"
                    ? "部分网站待更新"
                    : "网站证书待更新"
            }}
          </n-tag>
        </div>
        <n-alert
          v-if="
            certificate.versions.find(
              (item) => item.id === certificate!.latest_version_id,
            )?.environment === 'staging'
          "
          type="warning"
          :bordered="false"
        >
          当前为测试证书，浏览器不会信任。
        </n-alert>
        <template v-if="!certificate.bindings.length">
          <p class="muted">
            此证书尚未用于网站。前往网站设置，选择站点并设置 HTTPS
            证书，保存并应用后生效。
          </p>
          <div class="cert-actions">
            <router-link to="/nginx">
              <n-button type="primary">
                前往网站设置
              </n-button>
            </router-link>
          </div>
        </template>
        <template v-else>
          <div class="cert-actions">
            <n-button
              v-if="status.state !== 'applied'"
              type="primary"
              :disabled="busy || !!preview"
              @click="prepare"
            >
              检查可更新的网站
            </n-button>
            <NButton v-if="bindingGroups.length" @click="showUsage = true">
              查看使用网站
            </NButton><router-link to="/nginx">
              <n-button>管理网站</n-button>
            </router-link>
          </div>
        </template>
      </section>
      <DetailDialog
        :show="!!preview"
        title="网站证书更新"
        @update:show="(visible) => { if (!visible) preview = null; }"
      >
        <div v-if="preview" class="certificate-workspace">
          <p v-if="!preview.changes.length" class="muted">
            已保存的网站配置均使用当前证书。
          </p>
          <template v-else>
            <p>以下网站将应用新证书。</p>
            <div class="cert-actions">
              <NTag v-for="site in changedSites" :key="site">
                {{ site }}
              </NTag>
            </div>
          </template>
        </div>
        <template #actions>
          <NButton
            v-if="preview?.changes.length"
            type="primary"
            :loading="busy"
            @click="deploy"
          >
            确认更新
          </NButton>
        </template>
      </DetailDialog>
      <DetailDialog v-model:show="showUsage" title="使用此证书的网站">
        <div class="certificate-workspace">
          <div
            v-for="(binding, index) in bindingGroups"
            :key="index"
            class="cert-record"
          >
            <div class="cert-heading">
              <span>{{ binding.name }}</span><n-tag
                :bordered="false"
                :type="binding.applied && binding.current ? 'success' : 'warning'"
              >
                {{
                  !binding.current
                    ? "待更新证书"
                    : binding.applied
                      ? "已应用"
                      : "待应用配置"
                }}
              </n-tag>
            </div>
          </div>
          <p v-if="certificate.bindings_truncated" class="muted">
            仅显示部分网站，完整信息请前往网站设置查看。
          </p>
        </div>
      </DetailDialog>
      <section class="surface cert-section">
        <h2>更新记录</h2>
        <n-empty
          v-if="!status.history.length"
          description="尚无网站证书更新记录"
        />
        <article
          v-for="task in status.history"
          :key="task.task_id"
          class="cert-record"
        >
          <div class="cert-heading">
            <span>{{ task.automatic ? "自动更新" : "手动更新" }} ·
              {{ date(task.created_at) }}</span><n-tag :bordered="false">
              {{
                taskStates[task.state] ?? "处理中"
              }}
            </n-tag>
          </div>
          <p v-if="task.last_error" class="error">
            {{ task.last_error }}
          </p>
          <div>
            <n-button
              quaternary
              @click="inspectTask(task.task_id, '网站证书更新日志')"
            >
              查看日志
            </n-button>
          </div>
        </article>
      </section>
    </template>
  </CertificateWorkspace>
</template>
