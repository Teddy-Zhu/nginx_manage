<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import {
  NAlert,
  NButton,
  NEmpty,
  NFormItem,
  NInput,
  NRadio,
  NRadioGroup,
  NSelect,
  NSpin,
  NTag,
} from "naive-ui";
import {
  apiError,
  useNodeAPI,
  type ComponentVersion,
  type ComponentVersionCatalog,
} from "../api/client";
import { compareComponentVersions } from "../utils/component-version";
import FormDialog from "./FormDialog.vue";
const props = defineProps<{
  show: boolean;
  name: string;
  appId: string;
  busy?: boolean;
  submitText?: string;
  allowImageTag?: boolean;
  startWithImageTag?: boolean;
}>();
const emit = defineEmits<{
  choose: [version: ComponentVersion];
  "choose-tag": [tag: string];
  cancel: [];
}>();
const api = useNodeAPI(),
  catalog = ref<ComponentVersionCatalog | null>(null),
  channel = ref<"stable" | "beta">("stable"),
  page = ref(1),
  selected = ref(""),
  softwareVersion = ref(""),
  reading = ref(false),
  error = ref("");
const enteringTag = ref(false);
const imageTag = ref("latest");
const validTag = computed(() =>
  /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(imageTag.value.trim()),
);
const canChoose = computed(() =>
  enteringTag.value
    ? validTag.value
    : !reading.value &&
      !!version.value &&
      !version.value.unavailable &&
      version.value.id !== catalog.value?.current?.id,
);
const channels = [
  { label: "稳定版", value: "stable" },
  { label: "Beta 版", value: "beta" },
];
let controller: AbortController | undefined;
const softwareOptions = computed(() => {
  const versions = new Set(
    catalog.value?.versions.flatMap((item) =>
      item.software_version ? [item.software_version] : [],
    ),
  );
  return [
    { label: "全部软件版本", value: "" },
    ...Array.from(versions, (value) => ({ label: value, value })),
  ];
});
const visibleVersions = computed(() =>
  (catalog.value?.versions ?? []).filter(
    (item) =>
      !softwareVersion.value || item.software_version === softwareVersion.value,
  ),
);
const version = computed(() =>
  visibleVersions.value.find((v) => v.id === selected.value),
);
const recommended = computed(
  () =>
    visibleVersions.value.find(
      (item) =>
        !item.unavailable &&
        (!catalog.value?.current ||
          (compareComponentVersions(
            item.version,
            catalog.value.current.version,
          ) ?? 0) > 0),
    )?.id,
);
const downgrade = computed(() => {
  const current = catalog.value?.current;
  return !!(
    !enteringTag.value &&
    version.value &&
    current &&
    ((compareComponentVersions(version.value.version, current.version) ?? 0) <
      0 ||
      (compareComponentVersions(
        version.value.software_version ?? "",
        current.software_version ?? "",
      ) ?? 0) < 0)
  );
});
async function load(refresh = false) {
  controller?.abort();
  const request = new AbortController();
  controller = request;
  reading.value = true;
  error.value = "";
  selected.value = "";
  try {
    const result = await api.componentVersions(
      {
        app_id: props.appId,
        channel: channel.value,
        page: page.value,
        refresh,
      },
      request.signal,
    );
    if (request.signal.aborted) return;
    catalog.value = result;
    if (
      !softwareOptions.value.some(
        (option) => option.value === softwareVersion.value,
      )
    )
      softwareVersion.value = "";
    selected.value = recommended.value ?? "";
  } catch (e) {
    if (!request.signal.aborted) error.value = apiError(e).message;
  } finally {
    if (controller === request) reading.value = false;
  }
}
watch(
  () => [props.show, props.appId],
  () => {
    if (props.show) {
      channel.value = "stable";
      page.value = 1;
      softwareVersion.value = "";
      catalog.value = null;
      selected.value = "";
      enteringTag.value = !!(props.allowImageTag && props.startWithImageTag);
      imageTag.value = "latest";
      if (!enteringTag.value) void load();
    } else controller?.abort();
  },
  { immediate: true },
);
function showCatalog() {
  enteringTag.value = false;
  if (!catalog.value && !reading.value) void load();
}
function submit() {
  if (!canChoose.value || props.busy) return;
  if (enteringTag.value) emit("choose-tag", imageTag.value.trim());
  else if (version.value) emit("choose", version.value);
}
function versionLabel(item: ComponentVersion) {
  if (props.appId === "nginx") {
    return item.software_version
      ? `Nginx ${item.software_version}`
      : "Nginx 版本未提供";
  }
  return item.software_version ?? item.version;
}
function changeChannel(value: "stable" | "beta") {
  channel.value = value;
  page.value = 1;
  softwareVersion.value = "";
  catalog.value = null;
  void load();
}
function changePage(value: number) {
  page.value = value;
  softwareVersion.value = "";
  void load();
}
function changeSoftwareVersion(value: string) {
  softwareVersion.value = value;
  const items = visibleVersions.value.filter(
    (item) => !item.unavailable && item.id !== catalog.value?.current?.id,
  );
  selected.value = recommended.value ?? (items.length === 1 ? items[0].id : "");
}
function selectVersion(item: ComponentVersion) {
  if (
    !reading.value &&
    !props.busy &&
    !item.unavailable &&
    item.id !== catalog.value?.current?.id
  )
    selected.value = item.id;
}
onBeforeUnmount(() => controller?.abort());
</script>
<template>
  <FormDialog
    :show="show"
    :title="`${name} · 选择版本`"
    :busy="busy"
    :submit-disabled="!canChoose"
    :submit-text="
      downgrade
        ? '仍然切换'
        : (submitText ?? (catalog?.current ? '切换版本' : '安装此版本'))
    "
    width="720px"
    @submit="submit"
    @cancel="emit('cancel')"
  >
    <div class="page-stack">
      <div v-if="allowImageTag" class="version-toolbar">
        <NButton
          :type="enteringTag ? 'default' : 'primary'"
          :secondary="!enteringTag"
          :disabled="busy"
          @click="showCatalog"
        >
          选择已知版本
        </NButton>
        <NButton
          :type="enteringTag ? 'primary' : 'default'"
          :secondary="enteringTag"
          :disabled="busy"
          @click="enteringTag = true"
        >
          输入镜像标签
        </NButton>
      </div>
      <NFormItem
        v-if="enteringTag"
        label="Docker 镜像标签"
        :validation-status="imageTag.trim() && !validTag ? 'error' : undefined"
        :feedback="
          imageTag.trim() && !validTag
            ? '请输入有效的 Docker 镜像标签'
            : undefined
        "
      >
        <NInput
          v-model:value="imageTag"
          maxlength="128"
          placeholder="latest"
          :disabled="busy"
        />
      </NFormItem>
      <template v-else>
        <div class="version-toolbar">
          <span v-if="catalog?.current" class="muted"
            >{{ catalog.current.image_tag ? "当前镜像标签" : "当前版本" }}
            {{ catalog.current.version
            }}<template v-if="catalog.current.software_version">
              · {{ name }} {{ catalog.current.software_version }}</template
            ></span
          ><NSelect
            :value="channel"
            :options="channels"
            :disabled="reading || busy"
            aria-label="版本通道"
            class="version-channel"
            @update:value="changeChannel"
          /><NButton :disabled="reading || busy" @click="load(true)">
            检查新版
          </NButton>
        </div>
        <div v-if="softwareOptions.length > 1" class="version-toolbar">
          <label class="version-filter">
            {{ name }}版本
            <NSelect
              :value="softwareVersion"
              :options="softwareOptions"
              :disabled="reading || busy"
              :aria-label="`${name}版本`"
              @update:value="changeSoftwareVersion"
            />
          </label>
        </div>
        <NAlert v-if="error || catalog?.error" type="warning">
          {{
            catalog?.versions.some((item) => item.id === "bundled-nginx")
              ? "在线版本暂不可用，可使用安装包中的镜像。"
              : error || catalog?.error
          }}
        </NAlert>
        <NAlert v-if="channel === 'beta'" type="info">
          Beta 版本用于体验新功能，建议先备份重要配置。
        </NAlert>
        <NSpin :show="reading">
          <NRadioGroup
            v-if="visibleVersions.length"
            v-model:value="selected"
            class="version-list"
            :disabled="reading || busy"
          >
            <div
              v-for="item in visibleVersions"
              :key="item.id"
              class="version-row"
              :class="{ chosen: selected === item.id }"
              @click="selectVersion(item)"
            >
              <NRadio
                :value="item.id"
                :disabled="
                  !!item.unavailable || item.id === catalog?.current?.id
                "
              >
                <strong>{{ versionLabel(item) }}</strong>
              </NRadio>
              <div class="version-info">
                <div class="version-tags">
                  <NTag
                    v-if="item.id === catalog?.current?.id"
                    size="small"
                    type="success"
                  >
                    当前 </NTag
                  ><NTag
                    v-else-if="page === 1 && item.id === recommended"
                    size="small"
                    type="info"
                  >
                    推荐 </NTag
                  ><NTag v-if="item.id === catalog?.previous?.id" size="small">
                    上次安装 </NTag
                  ><NTag v-if="appId === 'nginx'" size="small">
                    {{
                      item.id === "bundled-nginx"
                        ? "安装包镜像"
                        : "在线发布镜像"
                    }} </NTag
                  ><NTag v-else-if="item.image_tag" size="small">
                    镜像标签 </NTag
                  ><span
                    v-if="
                      item.id !== 'bundled-nginx' &&
                      (appId === 'nginx' || item.software_version)
                    "
                    class="muted"
                    >组件 {{ item.version }}</span
                  ><span v-if="item.published_at" class="muted">{{
                    new Date(item.published_at * 1000).toLocaleDateString()
                  }}</span>
                </div>
                <p
                  v-if="item.unavailable || item.notes"
                  :class="item.unavailable ? 'version-warning' : 'muted'"
                >
                  {{ item.unavailable || item.notes }}
                </p>
              </div>
            </div> </NRadioGroup
          ><NEmpty v-else-if="!reading" description="此通道暂无可用版本" />
          <div v-else class="version-placeholder" />
        </NSpin>
        <div v-if="page > 1 || catalog?.has_more" class="version-pagination">
          <NButton
            :disabled="reading || busy || page <= 1"
            @click="changePage(page - 1)"
          >
            上一页 </NButton
          ><span class="muted">第 {{ page }} 页</span
          ><NButton
            :disabled="reading || busy || !catalog?.has_more"
            @click="changePage(page + 1)"
          >
            下一页
          </NButton>
        </div>
        <NAlert v-if="downgrade" type="warning">
          目标版本较旧，现有配置或数据可能不兼容。切换失败时将尝试恢复原版本。
        </NAlert>
        <p v-else-if="catalog?.current" class="muted version-tip">
          切换版本可能短暂中断服务，建议提前备份重要数据。
        </p>
      </template>
      <slot />
    </div>
  </FormDialog>
</template>
<style scoped>
.version-toolbar,
.version-tags,
.version-pagination {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.version-toolbar > span {
  margin-right: auto;
}
.version-channel {
  width: 130px;
}
.version-filter {
  display: flex;
  align-items: center;
  gap: 10px;
  width: min(100%, 320px);
}
.version-filter :deep(.n-select) {
  flex: 1;
}
.version-list {
  display: grid;
  width: 100%;
  gap: 10px;
}
.version-row {
  display: grid;
  grid-template-columns: minmax(140px, 1fr) minmax(0, 2fr);
  gap: 12px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 14px;
  cursor: pointer;
}
.version-row.chosen {
  border-color: var(--accent, #18a058);
}
.version-info {
  min-width: 0;
}
.version-row strong {
  overflow-wrap: anywhere;
}
.version-info p {
  margin: 8px 0 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 100px;
  overflow: auto;
  font-size: 13px;
  line-height: 1.6;
}
.version-warning {
  color: #b97912;
}
.version-pagination {
  justify-content: flex-end;
}
.version-placeholder {
  min-height: 120px;
}
.version-tip {
  margin: 0;
  font-size: 13px;
}
@media (max-width: 540px) {
  .version-row {
    grid-template-columns: 1fr;
  }
}
</style>
