<script setup lang="ts">
import AdvancedDetails from "./AdvancedDetails.vue";
import ValueListInput from "./ValueListInput.vue";
import { cleanList } from "../utils/form";
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import {
  NAlert,
  NButton,
  NFormItem,
  NInput,
  NInputNumber,
  NPopconfirm,
  NSelect,
  NTag,
  NTabs,
  NTabPane,
} from "naive-ui";
import { useNodeAPI, type Pairing, type PairingJob } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import { sourceNodeId } from "../api/context";

const api = useNodeAPI(),
  session = useSession(),
  { run, busy, message } = useAction();
const emit = defineEmits<{ connected: [] }>();
const canIssue = computed(
  () => !!session.localMe?.scopes.includes("auth.manage"),
);
const scopeNames: Record<string, string> = {
  read: "查看状态",
  "config.write": "管理 Nginx 配置",
  "config.secrets": "查看配置凭据",
  "security.write": "管理安全规则",
  "system.write": "管理系统设置",
  "host.dns.write": "管理系统 DNS",
  "monitoring.write": "管理监控",
  "components.manage": "管理组件",
  "auth.manage": "管理授权",
  "backup.export": "导出备份",
  "backup.secrets": "备份敏感配置",
  "backup.restore": "恢复备份",
  "update.execute": "执行升级",
  "nodes.manage": "管理服务器连接",
  "notifications.write": "管理通知",
};
const scopes = computed(() =>
  (session.localMe?.scopes ?? []).map((scope) => ({
    label: scopeNames[scope] ?? scope,
    value: scope,
  })),
);
const offers = ref<Pairing[]>([]),
  jobs = ref<PairingJob[]>([]);
const connect = reactive({ name: "", url: "", code: "" });
const grant = reactive({
  name: "",
  controller: "",
  scopes: ["read"],
  sources: [] as string[],
  days: 90,
});
const offeredID = ref(""),
  offeredCode = ref(""),
  offeredExpiry = ref(0);
let connectKey = useIdempotency(),
  offerKey = useIdempotency(),
  grantEpoch = Math.floor(Date.now() / 1000);
const offerStates: Record<Pairing["state"], string> = {
  offered: "等待领取",
  claimed: "等待确认",
  confirmed: "授权已确认",
  revoked: "已撤销",
  expired: "已过期",
};
const jobStates: Record<PairingJob["state"], string> = {
  pending: "待核对",
  recovery_required: "需要续办",
  abandoning: "放弃待完成",
  succeeded: "已登记连接",
  abandoned: "已放弃",
};
const stages: Record<PairingJob["stage"], string> = {
  exchange: "交换授权",
  confirm: "确认授权",
  register: "登记连接",
  finished: "已结束",
};
function date(value: number) {
  return value ? new Date(value * 1000).toLocaleString() : "—";
}
async function load() {
  await run(async () => {
    const result = await Promise.all([
      api.pairingJobs(),
      canIssue.value ? api.pairings() : Promise.resolve([]),
    ]);
    jobs.value = result[0];
    offers.value = result[1];
  });
}
function record(job: PairingJob) {
  jobs.value = [job, ...jobs.value.filter((item) => item.id !== job.id)];
  if (job.state === "succeeded") {
    window.dispatchEvent(new Event("node-connections-changed"));
    emit("connected");
  }
}
async function start() {
  await run(async () => {
    let code: { node_id?: unknown; id?: unknown; secret?: unknown };
    try {
      code = JSON.parse(connect.code);
    } catch {
      throw new Error("请粘贴目标节点生成的完整配对信息");
    }
    if (
      !code ||
      typeof code.node_id !== "string" ||
      typeof code.id !== "string" ||
      typeof code.secret !== "string"
    )
      throw new Error("配对信息缺少目标编号、配对编号或秘密");
    const input = {
      name: connect.name,
      url: connect.url,
      target_node_id: code.node_id,
      pairing_id: code.id,
      secret: code.secret,
    };
    const value = await api.startPairing(input, connectKey(input));
    record(value);
    connect.code = "";
    connectKey = useIdempotency();
    if (value.state === "succeeded") message.success("节点连接已登记");
  });
}
async function resume(job: PairingJob) {
  await run(async () => {
    record(await api.resumePairing(job.id));
  });
}
async function abandon(job: PairingJob) {
  await run(async () => {
    record(await api.abandonPairing(job.id));
  });
}
async function offer() {
  await run(async () => {
    const input = {
      name: grant.name,
      controller_node_id: grant.controller,
      scopes: grant.scopes,
      allowed_sources: cleanList(grant.sources),
      credential_expires_at: grantEpoch + grant.days * 86400,
    };
    const value = await api.createPairing(input, offerKey(input));
    offers.value = [
      value.pairing,
      ...offers.value.filter((item) => item.id !== value.pairing.id),
    ];
    offeredID.value = value.pairing.id;
    offeredExpiry.value = value.pairing.expires_at;
    offeredCode.value = value.secret
      ? JSON.stringify({
          node_id: value.pairing.node_id,
          id: value.pairing.id,
          secret: value.secret,
        })
      : "";
    if (!value.secret)
      message.warning(
        "原授权已创建，秘密不会再次展示；需要时先撤销原授权再生成",
      );
    offerKey = useIdempotency();
    grantEpoch = Math.floor(Date.now() / 1000);
  });
}
async function revoke(pair: Pairing) {
  await run(async () => {
    const value = await api.revokePairing(pair.id);
    offers.value = [
      value,
      ...offers.value.filter((item) => item.id !== value.id),
    ];
    if (offeredID.value === pair.id) offeredCode.value = "";
  }, "配对及其目标授权已撤销");
}
onMounted(load);
onUnmounted(() => {
  connect.code = "";
  offeredCode.value = "";
});
</script>
<template>
  <div class="page-stack">
    <div class="toolbar">
      <h3>一次性配对</h3>
      <NButton :disabled="busy" @click="load">刷新配对记录</NButton>
    </div>
    <AdvancedDetails title="本机连接信息"
      ><p class="mono">服务器编号：{{ sourceNodeId }}</p></AdvancedDetails
    >
    <NTabs type="segment"
      ><NTabPane name="connect" tab="连接其他服务器">
        <div class="form-grid">
          <NFormItem label="连接名称"
            ><NInput
              v-model:value="connect.name"
              :maxlength="100"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="目标 HTTPS API"
            ><NInput
              v-model:value="connect.url"
              :maxlength="2048"
              :disabled="busy"
              placeholder="https://node.example.com/api/v1"
          /></NFormItem>
          <NFormItem class="full-width" label="目标生成的配对信息"
            ><NInput
              v-model:value="connect.code"
              type="textarea"
              :maxlength="2048"
              :disabled="busy"
              autocomplete="off"
          /></NFormItem>
          <p class="section-note full-width">
            使用目标服务器生成的配对信息，在有效期内完成连接。
          </p>
          <div class="form-actions full-width">
            <NButton
              type="primary"
              :loading="busy"
              :disabled="!connect.name || !connect.url || !connect.code"
              @click="start"
              >配对并登记连接</NButton
            >
          </div>
        </div>
      </NTabPane>
      <NTabPane v-if="canIssue" name="grant" tab="授权其他服务器连接本机">
        <div class="form-grid">
          <NFormItem label="授权名称"
            ><NInput
              v-model:value="grant.name"
              :maxlength="100"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="控制节点永久编号"
            ><NInput
              v-model:value="grant.controller"
              :maxlength="36"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="授权权限"
            ><NSelect
              v-model:value="grant.scopes"
              multiple
              :options="scopes"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="允许来源 CIDR"
            ><ValueListInput
              v-model:value="grant.sources"
              item-label="来源网段"
              :max="32"
              placeholder="192.0.2.10/32"
              :maxlength="64"
              :disabled="busy"
          /></NFormItem>
          <NFormItem label="确认后凭据有效天数"
            ><NInputNumber
              :value="grant.days"
              :min="1"
              :max="366"
              :precision="0"
              :disabled="busy"
              :clearable="false"
              @update:value="
                (value: number | null) => {
                  if (value !== null) grant.days = value;
                }
              "
          /></NFormItem>
          <p class="section-note full-width">
            配对信息 5
            分钟内有效，仅展示一次。授权默认只读；允许来源按目标实际直连地址匹配，经网关时填写网关来源。
          </p>
          <div class="form-actions full-width">
            <NButton
              type="primary"
              :loading="busy"
              :disabled="
                !grant.name ||
                !grant.controller ||
                !cleanList(grant.sources).length ||
                !grant.scopes.includes('read')
              "
              @click="offer"
              >生成一次性配对信息</NButton
            >
          </div>
        </div>
      </NTabPane></NTabs
    >
    <NAlert v-if="offeredCode" type="warning" title="请安全传递配对信息">
      有效至 {{ date(offeredExpiry) }}
      <NInput :value="offeredCode" type="textarea" readonly />
      <NButton text @click="offeredCode = ''">隐藏配对信息</NButton>
    </NAlert>
    <article v-for="job in jobs" :key="job.id" class="record-card">
      <div class="toolbar">
        <strong>{{ job.name }}</strong
        ><NTag :type="job.state === 'succeeded' ? 'success' : 'warning'">{{
          jobStates[job.state]
        }}</NTag>
      </div>
      <p>
        {{ job.url }} · {{ stages[job.stage] }} · {{ date(job.updated_at) }}
      </p>
      <p class="muted">
        目标 {{ job.target_node_id }} · 配对 {{ job.pairing_id }}
      </p>
      <p v-if="job.credential_id" class="muted">
        目标凭据 {{ job.credential_id }}
      </p>
      <NAlert v-if="job.error" type="warning">{{ job.error }}</NAlert>
      <div
        v-if="job.state !== 'succeeded' && job.state !== 'abandoned'"
        class="toolbar"
      >
        <NButton
          v-if="job.state !== 'abandoning'"
          :disabled="busy"
          @click="resume(job)"
          >续办原配对</NButton
        >
        <NPopconfirm
          :disabled="busy"
          positive-text="放弃并核对撤销"
          @positive-click="abandon(job)"
          ><template #trigger
            ><NButton type="error" :disabled="busy">{{
              job.state === "abandoning" ? "继续放弃" : "放弃配对"
            }}</NButton></template
          >清除本机恢复材料，并尝试撤销已收到的目标授权。撤销未确认时，需要在目标按配对编号补做撤销。</NPopconfirm
        >
      </div>
    </article>
    <details v-if="canIssue && offers.length">
      <summary>本机签发的配对授权</summary>
      <article v-for="pair in offers" :key="pair.id" class="record-card">
        <div class="toolbar">
          <strong>{{ pair.name }}</strong
          ><NTag>{{ offerStates[pair.state] }}</NTag>
        </div>
        <p class="muted">
          配对 {{ pair.id }} · 控制节点 {{ pair.controller_node_id }}
        </p>
        <p>
          权限 {{ pair.scopes.join("、") }} · 来源
          {{ pair.allowed_sources.join("、") }}
        </p>
        <p>
          领取有效至 {{ date(pair.expires_at) }} · 凭据批准有效至
          {{ date(pair.credential_expires_at) }}
        </p>
        <p v-if="pair.credential_id">目标凭据 {{ pair.credential_id }}</p>
        <NPopconfirm
          v-if="pair.state !== 'revoked'"
          :disabled="busy"
          positive-text="撤销授权"
          @positive-click="revoke(pair)"
          ><template #trigger
            ><NButton type="error" :disabled="busy"
              >撤销配对及授权</NButton
            ></template
          >立即阻止领取，并撤销该配对已交换的机器凭据。</NPopconfirm
        >
      </article>
    </details>
  </div>
</template>
