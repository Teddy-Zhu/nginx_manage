<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { NAlert, NButton, NFormItem, NInput, NInputNumber, NPopconfirm, NSelect, NTag } from "naive-ui";
import { useNodeAPI, type Pairing, type PairingJob } from "../api/client";
import { useAction, useIdempotency } from "../composables/action";
import { useSession } from "../stores/session";
import { sourceNodeId } from "../api/context";

const api = useNodeAPI(), session = useSession(), { run, busy, message } = useAction();
const emit = defineEmits<{ connected: [] }>();
const canIssue = computed(() => !!session.localMe?.scopes.includes("auth.manage"));
const scopes = computed(() => (session.localMe?.scopes ?? []).map((scope) => ({ label: scope, value: scope })));
const offers = ref<Pairing[]>([]), jobs = ref<PairingJob[]>([]);
const connect = reactive({ name: "", url: "", fingerprint: "", code: "" });
const grant = reactive({ name: "", controller: "", scopes: ["read"], sources: "", days: 90 });
const offeredID = ref(""), offeredCode = ref(""), offeredExpiry = ref(0);
let connectKey = useIdempotency(), offerKey = useIdempotency(), grantEpoch = Math.floor(Date.now() / 1000);
const offerStates: Record<Pairing["state"], string> = { offered: "等待领取", claimed: "等待确认", confirmed: "授权已确认", revoked: "已撤销", expired: "已过期" };
const jobStates: Record<PairingJob["state"], string> = { pending: "待核对", recovery_required: "需要续办", abandoning: "放弃待完成", succeeded: "已登记连接", abandoned: "已放弃" };
const stages: Record<PairingJob["stage"], string> = { exchange: "交换授权", confirm: "确认授权", register: "登记连接", finished: "已结束" };
function date(value: number) { return value ? new Date(value * 1000).toLocaleString() : "—"; }
async function load() {
  await run(async () => {
    const result = await Promise.all([api.pairingJobs(), canIssue.value ? api.pairings() : Promise.resolve([])]);
    jobs.value = result[0]; offers.value = result[1];
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
    try { code = JSON.parse(connect.code); } catch { throw new Error("配对信息须为目标节点生成的 JSON"); }
    if (!code || typeof code.node_id !== "string" || typeof code.id !== "string" || typeof code.secret !== "string") throw new Error("配对信息缺少目标编号、配对编号或秘密");
    const input = { name: connect.name, url: connect.url, fingerprint: connect.fingerprint, target_node_id: code.node_id, pairing_id: code.id, secret: code.secret };
    const value = await api.startPairing(input, connectKey(input));
    record(value); connect.code = ""; connectKey = useIdempotency();
    if (value.state === "succeeded") message.success("节点连接已登记");
  });
}
async function resume(job: PairingJob) {
  await run(async () => { record(await api.resumePairing(job.id)); });
}
async function abandon(job: PairingJob) {
  await run(async () => { record(await api.abandonPairing(job.id)); });
}
async function offer() {
  await run(async () => {
    const input = { name: grant.name, controller_node_id: grant.controller, scopes: grant.scopes, allowed_sources: grant.sources.trim().split(/\s+/).filter(Boolean), credential_expires_at: grantEpoch + grant.days * 86400 };
    const value = await api.createPairing(input, offerKey(input));
    offers.value = [value.pairing, ...offers.value.filter((item) => item.id !== value.pairing.id)];
    offeredID.value = value.pairing.id; offeredExpiry.value = value.pairing.expires_at;
    offeredCode.value = value.secret ? JSON.stringify({ node_id: value.pairing.node_id, id: value.pairing.id, secret: value.secret }) : "";
    if (!value.secret) message.warning("原授权已创建，秘密不会再次展示；需要时先撤销原授权再生成");
    offerKey = useIdempotency(); grantEpoch = Math.floor(Date.now() / 1000);
  });
}
async function revoke(pair: Pairing) {
  await run(async () => {
    const value = await api.revokePairing(pair.id);
    offers.value = [value, ...offers.value.filter((item) => item.id !== value.id)];
    if (offeredID.value === pair.id) offeredCode.value = "";
  }, "配对及其目标授权已撤销");
}
onMounted(load);
onUnmounted(() => { connect.code = ""; offeredCode.value = ""; });
</script>
<template>
  <section class="panel page-stack">
    <div class="toolbar"><h2>一次性配对</h2><NButton :disabled="busy" @click="load">刷新配对记录</NButton></div>
    <p class="muted">本机永久编号：{{ sourceNodeId }}</p>
    <details>
      <summary>连接目标节点</summary>
      <div class="page-stack">
        <NFormItem label="连接名称"><NInput v-model:value="connect.name" :maxlength="100" :disabled="busy" /></NFormItem>
        <NFormItem label="目标 HTTPS API"><NInput v-model:value="connect.url" :maxlength="2048" :disabled="busy" placeholder="https://node.example.com/api/v1" /></NFormItem>
        <NFormItem label="目标证书 SHA-256 指纹"><NInput v-model:value="connect.fingerprint" :maxlength="64" :disabled="busy" /></NFormItem>
        <NFormItem label="目标生成的配对信息"><NInput v-model:value="connect.code" type="textarea" :maxlength="2048" :disabled="busy" autocomplete="off" /></NFormItem>
        <p class="muted">目标授权须绑定上方本机永久编号。通过独立渠道核对证书指纹后，在配对有效期内连接。</p>
        <div><NButton type="primary" :loading="busy" :disabled="!connect.name || !connect.url || connect.fingerprint.length !== 64 || !connect.code" @click="start">配对并登记连接</NButton></div>
      </div>
    </details>
    <details v-if="canIssue">
      <summary>允许控制节点配对本机</summary>
      <div class="page-stack">
        <NFormItem label="授权名称"><NInput v-model:value="grant.name" :maxlength="100" :disabled="busy" /></NFormItem>
        <NFormItem label="控制节点永久编号"><NInput v-model:value="grant.controller" :maxlength="36" :disabled="busy" /></NFormItem>
        <NFormItem label="授权权限"><NSelect v-model:value="grant.scopes" multiple :options="scopes" :disabled="busy" /></NFormItem>
        <NFormItem label="允许来源 CIDR"><NInput v-model:value="grant.sources" type="textarea" :maxlength="4096" :disabled="busy" placeholder="每行一个 CIDR，例如 192.0.2.10/32" /></NFormItem>
        <NFormItem label="确认后凭据有效天数"><NInputNumber :value="grant.days" :min="1" :max="366" :precision="0" :disabled="busy" :clearable="false" @update:value="(value: number | null) => { if (value !== null) grant.days = value; }" /></NFormItem>
        <p class="muted">配对信息 5 分钟内有效，仅展示一次。授权默认只读；允许来源按目标实际直连地址匹配，经网关时填写网关来源。</p>
        <div><NButton type="primary" :loading="busy" :disabled="!grant.name || !grant.controller || !grant.sources.trim() || !grant.scopes.includes('read')" @click="offer">生成一次性配对信息</NButton></div>
      </div>
    </details>
    <NAlert v-if="offeredCode" type="warning" title="请安全传递配对信息">
      有效至 {{ date(offeredExpiry) }}
      <NInput :value="offeredCode" type="textarea" readonly />
      <NButton text @click="offeredCode = ''">隐藏配对信息</NButton>
    </NAlert>
    <article v-for="job in jobs" :key="job.id" class="panel page-stack">
      <div class="toolbar"><strong>{{ job.name }}</strong><NTag :type="job.state === 'succeeded' ? 'success' : 'warning'">{{ jobStates[job.state] }}</NTag></div>
      <p>{{ job.url }} · {{ stages[job.stage] }} · {{ date(job.updated_at) }}</p>
      <p class="muted">目标 {{ job.target_node_id }} · 配对 {{ job.pairing_id }}</p>
      <p v-if="job.credential_id" class="muted">目标凭据 {{ job.credential_id }}</p>
      <NAlert v-if="job.error" type="warning">{{ job.error }}</NAlert>
      <div v-if="job.state !== 'succeeded' && job.state !== 'abandoned'" class="toolbar">
        <NButton v-if="job.state !== 'abandoning'" :disabled="busy" @click="resume(job)">续办原配对</NButton>
        <NPopconfirm :disabled="busy" positive-text="放弃并核对撤销" @positive-click="abandon(job)"><template #trigger><NButton type="error" :disabled="busy">{{ job.state === 'abandoning' ? '继续放弃' : '放弃配对' }}</NButton></template>清除本机恢复材料，并尝试撤销已收到的目标授权。撤销未确认时，需要在目标按配对编号补做撤销。</NPopconfirm>
      </div>
    </article>
    <details v-if="canIssue && offers.length">
      <summary>本机签发的配对授权</summary>
      <article v-for="pair in offers" :key="pair.id" class="panel page-stack">
        <div class="toolbar"><strong>{{ pair.name }}</strong><NTag>{{ offerStates[pair.state] }}</NTag></div>
        <p class="muted">配对 {{ pair.id }} · 控制节点 {{ pair.controller_node_id }}</p>
        <p>权限 {{ pair.scopes.join('、') }} · 来源 {{ pair.allowed_sources.join('、') }}</p>
        <p>领取有效至 {{ date(pair.expires_at) }} · 凭据批准有效至 {{ date(pair.credential_expires_at) }}</p>
        <p v-if="pair.credential_id">目标凭据 {{ pair.credential_id }}</p>
        <NPopconfirm v-if="pair.state !== 'revoked'" :disabled="busy" positive-text="撤销授权" @positive-click="revoke(pair)"><template #trigger><NButton type="error" :disabled="busy">撤销配对及授权</NButton></template>立即阻止领取，并撤销该配对已交换的机器凭据。</NPopconfirm>
      </article>
    </details>
  </section>
</template>
