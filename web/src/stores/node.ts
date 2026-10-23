import { randomUUID } from "../utils/crypto";
import { defineStore } from "pinia";
import { computed, ref, watch } from "vue";
import { api, ApiError, type NodeConnection } from "../api/client";
import { invalidateNodeScope, nodeGeneration, nodeRequestError, selectedTarget, sourceNodeId } from "../api/context";

export const useNodes = defineStore("nodes", () => {
  const connections = ref<NodeConnection[]>([]);
  const switching = ref(false);
  const selected = computed(() => selectedTarget.value);
  const generation = nodeGeneration;
  const error = nodeRequestError;
  let loading: Promise<void> | null = null;
  async function load() {
    if (loading) return loading;
    loading = api.nodes().then((value) => {
      connections.value = value;
      const current = selectedTarget.value;
      const row = current && value.find((item) => item.id === current.connection);
      if (current && (!row || row.removed_at || row.state === "removing")) {
        selectedTarget.value = { ...current, scopes: [] };
        error.value = "当前节点连接已删除或正在删除，请选择其他节点";
      } else if (current && row) {
        selectedTarget.value = { ...current, name: row.name, scopes: row.state === "connected" ? [...row.scopes] : [] };
        if (row.state !== "connected") error.value = row.error || "当前连接需要重新检查";
      }
    }).finally(() => { loading = null; });
    return loading;
  }
  async function select(id: string) {
    if (switching.value) return;
    switching.value = true;
    invalidateNodeScope();
    try {
      if (!id) { selectedTarget.value = null; return; }
      const value = await api.refreshNode(id, randomUUID());
      connections.value = [value, ...connections.value.filter((item) => item.id !== id)];
      if (value.state !== "connected" || value.removed_at) throw new ApiError("REMOTE_CONNECTION_UNAVAILABLE", value.error || "目标连接未就绪", 409);
      selectedTarget.value = { connection: value.id, nodeId: value.node_id, name: value.name, scopes: [...value.scopes] };
    } catch (cause) {
      if (selectedTarget.value?.connection === id) error.value = cause instanceof Error ? cause.message : "目标连接检查失败";
      throw cause;
    } finally { switching.value = false; }
  }
  watch(sourceNodeId, (id) => { if (!id) connections.value = []; });
  return { connections, switching, selected, generation, error, load, select };
});
