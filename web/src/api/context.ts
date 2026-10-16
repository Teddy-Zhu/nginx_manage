import { ref, shallowRef } from "vue";

export interface TargetNode {
  connection: string;
  nodeId: string;
  name: string;
  scopes: string[];
}
export interface RequestScope {
  target: TargetNode | null;
  generation: number | null;
  signal?: AbortSignal;
}
export const sourceNodeId = ref("");
export const selectedTarget = shallowRef<TargetNode | null>(null);
export const nodeGeneration = ref(0);
export const nodeRequestError = ref("");
let nodeController = new AbortController();
let controlController = new AbortController();

export function invalidateNodeScope() {
  nodeController.abort();
  nodeController = new AbortController();
  nodeGeneration.value++;
  nodeRequestError.value = "";
}
export function pageScope(local: boolean, signal: AbortSignal): RequestScope {
  return { target: local ? null : selectedTarget.value, generation: nodeGeneration.value, signal: AbortSignal.any([signal, nodeController.signal]) };
}
export function scopeSignal(scope: RequestScope) {
  return scope.signal ?? controlController.signal;
}
export function resetAPIContext() {
  invalidateNodeScope();
  controlController.abort();
  controlController = new AbortController();
  selectedTarget.value = null;
  sourceNodeId.value = "";
}
