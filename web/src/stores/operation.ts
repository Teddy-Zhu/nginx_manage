import { ref, watch } from "vue";
import {
  nodeGeneration,
  selectedTarget,
  type RequestScope,
} from "../api/context";

export interface Operation {
  sequence: number;
  title: string;
  scope: RequestScope;
  taskId: string;
  submitting: boolean;
  requestOnly: boolean;
  error: string;
  uncertain: boolean;
  state: string;
}

export const currentOperation = ref<Operation | null>(null);
export const operationVisible = ref(false);
let sequence = 0;

export function beginOperation(
  title: string,
  scope: RequestScope,
  requestOnly = false,
) {
  const value: Operation = {
    sequence: ++sequence,
    title,
    scope: { target: scope.target, generation: nodeGeneration.value },
    taskId: "",
    submitting: true,
    requestOnly,
    error: "",
    uncertain: false,
    state: "queued",
  };
  currentOperation.value = value;
  operationVisible.value = true;
  return value.sequence;
}

export function acceptOperation(id: number, data: unknown) {
  const value = currentOperation.value;
  if (!value || value.sequence !== id) return;
  const result = data as { task_id?: unknown; id?: unknown } | null;
  const taskId = result?.task_id ?? result?.id;
  value.submitting = false;
  if (value.requestOnly) {
    value.state = "succeeded";
    return;
  }
  if (typeof taskId === "string" && /^[0-9a-f-]{36}$/.test(taskId)) {
    value.taskId = taskId;
  } else {
    value.error = "服务未返回任务编号，请在操作记录中确认执行结果。";
    value.uncertain = true;
  }
}

export function rejectOperation(id: number, error: string, uncertain: boolean) {
  const value = currentOperation.value;
  if (!value || value.sequence !== id) return;
  value.submitting = false;
  value.error = error;
  value.uncertain = uncertain;
}

export function inspectTask(taskId: string, title = "操作详情", local = false) {
  const id = beginOperation(title, {
    target: local ? null : selectedTarget.value,
    generation: nodeGeneration.value,
  });
  acceptOperation(id, { task_id: taskId });
}

watch(nodeGeneration, () => {
  currentOperation.value = null;
  operationVisible.value = false;
});
