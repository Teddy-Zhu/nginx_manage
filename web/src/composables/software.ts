import { computed, onMounted, ref, watch } from "vue";
import {
  useNodeAPI,
  type ComponentTask,
  type SoftwareRequest,
} from "../api/client";
import { useAction } from "./action";
import { useLiveRefresh } from "./live";
import { useSession } from "../stores/session";
import { inspectTask } from "../stores/operation";
import { randomUUID } from "../utils/crypto";
export function useSoftwareOperations(changed: () => Promise<void> | void) {
  const api = useNodeAPI(),
    session = useSession(),
    { run, busy, message } = useAction();
  const reading = ref(false);
  const tasks = ref<ComponentTask[]>([]),
    lastID = ref("");
  const permitted = computed(() =>
    ["components.manage", "system.write", "security.write"].every((s) =>
      session.me?.scopes.includes(s),
    ),
  );
  const active = computed(() =>
    tasks.value.some(
      (t) =>
        ["queued", "running", "recovery_required"].includes(t.state) &&
        t.stage !== "restore_isolated",
    ),
  );
  const last = computed(() => tasks.value.find((t) => t.id === lastID.value));
  async function refresh() {
    if (reading.value || !session.me?.scopes.includes("components.manage")) return;
    reading.value = true;
    try {
      tasks.value = await api.componentTasks();
    } catch (error) {
      message.error(
        error instanceof Error ? error.message : "无法读取操作状态",
      );
    } finally {
      reading.value = false;
    }
  }
  async function submit(request: SoftwareRequest, title: string) {
    return await run(async () => {
      const input = {
        action: "software" as const,
        tag: "",
        prerelease: false,
        plan_id: "",
        manifest_sha256: "",
        trust_sha256: "",
        software: request,
      };
      const task = await api.createComponentTask({ input }, randomUUID());
      lastID.value = task.id;
      tasks.value = [task, ...tasks.value.filter((t) => t.id !== task.id)];
      inspectTask(task.id, title);
      return true;
    });
  }
  watch(
    () => last.value?.state,
    (state, old) => {
      if (state && state !== old && ["succeeded", "failed"].includes(state))
        void changed();
    },
  );
  useLiveRefresh(api, ["tasks"], refresh, () => reading.value);
  onMounted(refresh);
  return { api, run, busy, permitted, active, last, submit, refresh };
}
