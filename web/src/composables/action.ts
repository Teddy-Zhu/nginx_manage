import { ref } from "vue";
import { useMessage } from "naive-ui";
import { ApiError } from "../api/client";

export function useAction() {
  const busy = ref(false);
  const message = useMessage();
  async function run<T>(
    action: () => Promise<T>,
    success?: string,
  ): Promise<T | undefined> {
    if (busy.value) return;
    busy.value = true;
    try {
      const result = await action();
      if (success) message.success(success);
      return result;
    } catch (error) {
      if (!(error instanceof ApiError && error.code === "CANCELLED"))
        message.error(error instanceof Error ? error.message : "操作失败");
    } finally {
      busy.value = false;
    }
  }
  return { busy, run, message };
}

export function useIdempotency() {
  let previous = "",
    key = "";
  return (payload: unknown) => {
    const digest = JSON.stringify(payload);
    if (digest !== previous || !key) {
      previous = digest;
      key = crypto.randomUUID();
    }
    return key;
  };
}
