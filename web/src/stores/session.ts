import { setLiveSession } from "../api/live";
import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { api, setCSRF, type Me } from "../api/client";
import { resetAPIContext, selectedTarget } from "../api/context";

export const useSession = defineStore("session", () => {
  const localMe = ref<Me | null>(null);
  const me = computed(() => localMe.value && selectedTarget.value ? { ...localMe.value, scopes: localMe.value.scopes.filter((scope) => selectedTarget.value!.scopes.includes(scope)) } : localMe.value);
  const ready = ref(false);
  let restoring: Promise<void> | null = null;
  function set(value: Me) {
    localMe.value = value;
    setLiveSession(value.authenticated, value.scopes);
    setCSRF(value.csrf);
  }
  async function restore() {
    if (restoring) return restoring;
    restoring = api
      .me()
      .then(set)
      .finally(() => {
        ready.value = true;
        restoring = null;
      });
    return restoring;
  }
  async function login(username: string, password: string) {
    set(await api.login(username, password));
  }
  async function logout() {
    await api.logout();
    clear();
  }
  function clear() {
    setLiveSession(false);
    resetAPIContext();
    localMe.value = null;
    ready.value = false;
    setCSRF("");
  }
  return { me, localMe, ready, restore, login, logout, clear };
});
