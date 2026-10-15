import { defineStore } from "pinia";
import { ref } from "vue";
import { api, setCSRF, cancelNodeRequests, type Me } from "../api/client";

export const useSession = defineStore("session", () => {
  const me = ref<Me | null>(null);
  const ready = ref(false);
  let restoring: Promise<void> | null = null;
  function set(value: Me) {
    me.value = value;
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
    cancelNodeRequests();
    me.value = null;
    ready.value = false;
    setCSRF("");
  }
  return { me, ready, restore, login, logout, clear };
});
