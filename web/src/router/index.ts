import { createRouter, createWebHistory } from "vue-router";
import { routes, handleHotUpdate } from "vue-router/auto-routes";
import { useSession } from "../stores/session";

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach(async (to) => {
  const session = useSession();
  if (!session.ready) {
    try {
      await session.restore();
    } catch {
      if (!to.meta.public) return "/login";
    }
  }
  if (!to.meta.public && !session.me?.authenticated) return "/login";
  if (to.path === "/login" && session.me?.authenticated) return "/";
});

window.addEventListener("session-expired", () => {
  useSession().clear();
  void router.push("/login");
});
if (import.meta.hot) handleHotUpdate(router);
export default router;
