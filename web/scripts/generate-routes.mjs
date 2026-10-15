import { createRoutesContext, resolveOptions } from "vue-router/unplugin";
import { routeOptions } from "../routing.config.ts";

const context = createRoutesContext(resolveOptions(routeOptions));
await context.scanPages(false);
context.writeConfigFiles();
context.stopWatcher();
