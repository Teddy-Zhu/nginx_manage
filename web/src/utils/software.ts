import type {
  ComponentOverview,
  Fail2banObservation,
  SoftwareCatalog,
} from "../api/client";

export function softwareCatalogEntries(catalog?: SoftwareCatalog) {
  return (catalog?.sources ?? []).flatMap((source) => {
    const installations = (catalog?.installed ?? []).filter(
      (item) => item.source_id === source.id,
    );
    const applications = [
      ...source.applications,
      ...installations
        .filter(
          (item) =>
            !source.applications.some((app) => app.id === item.application.id),
        )
        .map((item) => item.application),
    ];
    return applications.map((application) => ({
      source,
      application,
      installation: installations.find(
        (item) => item.application.id === application.id,
      ),
    }));
  });
}

export type SoftwareState =
  "installed" | "missing" | "unbound" | "recovery" | "unavailable";

export function nginxState(view: ComponentOverview | null): SoftwareState {
  if (!view || view.scope !== "host") return "unavailable";
  return view.installation ? "installed" : "missing";
}

export function fail2banState(view: Fail2banObservation | null): SoftwareState {
  if (!view?.available) return "unavailable";
  if (view.container) return view.container.installed ? "installed" : "missing";
  if (view.managed.state === "installed" || view.binding.state === "bound")
    return "installed";
  if (
    ["reserved", "ready", "interrupted", "rolling-back"].includes(
      view.managed.state,
    )
  )
    return "recovery";
  if (
    view.managed.state === "unavailable" ||
    view.binding.state !== "unbound" ||
    !view.tools.length ||
    view.tools.some((tool) => tool.present == null)
  )
    return "unavailable";
  return view.tools.some((tool) => tool.present) ? "unbound" : "missing";
}
