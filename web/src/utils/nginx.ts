import type { Resource } from "../api/types";

export function siteName(item: Resource) {
  return (
    item.metadata.name ||
    item.fields.domains?.values[0] ||
    (item.kind === "http" ? "未命名网站" : "未命名端口转发")
  );
}
