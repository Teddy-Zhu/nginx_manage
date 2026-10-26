import type { FirewallRule } from "../api/client";
import { randomUUID } from "./crypto";

const defaultIDs = {
  tcp: "719bb978-3ccd-4b25-871c-e718290a6b84",
  udp: "5988974f-f193-461b-b85f-41f1210a8541",
};

export function unrestrictedPorts(rule: FirewallRule) {
  return rule.scope === "host_input" && rule.family === "both" &&
    !rule.interface && !rule.sources.length && rule.ports.length === 1 &&
    rule.ports[0]!.from === 1 && rule.ports[0]!.to === 65535;
}

export function defaultRule(rule: FirewallRule) {
  return unrestrictedPorts(rule) &&
    (rule.protocol === "tcp" && rule.id === defaultIDs.tcp ||
      rule.protocol === "udp" && rule.id === defaultIDs.udp);
}

export function orderRules(rules: FirewallRule[]) {
  if (rules.length > 1000) throw new Error("最多支持 1000 条规则，请先删除不再使用的规则");
  if (rules.some((rule) => rule.ports.length > 16))
    throw new Error("调整后的端口范围超过限制，请先合并相关端口规则");
  return [...rules.filter((rule) => !defaultRule(rule)), ...rules.filter(defaultRule)]
    .map((rule, index) => ({ ...rule, priority: index * 10 }));
}

function portRule(name: string, protocol: "tcp" | "udp", ports: number[]): FirewallRule {
  return {
    id: randomUUID(), name, enabled: true, scope: "host_input", family: "both",
    protocol, ports: ports.map((port) => ({ from: port, to: port })),
    sources: [], action: "allow", priority: 0, interface: "", comment: "", countries: [],
  };
}

export function accessMode(rules: FirewallRule[]) {
  const defaults = rules.filter((rule) => defaultRule(rule) && rule.enabled);
  if (defaults.length !== 2 || defaults[0]!.action !== defaults[1]!.action) return "custom";
  return defaults[0]!.action;
}

export function modeRules(rules: FirewallRule[], action: "allow" | "deny") {
  const defaults = (["tcp", "udp"] as const).map((protocol) => ({
    ...portRule(action === "allow" ? "默认放通其他端口" : "默认屏蔽其他端口", protocol, [1]),
    id: defaultIDs[protocol], action, ports: [{ from: 1, to: 65535 }],
  }));
  return orderRules([...rules.filter((rule) => !unrestrictedPorts(rule)), ...defaults]);
}

// Port shortcuts retain IP/region restrictions. Only unrestricted host TCP
// port selections are replaced; unrelated ports and Docker rules are retained.
export function allowPorts(rules: FirewallRule[], name: string, requested: number[]) {
  const ports = [...new Set(requested)].sort((a, b) => a - b);
  if (!ports.length || ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535))
    throw new Error("未读取到有效端口，请刷新后重试或手动添加规则");
  const remaining = rules.flatMap((rule) => {
    if (defaultRule(rule) || rule.scope !== "host_input" || rule.protocol !== "tcp" ||
      rule.interface || rule.sources.length || !rule.enabled) return [rule];
    let ranges = rule.ports;
    for (const port of ports) {
      ranges = ranges.flatMap((range) => {
        if (port < range.from || port > range.to) return [range];
        return [
          ...(port > range.from ? [{ from: range.from, to: port - 1 }] : []),
          ...(port < range.to ? [{ from: port + 1, to: range.to }] : []),
        ];
      });
    }
    return ranges.length ? [{ ...rule, ports: ranges }] : [];
  });
  // Separate ranges keep the rule valid when SSH has many listening ports.
  const added: FirewallRule[] = [];
  for (let start = 0; start < ports.length; start += 16)
    added.push(portRule(name, "tcp", ports.slice(start, start + 16)));
  return orderRules([...remaining, ...added]);
}
