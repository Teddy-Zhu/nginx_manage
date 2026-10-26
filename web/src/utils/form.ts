export const cleanList = (values: string[]) => values.map((value) => value.trim()).filter(Boolean);

export interface MappingRow { source: string; target: string }
export interface PortRange { from: number | null; to: number | null }
export function mappingRecord(rows: MappingRow[]): Record<string, string> {
  const entries = rows.filter((row) => row.source.trim() || row.target.trim());
  const result: Record<string, string> = Object.create(null);
  for (const row of entries) {
    const source = row.source.trim();
    if (!source) throw new Error("请填写映射的来源");
    if (Object.hasOwn(result, source)) throw new Error("映射的来源不能重复");
    result[source] = row.target.trim();
  }
  return result;
}

export function nginxArgs(text: string): string[] {
  const args: string[] = [];
  let value = "", quote = "", started = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    if (char === "\\") {
      if (++i === text.length) throw new Error("参数转义不完整");
      const escaped = text[i]!;
      value += escaped === "n" ? "\n" : escaped === "r" ? "\r" : escaped === "t" ? "\t" : /[\\'"]/.test(escaped) ? escaped : "\\" + escaped;
      started = true;
    } else if (quote) {
      if (char === quote) quote = "";
      else value += char;
    } else if (char === '"' || char === "'") {
      quote = char; started = true;
    } else if (/\s/.test(char)) {
      if (started) args.push(value);
      value = ""; started = false;
    } else {
      value += char; started = true;
    }
  }
  if (quote) throw new Error("参数引号不完整");
  if (started) args.push(value);
  return args;
}
export const nginxQuote = (value: string) => '"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';

export function dnsLocationLabel(target: string): string {
  if (!target) return "系统 DNS";
  const name = target.startsWith("networkd:") ? target.slice(9) : target.split("@").at(-1);
  return name ? `网卡 ${name}` : "网络连接";
}
