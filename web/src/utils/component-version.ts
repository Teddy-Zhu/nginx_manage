// Semantic-version precedence, including prerelease identifiers. Build metadata
// does not affect whether selecting an installed component is a downgrade.
export function compareComponentVersions(a: string, b: string): number | null {
  const pattern =
    /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
  const left = pattern.exec(a),
    right = pattern.exec(b);
  if (!left || !right) return null;
  for (let i = 1; i <= 3; i++) {
    const x = BigInt(left[i]!),
      y = BigInt(right[i]!);
    if (x !== y) return x > y ? 1 : -1;
  }
  if (!left[4] || !right[4]) return left[4] === right[4] ? 0 : left[4] ? -1 : 1;
  const x = left[4].split("."),
    y = right[4].split(".");
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const u = x[i],
      v = y[i];
    if (u === v) continue;
    if (u === undefined) return -1;
    if (v === undefined) return 1;
    const un = /^\d+$/.test(u),
      vn = /^\d+$/.test(v);
    if (un && vn) {
      const m = BigInt(u),
        n = BigInt(v);
      if (m !== n) return m > n ? 1 : -1;
      continue;
    }
    if (un !== vn) return un ? -1 : 1;
    return u > v ? 1 : -1;
  }
  return 0;
}
