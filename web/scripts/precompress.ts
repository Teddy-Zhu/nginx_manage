import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, extname, join, relative, sep } from "node:path";
import { gzipSync } from "node:zlib";
import type { Plugin } from "vite";

const compressible = new Set([
  ".html",
  ".js",
  ".mjs",
  ".css",
  ".svg",
  ".json",
  ".txt",
]);
const maximumSize = 8 * 1024 * 1024;

export function precompress(): Plugin {
  return {
    name: "precompress-frontend",
    apply: "build",
    async writeBundle({ dir }) {
      if (!dir)
        throw new Error("Missing output directory for frontend compression");
      for (const entry of await readdir(dir, {
        recursive: true,
        withFileTypes: true,
      })) {
        if (!entry.isFile() || !compressible.has(extname(entry.name))) continue;
        const file = join(entry.parentPath, entry.name);
        const name = relative(dir, file);
        if (name.startsWith("gzip" + sep)) continue;
        const size = (await stat(file)).size;
        if (size < 512 || size > maximumSize) continue;
        const compressed = gzipSync(await readFile(file));
        if (compressed.length >= size) continue;
        const output = join(dir, "gzip", name);
        await mkdir(dirname(output), { recursive: true });
        await writeFile(output, compressed);
      }
    },
  };
}
