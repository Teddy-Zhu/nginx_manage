<script setup lang="ts">
import { computed, ref } from "vue";
import { NButton } from "naive-ui";
const props = withDefaults(
  defineProps<{
    before: string;
    after: string;
    beforeLabel?: string;
    afterLabel?: string;
  }>(),
  { beforeLabel: "修改前", afterLabel: "修改后" },
);
const raw = ref(false);
interface Row {
  kind: "equal" | "removed" | "added" | "skip";
  old: number | null;
  next: number | null;
  text: string;
}
const lines = computed(() => {
  const a = props.before ? props.before.split("\n") : [],
    b = props.after ? props.after.split("\n") : [];
  if (a.length + b.length > 5000) return null;
  let prefix = 0,
    suffix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix])
    prefix++;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  )
    suffix++;
  const rows: Row[] = [];
  if (prefix > 3)
    rows.push({
      kind: "skip",
      old: null,
      next: null,
      text: `省略 ${prefix - 3} 行未变内容`,
    });
  for (let i = Math.max(0, prefix - 3); i < prefix; i++)
    rows.push({ kind: "equal", old: i + 1, next: i + 1, text: a[i] });
  const old = a.slice(prefix, a.length - suffix),
    next = b.slice(prefix, b.length - suffix);
  let i = 0,
    j = 0;
  const removed = () => {
    rows.push({
      kind: "removed",
      old: prefix + i + 1,
      next: null,
      text: old[i],
    });
    i++;
  };
  const added = () => {
    rows.push({
      kind: "added",
      old: null,
      next: prefix + j + 1,
      text: next[j],
    });
    j++;
  };
  if ((old.length + 1) * (next.length + 1) <= 500000) {
    const width = next.length + 1,
      table = new Uint16Array((old.length + 1) * width);
    for (let x = old.length - 1; x >= 0; x--)
      for (let y = next.length - 1; y >= 0; y--)
        table[x * width + y] =
          old[x] === next[y]
            ? table[(x + 1) * width + y + 1] + 1
            : Math.max(table[(x + 1) * width + y], table[x * width + y + 1]);
    while (i < old.length || j < next.length) {
      if (i < old.length && j < next.length && old[i] === next[j]) {
        rows.push({
          kind: "equal",
          old: prefix + i + 1,
          next: prefix + j + 1,
          text: old[i],
        });
        i++;
        j++;
      } else if (
        i < old.length &&
        (j === next.length ||
          table[(i + 1) * width + j] >= table[i * width + j + 1])
      )
        removed();
      else added();
    }
  } else {
    while (i < old.length) removed();
    while (j < next.length) added();
  }
  for (let k = 0; k < Math.min(3, suffix); k++)
    rows.push({
      kind: "equal",
      old: a.length - suffix + k + 1,
      next: b.length - suffix + k + 1,
      text: a[a.length - suffix + k],
    });
  if (suffix > 3)
    rows.push({
      kind: "skip",
      old: null,
      next: null,
      text: `省略 ${suffix - 3} 行未变内容`,
    });
  return rows;
});
</script>

<template>
  <div class="source-diff">
    <div class="diff-heading">
      <span>{{ beforeLabel }} → {{ afterLabel }}</span><n-button v-if="lines" size="small" @click="raw = !raw">
        {{
          raw ? "逐行差异" : "原文对照"
        }}
      </n-button>
    </div>
    <div v-if="raw || !lines" class="raw-columns">
      <div>
        <h4>{{ beforeLabel }}</h4>
        <pre>{{ before }}</pre>
      </div>
      <div>
        <h4>{{ afterLabel }}</h4>
        <pre>{{ after }}</pre>
      </div>
    </div>
    <div v-else class="line-diff" role="table" aria-label="原文逐行差异">
      <div
        v-for="(row, index) in lines"
        :key="index"
        class="diff-row"
        :class="row.kind"
        role="row"
      >
        <span class="line-number">{{ row.old ?? "" }}</span><span class="line-number">{{ row.next ?? "" }}</span><span class="diff-sign">{{
          row.kind === "removed" ? "−" : row.kind === "added" ? "+" : " "
        }}</span><span class="line-text">{{ row.text || " " }}</span>
      </div>
    </div>
    <p
      v-if="
        (before && !before.endsWith('\n')) || (after && !after.endsWith('\n'))
      "
      class="muted"
    >
      {{ before && !before.endsWith("\n") ? `${beforeLabel}末尾无换行。` : ""
      }}{{ after && !after.endsWith("\n") ? `${afterLabel}末尾无换行。` : "" }}
    </p>
  </div>
</template>

<style scoped>
.source-diff {
  border: 1px solid #dce5df;
  border-radius: 8px;
  overflow: hidden;
}
.diff-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 16px;
  background: #f3f6f5;
}
.line-diff {
  overflow: auto;
  max-height: 65vh;
  font: 12px/1.7 var(--mono, monospace);
}
.diff-row {
  display: flex;
  min-width: max-content;
}
.line-number {
  width: 52px;
  flex: none;
  box-sizing: border-box;
  padding: 0 8px;
  text-align: right;
  color: #7a8580;
  border-right: 1px solid #dce5df;
  user-select: none;
}
.diff-sign {
  width: 24px;
  text-align: center;
  flex: none;
}
.line-text {
  white-space: pre;
  padding-right: 16px;
}
.added {
  background: #e5f5eb;
}
.removed {
  background: #ffeded;
}
.skip {
  color: #73847a;
  background: #f4f7f5;
}
.raw-columns {
  display: grid;
  grid-template-columns: 1fr 1fr;
  max-height: 65vh;
  overflow: auto;
}
.raw-columns > div {
  min-width: 0;
  padding: 0 12px;
}
.raw-columns > div + div {
  border-left: 1px solid #dce5df;
}
.raw-columns pre {
  white-space: pre;
  overflow: auto;
  font: 12px/1.7 monospace;
}
.source-diff > p {
  margin: 8px 12px;
}
@media (max-width: 760px) {
  .raw-columns {
    grid-template-columns: 1fr;
  }
  .line-number {
    width: 42px;
  }
}
</style>
