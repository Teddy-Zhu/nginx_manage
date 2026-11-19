<script setup lang="ts">
import { computed, ref } from "vue";
import type { MonitoringHistory, MonitoringPoint } from "../api/client";
const props = defineProps<{
  history: MonitoringHistory | null;
  unit: string;
}>();
const selected = ref<number | null>(null);
const points = computed<MonitoringPoint[]>(() => {
  const history = props.history;
  if (!history?.points.length) return [];
  const minute = history.step_seconds;
  const minutes = (history.until - history.from) / minute + 1;
  const span = Math.ceil(minutes / 180);
  const intervals = Array.from(
    { length: Math.ceil(minutes / span) },
    (_, i) => ({
      at: history.from + i * span * minute,
      samples: 0,
      sum: 0,
      min: Infinity,
      max: -Infinity,
      seen: 0,
      gap: false,
    }),
  );
  for (const point of history.points) {
    const index = Math.floor((point.at - history.from) / (span * minute));
    const interval = intervals[index];
    if (
      !interval ||
      point.average === null ||
      point.minimum === null ||
      point.maximum === null
    )
      continue;
    interval.sum += point.average * point.count;
    interval.samples += point.count;
    interval.min = Math.min(interval.min, point.minimum);
    interval.max = Math.max(interval.max, point.maximum);
    interval.seen++;
    interval.gap ||= point.gap;
  }
  return intervals.map((interval, i) => ({
    at: interval.at,
    average: interval.samples ? interval.sum / interval.samples : null,
    minimum: interval.samples ? interval.min : null,
    maximum: interval.samples ? interval.max : null,
    count: interval.samples,
    gap: interval.gap || interval.seen < Math.min(span, minutes - i * span),
  }));
});
const ceiling = computed(() =>
  props.unit === "%"
    ? 100
    : Math.max(1, ...points.value.map((p) => p.maximum ?? 0)),
);
const x = (i: number) => 56 + (i / Math.max(1, points.value.length - 1)) * 860;
const y = (v: number) => 200 - (v / ceiling.value) * 176;
const samples = computed(() =>
  points.value.flatMap(({ average }, index) =>
    average === null ? [] : [{ average, index }],
  ),
);
const path = computed(() => {
  let line = "";
  let previousIndex = -1;
  for (const { average, index } of samples.value) {
    const horizontal = x(index);
    const vertical = y(average);
    if (previousIndex < 0) {
      line = `M${horizontal},${vertical}`;
    } else if (index > previousIndex + 1) {
      line += ` H${horizontal} V${vertical}`;
    } else {
      line += ` L${horizontal},${vertical}`;
    }
    previousIndex = index;
  }
  const lastIndex = points.value.length - 1;
  if (line && previousIndex < lastIndex) line += ` H${x(lastIndex)}`;
  return line;
});
const active = computed(() =>
  selected.value === null ? undefined : points.value[selected.value],
);
function sampleStatus(point: MonitoringPoint, index: number) {
  if (point.average !== null) return point.gap ? "采样不完整" : "";
  return index > (samples.value[0]?.index ?? index)
    ? "沿用上次采样值"
    : "暂无采样";
}
const format = (v: number | null | undefined) =>
  v === null || v === undefined
    ? "—"
    : v.toLocaleString(undefined, { maximumFractionDigits: 2 });
const time = (p: MonitoringPoint | undefined) =>
  p ? new Date(p.at * 1000).toLocaleString() : "";
</script>

<template>
  <div class="metric-trend">
    <svg
      v-if="path"
      viewBox="0 0 940 244"
      role="img"
      :aria-label="`资源趋势，单位 ${unit}`"
    >
      <g v-for="fraction in [0, 0.5, 1]" :key="fraction" class="grid">
        <line
          x1="56"
          x2="916"
          :y1="y(fraction * ceiling)"
          :y2="y(fraction * ceiling)"
        />
        <text x="48" :y="y(fraction * ceiling) + 4" text-anchor="end">
          {{ format(fraction * ceiling) }}
        </text>
      </g>
      <path :d="path" class="trend-line" />
      <circle
        v-for="sample in samples"
        :key="sample.index"
        :cx="x(sample.index)"
        :cy="y(sample.average)"
        r="2.5"
        class="trend-dot"
      />
      <rect
        v-for="(point, i) in points"
        :key="point.at"
        :x="x(i) - Math.max(2, 430 / Math.max(points.length, 1))"
        y="16"
        :width="Math.max(4, 860 / Math.max(points.length, 1))"
        height="190"
        fill="transparent"
        tabindex="0"
        :aria-label="
          [
            time(point),
            point.average === null ? '' : `${format(point.average)} ${unit}`,
            sampleStatus(point, i),
          ].filter(Boolean).join('，')
        "
        @mouseenter="selected = i"
        @focus="selected = i"
        @mouseleave="selected = null"
        @blur="selected = null"
      />
      <text x="56" y="230">
        {{
          points[0] ? new Date(points[0].at * 1000).toLocaleTimeString() : ""
        }}
      </text>
      <text x="916" y="230" text-anchor="end">
        {{
          points.at(-1)
            ? new Date(points.at(-1)!.at * 1000).toLocaleTimeString()
            : ""
        }}
      </text>
    </svg>
    <div v-else class="trend-empty">
      所选时段暂无有效样本
    </div>
    <div class="muted trend-detail" aria-live="polite">
      <template v-if="active && selected !== null">
        {{ time(active) }}
        <template v-if="active.average !== null">
          · 均值 {{ format(active.average) }} {{ unit }} · 最小
          {{ format(active.minimum) }} · 最大 {{ format(active.maximum) }} ·
          {{ active.count }} 个样本
        </template>
        <template v-if="active.gap">
          · {{ sampleStatus(active, selected) }}
        </template>
      </template>
    </div>
  </div>
</template>

<style scoped>
svg {
  width: 100%;
  min-height: 180px;
  display: block;
}
.grid line {
  stroke: var(--border, #ddd);
  stroke-dasharray: 3 5;
}
text {
  fill: currentColor;
  font-size: 11px;
  opacity: 0.65;
}
.trend-line {
  fill: none;
  stroke: #378a70;
  stroke-width: 2;
}
.trend-dot {
  fill: #378a70;
}
.trend-empty {
  min-height: 200px;
  display: grid;
  place-items: center;
  color: var(--text-muted, #777);
}
.trend-detail {
  min-height: 24px;
  font-size: 12px;
}
</style>
