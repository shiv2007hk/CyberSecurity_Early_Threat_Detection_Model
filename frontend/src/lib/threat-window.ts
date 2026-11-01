import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, qs, type Paginated, type Threat } from "./api";

export type GeoMeta = { country?: string; code?: string; lat?: number; lon?: number };
export type ThreatIndicator = { type?: string; value?: string; geo?: GeoMeta };

export type GeoBucket = {
  country: string;
  code: string;
  lat: number;
  lon: number;
  count: number;
  maxRisk: number;
  categories: Array<{ name: string; count: number }>;
  sources: Array<{ name: string; count: number }>;
  threats: Threat[];
};

export function rangeDays(range: string) {
  const match = /^(\d+)d$/.exec(range);
  return match ? Math.max(1, Number(match[1])) : 90;
}

/* The threats endpoint caps a page at 100 rows. Two pages cover the seeded
   windows (and any range where the record count stays under 200); the UI states
   how many records each figure was computed from. */
export function useThreatWindow(range: string, category?: string) {
  const base = {
    range,
    size: 100,
    category: category && category !== "all" ? category : undefined,
    sort_by: "risk_score",
    order: "desc",
  };
  const first = useQuery({
    queryKey: ["threat-window", range, category || "all", 1],
    queryFn: () => api<Paginated<Threat>>(`/threats${qs({ ...base, page: 1 })}`),
  });
  const total = first.data?.total ?? 0;
  const second = useQuery({
    queryKey: ["threat-window", range, category || "all", 2],
    queryFn: () => api<Paginated<Threat>>(`/threats${qs({ ...base, page: 2 })}`),
    enabled: total > 100,
  });

  const items = useMemo(
    () => [...(first.data?.items || []), ...(second.data?.items || [])],
    [first.data, second.data],
  );

  return {
    items,
    total,
    facets: first.data?.facets || {},
    isLoading: first.isLoading || (total > 100 && second.isLoading),
    isError: first.isError || second.isError,
    error: first.error || second.error,
    refetch: first.refetch,
  };
}

export function threatsWithGeography(threats: Threat[]) {
  return threats.filter((threat) =>
    (threat.indicators as ThreatIndicator[] | undefined)?.some(
      (indicator) => indicator?.geo && Number.isFinite(indicator.geo.lat) && Number.isFinite(indicator.geo.lon),
    ),
  );
}

export function aggregateGeography(threats: Threat[]): GeoBucket[] {
  const buckets = new Map<string, GeoBucket & { threatRefs: Set<string>; categoryMap: Map<string, number>; sourceMap: Map<string, number> }>();

  threats.forEach((threat) => {
    (threat.indicators as ThreatIndicator[] | undefined)?.forEach((indicator) => {
      const geo = indicator?.geo;
      if (!geo?.country || !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon)) return;
      const code = geo.code || geo.country.slice(0, 2).toUpperCase();
      const bucket = buckets.get(code) || {
        country: geo.country,
        code,
        lat: geo.lat as number,
        lon: geo.lon as number,
        count: 0,
        maxRisk: 0,
        categories: [],
        sources: [],
        threats: [],
        threatRefs: new Set<string>(),
        categoryMap: new Map<string, number>(),
        sourceMap: new Map<string, number>(),
      };
      bucket.count += 1;
      bucket.maxRisk = Math.max(bucket.maxRisk, Number(threat.risk_score || 0));
      bucket.categoryMap.set(threat.category, (bucket.categoryMap.get(threat.category) || 0) + 1);
      bucket.sourceMap.set(threat.source, (bucket.sourceMap.get(threat.source) || 0) + 1);
      if (!bucket.threatRefs.has(threat.ref)) {
        bucket.threatRefs.add(threat.ref);
        bucket.threats.push(threat);
      }
      buckets.set(code, bucket);
    });
  });

  return [...buckets.values()]
    .map((bucket) => ({
      country: bucket.country,
      code: bucket.code,
      lat: bucket.lat,
      lon: bucket.lon,
      count: bucket.count,
      maxRisk: Math.round(bucket.maxRisk),
      categories: [...bucket.categoryMap.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count),
      sources: [...bucket.sourceMap.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count),
      threats: bucket.threats.sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0)),
    }))
    .sort((a, b) => b.count - a.count);
}

export function countTechniques(threats: Threat[]) {
  const counts = new Map<string, number>();
  threats.forEach((threat) => {
    (threat.indicators as ThreatIndicator[] | undefined)?.forEach((indicator) => {
      if (indicator?.type !== "mitre" || !indicator.value) return;
      counts.set(indicator.value, (counts.get(indicator.value) || 0) + 1);
    });
  });
  return [...counts.entries()]
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);
}

export function countBy(threats: Threat[], key: "category" | "source" | "severity" | "recommended_action") {
  const counts = new Map<string, number>();
  threats.forEach((threat) => {
    const label = threat[key];
    if (!label) return;
    counts.set(label, (counts.get(label) || 0) + 1);
  });
  // `value` is the key every chart binding reads; a `count` field rendered empty bars and donuts.
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

export function buildThreatTimeline(threats: Threat[], range: string) {
  const days = rangeDays(range);
  const bucketDays = days <= 30 ? 1 : days <= 90 ? 7 : days <= 180 ? 14 : 30;
  const end = new Date();
  end.setHours(0, 0, 0, 0);
  const start = new Date(end);
  start.setDate(start.getDate() - days + 1);
  const buckets: Array<{ start: Date; value: number }> = [];
  for (let cursor = new Date(start); cursor <= end; ) {
    buckets.push({ start: new Date(cursor), value: 0 });
    cursor = new Date(cursor);
    cursor.setDate(cursor.getDate() + bucketDays);
  }
  const dayMs = 86_400_000;
  threats.forEach((threat) => {
    const stamp = new Date(threat.published_at || threat.created_at || "");
    if (Number.isNaN(stamp.getTime())) return;
    const index = Math.floor((stamp.getTime() - start.getTime()) / dayMs / bucketDays);
    if (index >= 0 && index < buckets.length) buckets[index].value += 1;
  });
  return buckets.map((bucket) => ({
    start: bucket.start.toISOString(),
    value: bucket.value,
    bucketDays,
  }));
}
