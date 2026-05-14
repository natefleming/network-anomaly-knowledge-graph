import type { AnomalyCounts, GraphNode, GraphPayload } from "../types";

const BASE = ""; // same-origin

async function getJson<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`${path} → ${r.status} ${r.statusText}`);
  return r.json() as Promise<T>;
}

export const api = {
  health: () => getJson<{ status: string }>("/api/health"),
  graph: (limit = 2000) => getJson<GraphPayload>(`/api/graph?limit=${limit}`),
  search: (q: string) => getJson<GraphNode[]>(`/api/search?q=${encodeURIComponent(q)}`),
  anomalies: () => getJson<AnomalyCounts>("/api/anomalies"),
  node: (id: string) =>
    getJson<{ node: GraphNode; neighbors: any[] }>(
      `/api/node/${encodeURIComponent(id)}`,
    ),
};
