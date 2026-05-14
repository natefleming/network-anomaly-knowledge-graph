// Pure, testable helpers for the graph viewer.
//
// These functions are intentionally framework-agnostic — they take plain objects
// in and return plain objects out — so they can be unit-tested with vitest
// without needing to mount React or a canvas. The state math they encode
// (focus neighborhoods, attribute parsing, edge identity) is what drives what
// the user sees, so a regression that would shrink the visible set to nothing
// surfaces here in CI before it reaches the browser.

import type { GraphEdge, GraphNode } from "../types";

/**
 * Build an undirected adjacency map from a list of edges.
 *
 * Used by `computeFocusedIds` to walk the N-hop neighborhood of a selected
 * node. Both directions are recorded so focus mode is symmetric — selecting
 * either endpoint of an edge will include the other.
 */
export function buildAdjacency(edges: Pick<GraphEdge, "src_id" | "dst_id">[]): Map<string, Set<string>> {
  const m = new Map<string, Set<string>>();
  for (const e of edges) {
    if (!m.has(e.src_id)) m.set(e.src_id, new Set());
    if (!m.has(e.dst_id)) m.set(e.dst_id, new Set());
    m.get(e.src_id)!.add(e.dst_id);
    m.get(e.dst_id)!.add(e.src_id);
  }
  return m;
}

/**
 * BFS `hops` levels out from `selectedId`. Returns the set of node ids that
 * should remain at full opacity in the viewer.
 *
 * Returns `null` when there's no selection or focus is off (caller treats null
 * as "no dimming"). When the selected node is isolated (no edges in the
 * adjacency map), the returned set is `{selectedId}` — the selection is still
 * visible.
 */
export function computeFocusedIds(
  adjacency: Map<string, Set<string>>,
  selectedId: string | null,
  hops: number,
): Set<string> | null {
  if (!selectedId || hops <= 0) return null;
  const reach = new Set<string>([selectedId]);
  let frontier: string[] = [selectedId];
  for (let h = 0; h < hops; h++) {
    const next: string[] = [];
    for (const id of frontier) {
      const neigh = adjacency.get(id);
      if (!neigh) continue;
      for (const n of neigh) {
        if (!reach.has(n)) {
          reach.add(n);
          next.push(n);
        }
      }
    }
    frontier = next;
    if (!frontier.length) break;
  }
  return reach;
}

/**
 * Stable composite key for an edge — used to mark incident edges around a
 * selected node and to identify the currently-clicked edge for the drawer.
 */
export function edgeKey(e: { src_id: string; dst_id: string; edge_type: string }): string {
  return `${e.src_id}|${e.dst_id}|${e.edge_type}`;
}

/**
 * Tolerant VARIANT-attrs parser. The databricks-sql-connector returns the
 * VARIANT column as a JSON string; from the API it can arrive as a string OR
 * already-parsed object depending on Pydantic/FastAPI serialization. Be
 * defensive.
 */
export function parseAttrs(value: unknown): Record<string, unknown> {
  if (value == null) return {};
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : { raw: value };
    } catch {
      return { raw: value };
    }
  }
  if (typeof value === "object") return value as Record<string, unknown>;
  return { raw: value };
}

/**
 * Stable graph-data identity for ForceGraph2D.
 *
 * This is the core fix for the "graph disappears" bug. d3-force-3d stamps
 * `x`, `y`, `vx`, `vy` onto each node object during the simulation. If we
 * pass it a freshly-spread copy on every render (the obvious `useMemo` over
 * `graph.nodes.map(n => ({...n, id: n.node_id}))` pattern), those coords get
 * lost every render — the simulation has to re-lay-out from scratch, and
 * during that brief re-layout the nodes have undefined or NaN coords and the
 * canvas appears blank.
 *
 * Instead we mutate the API payload objects in place: add the `id`/`source`/
 * `target` aliases d3-force expects, and return references to the same arrays
 * the API returned. On subsequent re-renders the node objects are the same
 * references — d3 keeps its layout, and the canvas keeps drawing.
 *
 * We use a WeakSet to track which payloads we've already augmented so we
 * never write the alias twice (which would no-op anyway, but it avoids any
 * surprise when the payload contains a node that already had `id` set).
 */
const augmented = new WeakSet<object>();
export interface ForceGraphData<N, L> {
  nodes: N[];
  links: L[];
}
export function ensureGraphIdentity(payload: {
  nodes: GraphNode[];
  edges: GraphEdge[];
}): ForceGraphData<GraphNode, GraphEdge> {
  if (!augmented.has(payload.nodes)) {
    for (const n of payload.nodes) {
      // Force-graph reads `node.id`; we use node_id everywhere else.
      (n as GraphNode & { id?: string }).id = n.node_id;
    }
    augmented.add(payload.nodes);
  }
  if (!augmented.has(payload.edges)) {
    for (const e of payload.edges) {
      // Force-graph reads `link.source` / `link.target`; we use src_id/dst_id.
      (e as GraphEdge & { source?: string; target?: string }).source = e.src_id;
      (e as GraphEdge & { source?: string; target?: string }).target = e.dst_id;
    }
    augmented.add(payload.edges);
  }
  // We return the same arrays — same identity — so React.memo / ForceGraph2D
  // internals see "no change" across re-renders.
  return { nodes: payload.nodes, links: payload.edges as unknown as GraphEdge[] };
}
