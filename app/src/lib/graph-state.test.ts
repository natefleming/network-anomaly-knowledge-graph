import { describe, expect, it } from "vitest";
import {
  buildAdjacency,
  computeFocusedIds,
  edgeKey,
  ensureGraphIdentity,
  parseAttrs,
} from "./graph-state";
import type { GraphEdge, GraphNode } from "../types";

// ---------- helpers --------------------------------------------------------

function n(id: string, opts: Partial<GraphNode> = {}): GraphNode {
  return {
    node_id: id,
    node_type: "host",
    label: id,
    host_type: "workstation",
    subnet_id: null,
    is_external: false,
    anomaly_score: 0,
    anomaly_labels: [],
    ...opts,
  };
}

function e(src: string, dst: string, type: GraphEdge["edge_type"] = "flow"): GraphEdge {
  return {
    src_id: src,
    dst_id: dst,
    edge_type: type,
    packet_count: 1,
    byte_count: 0,
    is_cross_zone: false,
    is_anomalous: false,
    anomaly_label: null,
    anomaly_score: 0,
    last_seen_ts: "",
  };
}

// ---------- buildAdjacency -------------------------------------------------

describe("buildAdjacency", () => {
  it("records both directions for each edge", () => {
    const adj = buildAdjacency([e("a", "b"), e("b", "c")]);
    expect(adj.get("a")).toEqual(new Set(["b"]));
    expect(adj.get("b")).toEqual(new Set(["a", "c"]));
    expect(adj.get("c")).toEqual(new Set(["b"]));
  });

  it("returns an empty map for no edges", () => {
    expect(buildAdjacency([]).size).toBe(0);
  });
});

// ---------- computeFocusedIds ----------------------------------------------

describe("computeFocusedIds", () => {
  // Graph:  a — b — c — d ;  x (isolated)
  const adj = buildAdjacency([e("a", "b"), e("b", "c"), e("c", "d")]);

  it("returns null when no node is selected", () => {
    expect(computeFocusedIds(adj, null, 1)).toBeNull();
  });

  it("returns null when hops is 0 (focus mode off)", () => {
    expect(computeFocusedIds(adj, "b", 0)).toBeNull();
  });

  it("1 hop returns the selected node + direct neighbors", () => {
    const s = computeFocusedIds(adj, "b", 1)!;
    expect(s).toEqual(new Set(["b", "a", "c"]));
  });

  it("2 hops widens the neighborhood", () => {
    const s = computeFocusedIds(adj, "a", 2)!;
    expect(s).toEqual(new Set(["a", "b", "c"]));
  });

  it("3 hops reaches the far side of the chain", () => {
    const s = computeFocusedIds(adj, "a", 3)!;
    expect(s).toEqual(new Set(["a", "b", "c", "d"]));
  });

  it("isolated selected node returns just itself — never an empty set", () => {
    // This is the regression test for "graph appears to disappear when an
    // isolated rogue device is selected": the visible set must always
    // contain at least the selected node.
    const s = computeFocusedIds(adj, "x", 2)!;
    expect(s).toEqual(new Set(["x"]));
    expect(s.size).toBeGreaterThan(0);
  });
});

// ---------- edgeKey --------------------------------------------------------

describe("edgeKey", () => {
  it("produces a stable composite identity", () => {
    expect(edgeKey({ src_id: "a", dst_id: "b", edge_type: "flow" })).toBe("a|b|flow");
  });

  it("treats reversed direction as a different edge", () => {
    expect(edgeKey({ src_id: "a", dst_id: "b", edge_type: "flow" })).not.toBe(
      edgeKey({ src_id: "b", dst_id: "a", edge_type: "flow" }),
    );
  });

  it("treats different edge_types as different edges between the same endpoints", () => {
    expect(edgeKey({ src_id: "a", dst_id: "b", edge_type: "flow" })).not.toBe(
      edgeKey({ src_id: "a", dst_id: "b", edge_type: "resolves" }),
    );
  });
});

// ---------- parseAttrs -----------------------------------------------------

describe("parseAttrs", () => {
  it("parses a JSON string into an object", () => {
    expect(parseAttrs('{"a":1,"b":"x"}')).toEqual({ a: 1, b: "x" });
  });

  it("returns dicts as-is", () => {
    const d = { a: 1 };
    expect(parseAttrs(d)).toBe(d);
  });

  it("returns {} for null and undefined", () => {
    expect(parseAttrs(null)).toEqual({});
    expect(parseAttrs(undefined)).toEqual({});
  });

  it("wraps malformed JSON in {raw} instead of throwing", () => {
    expect(parseAttrs("not-json")).toEqual({ raw: "not-json" });
  });

  it("wraps primitives in {raw}", () => {
    expect(parseAttrs(42)).toEqual({ raw: 42 });
  });
});

// ---------- ensureGraphIdentity -------------------------------------------

describe("ensureGraphIdentity", () => {
  it("augments nodes with `id` and edges with `source`/`target` in place", () => {
    const payload = {
      nodes: [n("a"), n("b")],
      edges: [e("a", "b")],
    };
    const result = ensureGraphIdentity(payload);
    // mutated in place
    expect((payload.nodes[0] as any).id).toBe("a");
    expect((payload.edges[0] as any).source).toBe("a");
    expect((payload.edges[0] as any).target).toBe("b");
    // same array identity returned
    expect(result.nodes).toBe(payload.nodes);
    expect(result.links).toBe(payload.edges);
  });

  it("is idempotent — repeated calls preserve identity", () => {
    const payload = { nodes: [n("a")], edges: [e("a", "a")] };
    const r1 = ensureGraphIdentity(payload);
    const r2 = ensureGraphIdentity(payload);
    expect(r1.nodes).toBe(r2.nodes);
    expect(r1.links).toBe(r2.links);
  });

  it("simulates d3-force stamping coords — those coords survive a re-call", () => {
    // This is the core invariant the bug-fix relies on: if d3 has set x/y/vx
    // /vy on the node, calling ensureGraphIdentity again must NOT clobber
    // them.
    const payload = { nodes: [n("a")], edges: [] };
    ensureGraphIdentity(payload);
    (payload.nodes[0] as any).x = 123;
    (payload.nodes[0] as any).y = 456;
    (payload.nodes[0] as any).vx = 0.1;
    (payload.nodes[0] as any).vy = -0.2;
    const after = ensureGraphIdentity(payload);
    const same = after.nodes[0] as any;
    expect(same.x).toBe(123);
    expect(same.y).toBe(456);
    expect(same.vx).toBe(0.1);
    expect(same.vy).toBe(-0.2);
  });
});
