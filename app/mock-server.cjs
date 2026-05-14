// Tiny mock backend that returns a tractable graph payload so we can debug
// the React rendering layer offline. Run with `node mock-server.cjs` while
// `npm run dev` is also running — vite will proxy /api/* to this server.
const http = require("http");

// Deterministic-ish small graph: 60 nodes, 120 edges, with 3 "anomalous"
// nodes so we exercise the same paint paths the live data does.
const NODE_COUNT = 60;
const nodes = [];
for (let i = 0; i < NODE_COUNT; i++) {
  const isAnomalous = i % 19 === 0;
  const isRogue = i === 7;
  const hostType = i % 12 === 0 ? "server" : i % 17 === 0 ? "gateway" : "workstation";
  nodes.push({
    node_id: `host:H-${String(i).padStart(4, "0")}`,
    node_type: "host",
    label: `host-${i}`,
    host_type: hostType,
    subnet_id: `SUB-${i % 6}`,
    is_external: false,
    anomaly_score: isAnomalous ? 0.95 : isRogue ? 0.95 : 0,
    anomaly_labels: isRogue ? ["rogue_device"] : isAnomalous ? ["port_scan"] : [],
    attrs: JSON.stringify({ host_type: hostType, zone: "corporate" }),
  });
}
const edges = [];
for (let i = 0; i < NODE_COUNT; i++) {
  // Ring + chord pattern so the graph is connected and visually interesting
  const next = (i + 1) % NODE_COUNT;
  const chord = (i + 7) % NODE_COUNT;
  edges.push(makeFlow(`host:H-${pad(i)}`, `host:H-${pad(next)}`));
  edges.push(makeFlow(`host:H-${pad(i)}`, `host:H-${pad(chord)}`));
}
function pad(n) { return String(n).padStart(4, "0"); }
function makeFlow(src, dst) {
  return {
    src_id: src,
    dst_id: dst,
    edge_type: "flow",
    packet_count: 100,
    byte_count: 5000,
    is_cross_zone: false,
    is_anomalous: src.endsWith("0019"),
    anomaly_label: src.endsWith("0019") ? "port_scan" : null,
    anomaly_score: src.endsWith("0019") ? 0.95 : 0,
    last_seen_ts: "2026-05-13T00:00:00Z",
    attrs: JSON.stringify({ src_zone: "corporate", dst_zone: "corporate", byte_count: 5000, flow_count: 1 }),
  };
}

const routes = {
  "/api/health": () => ({ status: "ok", catalog: "mock", schema: "network_anomaly_graph" }),
  "/api/graph": () => ({ nodes, edges }),
  "/api/anomalies": () => ({
    counts: [
      { anomaly_type: "port_scan", count: 1 },
      { anomaly_type: "rogue_device", count: 1 },
    ],
    samples: {
      port_scan: [{ node_id: "host:H-0019", label: "host-19", score: 0.95 }],
      rogue_device: [{ node_id: "host:H-0007", label: "host-7", score: 0.95 }],
    },
  }),
  "/api/datasources": () => ({
    workspace_url: "https://mock",
    catalog: "mock",
    schema: "network_anomaly_graph",
    tables: [
      { name: "gold_graph_nodes", fqn: "mock.network_anomaly_graph.gold_graph_nodes", layer: "gold", kind: "MV", description: "mock", explorer_url: "https://mock" },
    ],
  }),
};

http.createServer((req, res) => {
  const path = req.url.split("?")[0];
  const handler = routes[path];
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  if (path === "/api/search") {
    res.end("[]");
    return;
  }
  if (path.startsWith("/api/node/")) {
    res.end(JSON.stringify({ node: nodes[0], neighbors: [] }));
    return;
  }
  if (!handler) { res.statusCode = 404; res.end("not found"); return; }
  res.end(JSON.stringify(handler()));
}).listen(8000, () => console.log("mock api on :8000"));
