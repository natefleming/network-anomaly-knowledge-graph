import { useEffect, useState } from "react";
import type { GraphEdge, GraphNode } from "../types";
import { api } from "../lib/api";
import { ANOMALY_LABELS } from "../lib/styling";

interface Props {
  node: GraphNode | null;
  edge: GraphEdge | null;
}

function fmtBytes(n: number | undefined | null): string {
  if (!n || n <= 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function parseAttrs(attrs: any): Record<string, any> {
  if (!attrs) return {};
  if (typeof attrs === "string") {
    try {
      return JSON.parse(attrs);
    } catch {
      return { raw: attrs };
    }
  }
  if (typeof attrs === "object") return attrs as Record<string, any>;
  return {};
}

function AttrsBlock({ attrs }: { attrs: any }) {
  const parsed = parseAttrs(attrs);
  const entries = Object.entries(parsed);
  if (!entries.length) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <div
        style={{
          fontSize: 9,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          color: "var(--text-muted)",
          marginBottom: 4,
        }}
      >
        VARIANT attrs
      </div>
      <dl className="kv">
        {entries.map(([k, v]) => (
          <FragmentRow key={k} k={k} v={v} />
        ))}
      </dl>
    </div>
  );
}

function FragmentRow({ k, v }: { k: string; v: any }) {
  let display: string;
  if (v === null || v === undefined) display = "—";
  else if (Array.isArray(v)) display = v.slice(0, 6).join(", ") + (v.length > 6 ? ` … (+${v.length - 6})` : "");
  else if (typeof v === "object") display = JSON.stringify(v);
  else display = String(v);
  return (
    <>
      <dt>{k}</dt>
      <dd>{display}</dd>
    </>
  );
}

export function DetailDrawer({ node, edge }: Props) {
  const [neighbors, setNeighbors] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!node) {
      setNeighbors([]);
      return;
    }
    let cancel = false;
    setLoading(true);
    (async () => {
      try {
        const r = await api.node(node.node_id);
        if (!cancel) setNeighbors(r.neighbors || []);
      } finally {
        if (!cancel) setLoading(false);
      }
    })();
    return () => {
      cancel = true;
    };
  }, [node]);

  // === Edge view ===
  if (edge) {
    const labels = [edge.anomaly_label].filter(Boolean) as string[];
    return (
      <div className="section detail">
        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>edge</div>
        <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4 }}>
          {edge.src_id} <span style={{ color: "var(--text-muted)" }}>→</span> {edge.dst_id}
        </div>
        <div style={{ marginTop: 8 }}>
          <span
            style={{
              display: "inline-block",
              fontFamily: "var(--font-mono, DM Mono, monospace)",
              fontSize: 10,
              background: "rgba(250, 204, 21, 0.15)",
              color: "#FACC15",
              padding: "2px 8px",
              borderRadius: 3,
              textTransform: "uppercase",
              letterSpacing: "0.05em",
            }}
          >
            {edge.edge_type}
          </span>
          {edge.is_anomalous && (
            <span
              style={{
                marginLeft: 6,
                display: "inline-block",
                fontFamily: "var(--font-mono, DM Mono, monospace)",
                fontSize: 10,
                background: "rgba(255, 54, 33, 0.15)",
                color: "var(--lava)",
                padding: "2px 8px",
                borderRadius: 3,
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              {edge.anomaly_label || "anomalous"}
            </span>
          )}
        </div>
        <dl className="kv">
          <dt>edge_type</dt>
          <dd>{edge.edge_type}</dd>
          <dt>src_id</dt>
          <dd>{edge.src_id}</dd>
          <dt>dst_id</dt>
          <dd>{edge.dst_id}</dd>
          <dt>packets</dt>
          <dd>{(edge.packet_count || 0).toLocaleString()}</dd>
          <dt>bytes</dt>
          <dd>{fmtBytes(edge.byte_count)}</dd>
          <dt>cross-zone</dt>
          <dd>{edge.is_cross_zone ? "yes" : "no"}</dd>
          <dt>anomaly</dt>
          <dd>{labels.length ? labels.map((l) => ANOMALY_LABELS[l] || l).join(", ") : "—"}</dd>
          <dt>anomaly_score</dt>
          <dd>{(edge.anomaly_score ?? 0).toFixed(2)}</dd>
          <dt>last_seen</dt>
          <dd>{edge.last_seen_ts || "—"}</dd>
        </dl>
        <AttrsBlock attrs={(edge as any).attrs} />
      </div>
    );
  }

  // === Node view ===
  if (!node) {
    return (
      <div className="section detail">
        <div style={{ color: "var(--text-muted)", fontSize: 12 }}>
          Click a node or edge to inspect.
        </div>
      </div>
    );
  }

  return (
    <div className="section detail">
      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{node.node_type}</div>
      <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4 }}>{node.label}</div>
      <div style={{ color: "var(--text-muted)", fontSize: 11 }}>{node.node_id}</div>
      <dl className="kv">
        <dt>Type</dt>
        <dd>{node.node_type}</dd>
        <dt>Host type</dt>
        <dd>{node.host_type ?? "—"}</dd>
        <dt>Subnet</dt>
        <dd>{node.subnet_id ?? "—"}</dd>
        <dt>External</dt>
        <dd>{node.is_external ? "yes" : "no"}</dd>
        <dt>Anomaly score</dt>
        <dd>{(node.anomaly_score ?? 0).toFixed(2)}</dd>
        <dt>Labels</dt>
        <dd>
          {(node.anomaly_labels || []).length === 0
            ? "—"
            : (node.anomaly_labels || []).map((l) => ANOMALY_LABELS[l] || l).join(", ")}
        </dd>
      </dl>
      <AttrsBlock attrs={(node as any).attrs} />
      <div className="neighbors">
        <div
          style={{
            fontSize: 11,
            textTransform: "uppercase",
            color: "var(--text-muted)",
            marginBottom: 6,
          }}
        >
          Edges {loading && "(loading…)"} {!loading && `(${neighbors.length})`}
        </div>
        {neighbors.map((e, i) => (
          <div className="neighbor" key={i}>
            <span>
              {e.src_id === node.node_id ? "→ " : "← "}
              {e.src_id === node.node_id ? e.dst_id : e.src_id}
            </span>
            <span style={{ color: e.is_anomalous ? "var(--lava)" : "inherit" }}>
              {e.edge_type}
              {e.byte_count > 0 ? ` · ${fmtBytes(e.byte_count)}` : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
