import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AnomalyCounts, GraphEdge, GraphNode, GraphPayload } from "./types";
import { api } from "./lib/api";
import { buildAdjacency, computeFocusedIds } from "./lib/graph-state";
import { NetworkGraph } from "./components/NetworkGraph";
import { SearchBar } from "./components/SearchBar";
import { AnomalyPanel } from "./components/AnomalyPanel";
import { DetailDrawer } from "./components/DetailDrawer";
import { Legend } from "./components/Legend";
import { DataSources } from "./components/DataSources";

export function App() {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyCounts | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set());
  const [focusHops, setFocusHops] = useState<number>(1); // 0 = no focus
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [graphKey, setGraphKey] = useState<number>(0); // bumped to force a fresh mount
  const graphRef = useRef<any>(null);

  // Resizable side panels — widths persisted to localStorage
  const [sidebarWidth, setSidebarWidth] = useState<number>(() => {
    const v = parseInt(localStorage.getItem("sidebar_w") || "0", 10);
    return v > 0 ? v : 320;
  });
  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    const v = parseInt(localStorage.getItem("drawer_w") || "0", 10);
    return v > 0 ? v : 360;
  });
  useEffect(() => {
    localStorage.setItem("sidebar_w", String(sidebarWidth));
  }, [sidebarWidth]);
  useEffect(() => {
    localStorage.setItem("drawer_w", String(drawerWidth));
  }, [drawerWidth]);

  // Generic drag-resize handler for either the left or right handle.
  const startResize = (side: "left" | "right") => (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = side === "left" ? sidebarWidth : drawerWidth;
    const direction = side === "left" ? 1 : -1; // dragging right widens left pane, narrows right pane
    const onMove = (ev: MouseEvent) => {
      const delta = (ev.clientX - startX) * direction;
      const next = Math.min(700, Math.max(220, startWidth + delta));
      if (side === "left") setSidebarWidth(next);
      else setDrawerWidth(next);
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  };

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const [g, a] = await Promise.all([api.graph(2000), api.anomalies()]);
        if (!live) return;
        setGraph(g);
        setAnomalies(a);
        setLoading(false);
      } catch (e: any) {
        setError(String(e?.message || e));
        setLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  // Pure-functional adjacency + focus computation (also covered by vitest in
  // src/lib/graph-state.test.ts).
  const adjacency = useMemo(
    () => (graph ? buildAdjacency(graph.edges) : new Map<string, Set<string>>()),
    [graph],
  );
  const focusedIds = useMemo<Set<string> | null>(
    () => computeFocusedIds(adjacency, selected?.node_id ?? null, focusHops),
    [selected, focusHops, adjacency],
  );

  // Node click — DO NOT auto-zoom. Past versions called centerAt+zoom(2.5)
  // immediately after setSelected; those camera ops race the d3 simulation
  // tick and can leave the camera positioned away from any nodes (the
  // "graph disappears on click" symptom). Just select. The user can pan
  // manually if they want, and focus mode + the drawer already make the
  // selection visually obvious.
  const onSelect = useCallback((node: GraphNode | null) => {
    setSelected(node);
    if (node) setSelectedEdge(null);
  }, []);

  const onSelectEdge = useCallback((edge: GraphEdge | null) => {
    setSelectedEdge(edge);
    if (edge) setSelected(null);
  }, []);

  const onHighlight = useCallback((ids: string[]) => {
    setHighlighted(new Set(ids));
  }, []);

  // Dimming is ONLY driven by an explicit node selection + focus mode.
  // Highlights (from search / anomaly tiles) never dim anything — they only
  // add a visual ring/glow on top of the full graph so the user keeps their
  // mental map of the topology.
  const focusedSet: Set<string> | null = focusedIds;

  return (
    <div className="app">
      <aside className="sidebar" style={{ width: sidebarWidth }}>
        <div className="section">
          <h1>
            Network Anomaly Graph
            <small>Network-traffic knowledge graph on Databricks</small>
          </h1>
        </div>
        <div className="section">
          <h2>Search</h2>
          <SearchBar onPick={onSelect} onHighlight={onHighlight} />
          {error && <div className="banner-error">{error}</div>}
        </div>
        <div className="section" style={{ flex: 1 }}>
          <h2>Anomalies</h2>
          {anomalies ? (
            <AnomalyPanel
              data={anomalies}
              onPick={(id) => {
                const n = graph?.nodes.find((x) => x.node_id === id);
                if (n) onSelect(n);
                setHighlighted(new Set([id]));
              }}
              onHighlightType={(type) => {
                const ids = (anomalies.samples[type] || []).map((s) => s.node_id);
                setHighlighted(new Set(ids));
                // Clear selection so we don't enter aggressive focus mode on a
                // single (possibly isolated) anomaly node. User can click a
                // specific sample to focus on it.
                setSelected(null);
                // Re-fit so all highlighted nodes are visible
                setTimeout(() => {
                  if (graphRef.current) graphRef.current.zoomToFit(600, 80);
                }, 50);
              }}
            />
          ) : (
            <div className="result-row">loading…</div>
          )}
        </div>
        <div className="section">
          <h2>Data sources</h2>
          <DataSources />
        </div>
        <div className="section">
          <h2>Legend</h2>
          <Legend />
        </div>
      </aside>

      <div
        className="resize-handle"
        title="Drag to resize"
        onMouseDown={startResize("left")}
      />

      <main className="canvas">
        {loading && <div className="loading">Loading graph…</div>}
        {graph && (
          <NetworkGraph
            key={graphKey}
            graph={graph}
            focused={focusedSet}
            highlighted={highlighted}
            selectedId={selected?.node_id || null}
            selectedEdgeKey={
              selectedEdge
                ? `${selectedEdge.src_id}|${selectedEdge.dst_id}|${selectedEdge.edge_type}`
                : null
            }
            onSelect={onSelect}
            onSelectEdge={onSelectEdge}
            forwardRef={graphRef}
          />
        )}
        <div className="toolbar">
          <button
            className="ghost"
            title="Re-center the graph and fit all nodes in view"
            onClick={() => {
              // Single, idempotent call. Previous versions chained
              // d3ReheatSimulation + zoom(1) + centerAt(0,0) + setTimeout
              // zoomToFit — that 4-step sequence is what caused NaN
              // propagation through the simulation and the "graph
              // disappears" symptom (per react-force-graph#545 / #543 and
              // force-graph#229). zoomToFit is safe when called by itself.
              graphRef.current?.zoomToFit?.(600, 80);
            }}
          >
            ⌖ Re-center
          </button>
          <button
            className="ghost"
            title="Clear search highlights and selected node"
            onClick={() => {
              setHighlighted(new Set());
              setSelected(null);
              setSelectedEdge(null);
              setFocusHops(1);
            }}
          >
            ✕ Clear filters
          </button>
          <button
            className="ghost"
            title="Reset everything — clear filters, reload from the server, and rebuild the graph from scratch"
            onClick={async () => {
              setHighlighted(new Set());
              setSelected(null);
              setSelectedEdge(null);
              setFocusHops(1);
              try {
                const g = await api.graph(2000);
                setGraph(g);
                // Force a fresh remount of ForceGraph2D so the simulation
                // restarts cleanly with new node positions (drops any NaN
                // velocities the user may have introduced via dragging).
                setGraphKey((k) => k + 1);
              } catch (e: any) {
                setError(String(e?.message || e));
              }
            }}
          >
            ↻ Reset graph
          </button>
        </div>
        {selected && (
          <div className="focus-controls">
            <span className="focus-label">Focus on {selected.label}</span>
            <div className="focus-hop-group">
              {[1, 2, 3].map((h) => (
                <button
                  key={h}
                  className={"focus-hop" + (focusHops === h ? " active" : "")}
                  title={`Show node + ${h}-hop neighborhood`}
                  onClick={() => setFocusHops(h)}
                >
                  {h} hop{h > 1 ? "s" : ""}
                </button>
              ))}
              <button
                className={"focus-hop" + (focusHops === 0 ? " active" : "")}
                title="Show the entire graph"
                onClick={() => setFocusHops(0)}
              >
                All
              </button>
            </div>
          </div>
        )}
      </main>

      <div
        className="resize-handle"
        title="Drag to resize"
        onMouseDown={startResize("right")}
      />

      <aside className="drawer" style={{ width: drawerWidth }}>
        <div className="section">
          <h2>Detail</h2>
        </div>
        <DetailDrawer node={selected} edge={selectedEdge} />
      </aside>
    </div>
  );
}
