import { useCallback, useEffect, useMemo, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { GraphEdge, GraphNode, GraphPayload } from "../types";
import {
  edgeColor,
  edgeWidth,
  nodeColor,
  nodeSize,
  particleCount,
  particleSpeed,
} from "../lib/styling";
import { edgeKey, ensureGraphIdentity } from "../lib/graph-state";

interface Props {
  graph: GraphPayload;
  focused: Set<string> | null;
  highlighted: Set<string>;
  selectedId: string | null;
  selectedEdgeKey: string | null;
  onSelect: (n: GraphNode | null) => void;
  onSelectEdge: (e: GraphEdge | null) => void;
  forwardRef: React.MutableRefObject<any>;
}

export function NetworkGraph({
  graph,
  focused,
  highlighted,
  selectedId,
  selectedEdgeKey,
  onSelect,
  onSelectEdge,
  forwardRef,
}: Props) {
  // Stable graph data identity — mutates the API payload in place to add
  // `id`/`source`/`target` aliases. Returns the same array references across
  // re-renders so the d3-force simulation keeps every node's accumulated x/y
  // /vx/vy. This is the core fix for "graph disappears after click/recenter".
  const data = useMemo(() => ensureGraphIdentity(graph), [graph]);

  // Set of edge keys incident to the selected node (for emphasis + label drawing).
  const incidentEdgeKeys = useMemo(() => {
    if (!selectedId) return new Set<string>();
    const s = new Set<string>();
    for (const e of graph.edges) {
      if (e.src_id === selectedId || e.dst_id === selectedId) s.add(edgeKey(e));
    }
    return s;
  }, [selectedId, graph]);

  // Has the simulation cooled and have we already auto-fit once? Ref because
  // we don't want this to trigger renders.
  const didInitialFit = useRef(false);

  // Pull stable refs to the d3 forces once on mount. Avoid re-applying on every
  // data change — re-applying force strength is what causes the "wake the
  // simulation up and risk NaN propagation" pattern documented in
  // react-force-graph#543 / force-graph#229.
  useEffect(() => {
    const fg = forwardRef.current;
    if (!fg) return;
    fg.d3Force("charge")?.strength(-180);
    fg.d3Force("link")?.distance(60);
    // Run once when the ref appears.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [forwardRef.current]);

  const handleNodeClick = useCallback((node: any) => onSelect(node), [onSelect]);

  const handleNodeDrag = useCallback((node: any) => {
    // d3-force-3d can pick up NaN/Infinity velocity if the mouse moves faster
    // than the frame budget; those NaNs propagate through the link spring
    // force on the next tick and blank the canvas. Clamp on every drag tick.
    if (!Number.isFinite(node.vx)) node.vx = 0;
    if (!Number.isFinite(node.vy)) node.vy = 0;
  }, []);

  const handleNodeDragEnd = useCallback((node: any) => {
    // Pin the node where dropped. Without this, residual velocity after
    // release can send the node and its neighbors off-canvas.
    if (Number.isFinite(node.x)) node.fx = node.x;
    if (Number.isFinite(node.y)) node.fy = node.y;
    node.vx = 0;
    node.vy = 0;
  }, []);

  const handleLinkClick = useCallback(
    (link: any) => {
      const e: GraphEdge = {
        ...link,
        src_id: link.src_id ?? (link.source?.id ?? link.source),
        dst_id: link.dst_id ?? (link.target?.id ?? link.target),
      };
      onSelectEdge(e);
    },
    [onSelectEdge],
  );

  const handleBackgroundClick = useCallback(() => {
    onSelect(null);
    onSelectEdge(null);
  }, [onSelect, onSelectEdge]);

  // Fired once when the d3 simulation has cooled. This is the documented
  // stable place to auto-fit the camera — it doesn't race the simulation
  // tick the way a click-handler-driven zoomToFit does. After the first
  // fire we ignore it (otherwise it keeps re-firing whenever the user
  // pans/zooms and the simulation gets reheated).
  const handleEngineStop = useCallback(() => {
    if (didInitialFit.current) return;
    if (!forwardRef.current) return;
    forwardRef.current.zoomToFit?.(600, 80);
    didInitialFit.current = true;
  }, [forwardRef]);

  // ----- Link/node visual callbacks. Each is useCallback'd with TIGHT deps
  // so ForceGraph2D sees stable callback identity until the inputs that
  // genuinely affect rendering change. ----------------------------------

  const linkColor = useCallback(
    (l: any) => {
      const e = l as GraphEdge;
      const src = l.source;
      const dst = l.target;
      if (!Number.isFinite(src?.x) || !Number.isFinite(dst?.x)) return "rgba(0,0,0,0)";
      const key = edgeKey({
        src_id: String(src.id ?? src),
        dst_id: String(dst.id ?? dst),
        edge_type: e.edge_type,
      });
      if (selectedEdgeKey && key === selectedEdgeKey) return "#FACC15";
      if (incidentEdgeKeys.has(key)) return edgeColorSafe(e);
      if (focused !== null) {
        const srcId = String(src.id ?? src);
        const dstId = String(dst.id ?? dst);
        if (!focused.has(srcId) && !focused.has(dstId)) return "rgba(140,140,140,0.18)";
        if (!focused.has(srcId) || !focused.has(dstId)) return "rgba(180,180,180,0.45)";
      }
      return edgeColorSafe(e);
    },
    [focused, incidentEdgeKeys, selectedEdgeKey],
  );

  const linkWidth = useCallback(
    (l: any) => {
      const e = l as GraphEdge;
      const src = l.source;
      const dst = l.target;
      if (!Number.isFinite(src?.x) || !Number.isFinite(dst?.x)) return 0;
      const key = edgeKey({
        src_id: String(src.id ?? src),
        dst_id: String(dst.id ?? dst),
        edge_type: e.edge_type,
      });
      if (selectedEdgeKey && key === selectedEdgeKey) return 3.5;
      if (incidentEdgeKeys.has(key)) return Math.max(1.6, edgeWidth(e) * 1.5);
      if (focused !== null) {
        const srcId = String(src.id ?? src);
        const dstId = String(dst.id ?? dst);
        if (!focused.has(srcId) && !focused.has(dstId)) return 0.4;
      }
      return edgeWidth(e);
    },
    [focused, incidentEdgeKeys, selectedEdgeKey],
  );

  const linkParticles = useCallback(
    (l: any) => {
      if (!Number.isFinite(l.source?.x) || !Number.isFinite(l.target?.x)) return 0;
      if (focused !== null) {
        const srcId = String(l.source?.id ?? l.source);
        const dstId = String(l.target?.id ?? l.target);
        if (!focused.has(srcId) || !focused.has(dstId)) return 0;
      }
      return particleCount(l as GraphEdge);
    },
    [focused],
  );

  const linkParticleSpeed = useCallback((l: any) => particleSpeed(l as GraphEdge), []);

  const linkCanvasObjectMode = useCallback(
    (l: any) => {
      const key = edgeKey({
        src_id: String(l.source?.id ?? l.source),
        dst_id: String(l.target?.id ?? l.target),
        edge_type: (l as GraphEdge).edge_type,
      });
      if (selectedEdgeKey === key || incidentEdgeKeys.has(key)) return "after";
      return undefined as unknown as string;
    },
    [incidentEdgeKeys, selectedEdgeKey],
  );

  const linkCanvasObject = useCallback((l: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const e = l as GraphEdge;
    const src = l.source;
    const dst = l.target;
    // Defense in depth — if either endpoint hasn't been positioned yet, skip
    // the label. force-graph#229 / #287 root-cause for "graph disappears".
    if (
      !src || !dst ||
      !Number.isFinite(src.x) || !Number.isFinite(src.y) ||
      !Number.isFinite(dst.x) || !Number.isFinite(dst.y)
    ) {
      return;
    }
    const mx = (src.x + dst.x) / 2;
    const my = (src.y + dst.y) / 2;
    const label = e.edge_type + (e.anomaly_label ? ` · ${e.anomaly_label}` : "");
    const fontSize = Math.max(6, 9 / globalScale);
    ctx.font = `${fontSize}px DM Mono, monospace`;
    const metrics = ctx.measureText(label);
    const padX = 3;
    const padY = 2;
    const w = metrics.width + padX * 2;
    const h = fontSize + padY * 2;
    ctx.fillStyle = "rgba(11, 32, 38, 0.9)";
    ctx.strokeStyle = "rgba(250, 204, 21, 0.8)";
    ctx.lineWidth = 1 / globalScale;
    ctx.beginPath();
    ctx.rect(mx - w / 2, my - h / 2, w, h);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = "#FACC15";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(label, mx, my);
  }, []);

  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as GraphNode;
      if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;
      const x = node.x;
      const y = node.y;
      const r = nodeSize(n);
      const color = nodeColor(n);
      const dimmed = focused !== null && !focused.has(n.node_id);
      const selected = selectedId === n.node_id;

      if (n.anomaly_score >= 0.5 && !dimmed) {
        const t = (Date.now() % 1500) / 1500;
        const glowR = r + 4 + Math.sin(t * Math.PI * 2) * 3;
        const grad = ctx.createRadialGradient(x, y, r, x, y, glowR);
        grad.addColorStop(0, color + "AA");
        grad.addColorStop(1, color + "00");
        ctx.beginPath();
        ctx.arc(x, y, glowR, 0, 2 * Math.PI);
        ctx.fillStyle = grad;
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(x, y, r, 0, 2 * Math.PI);
      ctx.fillStyle = dimmed ? color + "70" : color;
      ctx.fill();

      const isHighlighted = highlighted.has(n.node_id);
      if (selected) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2.5 / globalScale;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, 2 * Math.PI);
        ctx.strokeStyle = "rgba(255, 255, 255, 0.4)";
        ctx.lineWidth = 1.5 / globalScale;
        ctx.stroke();
      } else if (isHighlighted) {
        ctx.strokeStyle = "#FACC15";
        ctx.lineWidth = 2.5 / globalScale;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(x, y, r + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = "rgba(250, 204, 21, 0.45)";
        ctx.lineWidth = 1.5 / globalScale;
        ctx.stroke();
      }

      if (globalScale > 1.5 || n.anomaly_score >= 0.85 || selected) {
        ctx.font = `${Math.max(8, 10 / globalScale)}px DM Sans`;
        ctx.fillStyle = dimmed ? "#ffffff33" : "#ffffffcc";
        ctx.textAlign = "left";
        ctx.fillText(n.label, x + r + 2, y + 3);
      }
    },
    [focused, highlighted, selectedId],
  );

  const nodePointerAreaPaint = useCallback((node: any, color: string, ctx: CanvasRenderingContext2D) => {
    if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;
    const r = nodeSize(node) + 4;
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
    ctx.fillStyle = color;
    ctx.fill();
  }, []);

  const linkParticleColor = useCallback(
    (l: any) => ((l as GraphEdge).is_anomalous ? "#FF3621" : "rgba(255,255,255,0.7)"),
    [],
  );

  const linkParticleWidth = useCallback(
    (l: any) => ((l as GraphEdge).is_anomalous ? 4 : 2),
    [],
  );

  return (
    <ForceGraph2D
      ref={forwardRef}
      graphData={data as any}
      backgroundColor="rgba(0,0,0,0)"
      nodeRelSize={1}
      cooldownTicks={120}
      enableNodeDrag={true}
      onEngineStop={handleEngineStop}
      onNodeClick={handleNodeClick}
      onNodeDrag={handleNodeDrag}
      onNodeDragEnd={handleNodeDragEnd}
      onLinkClick={handleLinkClick}
      onBackgroundClick={handleBackgroundClick}
      linkColor={linkColor}
      linkWidth={linkWidth}
      linkDirectionalParticles={linkParticles}
      linkDirectionalParticleSpeed={linkParticleSpeed}
      linkDirectionalParticleWidth={linkParticleWidth}
      linkDirectionalParticleColor={linkParticleColor}
      linkCanvasObjectMode={linkCanvasObjectMode}
      linkCanvasObject={linkCanvasObject}
      nodeCanvasObject={nodeCanvasObject}
      nodePointerAreaPaint={nodePointerAreaPaint}
    />
  );
}

// Wrap the styling-layer edgeColor to never return undefined.
function edgeColorSafe(e: GraphEdge): string {
  const c = edgeColor(e);
  return c || "rgba(200, 200, 200, 0.35)";
}
