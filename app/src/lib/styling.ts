import type { GraphEdge, GraphNode } from "../types";

// Databricks brand colors
export const COLORS = {
  navy: "#1B3139",
  oat: "#F9F7F4",
  lava: "#FF3621",
  green: "#00A972",
  teal: "#1B5162",
  amber: "#FEAB03",
  indigo: "#4259FE",
  burgundy: "#970F29",
};

// Per the visual spec:
//   Blue  — normal workstation
//   Green — core servers / gateways
//   Yellow pulsing — elevated anomaly score
//   Red glowing  — confirmed anomalous
//   Purple — isolated rogue devices
export const NODE_COLOR = {
  normal: "#3B82F6", // blue
  server: "#00A972", // green
  warn: "#FACC15",   // yellow
  alert: "#EF4444",  // red
  rogue: "#A855F7",  // purple
  subnet: "#94A3B8", // gray
  external: "#64748B", // slate
  service: "#0EA5E9", // sky
};

export function nodeColor(n: GraphNode): string {
  const labels = n.anomaly_labels || [];
  if (labels.includes("rogue_device")) return NODE_COLOR.rogue;
  if (n.anomaly_score >= 0.85) return NODE_COLOR.alert;
  if (n.anomaly_score >= 0.5) return NODE_COLOR.warn;
  if (n.node_type === "subnet") return NODE_COLOR.subnet;
  if (n.node_type === "external_ip") return NODE_COLOR.external;
  if (n.node_type === "service") return NODE_COLOR.service;
  if (n.host_type === "server" || n.host_type === "gateway") return NODE_COLOR.server;
  return NODE_COLOR.normal;
}

export function nodeSize(n: GraphNode): number {
  const labels = n.anomaly_labels || [];
  if (labels.includes("rogue_device")) return 7;
  if (n.anomaly_score >= 0.85) return 9;
  if (n.anomaly_score >= 0.5) return 7;
  if (n.host_type === "server" || n.host_type === "gateway") return 6;
  if (n.node_type === "subnet") return 5;
  return 4.5;
}

export function edgeColor(e: GraphEdge): string {
  if (e.is_anomalous) return NODE_COLOR.alert;
  if (e.byte_count > 1_000_000) return "rgba(251, 146, 60, 0.7)"; // orange
  if (e.edge_type === "resolves") return "rgba(14, 165, 233, 0.35)";
  if (e.edge_type === "in_subnet") return "rgba(148, 163, 184, 0.25)";
  if (e.edge_type === "hosts") return "rgba(14, 165, 233, 0.25)";
  return "rgba(200, 200, 200, 0.35)";
}

export function edgeWidth(e: GraphEdge): number {
  if (e.is_anomalous) return 2.5;
  if (e.byte_count > 1_000_000) return 1.8;
  return 0.6;
}

export function particleCount(e: GraphEdge): number {
  if (e.is_anomalous) return 6;
  if (e.byte_count > 1_000_000) return 3;
  if (e.edge_type === "flow") return 1;
  return 0;
}

export function particleSpeed(e: GraphEdge): number {
  if (e.is_anomalous) return 0.02;
  if (e.byte_count > 1_000_000) return 0.01;
  return 0.005;
}

export const ANOMALY_LABELS: Record<string, string> = {
  port_scan: "Port scan",
  lateral_movement: "Lateral movement",
  data_exfiltration: "Data exfiltration",
  rogue_device: "Rogue device",
  ddos: "DDoS target",
  suspicious_dns: "Suspicious DNS",
};
