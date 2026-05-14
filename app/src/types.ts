export type AnomalyType =
  | "port_scan"
  | "lateral_movement"
  | "data_exfiltration"
  | "rogue_device"
  | "ddos"
  | "suspicious_dns";

export interface GraphNode {
  node_id: string;
  node_type: "host" | "subnet" | "service" | "external_ip";
  label: string;
  host_type: string | null;
  subnet_id: string | null;
  is_external: boolean;
  anomaly_score: number;
  anomaly_labels: AnomalyType[] | null;
  // augmented at render time
  id?: string;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface GraphEdge {
  src_id: string;
  dst_id: string;
  edge_type: "flow" | "resolves" | "hosts" | "in_subnet";
  packet_count: number;
  byte_count: number;
  is_cross_zone: boolean;
  is_anomalous: boolean;
  anomaly_label: AnomalyType | null;
  anomaly_score: number;
  last_seen_ts: string;
  // for force-graph
  source?: string | GraphNode;
  target?: string | GraphNode;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnomalyCounts {
  counts: { anomaly_type: AnomalyType; count: number }[];
  samples: Record<AnomalyType, { node_id: string; label: string; score: number }[]>;
}
