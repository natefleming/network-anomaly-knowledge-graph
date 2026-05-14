import type { AnomalyType } from "../types";

export interface AnomalyDef {
  label: string;
  shortDescription: string;
  thresholds: string[];
  whatToLookFor: string;
  sql: string;
  sqlFile: string;
}

export const ANOMALY_DEFS: Record<AnomalyType, AnomalyDef> = {
  port_scan: {
    label: "Port scan",
    shortDescription:
      "A single host fanning out to many destination hosts on many distinct ports in a short window — the classic signature of an Nmap-style reconnaissance scan.",
    thresholds: [
      "≥ 30 distinct destination hosts AND",
      "≥ 30 distinct destination ports AND",
      "within a single 10-minute tumbling window",
    ],
    whatToLookFor:
      "In the graph this shows up as a starburst — one red glowing node with edges radiating to dozens of distinct neighbors.",
    sqlFile: "pipelines/gold/gold_anomaly_scan.sql",
    sql: `CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_scan AS
SELECT
  CONCAT('host:', src_host_id) AS node_id,
  src_host_id,
  src_hostname,
  window.start AS window_start,
  window.end   AS window_end,
  COUNT(DISTINCT COALESCE(CAST(dst_host_id AS STRING), dst_ip)) AS distinct_dests,
  COUNT(DISTINCT dst_port) AS distinct_ports,
  COUNT(*) AS flow_count,
  'port_scan' AS anomaly_type,
  LEAST(1.0, COUNT(DISTINCT dst_port) / 200.0) AS score,
  to_json(...) AS evidence
FROM silver_flows
WHERE src_host_id IS NOT NULL
GROUP BY src_host_id, src_hostname, window(ts, '10 minutes')
HAVING COUNT(DISTINCT dst_port) >= 30
   AND COUNT(DISTINCT COALESCE(CAST(dst_host_id AS STRING), dst_ip)) >= 30;`,
  },

  lateral_movement: {
    label: "Lateral movement",
    shortDescription:
      "A multi-hop chain of cross-zone flows where each hop becomes the source of the next, crossing security zones an attacker would not normally traverse.",
    thresholds: [
      "≥ 3 sequential cross-zone hops (a→b→c→d)",
      "All hops within a single 15-minute window",
      "≥ 3 distinct zones visited across the chain",
    ],
    whatToLookFor:
      "A snake of red edges connecting nodes across different subnets — for example corporate → iot → dmz → corporate — that should never communicate directly.",
    sqlFile: "pipelines/gold/gold_anomaly_lateral.sql",
    sql: `-- Self-joins find chains where each edge dst becomes the next edge src
WITH cross_zone AS (
  SELECT flow_id, ts, src_host_id, dst_host_id, src_zone, dst_zone
  FROM silver_flows
  WHERE is_cross_zone = TRUE AND src_host_id IS NOT NULL AND dst_host_id IS NOT NULL
)
SELECT ...
FROM cross_zone a
JOIN cross_zone b ON a.dst_host_id = b.src_host_id
  AND b.ts BETWEEN a.ts AND a.ts + INTERVAL 15 MINUTES
JOIN cross_zone c ON b.dst_host_id = c.src_host_id
  AND c.ts BETWEEN b.ts AND a.ts + INTERVAL 15 MINUTES
WHERE size(array_distinct(array(a.src_zone, a.dst_zone, b.dst_zone, c.dst_zone))) >= 3;`,
  },

  data_exfiltration: {
    label: "Data exfiltration",
    shortDescription:
      "Large outbound flow from an internal host to a single external IP in a short window — the byte volume is dramatically asymmetric (lots out, little in).",
    thresholds: [
      "Outbound flow to an external destination IP",
      "Total bytes > 5 MB",
      "Within a 5-minute window per (source, external_ip) pair",
    ],
    whatToLookFor:
      "A thick red edge from one internal node to an external_ip node, with fast-moving animated packet particles flowing outward.",
    sqlFile: "pipelines/gold/gold_anomaly_exfil.sql",
    sql: `CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_exfil AS
SELECT
  CONCAT('host:', src_host_id) AS node_id,
  src_host_id, src_hostname, dst_ip AS external_dst_ip,
  window.start AS window_start, window.end AS window_end,
  SUM(bytes) AS total_bytes, COUNT(*) AS flow_count,
  'data_exfiltration' AS anomaly_type,
  LEAST(1.0, SUM(bytes) / 50000000.0) AS score
FROM silver_flows
WHERE is_dst_external = TRUE AND src_host_id IS NOT NULL
GROUP BY src_host_id, src_hostname, dst_ip, window(ts, '5 minutes')
HAVING SUM(bytes) > 5000000;`,
  },

  rogue_device: {
    label: "Rogue device",
    shortDescription:
      "An internal host that has zero traffic peers in the entire dataset AND makes DNS lookups to suspicious top-level domains. A real workstation makes hundreds of flows per day — silence + sketchy DNS is highly anomalous.",
    thresholds: [
      "Internal host (not external)",
      "flow_count = 0 across all observed traffic",
      "AND ≥ 1 DNS query to a flagged TLD (.xyz, .top, .tk, .click, .ru, .pw, .cc, .bid)",
    ],
    whatToLookFor:
      "Purple isolated nodes floating at the periphery of the graph — connected only by DNS resolves edges to external IPs.",
    sqlFile: "pipelines/gold/gold_anomaly_rogue.sql",
    sql: `WITH host_peer_counts AS (
  SELECT h.host_id, h.hostname,
    COALESCE(SUM(CASE WHEN f.src_host_id = h.host_id THEN 1 ELSE 0 END), 0)
    + COALESCE(SUM(CASE WHEN f.dst_host_id = h.host_id THEN 1 ELSE 0 END), 0) AS flow_count
  FROM silver_hosts h
  LEFT JOIN silver_flows f ON h.host_id IN (f.src_host_id, f.dst_host_id)
  WHERE h.is_external = FALSE
  GROUP BY h.host_id, h.hostname
),
suspicious_dns AS (
  SELECT src_host_id, COUNT(*) AS suspicious_query_count
  FROM silver_dns WHERE is_suspicious_tld = TRUE
  GROUP BY src_host_id
)
SELECT hpc.host_id, hpc.hostname, hpc.flow_count,
       COALESCE(sd.suspicious_query_count, 0) AS suspicious_query_count, ...
FROM host_peer_counts hpc
LEFT JOIN suspicious_dns sd ON hpc.host_id = sd.src_host_id
WHERE hpc.flow_count = 0 AND COALESCE(sd.suspicious_query_count, 0) > 0;`,
  },

  ddos: {
    label: "DDoS target",
    shortDescription:
      "A single internal host receiving traffic from a large number of distinct sources within a tight time window — the fan-in signature of a distributed denial-of-service.",
    thresholds: [
      "≥ 50 distinct source hosts hitting the same destination",
      "Within a single 5-minute tumbling window",
    ],
    whatToLookFor:
      "A visually overwhelmed node with dozens of edges fanning IN from every direction. Often the highest degree-centrality node in the graph.",
    sqlFile: "pipelines/gold/gold_anomaly_ddos.sql",
    sql: `CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_ddos AS
SELECT
  CONCAT('host:', dst_host_id) AS node_id,
  dst_host_id, dst_hostname,
  window.start AS window_start, window.end AS window_end,
  COUNT(DISTINCT src_host_id) AS distinct_sources,
  COUNT(*) AS flow_count,
  'ddos' AS anomaly_type,
  LEAST(1.0, COUNT(DISTINCT src_host_id) / 200.0) AS score
FROM silver_flows
WHERE dst_host_id IS NOT NULL
GROUP BY dst_host_id, dst_hostname, window(ts, '5 minutes')
HAVING COUNT(DISTINCT src_host_id) >= 50;`,
  },

  suspicious_dns: {
    label: "Suspicious DNS",
    shortDescription:
      "DNS resolution edge where the queried domain matches a flagged suspicious TLD list. Surfaced on edges, not nodes — anomalies live in the DNS-resolves relationships.",
    thresholds: [
      "Resolved domain ends in one of: .xyz, .top, .tk, .click, .ru, .pw, .cc, .bid",
    ],
    whatToLookFor:
      "Red DNS-edge from a host to an external_ip node, flagged inline on the edge attrs.",
    sqlFile: "pipelines/gold/gold_graph_edges.sql (DNS edges)",
    sql: `-- DNS edges are flagged inside gold_graph_edges.sql
SELECT
  CONCAT('host:', d.src_host_id) AS src_id,
  CONCAT('ext:', d.resolved_ip)  AS dst_id,
  'resolves' AS edge_type,
  COUNT(*) AS query_count,
  MAX(CASE WHEN d.is_suspicious_tld THEN TRUE ELSE FALSE END) AS is_anomalous,
  CASE WHEN MAX(CASE WHEN d.is_suspicious_tld THEN 1 ELSE 0 END) = 1
       THEN 'suspicious_dns' END AS anomaly_label,
  parse_json(to_json(named_struct(
    'sample_queries',  slice(collect_set(d.query_name), 1, 5),
    'is_suspicious_tld', MAX(d.is_suspicious_tld)
  ))) AS attrs
FROM silver_dns d
WHERE d.resolved_ip IS NOT NULL
GROUP BY d.src_host_id, d.resolved_ip;`,
  },
};
