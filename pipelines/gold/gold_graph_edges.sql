-- The knowledge-graph edge table.
-- Edge types: flow, resolves, hosts, in_subnet.
-- attrs is a VARIANT column carrying edge-specific properties (ports, protocols,
-- aggregate stats, anomaly evidence).
-- Cluster by (src_id, dst_id, edge_type) — the app filters neighbor lookups
-- by src_id OR dst_id, the graph payload sort filters by edge_type, and the
-- anomaly detectors join edges by (src_id, dst_id).
CREATE OR REFRESH MATERIALIZED VIEW gold_graph_edges (
  src_id        STRING    COMMENT 'Source node id (FK to gold_graph_nodes.node_id). For flow edges this is host:*. For resolves it is host:*. For hosts it is service:*. For in_subnet it is host:*.',
  dst_id        STRING    COMMENT 'Destination node id (FK). flow → host:* or ext:*. resolves → ext:*. hosts → host:*. in_subnet → subnet:*.',
  edge_type     STRING    COMMENT 'Relationship type: flow (network traffic), resolves (DNS lookup), hosts (service runs on host), in_subnet (host belongs to subnet).',
  packet_count  BIGINT    COMMENT 'Aggregated packet count for flow edges; query count for resolves; 0 for hosts/in_subnet.',
  byte_count    BIGINT    COMMENT 'Aggregated byte count for flow edges; 0 for non-flow edges.',
  flow_count    BIGINT    COMMENT 'Number of distinct flows/resolves represented by this aggregated edge.',
  is_cross_zone BOOLEAN   COMMENT 'True if the edge crosses security zones (e.g. corporate → iot).',
  is_anomalous  BOOLEAN   COMMENT 'True if this edge participates in any anomaly (driven by flow_anomaly_src/dst or suspicious DNS).',
  anomaly_label STRING    COMMENT 'Which anomaly type flagged this edge: port_scan | data_exfiltration | ddos | suspicious_dns.',
  anomaly_score DOUBLE    COMMENT 'Anomaly score 0-1 (max across applicable detectors).',
  last_seen_ts  TIMESTAMP COMMENT 'Most recent observation of this edge in the source data.',
  attrs         VARIANT   COMMENT 'Schema-less per-edge-type payload. flow: src_zone/dst_zone/is_cross_zone/byte_count/flow_count/distinct_dst_ports/distinct_protocols/avg_duration_ms/last_seen_ts. resolves: query_count/sample_queries/query_types/is_suspicious_tld. hosts: port/protocol/service_name. in_subnet: zone/cidr. Query with attrs:field::type.'
)
COMMENT 'Gold — the knowledge graph edge table. Aggregates flows, DNS resolutions, service-runs-on, and host-in-subnet relationships into one table. 32,734 rows on the current dataset.'
CLUSTER BY (src_id, dst_id, edge_type)
AS
WITH flow_anomaly_src AS (
  SELECT src_host_id AS host_id, MAX(score) AS score, 'port_scan' AS label
  FROM gold_anomaly_scan GROUP BY src_host_id
  UNION ALL
  SELECT src_host_id AS host_id, MAX(score) AS score, 'data_exfiltration' AS label
  FROM gold_anomaly_exfil GROUP BY src_host_id
),
flow_anomaly_dst AS (
  SELECT dst_host_id AS host_id, MAX(score) AS score, 'ddos' AS label
  FROM gold_anomaly_ddos GROUP BY dst_host_id
),
flow_agg AS (
  SELECT
    CONCAT('host:', src_host_id) AS src_id,
    CASE
      WHEN dst_host_id IS NOT NULL THEN CONCAT('host:', dst_host_id)
      ELSE CONCAT('ext:', dst_ip)
    END AS dst_id,
    src_host_id,
    dst_host_id,
    dst_ip,
    is_cross_zone,
    is_dst_external,
    MAX(src_zone) AS src_zone,
    MAX(dst_zone) AS dst_zone,
    SUM(packets) AS packet_count,
    SUM(bytes)   AS byte_count,
    COUNT(*)     AS flow_count,
    collect_set(dst_port) AS distinct_dst_ports,
    collect_set(protocol) AS distinct_protocols,
    AVG(duration_ms) AS avg_duration_ms,
    MAX(ts)      AS last_seen_ts
  FROM silver_flows
  WHERE src_host_id IS NOT NULL
  GROUP BY src_host_id, dst_host_id, dst_ip, is_cross_zone, is_dst_external
),
flow_edges AS (
  SELECT
    fa.src_id, fa.dst_id,
    'flow' AS edge_type,
    fa.packet_count, fa.byte_count, fa.flow_count,
    fa.is_cross_zone,
    CASE WHEN COALESCE(fas.score, 0.0) > 0 OR COALESCE(fad.score, 0.0) > 0 THEN TRUE ELSE FALSE END AS is_anomalous,
    COALESCE(fas.label, fad.label) AS anomaly_label,
    GREATEST(COALESCE(fas.score, 0.0), COALESCE(fad.score, 0.0)) AS anomaly_score,
    fa.last_seen_ts,
    parse_json(to_json(named_struct(
      'src_zone', fa.src_zone,
      'dst_zone', fa.dst_zone,
      'is_cross_zone', fa.is_cross_zone,
      'is_dst_external', fa.is_dst_external,
      'packet_count', fa.packet_count,
      'byte_count', fa.byte_count,
      'flow_count', fa.flow_count,
      'distinct_dst_ports', fa.distinct_dst_ports,
      'distinct_protocols', fa.distinct_protocols,
      'avg_duration_ms', CAST(fa.avg_duration_ms AS DOUBLE),
      'last_seen_ts', CAST(fa.last_seen_ts AS STRING)
    ))) AS attrs
  FROM flow_agg fa
  LEFT JOIN flow_anomaly_src fas ON fa.src_host_id = fas.host_id
  LEFT JOIN flow_anomaly_dst fad ON fa.dst_host_id = fad.host_id
),
dns_agg AS (
  SELECT
    src_host_id,
    resolved_ip,
    COUNT(*) AS query_count,
    MAX(CASE WHEN is_suspicious_tld THEN 1 ELSE 0 END) AS any_suspicious,
    collect_set(query_name) AS sample_queries,
    collect_set(query_type) AS query_types,
    MAX(ts) AS last_seen_ts
  FROM silver_dns
  WHERE resolved_ip IS NOT NULL
  GROUP BY src_host_id, resolved_ip
),
dns_edges AS (
  SELECT
    CONCAT('host:', d.src_host_id) AS src_id,
    CONCAT('ext:', d.resolved_ip) AS dst_id,
    'resolves' AS edge_type,
    d.query_count AS packet_count,
    CAST(0 AS BIGINT) AS byte_count,
    d.query_count AS flow_count,
    FALSE AS is_cross_zone,
    CAST(d.any_suspicious = 1 AS BOOLEAN) AS is_anomalous,
    CASE WHEN d.any_suspicious = 1 THEN 'suspicious_dns' ELSE CAST(NULL AS STRING) END AS anomaly_label,
    CASE WHEN d.any_suspicious = 1 THEN 0.7 ELSE 0.0 END AS anomaly_score,
    d.last_seen_ts,
    parse_json(to_json(named_struct(
      'query_count', d.query_count,
      'sample_queries', slice(d.sample_queries, 1, 5),
      'query_types', d.query_types,
      'is_suspicious_tld', d.any_suspicious = 1,
      'last_seen_ts', CAST(d.last_seen_ts AS STRING)
    ))) AS attrs
  FROM dns_agg d
),
service_edges AS (
  SELECT
    CONCAT('service:', svc.service_id) AS src_id,
    CONCAT('host:', svc.host_id) AS dst_id,
    'hosts' AS edge_type,
    CAST(0 AS BIGINT) AS packet_count,
    CAST(0 AS BIGINT) AS byte_count,
    1 AS flow_count,
    FALSE AS is_cross_zone,
    FALSE AS is_anomalous,
    CAST(NULL AS STRING) AS anomaly_label,
    0.0 AS anomaly_score,
    current_timestamp() AS last_seen_ts,
    parse_json(to_json(named_struct(
      'port', svc.port,
      'protocol', svc.protocol,
      'service_name', svc.service_name
    ))) AS attrs
  FROM silver_services svc
),
subnet_edges AS (
  SELECT
    CONCAT('host:', h.host_id) AS src_id,
    CONCAT('subnet:', h.subnet_id) AS dst_id,
    'in_subnet' AS edge_type,
    CAST(0 AS BIGINT) AS packet_count,
    CAST(0 AS BIGINT) AS byte_count,
    1 AS flow_count,
    FALSE AS is_cross_zone,
    FALSE AS is_anomalous,
    CAST(NULL AS STRING) AS anomaly_label,
    0.0 AS anomaly_score,
    current_timestamp() AS last_seen_ts,
    parse_json(to_json(named_struct(
      'zone', h.zone,
      'cidr', h.cidr
    ))) AS attrs
  FROM silver_hosts h
  WHERE h.subnet_id IS NOT NULL
)
SELECT * FROM flow_edges
UNION ALL SELECT * FROM dns_edges
UNION ALL SELECT * FROM service_edges
UNION ALL SELECT * FROM subnet_edges;
