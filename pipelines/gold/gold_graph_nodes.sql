-- The knowledge-graph node table.
-- attrs is a VARIANT column so each node type can carry a different attribute payload
-- and downstream queries can use the `attrs:field::type` operator to extract values.
-- Cluster by (node_id, node_type) — the app's /api/node/{id} endpoint and
-- /api/graph filter on node_id directly, and many queries filter by node_type.
CREATE OR REFRESH MATERIALIZED VIEW gold_graph_nodes (
  node_id        STRING         COMMENT 'Typed primary key: host:H-NNNN, subnet:SUB-NNN, service:SVC-NNNN, ext:<ip>. Used as both PK and FK target on gold_graph_edges.',
  node_type      STRING         COMMENT 'Node category: host | subnet | service | external_ip.',
  label          STRING         COMMENT 'Display label — hostname for hosts, CIDR for subnets, service_name for services, IP for external_ip.',
  attrs          VARIANT        COMMENT 'Schema-less per-type attribute payload. host: ip/host_type/os/owner/criticality/zone/cidr/last_active_ts/flow_total. subnet: cidr/zone/description. service: host_id/port/protocol/service_name. external_ip: ip/total_bytes/flow_count/distinct_internal_callers/last_seen_ts. Query with attrs:field::type.',
  criticality   INT             COMMENT 'Business criticality 1-5 — host nodes only, NULL otherwise.',
  subnet_id      STRING         COMMENT 'Subnet membership — host and subnet nodes only.',
  is_external    BOOLEAN        COMMENT 'True for external_ip nodes and external-zone subnets.',
  host_type      STRING         COMMENT 'Type indicator: workstation | server | gateway | iot | subnet | service | external.',
  anomaly_score  DOUBLE         COMMENT 'Maximum score (0-1) across all anomaly detector MVs that flagged this node.',
  anomaly_labels ARRAY<STRING>  COMMENT 'Anomaly types that flagged this node: any of port_scan, lateral_movement, data_exfiltration, rogue_device, ddos.'
)
COMMENT 'Gold — the knowledge graph node table. Unions hosts, subnets, services, and observed external IPs into one typed entity table. 5,397 rows on the current dataset. Powers the Databricks App graph visualization and all downstream graph analytics.'
CLUSTER BY (node_id, node_type)
AS
WITH host_anomalies AS (
  SELECT node_id, MAX(score) AS score, collect_set(anomaly_type) AS labels FROM (
    SELECT node_id, score, anomaly_type FROM gold_anomaly_scan
    UNION ALL SELECT node_id, score, anomaly_type FROM gold_anomaly_exfil
    UNION ALL SELECT node_id, score, anomaly_type FROM gold_anomaly_ddos
    UNION ALL SELECT node_id, score, anomaly_type FROM gold_anomaly_rogue
    UNION ALL SELECT node_id, score, anomaly_type FROM gold_anomaly_lateral
  )
  GROUP BY node_id
),
host_activity AS (
  SELECT host_id, MAX(ts) AS last_active_ts, COUNT(*) AS flow_total
  FROM (
    SELECT src_host_id AS host_id, ts FROM silver_flows WHERE src_host_id IS NOT NULL
    UNION ALL
    SELECT dst_host_id AS host_id, ts FROM silver_flows WHERE dst_host_id IS NOT NULL
  ) GROUP BY host_id
),
host_nodes AS (
  SELECT
    CONCAT('host:', h.host_id) AS node_id,
    'host' AS node_type,
    h.hostname AS label,
    parse_json(to_json(named_struct(
      'host_id', h.host_id,
      'ip', h.ip,
      'host_type', h.host_type,
      'os', h.os,
      'owner', h.owner,
      'criticality', h.criticality,
      'subnet_id', h.subnet_id,
      'zone', h.zone,
      'cidr', h.cidr,
      'is_external', h.is_external,
      'last_active_ts', CAST(ha.last_active_ts AS STRING),
      'flow_total', COALESCE(ha.flow_total, 0)
    ))) AS attrs,
    h.criticality,
    h.subnet_id,
    h.is_external,
    h.host_type
  FROM silver_hosts h
  LEFT JOIN host_activity ha ON h.host_id = ha.host_id
),
subnet_nodes AS (
  SELECT
    CONCAT('subnet:', s.subnet_id) AS node_id,
    'subnet' AS node_type,
    s.cidr AS label,
    parse_json(to_json(named_struct(
      'subnet_id', s.subnet_id,
      'cidr', s.cidr,
      'zone', s.zone,
      'description', s.description
    ))) AS attrs,
    CAST(NULL AS INT) AS criticality,
    s.subnet_id,
    CAST(s.zone = 'external' AS BOOLEAN) AS is_external,
    'subnet' AS host_type
  FROM bronze_subnets s
),
service_nodes AS (
  SELECT
    CONCAT('service:', svc.service_id) AS node_id,
    'service' AS node_type,
    svc.service_name AS label,
    parse_json(to_json(named_struct(
      'service_id', svc.service_id,
      'host_id', svc.host_id,
      'host_type', svc.host_type,
      'port', svc.port,
      'protocol', svc.protocol,
      'service_name', svc.service_name
    ))) AS attrs,
    CAST(NULL AS INT) AS criticality,
    CAST(NULL AS STRING) AS subnet_id,
    FALSE AS is_external,
    'service' AS host_type
  FROM silver_services svc
),
-- Union external IPs that appear as flow destinations AND as DNS resolution
-- answers. Without including the DNS side, gold_graph_edges' `resolves` edges
-- end up pointing at non-existent nodes — d3-force throws "node not found"
-- in the browser and the canvas never renders.
external_ips_from_flows AS (
  SELECT
    dst_ip AS ip,
    SUM(bytes) AS total_bytes,
    COUNT(*) AS flow_count,
    COUNT(DISTINCT src_host_id) AS distinct_internal_callers,
    MAX(ts) AS last_seen_ts
  FROM silver_flows
  WHERE is_dst_external = TRUE AND dst_ip IS NOT NULL
  GROUP BY dst_ip
),
external_ips_from_dns AS (
  SELECT
    resolved_ip AS ip,
    CAST(0 AS BIGINT) AS total_bytes,
    CAST(0 AS BIGINT) AS flow_count,
    COUNT(DISTINCT src_host_id) AS distinct_internal_callers,
    MAX(ts) AS last_seen_ts
  FROM silver_dns
  WHERE resolved_ip IS NOT NULL
  GROUP BY resolved_ip
),
external_ips_with_stats AS (
  SELECT
    ip,
    SUM(total_bytes) AS total_bytes,
    SUM(flow_count) AS flow_count,
    SUM(distinct_internal_callers) AS distinct_internal_callers,
    MAX(last_seen_ts) AS last_seen_ts
  FROM (
    SELECT * FROM external_ips_from_flows
    UNION ALL
    SELECT * FROM external_ips_from_dns
  )
  GROUP BY ip
),
external_ip_nodes AS (
  SELECT
    CONCAT('ext:', e.ip) AS node_id,
    'external_ip' AS node_type,
    e.ip AS label,
    parse_json(to_json(named_struct(
      'ip', e.ip,
      'total_bytes', e.total_bytes,
      'flow_count', e.flow_count,
      'distinct_internal_callers', e.distinct_internal_callers,
      'last_seen_ts', CAST(e.last_seen_ts AS STRING)
    ))) AS attrs,
    CAST(NULL AS INT) AS criticality,
    CAST(NULL AS STRING) AS subnet_id,
    TRUE AS is_external,
    'external' AS host_type
  FROM external_ips_with_stats e
),
all_nodes AS (
  SELECT * FROM host_nodes
  UNION ALL SELECT * FROM subnet_nodes
  UNION ALL SELECT * FROM service_nodes
  UNION ALL SELECT * FROM external_ip_nodes
)
SELECT
  n.node_id,
  n.node_type,
  n.label,
  n.attrs,
  n.criticality,
  n.subnet_id,
  n.is_external,
  n.host_type,
  COALESCE(ha.score, 0.0) AS anomaly_score,
  COALESCE(ha.labels, array()) AS anomaly_labels
FROM all_nodes n
LEFT JOIN host_anomalies ha ON n.node_id = ha.node_id;
