-- Port-scan detector: one source emitting flows to many destinations on sequential ports in a short window.
-- Threshold: ≥30 unique destinations AND ≥30 unique ports within a single 10-minute tumbling window from the same src.
-- Cluster by node_id so gold_graph_nodes can efficiently left-join to pull in the score/labels.
CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_scan (
  node_id         STRING    COMMENT 'Flagged host node id (host:<host_id>). FK target for gold_graph_nodes.',
  src_host_id     STRING    COMMENT 'Originating host id.',
  src_hostname    STRING    COMMENT 'Originating hostname.',
  window_start    TIMESTAMP COMMENT 'Start of the 10-minute tumbling window where the scan was observed.',
  window_end      TIMESTAMP COMMENT 'End of the window.',
  distinct_dests  BIGINT    COMMENT 'Number of distinct destination hosts/IPs hit in the window.',
  distinct_ports  BIGINT    COMMENT 'Number of distinct destination ports hit in the window.',
  flow_count      BIGINT    COMMENT 'Total flows in the window from this src.',
  anomaly_type    STRING    COMMENT 'Literal "port_scan".',
  score           DOUBLE    COMMENT 'Anomaly score 0-1 = LEAST(1.0, distinct_ports / 200.0).',
  evidence        STRING    COMMENT 'JSON evidence payload for the analyst.'
)
COMMENT 'Anomaly detector — port scan. Surfaces hosts that contacted ≥30 distinct destinations on ≥30 distinct ports within a single 10-minute tumbling window. Visual signature: starburst in the graph.'
CLUSTER BY (node_id)
AS
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
  CAST(LEAST(1.0, COUNT(DISTINCT dst_port) / 200.0) AS DOUBLE) AS score,
  to_json(named_struct(
    'distinct_dests', COUNT(DISTINCT COALESCE(CAST(dst_host_id AS STRING), dst_ip)),
    'distinct_ports', COUNT(DISTINCT dst_port),
    'flow_count', COUNT(*),
    'window_start', CAST(window.start AS STRING),
    'window_end', CAST(window.end AS STRING)
  )) AS evidence
FROM silver_flows
WHERE src_host_id IS NOT NULL
GROUP BY src_host_id, src_hostname, window(ts, '10 minutes')
HAVING COUNT(DISTINCT dst_port) >= 30
   AND COUNT(DISTINCT COALESCE(CAST(dst_host_id AS STRING), dst_ip)) >= 30;
