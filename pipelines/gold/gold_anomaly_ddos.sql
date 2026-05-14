-- DDoS detector: a single target receiving traffic from many distinct sources in a 5-minute window.
-- Cluster by node_id so gold_graph_nodes can efficiently left-join the labels in.
CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_ddos (
  node_id          STRING    COMMENT 'Flagged target host node id (host:<dst_host_id>). FK target for gold_graph_nodes.',
  dst_host_id      STRING    COMMENT 'Target host id.',
  dst_hostname     STRING    COMMENT 'Target hostname.',
  window_start     TIMESTAMP COMMENT 'Start of the 5-minute window where the fan-in was observed.',
  window_end       TIMESTAMP COMMENT 'End of the window.',
  distinct_sources BIGINT    COMMENT 'Number of distinct source hosts that hit this target in the window — must be ≥50 to fire.',
  flow_count       BIGINT    COMMENT 'Total flows landing on this target in the window.',
  anomaly_type     STRING    COMMENT 'Literal "ddos".',
  score            DOUBLE    COMMENT 'Anomaly score 0-1 = LEAST(1.0, distinct_sources / 200.0).',
  evidence         STRING    COMMENT 'JSON evidence payload.'
)
COMMENT 'Anomaly detector — DDoS target. Surfaces hosts receiving traffic from ≥50 distinct source hosts within a single 5-minute tumbling window. Visual signature: fan-in to a single node; appears at the top of the GraphFrames degree-centrality ranking.'
CLUSTER BY (node_id)
AS
SELECT
  CONCAT('host:', dst_host_id) AS node_id,
  dst_host_id,
  dst_hostname,
  window.start AS window_start,
  window.end   AS window_end,
  COUNT(DISTINCT src_host_id) AS distinct_sources,
  COUNT(*) AS flow_count,
  'ddos' AS anomaly_type,
  CAST(LEAST(1.0, COUNT(DISTINCT src_host_id) / 200.0) AS DOUBLE) AS score,
  to_json(named_struct(
    'target_host_id', dst_host_id,
    'distinct_sources', COUNT(DISTINCT src_host_id),
    'flow_count', COUNT(*),
    'window_start', CAST(window.start AS STRING)
  )) AS evidence
FROM silver_flows
WHERE dst_host_id IS NOT NULL
GROUP BY dst_host_id, dst_hostname, window(ts, '5 minutes')
HAVING COUNT(DISTINCT src_host_id) >= 50;
