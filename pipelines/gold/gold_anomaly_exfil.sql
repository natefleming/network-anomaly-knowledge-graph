-- Data exfiltration detector: large outbound flow to an external destination.
-- Threshold: >5 MB to an external dst from a single internal host within a 5-minute window.
-- Cluster by node_id so gold_graph_nodes can efficiently left-join the labels in.
CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_exfil (
  node_id         STRING    COMMENT 'Flagged host node id (host:<src_host_id>). FK target for gold_graph_nodes.',
  src_host_id     STRING    COMMENT 'Internal host that sent the data.',
  src_hostname    STRING    COMMENT 'Source hostname.',
  external_dst_ip STRING    COMMENT 'External destination IPv4 that received the bytes.',
  window_start    TIMESTAMP COMMENT 'Start of the 5-minute window in which the threshold was crossed.',
  window_end      TIMESTAMP COMMENT 'End of the window.',
  total_bytes     BIGINT    COMMENT 'Total outbound bytes in the window from src → external_dst_ip.',
  flow_count      BIGINT    COMMENT 'Number of flows in the window.',
  anomaly_type    STRING    COMMENT 'Literal "data_exfiltration".',
  score           DOUBLE    COMMENT 'Anomaly score 0-1 = LEAST(1.0, total_bytes / 50,000,000).',
  evidence        STRING    COMMENT 'JSON evidence payload.'
)
COMMENT 'Anomaly detector — data exfiltration. Surfaces internal hosts sending >5 MB to a single external IP within any 5-minute window. Visual signature: thick red edge from internal host to external_ip node with fast-moving packet particles.'
CLUSTER BY (node_id)
AS
SELECT
  CONCAT('host:', src_host_id) AS node_id,
  src_host_id,
  src_hostname,
  dst_ip AS external_dst_ip,
  window.start AS window_start,
  window.end   AS window_end,
  SUM(bytes) AS total_bytes,
  COUNT(*) AS flow_count,
  'data_exfiltration' AS anomaly_type,
  CAST(LEAST(1.0, SUM(bytes) / 50000000.0) AS DOUBLE) AS score,
  to_json(named_struct(
    'src_host_id', src_host_id,
    'external_dst_ip', dst_ip,
    'total_bytes', SUM(bytes),
    'flow_count', COUNT(*),
    'window_start', CAST(window.start AS STRING)
  )) AS evidence
FROM silver_flows
WHERE is_dst_external = TRUE
  AND src_host_id IS NOT NULL
GROUP BY src_host_id, src_hostname, dst_ip, window(ts, '5 minutes')
HAVING SUM(bytes) > 5000000;
