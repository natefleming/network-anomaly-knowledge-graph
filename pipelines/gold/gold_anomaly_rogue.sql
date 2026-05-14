-- Rogue device detector: internal hosts with zero traffic peers AND any suspicious DNS lookups.
-- Cluster by node_id so gold_graph_nodes can efficiently left-join the labels in.
CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_rogue (
  node_id                STRING  COMMENT 'Flagged host node id (host:<host_id>). FK target for gold_graph_nodes.',
  host_id                STRING  COMMENT 'Internal host identifier.',
  hostname               STRING  COMMENT 'Hostname.',
  flow_count             BIGINT  COMMENT 'Total flows observed where this host is either src or dst — must be 0 to fire.',
  suspicious_query_count BIGINT  COMMENT 'Number of DNS queries to flagged TLDs (.xyz/.top/.tk/.click/.ru/.pw/.cc/.bid) — must be > 0 to fire.',
  anomaly_type           STRING  COMMENT 'Literal "rogue_device".',
  score                  DOUBLE  COMMENT 'Fixed at 0.95 — silent host + suspicious DNS is high-confidence.',
  evidence               STRING  COMMENT 'JSON evidence payload.'
)
COMMENT 'Anomaly detector — rogue device. Surfaces internal hosts with zero flow peers across the entire dataset AND at least one DNS query to a suspicious TLD. Real workstations generate hundreds of flows per day; silence + sketchy DNS is highly anomalous. Visual signature: purple isolated node at the periphery, connected only by DNS resolves edges.'
CLUSTER BY (node_id)
AS
WITH host_peer_counts AS (
  SELECT h.host_id, h.hostname,
    COALESCE(SUM(CASE WHEN f.src_host_id = h.host_id THEN 1 ELSE 0 END), 0)
      + COALESCE(SUM(CASE WHEN f.dst_host_id = h.host_id THEN 1 ELSE 0 END), 0) AS flow_count
  FROM silver_hosts h
  LEFT JOIN silver_flows f
    ON h.host_id IN (f.src_host_id, f.dst_host_id)
  WHERE h.is_external = FALSE
  GROUP BY h.host_id, h.hostname
),
suspicious_dns AS (
  SELECT src_host_id, COUNT(*) AS suspicious_query_count
  FROM silver_dns
  WHERE is_suspicious_tld = TRUE
  GROUP BY src_host_id
)
SELECT
  CONCAT('host:', hpc.host_id) AS node_id,
  hpc.host_id,
  hpc.hostname,
  hpc.flow_count,
  COALESCE(sd.suspicious_query_count, 0) AS suspicious_query_count,
  'rogue_device' AS anomaly_type,
  CAST(0.95 AS DOUBLE) AS score,
  to_json(named_struct(
    'host_id', hpc.host_id,
    'flow_count', hpc.flow_count,
    'suspicious_query_count', COALESCE(sd.suspicious_query_count, 0)
  )) AS evidence
FROM host_peer_counts hpc
LEFT JOIN suspicious_dns sd ON hpc.host_id = sd.src_host_id
WHERE hpc.flow_count = 0
  AND COALESCE(sd.suspicious_query_count, 0) > 0;
