-- Lateral movement detector: 3+ hop chain of cross-zone flows in a 15-minute window.
-- Built via self-joins (a→b→c) on cross-zone flows.
-- Cluster by node_id so gold_graph_nodes can efficiently left-join the labels in.
CREATE OR REFRESH MATERIALIZED VIEW gold_anomaly_lateral (
  node_id         STRING        COMMENT 'Origin host node id (host:<hop1_src>). FK target for gold_graph_nodes.',
  origin_host_id  STRING        COMMENT 'Originating host of the chain (hop 1 src).',
  chain           ARRAY<STRING> COMMENT 'Ordered list of host ids visited: [hop1_src, hop1_dst, hop2_dst, hop3_dst].',
  zone_chain      ARRAY<STRING> COMMENT 'Zones traversed by the chain in order — must include ≥3 distinct zones to fire.',
  start_ts        TIMESTAMP     COMMENT 'Timestamp of the first hop in the chain.',
  end_ts          TIMESTAMP     COMMENT 'Timestamp of the last hop in the chain.',
  anomaly_type    STRING        COMMENT 'Literal "lateral_movement".',
  score           DOUBLE        COMMENT 'Fixed at 0.9 — lateral movement is high-confidence when detected.',
  evidence        STRING        COMMENT 'JSON evidence payload (chain + zone_chain + timestamps).'
)
COMMENT 'Anomaly detector — lateral movement. Surfaces 3-hop flow chains (a→b, b→c, c→d) across ≥3 distinct security zones within a single 15-minute window. Built via three self-joins on cross-zone flows in silver_flows. Visual signature: snake of red edges across subnets.'
CLUSTER BY (node_id)
AS
WITH cross_zone AS (
  SELECT
    flow_id, ts, src_host_id, src_hostname, src_zone,
    dst_host_id, dst_hostname, dst_zone, bytes
  FROM silver_flows
  WHERE is_cross_zone = TRUE
    AND src_host_id IS NOT NULL
    AND dst_host_id IS NOT NULL
),
chain3 AS (
  SELECT
    a.flow_id AS hop1_flow,
    a.src_host_id AS hop1_src,
    a.dst_host_id AS hop1_dst,
    a.src_zone AS hop1_src_zone,
    a.dst_zone AS hop1_dst_zone,
    b.dst_host_id AS hop2_dst,
    b.dst_zone AS hop2_dst_zone,
    c.dst_host_id AS hop3_dst,
    c.dst_zone AS hop3_dst_zone,
    a.ts AS start_ts,
    c.ts AS end_ts
  FROM cross_zone a
  JOIN cross_zone b
    ON a.dst_host_id = b.src_host_id
   AND b.ts > a.ts
   AND b.ts <= a.ts + INTERVAL 15 MINUTES
  JOIN cross_zone c
    ON b.dst_host_id = c.src_host_id
   AND c.ts > b.ts
   AND c.ts <= a.ts + INTERVAL 15 MINUTES
  WHERE size(array_distinct(array(a.src_zone, a.dst_zone, b.dst_zone, c.dst_zone))) >= 3
)
SELECT
  CONCAT('host:', hop1_src) AS node_id,
  hop1_src AS origin_host_id,
  array(hop1_src, hop1_dst, hop2_dst, hop3_dst) AS chain,
  array(hop1_src_zone, hop1_dst_zone, hop2_dst_zone, hop3_dst_zone) AS zone_chain,
  start_ts, end_ts,
  'lateral_movement' AS anomaly_type,
  CAST(0.9 AS DOUBLE) AS score,
  to_json(named_struct(
    'chain', array(hop1_src, hop1_dst, hop2_dst, hop3_dst),
    'zone_chain', array(hop1_src_zone, hop1_dst_zone, hop2_dst_zone, hop3_dst_zone),
    'start_ts', CAST(start_ts AS STRING),
    'end_ts', CAST(end_ts AS STRING)
  )) AS evidence
FROM chain3;
