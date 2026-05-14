-- Cleaned network flows with src/dst host enrichment + cross-zone flag.
-- Schema is OCSF-aligned: bronze columns were renamed to Network Activity (class_uid=4001)
-- field names (time, src_endpoint.*, dst_endpoint.*, traffic.*, connection_info.protocol_name).
-- Silver propagates OCSF identifiers AND keeps a few short aliases (ts, bytes, packets)
-- for the gold + anomaly detector layers that haven't been renamed yet.
-- Liquid clustering tuned for the lateral-movement self-joins and windowed detectors.
CREATE OR REFRESH MATERIALIZED VIEW silver_flows (
  flow_id           STRING    COMMENT 'OCSF metadata.uid — stable flow identifier.',
  time              TIMESTAMP COMMENT 'OCSF time — flow start time (parsed from bronze string).',
  ts                TIMESTAMP COMMENT 'Alias of time (downstream gold/anomaly layer compatibility).',
  src_host_id       STRING    COMMENT 'OCSF src_endpoint.uid.',
  src_hostname      STRING    COMMENT 'OCSF src_endpoint.hostname (denormalized).',
  src_host_type     STRING    COMMENT 'OCSF src_endpoint.type — workstation/server/gateway/iot/external.',
  src_subnet_id     STRING    COMMENT 'OCSF src_endpoint.network_uid.',
  src_zone          STRING    COMMENT 'OCSF src_endpoint.zone (extension).',
  src_ip            STRING    COMMENT 'OCSF src_endpoint.ip.',
  dst_host_id       STRING    COMMENT 'OCSF dst_endpoint.uid (NULL when external).',
  dst_hostname      STRING    COMMENT 'OCSF dst_endpoint.hostname (NULL when external).',
  dst_host_type     STRING    COMMENT 'OCSF dst_endpoint.type (NULL when external).',
  dst_subnet_id     STRING    COMMENT 'OCSF dst_endpoint.network_uid (NULL when external).',
  dst_zone          STRING    COMMENT 'OCSF dst_endpoint.zone — "external" when dst_host_id is NULL.',
  dst_ip            STRING    COMMENT 'OCSF dst_endpoint.ip — populated whether internal or external.',
  src_port          INT       COMMENT 'OCSF src_endpoint.port.',
  dst_port          INT       COMMENT 'OCSF dst_endpoint.port.',
  protocol_name     STRING    COMMENT 'OCSF connection_info.protocol_name (tcp | udp).',
  protocol          STRING    COMMENT 'Alias of protocol_name (downstream compatibility).',
  traffic_packets   BIGINT    COMMENT 'OCSF traffic.packets — packets in this flow.',
  packets           BIGINT    COMMENT 'Alias of traffic_packets.',
  traffic_bytes     BIGINT    COMMENT 'OCSF traffic.bytes — bytes in this flow.',
  bytes             BIGINT    COMMENT 'Alias of traffic_bytes.',
  duration          INT       COMMENT 'OCSF duration — flow duration in milliseconds.',
  duration_ms       INT       COMMENT 'Alias of duration.',
  class_uid         INT       COMMENT 'OCSF class_uid — 4001 (Network Activity).',
  activity_id       INT       COMMENT 'OCSF activity_id — 6 (Traffic).',
  type_uid          INT       COMMENT 'OCSF type_uid — 400106.',
  severity_id       INT       COMMENT 'OCSF severity_id — 1 (Informational) on raw observation.',
  is_dst_external   BOOLEAN   COMMENT 'True when destination is an external IP (no dst_host_id).',
  is_cross_zone     BOOLEAN   COMMENT 'True when src and dst are in different security zones — the lateral-movement primitive.',
  _silver_loaded_at TIMESTAMP COMMENT 'When this silver row was last refreshed.'
)
COMMENT 'Silver — OCSF-aligned Network Activity events (class_uid=4001). Enriched with src/dst host + subnet zone metadata + cross-zone flag. Powers port-scan, lateral-movement, exfiltration, and DDoS detectors.'
CLUSTER BY (src_host_id, dst_host_id, time)
AS
WITH src AS (
  SELECT host_id, hostname, host_type, subnet_id, zone, ip AS src_ip
  FROM silver_hosts
),
dst AS (
  SELECT host_id, hostname, host_type, subnet_id, zone, ip AS dst_ip_internal
  FROM silver_hosts
)
SELECT
  f.flow_id,
  CAST(f.time AS TIMESTAMP)   AS time,
  CAST(f.time AS TIMESTAMP)   AS ts,
  f.src_host_id,
  src.hostname                AS src_hostname,
  src.host_type               AS src_host_type,
  src.subnet_id               AS src_subnet_id,
  src.zone                    AS src_zone,
  src.src_ip,
  f.dst_host_id,
  dst.hostname                AS dst_hostname,
  dst.host_type               AS dst_host_type,
  dst.subnet_id               AS dst_subnet_id,
  COALESCE(dst.zone, 'external') AS dst_zone,
  COALESCE(dst.dst_ip_internal, f.dst_ip) AS dst_ip,
  f.src_port,
  f.dst_port,
  f.protocol_name,
  f.protocol_name             AS protocol,
  f.traffic_packets,
  f.traffic_packets           AS packets,
  f.traffic_bytes,
  f.traffic_bytes             AS bytes,
  f.duration,
  f.duration                  AS duration_ms,
  f.class_uid,
  f.activity_id,
  f.type_uid,
  f.severity_id,
  CASE WHEN f.dst_host_id IS NULL THEN TRUE ELSE FALSE END AS is_dst_external,
  CASE WHEN src.zone IS NOT NULL AND dst.zone IS NOT NULL AND src.zone <> dst.zone THEN TRUE ELSE FALSE END AS is_cross_zone,
  current_timestamp() AS _silver_loaded_at
FROM bronze_network_flows f
LEFT JOIN src ON f.src_host_id = src.host_id
LEFT JOIN dst ON f.dst_host_id = dst.host_id;
