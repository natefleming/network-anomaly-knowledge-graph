-- Cleaned + enriched host inventory: join hosts with their subnet metadata.
-- Liquid clustering on host_id since this MV is looked up by host_id from
-- silver_flows, silver_services, silver_dns, and the gold node builders.
CREATE OR REFRESH MATERIALIZED VIEW silver_hosts (
  host_id            STRING    COMMENT 'Stable host identifier (PK). FK target for silver_flows/silver_services/silver_dns.',
  hostname           STRING    COMMENT 'Friendly hostname.',
  ip                 STRING    COMMENT 'Primary IPv4 address.',
  subnet_id          STRING    COMMENT 'Subnet membership (FK to bronze_subnets).',
  host_type          STRING    COMMENT 'workstation | server | gateway | iot | external.',
  os                 STRING    COMMENT 'Operating system identifier.',
  owner              STRING    COMMENT 'Person or team accountable for the host.',
  criticality        INT       COMMENT 'Business criticality 1-5.',
  cidr               STRING    COMMENT 'CIDR of the subnet this host belongs to (joined from bronze_subnets).',
  zone               STRING    COMMENT 'Security zone of the subnet: corporate | dmz | guest | iot | external.',
  subnet_description STRING    COMMENT 'Human-readable subnet description.',
  is_external        BOOLEAN   COMMENT 'True if the host is in an external-zone subnet or host_type=external.',
  _silver_loaded_at  TIMESTAMP COMMENT 'When this silver row was last refreshed.'
)
COMMENT 'Silver — cleaned host inventory joined to subnet metadata. One row per host. Cluster by host_id since every downstream consumer joins on it.'
CLUSTER BY (host_id)
AS
SELECT
  h.host_id,
  h.hostname,
  h.ip,
  h.subnet_id,
  h.host_type,
  h.os,
  h.owner,
  h.criticality,
  s.cidr,
  s.zone,
  s.description AS subnet_description,
  CASE WHEN h.host_type = 'external' OR s.zone = 'external' THEN TRUE ELSE FALSE END AS is_external,
  current_timestamp() AS _silver_loaded_at
FROM bronze_hosts h
LEFT JOIN bronze_subnets s ON h.subnet_id = s.subnet_id;
