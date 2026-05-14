-- Service catalog joined to its host.
-- Cluster by host_id — every downstream join joins services to a host.
CREATE OR REFRESH MATERIALIZED VIEW silver_services (
  service_id        STRING    COMMENT 'Stable service identifier (PK).',
  host_id           STRING    COMMENT 'Host this service runs on (FK to silver_hosts).',
  hostname          STRING    COMMENT 'Friendly hostname of the host (denormalized).',
  host_type         STRING    COMMENT 'Type of host running this service (workstation/server/gateway/iot).',
  port              INT       COMMENT 'TCP/UDP port the service listens on.',
  protocol          STRING    COMMENT 'Transport protocol: tcp | udp.',
  service_name      STRING    COMMENT 'Common service name (ssh, http, https, rdp, mssql, postgres, ...).',
  _silver_loaded_at TIMESTAMP COMMENT 'When this silver row was last refreshed.'
)
COMMENT 'Silver — service catalog joined to its host metadata. One row per (host, listening port).'
CLUSTER BY (host_id)
AS
SELECT
  s.service_id,
  s.host_id,
  h.hostname,
  h.host_type,
  s.port,
  s.protocol,
  s.service_name,
  current_timestamp() AS _silver_loaded_at
FROM bronze_services s
LEFT JOIN bronze_hosts h ON s.host_id = h.host_id;
