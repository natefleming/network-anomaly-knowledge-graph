-- Parsed DNS queries with a flag for suspicious TLDs.
-- Schema is OCSF-aligned: bronze columns conform to DNS Activity (class_uid=4003)
-- field names (time, src_endpoint.uid, query.hostname, query.type, rcode_id, answers[*].ip).
-- Silver propagates OCSF identifiers AND keeps `ts`, `query_name`, `response_code`,
-- and `resolved_ip` as aliases for downstream layers that haven't been renamed.
CREATE OR REFRESH MATERIALIZED VIEW silver_dns (
  query_id          STRING    COMMENT 'OCSF metadata.uid — stable DNS query identifier.',
  time              TIMESTAMP COMMENT 'OCSF time — query timestamp.',
  ts                TIMESTAMP COMMENT 'Alias of time.',
  src_host_id       STRING    COMMENT 'OCSF src_endpoint.uid — host that issued the query.',
  src_hostname      STRING    COMMENT 'OCSF src_endpoint.hostname (denormalized).',
  query_hostname    STRING    COMMENT 'OCSF query.hostname — the queried domain.',
  query_name        STRING    COMMENT 'Alias of query_hostname.',
  query_type        STRING    COMMENT 'OCSF query.type — A | AAAA | CNAME | MX.',
  rcode_id          INT       COMMENT 'OCSF rcode_id — DNS response code (0=NOERROR, 3=NXDOMAIN).',
  response_code     INT       COMMENT 'Alias of rcode_id.',
  answer_ip         STRING    COMMENT 'OCSF answers[0].rdata — IPv4 returned by the resolver.',
  resolved_ip       STRING    COMMENT 'Alias of answer_ip.',
  class_uid         INT       COMMENT 'OCSF class_uid — 4003 (DNS Activity).',
  activity_id       INT       COMMENT 'OCSF activity_id — 1 (Query).',
  type_uid          INT       COMMENT 'OCSF type_uid — 400301.',
  severity_id       INT       COMMENT 'OCSF severity_id — 1 Informational or 2 Low for suspicious TLD lookups.',
  is_suspicious_tld BOOLEAN   COMMENT 'True if query_hostname ends in a flagged TLD: .xyz/.top/.tk/.click/.ru/.pw/.cc/.bid.',
  _silver_loaded_at TIMESTAMP COMMENT 'When this silver row was last refreshed.'
)
COMMENT 'Silver — OCSF-aligned DNS Activity events (class_uid=4003) with a suspicious-TLD flag. Powers the rogue-device detector and the suspicious-DNS edge annotation.'
CLUSTER BY (src_host_id)
AS
WITH flagged_tlds AS (
  SELECT explode(array('.xyz', '.top', '.tk', '.click', '.ru', '.pw', '.cc', '.bid')) AS tld
)
SELECT
  d.query_id,
  CAST(d.time AS TIMESTAMP) AS time,
  CAST(d.time AS TIMESTAMP) AS ts,
  d.src_host_id,
  h.hostname AS src_hostname,
  d.query_hostname,
  d.query_hostname AS query_name,
  d.query_type,
  d.rcode_id,
  d.rcode_id AS response_code,
  d.answer_ip,
  d.answer_ip AS resolved_ip,
  d.class_uid,
  d.activity_id,
  d.type_uid,
  d.severity_id,
  EXISTS (
    SELECT 1 FROM flagged_tlds f
    WHERE lower(d.query_hostname) LIKE concat('%', f.tld)
  ) AS is_suspicious_tld,
  current_timestamp() AS _silver_loaded_at
FROM bronze_dns_queries d
LEFT JOIN bronze_hosts h ON d.src_host_id = h.host_id;
