# Databricks notebook source
# MAGIC %md
# MAGIC # 03 — Anomaly Queries
# MAGIC
# MAGIC Demonstrates two complementary ways to surface anomalies from the knowledge graph:
# MAGIC
# MAGIC 1. **Detector materialized views** — `gold_anomaly_*` precomputed in the SDP.
# MAGIC 2. **Direct attribute queries** — using the `attrs` **VARIANT** column on nodes and
# MAGIC    edges with the `:field::type` extraction operator.
# MAGIC
# MAGIC The VARIANT column lets us store rich, schema-less metadata per entity/edge and query
# MAGIC it efficiently without joins back to bronze.

# COMMAND ----------
dbutils.widgets.text("catalog", "retail_consumer_goods")
dbutils.widgets.text("schema", "network_anomaly_graph")
CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
spark.sql(f"USE CATALOG {CATALOG}")
spark.sql(f"USE SCHEMA {SCHEMA}")

# COMMAND ----------
# MAGIC %md ## 1. Port-scan: one host fanning out to many destinations on many ports

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_host_id,
# MAGIC   src_hostname,
# MAGIC   distinct_dests,
# MAGIC   distinct_ports,
# MAGIC   flow_count,
# MAGIC   score,
# MAGIC   window_start,
# MAGIC   window_end
# MAGIC FROM gold_anomaly_scan
# MAGIC ORDER BY score DESC, distinct_ports DESC
# MAGIC LIMIT 10;

# COMMAND ----------
# MAGIC %md
# MAGIC ### And the same insight via VARIANT attrs on edges
# MAGIC Every flow edge stores its full attribute payload in `attrs`. We can find port-scan
# MAGIC behavior directly by looking at flow edges whose `distinct_dst_ports` array is large.

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_id,
# MAGIC   COUNT(*)                                                  AS distinct_dst_hosts,
# MAGIC   SUM(size(CAST(attrs:distinct_dst_ports AS ARRAY<INT>)))   AS total_distinct_ports_across_dests,
# MAGIC   SUM(CAST(attrs:flow_count AS BIGINT))                     AS total_flows
# MAGIC FROM gold_graph_edges
# MAGIC WHERE edge_type = 'flow'
# MAGIC GROUP BY src_id
# MAGIC HAVING distinct_dst_hosts >= 30
# MAGIC    AND total_distinct_ports_across_dests >= 30
# MAGIC ORDER BY total_distinct_ports_across_dests DESC
# MAGIC LIMIT 10;

# COMMAND ----------
# MAGIC %md ## 2. Lateral movement: cross-zone chains 3+ hops long

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   origin_host_id,
# MAGIC   chain,
# MAGIC   zone_chain,
# MAGIC   start_ts,
# MAGIC   end_ts,
# MAGIC   score
# MAGIC FROM gold_anomaly_lateral
# MAGIC ORDER BY start_ts;

# COMMAND ----------
# MAGIC %md
# MAGIC ### Cross-zone edges via VARIANT
# MAGIC Each flow edge stores `attrs:src_zone` and `attrs:dst_zone`. The full edge set of
# MAGIC suspicious cross-zone traffic is one query:

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_id,
# MAGIC   dst_id,
# MAGIC   attrs:src_zone::string AS src_zone,
# MAGIC   attrs:dst_zone::string AS dst_zone,
# MAGIC   attrs:byte_count::bigint AS bytes,
# MAGIC   attrs:flow_count::bigint AS flows
# MAGIC FROM gold_graph_edges
# MAGIC WHERE edge_type = 'flow'
# MAGIC   AND attrs:is_cross_zone::boolean = TRUE
# MAGIC ORDER BY bytes DESC
# MAGIC LIMIT 50;

# COMMAND ----------
# MAGIC %md ## 3. Data exfiltration: large outbound traffic to an external IP

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_host_id,
# MAGIC   src_hostname,
# MAGIC   external_dst_ip,
# MAGIC   total_bytes,
# MAGIC   flow_count,
# MAGIC   window_start,
# MAGIC   score
# MAGIC FROM gold_anomaly_exfil
# MAGIC ORDER BY total_bytes DESC
# MAGIC LIMIT 10;

# COMMAND ----------
# MAGIC %md
# MAGIC ### Top external destinations by traffic (node attrs)
# MAGIC External IP nodes carry `total_bytes`, `flow_count`, `distinct_internal_callers` in
# MAGIC their VARIANT attrs.

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   node_id,
# MAGIC   label                                              AS ip,
# MAGIC   CAST(attrs:total_bytes              AS BIGINT)     AS total_bytes,
# MAGIC   CAST(attrs:flow_count               AS BIGINT)     AS flows,
# MAGIC   CAST(attrs:distinct_internal_callers AS BIGINT)    AS callers
# MAGIC FROM gold_graph_nodes
# MAGIC WHERE node_type = 'external_ip'
# MAGIC ORDER BY total_bytes DESC
# MAGIC LIMIT 20;

# COMMAND ----------
# MAGIC %md ## 4. Rogue devices: zero peers + suspicious DNS

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   host_id,
# MAGIC   hostname,
# MAGIC   flow_count,
# MAGIC   suspicious_query_count,
# MAGIC   score
# MAGIC FROM gold_anomaly_rogue
# MAGIC ORDER BY suspicious_query_count DESC;

# COMMAND ----------
# MAGIC %md
# MAGIC ### Rogues via VARIANT — `flow_total = 0` AND suspicious DNS resolves edge
# MAGIC Host node attrs include `flow_total` (lifetime flow count). DNS edges have
# MAGIC `is_suspicious_tld` flag. Combine them.

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   n.node_id,
# MAGIC   n.label,
# MAGIC   n.attrs:host_type::string  AS host_type,
# MAGIC   n.attrs:zone::string       AS zone,
# MAGIC   n.attrs:flow_total::bigint AS flow_total,
# MAGIC   COUNT(e.dst_id)            AS suspicious_dns_targets
# MAGIC FROM gold_graph_nodes n
# MAGIC JOIN gold_graph_edges e
# MAGIC   ON e.src_id = n.node_id
# MAGIC  AND e.edge_type = 'resolves'
# MAGIC  AND e.attrs:is_suspicious_tld::boolean = TRUE
# MAGIC WHERE n.node_type = 'host'
# MAGIC   AND CAST(n.attrs:flow_total AS BIGINT) = 0
# MAGIC GROUP BY n.node_id, n.label, n.attrs:host_type::string, n.attrs:zone::string, n.attrs:flow_total::bigint
# MAGIC ORDER BY suspicious_dns_targets DESC;

# COMMAND ----------
# MAGIC %md ## 5. DDoS targets: fan-in from many sources at once

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   dst_host_id,
# MAGIC   dst_hostname,
# MAGIC   distinct_sources,
# MAGIC   flow_count,
# MAGIC   window_start,
# MAGIC   score
# MAGIC FROM gold_anomaly_ddos
# MAGIC ORDER BY distinct_sources DESC
# MAGIC LIMIT 10;

# COMMAND ----------
# MAGIC %md ## 6. Combined view — every node currently flagged, with selected attrs

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   node_id,
# MAGIC   label,
# MAGIC   node_type,
# MAGIC   attrs:host_type::string  AS host_type,
# MAGIC   attrs:zone::string       AS zone,
# MAGIC   attrs:criticality::int   AS criticality,
# MAGIC   anomaly_score,
# MAGIC   anomaly_labels
# MAGIC FROM gold_graph_nodes
# MAGIC WHERE anomaly_score > 0
# MAGIC ORDER BY anomaly_score DESC, size(anomaly_labels) DESC
# MAGIC LIMIT 50;

# COMMAND ----------
# MAGIC %md ## 7. Most-targeted services (attrs:port + service_edges)

# COMMAND ----------
# MAGIC %sql
# MAGIC WITH service_flow_targets AS (
# MAGIC   SELECT
# MAGIC     se.src_id                                   AS service_node_id,
# MAGIC     se.dst_id                                   AS host_node_id,
# MAGIC     se.attrs:port::int                          AS port,
# MAGIC     se.attrs:service_name::string               AS service_name
# MAGIC   FROM gold_graph_edges se
# MAGIC   WHERE se.edge_type = 'hosts'
# MAGIC )
# MAGIC SELECT
# MAGIC   sft.service_name,
# MAGIC   sft.port,
# MAGIC   COUNT(DISTINCT fe.src_id)               AS distinct_callers,
# MAGIC   SUM(CAST(fe.attrs:byte_count AS BIGINT)) AS total_bytes
# MAGIC FROM service_flow_targets sft
# MAGIC JOIN gold_graph_edges fe
# MAGIC   ON fe.dst_id = sft.host_node_id
# MAGIC  AND fe.edge_type = 'flow'
# MAGIC  AND array_contains(CAST(fe.attrs:distinct_dst_ports AS ARRAY<INT>), sft.port)
# MAGIC GROUP BY sft.service_name, sft.port
# MAGIC ORDER BY distinct_callers DESC
# MAGIC LIMIT 20;

# COMMAND ----------
# MAGIC %md ## 8. Cross-zone bytes by zone pair (attrs roll-up)

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   attrs:src_zone::string AS src_zone,
# MAGIC   attrs:dst_zone::string AS dst_zone,
# MAGIC   SUM(CAST(attrs:byte_count   AS BIGINT)) AS total_bytes,
# MAGIC   SUM(CAST(attrs:flow_count   AS BIGINT)) AS total_flows,
# MAGIC   COUNT(*)                                 AS distinct_pairs
# MAGIC FROM gold_graph_edges
# MAGIC WHERE edge_type = 'flow'
# MAGIC GROUP BY ALL
# MAGIC ORDER BY total_bytes DESC;

# COMMAND ----------
# MAGIC %md ## 9. Anomalous edges with full evidence payload

# COMMAND ----------
# MAGIC %sql
# MAGIC SELECT
# MAGIC   src_id,
# MAGIC   dst_id,
# MAGIC   edge_type,
# MAGIC   anomaly_label,
# MAGIC   anomaly_score,
# MAGIC   attrs
# MAGIC FROM gold_graph_edges
# MAGIC WHERE is_anomalous = TRUE
# MAGIC ORDER BY anomaly_score DESC
# MAGIC LIMIT 25;

# COMMAND ----------
result_counts = {}
for tbl in ["gold_anomaly_scan", "gold_anomaly_lateral", "gold_anomaly_exfil", "gold_anomaly_rogue", "gold_anomaly_ddos"]:
    result_counts[tbl] = spark.table(f"{CATALOG}.{SCHEMA}.{tbl}").count()
result_counts["gold_graph_nodes"] = spark.table(f"{CATALOG}.{SCHEMA}.gold_graph_nodes").count()
result_counts["gold_graph_edges"] = spark.table(f"{CATALOG}.{SCHEMA}.gold_graph_edges").count()
print(result_counts)
import json
dbutils.notebook.exit(json.dumps(result_counts))
