# Databricks notebook source
# MAGIC %md
# MAGIC # 02 — Graph Analytics on the Knowledge Graph
# MAGIC
# MAGIC We use **GraphFrames** where possible (the current state of the art for distributed
# MAGIC graph processing on Spark — GraphX was deprecated in Spark 4.0) and Spark SQL as a
# MAGIC fallback when a particular GraphFrames algorithm hasn't been fully ported to Spark
# MAGIC Connect serverless yet.
# MAGIC
# MAGIC We demonstrate:
# MAGIC 1. **Degree centrality** — who has the most peers? Identifies gateways/servers AND
# MAGIC    suspicious hosts (port-scanner).
# MAGIC 2. **Connected components** — find isolated subgraphs / orphan nodes.
# MAGIC 3. **Motif finding** — 3-hop chains across zones for lateral-movement validation.
# MAGIC 4. **Reach analysis** — which nodes can a rogue device touch directly?

# COMMAND ----------
# graphframes-py is installed via the job environment spec in resources/jobs.yml.

# COMMAND ----------
dbutils.widgets.text("catalog", "retail_consumer_goods")
dbutils.widgets.text("schema", "network_anomaly_graph")
CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
spark.sql(f"USE CATALOG {CATALOG}")
spark.sql(f"USE SCHEMA {SCHEMA}")

# COMMAND ----------
from pyspark.sql import functions as F
from graphframes import GraphFrame

vertices = (
    spark.table("gold_graph_nodes")
    .withColumnRenamed("node_id", "id")
    .select("id", "node_type", "label", "host_type", "subnet_id", "is_external",
            "anomaly_score", "anomaly_labels", "attrs")
)
edges = (
    spark.table("gold_graph_edges")
    .withColumnRenamed("src_id", "src")
    .withColumnRenamed("dst_id", "dst")
    .select("src", "dst", "edge_type", "packet_count", "byte_count",
            "is_anomalous", "anomaly_label", "anomaly_score", "attrs")
)
print(f"vertices: {vertices.count():,}   edges: {edges.count():,}")
g = GraphFrame(vertices, edges)

# COMMAND ----------
# MAGIC %md ## 1. Degree centrality
# MAGIC In a real network graph the highest-degree nodes are almost always either
# MAGIC infrastructure (gateways, DNS servers) or anomalous (port-scanners with one outgoing
# MAGIC edge to every other host). We rank by total degree and surface both populations.

# COMMAND ----------
out_degree = (
    edges.filter(F.col("edge_type") == "flow")
    .groupBy("src").agg(F.count("*").alias("out_degree"))
    .withColumnRenamed("src", "id")
)
in_degree = (
    edges.filter(F.col("edge_type") == "flow")
    .groupBy("dst").agg(F.count("*").alias("in_degree"))
    .withColumnRenamed("dst", "id")
)
degree = (
    vertices.join(out_degree, "id", "left")
    .join(in_degree, "id", "left")
    .fillna(0, ["out_degree", "in_degree"])
    .withColumn("total_degree", F.col("out_degree") + F.col("in_degree"))
)
print("Top 20 by total degree (gateways/servers AND anomalous hosts):")
display(degree.orderBy(F.desc("total_degree")).select(
    "id", "label", "host_type", "out_degree", "in_degree", "total_degree",
    "anomaly_labels"
).limit(20))

# COMMAND ----------
# MAGIC %md ## 2. Connected components

# COMMAND ----------
component_sizes = None
try:
    # Try to set a checkpoint dir for GraphFrames (required for some algorithms).
    # Not supported on Spark Connect serverless — we wrap the whole block in try/except.
    spark.conf.set("spark.databricks.io.cache.enabled", "true")
    cc = g.connectedComponents()
    component_sizes = (
        cc.groupBy("component")
        .agg(F.count("*").alias("size"))
        .orderBy(F.desc("size"))
    )
    print(f"Total components (GraphFrames): {component_sizes.count()}")
    display(component_sizes.limit(10))
except Exception as e:
    print(f"GraphFrames connectedComponents not available on this runtime ({type(e).__name__}: {str(e)[:140]}).")
    print("Falling back to subnet-based component approximation (one component per UC subnet).")
    fallback = spark.sql("""
        SELECT subnet_id AS component, COUNT(*) AS size
        FROM gold_graph_nodes
        WHERE subnet_id IS NOT NULL
        GROUP BY subnet_id
        ORDER BY size DESC
    """)
    display(fallback.limit(10))

# COMMAND ----------
# MAGIC %md ## 3. Motif finding — `(a)->(b); (b)->(c); (c)->(d)` chains
# MAGIC GraphFrames offers declarative path-pattern matching via `g.find("(a)-[]->(b); ...")`,
# MAGIC but it relies on a JVM-side extension that isn't loaded in Spark Connect serverless.
# MAGIC We try GraphFrames first; if that fails, fall back to the same primitive expressed
# MAGIC as a SQL self-join — which runs cleanly on serverless and is what an analyst would
# MAGIC actually write against `gold_graph_edges`.

# COMMAND ----------
chains_count = 0
try:
    flow_only = g.filterEdges("edge_type = 'flow'")
    chains = flow_only.find("(a)-[e1]->(b); (b)-[e2]->(c); (c)-[e3]->(d)")
    chains_count = chains.count()
    print(f"GraphFrames motif chains discovered: {chains_count:,}")
    display(chains.select(
        F.col("a.label").alias("hop1"),
        F.col("b.label").alias("hop2"),
        F.col("c.label").alias("hop3"),
        F.col("d.label").alias("hop4"),
    ).limit(20))
except Exception:
    print("GraphFrames motif find is not available on Spark Connect serverless — falling back to a SQL self-join.")

# COMMAND ----------
# SQL-based motif finder — equivalent to GraphFrames `g.find("(a)->(b); (b)->(c); (c)->(d)")`
# but expressed as plain Spark SQL. Always works on serverless.
sql_chains = spark.sql(f"""
WITH flow_edges AS (
  SELECT src_id, dst_id FROM {CATALOG}.{SCHEMA}.gold_graph_edges WHERE edge_type = 'flow'
)
SELECT
  a.src_id AS hop1,
  a.dst_id AS hop2,
  b.dst_id AS hop3,
  c.dst_id AS hop4
FROM flow_edges a
JOIN flow_edges b ON a.dst_id = b.src_id
JOIN flow_edges c ON b.dst_id = c.src_id
WHERE a.src_id <> a.dst_id
  AND b.src_id <> b.dst_id
  AND c.src_id <> c.dst_id
""")
sql_chains_count = sql_chains.count()
print(f"SQL motif chains discovered: {sql_chains_count:,}")
display(sql_chains.limit(20))
chains_count = chains_count or sql_chains_count

# COMMAND ----------
# MAGIC %md ## 4. Reach analysis from each rogue device

# COMMAND ----------
rogue_ids = [
    r.id for r in vertices.filter(F.array_contains("anomaly_labels", "rogue_device")).select("id").collect()
]
print(f"Rogue devices: {rogue_ids}")
if rogue_ids:
    sample = rogue_ids[0]
    neighbor_edges = edges.filter((F.col("src") == sample) | (F.col("dst") == sample))
    print(f"Rogue {sample} has {neighbor_edges.count()} edges; a true rogue should have only DNS edges (zero flows).")
    display(neighbor_edges.groupBy("edge_type").agg(F.count("*").alias("count")))

# COMMAND ----------
# MAGIC %md ## 5. VARIANT-attribute query (showcasing the schema-less power of the graph)
# MAGIC Find every cross-zone flow above 1 MB AND with > 100 packets, grouped by zone pair.

# COMMAND ----------
display(spark.sql("""
SELECT
  attrs:src_zone::string AS src_zone,
  attrs:dst_zone::string AS dst_zone,
  COUNT(*)                                AS edge_count,
  SUM(CAST(attrs:byte_count   AS BIGINT)) AS total_bytes,
  SUM(CAST(attrs:packet_count AS BIGINT)) AS total_packets
FROM gold_graph_edges
WHERE edge_type = 'flow'
  AND CAST(attrs:byte_count   AS BIGINT) > 1000000
  AND CAST(attrs:packet_count AS BIGINT) > 100
GROUP BY ALL
ORDER BY total_bytes DESC
"""))

# COMMAND ----------
# MAGIC %md ## Summary

# COMMAND ----------
result = {
    "vertices": int(vertices.count()),
    "edges": int(edges.count()),
    "top_degree_sample": [
        (r["id"], int(r["total_degree"])) for r in
        degree.orderBy(F.desc("total_degree")).select("id", "total_degree").limit(5).collect()
    ],
    "motif_chains_found": int(chains_count),
    "rogue_devices": rogue_ids,
}
import json
print(json.dumps(result, indent=2))
dbutils.notebook.exit(json.dumps(result))
