"""FastAPI backend for the network anomaly knowledge-graph viewer.

Serves the built React app (Vite output in ../dist) at `/` and the read-only
graph API under `/api/*`. Authenticates to the SQL warehouse via the App
runtime's service principal (Databricks SDK Config picks this up automatically).
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .databricks_client import get_client

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("network-anomaly-app")

app = FastAPI(title="Network Anomaly Knowledge Graph")

CATALOG = os.environ.get("DATABRICKS_CATALOG", "retail_consumer_goods")
SCHEMA = os.environ.get("DATABRICKS_SCHEMA", "network_anomaly_graph")

# ----- API ------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "catalog": CATALOG, "schema": SCHEMA}


@app.get("/api/datasources")
def datasources() -> dict[str, Any]:
    """Return the UC tables that back the app, plus a workspace base URL for
    constructing deep links into UC Explorer."""
    from databricks.sdk.core import Config as _Config
    cfg = _Config()
    workspace_url = (cfg.host or "").rstrip("/")

    def t(name: str, layer: str, kind: str, description: str) -> dict[str, Any]:
        return {
            "name": name,
            "fqn": f"{CATALOG}.{SCHEMA}.{name}",
            "layer": layer,
            "kind": kind,
            "description": description,
            "explorer_url": f"{workspace_url}/explore/data/{CATALOG}/{SCHEMA}/{name}",
        }

    tables = [
        # Gold — graph
        t("gold_graph_nodes", "gold", "MV",
          "The knowledge-graph node table. Unions hosts, subnets, services, external IPs. Carries VARIANT attrs per node type."),
        t("gold_graph_edges", "gold", "MV",
          "The knowledge-graph edge table. flow / resolves / hosts / in_subnet edges. VARIANT attrs hold ports, byte/packet counts, anomaly evidence."),
        # Gold — anomaly detectors
        t("gold_anomaly_scan", "gold", "MV",
          "Port-scan detector: hosts emitting flows to ≥30 distinct destinations on ≥30 distinct ports in a 10-min window."),
        t("gold_anomaly_lateral", "gold", "MV",
          "Lateral-movement detector: 3-hop cross-zone chains within a 15-min window."),
        t("gold_anomaly_exfil", "gold", "MV",
          "Data-exfiltration detector: >5 MB outbound to a single external IP in a 5-min window."),
        t("gold_anomaly_rogue", "gold", "MV",
          "Rogue-device detector: internal hosts with zero flow peers AND suspicious DNS lookups."),
        t("gold_anomaly_ddos", "gold", "MV",
          "DDoS-target detector: targets receiving traffic from ≥50 distinct sources in a 5-min window."),
        # Silver
        t("silver_hosts", "silver", "MV", "Hosts enriched with their subnet zone."),
        t("silver_services", "silver", "MV", "Service catalog joined to host metadata."),
        t("silver_flows", "silver", "MV", "Network flows enriched with src/dst host + zone metadata."),
        t("silver_dns", "silver", "MV", "DNS queries with a suspicious-TLD flag."),
        # Bronze
        t("bronze_subnets", "bronze", "TABLE", "Raw subnet inventory (subnet_id, cidr, zone)."),
        t("bronze_hosts", "bronze", "TABLE", "Raw host inventory (host_id, hostname, ip, subnet, type, criticality)."),
        t("bronze_services", "bronze", "TABLE", "Raw service catalog (service_id, host_id, port, protocol)."),
        t("bronze_network_flows", "bronze", "TABLE", "Raw network flow logs (~25K rows including seeded anomalies)."),
        t("bronze_dns_queries", "bronze", "TABLE", "Raw DNS query log (~5K rows including suspicious-TLD lookups)."),
    ]
    return {"workspace_url": workspace_url, "catalog": CATALOG, "schema": SCHEMA, "tables": tables}


@app.get("/api/graph")
def get_graph(limit: int = Query(default=2000, ge=1, le=10000)) -> dict[str, Any]:
    """Return nodes + edges for the graph viewer.

    Edges are capped to `limit` (most-anomalous + highest-traffic first), and
    only nodes referenced by those edges are returned.
    """
    cli = get_client()
    edges = cli.query(
        f"""
        SELECT
          src_id, dst_id, edge_type, packet_count, byte_count,
          is_cross_zone, is_anomalous, anomaly_label, anomaly_score,
          CAST(last_seen_ts AS STRING) AS last_seen_ts
        FROM gold_graph_edges
        ORDER BY is_anomalous DESC, anomaly_score DESC, byte_count DESC
        LIMIT {int(limit)}
        """
    )
    node_ids = set()
    for e in edges:
        node_ids.add(e["src_id"])
        node_ids.add(e["dst_id"])
    if not node_ids:
        return {"nodes": [], "edges": []}

    in_clause = ", ".join("'" + n.replace("'", "''") + "'" for n in node_ids)
    nodes = cli.query(
        f"""
        SELECT
          node_id, node_type, label, host_type, subnet_id, is_external,
          anomaly_score, anomaly_labels
        FROM gold_graph_nodes
        WHERE node_id IN ({in_clause})
        """
    )

    # Defense in depth: never ship orphan edges. If gold_graph_nodes is missing
    # any node id referenced by an edge (e.g. a DNS-resolves edge pointing at
    # an external IP that the nodes MV didn't include), d3-force throws
    # "node not found" in the browser and the canvas never renders. Drop any
    # such edges and log a count so we notice a schema regression in the
    # logs even when the UI keeps working.
    actual_ids = {n["node_id"] for n in nodes}
    clean_edges = [e for e in edges if e["src_id"] in actual_ids and e["dst_id"] in actual_ids]
    dropped = len(edges) - len(clean_edges)
    if dropped:
        log.warning("dropped %d orphan edges (endpoints missing from gold_graph_nodes)", dropped)

    log.info("graph payload: %d nodes, %d edges", len(nodes), len(clean_edges))
    return {"nodes": nodes, "edges": clean_edges}


@app.get("/api/search")
def search(q: str = Query(..., min_length=1)) -> list[dict[str, Any]]:
    cli = get_client()
    pat = f"%{q.replace('%', '')}%"
    rows = cli.query(
        f"""
        SELECT node_id, label, node_type, host_type, anomaly_score, anomaly_labels
        FROM gold_graph_nodes
        WHERE lower(node_id) LIKE lower('{pat}')
           OR lower(label) LIKE lower('{pat}')
           OR EXISTS (
             SELECT 1 FROM (SELECT explode(anomaly_labels) AS l) WHERE lower(l) LIKE lower('{pat}')
           )
        ORDER BY anomaly_score DESC, label
        LIMIT 50
        """
    )
    return rows


@app.get("/api/anomalies")
def anomalies() -> dict[str, Any]:
    cli = get_client()
    rows = cli.query(
        """
        SELECT 'port_scan' AS anomaly_type, COUNT(*) AS count FROM gold_anomaly_scan
        UNION ALL SELECT 'lateral_movement', COUNT(*) FROM gold_anomaly_lateral
        UNION ALL SELECT 'data_exfiltration', COUNT(*) FROM gold_anomaly_exfil
        UNION ALL SELECT 'rogue_device', COUNT(*) FROM gold_anomaly_rogue
        UNION ALL SELECT 'ddos', COUNT(*) FROM gold_anomaly_ddos
        """
    )
    sample_nodes = cli.query(
        """
        SELECT node_id, label, anomaly_labels, anomaly_score
        FROM gold_graph_nodes
        WHERE anomaly_score > 0
        ORDER BY anomaly_score DESC
        LIMIT 100
        """
    )
    by_type: dict[str, list[dict]] = defaultdict(list)
    for n in sample_nodes:
        for lbl in (n.get("anomaly_labels") or []):
            by_type[lbl].append({"node_id": n["node_id"], "label": n["label"], "score": float(n["anomaly_score"])})
    return {
        "counts": rows,
        "samples": by_type,
    }


@app.get("/api/node/{node_id}")
def get_node(node_id: str) -> dict[str, Any]:
    cli = get_client()
    safe = node_id.replace("'", "''")
    nodes = cli.query(
        f"SELECT * FROM gold_graph_nodes WHERE node_id = '{safe}'"
    )
    if not nodes:
        raise HTTPException(status_code=404, detail="node not found")
    neighbors = cli.query(
        f"""
        SELECT src_id, dst_id, edge_type, packet_count, byte_count,
               is_anomalous, anomaly_label, anomaly_score
        FROM gold_graph_edges
        WHERE src_id = '{safe}' OR dst_id = '{safe}'
        ORDER BY anomaly_score DESC, byte_count DESC
        LIMIT 200
        """
    )
    return {"node": nodes[0], "neighbors": neighbors}


# ----- Static React build ---------------------------------------------------

DIST_DIR = Path(__file__).resolve().parent.parent / "dist"
if DIST_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DIST_DIR), html=True), name="static")
    log.info("Serving static React build from %s", DIST_DIR)
else:
    log.warning("React build (%s) not found — only /api routes will work.", DIST_DIR)


@app.on_event("startup")
def _on_start() -> None:
    log.info("✅ Initialized real backend: %s.%s", CATALOG, SCHEMA)
