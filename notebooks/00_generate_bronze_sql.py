# Databricks notebook source
# MAGIC %md
# MAGIC # 00 — Generate Bronze SQL Files
# MAGIC
# MAGIC Generates synthetic network-traffic data and writes it to a set of SQL files in the
# MAGIC bundle's workspace `data/` directory. These SQL files are then consumed by notebook
# MAGIC `01_load_bronze_from_sql` to populate the `bronze_*` tables.
# MAGIC
# MAGIC Seeded anomalies:
# MAGIC - 1× port-scan: one host emits flows to 200+ destinations on sequential ports
# MAGIC - 2× lateral-movement chains: 3-hop sequence across zones
# MAGIC - 1× exfiltration: large outbound flow to an external IP
# MAGIC - 3× rogue devices: zero flow peers + suspicious DNS lookups
# MAGIC - 1× DDoS: ~150 hosts pinging a single target

# COMMAND ----------
# Dependencies (faker, numpy, pandas) are installed via the job environment
# spec in resources/jobs.yml. No %pip install needed here.

# COMMAND ----------
dbutils.widgets.text("catalog", "retail_consumer_goods")
dbutils.widgets.text("schema", "network_anomaly_graph")
dbutils.widgets.text("volume", "bronze_landing")
CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
VOLUME = dbutils.widgets.get("volume")
print(f"Generating into {CATALOG}.{SCHEMA} (volume {VOLUME})")

# COMMAND ----------
# MAGIC %md ## Configuration

# COMMAND ----------
import random
import json
from datetime import datetime, timedelta
from faker import Faker

SEED = 42
random.seed(SEED)
fake = Faker()
Faker.seed(SEED)

N_SUBNETS = 24
N_HOSTS = 2000           # mix of workstation/server/gateway/iot/external
N_SERVICES = 800
N_FLOWS_BASE = 25000     # plus the seeded-anomaly flows
N_DNS = 5000

END_DATE = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
START_DATE = END_DATE - timedelta(days=14)

# Where the generated SQL files go. The bundle deploys this notebook into
# /Workspace/.../<bundle>/files/notebooks/, and `data/` is a sibling directory.
import os
NOTEBOOK_PATH = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
BUNDLE_ROOT = "/Workspace" + os.path.dirname(os.path.dirname(NOTEBOOK_PATH))
DATA_DIR = f"{BUNDLE_ROOT}/data"
print(f"Bundle root: {BUNDLE_ROOT}")
print(f"Writing SQL files to: {DATA_DIR}")

# COMMAND ----------
# MAGIC %md ## 1 — Subnets

# COMMAND ----------
ZONES = ["corporate", "dmz", "guest", "iot", "external"]
subnets = []
for i in range(N_SUBNETS):
    zone = ZONES[i % len(ZONES)]
    subnets.append({
        "subnet_id": f"SUB-{i:03d}",
        "cidr": f"10.{i+1}.0.0/16" if zone != "external" else f"203.0.{113+i}.0/24",
        "zone": zone,
        "description": f"{zone} subnet #{i+1}",
    })
print(f"Generated {len(subnets)} subnets")

# COMMAND ----------
# MAGIC %md ## 2 — Hosts

# COMMAND ----------
HOST_TYPES_BY_ZONE = {
    "corporate": [("workstation", 0.75), ("server", 0.2), ("gateway", 0.05)],
    "dmz":       [("server", 0.85), ("gateway", 0.15)],
    "guest":     [("workstation", 1.0)],
    "iot":       [("iot", 1.0)],
    "external":  [("external", 1.0)],
}

def pick(weighted):
    r = random.random()
    cum = 0
    for v, w in weighted:
        cum += w
        if r <= cum:
            return v
    return weighted[-1][0]

hosts = []
ROGUE_HOST_IDS = []
for i in range(N_HOSTS):
    subnet = random.choice(subnets)
    host_type = pick(HOST_TYPES_BY_ZONE[subnet["zone"]])
    octets = subnet["cidr"].split("/")[0].split(".")
    ip = f"{octets[0]}.{octets[1]}.{random.randint(1, 250)}.{random.randint(1, 250)}"
    hosts.append({
        "host_id": f"H-{i:04d}",
        "hostname": f"{host_type[:3]}-{i:04d}-{fake.word()}",
        "ip": ip,
        "subnet_id": subnet["subnet_id"],
        "host_type": host_type,
        "os": random.choice(["Win11", "Win10", "Ubuntu22", "RHEL9", "iOS", "Android", "Embedded"]),
        "owner": fake.name(),
        "criticality": random.choice([1, 2, 3, 4, 5]),
    })

# pick 5 rogue hosts (corporate workstations with no normal traffic)
rogue_candidates = [h for h in hosts if h["host_type"] == "workstation"][:5]
for h in rogue_candidates:
    ROGUE_HOST_IDS.append(h["host_id"])
print(f"Generated {len(hosts)} hosts; rogues = {ROGUE_HOST_IDS}")

# COMMAND ----------
# MAGIC %md ## 3 — Services

# COMMAND ----------
COMMON_SERVICES = [
    (22, "tcp", "ssh"), (80, "tcp", "http"), (443, "tcp", "https"),
    (3389, "tcp", "rdp"), (445, "tcp", "smb"), (53, "udp", "dns"),
    (1433, "tcp", "mssql"), (5432, "tcp", "postgres"), (3306, "tcp", "mysql"),
    (8080, "tcp", "http-alt"), (9000, "tcp", "internal-api"),
]
server_hosts = [h for h in hosts if h["host_type"] in ("server", "gateway")]
services = []
for i in range(N_SERVICES):
    h = random.choice(server_hosts)
    port, proto, name = random.choice(COMMON_SERVICES)
    services.append({
        "service_id": f"SVC-{i:04d}",
        "host_id": h["host_id"],
        "port": port,
        "protocol": proto,
        "service_name": name,
    })
print(f"Generated {len(services)} services")

# COMMAND ----------
# MAGIC %md ## 4 — Network Flows (with seeded anomalies)

# COMMAND ----------
def random_ts():
    delta = END_DATE - START_DATE
    seconds = random.randint(0, int(delta.total_seconds()))
    return (START_DATE + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")

flows = []
flow_idx = [0]
# OCSF Network Activity class_uid = 4001; activity_id 6 = "Traffic"; type_uid = 4001*100+6 = 400106
OCSF_NETWORK_CLASS_UID = 4001
OCSF_NETWORK_ACTIVITY_ID = 6
OCSF_NETWORK_TYPE_UID = 400106
def add_flow(src_h, dst_h, dst_ip, src_port, dst_port, packets, bytes_, ts=None, protocol="tcp"):
    flows.append({
        "flow_id": f"F-{flow_idx[0]:07d}",
        "time": ts or random_ts(),
        "src_host_id": src_h,
        "dst_host_id": dst_h,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol_name": protocol,
        "traffic_packets": packets,
        "traffic_bytes": bytes_,
        "duration": random.randint(10, 5000),
        "class_uid": OCSF_NETWORK_CLASS_UID,
        "activity_id": OCSF_NETWORK_ACTIVITY_ID,
        "type_uid": OCSF_NETWORK_TYPE_UID,
        "severity_id": 1,  # OCSF: 1 = Informational (raw flow; analysis later)
    })
    flow_idx[0] += 1

# Normal traffic — mostly intra-zone, weighted toward servers/gateways
gateways = [h for h in hosts if h["host_type"] == "gateway"]
servers = [h for h in hosts if h["host_type"] == "server"]
workstations = [h for h in hosts if h["host_type"] == "workstation"]
iot_hosts = [h for h in hosts if h["host_type"] == "iot"]
externals = [h for h in hosts if h["host_type"] == "external"]
internal_hosts = [h for h in hosts if h["host_type"] not in ("external",)]
# Exclude rogues from normal traffic
normal_internal = [h for h in internal_hosts if h["host_id"] not in ROGUE_HOST_IDS]

for _ in range(N_FLOWS_BASE):
    src = random.choice(normal_internal)
    # 70% to servers in same zone, 20% to gateway, 10% to external
    r = random.random()
    if r < 0.7:
        dst = random.choice(servers) if servers else random.choice(normal_internal)
        dst_host = dst["host_id"]; dst_ip = None
    elif r < 0.9 and gateways:
        dst = random.choice(gateways)
        dst_host = dst["host_id"]; dst_ip = None
    else:
        dst = None
        dst_host = None
        dst_ip = fake.ipv4_public()
    add_flow(
        src["host_id"], dst_host, dst_ip,
        random.randint(1024, 65000),
        random.choice([80, 443, 22, 3389, 53, 5432]),
        random.randint(5, 500),
        int(abs(random.lognormvariate(7, 1))),  # bytes
    )

# COMMAND ----------
# MAGIC %md ### Seed anomaly 1: PORT SCAN

# COMMAND ----------
scanner = random.choice([h for h in workstations if h["host_id"] not in ROGUE_HOST_IDS])
scan_ts = (END_DATE - timedelta(days=2, hours=10)).strftime("%Y-%m-%d %H:%M:%S")
scan_start = END_DATE - timedelta(days=2, hours=10)
targets = random.sample([h for h in normal_internal if h["host_id"] != scanner["host_id"]], 60)
for i, tgt in enumerate(targets):
    for port in random.sample(range(1, 1500), 6):
        add_flow(
            scanner["host_id"], tgt["host_id"], None,
            random.randint(40000, 60000), port,
            random.randint(1, 3), random.randint(60, 200),
            ts=(scan_start + timedelta(seconds=i * 3 + random.randint(0, 2))).strftime("%Y-%m-%d %H:%M:%S"),
        )
print(f"Seeded port-scan: scanner={scanner['host_id']} → {len(targets)} targets, ~360 flows")

# COMMAND ----------
# MAGIC %md ### Seed anomaly 2: LATERAL MOVEMENT CHAINS (×2)

# COMMAND ----------
def seed_lateral_chain(label_offset):
    # Pick four hosts in different zones
    hops = []
    for zone in ["corporate", "iot", "dmz", "corporate"]:
        candidates = [h for h in normal_internal if any(s["subnet_id"] == h["subnet_id"] and s["zone"] == zone for s in subnets)]
        if not candidates:
            return None
        hops.append(random.choice(candidates))
    base = END_DATE - timedelta(hours=label_offset)
    for i in range(3):
        add_flow(
            hops[i]["host_id"], hops[i + 1]["host_id"], None,
            random.randint(40000, 60000), random.choice([22, 3389, 445]),
            random.randint(10, 80), random.randint(5000, 50000),
            ts=(base + timedelta(minutes=i * 4)).strftime("%Y-%m-%d %H:%M:%S"),
        )
    return [h["host_id"] for h in hops]

chain1 = seed_lateral_chain(label_offset=20)
chain2 = seed_lateral_chain(label_offset=72)
chain3 = seed_lateral_chain(label_offset=120)
print(f"Seeded lateral chains: {chain1}, {chain2}, {chain3}")

# COMMAND ----------
# MAGIC %md ### Seed anomaly 3: DATA EXFILTRATION

# COMMAND ----------
exfil_src = random.choice(servers)
exfil_dst_ip = "185.220.101.42"   # well-known suspicious-looking external IP
exfil_base = END_DATE - timedelta(days=1, hours=6)
for i in range(20):
    add_flow(
        exfil_src["host_id"], None, exfil_dst_ip,
        random.randint(40000, 60000), 443,
        random.randint(5000, 20000), random.randint(500_000, 2_000_000),
        ts=(exfil_base + timedelta(seconds=i * 12)).strftime("%Y-%m-%d %H:%M:%S"),
    )
print(f"Seeded exfiltration: src={exfil_src['host_id']} → {exfil_dst_ip} (~25 MB)")

# COMMAND ----------
# MAGIC %md ### Seed anomaly 4: DDoS target

# COMMAND ----------
ddos_target = random.choice(servers)
ddos_base = END_DATE - timedelta(hours=3)
sources = random.sample(normal_internal, min(150, len(normal_internal)))
for src in sources:
    if src["host_id"] == ddos_target["host_id"]:
        continue
    add_flow(
        src["host_id"], ddos_target["host_id"], None,
        random.randint(1024, 65000), 443,
        random.randint(50, 200), random.randint(2000, 8000),
        ts=(ddos_base + timedelta(seconds=random.randint(0, 240))).strftime("%Y-%m-%d %H:%M:%S"),
    )
print(f"Seeded DDoS: target={ddos_target['host_id']} from {len(sources)} sources")

# COMMAND ----------
# MAGIC %md ## 5 — DNS Queries (with suspicious TLD lookups for rogues)

# COMMAND ----------
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".click", ".ru", ".pw"]
# OCSF DNS Activity class_uid = 4003; activity_id 1 = "Query"; type_uid = 4003*100+1 = 400301
OCSF_DNS_CLASS_UID = 4003
OCSF_DNS_ACTIVITY_ID = 1
OCSF_DNS_TYPE_UID = 400301
dns_rows = []
for i in range(N_DNS):
    src = random.choice(normal_internal)
    dns_rows.append({
        "query_id": f"DNS-{i:06d}",
        "time": random_ts(),
        "src_host_id": src["host_id"],
        "query_hostname": fake.domain_name(),
        "query_type": random.choice(["A", "AAAA", "CNAME", "MX"]),
        "rcode_id": random.choice([0, 0, 0, 0, 3]),
        "answer_ip": fake.ipv4_public(),
        "class_uid": OCSF_DNS_CLASS_UID,
        "activity_id": OCSF_DNS_ACTIVITY_ID,
        "type_uid": OCSF_DNS_TYPE_UID,
        "severity_id": 1,
    })

# Rogue devices: emit suspicious DNS lookups (but no flows — already excluded from normal traffic)
for rogue_id in ROGUE_HOST_IDS:
    for j in range(8):
        domain = f"{fake.word()}{fake.word()}{random.choice(SUSPICIOUS_TLDS)}"
        dns_rows.append({
            "query_id": f"DNS-R-{rogue_id}-{j}",
            "time": random_ts(),
            "src_host_id": rogue_id,
            "query_hostname": domain,
            "query_type": "A",
            "rcode_id": 0,
            "answer_ip": fake.ipv4_public(),
            "class_uid": OCSF_DNS_CLASS_UID,
            "activity_id": OCSF_DNS_ACTIVITY_ID,
            "type_uid": OCSF_DNS_TYPE_UID,
            "severity_id": 2,  # 2 = Low — suspicious TLD lookups are mildly elevated
        })
print(f"Generated {len(dns_rows)} DNS rows")

# COMMAND ----------
# MAGIC %md ## 6 — Emit SQL Files

# COMMAND ----------
def sql_str(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v).replace("'", "''")
    return f"'{s}'"

def emit_sql(table, col_defs, rows, table_comment, cluster_by, chunk_size=500):
    """Generate CREATE TABLE + TRUNCATE + chunked INSERT statements.

    col_defs is a list of (name, type, comment) triples — comments end up on
    the column metadata in UC and show up in the UC Explorer schema view.
    cluster_by is a list of column names for Liquid Clustering (empty for tiny dim tables).
    Row tracking is enabled so downstream materialized views can incrementally refresh.
    Change data feed is enabled so external CDC consumers can subscribe.
    """
    cols = [name for name, _t, _c in col_defs]
    col_lines = ",\n  ".join(
        f"{name} {typ} COMMENT '{comment.replace(chr(39), chr(39) * 2)}'"
        for name, typ, comment in col_defs
    )
    # DROP + CREATE (not CREATE IF NOT EXISTS) so schema evolution from OCSF
    # field renames takes effect when this file is replayed. The downstream
    # SDP pipeline runs a full refresh anyway.
    drop = f"DROP TABLE IF EXISTS {CATALOG}.{SCHEMA}.{table};"
    create = (
        f"CREATE TABLE {CATALOG}.{SCHEMA}.{table} (\n  "
        + col_lines
        + "\n)\n"
        f"COMMENT '{table_comment.replace(chr(39), chr(39) * 2)}'"
    )
    if cluster_by:
        create += f"\nCLUSTER BY ({', '.join(cluster_by)})"
    create += "\nTBLPROPERTIES (\n  'delta.enableRowTracking' = 'true',\n  'delta.enableChangeDataFeed' = 'true'\n);"
    parts = [drop, create]
    for i in range(0, len(rows), chunk_size):
        batch = rows[i : i + chunk_size]
        values = ",\n  ".join(
            "(" + ", ".join(sql_str(r[c]) for c in cols) + ")"
            for r in batch
        )
        parts.append(
            f"INSERT INTO {CATALOG}.{SCHEMA}.{table} ({', '.join(cols)}) VALUES\n  {values};"
        )
    return "\n\n".join(parts) + "\n"

# Bronze table column metadata + Liquid clustering keys.
# Comments propagate to UC Explorer + Genie + downstream catalogs.
files = [
    ("01_subnets.sql", "bronze_subnets",
        [
            ("subnet_id",   "STRING", "Stable subnet identifier (PK). Format SUB-NNN. OCSF mapping: Network.uid."),
            ("cidr",        "STRING", "CIDR block this subnet covers (e.g. 10.5.0.0/16). OCSF: Network.subnet."),
            ("zone",        "STRING", "Security zone: corporate | dmz | guest | iot | external. OCSF extension: zone_name."),
            ("description", "STRING", "Human-readable subnet description."),
        ],
        subnets,
        "Raw subnet inventory — 24 zoned subnets across corporate, dmz, guest, iot, and external. Maps to OCSF Network object. Loaded from data/01_subnets.sql.",
        []),
    ("02_hosts.sql", "bronze_hosts",
        [
            ("host_id",     "STRING", "Stable host identifier (PK). Format H-NNNN. OCSF mapping: Device.uid."),
            ("hostname",    "STRING", "Friendly hostname assigned by IT. OCSF: Device.hostname."),
            ("ip",          "STRING", "Primary IPv4 address. OCSF: Device.ip."),
            ("subnet_id",   "STRING", "FK to bronze_subnets.subnet_id. OCSF: Device.network_uid."),
            ("host_type",   "STRING", "workstation | server | gateway | iot | external. OCSF: Device.type."),
            ("os",          "STRING", "Operating system identifier. OCSF: Device.os.name."),
            ("owner",       "STRING", "Person or team accountable for the host. OCSF extension: Device.owner."),
            ("criticality", "INT",    "Business criticality 1 (lowest) - 5 (highest). OCSF: Device.risk_level."),
        ],
        hosts,
        "Raw host inventory — 2,000 hosts. Maps to OCSF Device object (entity, not an event). Includes 5 seeded rogue devices. Loaded from data/02_hosts.sql.",
        ["host_id", "subnet_id"]),
    ("03_services.sql", "bronze_services",
        [
            ("service_id",   "STRING", "Stable service identifier (PK). Format SVC-NNNN. OCSF: Service.uid (custom)."),
            ("host_id",      "STRING", "FK to bronze_hosts.host_id. OCSF: Service.device.uid."),
            ("port",         "INT",    "TCP/UDP port the service listens on. OCSF: Service.port."),
            ("protocol",     "STRING", "Transport protocol: tcp | udp. OCSF: Service.protocol_name."),
            ("service_name", "STRING", "Common service name (ssh, http, https, rdp, mssql, postgres, ...). OCSF: Service.name."),
        ],
        services,
        "Raw service catalog — ~800 listening services on server + gateway hosts. Custom object aligned with OCSF Service-style naming. Loaded from data/03_services.sql.",
        ["host_id"]),
    ("04_network_flows.sql", "bronze_network_flows",
        [
            ("flow_id",         "STRING", "Stable flow identifier (PK). Format F-NNNNNNN. OCSF: metadata.uid."),
            ("time",            "STRING", "Flow timestamp in ISO format (YYYY-MM-DD HH:MM:SS). OCSF: time."),
            ("src_host_id",     "STRING", "FK to bronze_hosts.host_id. OCSF: src_endpoint.uid."),
            ("dst_host_id",     "STRING", "FK to bronze_hosts.host_id (NULL when destination is external). OCSF: dst_endpoint.uid."),
            ("dst_ip",          "STRING", "Destination IPv4 (populated when external). OCSF: dst_endpoint.ip."),
            ("src_port",        "INT",    "Source ephemeral port. OCSF: src_endpoint.port."),
            ("dst_port",        "INT",    "Destination port. OCSF: dst_endpoint.port."),
            ("protocol_name",   "STRING", "Transport protocol (tcp | udp). OCSF: connection_info.protocol_name."),
            ("traffic_packets", "BIGINT", "Packets transferred. OCSF: traffic.packets."),
            ("traffic_bytes",   "BIGINT", "Bytes transferred. OCSF: traffic.bytes."),
            ("duration",        "INT",    "Flow duration in milliseconds. OCSF: duration."),
            ("class_uid",       "INT",    "OCSF class identifier. 4001 = Network Activity."),
            ("activity_id",     "INT",    "OCSF activity within the class. 6 = Traffic."),
            ("type_uid",        "INT",    "OCSF type_uid = class_uid*100 + activity_id = 400106."),
            ("severity_id",     "INT",    "OCSF severity_id. 1 = Informational (raw observation)."),
        ],
        flows,
        "Raw network flow log — ~25K flows. Conforms to OCSF Network Activity event class (class_uid=4001). Includes seeded port scan (H-1027), 3 lateral-movement chains, data exfiltration (H-1793 → 185.220.101.42, ~25 MB), and DDoS target (H-1447). Loaded from data/04_network_flows.sql.",
        ["src_host_id", "dst_host_id", "time"]),
    ("05_dns_queries.sql", "bronze_dns_queries",
        [
            ("query_id",       "STRING", "Stable DNS query identifier (PK). Format DNS-NNNNNN. OCSF: metadata.uid."),
            ("time",           "STRING", "Query timestamp in ISO format. OCSF: time."),
            ("src_host_id",    "STRING", "FK to bronze_hosts.host_id. OCSF: src_endpoint.uid."),
            ("query_hostname", "STRING", "Queried domain name. OCSF: query.hostname."),
            ("query_type",     "STRING", "DNS record type (A | AAAA | CNAME | MX). OCSF: query.type."),
            ("rcode_id",       "INT",    "DNS response code (0=NOERROR, 3=NXDOMAIN). OCSF: rcode_id."),
            ("answer_ip",      "STRING", "IPv4 returned by the resolver. OCSF: answers[0].rdata (flattened)."),
            ("class_uid",      "INT",    "OCSF class identifier. 4003 = DNS Activity."),
            ("activity_id",    "INT",    "OCSF activity within the class. 1 = Query."),
            ("type_uid",       "INT",    "OCSF type_uid = class_uid*100 + activity_id = 400301."),
            ("severity_id",    "INT",    "OCSF severity_id. 1 = Informational; 2 = Low for suspicious-TLD lookups."),
        ],
        dns_rows,
        "Raw DNS query log — ~5K queries. Conforms to OCSF DNS Activity event class (class_uid=4003). Includes seeded rogue-device lookups to suspicious TLDs. Loaded from data/05_dns_queries.sql.",
        ["src_host_id", "time"]),
]

dbutils.fs.mkdirs(DATA_DIR)
for filename, table, col_defs, rows, table_comment, cluster_by in files:
    body = emit_sql(table, col_defs, rows, table_comment, cluster_by)
    path = f"{DATA_DIR}/{filename}"
    dbutils.fs.put(path, body, overwrite=True)
    cluster_str = f"CLUSTER BY ({', '.join(cluster_by)})" if cluster_by else "(no clustering)"
    print(f"Wrote {path} ({len(rows)} rows, {len(body):,} bytes) {cluster_str}")

# COMMAND ----------
# MAGIC %md ## 7 — Summary

# COMMAND ----------
summary = {
    "subnets": len(subnets),
    "hosts": len(hosts),
    "services": len(services),
    "flows": len(flows),
    "dns_queries": len(dns_rows),
    "rogue_hosts": ROGUE_HOST_IDS,
    "port_scan_source": scanner["host_id"],
    "lateral_chain_1": chain1,
    "lateral_chain_2": chain2,
    "lateral_chain_3": chain3,
    "exfil_source": exfil_src["host_id"],
    "ddos_target": ddos_target["host_id"],
    "data_dir": DATA_DIR,
}
print(json.dumps(summary, indent=2))
dbutils.notebook.exit(json.dumps(summary))
