"""Thin wrapper around databricks-sql-connector for the FastAPI backend.

Uses the Databricks SDK Config() — credentials are picked up from the App runtime
environment (service-principal token) with no explicit DATABRICKS_TOKEN needed.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import numpy as np
from databricks import sql
from databricks.sdk.core import Config


def _to_python(v: Any) -> Any:
    """Recursively convert databricks-sql-connector return types into JSON-safe Python."""
    if v is None:
        return None
    if isinstance(v, np.ndarray):
        return [_to_python(x) for x in v.tolist()]
    if isinstance(v, np.generic):
        return v.item()
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, dict):
        return {k: _to_python(vv) for k, vv in v.items()}
    if isinstance(v, (list, tuple)):
        return [_to_python(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("utf-8")
        except Exception:
            return v.hex()
    if isinstance(v, str):
        # VARIANT columns arrive as JSON strings — leave as strings (clients can parse).
        return v
    return v


class DatabricksClient:
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.warehouse_id = os.environ["DATABRICKS_WAREHOUSE_ID"]
        self.catalog = os.environ.get("DATABRICKS_CATALOG", "retail_consumer_goods")
        self.schema = os.environ.get("DATABRICKS_SCHEMA", "network_anomaly_graph")
        self._config = Config()
        self._connection = None

    def _conn(self):
        with self._lock:
            if self._connection is None:
                self._connection = sql.connect(
                    server_hostname=self._config.host.replace("https://", "").rstrip("/"),
                    http_path=f"/sql/1.0/warehouses/{self.warehouse_id}",
                    credentials_provider=lambda: self._config.authenticate,
                )
            return self._connection

    def _reset(self) -> None:
        with self._lock:
            conn, self._connection = self._connection, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def query(self, q: str, params: dict[str, Any] | None = None) -> list[dict]:
        for attempt in (1, 2):
            cur = self._conn().cursor()
            try:
                cur.execute(f"USE CATALOG {self.catalog}")
                cur.execute(f"USE SCHEMA {self.schema}")
                cur.execute(q, params or {})
                cols = [d[0] for d in cur.description]
                return [
                    {c: _to_python(v) for c, v in zip(cols, row)}
                    for row in cur.fetchall()
                ]
            except sql.exc.RequestError:
                # Session went stale (idle timeout, warehouse restart). Drop the
                # cached connection and retry once with a fresh one.
                try:
                    cur.close()
                except Exception:
                    pass
                self._reset()
                if attempt == 2:
                    raise
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        raise RuntimeError("unreachable")


_client: DatabricksClient | None = None


def get_client() -> DatabricksClient:
    global _client
    if _client is None:
        _client = DatabricksClient()
    return _client
