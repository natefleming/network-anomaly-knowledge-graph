import { useEffect, useState } from "react";
import type { GraphNode } from "../types";
import { api } from "../lib/api";
import { ANOMALY_LABELS } from "../lib/styling";

interface Props {
  onPick: (n: GraphNode) => void;
  onHighlight: (ids: string[]) => void;
}

export function SearchBar({ onPick, onHighlight }: Props) {
  const [q, setQ] = useState("");
  const [results, setResults] = useState<GraphNode[]>([]);

  useEffect(() => {
    if (q.trim().length === 0) {
      setResults([]);
      onHighlight([]);
      return;
    }
    let cancel = false;
    const t = setTimeout(async () => {
      try {
        const rows = await api.search(q);
        if (!cancel) {
          setResults(rows);
          onHighlight(rows.map((r) => r.node_id));
        }
      } catch {
        if (!cancel) setResults([]);
      }
    }, 200);
    return () => {
      cancel = true;
      clearTimeout(t);
    };
  }, [q, onHighlight]);

  return (
    <div className="search">
      <input
        placeholder="Hostname, IP, or anomaly type…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
      />
      <div className="results">
        {results.map((r) => (
          <div
            key={r.node_id}
            className="result-row"
            onClick={() => onPick(r)}
          >
            <span>{r.label}</span>
            <span className="meta">
              {r.host_type || r.node_type}
              {r.anomaly_labels && r.anomaly_labels.length > 0
                ? " · " +
                  r.anomaly_labels
                    .map((l) => ANOMALY_LABELS[l] || l)
                    .join(", ")
                : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
