import { useEffect, useState } from "react";

interface Table {
  name: string;
  fqn: string;
  layer: "bronze" | "silver" | "gold";
  kind: string;
  description: string;
  explorer_url: string;
}

interface DataSourcesPayload {
  workspace_url: string;
  catalog: string;
  schema: string;
  tables: Table[];
}

const LAYER_ORDER: Array<Table["layer"]> = ["gold", "silver", "bronze"];
const LAYER_LABELS: Record<Table["layer"], string> = {
  gold: "Gold — graph + anomalies",
  silver: "Silver — enriched",
  bronze: "Bronze — raw",
};
const LAYER_PILL: Record<Table["layer"], string> = {
  gold: "ds-pill-gold",
  silver: "ds-pill-silver",
  bronze: "ds-pill-bronze",
};

export function DataSources() {
  const [data, setData] = useState<DataSourcesPayload | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({
    gold: false,
    silver: false,
    bronze: false,
  });

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const r = await fetch("/api/datasources");
        const d = await r.json();
        if (live) setData(d);
      } catch {
        /* swallow */
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  if (!data) return <div className="result-row">loading…</div>;

  const byLayer = (l: Table["layer"]) => data.tables.filter((t) => t.layer === l);

  return (
    <div className="datasources">
      <div className="ds-meta">
        <code>{data.catalog}.{data.schema}</code>
        <a
          className="ds-uc-root"
          href={`${data.workspace_url}/explore/data/${data.catalog}/${data.schema}`}
          target="_blank"
          rel="noreferrer"
          title="Open this schema in Unity Catalog Explorer"
        >
          Open in UC ↗
        </a>
      </div>
      {LAYER_ORDER.map((layer) => {
        const tables = byLayer(layer);
        if (!tables.length) return null;
        const isOpen = open[layer];
        return (
          <div key={layer} className="ds-group">
            <button
              className="ds-group-header"
              onClick={() => setOpen({ ...open, [layer]: !isOpen })}
            >
              <span className={"ds-pill " + LAYER_PILL[layer]}>
                {layer}
              </span>
              <span className="ds-group-label">{LAYER_LABELS[layer]}</span>
              <span className="ds-group-count">{tables.length}</span>
              <span className="ds-chevron">{isOpen ? "▾" : "▸"}</span>
            </button>
            {isOpen && (
              <div className="ds-tables">
                {tables.map((t) => (
                  <a
                    key={t.name}
                    href={t.explorer_url}
                    target="_blank"
                    rel="noreferrer"
                    className="ds-table"
                    title={t.description}
                  >
                    <div className="ds-table-name">
                      {t.name}
                      <span className="ds-kind">{t.kind}</span>
                    </div>
                    <div className="ds-table-desc">{t.description}</div>
                  </a>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
