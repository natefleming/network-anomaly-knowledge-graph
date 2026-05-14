import { useState } from "react";
import type { AnomalyCounts, AnomalyType } from "../types";
import { ANOMALY_LABELS } from "../lib/styling";
import { ANOMALY_DEFS } from "../lib/anomalyDefs";

interface Props {
  data: AnomalyCounts;
  onPick: (nodeId: string) => void;
  onHighlightType: (t: AnomalyType) => void;
}

const ORDER: AnomalyType[] = [
  "port_scan",
  "lateral_movement",
  "data_exfiltration",
  "rogue_device",
  "ddos",
  "suspicious_dns",
];

export function AnomalyPanel({ data, onPick, onHighlightType }: Props) {
  const counts = new Map(data.counts.map((c) => [c.anomaly_type, c.count]));
  const [openInfo, setOpenInfo] = useState<AnomalyType | null>(null);
  return (
    <div>
      {ORDER.map((t) => {
        const c = Number(counts.get(t) || 0);
        const samples = data.samples[t] || [];
        if (c === 0 && samples.length === 0) return null;
        const def = ANOMALY_DEFS[t];
        return (
          <div key={t} className="anomaly-tile">
            <div
              className="anomaly-tile-header"
              onClick={() => onHighlightType(t)}
            >
              <span className="title-text">
                {ANOMALY_LABELS[t] || t}
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span className="count">{c}</span>
                <button
                  className="info-btn"
                  title={`How "${ANOMALY_LABELS[t] || t}" is detected`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpenInfo((cur) => (cur === t ? null : t));
                  }}
                >
                  ⓘ
                </button>
              </span>
            </div>
            {samples.slice(0, 3).map((s) => (
              <div
                key={s.node_id}
                className="sample"
                onClick={(e) => {
                  e.stopPropagation();
                  onPick(s.node_id);
                }}
              >
                {s.label} · score {s.score.toFixed(2)}
              </div>
            ))}
            {openInfo === t && def && (
              <div className="anomaly-info">
                <div className="anomaly-info-row">
                  <div className="anomaly-info-label">What it is</div>
                  <div>{def.shortDescription}</div>
                </div>
                <div className="anomaly-info-row">
                  <div className="anomaly-info-label">Detection rule</div>
                  <ul className="anomaly-info-list">
                    {def.thresholds.map((th, i) => (
                      <li key={i}>{th}</li>
                    ))}
                  </ul>
                </div>
                <div className="anomaly-info-row">
                  <div className="anomaly-info-label">Visual signature</div>
                  <div>{def.whatToLookFor}</div>
                </div>
                <div className="anomaly-info-row">
                  <div className="anomaly-info-label">
                    SQL · <code>{def.sqlFile}</code>
                  </div>
                  <pre className="anomaly-sql">{def.sql}</pre>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
