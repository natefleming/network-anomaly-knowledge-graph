import { NODE_COLOR } from "../lib/styling";

export function Legend() {
  const items: { color: string; label: string }[] = [
    { color: NODE_COLOR.normal, label: "Normal host" },
    { color: NODE_COLOR.server, label: "Server / gateway" },
    { color: NODE_COLOR.warn, label: "Elevated anomaly (pulsing)" },
    { color: NODE_COLOR.alert, label: "Confirmed anomalous (glowing)" },
    { color: NODE_COLOR.rogue, label: "Rogue device" },
    { color: NODE_COLOR.subnet, label: "Subnet" },
    { color: NODE_COLOR.external, label: "External IP" },
    { color: NODE_COLOR.service, label: "Service" },
  ];
  return (
    <div>
      {items.map((i) => (
        <div className="legend-row" key={i.label}>
          <span className="legend-dot" style={{ background: i.color }} />
          <span>{i.label}</span>
        </div>
      ))}
      <div style={{ marginTop: 10, fontSize: 11, color: "#94A3B8" }}>
        Thin gray edges = normal · orange = high traffic · red = anomalous.<br />
        Moving dots along edges represent packet flow.
      </div>
    </div>
  );
}
