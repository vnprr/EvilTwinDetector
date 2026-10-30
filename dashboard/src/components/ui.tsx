import { AlertTriangle, Info } from "lucide-react";
import type { ReactNode } from "react";
import { VERDICT_LABEL } from "../lib/format";
import type { Verdict } from "../types";

export function StatusPill({ status, label }: { status: Verdict; label?: string }) {
  return <span className={`status status-${status}`}>{label ?? VERDICT_LABEL[status]}</span>;
}

export function Panel({ title, sub, actions, children, className = "" }: {
  title: string;
  sub?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {sub && <p className="panel-sub">{sub}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Fact({ label, value, title }: { label: string; value: ReactNode; title?: string }) {
  return (
    <div className="fact" title={title}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function Metric({ icon, label, value, hint }: { icon: ReactNode; label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        {hint && <div className="metric-hint">{hint}</div>}
      </div>
    </div>
  );
}

export function Notice({ tone, children }: { tone: "error" | "warning" | "info"; children: ReactNode }) {
  const Icon = tone === "info" ? Info : AlertTriangle;
  return (
    <div className={`notice ${tone}`} role={tone === "error" ? "alert" : "status"}>
      <Icon size={18} />
      <span>{children}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function RawJson({ label, value }: { label: string; value: unknown }) {
  return (
    <details className="raw-json">
      <summary>{label}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}
