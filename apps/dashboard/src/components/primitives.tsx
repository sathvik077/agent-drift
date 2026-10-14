/** Small shared presentational pieces: states, pills, meters, key-value lists. */

import type { ReactNode } from "react";
import type { DecisionStatus, RiskLevel } from "../types";

export function Card({
  title,
  hint,
  actions,
  children,
  flush = false,
}: {
  title: string;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>{title}</h2>
        {actions}
        {hint ? <p className="hint">{hint}</p> : null}
      </div>
      <div className={flush ? "card-body flush" : "card-body"}>{children}</div>
    </section>
  );
}

export function StatusPill({ status }: { status: DecisionStatus | string | null }) {
  const value = status ?? "neutral";
  const label =
    value === "allow" ? "Allowed" :
    value === "deny" ? "Blocked" :
    value === "needs_approval" ? "Needs review" :
    String(value);
  const cls =
    value === "allow" || value === "deny" || value === "needs_approval" ? value : "neutral";
  return <span className={`pill ${cls}`}>{label}</span>;
}

export function RiskLabel({ risk }: { risk: RiskLevel | string }) {
  return <span className={`risk-${risk}`}>{risk}</span>;
}

/** Empty state. Says what would make the panel fill up, not just that it is empty. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state center" role="status">
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
    </div>
  );
}

/** Loading state: a shimmer skeleton with an accessible label. */
export function LoadingState({ rows = 3, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div className="state" role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          className="skeleton"
          style={{ width: `${88 - index * 14}%` }}
          aria-hidden="true"
        />
      ))}
    </div>
  );
}

/** Error state. Always offers the user something to do next. */
export function ErrorState({
  message,
  detail,
  onRetry,
}: {
  message: string;
  detail?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state error" role="alert">
      <h3>{message}</h3>
      {detail ? <p>{detail}</p> : null}
      {onRetry ? (
        <button type="button" className="btn small" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function Meter({
  used,
  max,
  label,
}: {
  used: number;
  max: number;
  label: string;
}) {
  const ratio = max <= 0 ? (used > 0 ? 1 : 0) : Math.min(used / max, 1);
  const cls = ratio >= 1 ? "meter full" : ratio >= 0.7 ? "meter warn" : "meter";
  return (
    <div>
      <div
        className={cls}
        role="meter"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={Math.max(max, used)}
        aria-label={label}
      >
        <span style={{ width: `${ratio * 100}%` }} />
      </div>
      <p className="footnote">
        {label}: {used} of {max}
        {max === 0 ? " (none permitted)" : null}
      </p>
    </div>
  );
}

export function Stat({
  value,
  label,
  detail,
}: {
  value: number | string;
  label: string;
  detail?: string;
}) {
  return (
    <div className="stat">
      <span className="n">{value}</span>
      <span className="l">{label}</span>
      {detail ? <span className="d">{detail}</span> : null}
    </div>
  );
}

export function KeyValues({ entries }: { entries: Array<[string, ReactNode]> }) {
  return (
    <dl className="kv">
      {entries.map(([key, value]) => (
        <div key={key} style={{ display: "contents" }}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function TagRow({ items, kind = "neutral" }: { items: string[]; kind?: string }) {
  if (items.length === 0) {
    return <span className="footnote">none</span>;
  }
  return (
    <span className="tag-row">
      {items.map((item) => (
        <code className="chip" key={item} data-kind={kind}>
          {item}
        </code>
      ))}
    </span>
  );
}

/** Short relative time, e.g. "12s ago". Falls back to the raw ISO string. */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return new Date(then).toLocaleString();
}
