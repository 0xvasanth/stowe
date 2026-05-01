import { useEffect, useState } from "react";
import { auditQuery, listNamespaces, type AccessRow, type NamespaceSummary } from "../tauri";

const OUTCOMES = ["all", "allowed", "denied", "biometric_failed"] as const;

export function AuditLogView() {
  const [namespaces, setNamespaces] = useState<NamespaceSummary[]>([]);
  const [filterNs, setFilterNs] = useState<string>("all");
  const [filterOutcome, setFilterOutcome] = useState<string>("all");
  const [limit, setLimit] = useState<number>(100);
  const [rows, setRows] = useState<AccessRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    listNamespaces()
      .then(setNamespaces)
      .catch(() => {});
  }, []);

  useEffect(() => {
    setRows(null);
    setError(null);
    auditQuery(
      filterNs === "all" ? null : filterNs,
      filterOutcome === "all" ? null : filterOutcome,
      limit,
    )
      .then(setRows)
      .catch((e) => setError(String(e)));
  }, [filterNs, filterOutcome, limit]);

  return (
    <div className="audit-log-view">
      <div className="audit-filters">
        <label>
          <span>Namespace</span>
          <select value={filterNs} onChange={(e) => setFilterNs(e.target.value)}>
            <option value="all">all</option>
            {namespaces.map((n) => (
              <option key={n.namespace} value={n.namespace}>
                {n.namespace}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Outcome</span>
          <select value={filterOutcome} onChange={(e) => setFilterOutcome(e.target.value)}>
            {OUTCOMES.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Limit</span>
          <input
            type="number"
            min={1}
            max={1000}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value) || 100)}
          />
        </label>
      </div>

      {error && <p className="error">{error}</p>}
      {rows === null && !error && <p>Loading…</p>}
      {rows !== null && rows.length === 0 && <p className="empty">No audit rows match.</p>}

      {rows !== null && rows.length > 0 && (
        <table className="audit-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Namespace</th>
              <th>Binary</th>
              <th>Vars</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <RowItem
                key={r.id}
                row={r}
                expanded={expanded === r.id}
                onToggle={() => setExpanded(expanded === r.id ? null : r.id)}
              />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RowItem({
  row,
  expanded,
  onToggle,
}: {
  row: AccessRow;
  expanded: boolean;
  onToggle: () => void;
}) {
  const ts = (() => {
    const d = new Date(row.ts);
    return isNaN(d.getTime()) ? row.ts : d.toLocaleString();
  })();
  const bin = row.binary_path.split("/").pop() || row.binary_path;
  return (
    <>
      <tr
        className={`audit-row ${row.outcome === "denied" ? "denied" : ""}`}
        onClick={onToggle}
      >
        <td className="ts">{ts}</td>
        <td>{row.namespace}</td>
        <td>{bin}</td>
        <td>{row.var_names.length === 0 ? "—" : row.var_names.join(", ")}</td>
        <td>{row.outcome}</td>
      </tr>
      {expanded && (
        <tr className="audit-row-detail">
          <td colSpan={5}>
            <dl>
              <dt>Full path</dt>
              <dd>
                <code>{row.binary_path}</code>
              </dd>
              <dt>argv</dt>
              <dd>
                <code>{row.argv.length === 0 ? "—" : row.argv.join(" ")}</code>
              </dd>
              {row.binary_hash && (
                <>
                  <dt>SHA-256</dt>
                  <dd>
                    <code>{row.binary_hash}</code>
                  </dd>
                </>
              )}
              {row.pid !== null && (
                <>
                  <dt>PID</dt>
                  <dd>{row.pid}</dd>
                </>
              )}
              {row.duration_ms !== null && (
                <>
                  <dt>Duration</dt>
                  <dd>{row.duration_ms} ms</dd>
                </>
              )}
              {row.child_exit !== null && (
                <>
                  <dt>Exit code</dt>
                  <dd>{row.child_exit}</dd>
                </>
              )}
              {row.reason && (
                <>
                  <dt>Reason</dt>
                  <dd>{row.reason}</dd>
                </>
              )}
            </dl>
          </td>
        </tr>
      )}
    </>
  );
}
