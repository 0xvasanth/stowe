import { useEffect, useState } from "react";
import { listNamespaces, type NamespaceSummary } from "../tauri";

interface Props {
  selected: string | null;
  onSelect: (namespace: string) => void;
}

export function VaultList({ selected, onSelect }: Props) {
  const [items, setItems] = useState<NamespaceSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listNamespaces()
      .then(setItems)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <div className="vault-list error">Error: {error}</div>;
  if (items === null) return <div className="vault-list loading">Loading…</div>;
  if (items.length === 0)
    return <div className="vault-list empty">No namespaces yet.</div>;

  return (
    <ul className="vault-list">
      {items.map((it) => (
        <li
          key={it.namespace}
          className={selected === it.namespace ? "selected" : ""}
          onClick={() => onSelect(it.namespace)}
        >
          <span className="ns-name">{it.namespace}</span>
          <span className="ns-count">
            {it.var_count} {it.var_count === 1 ? "var" : "vars"}
          </span>
        </li>
      ))}
    </ul>
  );
}
