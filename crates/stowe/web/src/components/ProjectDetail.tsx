import { useEffect, useState } from "react";
import { listVars } from "../tauri";

interface Props {
  namespace: string | null;
}

export function ProjectDetail({ namespace }: Props) {
  const [vars, setVars] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!namespace) {
      setVars(null);
      return;
    }
    setVars(null);
    setError(null);
    listVars(namespace)
      .then(setVars)
      .catch((e) => setError(String(e)));
  }, [namespace]);

  if (!namespace)
    return (
      <div className="project-detail empty">
        Select a namespace from the left to view its variables.
      </div>
    );
  if (error)
    return <div className="project-detail error">Error: {error}</div>;
  if (vars === null) return <div className="project-detail loading">Loading…</div>;
  if (vars.length === 0)
    return (
      <div className="project-detail empty">
        Namespace <code>{namespace}</code> has no variables.
      </div>
    );

  return (
    <div className="project-detail">
      <h2>{namespace}</h2>
      <table>
        <thead>
          <tr>
            <th>Variable</th>
          </tr>
        </thead>
        <tbody>
          {vars.map((v) => (
            <tr key={v}>
              <td>
                <code>{v}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="note">
        Use <code>stowe reveal {namespace} &lt;VAR&gt;</code> in a terminal to
        view a value.
      </p>
    </div>
  );
}
