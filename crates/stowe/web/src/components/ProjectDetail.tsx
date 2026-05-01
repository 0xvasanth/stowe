import { useEffect, useState } from "react";
import { listVars, deleteSecret } from "../tauri";
import { RevealDialog } from "./RevealDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { EditSecretDialog } from "./EditSecretDialog";

interface Props {
  namespace: string | null;
  /** Increment to force a refetch of the variables list. */
  refreshKey: number;
  onChanged: () => void;
}

export function ProjectDetail({ namespace, refreshKey, onChanged }: Props) {
  const [vars, setVars] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealing, setRevealing] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

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
  }, [namespace, refreshKey]);

  async function confirmDelete(v: string) {
    if (!namespace) return;
    setDeleteError(null);
    try {
      await deleteSecret(namespace, v);
      setDeleting(null);
      onChanged();
    } catch (e) {
      setDeleteError(String(e));
    }
  }

  if (!namespace)
    return (
      <div className="project-detail empty">
        Select a namespace from the left to view its variables.
      </div>
    );
  if (error)
    return <div className="project-detail error">Error: {error}</div>;
  if (vars === null) return <div className="project-detail loading">Loading…</div>;

  return (
    <div className="project-detail">
      <h2>{namespace}</h2>
      {vars.length === 0 ? (
        <p className="empty">
          Namespace <code>{namespace}</code> has no variables yet. Use the
          "+ Add secret" button in the header to add one.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Variable</th>
              <th className="actions-col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {vars.map((v) => (
              <tr key={v}>
                <td>
                  <code>{v}</code>
                </td>
                <td className="actions-col">
                  <button
                    className="btn-link"
                    onClick={() => setRevealing(v)}
                  >
                    Reveal
                  </button>
                  <button
                    className="btn-link"
                    onClick={() => setEditing(v)}
                  >
                    Edit
                  </button>
                  <button
                    className="btn-link btn-link-destructive"
                    onClick={() => {
                      setDeleting(v);
                      setDeleteError(null);
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {revealing && (
        <RevealDialog
          namespace={namespace}
          variable={revealing}
          onClose={() => setRevealing(null)}
        />
      )}

      {editing && (
        <EditSecretDialog
          namespace={namespace}
          variable={editing}
          onSuccess={() => {
            setEditing(null);
            onChanged();
          }}
          onCancel={() => setEditing(null)}
        />
      )}

      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting}?`}
          message={
            deleteError
              ? `Delete failed: ${deleteError}`
              : `This will permanently remove ${deleting} from ${namespace}.`
          }
          confirmLabel="Delete"
          destructive={true}
          onConfirm={() => confirmDelete(deleting)}
          onCancel={() => setDeleting(null)}
        />
      )}
    </div>
  );
}
