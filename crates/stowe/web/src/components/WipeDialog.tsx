import { useState } from "react";
import { wipeAll, type WipeReport } from "../tauri";

interface Props {
  onClose: () => void;
  onWiped: () => void;
}

const REQUIRED_PHRASE = "WIPE EVERYTHING";

export function WipeDialog({ onClose, onWiped }: Props) {
  const [phrase, setPhrase] = useState("");
  const [alsoAudit, setAlsoAudit] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<WipeReport | null>(null);

  async function handleWipe() {
    if (phrase !== REQUIRED_PHRASE) {
      setError(`Type the phrase exactly: ${REQUIRED_PHRASE}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await wipeAll(alsoAudit);
      setReport(r);
      onWiped();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Wipe everything</h3>
        {report ? (
          <>
            <p>Wipe complete:</p>
            <ul>
              <li>{report.namespaces_deleted} namespaces</li>
              <li>{report.vars_deleted} secrets</li>
              {report.audit_rows_deleted > 0 && (
                <li>{report.audit_rows_deleted} audit rows</li>
              )}
            </ul>
            <div className="modal-actions">
              <button className="btn-primary" onClick={onClose}>Close</button>
            </div>
          </>
        ) : (
          <>
            <p className="warning">
              This will permanently delete every secret stowe knows about
              from your macOS Keychain. There is no undo. <code>stowe.toml</code>
              files in your projects are NOT touched.
            </p>
            <label className="field">
              <span>Type {REQUIRED_PHRASE} to confirm</span>
              <input
                type="text"
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="field field-row">
              <input
                type="checkbox"
                checked={alsoAudit}
                onChange={(e) => setAlsoAudit(e.target.checked)}
              />
              <span style={{ flex: 1 }}>Also clear the audit log</span>
            </label>
            {error && <p className="error">{error}</p>}
            <div className="modal-actions">
              <button className="btn-secondary" onClick={onClose} disabled={busy}>
                Cancel
              </button>
              <button
                className="btn-destructive"
                onClick={handleWipe}
                disabled={busy || phrase !== REQUIRED_PHRASE}
              >
                {busy ? "Wiping…" : "Wipe"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
