import { useState } from "react";
import { exportVault, chooseSavePath, type ExportFormat } from "../tauri";

interface Props {
  onClose: () => void;
}

export function ExportDialog({ onClose }: Props) {
  const [format, setFormat] = useState<ExportFormat>("encrypted");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function handleExport() {
    setError(null);
    if (format === "encrypted") {
      if (!passphrase) {
        setError("Passphrase required for encrypted export.");
        return;
      }
      if (passphrase !== confirm) {
        setError("Passphrases don't match.");
        return;
      }
    }
    const defaultName =
      format === "encrypted"
        ? `stowe-backup-${new Date().toISOString().slice(0, 10)}.age`
        : `stowe-backup-${new Date().toISOString().slice(0, 10)}.env`;
    const path = await chooseSavePath(defaultName);
    if (!path) return;
    setBusy(true);
    try {
      await exportVault([], format, format === "encrypted" ? passphrase : null, path);
      setDone(path);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Export vault</h3>
        {done ? (
          <>
            <p>Wrote backup to:</p>
            <div className="reveal-value">
              <code>{done}</code>
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={onClose}>Done</button>
            </div>
          </>
        ) : (
          <>
            <label className="field field-row">
              <span>Format</span>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as ExportFormat)}
              >
                <option value="encrypted">Encrypted (.age, recommended)</option>
                <option value="env">Plaintext (.env, insecure)</option>
              </select>
            </label>
            {format === "encrypted" ? (
              <>
                <label className="field">
                  <span>Passphrase</span>
                  <input
                    type="password"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                  />
                </label>
                <label className="field">
                  <span>Confirm passphrase</span>
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                  />
                </label>
              </>
            ) : (
              <p className="warning">
                Plaintext exports write every secret in cleartext to disk.
                Use only for migration to a different secret store; delete
                the file immediately after.
              </p>
            )}
            {error && <p className="error">{error}</p>}
            <div className="modal-actions">
              <button className="btn-secondary" onClick={onClose} disabled={busy}>
                Cancel
              </button>
              <button className="btn-primary" onClick={handleExport} disabled={busy}>
                {busy ? "Exporting…" : "Choose file & export"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
