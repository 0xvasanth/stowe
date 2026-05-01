import { useEffect, useRef, useState } from "react";
import { addSecret, type BiometricMode } from "../tauri";

interface Props {
  namespace: string;
  variable: string;
  onSuccess: () => void;
  onCancel: () => void;
}

export function EditSecretDialog({ namespace, variable, onSuccess, onCancel }: Props) {
  const [value, setValue] = useState("");
  const [biometric, setBiometric] = useState<BiometricMode>("never");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const valueRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    valueRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!value) {
      setError("New value is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await addSecret(namespace, variable, value, biometric);
      onSuccess();
    } catch (err) {
      setError(String(err));
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>
          Edit <code>{variable}</code>
        </h3>
        <p className="modal-subtitle">
          namespace <code>{namespace}</code>
        </p>
        <form onSubmit={handleSubmit}>
          <label className="field">
            <span>New value</span>
            <input
              ref={valueRef}
              type="password"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="(hidden)"
              autoComplete="off"
              spellCheck={false}
              required
            />
          </label>
          <label className="field field-row">
            <span>Biometric protection</span>
            <select
              value={biometric}
              onChange={(e) => setBiometric(e.target.value as BiometricMode)}
            >
              <option value="never">never (default)</option>
              <option value="always">always (requires signed binary; M6+)</option>
            </select>
          </label>
          {error && <p className="error">{error}</p>}
          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
