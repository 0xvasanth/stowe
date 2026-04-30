import { useEffect, useRef, useState } from "react";
import { addSecret, type BiometricMode } from "../tauri";

interface Props {
  namespace: string;
  onSuccess: () => void;
  onCancel: () => void;
}

export function AddSecretDialog({ namespace, onSuccess, onCancel }: Props) {
  const [varName, setVarName] = useState("");
  const [value, setValue] = useState("");
  const [biometric, setBiometric] = useState<BiometricMode>("never");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    nameRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!varName || !value) {
      setError("Variable name and value are required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await addSecret(namespace, varName, value, biometric);
      onSuccess();
    } catch (err) {
      setError(String(err));
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Add secret to {namespace}</h3>
        <form onSubmit={handleSubmit}>
          <label className="field">
            <span>Variable name</span>
            <input
              ref={nameRef}
              type="text"
              value={varName}
              onChange={(e) => setVarName(e.target.value)}
              placeholder="ANTHROPIC_API_KEY"
              autoComplete="off"
              spellCheck={false}
              required
            />
          </label>

          <label className="field">
            <span>Value</span>
            <input
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

          {biometric === "always" && (
            <p className="warning">
              Biometric items can't be created from unsigned dev builds.
              Expect <code>errSecMissingEntitlement</code> until M6 ships
              code signing.
            </p>
          )}

          {error && <p className="error">{error}</p>}

          <div className="modal-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={onCancel}
              disabled={busy}
            >
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Adding…" : "Add"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
