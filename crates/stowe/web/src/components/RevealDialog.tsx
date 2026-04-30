import { useEffect, useRef, useState } from "react";
import { revealSecret, copyWithAutoClear, lastFour } from "../tauri";

interface Props {
  namespace: string;
  variable: string;
  onClose: () => void;
}

const CLEAR_MS = 30_000;

export function RevealDialog({ namespace, variable, onClose }: Props) {
  const [value, setValue] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showFull, setShowFull] = useState(false);
  const [copiedAt, setCopiedAt] = useState<number | null>(null);
  const cancelRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    revealSecret(namespace, variable)
      .then(setValue)
      .catch((e) => setError(String(e)));
    return () => {
      cancelRef.current?.();
    };
  }, [namespace, variable]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function handleCopy() {
    if (!value) return;
    cancelRef.current?.();
    cancelRef.current = copyWithAutoClear(value, CLEAR_MS);
    setCopiedAt(Date.now());
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <h3>
          Reveal <code>{variable}</code>
        </h3>
        <p className="modal-subtitle">
          namespace <code>{namespace}</code>
        </p>

        {error && <p className="error">{error}</p>}
        {!error && value === null && <p>Loading…</p>}

        {value !== null && (
          <>
            <div className="reveal-value">
              <code>{showFull ? value : lastFour(value)}</code>
            </div>
            <div className="reveal-actions">
              {!showFull && (
                <button className="btn-secondary" onClick={() => setShowFull(true)}>
                  Show full value
                </button>
              )}
              <button className="btn-primary" onClick={handleCopy}>
                {copiedAt
                  ? `Copied (clipboard auto-clears in ${CLEAR_MS / 1000}s)`
                  : "Copy to clipboard"}
              </button>
            </div>
            <p className="warning">
              Clipboard managers (Alfred, Maccy, Raycast) often persist
              clipboard history. The auto-clear erases the system clipboard
              but cannot purge those caches.
            </p>
          </>
        )}

        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
