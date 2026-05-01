import { useState } from "react";
import { addSecret } from "../tauri";

interface Props {
  onClose: () => void;
}

export function OnboardingWizard({ onClose }: Props) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function dismiss() {
    try {
      window.localStorage.setItem("stowe.onboarding_seen", "true");
    } catch {
      // localStorage unavailable in some webviews; ignore.
    }
    onClose();
  }

  async function createSample() {
    setBusy(true);
    setError(null);
    try {
      await addSecret("demo", "EXAMPLE_KEY", "hello-world", "never");
      setStep(3);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        {step === 1 && (
          <>
            <h3>Welcome to Stowe</h3>
            <p>
              Stowe stores secrets in your macOS Keychain — encrypted at rest,
              key bound to your login. Secrets never sit as plaintext on disk;
              they're injected as env vars only when a child process needs them.
            </p>
            <p>This app lets you:</p>
            <ul>
              <li>Browse what's stored, by project namespace.</li>
              <li>Add, edit, reveal, and delete secrets.</li>
              <li>Export to an encrypted backup, or wipe everything.</li>
              <li>See an audit log of every <code>stowe run</code> invocation.</li>
            </ul>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={dismiss}>
                Skip
              </button>
              <button className="btn-primary" onClick={() => setStep(2)}>
                Next
              </button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <h3>Permissions</h3>
            <p>
              When Stowe reads from the Keychain for the first time, macOS will
              prompt with a system dialog asking you to allow access. Click{" "}
              <strong>Always Allow</strong> once per item to silence the prompt
              for future reads.
            </p>
            <p>
              Until M6 ships proper code signing, items added with the{" "}
              <code>biometric=always</code> option will fail with{" "}
              <code>errSecMissingEntitlement</code>. The default is{" "}
              <code>never</code>, which works fine for unsigned dev builds.
            </p>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={dismiss}>
                Skip
              </button>
              <button className="btn-primary" onClick={createSample} disabled={busy}>
                {busy ? "Creating…" : "Create a sample secret"}
              </button>
            </div>
            {error && <p className="error">{error}</p>}
          </>
        )}

        {step === 3 && (
          <>
            <h3>Done</h3>
            <p>
              Created a <code>demo</code> namespace with one variable{" "}
              <code>EXAMPLE_KEY</code>. Click it in the sidebar to see it; use{" "}
              <strong>Reveal</strong> to view the value (it's <code>hello-world</code>).
            </p>
            <div className="modal-actions">
              <button className="btn-primary" onClick={dismiss}>
                Get started
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
