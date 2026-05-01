import { useEffect, useState } from "react";
import { VaultList } from "./components/VaultList";
import { ProjectDetail } from "./components/ProjectDetail";
import { AuditFeed } from "./components/AuditFeed";
import { AddSecretDialog } from "./components/AddSecretDialog";
import { ExportDialog } from "./components/ExportDialog";
import { WipeDialog } from "./components/WipeDialog";
import { AuditLogView } from "./components/AuditLogView";
import { OnboardingWizard } from "./components/OnboardingWizard";
import { listNamespaces } from "./tauri";

type Tab = "vault" | "audit";

export default function App() {
  const [tab, setTab] = useState<Tab>("vault");
  const [selected, setSelected] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [namespacesKey, setNamespacesKey] = useState(0);
  const [adding, setAdding] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [wiping, setWiping] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState<boolean | null>(null);

  useEffect(() => {
    let dismissed = false;
    try {
      dismissed = window.localStorage.getItem("stowe.onboarding_seen") === "true";
    } catch {
      dismissed = false;
    }
    if (dismissed) {
      setShowOnboarding(false);
      return;
    }
    listNamespaces()
      .then((nses) => setShowOnboarding(nses.length === 0))
      .catch(() => setShowOnboarding(false));
  }, []);

  function handleChanged() {
    setRefreshKey((k) => k + 1);
    setNamespacesKey((k) => k + 1);
  }

  function handleWiped() {
    setSelected(null);
    handleChanged();
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-left">
          <h1>Stowe</h1>
          <nav className="tab-nav">
            <button
              className={tab === "vault" ? "tab active" : "tab"}
              onClick={() => setTab("vault")}
            >
              Vault
            </button>
            <button
              className={tab === "audit" ? "tab active" : "tab"}
              onClick={() => setTab("audit")}
            >
              Audit
            </button>
          </nav>
        </div>
        <div className="header-actions">
          {tab === "vault" && selected && (
            <button className="btn-primary" onClick={() => setAdding(true)}>
              + Add secret
            </button>
          )}
          <button className="btn-secondary" onClick={() => setExporting(true)}>
            Export
          </button>
          <button
            className="btn-secondary btn-danger-tone"
            onClick={() => setWiping(true)}
          >
            Wipe…
          </button>
        </div>
      </header>

      {tab === "vault" ? (
        <>
          <main className="app-main">
            <aside className="sidebar">
              <h2>Namespaces</h2>
              <VaultList
                key={namespacesKey}
                selected={selected}
                onSelect={setSelected}
              />
            </aside>
            <section className="detail">
              <ProjectDetail
                namespace={selected}
                refreshKey={refreshKey}
                onChanged={handleChanged}
              />
            </section>
          </main>
          <footer className="app-footer">
            <AuditFeed />
          </footer>
        </>
      ) : (
        <main className="app-main app-main-single">
          <AuditLogView />
        </main>
      )}

      {adding && selected && (
        <AddSecretDialog
          namespace={selected}
          onSuccess={() => {
            setAdding(false);
            handleChanged();
          }}
          onCancel={() => setAdding(false)}
        />
      )}

      {exporting && <ExportDialog onClose={() => setExporting(false)} />}

      {wiping && (
        <WipeDialog onClose={() => setWiping(false)} onWiped={handleWiped} />
      )}

      {showOnboarding && (
        <OnboardingWizard
          onClose={() => {
            setShowOnboarding(false);
            handleChanged();
          }}
        />
      )}
    </div>
  );
}
