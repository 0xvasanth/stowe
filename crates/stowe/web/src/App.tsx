import { useState } from "react";
import { VaultList } from "./components/VaultList";
import { ProjectDetail } from "./components/ProjectDetail";
import { AuditFeed } from "./components/AuditFeed";
import { AddSecretDialog } from "./components/AddSecretDialog";
import { ExportDialog } from "./components/ExportDialog";
import { WipeDialog } from "./components/WipeDialog";

export default function App() {
  const [selected, setSelected] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [namespacesKey, setNamespacesKey] = useState(0);
  const [adding, setAdding] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [wiping, setWiping] = useState(false);

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
        <h1>Stowe</h1>
        <div className="header-actions">
          {selected && (
            <button
              className="btn-primary"
              onClick={() => setAdding(true)}
            >
              + Add secret
            </button>
          )}
          <button
            className="btn-secondary"
            onClick={() => setExporting(true)}
          >
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
        <WipeDialog
          onClose={() => setWiping(false)}
          onWiped={handleWiped}
        />
      )}
    </div>
  );
}
