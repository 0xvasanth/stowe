import { useState } from "react";
import { VaultList } from "./components/VaultList";
import { ProjectDetail } from "./components/ProjectDetail";
import { AuditFeed } from "./components/AuditFeed";
import { AddSecretDialog } from "./components/AddSecretDialog";

export default function App() {
  const [selected, setSelected] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [namespacesKey, setNamespacesKey] = useState(0);
  const [adding, setAdding] = useState(false);

  function handleChanged() {
    setRefreshKey((k) => k + 1);
    setNamespacesKey((k) => k + 1);
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
    </div>
  );
}
