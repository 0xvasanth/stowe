import { useState } from "react";
import { VaultList } from "./components/VaultList";
import { ProjectDetail } from "./components/ProjectDetail";
import { AuditFeed } from "./components/AuditFeed";

export default function App() {
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>Stowe</h1>
      </header>
      <main className="app-main">
        <aside className="sidebar">
          <h2>Namespaces</h2>
          <VaultList selected={selected} onSelect={setSelected} />
        </aside>
        <section className="detail">
          <ProjectDetail namespace={selected} />
        </section>
      </main>
      <footer className="app-footer">
        <AuditFeed />
      </footer>
    </div>
  );
}
