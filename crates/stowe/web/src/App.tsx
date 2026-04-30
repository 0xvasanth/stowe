import { useEffect, useState } from "react";

export default function App() {
  const [now, setNow] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="app-shell">
      <h1>Stowe</h1>
      <p>UI scaffolding live. {now}</p>
    </div>
  );
}
