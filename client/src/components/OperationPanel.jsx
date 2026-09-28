import Icon from "./Icon.jsx";

export default function OperationPanel({ title, subtitle, stages, steps, active }) {
  if (!active && steps.length === 0) return null;
  const completed = new Set(steps.map((step) => step.id));
  const count = stages.filter(([id]) => completed.has(id)).length;
  const finished = count === stages.length;

  return (
    <section className="operation-card" aria-label={title}>
      <div className="operation-head" role="status">
        <span className={`operation-icon ${finished ? "complete" : ""}`}><Icon name={finished ? "check" : "lock"} /></span>
        <div><strong>{title}</strong><small>{active ? "Working on it…" : finished ? "All done." : "Operation stopped."}</small></div>
        <span className="operation-count">{count} / {stages.length}</span>
      </div>
      <progress className="operation-progress" value={count} max={stages.length} aria-label={title} />
      <details className="operation-details">
        <summary>View steps</summary>
        {subtitle && <p className="operation-subtitle">{subtitle}</p>}
        <div className="pipeline">
          {stages.map(([id, label], index) => {
            const done = completed.has(id);
            return (
              <div className={`pipeline-step ${done ? "done" : ""}`} key={id}>
                <span aria-hidden="true">{done ? "✓" : String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{label}</strong>
                  {(done || active) && <small>{done ? "Reached" : "Up next"}</small>}
                </div>
              </div>
            );
          })}
        </div>
      </details>
    </section>
  );
}
