export default function OperationPanel({ title, subtitle, stages, steps, active }) {
  const completed = new Set(steps.map((step) => step.id));

  return (
    <section className="operation-card" aria-label={title} aria-busy={active}>
      <div className="operation-head">
        <span className="operation-live">
          <i className={active ? "pulse" : ""} aria-hidden="true" />
          {active ? "Processing" : "Secure activity"}
        </span>
        <strong>{title}</strong>
        <small>{subtitle}</small>
      </div>
      <div className="pipeline">
        {stages.map(([id, label], index) => {
          const done = completed.has(id);
          return (
            <div className={`pipeline-step ${done ? "done" : ""}`} key={id}>
              <span aria-hidden="true">{done ? "✓" : String(index + 1).padStart(2, "0")}</span>
              <div>
                <strong>{label}</strong>
                {(done || active) && <small>{done ? "Completed" : "Waiting for this stage"}</small>}
              </div>
              {index < stages.length - 1 && <i className={`connector ${done ? "done" : ""}`} aria-hidden="true" />}
            </div>
          );
        })}
      </div>
      <div className="operation-foot">Cryptographic operations run in your browser; upload and storage stages run on the server.</div>
    </section>
  );
}
