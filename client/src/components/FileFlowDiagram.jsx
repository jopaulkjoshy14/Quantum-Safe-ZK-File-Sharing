import { useState } from "react";
import Icon from "./Icon.jsx";

const JOURNEYS = {
  upload: {
    label: "Upload",
    icon: "upload",
    title: "From your device to your vault",
    note: "Your file and its details are encrypted before they leave your browser.",
    steps: [
      { icon: "file", title: "Choose a file", location: "Your browser", tone: "indigo" },
      { icon: "lock", title: "Encrypt locally", location: "Your browser", tone: "teal" },
      { icon: "upload", title: "Send encrypted data", location: "Browser → server", tone: "sky" },
      { icon: "cloud", title: "Store in your vault", location: "Encrypted storage", tone: "indigo" },
    ],
  },
  share: {
    label: "Share",
    icon: "share",
    title: "Give someone access to a file",
    note: "The file keys are protected for your recipient before the share is sent.",
    steps: [
      { icon: "users", title: "Choose a recipient", location: "Their username", tone: "indigo" },
      { icon: "key", title: "Protect the file keys", location: "Your browser", tone: "teal" },
      { icon: "share", title: "Save shared access", location: "Server", tone: "sky" },
      { icon: "download", title: "Recipient downloads", location: "Their browser", tone: "indigo" },
    ],
  },
  download: {
    label: "Download",
    icon: "download",
    title: "Bring a file back to your device",
    note: "Your browser decrypts the file and restores its original name before saving.",
    steps: [
      { icon: "download", title: "Request a file", location: "Your browser", tone: "indigo" },
      { icon: "shield", title: "Check your access", location: "Server", tone: "sky" },
      { icon: "cloud", title: "Return encrypted data", location: "Server → browser", tone: "sky" },
      { icon: "folder", title: "Decrypt and save", location: "Your browser", tone: "teal" },
    ],
  },
};

export default function FileFlowDiagram() {
  const [selectedJourney, setSelectedJourney] = useState("upload");
  const journey = JOURNEYS[selectedJourney];

  return (
    <section className="flow-card" aria-labelledby="website-flow-title">
      <div className="flow-heading">
        <span className="flow-heading-icon"><Icon name="flow" /></span>
        <div><span className="section-kicker">Behind the scenes</span><h3 id="website-flow-title">Website flow</h3></div>
      </div>
      <div className="flow-entry"><Icon name="login" /><span>Start by signing in to your workspace.</span></div>
      <div className="flow-switch" role="group" aria-label="Choose a file workflow">
        {Object.entries(JOURNEYS).map(([id, item]) => (
          <button key={id} type="button" aria-pressed={selectedJourney === id} aria-controls="flow-journey" onClick={() => setSelectedJourney(id)}>
            <Icon name={item.icon} />{item.label}
          </button>
        ))}
      </div>
      <div id="flow-journey" className="flow-journey" aria-live="polite">
        <h4>{journey.title}</h4>
        <ol className="flow-steps" role="list" aria-label={`${journey.label} flow`}>
          {journey.steps.map((step, index) => (
            <li className={`flow-step ${step.tone}`} key={`${selectedJourney}-${index}`}>
              <span className="flow-step-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
              <span className="flow-step-icon"><Icon name={step.icon} /></span>
              <strong>{step.title}</strong>
              <span className="flow-location">{step.location}</span>
              {index < journey.steps.length - 1 && <span className="flow-connector" aria-hidden="true"><Icon name="arrow" /></span>}
            </li>
          ))}
        </ol>
        <p className="flow-note"><Icon name="lock" /><span>{journey.note}</span></p>
      </div>
    </section>
  );
}
