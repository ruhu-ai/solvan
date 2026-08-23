import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { initializePreferences } from "./preferences";
import "./styles/tokens.css";
import "./styles/app.css";
import "./styles/alerts.css";
import "./styles/code-change.css";
import "./styles/incident.css";
import "./styles/operability.css";
import "./styles/settings.css";
import "./styles/skills.css";
import "./styles/states.css";
import "./styles/responsive.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root mount point");
initializePreferences();
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
