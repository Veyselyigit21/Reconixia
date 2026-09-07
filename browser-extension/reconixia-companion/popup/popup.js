const defaults = {
  enabled: false,
  target: "",
  h1User: "",
  headerName: "X-HackerOne-Research",
  rate: 2,
  maxRequests: 50,
  scanPaths: false,
  probeLimit: 30,
  captureMode: "jsonl",
  capturePath: "captures/owned-account-detail.jsonl",
  policyPath: "",
  oastDomain: ""
};

const presets = {
  custom: {},
  whatnot: {
    headerName: "X-HackerOne-Research",
    rate: 2,
    maxRequests: 50,
    captureMode: "jsonl",
    capturePath: "captures/whatnot-account-a-detail.jsonl",
    policyPath: "examples/program-policies/whatnot.idor-policy.example.json"
  },
  syfe: {
    headerName: "X-HackerOne-Research",
    rate: 2,
    maxRequests: 50,
    captureMode: "jsonl",
    capturePath: "captures/syfe-account-a-detail.jsonl",
    policyPath: "examples/program-policies/syfe.idor-policy.json"
  }
};

const fields = {
  enabled: document.querySelector("#enabled"),
  preset: document.querySelector("#preset"),
  target: document.querySelector("#target"),
  h1User: document.querySelector("#h1User"),
  headerName: document.querySelector("#headerName"),
  rate: document.querySelector("#rate"),
  maxRequests: document.querySelector("#maxRequests"),
  scanPaths: document.querySelector("#scanPaths"),
  probeLimit: document.querySelector("#probeLimit"),
  scanActive: document.querySelector("#scanActive"),
  copyReconJson: document.querySelector("#copyReconJson"),
  downloadReconJson: document.querySelector("#downloadReconJson"),
  reconSummary: document.querySelector("#reconSummary"),
  reconOutput: document.querySelector("#reconOutput"),
  captureMode: document.querySelector("#captureMode"),
  capturePath: document.querySelector("#capturePath"),
  policyPath: document.querySelector("#policyPath"),
  command: document.querySelector("#command"),
  copyCommand: document.querySelector("#copyCommand"),
  oastDomain: document.querySelector("#oastDomain"),
  callbackPayloads: document.querySelector("#callbackPayloads"),
  copyCallbacks: document.querySelector("#copyCallbacks"),
  status: document.querySelector("#status")
};

let lastReconReport = null;

init();

async function init() {
  const config = await chrome.storage.local.get(Object.keys(defaults));
  setForm({ ...defaults, ...config });
  updateCommand();
  updateCallbacks();
  bind();
}

function bind() {
  ["enabled", "target", "h1User", "headerName", "rate", "maxRequests", "scanPaths", "probeLimit", "captureMode", "capturePath", "policyPath", "oastDomain"].forEach((key) => {
    fields[key].addEventListener("input", save);
    fields[key].addEventListener("change", save);
  });
  fields.h1User.addEventListener("input", updateCallbacks);
  fields.oastDomain.addEventListener("input", updateCallbacks);

  fields.preset.addEventListener("change", async () => {
    const preset = presets[fields.preset.value] || {};
    setForm({ ...readForm(), ...preset });
    await save();
  });

  fields.copyCommand.addEventListener("click", async () => {
    await navigator.clipboard.writeText(fields.command.value);
    setStatus("Command copied");
  });

  fields.scanActive.addEventListener("click", runBrowserRecon);

  fields.copyReconJson.addEventListener("click", async () => {
    await navigator.clipboard.writeText(fields.reconOutput.value || "");
    setStatus("Recon JSON copied");
  });

  fields.downloadReconJson.addEventListener("click", () => {
    if (!lastReconReport) {
      setStatus("No browser recon yet");
      return;
    }
    const blob = new Blob([JSON.stringify(lastReconReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `reconixia-browser-recon-${safeFilename(lastReconReport.host || "target")}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus("Recon JSON downloaded");
  });

  fields.copyCallbacks.addEventListener("click", async () => {
    await navigator.clipboard.writeText(fields.callbackPayloads.value);
    setStatus("Callbacks copied");
  });
}

function setForm(config) {
  fields.enabled.checked = Boolean(config.enabled);
  fields.target.value = config.target || "";
  fields.h1User.value = config.h1User || "";
  fields.headerName.value = config.headerName || defaults.headerName;
  fields.rate.value = String(config.rate || defaults.rate);
  fields.maxRequests.value = String(config.maxRequests || defaults.maxRequests);
  fields.scanPaths.checked = Boolean(config.scanPaths);
  fields.probeLimit.value = String(config.probeLimit || defaults.probeLimit);
  fields.captureMode.value = config.captureMode || defaults.captureMode;
  fields.capturePath.value = config.capturePath || defaults.capturePath;
  fields.policyPath.value = config.policyPath || "";
  fields.oastDomain.value = config.oastDomain || "";
}

function readForm() {
  return {
    enabled: fields.enabled.checked,
    target: fields.target.value.trim(),
    h1User: fields.h1User.value.trim(),
    headerName: fields.headerName.value.trim() || defaults.headerName,
    rate: Math.max(1, Number(fields.rate.value || defaults.rate)),
    maxRequests: Math.max(1, Number(fields.maxRequests.value || defaults.maxRequests)),
    scanPaths: fields.scanPaths.checked,
    probeLimit: Math.max(1, Number(fields.probeLimit.value || defaults.probeLimit)),
    captureMode: fields.captureMode.value === "har" ? "har" : "jsonl",
    capturePath: fields.capturePath.value.trim() || defaults.capturePath,
    policyPath: fields.policyPath.value.trim(),
    oastDomain: fields.oastDomain.value.trim()
  };
}

async function save() {
  const config = readForm();
  updateCommand();
  updateCallbacks();
  await chrome.storage.local.set(config);
  try {
    await chrome.runtime.sendMessage({ type: "refreshRules" });
  } catch (_) {
    // The popup UI should still update even if the service worker is waking up.
  }
  setStatus(config.enabled ? "Header injection enabled" : "Saved");
}

function updateCommand() {
  const config = readForm();
  const target = firstTarget(config.target) || "target.com";
  const policy = config.policyPath || (target.includes("whatnot.com")
    ? "examples/program-policies/whatnot.idor-policy.example.json"
    : "examples/program-policies/target.idor-policy.json");
  const sourceFlag = config.captureMode === "har" ? "-har" : "-input";
  const capturePath = config.capturePath || (config.captureMode === "har" ? "owned-account.har" : "captures/owned-account-detail.jsonl");
  fields.command.value = [
    "export RECONIXIA_IDOR_COOKIE_A='ACCOUNT_A_COOKIE'",
    "export RECONIXIA_IDOR_COOKIE_B='ACCOUNT_B_COOKIE'",
    "",
    "./reconixia-idor \\",
    `  -target ${shellQuote(rootDomain(target))} \\`,
    `  ${sourceFlag} ${shellQuote(capturePath)} \\`,
    `  -rules ${shellQuote(policy)} \\`,
    `  -rate ${config.rate} \\`,
    `  -max ${config.maxRequests}${config.h1User ? " \\" : ""}`,
    config.h1User ? `  -h1-user ${shellQuote(config.h1User)}` : ""
  ].filter(Boolean).join("\n");
}

async function runBrowserRecon() {
  const config = readForm();
  fields.scanActive.disabled = true;
  fields.scanActive.textContent = "Scanning...";
  fields.reconSummary.textContent = "Collecting page signals...";
  fields.reconOutput.value = "";
  try {
    const report = await ReconixiaBrowserRecon.scanActiveTab(config, (message) => {
      fields.reconSummary.textContent = message;
      setStatus(message);
    });
    lastReconReport = report;
    fields.reconOutput.value = JSON.stringify(report, null, 2);
    fields.reconSummary.textContent = [
      `${report.summary.totalFindings} findings`,
      `${report.summary.secrets} secrets`,
      `${report.summary.endpoints} endpoints`,
      `${report.summary.thirdPartySignals || 0} vendor signals`,
      `${report.summary.tech} tech`,
      `${report.summary.pathFindings} path hits`
    ].join(" / ");
    setStatus("Browser recon complete");
  } catch (error) {
    fields.reconSummary.textContent = String(error.message || error);
    setStatus("Browser recon failed");
  } finally {
    fields.scanActive.disabled = false;
    fields.scanActive.textContent = "Scan active tab";
  }
}

function updateCallbacks() {
  const config = readForm();
  const domain = cleanCallbackDomain(config.oastDomain);
  if (!domain) {
    fields.callbackPayloads.value = [
      "Enter your own OAST domain, for example:",
      "aello.interact.sh",
      "",
      "Use only for authorized, non-destructive callback verification."
    ].join("\n");
    return;
  }
  const tag = encodeURIComponent(config.h1User || "research");
  fields.callbackPayloads.value = [
    `https://${domain}/reconixia/${tag}`,
    `http://${domain}/reconixia/${tag}`,
    `${tag}.${domain}`,
    "",
    `curl -I https://${domain}/reconixia/${tag}`,
    "",
    "Use for OAST/callback checks only. Do not use shell, persistence, or destructive payloads."
  ].join("\n");
}

function cleanCallbackDomain(value) {
  return String(value || "")
    .trim()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/[^a-zA-Z0-9._-]/g, "");
}

function firstTarget(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean)[0] || "";
}

function rootDomain(value) {
  return String(value || "").replace(/^https?:\/\//, "").split("/")[0];
}

function shellQuote(value) {
  return "'" + String(value).replaceAll("'", "'\\''") + "'";
}

function safeFilename(value) {
  return String(value || "target").replace(/[^a-z0-9._-]/gi, "_").slice(0, 80);
}

function setStatus(message) {
  fields.status.textContent = message;
  window.setTimeout(() => {
    fields.status.textContent = "Ready";
  }, 1800);
}
