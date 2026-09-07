const state = {
  enabled: true,
  requests: [],
  seen: new Set()
};

const els = {
  toggle: document.querySelector("#toggle"),
  clear: document.querySelector("#clear"),
  copyJsonl: document.querySelector("#copyJsonl"),
  downloadJsonl: document.querySelector("#downloadJsonl"),
  copyIdorJsonl: document.querySelector("#copyIdorJsonl"),
  downloadIdorJsonl: document.querySelector("#downloadIdorJsonl"),
  search: document.querySelector("#search"),
  method: document.querySelector("#method"),
  apiOnly: document.querySelector("#apiOnly"),
  idorOnly: document.querySelector("#idorOnly"),
  detailOnly: document.querySelector("#detailOnly"),
  captured: document.querySelector("#captured"),
  visible: document.querySelector("#visible"),
  hints: document.querySelector("#hints"),
  details: document.querySelector("#details"),
  rows: document.querySelector("#rows")
};

chrome.devtools.network.onRequestFinished.addListener((request) => {
  if (!state.enabled) {
    return;
  }
  const spec = specFromRequest(request);
  if (!spec) {
    return;
  }
  const key = `${spec.method} ${spec.url} ${spec.body || ""}`;
  if (state.seen.has(key)) {
    return;
  }
  state.seen.add(key);
  state.requests.push(spec);
  render();
});

els.toggle.addEventListener("click", () => {
  state.enabled = !state.enabled;
  els.toggle.textContent = state.enabled ? "Pause" : "Resume";
});

els.clear.addEventListener("click", () => {
  state.requests = [];
  state.seen.clear();
  render();
});

els.copyJsonl.addEventListener("click", async () => {
  await navigator.clipboard.writeText(jsonl(visibleRequests()));
  els.copyJsonl.textContent = "Copied";
  setTimeout(() => {
    els.copyJsonl.textContent = "Copy JSONL";
  }, 1200);
});

els.downloadJsonl.addEventListener("click", () => {
  downloadRequests(visibleRequests(), "reconixia-idor-requests.jsonl");
});

els.copyIdorJsonl.addEventListener("click", async () => {
  await navigator.clipboard.writeText(jsonl(idorCandidateRequests()));
  els.copyIdorJsonl.textContent = "Copied";
  setTimeout(() => {
    els.copyIdorJsonl.textContent = "Copy IDOR";
  }, 1200);
});

els.downloadIdorJsonl.addEventListener("click", () => {
  downloadRequests(idorCandidateRequests(), "reconixia-idor-detail-requests.jsonl");
});

["input", "change"].forEach((eventName) => {
  [els.search, els.method, els.apiOnly, els.idorOnly, els.detailOnly].forEach((el) => {
    el.addEventListener(eventName, render);
  });
});

function specFromRequest(entry) {
  const request = entry.request || {};
  if (!request.url || !request.method) {
    return null;
  }
  if (isNoisyTelemetry(request.url)) {
    return null;
  }
  const headers = {};
  for (const header of request.headers || []) {
    if (!skipHeader(header.name)) {
      headers[header.name] = header.value;
    }
  }
  const body = request.postData?.text || "";
  const graphQL = graphQLInfo(request.url, body);
  const hints = hintForRequest(request.url, body, graphQL);
  const detailCandidate = isDetailCandidate(request.url, hints, graphQL);
  const replaySafe = isReadOnlyReplaySafe(request.method, graphQL);
  const spec = {
    name: hints.join(", "),
    method: request.method,
    url: request.url,
    headers
  };
  if (body && body.length < 20000) {
    spec.body = body;
  }
  spec.status = entry.response?.status || 0;
  spec.hints = hints;
  spec.graphqlOperation = graphQL.operationName;
  spec.detailCandidate = detailCandidate;
  spec.replaySafe = replaySafe;
  spec.score = scoreRequest(request.url, request.method, hints, graphQL, detailCandidate);
  return spec;
}

function skipHeader(name) {
  const n = String(name || "").toLowerCase();
  return n === "authorization" ||
    n === "cookie" ||
    n === "host" ||
    n === "content-length" ||
    n === "connection" ||
    n === "proxy-authorization" ||
    n === "x-whatnot-app-session-id" ||
    n === "x-whatnot-app-user-session-id" ||
    n === "x-whatnot-web-request-id" ||
    n.startsWith("x-kpsdk") ||
    n.startsWith(":");
}

function isNoisyTelemetry(rawURL) {
  let host = "";
  let path = "";
  try {
    const parsed = new URL(rawURL);
    host = parsed.hostname.toLowerCase();
    path = parsed.pathname.toLowerCase();
  } catch (_) {
    return false;
  }
  if (host === "analytics.tiktok.com" ||
      host === "reports.sdiapi.com" ||
      host === "services.sdiapi.com" ||
      host === "vice-prod.sdiapi.com" ||
      host === "log.cookieyes.com" ||
      host === "cdn-cookieyes.com" ||
      host === "directory.cookieyes.com" ||
      host.includes("googletagmanager.com")) {
    return true;
  }
  return path.includes("/reroute/datadog/") ||
    path.includes("/collect") ||
    path.includes("/pixel/act");
}

function visibleRequests() {
  const query = els.search.value.trim().toLowerCase();
  const method = els.method.value;
  return state.requests.filter((request) => {
    const text = `${request.method} ${request.url} ${request.name} ${request.graphqlOperation || ""}`.toLowerCase();
    if (query && !text.includes(query)) {
      return false;
    }
    if (method && request.method !== method) {
      return false;
    }
    if (els.apiOnly.checked && !isAPI(request.url)) {
      return false;
    }
    if (els.idorOnly.checked && request.hints.length === 0) {
      return false;
    }
    if (els.detailOnly.checked && !request.detailCandidate) {
      return false;
    }
    return true;
  });
}

function render() {
  const visible = visibleRequests();
  els.captured.textContent = String(state.requests.length);
  els.visible.textContent = String(visible.length);
  els.hints.textContent = String(state.requests.filter((item) => item.hints.length > 0).length);
  els.details.textContent = String(state.requests.filter((item) => item.detailCandidate).length);
  els.rows.textContent = "";
  for (const request of visible.slice(-500).sort((a, b) => b.score - a.score)) {
    const row = document.createElement("tr");
    row.innerHTML = [
      `<td><span class="tag">${escapeHTML(request.method)}</span></td>`,
      `<td>${escapeHTML(String(request.status || ""))}</td>`,
      `<td><span class="score score${Math.min(3, request.score)}">${escapeHTML(String(request.score))}</span></td>`,
      `<td class="hint">${escapeHTML(request.hints.join(", ") || "-")}</td>`,
      `<td>${escapeHTML(request.graphqlOperation || "-")}</td>`,
      `<td><code>${escapeHTML(request.url)}</code></td>`
    ].join("");
    els.rows.appendChild(row);
  }
}

function jsonl(requests) {
  return requests.map((request) => {
    const { status, hints, graphqlOperation, detailCandidate, replaySafe, score, ...spec } = request;
    return JSON.stringify(spec);
  }).join("\n") + (requests.length ? "\n" : "");
}

function idorCandidateRequests() {
  return state.requests
    .filter((request) => request.replaySafe && (request.detailCandidate || request.score >= 3))
    .sort((a, b) => b.score - a.score);
}

function downloadRequests(requests, filename) {
  const blob = new Blob([jsonl(requests)], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function isAPI(rawURL) {
  const u = rawURL.toLowerCase();
  return u.includes("/api/") ||
    u.includes("api.") ||
    u.includes("graphql") ||
    u.includes("auction-service") ||
    u.includes("live-service");
}

function hintForRequest(rawURL, body, graphQL) {
  let path = rawURL;
  try {
    const parsed = new URL(rawURL);
    path = `${parsed.pathname}?${parsed.searchParams.toString()}`;
  } catch (_) {
    path = rawURL;
  }
  const lower = path.toLowerCase();
  const hints = new Set();
  [
    "user",
    "account",
    "address",
    "order",
    "payment",
    "wallet",
    "seller",
    "inventory",
    "livestream",
    "auction",
    "message",
    "conversation",
    "profile",
    "shipping",
    "shipment",
    "listing",
    "payout"
  ].forEach((term) => {
    if (lower.includes(term)) {
      hints.add(term);
    }
  });
  if (graphQL.operationName) {
    const op = graphQL.operationName.toLowerCase();
    [
      "user",
      "account",
      "address",
      "order",
      "payment",
      "wallet",
      "seller",
      "inventory",
      "listing",
      "livestream",
      "auction",
      "message",
      "conversation",
      "shipping",
      "shipment",
      "payout"
    ].forEach((term) => {
      if (op.includes(term)) {
        hints.add(term);
      }
    });
  }
  for (const key of graphQL.variableKeys) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (normalized === "id" || normalized.endsWith("id") || normalized.includes("uuid") || normalized.includes("slug")) {
      hints.add("object_id");
    }
    [
      "user",
      "account",
      "order",
      "shipment",
      "conversation",
      "listing",
      "inventory",
      "payout",
      "seller"
    ].forEach((term) => {
      if (normalized.includes(term)) {
        hints.add(term);
      }
    });
  }
  lower.split(/[/?=&._-]+/).forEach((part) => {
    if (/^\d{4,}$/.test(part) || /^[a-f0-9-]{24,}$/i.test(part) || /^[a-z0-9_-]{16,}$/i.test(part)) {
      hints.add("object_id");
    }
  });
  return Array.from(hints).sort();
}

function graphQLInfo(rawURL, body) {
  const info = { operationName: "", variableKeys: [], hasVariables: false, isQuery: false, isMutation: false };
  if (!rawURL.toLowerCase().includes("graphql") && !body) {
    return info;
  }
  try {
    const parsedURL = new URL(rawURL);
    info.operationName = parsedURL.searchParams.get("operationName") || "";
  } catch (_) {
    // Non-standard URLs are still handled through body parsing.
  }
  try {
    const payload = JSON.parse(body || "{}");
    info.operationName = payload.operationName || info.operationName;
    const query = String(payload.query || "").trim().toLowerCase();
    info.isQuery = query.startsWith("query") || query.startsWith("fragment");
    info.isMutation = query.startsWith("mutation");
    if (payload.variables && typeof payload.variables === "object") {
      info.hasVariables = Object.keys(payload.variables).length > 0;
      info.variableKeys = collectVariableKeys(payload.variables);
    }
  } catch (_) {
    // Body may be form data or omitted.
  }
  return info;
}

function collectVariableKeys(value, prefix = "", depth = 0) {
  if (!value || typeof value !== "object" || depth > 5) {
    return [];
  }
  const keys = [];
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 5)) {
      keys.push(...collectVariableKeys(item, prefix, depth + 1));
    }
    return keys;
  }
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    keys.push(path);
    keys.push(...collectVariableKeys(child, path, depth + 1));
  }
  return Array.from(new Set(keys));
}

function isDetailCandidate(rawURL, hints, graphQL) {
  if (!hints.includes("object_id")) {
    return false;
  }
  const lower = rawURL.toLowerCase();
  const hasPrivateNoun = hints.some((hint) => [
    "account",
    "address",
    "order",
    "payment",
    "wallet",
    "inventory",
    "message",
    "conversation",
    "shipping",
    "shipment",
    "payout",
    "seller",
    "listing"
  ].includes(hint));
  if (hasPrivateNoun) {
    return true;
  }
  return Boolean(graphQL.operationName && graphQL.hasVariables && !graphQL.isMutation && lower.includes("graphql"));
}

function scoreRequest(rawURL, method, hints, graphQL, detailCandidate) {
  let score = 0;
  if (isAPI(rawURL)) score += 1;
  if (hints.length > 0) score += 1;
  if (hints.includes("object_id")) score += 1;
  if (detailCandidate) score += 1;
  if (graphQL.operationName) score += 1;
  if (graphQL.isMutation || ["PUT", "PATCH", "DELETE"].includes(method)) score -= 2;
  return Math.max(0, Math.min(5, score));
}

function isReadOnlyReplaySafe(method, graphQL) {
  const normalized = String(method || "").toUpperCase();
  if (["GET", "HEAD", "OPTIONS"].includes(normalized)) {
    return true;
  }
  if (normalized === "POST" && graphQL.operationName) {
    return graphQL.isQuery && !graphQL.isMutation;
  }
  return false;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

render();
