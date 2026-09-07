const DEFAULT_CONFIG = {
  enabled: false,
  target: "",
  h1User: "",
  headerName: "X-HackerOne-Research",
  rate: 2,
  maxRequests: 50
};

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULT_CONFIG));
  await chrome.storage.local.set({ ...DEFAULT_CONFIG, ...existing });
  await refreshRules();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "refreshRules") {
    return false;
  }
  refreshRules()
    .then(() => sendResponse({ ok: true }))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

async function refreshRules() {
  const config = await chrome.storage.local.get(Object.keys(DEFAULT_CONFIG));
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((rule) => rule.id);
  const addRules = [];

  if (config.enabled && config.h1User && config.target) {
    const domains = domainsForTarget(config.target);
    if (domains.length > 0) {
      addRules.push({
        id: 1001,
        priority: 1,
        action: {
          type: "modifyHeaders",
          requestHeaders: [
            {
              header: config.headerName || DEFAULT_CONFIG.headerName,
              operation: "set",
              value: config.h1User
            }
          ]
        },
        condition: {
          requestDomains: domains,
          resourceTypes: [
            "main_frame",
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "csp_report",
            "media",
            "websocket",
            "other"
          ]
        }
      });
    }
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules
  });
}

function domainsForTarget(target) {
  return String(target)
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .map((item) => item.replace(/^https?:\/\//, "").split("/")[0])
    .filter(Boolean)
    .filter((item) => !item.includes("*"))
    .slice(0, 20);
}
