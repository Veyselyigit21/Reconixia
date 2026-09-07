const ReconixiaBrowserRecon = (() => {
  const MAX_INLINE_SCRIPT = 120000;
  const MAX_PAGE_HTML = 220000;
  const MAX_SCRIPT_BYTES = 900000;
  const MAX_FETCHED_SCRIPTS = 40;

  const secretPatterns = [
    { name: "AWS access key", severity: "high", regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { name: "AWS temp access key", severity: "medium", regex: /\bASIA[0-9A-Z]{16}\b/g },
    { name: "Google API key", severity: "high", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { name: "GitHub token", severity: "high", regex: /\bgh[pousr]_[A-Za-z0-9_]{30,255}\b/g },
    { name: "GitLab token", severity: "high", regex: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g },
    { name: "OpenAI key", severity: "high", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g },
    { name: "Anthropic key", severity: "high", regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g },
    { name: "Hugging Face token", severity: "high", regex: /\bhf_[A-Za-z0-9]{30,}\b/g },
    { name: "Slack token", severity: "high", regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
    { name: "Stripe live key", severity: "high", regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
    { name: "SendGrid key", severity: "high", regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
    { name: "Mailgun key", severity: "high", regex: /\bkey-[0-9a-f]{32}\b/gi },
    { name: "Twilio SID", severity: "medium", regex: /\bAC[a-f0-9]{32}\b/gi },
    { name: "JWT", severity: "medium", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { name: "Private key marker", severity: "critical", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
    { name: "Database URL", severity: "high", regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`<>]{12,}/gi },
    { name: "Firebase database", severity: "medium", regex: /\b[a-z0-9-]+\.firebaseio\.com\b/gi },
    { name: "Sentry DSN", severity: "medium", regex: /\bhttps:\/\/[a-f0-9]{32}@[a-z0-9.-]+\/\d+\b/gi },
    { name: "Generic assigned secret", severity: "medium", regex: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*["'][^"']{16,}["']/gi }
  ];

  const publicClientKeyPatterns = [
    { name: "Stripe publishable key", provider: "stripe", regex: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b/g, note: "Stripe publishable keys are normally public frontend identifiers. Report only with impact such as unauthorized charges, restricted object access, or mis-scoped backend trust." },
    { name: "Segment writeKey", provider: "segment", regex: /\bwriteKey["']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']/gi, note: "Segment write keys are commonly public analytics identifiers. Treat as informational unless event injection has business impact and is accepted by the program." },
    { name: "Sentry DSN", provider: "sentry", regex: /\bhttps:\/\/[a-f0-9]{32}@[a-z0-9.-]+\/\d+\b/gi, note: "Sentry browser DSNs are commonly public. Treat as informational unless abuse impact is demonstrated." }
  ];

  const sensitivePaths = [
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.svn/entries",
    "/config.json", "/config.js", "/app-config.json", "/runtime-config.json",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger-ui", "/api-docs",
    "/graphql", "/graphiql", "/playground", "/admin", "/dashboard", "/debug",
    "/server-status", "/server-info", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/metrics", "/health", "/status", "/version", "/phpinfo.php", "/info.php",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt", "/manifest.json", "/asset-manifest.json", "/service-worker.js",
    "/_next/static/", "/static/js/", "/build/", "/dist/"
  ];

  async function scanActiveTab(config, progress) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id || !isHTTP(tab.url)) {
      throw new Error("Active tab is not an HTTP(S) page");
    }
    const activeURL = new URL(tab.url);
    if (config.target && !targetMatches(activeURL.hostname, config.target)) {
      throw new Error(`Active host ${activeURL.hostname} is outside target domains`);
    }

    progress("Reading page");
    const [injected] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: collectPageSnapshot
    });
    const snapshot = injected?.result || {};

    progress("Fetching script bundles");
    const scripts = await fetchExternalScripts(snapshot, config);
    const pageHeaders = await fetchHeaders(tab.url, config);

    let probes = [];
    if (config.scanPaths) {
      progress("Probing safe paths");
      probes = await probeSensitivePaths(activeURL.origin, config);
    }

    progress("Classifying signals");
    return analyzeSnapshot(snapshot, scripts, pageHeaders, probes, config);
  }

  function collectPageSnapshot() {
    function safeText(value, limit) {
      return String(value || "").slice(0, limit);
    }
    function absolute(value) {
      try {
        return new URL(value, location.href).href;
      } catch (_) {
        return "";
      }
    }
    function storageArea(name) {
      const out = [];
      try {
        const area = window[name];
        if (!area) {
          return out;
        }
        for (let i = 0; i < area.length; i += 1) {
          const key = area.key(i);
          out.push({ key, value: safeText(area.getItem(key), 4000) });
        }
      } catch (error) {
        out.push({ key: "storage_error", value: String(error) });
      }
      return out;
    }
    const scripts = Array.from(document.scripts || []).map((script) => ({
      src: script.src || "",
      inline: script.src ? "" : safeText(script.textContent, 120000),
      type: script.type || ""
    }));
    const links = Array.from(document.querySelectorAll("a[href],link[href],script[src],img[src],source[src],video[src],audio[src],iframe[src]"))
      .map((node) => absolute(node.getAttribute("href") || node.getAttribute("src") || ""))
      .filter(Boolean)
      .slice(0, 1200);
    const metas = Array.from(document.querySelectorAll("meta[name],meta[property]"))
      .map((node) => ({
        name: node.getAttribute("name") || node.getAttribute("property") || "",
        content: safeText(node.getAttribute("content"), 500)
      }))
      .slice(0, 200);
    const globals = {};
    for (const key of ["__NEXT_DATA__", "__NUXT__", "__APOLLO_STATE__", "__INITIAL_STATE__", "__REDUX_STATE__", "webpackChunk_N_E"]) {
      try {
        if (window[key] !== undefined) {
          globals[key] = safeText(JSON.stringify(window[key]), 60000);
        }
      } catch (_) {
        globals[key] = "[unserializable]";
      }
    }
    return {
      url: location.href,
      origin: location.origin,
      host: location.hostname,
      title: document.title || "",
      html: safeText(document.documentElement?.outerHTML, 220000),
      scripts,
      links,
      metas,
      storage: {
        localStorage: storageArea("localStorage"),
        sessionStorage: storageArea("sessionStorage")
      },
      globals
    };
  }

  async function fetchExternalScripts(snapshot, config) {
    const urls = uniq((snapshot.scripts || []).map((script) => script.src).filter(Boolean)).slice(0, MAX_FETCHED_SCRIPTS);
    const out = [];
    for (const url of urls) {
      if (!isHTTP(url)) {
        continue;
      }
      try {
        const resp = await fetch(url, {
          credentials: "omit",
          headers: researchHeaders(config),
          cache: "force-cache"
        });
        const text = await limitedText(resp, MAX_SCRIPT_BYTES);
        out.push({ url, status: resp.status, contentType: resp.headers.get("content-type") || "", text });
      } catch (error) {
        out.push({ url, error: String(error) });
      }
    }
    return out;
  }

  async function fetchHeaders(url, config) {
    const headers = researchHeaders(config);
    try {
      const resp = await fetch(url, {
        method: "HEAD",
        credentials: "omit",
        headers,
        cache: "no-store"
      });
      return responseHeaders(resp);
    } catch (_) {
      // Some apps/CDNs reject HEAD. Fall back to GET without parsing or storing the body.
    }
    try {
      const resp = await fetch(url, {
        method: "GET",
        credentials: "omit",
        headers,
        cache: "no-store"
      });
      return responseHeaders(resp);
    } catch (error) {
      return { error: String(error), headers: {} };
    }
  }

  function responseHeaders(resp) {
    const headers = {};
      for (const [key, value] of resp.headers.entries()) {
        headers[key.toLowerCase()] = value;
      }
    return { status: resp.status, headers };
  }

  async function probeSensitivePaths(origin, config) {
    const limit = Math.min(Math.max(Number(config.probeLimit || 30), 1), sensitivePaths.length);
    const delay = Math.max(Math.ceil(1000 / Math.max(Number(config.rate || 2), 1)), 120);
    const out = [];
    for (const path of sensitivePaths.slice(0, limit)) {
      const url = origin.replace(/\/$/, "") + path;
      try {
        const resp = await fetch(url, {
          credentials: "omit",
          redirect: "manual",
          headers: researchHeaders(config),
          cache: "no-store"
        });
        const text = await limitedText(resp, 12000);
        const contentType = resp.headers.get("content-type") || "";
        const finding = classifyProbe(url, resp.status, contentType, text);
        if (finding) {
          out.push(finding);
        }
      } catch (error) {
        if (String(error).includes("Failed to fetch")) {
          // Network-denied probes are expected on some targets; keep output quiet.
        } else {
          out.push({ url, status: 0, classification: "probe_error", note: String(error) });
        }
      }
      await sleep(delay);
    }
    return out;
  }

  function analyzeSnapshot(snapshot, scripts, pageHeaders, probes, config) {
    const sources = [];
    sources.push({ name: "page.html", text: snapshot.html || "" });
    for (const script of snapshot.scripts || []) {
      if (script.inline) {
        sources.push({ name: "inline-script", text: script.inline.slice(0, MAX_INLINE_SCRIPT) });
      }
    }
    for (const [key, value] of Object.entries(snapshot.globals || {})) {
      sources.push({ name: `window.${key}`, text: value });
    }
    for (const item of [...(snapshot.storage?.localStorage || []), ...(snapshot.storage?.sessionStorage || [])]) {
      sources.push({ name: `storage.${item.key}`, text: `${item.key}=${item.value}` });
    }
    for (const script of scripts) {
      if (script.text) {
        sources.push({ name: script.url, text: script.text });
      }
    }

    const allSecrets = uniqFindings(sources.flatMap((source) => scanSecrets(source.name, source.text)));
    const publicClientKeys = uniqFindings(sources.flatMap((source) => scanPublicClientKeys(source.name, source.text)))
      .map((finding) => ({
        ...finding,
        category: "public_client_key",
        severity: "info"
      }));
    const secrets = allSecrets.filter((secret) => sourceIsInScope(secret.source, snapshot.host, config.target));
    const thirdPartySignals = allSecrets
      .filter((secret) => !sourceIsInScope(secret.source, snapshot.host, config.target))
      .map((secret) => ({
        ...secret,
        category: "third_party_signal",
        severity: "info",
        note: "Third-party source; do not report to the target program unless impact crosses into the target application."
      }));

    const allEndpoints = uniqStrings([
      ...sources.flatMap((source) => extractEndpoints(source.text, snapshot.url)),
      ...(snapshot.links || []).filter((url) => looksLikeEndpoint(url))
    ]).slice(0, 1200);
    const endpoints = allEndpoints.filter((url) => sourceIsInScope(url, snapshot.host, config.target));
    const thirdPartyEndpoints = allEndpoints.filter((url) => !sourceIsInScope(url, snapshot.host, config.target));

    const media = uniqStrings([
      ...sources.flatMap((source) => extractMedia(source.text, snapshot.url)),
      ...(snapshot.links || []).filter((url) => looksLikeMedia(url))
    ]).slice(0, 600);
    const storageFindings = scanStorage(snapshot.storage || {});
    const tech = fingerprintTech(snapshot, scripts, pageHeaders);
    const headerFindings = analyzeHeaders(pageHeaders.headers || {});
    const domFindings = analyzeDOMSecurity(snapshot.html || "");
    const findings = [
      ...secrets.map((secret) => ({ ...secret, category: "secret" })),
      ...storageFindings,
      ...headerFindings,
      ...domFindings,
      ...probes.map((probe) => ({ ...probe, category: "sensitive_path" })),
      ...media.filter((url) => sourceIsInScope(url, snapshot.host, config.target) && hasSignedURLHint(url)).map((url) => ({
        category: "media",
        severity: "medium",
        title: "Signed media URL candidate",
        asset: url,
        evidence: "URL contains signature/token-like query parameters"
      }))
    ];

    return {
      tool: "reconixia-companion",
      generatedAt: new Date().toISOString(),
      target: snapshot.url || "",
      host: snapshot.host || "",
      title: snapshot.title || "",
      summary: {
        secrets: secrets.length,
        publicClientKeys: publicClientKeys.length,
        endpoints: endpoints.length,
        thirdPartyEndpoints: thirdPartyEndpoints.length,
        thirdPartySignals: thirdPartySignals.length,
        media: media.length,
        tech: tech.length,
        storageFindings: storageFindings.length,
        pathFindings: probes.length,
        totalFindings: findings.length
      },
      tech,
      endpoints,
      thirdPartyEndpoints,
      media,
      secrets,
      publicClientKeys,
      thirdPartySignals,
      storageFindings,
      headerFindings,
      domFindings,
      sensitivePathFindings: probes,
      findings,
      notes: [
        "Browser recon is passive except optional safe path probe.",
        "Third-party vendor secrets/endpoints are separated to reduce false positives.",
        "Credentials and cookies are not exported.",
        "Manually verify every finding before reporting."
      ]
    };
  }

  function scanSecrets(source, text) {
    const findings = [];
    if (!text) {
      return findings;
    }
    for (const pattern of secretPatterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      let count = 0;
      while ((match = regex.exec(text)) && count < 5) {
        const evidence = match[0];
        if (looksLikeDummySecret(evidence)) {
          continue;
        }
        findings.push({
          title: pattern.name,
          severity: pattern.severity,
          source,
          evidence: redactSecret(evidence),
          offset: match.index
        });
        count += 1;
      }
    }
    return findings;
  }

  function scanPublicClientKeys(source, text) {
    const findings = [];
    if (!text) {
      return findings;
    }
    for (const pattern of publicClientKeyPatterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      let count = 0;
      while ((match = regex.exec(text)) && count < 5) {
        const evidence = match[1] || match[0];
        if (looksLikeDummySecret(evidence)) {
          continue;
        }
        findings.push({
          title: pattern.name,
          provider: pattern.provider,
          source,
          evidence: redactSecret(evidence),
          offset: match.index,
          note: pattern.note
        });
        count += 1;
      }
    }
    return findings;
  }

  function extractEndpoints(text, baseURL) {
    if (!text) {
      return [];
    }
    const out = [];
    const abs = /\b(?:https?:|wss?:)\/\/[^\s"'`<>\\)]+/gi;
    const path = /["'`]((?:\/|\.\/)(?:api|auth|graphql|v\d|users?|accounts?|orders?|payments?|wallet|seller|inventory|admin|config|oauth|callback)[^"'`\s<>\\)]{0,260})["'`]/gi;
    for (const match of text.matchAll(abs)) {
      if (looksLikeEndpoint(match[0])) {
        out.push(cleanURL(match[0]));
      }
    }
    for (const match of text.matchAll(path)) {
      out.push(absoluteURL(match[1], baseURL));
    }
    return out.filter(Boolean);
  }

  function extractMedia(text, baseURL) {
    if (!text) {
      return [];
    }
    const re = /\b(?:https?:)?\/\/[^\s"'`<>\\)]+\.(?:m3u8|mpd|mp4|m4v|webm|mov|mp3|wav|aac|pdf|docx?|xlsx?)(?:\?[^\s"'`<>\\)]*)?/gi;
    const relative = /["'`]((?:\/|\.\/)[^"'`\s<>\\)]*\.(?:m3u8|mpd|mp4|m4v|webm|mov|mp3|wav|aac|pdf|docx?|xlsx?)(?:\?[^"'`\s<>\\)]*)?)["'`]/gi;
    return [
      ...Array.from(text.matchAll(re)).map((match) => absoluteURL(match[0], baseURL)),
      ...Array.from(text.matchAll(relative)).map((match) => absoluteURL(match[1], baseURL))
    ].filter(Boolean);
  }

  function scanStorage(storage) {
    const out = [];
    for (const area of ["localStorage", "sessionStorage"]) {
      for (const item of storage[area] || []) {
        const key = String(item.key || "");
        const value = String(item.value || "");
        const haystack = `${key} ${value}`.toLowerCase();
        if (isEmptyStorageValue(value)) {
          continue;
        }
        if (isKnownAnalyticsStorageKey(key) && !containsStrongStorageSignal(haystack)) {
          continue;
        }
        if (isKnownVendorTelemetryStorageKey(key) && !containsCredentialStorageSignal(haystack)) {
          continue;
        }
        if (/(token|secret|jwt|auth|session|apikey|api_key|email|phone|address|user|account|balance|role)/.test(haystack)) {
          out.push({
            category: "storage",
            severity: containsCredentialStorageSignal(haystack) ? "high" : "medium",
            title: "Sensitive web storage candidate",
            asset: `${area}.${key}`,
            evidence: redactSecret(value.slice(0, 180))
          });
        }
      }
    }
    return uniqFindings(out);
  }

  function isEmptyStorageValue(value) {
    const trimmed = String(value || "").trim().toLowerCase();
    return trimmed === "" ||
      trimmed === "null" ||
      trimmed === "undefined" ||
      trimmed === "{}" ||
      trimmed === "[]" ||
      trimmed === "{\"index\":0,\"main\":0}";
  }

  function isKnownAnalyticsStorageKey(key) {
    const normalized = String(key || "").toLowerCase();
    return normalized.startsWith("ajs_") ||
      normalized.startsWith("tt_") ||
      normalized.includes("statsig") ||
      normalized.includes("tiktok") ||
      normalized.includes("amplitude") ||
      normalized.includes("mixpanel") ||
      normalized.includes("segment") ||
      normalized.includes("google_analytics") ||
      normalized.startsWith("_ga") ||
      normalized.startsWith("_gid");
  }

  function isKnownVendorTelemetryStorageKey(key) {
    const normalized = String(key || "").toLowerCase();
    return normalized.startsWith("tgt:tlm") ||
      normalized.includes("6sense") ||
      normalized.includes("hubspot") ||
      normalized.includes("hs_") ||
      normalized.includes("optimizely") ||
      normalized.includes("onetrust") ||
      normalized.includes("cookieconsent") ||
      normalized.includes("consent") ||
      normalized.includes("telemetry");
  }

  function containsStrongStorageSignal(text) {
    return containsCredentialStorageSignal(text);
  }

  function containsCredentialStorageSignal(text) {
    return /(access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|authorization|bearer|password|secret|apikey|api_key|private[_-]?key|session[_-]?token|auth[_-]?token)/.test(String(text || "").toLowerCase());
  }

  function fingerprintTech(snapshot, scripts, pageHeaders) {
    const text = [
      snapshot.html || "",
      ...(snapshot.scripts || []).map((script) => script.src || ""),
      ...scripts.map((script) => `${script.url} ${script.text?.slice(0, 5000) || ""}`),
      JSON.stringify(pageHeaders.headers || {})
    ].join("\n").toLowerCase();
    const signatures = [
      ["Next.js", "_next/static"], ["Nuxt", "__nuxt"], ["React", "react"], ["Vue", "vue"],
      ["Angular", "ng-version"], ["Svelte", "svelte"], ["Webpack", "webpack"],
      ["Vite", "/@vite/"], ["jQuery", "jquery"], ["Apollo GraphQL", "apollo"],
      ["GraphQL", "graphql"], ["Webflow", "webflow"], ["WordPress", "wp-content"],
      ["Shopify", "shopify"], ["Cloudflare", "cloudflare"], ["Vercel", "vercel"],
      ["Netlify", "netlify"], ["Sentry", "sentry"], ["Datadog", "datadog"],
      ["Google Tag Manager", "googletagmanager"], ["Segment", "segment.com"],
      ["Stripe", "js.stripe.com"], ["Zendesk", "zendesk"], ["Firebase", "firebase"]
    ];
    return signatures.filter(([, needle]) => text.includes(needle)).map(([name]) => name);
  }

  function analyzeHeaders(headers) {
    const out = [];
    if (!headers || Object.keys(headers).length === 0) {
      return out;
    }
    if (!headers["content-security-policy"]) {
      out.push({ category: "headers", severity: "low", title: "Missing CSP header", asset: "document", evidence: "content-security-policy absent" });
    }
    if (!headers["strict-transport-security"]) {
      out.push({ category: "headers", severity: "low", title: "Missing HSTS header", asset: "document", evidence: "strict-transport-security absent" });
    }
    const cors = headers["access-control-allow-origin"] || "";
    if (cors === "*" || cors === "null") {
      const credentials = String(headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
      out.push({
        category: "headers",
        severity: credentials ? "medium" : "info",
        title: credentials ? "Permissive CORS with credentials candidate" : "Permissive CORS observation",
        asset: "document",
        evidence: `access-control-allow-origin: ${cors}${credentials ? "; access-control-allow-credentials: true" : ""}`,
        note: credentials ? "Manual validation required; browsers reject wildcard credentials, but server-side policy may still be risky." : "Wildcard CORS without credentials is usually low impact by itself."
      });
    }
    for (const name of ["server", "x-powered-by", "x-aspnet-version"]) {
      if (headers[name]) {
        out.push({ category: "headers", severity: "info", title: "Server disclosure", asset: name, evidence: `${name}: ${headers[name]}` });
      }
    }
    return out;
  }

  function analyzeDOMSecurity(html) {
    const out = [];
    const lower = String(html || "").toLowerCase();
    const sinks = [
      ["innerHTML sink marker", ".innerhtml"],
      ["document.write sink marker", "document.write"],
      ["eval sink marker", "eval("],
      ["postMessage marker", "postmessage"],
      ["JSONP callback marker", "callback="],
      ["Prototype pollution marker", "__proto__"]
    ];
    for (const [title, marker] of sinks) {
      if (lower.includes(marker)) {
        out.push({ category: "dom", severity: "info", title, asset: "page", evidence: marker });
      }
    }
    return out;
  }

  function classifyProbe(url, status, contentType, text) {
    const lower = `${url} ${contentType} ${text.slice(0, 500)}`.toLowerCase();
    if (status === 404 || status === 405 || status === 0) {
      return null;
    }
    if (status === 401 || status === 403) {
      return { url, status, classification: "protected", severity: "info", title: "Protected sensitive path", note: "Endpoint exists but requires auth/permission" };
    }
    if (status >= 300 && status < 400) {
      return { url, status, classification: "redirect", severity: "info", title: "Sensitive path redirect", note: "Review destination manually" };
    }
    if (status >= 200 && status < 300) {
      let severity = "medium";
      let title = "Accessible sensitive path candidate";
      if (/(private key|aws_access_key|database_url|db_password|secret|token|password|apikey|api_key)/.test(lower)) {
        severity = "high";
        title = "Accessible sensitive data candidate";
      }
      return { url, status, classification: "accessible", severity, title, contentType, size: text.length, note: "Manual validation required" };
    }
    return null;
  }

  function researchHeaders(config) {
    const headers = {};
    if (config.h1User && config.headerName) {
      headers[config.headerName] = config.h1User;
    }
    return headers;
  }

  function targetMatches(host, targets) {
    const normalized = host.toLowerCase();
    return String(targets || "")
      .split(",")
      .map((item) => item.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0])
      .filter(Boolean)
      .some((target) => normalized === target || normalized.endsWith(`.${target}`));
  }

  function sourceIsInScope(source, pageHost, targets) {
    if (!source || source === "page.html" || source.startsWith("inline-script") || source.startsWith("window.") || source.startsWith("storage.")) {
      return true;
    }
    let host = "";
    try {
      host = new URL(source).hostname.toLowerCase();
    } catch (_) {
      return true;
    }
    const normalizedPageHost = String(pageHost || "").toLowerCase();
    if (host === normalizedPageHost || host.endsWith(`.${normalizedPageHost}`)) {
      return true;
    }
    return targetMatches(host, targets);
  }

  function looksLikeEndpoint(url) {
    const lower = String(url || "").toLowerCase();
    return /\/(?:api|auth|graphql|v\d|users?|accounts?|orders?|payments?|wallet|seller|inventory|admin|config|oauth|callback)(?:[/?#.]|$)/.test(lower) ||
      lower.includes("api.") ||
      lower.includes("graphql");
  }

  function looksLikeMedia(url) {
    return /\.(?:m3u8|mpd|mp4|m4v|webm|mov|mp3|wav|aac|pdf|docx?|xlsx?)(?:[?#]|$)/i.test(String(url || ""));
  }

  function hasSignedURLHint(url) {
    return /[?&](?:signature|sig|token|expires|x-amz-signature|x-amz-credential|policy)=/i.test(String(url || ""));
  }

  function looksLikeDummySecret(value) {
    return /(example|sample|dummy|placeholder|test|changeme|your[_-]?key|xxxxx|00000|12345)/i.test(String(value || ""));
  }

  function redactSecret(value) {
    return String(value || "").replace(/[A-Za-z0-9_./+=-]{12,}/g, (token) => {
      if (token.length <= 14) {
        return "[REDACTED]";
      }
      return `${token.slice(0, 5)}...[REDACTED]...${token.slice(-4)}`;
    });
  }

  function absoluteURL(value, baseURL) {
    try {
      if (String(value).startsWith("//")) {
        return `https:${value}`;
      }
      return new URL(value, baseURL).href;
    } catch (_) {
      return "";
    }
  }

  function cleanURL(value) {
    return String(value || "").replace(/[),.;]+$/, "");
  }

  function uniq(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function uniqStrings(values) {
    return uniq(values.map(cleanURL));
  }

  function uniqFindings(findings) {
    const seen = new Set();
    const out = [];
    for (const finding of findings) {
      const key = `${finding.category || ""}|${finding.title || ""}|${finding.asset || finding.source || ""}|${finding.evidence || finding.url || ""}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(finding);
    }
    return out;
  }

  async function limitedText(resp, maxBytes) {
    const text = await resp.text();
    return text.slice(0, maxBytes);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isHTTP(url) {
    return /^https?:\/\//i.test(String(url || ""));
  }

  return {
    scanActiveTab
  };
})();
