
"use strict";

const API_BASE_URL = "http://127.0.0.1:8000/api/v1";

const elements = {
  siteHost: document.getElementById("siteHost"),
  siteUrl: document.getElementById("siteUrl"),
  siteIcon: document.getElementById("siteIcon"),
  scanButton: document.getElementById("scanButton"),
  scanButtonText: document.getElementById("scanButtonText"),
  message: document.getElementById("message"),
  resultCard: document.getElementById("resultCard"),
  resultTitle: document.getElementById("resultTitle"),
  resultBadge: document.getElementById("resultBadge"),
  riskScore: document.getElementById("riskScore"),
  scoreFill: document.getElementById("scoreFill"),
  modelVersion: document.getElementById("modelVersion"),
  indicatorList: document.getElementById("indicatorList"),
  resultDisclaimer: document.getElementById("resultDisclaimer"),
  connectionDot: document.getElementById("connectionDot"),
  connectionText: document.getElementById("connectionText"),
  protectionText: document.getElementById("protectionText"),
  settingsButton: document.getElementById("settingsButton"),
  protectionSettings: document.getElementById("protectionSettings"),

  diagnosticUrl: document.getElementById("diagnosticUrl"),
  currentTabButton: document.getElementById("currentTabButton"),
  diagnoseButton: document.getElementById("diagnoseButton"),
  diagnosticMessage: document.getElementById("diagnosticMessage"),
  diagnosticResult: document.getElementById("diagnosticResult"),
  diagnosticHttpBadge: document.getElementById("diagnosticHttpBadge"),
  diagnosisText: document.getElementById("diagnosisText"),
  httpStatus: document.getElementById("httpStatus"),
  latencyValue: document.getElementById("latencyValue"),
  redirectCount: document.getElementById("redirectCount"),
  dnsStatus: document.getElementById("dnsStatus"),
  dnsDetails: document.getElementById("dnsDetails"),
  tlsStatus: document.getElementById("tlsStatus"),
  tlsDetails: document.getElementById("tlsDetails"),
  httpDetails: document.getElementById("httpDetails"),
  redirectList: document.getElementById("redirectList"),
  fixDetails: document.getElementById("fixDetails")
};

let currentUrl = null;

function setMessage(text, type = "") {
  elements.message.textContent = text;
  elements.message.className = `message ${type}`.trim();
}

function setDiagnosticMessage(text, type = "") {
  elements.diagnosticMessage.textContent = text;
  elements.diagnosticMessage.className =
    `diagnostic-message ${type}`.trim();
}

function normalizeClassification(data) {
  const raw = String(
    data.classification || data.prediction || data.label || "unknown"
  ).trim().toLowerCase().replaceAll("_", "-");

  if (["malicious", "phishing", "phishing-url", "high-risk"].includes(raw)) {
    return "malicious";
  }

  if (["suspicious", "potentially-malicious", "medium-risk"].includes(raw)) {
    return "suspicious";
  }

  if (["legitimate", "benign", "safe", "low-risk"].includes(raw)) {
    return "low";
  }

  return "unknown";
}

function classificationLabel(classification) {
  const labels = {
    low: "Low risk",
    suspicious: "Suspicious",
    malicious: "Malicious",
    unknown: "Unknown"
  };

  return labels[classification] || "Unknown";
}

function clearIndicators(message) {
  elements.indicatorList.replaceChildren();

  const li = document.createElement("li");
  li.textContent = message;
  elements.indicatorList.appendChild(li);
}

function renderResult(data) {
  const classification = normalizeClassification(data);
  const rawScore = data.risk_score;

  const hasScore =
    rawScore !== null &&
    rawScore !== undefined &&
    rawScore !== "" &&
    Number.isFinite(Number(rawScore)) &&
    Number(rawScore) >= 0 &&
    Number(rawScore) <= 100;

  elements.resultCard.classList.remove("hidden");

  elements.resultTitle.textContent =
    classification === "malicious" ? "Potential threat detected" :
    classification === "suspicious" ? "Further review recommended" :
    classification === "low" ? "No high-risk signal detected" :
    "Result is inconclusive";

  elements.resultBadge.textContent = classificationLabel(classification);
  elements.resultBadge.className = `risk-badge ${classification}`;

  elements.riskScore.textContent = hasScore ? `${Number(rawScore)}/100` : "N/A";
  elements.scoreFill.style.width = hasScore ? `${Number(rawScore)}%` : "0%";

  elements.scoreFill.style.background =
    classification === "malicious" ? "#ef4444" :
    classification === "suspicious" ? "#f59e0b" :
    classification === "low" ? "#34d399" : "#818cf8";

  elements.modelVersion.textContent =
    typeof data.model_version === "string"
      ? data.model_version
      : "Not provided";

  elements.indicatorList.replaceChildren();

  const indicators = Array.isArray(data.indicators) ? data.indicators : [];

  if (indicators.length === 0) {
    clearIndicators(
      "No detailed indicators were provided by the analysis service."
    );
  } else {
    for (const indicator of indicators.slice(0, 8)) {
      const li = document.createElement("li");

      li.textContent =
        typeof indicator === "string"
          ? indicator
          : indicator && typeof indicator.description === "string"
            ? indicator.description
            : "An indicator was returned without a description.";

      elements.indicatorList.appendChild(li);
    }
  }

  elements.resultDisclaimer.textContent =
    classification === "low"
      ? "No high-risk signal was detected. This does not guarantee that the website is safe."
      : "Automated detection can make mistakes. Avoid entering sensitive information on untrusted websites.";

  setMessage("Analysis response received.", "success");
}

function normalizeHttpUrl(value) {
  let candidate = value.trim();

  if (!candidate) {
    throw new Error("Enter a website URL first.");
  }

  if (!/^[a-z][a-z\d+.-]*:/i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website URL.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS websites are supported.");
  }

  if (!parsed.hostname || parsed.username || parsed.password) {
    throw new Error("Check the website address and try again.");
  }

  return parsed.href;
}

async function loadCurrentTab() {
  elements.resultCard.classList.add("hidden");

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true
    });

    const tab = tabs[0];

    if (!tab || typeof tab.url !== "string") {
      throw new Error("Chrome did not provide an active tab URL.");
    }

    currentUrl = tab.url;

    let parsedUrl;

    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      parsedUrl = null;
    }

    if (!parsedUrl || !["http:", "https:"].includes(parsedUrl.protocol)) {
      elements.siteHost.textContent = "Page cannot be scanned";
      elements.siteUrl.textContent = "Open a regular HTTP or HTTPS website.";
      elements.siteIcon.textContent = "!";
      elements.scanButton.disabled = true;
      setMessage(
        "Browser-internal pages cannot be scanned. You can still enter a public website below."
      );
      return;
    }

    elements.siteHost.textContent = parsedUrl.hostname;
    elements.siteUrl.textContent = currentUrl;
    elements.siteIcon.textContent =
      parsedUrl.protocol === "https:" ? "🔒" : "◎";

    elements.scanButton.disabled = false;
    elements.diagnosticUrl.value = currentUrl;
    setMessage("Ready to analyze this URL.");
  } catch (error) {
    currentUrl = null;
    elements.siteHost.textContent = "Unable to read current tab";
    elements.siteUrl.textContent = "Try opening the extension on a website.";
    elements.siteIcon.textContent = "!";
    elements.scanButton.disabled = true;
    setMessage(error.message || "Unable to read the active tab.", "error");
  }
}

async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);

    let response;

    try {
      response = await fetch(`${API_BASE_URL}/health`, {
        method: "GET",
        signal: controller.signal,
        headers: { Accept: "application/json" }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error("Health check returned an unsuccessful response.");
    }

    elements.connectionDot.className = "status-dot online";
    elements.connectionText.textContent = "Detection service connected";
  } catch {
    elements.connectionDot.className = "status-dot offline";
    elements.connectionText.textContent = "Detection service unavailable";
  }
}

async function scanCurrentUrl() {
  if (!currentUrl) {
    setMessage("No supported website URL is available to scan.", "error");
    return;
  }

  elements.scanButton.disabled = true;
  elements.scanButtonText.textContent = "Analyzing URL...";
  elements.resultCard.classList.add("hidden");
  setMessage("Sending URL to the local ML service...");

  try {
    const response = await chrome.runtime.sendMessage({
      type: "URL_SENTINEL_SCAN",
      url: currentUrl
    });

    if (!response || response.ok !== true || !response.result) {
      throw new Error(
        response?.error || "The scan could not be completed."
      );
    }

    renderResult(response.result);
  } catch (error) {
    elements.resultCard.classList.add("hidden");
    setMessage(
      error.message || "Cannot connect to the URL Sentinel service.",
      "error"
    );
  } finally {
    elements.scanButton.disabled = false;
    elements.scanButtonText.textContent = "Scan Current URL";
    checkBackendHealth();
  }
}

function renderDiagnostic(data) {
  elements.diagnosticResult.classList.remove("hidden");

  const status = data.http?.status_code;
  const latency = data.http?.latency_ms;
  const httpError = data.http?.error;
  const redirects = Array.isArray(data.redirects) ? data.redirects : [];

  elements.diagnosisText.textContent =
    data.diagnosis || "No diagnosis was returned.";

  elements.httpStatus.textContent =
    status === null || status === undefined ? "Unavailable" : String(status);

  elements.latencyValue.textContent =
    typeof latency === "number" ? `${latency} ms` : "N/A";

  elements.redirectCount.textContent = String(
    data.redirect_count ?? redirects.length
  );

  elements.diagnosticHttpBadge.className = "diagnostic-badge";

  if (typeof status === "number" && status >= 200 && status < 400) {
    elements.diagnosticHttpBadge.textContent = "Response received";
    elements.diagnosticHttpBadge.classList.add("good");
  } else if (typeof status === "number" && status >= 400) {
    elements.diagnosticHttpBadge.textContent = "HTTP error";
    elements.diagnosticHttpBadge.classList.add("warning");
  } else {
    elements.diagnosticHttpBadge.textContent = "Connection issue";
    elements.diagnosticHttpBadge.classList.add("bad");
  }

  const dns = data.dns || {};
  elements.dnsStatus.textContent = dns.resolved ? "Resolved" : "Failed";
  elements.dnsDetails.textContent = dns.resolved
    ? `IP addresses: ${(dns.addresses || []).join(", ") || "Not provided"}`
    : dns.error || "DNS resolution did not succeed.";

  const tls = data.tls || {};

  if (tls.checked && tls.valid === true) {
    elements.tlsStatus.textContent = "Valid";
  } else if (tls.valid === false) {
    elements.tlsStatus.textContent = "Certificate problem";
  } else {
    elements.tlsStatus.textContent = "Not verified";
  }

  const tlsParts = [];

  if (tls.issuer) tlsParts.push(`Issuer: ${tls.issuer}`);
  if (tls.expires_at) tlsParts.push(`Expires: ${tls.expires_at}`);
  if (tls.error) tlsParts.push(`Details: ${tls.error}`);

  elements.tlsDetails.textContent =
    tlsParts.join(" · ") ||
    "TLS details are unavailable or this URL did not use HTTPS.";

  elements.httpDetails.textContent = [
    `Final URL: ${data.final_url || data.url || "Not provided"}`,
    httpError ? `Connection detail: ${httpError}` : "No HTTP transport error was reported."
  ].join(" · ");

  elements.redirectList.replaceChildren();

  if (redirects.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No redirects reported.";
    elements.redirectList.appendChild(item);
  } else {
    for (const redirect of redirects.slice(0, 6)) {
      const item = document.createElement("li");
      item.textContent =
        `${redirect.status_code}: ${redirect.from} → ${redirect.to}`;
      elements.redirectList.appendChild(item);
    }
  }

  elements.fixDetails.textContent = suggestFix(data);
}

function suggestFix(data) {
  const status = data.http?.status_code;
  const error = String(data.http?.error || "").toLowerCase();
  const tls = data.tls || {};
  const dns = data.dns || {};
  const suggestions = [];

  if (!dns.resolved) {
    suggestions.push(
      "DNS: check the spelling of the domain, your internet connection and DNS settings."
    );
  }

  if (tls.valid === false) {
    suggestions.push(
      "TLS: check the device date/time and certificate configuration. Do not bypass certificate warnings on an untrusted site."
    );
  }

  if (error.includes("timed out") || error.includes("timeout")) {
    suggestions.push(
      "Timeout: retry later and check your network, VPN, proxy or firewall."
    );
  }

  if (status === 404) {
    suggestions.push(
      "HTTP 404: check the page path; the resource may have moved or been removed."
    );
  } else if (status === 401 || status === 403) {
    suggestions.push(
      `HTTP ${status}: the server may require authentication or be denying access.`
    );
  } else if (typeof status === "number" && status >= 500) {
    suggestions.push(
      `HTTP ${status}: the website server may be having an issue. Try again later.`
    );
  } else if (status === 429) {
    suggestions.push(
      "HTTP 429: too many requests. Wait before retrying."
    );
  }

  if (error.includes("redirect limit")) {
    suggestions.push(
      "Redirect loop/limit: check the site's redirect configuration."
    );
  }

  if (suggestions.length === 0 && status >= 200 && status < 400) {
    suggestions.push(
      "The server responded. If the page still fails in Chrome, check browser extensions, cookies, JavaScript, login requirements or network restrictions."
    );
  }

  if (suggestions.length === 0) {
    suggestions.push(
      "The exact cause is not confirmed. Check the URL, retry the site and compare using another network or browser."
    );
  }

  return suggestions.join(" ");
}

async function runDiagnostics() {
  let url;

  try {
    url = normalizeHttpUrl(elements.diagnosticUrl.value);
  } catch (error) {
    elements.diagnosticResult.classList.add("hidden");
    setDiagnosticMessage(error.message, "error");
    return;
  }

  elements.diagnoseButton.disabled = true;
  elements.currentTabButton.disabled = true;
  elements.diagnoseButton.textContent = "Checking...";
  elements.diagnosticResult.classList.add("hidden");
  setDiagnosticMessage("Checking DNS, TLS, HTTP response and redirects...");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45000);

    let response;

    try {
      response = await fetch(`${API_BASE_URL}/diagnostics`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const detail =
        typeof data.detail === "string"
          ? data.detail
          : "The diagnostics service rejected the request.";

      throw new Error(detail);
    }

    renderDiagnostic(data);
    setDiagnosticMessage("Diagnostics completed.", "success");
  } catch (error) {
    const message =
      error.name === "AbortError"
        ? "The diagnostic request timed out. Check that the backend is running."
        : error.message || "Diagnostics could not be completed.";

    setDiagnosticMessage(message, "error");
  } finally {
    elements.diagnoseButton.disabled = false;
    elements.currentTabButton.disabled = false;
    elements.diagnoseButton.textContent = "Diagnose";
  }
}

async function useCurrentTab() {
  try {
    const tabs = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true
    });

    const tab = tabs[0];

    if (!tab || typeof tab.url !== "string") {
      throw new Error("Unable to read the current tab URL.");
    }

    const url = normalizeHttpUrl(tab.url);
    elements.diagnosticUrl.value = url;
    setDiagnosticMessage("Current tab URL selected.");
  } catch (error) {
    setDiagnosticMessage(
      error.message || "This browser page cannot be diagnosed.",
      "error"
    );
  }
}

async function loadProtectionStatus() {
  try {
    const settings = await chrome.storage.local.get({
      automaticProtection: false
    });

    elements.protectionText.textContent = settings.automaticProtection
      ? "Enabled in settings. Navigation checks will be available after setup."
      : "Currently off. Configure it in settings.";
  } catch {
    elements.protectionText.textContent =
      "Open settings to configure protection.";
  }
}

function openSettings() {
  chrome.runtime.openOptionsPage();
}

elements.scanButton.addEventListener("click", scanCurrentUrl);
elements.settingsButton.addEventListener("click", openSettings);
elements.protectionSettings.addEventListener("click", openSettings);
elements.currentTabButton.addEventListener("click", useCurrentTab);
elements.diagnoseButton.addEventListener("click", runDiagnostics);

elements.diagnosticUrl.addEventListener("keydown", event => {
  if (event.key === "Enter") runDiagnostics();
});

document.addEventListener("DOMContentLoaded", async () => {
  await Promise.all([
    loadCurrentTab(),
    checkBackendHealth(),
    loadProtectionStatus()
  ]);
});
