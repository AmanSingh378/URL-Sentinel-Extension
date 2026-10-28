"use strict";

const API_BASE_URL = "http://127.0.0.1:8000";
const MAX_RECENT_SCANS = 50;
const BYPASS_TTL_MS = 15000;

const scansInProgress = new Set();

function getBypassKey(tabId, url) {
  return `bypass_${tabId}_${url}`;
}

// Initialize extension settings.
chrome.runtime.onInstalled.addListener(async () => {
  try {
    const existing = await chrome.storage.local.get({
      automaticProtection: true,
      recentScans: [],
      saveHistory: true
    });

    await chrome.storage.local.set({
      automaticProtection: existing.automaticProtection,
      recentScans: existing.recentScans,
      saveHistory: existing.saveHistory
    });

    console.log("URL Sentinel settings initialized.");
  } catch (error) {
    console.error("Settings initialization failed:", error);
  }
});

// Automatically scan newly opened webpages.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  let url;
  let scanKey;

  try {
    url = new URL(details.url);

    if (!["http:", "https:"].includes(url.protocol)) return;

    // Check one-time Continue anyway bypass.
    const bypassKey = getBypassKey(details.tabId, url.href);
    const bypassData = await chrome.storage.session.get(bypassKey);
    const bypassExpiry = bypassData[bypassKey];

    if (typeof bypassExpiry === "number") {
      await chrome.storage.session.remove(bypassKey);

      if (bypassExpiry > Date.now()) {
        console.log("URL Sentinel one-time bypass used:", url.href);
        return;
      }
    }

    const settings = await chrome.storage.local.get({
      automaticProtection: false
    });

    if (!settings.automaticProtection) return;

    scanKey = `${details.tabId}:${url.href}`;

    if (scansInProgress.has(scanKey)) return;

    scansInProgress.add(scanKey);

    const response = await scanUrl(url.href);

    if (!response.ok) return;

    const result = response.result;
    const classification = String(
      result.classification || ""
    ).toLowerCase();
    const risk = Number(result.risk_score) || 0;

    console.log("URL Sentinel scan result:", {
      url: url.href,
      classification,
      risk
    });

    const isHighRisk =
      ["malicious", "phishing", "high-risk"].includes(classification) ||
      risk >= 65;

    if (!isHighRisk) return;

    await showThreatNotification(url.hostname, risk);

    const warningUrl = new URL(
      chrome.runtime.getURL("warnings/warning.html")
    );

    warningUrl.searchParams.set("url", url.href);
    warningUrl.searchParams.set("risk", String(risk));

    console.warn("URL Sentinel opening warning page:", {
      hostname: url.hostname,
      risk
    });

    await chrome.tabs.update(details.tabId, {
      url: warningUrl.href
    });
  } catch (error) {
    console.error("URL Sentinel automatic scan failed:", error);
  } finally {
    if (scanKey) scansInProgress.delete(scanKey);
  }
});

// Show notification for potentially risky URLs.
async function showThreatNotification(hostname, risk) {
  try {
    const notificationId = await chrome.notifications.create("", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: "URL Sentinel: Potential Threat",
      message: `${hostname} may be unsafe. Risk score: ${Number(
        risk
      ).toFixed(1)}/100`,
      priority: 2
    });

    console.log("URL Sentinel notification requested:", notificationId);
  } catch (error) {
    console.error("URL Sentinel notification failed:", error);
  }
}

// Handle popup and warning-page messages.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("URL Sentinel received message:", message?.type);

  if (!message || typeof message.type !== "string") {
    sendResponse({ ok: false, error: "Invalid message." });
    return;
  }

  if (message.type === "URL_SENTINEL_PING") {
    sendResponse({
      ok: true,
      service: "URL Sentinel",
      version: chrome.runtime.getManifest().version
    });
    return;
  }

  if (message.type === "URL_SENTINEL_SCAN") {
    scanUrl(message.url)
      .then(sendResponse)
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error.message || "Unable to scan this URL."
        });
      });

    return true;
  }

  if (message.type === "URL_SENTINEL_CONTINUE") {
    handleContinue(message, sender)
      .then(sendResponse)
      .catch((error) => {
        console.error("Continue handler failed:", error);

        sendResponse({
          ok: false,
          error: error.message || "Navigation failed."
        });
      });

    return true;
  }

  sendResponse({
    ok: false,
    error: "Unknown message type."
  });
});

// Continue to the original website after an explicit user action.
async function handleContinue(message, sender) {
  const targetUrl = new URL(message.url || "");

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are allowed.");
  }

  if (targetUrl.username || targetUrl.password) {
    throw new Error("URLs containing credentials are not allowed.");
  }

  // Verify that the message came from our warning page.
  const senderUrl = new URL(sender.url || "");
  const expectedUrl = new URL(
    chrome.runtime.getURL("warnings/warning.html")
  );

  if (
    senderUrl.origin !== expectedUrl.origin ||
    senderUrl.pathname !== expectedUrl.pathname
  ) {
    throw new Error("Request did not come from the warning page.");
  }

  // Use the sender's actual tab, not a caller-supplied tab ID.
  const tabId = sender.tab?.id;

  if (!Number.isInteger(tabId)) {
    throw new Error("Could not identify the warning tab.");
  }

  const key = getBypassKey(tabId, targetUrl.href);

  await chrome.storage.session.set({
    [key]: Date.now() + BYPASS_TTL_MS
  });

  try {
    await chrome.tabs.update(tabId, {
      url: targetUrl.href
    });
  } catch (error) {
    await chrome.storage.session.remove(key);
    throw error;
  }

  console.log("URL Sentinel continue approved:", {
    tabId,
    url: targetUrl.href
  });

  return { ok: true };
}

// Send a URL to the API and save scan history.
async function scanUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("Please provide a URL to scan.");
  }

  let parsedUrl;

  try {
    parsedUrl = new URL(rawUrl.trim());
  } catch {
    throw new Error("Please enter a valid URL.");
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be scanned.");
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new Error(
      "URLs containing embedded credentials are not supported."
    );
  }

  let response;

  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: parsedUrl.href })
    });
  } catch (error) {
    throw new Error(
      `Cannot connect to URL Sentinel API. Check whether the backend is running. ${error.message}`
    );
  }

  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error("The API returned an invalid response.");
  }

  if (!response.ok) {
    throw new Error(
      data.detail || data.message || "URL scan failed."
    );
  }

  const result = {
    url: data.url || parsedUrl.href,
    classification: data.classification,
    risk_score: data.risk_score,
    model_version: data.model_version,
    indicators: Array.isArray(data.indicators) ? data.indicators : [],
    scannedAt: new Date().toISOString()
  };

  const settings = await chrome.storage.local.get({
    recentScans: [],
    saveHistory: true
  });

  if (settings.saveHistory) {
    const previousScans = Array.isArray(settings.recentScans)
      ? settings.recentScans
      : [];

    const recentScans = [
      result,
      ...previousScans.filter((item) => item.url !== result.url)
    ].slice(0, MAX_RECENT_SCANS);

    await chrome.storage.local.set({ recentScans });
  }

  return {
    ok: true,
    result
  };
}
