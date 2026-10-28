"use strict";

const targetUrl = document.getElementById("targetUrl");
const riskScore = document.getElementById("riskScore");
const riskBar = document.getElementById("riskBar");
const classification = document.getElementById("classification");
const backButton = document.getElementById("backButton");
const continueButton = document.getElementById("continueButton");
const statusMessage = document.getElementById("statusMessage");

// Read URL and risk score from the warning page query parameters.
const params = new URLSearchParams(window.location.search);
const rawUrl = params.get("url");
const rawRisk = Number(params.get("risk"));

const risk = Number.isFinite(rawRisk)
  ? Math.min(100, Math.max(0, rawRisk))
  : null;

// Validate the original URL before allowing navigation.
let safeTargetUrl = null;

try {
  const parsed = new URL(rawUrl);

  if (
    ["http:", "https:"].includes(parsed.protocol) &&
    !parsed.username &&
    !parsed.password
  ) {
    safeTargetUrl = parsed.href;
  }
} catch {
  safeTargetUrl = null;
}

// Display the warning details safely.
targetUrl.textContent = safeTargetUrl || "Original URL unavailable";

riskScore.textContent =
  risk === null ? "Unavailable" : `${risk.toFixed(1)}/100`;

riskBar.style.width = `${risk ?? 0}%`;

classification.textContent =
  risk === null
    ? "Scan result unavailable"
    : risk >= 65
      ? "Potentially high risk"
      : "Review recommended";

// Disable Continue if the original URL is invalid.
if (!safeTargetUrl) {
  continueButton.disabled = true;
  statusMessage.textContent = "The original URL is invalid or unavailable.";
}

// Go back to safety by opening a new tab.
backButton.addEventListener("click", async () => {
  backButton.disabled = true;
  statusMessage.textContent = "Opening a safe page...";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const currentTab = tabs[0];

    if (currentTab?.id === undefined) {
      throw new Error("Could not identify the current tab.");
    }

    await chrome.tabs.update(currentTab.id, {
      url: "chrome://newtab/",
    });
  } catch (error) {
    console.error("URL Sentinel back button error:", error);

    backButton.disabled = false;
    statusMessage.textContent =
      "Unable to open a safe page. Please close this tab manually.";
  }
});

// Continue to the original URL through the background service worker.

continueButton.addEventListener("click", async () => {
  if (!safeTargetUrl) {
    statusMessage.textContent = "Original URL is invalid.";
    return;
  }

  continueButton.disabled = true;
  statusMessage.textContent = "Opening website...";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const tabId = tabs[0]?.id;

    if (tabId === undefined) {
      throw new Error("Could not identify the warning tab.");
    }

    const response = await chrome.runtime.sendMessage({
      type: "URL_SENTINEL_CONTINUE",
      url: safeTargetUrl,
      tabId,
    });

    console.log("Continue response:", response);

    if (!response?.ok) {
      const reason = response?.error || JSON.stringify(response);
      console.error("Service worker rejection reason:", reason);
      throw new Error(reason);
    }
  } catch (error) {
    console.error("Continue failed:", error);
    statusMessage.textContent = error.message;
    continueButton.disabled = false;
  }
});
