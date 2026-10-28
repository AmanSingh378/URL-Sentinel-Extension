
"use strict";

const automaticProtection = document.getElementById("automaticProtection");
const saveHistory = document.getElementById("saveHistory");
const clearHistory = document.getElementById("clearHistory");

async function loadSettings() {
  const settings = await chrome.storage.local.get({
    automaticProtection: false,
    saveHistory: true,
    recentScans: []
  });

  automaticProtection.checked = settings.automaticProtection;
  saveHistory.checked = settings.saveHistory;
}

automaticProtection.addEventListener("change", async () => {
  await chrome.storage.local.set({
    automaticProtection: automaticProtection.checked
  });

  console.log(
    "Automatic Protection:",
    automaticProtection.checked ? "ON" : "OFF"
  );
});

saveHistory.addEventListener("change", async () => {
  await chrome.storage.local.set({
    saveHistory: saveHistory.checked
  });
});

clearHistory.addEventListener("click", async () => {
  await chrome.storage.local.set({ recentScans: [] });
});

document.addEventListener("DOMContentLoaded", loadSettings);
