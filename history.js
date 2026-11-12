/**
 * PhishGuard Lite - history.js
 * Displays the saved scan history and lets the user clear it.
 */
"use strict";

const $ = (id) => document.getElementById(id);

function buildEntry(item) {
  const li = document.createElement("li");
  li.className = "entry";
  li.dataset.level = ["low", "medium", "high"].includes(item.level) ? item.level : "low";

  const top = document.createElement("div");
  top.className = "entry-top";

  const domain = document.createElement("span");
  domain.className = "domain";
  domain.textContent = item.domain;

  const pill = document.createElement("span");
  pill.className = "pill";
  pill.textContent = item.score + "/100 · " + item.label;

  top.append(domain, pill);

  const url = document.createElement("p");
  url.className = "url";
  url.textContent = item.url;
  url.title = item.url;

  const time = document.createElement("p");
  time.className = "time";
  time.textContent = new Date(item.scannedAt).toLocaleString();

  li.append(top, url, time);
  return li;
}

async function render() {
  let history = [];
  try {
    history = await PhishGuard.getHistory();
  } catch (err) {
    console.error("PhishGuard could not load history:", err);
  }

  const list = $("list");
  list.replaceChildren(...history.map(buildEntry));

  const isEmpty = history.length === 0;
  $("empty").hidden = !isEmpty;
  $("clearBtn").disabled = isEmpty;
  $("countText").textContent = isEmpty
    ? ""
    : history.length + (history.length === 1 ? " scan saved" : " scans saved");
}

async function onClear() {
  if (!confirm("Delete all scan history? This cannot be undone.")) return;
  try {
    await PhishGuard.clearHistory();
  } catch (err) {
    console.error("PhishGuard could not clear history:", err);
  }
  render();
}

$("clearBtn").addEventListener("click", onClear);

// Refresh automatically if a new scan is saved while this page is open.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[PhishGuard.HISTORY_KEY]) render();
});

render();