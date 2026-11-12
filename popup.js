/**
 * PhishGuard Lite - popup.js
 * Reads the active tab's URL, runs the detector, saves the scan to history,
 * and renders the dashboard.
 */
"use strict";

const $ = (id) => document.getElementById(id);

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const MESSAGES = {
  low: "No strong signs of phishing were found. Stay careful anyway.",
  medium: "Some suspicious signs were found. Double-check before entering personal information.",
  high: "Several suspicious signs were found. Avoid entering passwords or payment details unless you are sure this site is genuine.",
};

/* ---------- Rendering ---------- */

function setGauge(score) {
  const fill = $("gaugeFill");
  fill.style.strokeDasharray = String(CIRCUMFERENCE);
  fill.style.strokeDashoffset = String(CIRCUMFERENCE * (1 - score / 100));
}

// Uses textContent (never innerHTML) because indicator text is built from the URL.
function renderIndicators(indicators, emptyText) {
  const list = $("indicators");
  list.replaceChildren();
  $("count").textContent = String(indicators.length);

  if (indicators.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = emptyText;
    list.appendChild(li);
    return;
  }

  for (const item of indicators) {
    const li = document.createElement("li");
    li.className = "indicator";

    const top = document.createElement("div");
    top.className = "indicator-top";

    const title = document.createElement("span");
    title.textContent = item.title;

    const points = document.createElement("span");
    points.className = "points";
    points.textContent = "+" + item.points;

    top.append(title, points);

    const detail = document.createElement("p");
    detail.textContent = item.detail;

    li.append(top, detail);
    list.appendChild(li);
  }
}

function renderResult(result) {
  $("domain").textContent = result.domain;
  $("url").textContent = result.url;
  $("url").title = result.url;

  const badge = $("protocol");
  badge.hidden = false;
  badge.textContent = result.protocol.toUpperCase();
  badge.className = "badge " + result.protocol;

  $("statusCard").dataset.level = result.level;
  $("score").textContent = String(result.score);
  setGauge(result.score);
  $("statusLabel").textContent = result.label;
  $("statusMessage").textContent = MESSAGES[result.level];
  renderIndicators(result.indicators, "No suspicious indicators found.");
}

function renderNotice(title, message, url) {
  $("domain").textContent = title;
  $("url").textContent = url || "";
  $("url").title = url || "";
  $("protocol").hidden = true;

  $("statusCard").dataset.level = "neutral";
  $("score").textContent = "–";
  setGauge(0);
  $("statusLabel").textContent = "Not scanned";
  $("statusMessage").textContent = message;
  renderIndicators([], "Nothing to show for this page.");
}

/* ---------- Scanning ---------- */

async function getActiveTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs[0] && tabs[0].url ? tabs[0].url : null;
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function scan() {
  const btn = $("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning…";

  try {
    // The short wait only exists so the button feedback is visible.
    const [url] = await Promise.all([getActiveTabUrl(), wait(300)]);

    if (!url) {
      renderNotice(
        "Unavailable",
        "Chrome did not share this tab's address. Open a normal website and click the extension icon again.",
        ""
      );
      return;
    }

    const result = PhishGuard.analyzeUrl(url);

    if (!result.supported) {
      renderNotice("Page not analyzed", result.reason, url);
      return;
    }

    renderResult(result);

    // Saving is separate so a storage problem never breaks the dashboard.
    try {
      await PhishGuard.saveScan(result);
    } catch (saveErr) {
      console.error("PhishGuard could not save history:", saveErr);
    }
  } catch (err) {
    console.error("PhishGuard scan failed:", err);
    renderNotice("Something went wrong", "The scan could not be completed. Please try again.", "");
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan again";
  }
}

function openHistory() {
  chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  window.close();
}

/* ---------- Start ---------- */

$("scanBtn").addEventListener("click", scan);
$("historyBtn").addEventListener("click", openHistory);

setGauge(0);
scan();