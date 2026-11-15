/**
 * PhishGuard Lite - popup.js
 * Reads the active tab's URL, runs the detector (applying the trusted list), saves the scan
 * to history, renders the dashboard, and manages the trusted websites list.
 */
"use strict";

const $ = (id) => document.getElementById(id);

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const MESSAGES = {
  low: "No strong signs of phishing were found. Stay careful anyway.",
  medium: "Some suspicious signs were found. Double-check before entering personal information.",
  high: "Several suspicious signs were found. Avoid entering passwords or payment details unless you are sure this site is genuine.",
  trusted: "This website is on your trusted list, so the suspicious-URL rules were skipped.",
};

let currentHost = null; // hostname of the scanned tab, used by "Use current site"

/* ---------- Rendering ---------- */

function setGauge(score) {
  const fill = $("gaugeFill");
  fill.style.strokeDasharray = String(CIRCUMFERENCE);
  fill.style.strokeDashoffset = String(CIRCUMFERENCE * (1 - score / 100));
}

function pointsClass(points) {
  if (points >= 25) return "points heavy";
  if (points >= 12) return "points medium";
  return "points light";
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
    points.className = pointsClass(item.points);
    points.textContent = "+" + item.points;

    top.append(title, points);

    const detail = document.createElement("p");
    detail.textContent = item.detail;

    li.append(top, detail);
    list.appendChild(li);
  }
}

/** Shows how the score was calculated, e.g. "Score: 30 + 20 + 10 + 8 = 68", plus any note. */
function renderBreakdown(result) {
  const box = $("breakdown");
  const lines = [];

  if (result) {
    if (result.indicators.length === 1) {
      lines.push("Score: " + result.rawScore);
    } else if (result.indicators.length > 1) {
      lines.push("Score: " + result.indicators.map((i) => i.points).join(" + ") + " = " + result.rawScore);
    }
    if (result.scoreNote) lines.push(result.scoreNote);
  }

  box.replaceChildren(
    ...lines.map((text) => {
      const p = document.createElement("p");
      p.textContent = text;
      return p;
    })
  );
  box.hidden = lines.length === 0;
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
  $("statusMessage").textContent = MESSAGES[result.trusted ? "trusted" : result.level];

  renderIndicators(
    result.indicators,
    result.trusted ? "Skipped: this website is on your trusted list." : "No suspicious indicators found."
  );
  renderBreakdown(result);
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
  renderBreakdown(null);
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
  currentHost = null;

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

    const result = await PhishGuard.scanUrl(url);

    if (!result.supported) {
      renderNotice("Page not analyzed", result.reason, url);
      return;
    }

    currentHost = result.domain.replace(/^www\./, "");
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

/* ---------- Trusted websites ---------- */

function showTrustedMessage(text, kind) {
  const msg = $("trustedMsg");
  msg.textContent = text;
  msg.className = "trusted-msg" + (kind ? " " + kind : "");
}

async function renderTrusted() {
  let list = [];
  try {
    list = await PhishGuard.getTrustedDomains();
  } catch (err) {
    console.error("PhishGuard could not load the trusted list:", err);
  }

  $("trustedCount").textContent = String(list.length);

  const ul = $("trustedList");
  ul.replaceChildren();

  if (list.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No trusted websites yet.";
    ul.appendChild(li);
    return;
  }

  for (const domain of list) {
    const li = document.createElement("li");
    li.className = "trusted-item";

    const name = document.createElement("span");
    name.textContent = domain;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-btn";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", "Remove " + domain + " from trusted websites");
    remove.addEventListener("click", () => onRemoveTrusted(domain));

    li.append(name, remove);
    ul.appendChild(li);
  }
}

async function onAddTrusted() {
  const input = $("trustedInput");
  try {
    const result = await PhishGuard.addTrustedDomain(input.value);
    if (!result.ok) {
      showTrustedMessage(result.error, "error");
      return;
    }
    input.value = "";
    showTrustedMessage("Added " + result.domain + ".", "ok");
    await renderTrusted();
    scan(); // refresh the dashboard in case the current site is now trusted
  } catch (err) {
    console.error("PhishGuard could not save the trusted list:", err);
    showTrustedMessage("Could not save the list. Please try again.", "error");
  }
}

async function onRemoveTrusted(domain) {
  try {
    await PhishGuard.removeTrustedDomain(domain);
    showTrustedMessage("Removed " + domain + ".", "ok");
    await renderTrusted();
    scan();
  } catch (err) {
    console.error("PhishGuard could not update the trusted list:", err);
    showTrustedMessage("Could not update the list. Please try again.", "error");
  }
}

function onUseCurrent() {
  if (!currentHost) {
    showTrustedMessage("Open a normal website first, then try again.", "error");
    return;
  }
  $("trustedInput").value = currentHost;
  showTrustedMessage("", "");
  $("trustedInput").focus();
}

/* ---------- Start ---------- */

$("scanBtn").addEventListener("click", scan);
$("historyBtn").addEventListener("click", openHistory);
$("trustedAddBtn").addEventListener("click", onAddTrusted);
$("useCurrentBtn").addEventListener("click", onUseCurrent);
$("trustedInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") onAddTrusted();
});

setGauge(0);
renderTrusted();
scan();