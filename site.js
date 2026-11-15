/**
 * PhishGuard Lite - site.js (website version)
 * Reuses detector.js unchanged. Web pages have no chrome.storage, so a small shim below
 * saves the same data to localStorage instead.
 */
"use strict";

/* ---------- Storage shim ---------- */
if (!(window.chrome && chrome.storage && chrome.storage.local)) {
  const PREFIX = "phishguard:";
  const local = {
    async get(key) {
      let value = null;
      try { value = JSON.parse(localStorage.getItem(PREFIX + key)); } catch (e) { /* storage blocked or corrupt */ }
      return value === null ? {} : { [key]: value };
    },
    async set(items) {
      for (const key of Object.keys(items)) localStorage.setItem(PREFIX + key, JSON.stringify(items[key]));
    },
    async remove(key) { localStorage.removeItem(PREFIX + key); },
  };
  window.chrome = Object.assign(window.chrome || {}, { storage: { local } });
}

/* ---------- Helpers ---------- */
const $ = (id) => document.getElementById(id);
const P = PhishGuard;
const CIRCUMFERENCE = 2 * Math.PI * 52;
const MESSAGES = {
  low: "No strong signs of phishing. Stay careful.",
  medium: "Some suspicious signs. Check before entering personal data.",
  high: "Several suspicious signs. Do not enter passwords or payment details unless you are sure.",
  trusted: "This site is on your trusted list. Rules were skipped.",
};
const STORAGE_ERROR = "Could not save. Allow site storage in your browser and retry.";
let current = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text; // textContent only: URLs are untrusted
  return node;
}

function note(id, text, kind) {
  const node = $(id);
  node.textContent = text;
  node.className = "msg" + (kind ? " " + kind : "");
}

function show(view) {
  for (const name of ["scan", "history", "trusted"]) $("v-" + name).hidden = name !== view;
  document.querySelectorAll("#tabs button").forEach((b) => {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  if (view === "history") renderHistory();
  if (view === "trusted") renderTrusted();
}

/* ---------- Scan ---------- */
function render(r) {
  current = r;
  $("result").hidden = false;
  $("rDomain").textContent = r.domain + " · " + r.protocol.toUpperCase();
  $("rUrl").textContent = r.url;
  $("rStatus").dataset.level = r.level;
  $("rScore").textContent = r.score;
  $("gFill").style.strokeDasharray = CIRCUMFERENCE;
  $("gFill").style.strokeDashoffset = CIRCUMFERENCE * (1 - r.score / 100);
  $("rLabel").textContent = r.label;
  $("rMsg").textContent = MESSAGES[r.trusted ? "trusted" : r.level];
  $("trustBtn").textContent = r.trusted ? "Remove from trusted" : "Trust this site";
  note("trustMsg", "");
  $("rCount").textContent = r.indicators.length;

  const list = $("rInd");
  list.replaceChildren();
  if (!r.indicators.length) {
    list.append(el("li", "empty", r.trusted ? "Skipped: site is trusted." : "No suspicious indicators."));
  }
  for (const i of r.indicators) {
    const li = el("li", "ind");
    const top = el("div", "top");
    top.append(el("span", "", i.title), el("span", "pts " + (i.points >= 25 ? "h" : i.points >= 12 ? "m" : "l"), "+" + i.points));
    li.append(top, el("p", "", i.detail));
    list.append(li);
  }

  const lines = [];
  if (r.indicators.length === 1) lines.push("Score: " + r.rawScore);
  else if (r.indicators.length > 1) lines.push("Score: " + r.indicators.map((i) => i.points).join(" + ") + " = " + r.rawScore);
  if (r.scoreNote) lines.push(r.scoreNote);
  $("rSum").replaceChildren(...lines.map((t) => el("p", "", t)));
  $("rSum").hidden = lines.length === 0;
}

async function scan(text) {
  let url = String(text || "").trim();
  if (!url) return note("scanMsg", "Enter a URL to scan.", "err");
  // Add https:// when no scheme is given (also for host:port such as localhost:3000)
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url) || /^[^/]*:\d+(\/|$)/.test(url)) url = "https://" + url;

  const result = await P.scanUrl(url);
  if (!result.supported) {
    $("result").hidden = true;
    return note("scanMsg", result.reason + " Enter a web address.", "err");
  }
  note("scanMsg", "");
  $("urlIn").value = url;
  try { await P.saveScan(result); } catch (e) { console.error("History not saved:", e); }
  render(result);
}

/* ---------- History ---------- */
async function renderHistory() {
  let history = [];
  try { history = await P.getHistory(); } catch (e) { console.error(e); }
  const list = $("hList");
  list.replaceChildren();
  $("clearBtn").hidden = history.length === 0;
  if (!history.length) return list.append(el("li", "empty", "No scans yet. Scan a URL to see it here."));

  for (const e of history) {
    const row = el("button", "item");
    row.type = "button";
    row.dataset.level = e.level;
    const left = el("span", "col");
    left.append(el("span", "name", e.domain), el("span", "url", new Date(e.scannedAt).toLocaleString()));
    row.append(left, el("span", "pill", e.score + "/100 · " + e.label));
    row.addEventListener("click", () => { show("scan"); scan(e.url); });
    const li = el("li");
    li.append(row);
    list.append(li);
  }
}

/* ---------- Trusted domains ---------- */
async function renderTrusted() {
  let trusted = [];
  try { trusted = await P.getTrustedDomains(); } catch (e) { console.error(e); }
  const list = $("tList");
  list.replaceChildren();
  if (!trusted.length) return list.append(el("li", "empty", "No trusted domains yet."));

  for (const domain of trusted) {
    const li = el("li", "item");
    const remove = el("button", "btn danger sm", "Remove");
    remove.type = "button";
    remove.setAttribute("aria-label", "Remove " + domain);
    remove.addEventListener("click", async () => {
      try {
        await P.removeTrustedDomain(domain);
        note("tMsg", "Removed " + domain + ".", "ok");
        renderTrusted();
      } catch (e) { note("tMsg", STORAGE_ERROR, "err"); }
    });
    li.append(el("span", "name", domain), remove);
    list.append(li);
  }
}

async function addTrusted() {
  try {
    const r = await P.addTrustedDomain($("tIn").value);
    if (!r.ok) return note("tMsg", r.error, "err");
    $("tIn").value = "";
    note("tMsg", "Added " + r.domain + ".", "ok");
    renderTrusted();
  } catch (e) { note("tMsg", STORAGE_ERROR, "err"); }
}

/* ---------- Events ---------- */
$("scanBtn").addEventListener("click", () => scan($("urlIn").value));
$("urlIn").addEventListener("keydown", (e) => { if (e.key === "Enter") scan($("urlIn").value); });
document.querySelectorAll("[data-ex]").forEach((b) => b.addEventListener("click", () => scan(b.dataset.ex)));
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
$("clearBtn").addEventListener("click", async () => {
  if (!confirm("Delete all scan history?")) return;
  try { await P.clearHistory(); } catch (e) { console.error(e); }
  renderHistory();
});
$("tAdd").addEventListener("click", addTrusted);
$("tIn").addEventListener("keydown", (e) => { if (e.key === "Enter") addTrusted(); });
$("trustBtn").addEventListener("click", async () => {
  if (!current) return;
  try {
    if (current.trusted) {
      await P.removeTrustedDomain(current.trustedBy);
    } else {
      const r = await P.addTrustedDomain(current.domain.replace(/^www\./, ""));
      if (!r.ok) return note("trustMsg", r.error, "err");
    }
    await scan(current.url);
  } catch (e) { note("trustMsg", STORAGE_ERROR, "err"); }
});

$("gFill").style.strokeDasharray = CIRCUMFERENCE;
$("gFill").style.strokeDashoffset = CIRCUMFERENCE;