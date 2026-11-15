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

/** Sets the position of a list row; site.css uses it to delay its entrance. */
function stagger(node, index) {
  node.style.setProperty("--i", String(Math.min(index, 10)));
  return node;
}

/* ---------- Motion ---------- */
const reducedMotion = () =>
  Boolean(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

/** Redraws the gauge from empty so the fill animates on every scan. */
function setGauge(score) {
  const fill = $("gFill");
  fill.style.strokeDasharray = String(CIRCUMFERENCE);
  fill.style.transition = "none";
  fill.style.strokeDashoffset = String(CIRCUMFERENCE);
  fill.getBoundingClientRect(); // force a reflow so the next change animates
  fill.style.transition = "";
  fill.style.strokeDashoffset = String(CIRCUMFERENCE * (1 - score / 100));
}

let countFrame = 0;

/** Counts the score up from 0. Shows the final number at once if motion is reduced. */
function countUp(node, target) {
  cancelAnimationFrame(countFrame);
  if (reducedMotion() || target === 0) {
    node.textContent = String(target);
    return;
  }
  const duration = 700;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    node.textContent = String(Math.round(target * eased));
    if (t < 1) countFrame = requestAnimationFrame(step);
  };
  node.textContent = "0";
  countFrame = requestAnimationFrame(step);
}

/* ---------- Scan ---------- */
function render(r) {
  current = r;
  $("idle").hidden = true;

  // Restart the entrance animation on every scan, including a re-scan of the same site.
  const result = $("result");
  result.hidden = false;
  result.classList.remove("enter");
  void result.offsetWidth;
  result.classList.add("enter");

  $("rDomain").textContent = r.domain + " · " + r.protocol.toUpperCase();
  $("rUrl").textContent = r.url;
  $("rStatus").dataset.level = r.level;
  countUp($("rScore"), r.score);
  setGauge(r.score);
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
  r.indicators.forEach((i, index) => {
    const weight = i.points >= 25 ? "h" : i.points >= 12 ? "m" : "l";
    const li = stagger(el("li", "ind " + weight), index);
    const top = el("div", "top");
    top.append(el("span", "", i.title), el("span", "pts " + weight, "+" + i.points));
    li.append(top, el("p", "", i.detail));
    list.append(li);
  });

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
    $("idle").hidden = false;
    return note("scanMsg", result.reason + " Enter a web address.", "err");
  }
  note("scanMsg", "");
  $("urlIn").value = url;
  try { await P.saveScan(result); } catch (e) { console.error("History not saved:", e); }
  renderHistory();
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

  history.forEach((e, index) => {
    const row = el("button", "item");
    row.type = "button";
    row.dataset.level = e.level;
    const left = el("span", "col");
    left.append(el("span", "name", e.domain), el("span", "url", new Date(e.scannedAt).toLocaleString()));
    row.append(left, el("span", "pill", e.score + "/100 · " + e.label));
    row.addEventListener("click", () => scan(e.url));
    const li = stagger(el("li"), index);
    li.append(row);
    list.append(li);
  });
}

/* ---------- Trusted domains ---------- */
async function renderTrusted() {
  let trusted = [];
  try { trusted = await P.getTrustedDomains(); } catch (e) { console.error(e); }
  const list = $("tList");
  list.replaceChildren();
  if (!trusted.length) return list.append(el("li", "empty", "No trusted domains yet."));

  trusted.forEach((domain, index) => {
    const li = stagger(el("li", "item"), index);
    const remove = el("button", "btn danger sm", "Remove");
    remove.type = "button";
    remove.setAttribute("aria-label", "Remove " + domain);
    remove.addEventListener("click", async () => {
      try {
        await P.removeTrustedDomain(domain);
        note("tMsg", "Removed " + domain + ".", "ok");
        renderTrusted();
        if (current) scan(current.url);
      } catch (e) { note("tMsg", STORAGE_ERROR, "err"); }
    });
    li.append(el("span", "name", domain), remove);
    list.append(li);
  });
}

async function addTrusted() {
  try {
    const r = await P.addTrustedDomain($("tIn").value);
    if (!r.ok) return note("tMsg", r.error, "err");
    $("tIn").value = "";
    note("tMsg", "Added " + r.domain + ".", "ok");
    renderTrusted();
    if (current) scan(current.url);
  } catch (e) { note("tMsg", STORAGE_ERROR, "err"); }
}

/* ---------- Events ---------- */
$("scanBtn").addEventListener("click", () => scan($("urlIn").value));
$("urlIn").addEventListener("keydown", (e) => { if (e.key === "Enter") scan($("urlIn").value); });
document.querySelectorAll("[data-ex]").forEach((b) => b.addEventListener("click", () => scan(b.dataset.ex)));
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
    renderTrusted();
  } catch (e) { note("trustMsg", STORAGE_ERROR, "err"); }
});

setGauge(0);
renderHistory();
renderTrusted();