/**
 * PhishGuard Lite - background.js (service worker)
 * Scans every page when it finishes loading, shows a badge on the toolbar icon,
 * and shows a warning notification for high-risk pages.
 * It never blocks a page: the score is only a heuristic, so the user decides.
 */
"use strict";

importScripts("detector.js");

const NOTIFIED_KEY = "recentlyNotified";
const NOTIFY_COOLDOWN_MS = 10 * 60 * 1000; // don't warn about the same URL again for 10 minutes
const NOTIFICATION_PREFIX = "phishguard-";

const BADGES = {
  high: { text: "!", color: "#ef4444" },
  medium: { text: "!", color: "#eab308" },
};

/* ---------- Helpers ---------- */

function truncate(text, max) {
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

// A tab can close before we update it, so errors here are ignored on purpose.
async function setBadge(tabId, level) {
  try {
    const badge = BADGES[level];
    if (!badge) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    await chrome.action.setBadgeText({ tabId, text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  } catch (e) {
    /* tab no longer exists */
  }
}

/**
 * Returns true if we haven't warned about this URL recently.
 * Uses chrome.storage.session because the service worker can be stopped at any time,
 * which would erase normal variables. Session storage is cleared when Chrome closes.
 */
async function shouldNotify(url) {
  const data = await chrome.storage.session.get(NOTIFIED_KEY);
  const notified = data[NOTIFIED_KEY] || {};
  const now = Date.now();

  for (const key of Object.keys(notified)) {
    if (now - notified[key] > NOTIFY_COOLDOWN_MS) delete notified[key];
  }

  const alreadyWarned = Boolean(notified[url]);
  if (!alreadyWarned) notified[url] = now;

  await chrome.storage.session.set({ [NOTIFIED_KEY]: notified });
  return !alreadyWarned;
}

function showWarning(result) {
  const reasons = result.indicators.slice(0, 3).map((i) => i.title).join(", ");

  chrome.notifications.create(NOTIFICATION_PREFIX + Date.now(), {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `PhishGuard: ${result.label} (${result.score}/100)`,
    message: `${truncate(result.url, 90)}\nWhy: ${reasons}`,
    contextMessage: "Heuristic result. This is not a confirmed phishing site.",
    priority: 2,
    requireInteraction: true, // stays visible until the user dismisses it
  });
}

/* ---------- Automatic scan ---------- */

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  try {
    const result = PhishGuard.analyzeUrl(tab.url);

    if (!result.supported) {
      await setBadge(tabId, "low");
      return;
    }

    await setBadge(tabId, result.level);

    // Low-risk pages are not stored, so History never becomes a full browsing log.
    // (Low-risk pages still get saved when the user scans them from the popup.)
    if (result.level === "low") return;

    await PhishGuard.saveScan(result);

    if (result.level === "high" && (await shouldNotify(result.url))) {
      showWarning(result);
    }
  } catch (err) {
    console.error("PhishGuard background scan failed:", err);
  }
});

/* ---------- Notification click ---------- */

chrome.notifications.onClicked.addListener((notificationId) => {
  if (!notificationId.startsWith(NOTIFICATION_PREFIX)) return;
  chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  chrome.notifications.clear(notificationId);
});