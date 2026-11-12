/**
 * PhishGuard Lite - detector.js
 * Rule-based URL analysis. Pure JavaScript: no network calls.
 * analyzeUrl() never touches Chrome APIs; only the history functions at the bottom do.
 *
 * Usage:  const result = PhishGuard.analyzeUrl("https://example.com");
 */
(function (global) {
  "use strict";

  /* ---------- Configuration (easy to tweak) ---------- */
  const CONFIG = {
    longUrl: 75,
    veryLongUrl: 120,
    singleIndicatorCap: 45, // one weak signal alone can never exceed this
    mediumThreshold: 30,
    highThreshold: 60,
  };

  const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "wallet",
    "suspend", "unlock", "billing", "payment",
  ];

  // brand -> official registrable domains
  const BRANDS = {
    paypal: ["paypal.com"],
    google: ["google.com", "google.co.in"],
    microsoft: ["microsoft.com", "live.com", "office.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com", "amazon.in", "amazon.co.uk"],
    facebook: ["facebook.com"],
    instagram: ["instagram.com"],
    netflix: ["netflix.com"],
    whatsapp: ["whatsapp.com"],
    linkedin: ["linkedin.com"],
    dropbox: ["dropbox.com"],
    paytm: ["paytm.com"],
    sbi: ["sbi.co.in", "onlinesbi.sbi"],
    hdfc: ["hdfcbank.com"],
    icici: ["icicibank.com"],
  };

  const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "edu", "ac"]);

  /* ---------- Helpers ---------- */

  /** Approximate registrable domain (handles co.in, com.au, etc.). */
  function getRegistrableDomain(hostname) {
    const labels = hostname.split(".");
    if (labels.length <= 2) return hostname;
    const last = labels[labels.length - 1];
    const secondLast = labels[labels.length - 2];
    const take = last.length === 2 && SECOND_LEVEL.has(secondLast) ? 3 : 2;
    return labels.slice(-take).join(".");
  }

  function isIpAddress(hostname) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^\[[0-9a-f:.]+\]$/i;
    return ipv4.test(hostname) || ipv6.test(hostname);
  }

  function safeDecode(text) {
    try { return decodeURIComponent(text); } catch (e) { return text; }
  }

  function getRiskLevel(score) {
    if (score >= CONFIG.highThreshold) {
      return { level: "high", label: "High Risk", color: "#ef4444" };
    }
    if (score >= CONFIG.mediumThreshold) {
      return { level: "medium", label: "Medium Risk", color: "#eab308" };
    }
    return { level: "low", label: "Low Risk", color: "#22c55e" };
  }

  /* ---------- Main analysis ---------- */

  function analyzeUrl(rawUrl) {
    let url;
    try {
      url = new URL(rawUrl);
    } catch (e) {
      return { supported: false, url: String(rawUrl), reason: "This is not a valid URL." };
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return {
        supported: false,
        url: rawUrl,
        reason: "Only http:// and https:// pages can be analyzed (this looks like a browser or local page).",
      };
    }

    const hostname = url.hostname.toLowerCase();
    const registrable = getRegistrableDomain(hostname);
    const indicators = [];
    const add = (id, title, detail, points) =>
      indicators.push({ id, title, detail, points });

    // 1. HTTP instead of HTTPS
    if (url.protocol === "http:") {
      add("http", "No HTTPS", "The connection is not encrypted (http://).", 10);
    }

    // 2. IP address instead of a domain name
    const usesIp = isIpAddress(hostname);
    if (usesIp) {
      add("ip", "IP address URL", "The site uses a raw IP address instead of a domain name.", 30);
    }

    // 3. Unusually long URL
    if (rawUrl.length > CONFIG.veryLongUrl) {
      add("long", "Very long URL", `The URL has ${rawUrl.length} characters.`, 15);
    } else if (rawUrl.length > CONFIG.longUrl) {
      add("long", "Long URL", `The URL has ${rawUrl.length} characters.`, 8);
    }

    // 4. '@' symbol
    if (rawUrl.includes("@")) {
      if (url.username) {
        add("at", "'@' hides the real host",
          "Text before '@' is ignored by the browser, which can disguise the real destination.", 25);
      } else {
        add("at", "'@' in URL", "An '@' symbol appears in the path or query.", 8);
      }
    }

    // 5. Excessive hyphens in the domain
    const hyphens = (hostname.match(/-/g) || []).length;
    if (hyphens >= 5) {
      add("hyphens", "Excessive hyphens", `The domain contains ${hyphens} hyphens.`, 14);
    } else if (hyphens >= 3) {
      add("hyphens", "Many hyphens", `The domain contains ${hyphens} hyphens.`, 8);
    }

    // 6. Misleading subdomains
    if (!usesIp) {
      const subCount = hostname.split(".").length - registrable.split(".").length;
      if (subCount >= 4) {
        add("subdomains", "Too many subdomains", `${subCount} subdomain levels can hide the real domain.`, 15);
      } else if (subCount === 3) {
        add("subdomains", "Deep subdomain nesting", `${subCount} subdomain levels found.`, 8);
      }

      // Brand name used on a domain that is not the official one
      const tokens = hostname.split(/[.\-_]/);
      for (const brand of Object.keys(BRANDS)) {
        if (tokens.includes(brand) && !BRANDS[brand].includes(registrable)) {
          add("brand", "Possible brand impersonation",
            `The domain mentions "${brand}" but the real domain is "${registrable}".`, 30);
          break;
        }
      }
    }

    // 7. Suspicious keywords (host + path + query)
    const searchable = safeDecode(hostname + url.pathname + url.search).toLowerCase();
    const found = SUSPICIOUS_KEYWORDS.filter((k) => searchable.includes(k));
    if (found.length > 0) {
      const pts = found.length >= 3 ? 20 : found.length === 2 ? 14 : 8;
      add("keywords", "Suspicious keywords", `Found: ${found.join(", ")}.`, pts);
    }

    // 8. Suspicious URL encoding / punycode
    const encodedCount = (rawUrl.match(/%[0-9a-f]{2}/gi) || []).length;
    const riskyEncoding = /%(40|2e|2f|5c|25)/i.test(rawUrl);
    if (riskyEncoding) {
      add("encoding", "Suspicious encoding",
        "Encoded characters such as @ . / \\ or double-encoding were found.", 15);
    } else if (encodedCount >= 3) {
      add("encoding", "Heavy URL encoding", `${encodedCount} percent-encoded characters found.`, 8);
    }
    if (hostname.split(".").some((l) => l.startsWith("xn--"))) {
      add("punycode", "Punycode domain",
        "The domain uses punycode, which can imitate look-alike characters.", 12);
    }

    /* ---------- Scoring ---------- */
    indicators.sort((a, b) => b.points - a.points);
    let score = indicators.reduce((sum, i) => sum + i.points, 0);
    score = Math.min(score, 100);
    if (indicators.length === 1) {
      score = Math.min(score, CONFIG.singleIndicatorCap);
    }

    return {
      supported: true,
      url: rawUrl,
      protocol: url.protocol.replace(":", ""),
      domain: hostname,
      score,
      ...getRiskLevel(score),
      indicators,
      scannedAt: Date.now(),
    };
  }

  /* ---------- Scan history (chrome.storage.local) ---------- */

  const HISTORY_KEY = "scanHistory";
  const HISTORY_LIMIT = 10;

  async function getHistory() {
    const data = await chrome.storage.local.get(HISTORY_KEY);
    return Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
  }

  /** Saves a scan result. Re-scanning the same URL updates its entry instead of duplicating it. */
  async function saveScan(result) {
    if (!result || !result.supported) return;

    const entry = {
      url: result.url,
      domain: result.domain,
      score: result.score,
      level: result.level,
      label: result.label,
      scannedAt: result.scannedAt,
    };

    let history = await getHistory();
    history = history.filter((e) => e.url !== entry.url);
    history.unshift(entry);                        // newest first
    history = history.slice(0, HISTORY_LIMIT);     // keep only the last 10
    await chrome.storage.local.set({ [HISTORY_KEY]: history });
  }

  async function clearHistory() {
    await chrome.storage.local.remove(HISTORY_KEY);
  }

  global.PhishGuard = {
    analyzeUrl,
    getRiskLevel,
    getHistory,
    saveScan,
    clearHistory,
    HISTORY_KEY,
  };
})(typeof self !== "undefined" ? self : window);