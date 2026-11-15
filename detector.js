/**
 * PhishGuard Lite - detector.js
 * Rule-based URL analysis. Pure JavaScript: no network calls.
 * analyzeUrl() never touches Chrome APIs; only the storage functions at the bottom do
 * (scan history and the trusted websites list).
 *
 * Usage:  const result = PhishGuard.analyzeUrl("https://example.com");
 *         const result = await PhishGuard.scanUrl("https://example.com"); // also applies the trusted list
 */
(function (global) {
  "use strict";

  /* ---------- Risk weights: points each indicator adds to the score ---------- */
  const WEIGHTS = {
    http: 10,                 // http:// instead of https://
    ip: 30,                   // raw IP address instead of a domain name
    longUrl: 8,               // over CONFIG.longUrl characters
    veryLongUrl: 15,          // over CONFIG.veryLongUrl characters
    atHidesHost: 25,          // user@host trick
    atInUrl: 8,               // '@' in the path or query
    manyHyphens: 8,           // 3-4 hyphens in the domain
    excessiveHyphens: 14,     // 5+ hyphens in the domain
    deepSubdomains: 8,        // 3 subdomain levels
    tooManySubdomains: 15,    // 4+ subdomain levels
    brand: 30,                // known brand name on an unofficial domain
    lookalike: 35,            // misspelled or disguised brand name
    combo: 15,                // brand impersonation + login wording
    brandPath: 12,            // brand name in the path + login wording
    riskyTld: 8,              // cheap / throwaway top-level domain
    shortener: 10,            // link shortener
    keywords1: 8,             // 1 suspicious keyword
    keywords2: 14,            // 2 suspicious keywords
    keywords3: 20,            // 3+ suspicious keywords
    heavyEncoding: 8,         // many %xx sequences
    suspiciousEncoding: 15,   // encoded @ . / \ or double-encoding
    punycode: 12,             // xn-- domain
    redirect: 10,             // another web address inside the URL
    download: 12,             // direct link to a program file
  };

  /* ---------- Configuration (easy to tweak) ---------- */
  const CONFIG = {
    longUrl: 75,
    veryLongUrl: 120,
    singleIndicatorCap: 45, // one weak signal alone can never exceed this
    mediumThreshold: 30,
    highThreshold: 60,
    minTypoBrandLength: 6,  // edit-distance matching only for brand names this long
    trustedLimit: 100,      // maximum entries in the trusted websites list
  };

  const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "wallet",
    "suspend", "unlock", "billing", "payment",
  ];

  // brand -> official registrable domains
  const BRANDS = {
    paypal: ["paypal.com", "paypal.me", "paypal-community.com"],
    google: ["google.com", "google.co.in", "google.dev", "google.org", "blog.google"],
    microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    apple: ["apple.com", "icloud.com", "apple-dns.net"],
    amazon: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.jobs"],
    facebook: ["facebook.com", "facebook.net"],
    instagram: ["instagram.com", "instagram-press.com"],
    netflix: ["netflix.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net"],
    linkedin: ["linkedin.com", "linkedin-ei.com"],
    dropbox: ["dropbox.com"],
    twitter: ["twitter.com", "x.com"],
    github: ["github.com", "github.io"],
    ebay: ["ebay.com"],
    spotify: ["spotify.com", "spotify.link"],
    adobe: ["adobe.com"],
    paytm: ["paytm.com"],
    phonepe: ["phonepe.com"],
    flipkart: ["flipkart.com"],
    irctc: ["irctc.co.in"],
    sbi: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    hdfc: ["hdfcbank.com", "hdfc.com"],
    icici: ["icicibank.com", "icici.com"],
  };

  // Big brands that really do own country domains (amazon.de, google.co.jp, ...).
  const LOCALIZED_BRANDS = new Set([
    "google", "amazon", "microsoft", "apple", "facebook", "netflix", "ebay", "linkedin", "instagram",
  ]);
  // Country domains that are free or heavily abused, so they never count as "official".
  const ABUSED_CCTLDS = new Set(["tk", "ml", "ga", "cf", "gq", "cc", "ws", "pw"]);

  // Top-level domains that are cheap and often used for throwaway sites (weak signal on their own).
  const RISKY_TLDS = new Set([
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov", "work",
    "support", "rest", "cam", "icu", "buzz", "monster", "link", "loan", "vip", "country",
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "buff.ly", "tiny.cc", "t.ly", "rebrand.ly", "s.id",
  ]);

  // Hosting services where thousands of unrelated people publish pages. Trusting the whole
  // service would trust every page on it, so these cannot be added to the trusted list.
  const SHARED_HOSTS = new Set([
    "github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "vercel.app", "netlify.app",
    "pages.dev", "web.app", "firebaseapp.com", "azurewebsites.net", "appspot.com",
    "wixsite.com", "weebly.com", "sites.google.com",
  ]);

  // Real, unrelated names that happen to be one letter away from a brand.
  const ALLOWED_SIMILAR = new Set(["paypay"]);

  const EXECUTABLE_FILE = /\.(exe|scr|msi|apk|bat|cmd|vbs|ps1|jar|hta|lnk|dmg|iso)$/i;
  const LOCAL_SUFFIX = /^(?:(?:co|com|net|org)\.)?[a-z]{2}$/;

  const SECOND_LEVEL = new Set([
    "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "gob", "mil", "nic", "res", "sch",
  ]);

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

  /** True if this registrable domain really belongs to the brand. */
  function isOfficial(brand, registrable) {
    if (BRANDS[brand].includes(registrable)) return true;
    if (LOCALIZED_BRANDS.has(brand)) {
      const sld = registrable.split(".")[0];
      if (sld === brand) {
        const suffix = registrable.slice(sld.length + 1);
        const tld = suffix.split(".").pop();
        return LOCAL_SUFFIX.test(suffix) && !ABUSED_CCTLDS.has(tld);
      }
    }
    return false;
  }

  /** True if the domain belongs to any known brand (used to avoid false alarms on real sites). */
  function isBrandDomain(registrable) {
    return Object.keys(BRANDS).some((brand) => isOfficial(brand, registrable));
  }

  /** Damerau-Levenshtein style distance: counts insert, delete, replace and swapped letters. */
  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[a.length][b.length];
  }

  /** Undoes common look-alike tricks: paypa1 -> paypal, g00gle -> google, arnazon -> amazon. */
  function lookalikeForms(text) {
    const base = text.replace(/rn/g, "m").replace(/vv/g, "w");
    const digits = { 0: "o", 3: "e", 4: "a", 5: "s", 7: "t" };
    const fix = (s, one) => s.replace(/[03457]/g, (d) => digits[d]).replace(/1/g, one);
    return [fix(base, "l"), fix(base, "i")];
  }

  /**
   * Looks for a misspelled or disguised brand name in the domain.
   * Returns { brand, token } or null.
   */
  function findLookalike(tokens, sld, registrable) {
    const candidates = new Set(tokens.filter((t) => t.length >= 4 && !ALLOWED_SIMILAR.has(t)));
    if (!ALLOWED_SIMILAR.has(sld)) candidates.add(sld.replace(/[-_]/g, ""));

    for (const brand of Object.keys(BRANDS)) {
      if (isOfficial(brand, registrable)) continue;
      for (const token of candidates) {
        if (token === brand) {
          // Only reachable for the hyphen-stripped domain, e.g. "pay-pal"
          if (token !== sld) return { brand, token: sld };
          continue;
        }
        if (lookalikeForms(token).includes(brand)) return { brand, token };
        if (brand.length >= CONFIG.minTypoBrandLength && editDistance(token, brand) === 1) {
          return { brand, token };
        }
      }
    }
    return null;
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

  /* ---------- Trusted websites: matching and validation ---------- */

  /**
   * Returns the trusted entry that covers this hostname, or null.
   * A hostname matches an entry only if it IS the entry or ends with "." + entry:
   *   entry "example.com" covers example.com and mail.example.com
   *   but NOT evilexample.com, example.com.evil.net or example.org
   */
  function findTrustedMatch(hostname, list) {
    for (const entry of list) {
      if (hostname === entry || hostname.endsWith("." + entry)) return entry;
    }
    return null;
  }

  /**
   * Cleans up what the user typed (a domain or a full address) into a plain lowercase domain.
   * Returns { ok: true, domain } or { ok: false, error }.
   */
  function normalizeDomain(input) {
    let text = String(input == null ? "" : input).trim().toLowerCase();
    if (!text) return { ok: false, error: "Enter a domain such as example.com." };

    if (!/^[a-z][a-z0-9+.-]*:\/\//.test(text)) text = "https://" + text;

    let url;
    try {
      url = new URL(text);
    } catch (e) {
      return { ok: false, error: "That does not look like a valid domain." };
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { ok: false, error: "Only website domains can be added." };
    }
    if (url.username || url.password) {
      return { ok: false, error: "Enter only the domain, without a user name or password." };
    }

    const host = url.hostname.replace(/\.+$/, "");
    const labels = host.split(".");
    const tld = labels[labels.length - 1];

    if (isIpAddress(host)) {
      return { ok: false, error: "IP addresses cannot be trusted. Enter a domain name instead." };
    }
    if (labels.length < 2) {
      return { ok: false, error: "Enter a full domain such as example.com." };
    }
    const labelOk = (l) => l.length >= 1 && l.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l);
    if (host.length > 253 || !labels.every(labelOk) || tld.length < 2 || /^\d+$/.test(tld)) {
      return { ok: false, error: "That does not look like a valid domain." };
    }
    if (labels.length === 2 && SECOND_LEVEL.has(labels[0]) && tld.length === 2) {
      return { ok: false, error: `"${host}" is shared by many websites. Enter a specific site, such as name.${host}.` };
    }
    if (SHARED_HOSTS.has(host)) {
      return { ok: false, error: `"${host}" hosts pages from many different people. Enter the full address of one specific site instead.` };
    }
    return { ok: true, domain: host };
  }

  /* ---------- Main analysis ---------- */

  /**
   * @param {string} rawUrl
   * @param {{trustedDomains?: string[]}} [options]  trusted list to apply (see scanUrl)
   */
  function analyzeUrl(rawUrl, options) {
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

    const hostname = url.hostname.toLowerCase().replace(/\.+$/, "");
    const protocol = url.protocol.replace(":", "");
    const notes = [];

    /* ---- User's trusted websites list ---- */
    const trustedList =
      options && Array.isArray(options.trustedDomains)
        ? options.trustedDomains.filter((d) => typeof d === "string" && d)
        : [];
    const trustedMatch = findTrustedMatch(hostname, trustedList);

    if (trustedMatch && url.protocol === "https:") {
      return {
        supported: true,
        url: rawUrl,
        protocol,
        domain: hostname,
        score: 0,
        ...getRiskLevel(0),
        label: "Trusted Site",
        trusted: true,
        trustedBy: trustedMatch,
        indicators: [],
        rawScore: 0,
        scoreNote: `This website is covered by "${trustedMatch}" in your trusted list, so the suspicious-URL rules were skipped.`,
        scannedAt: Date.now(),
      };
    }
    if (trustedMatch) {
      // Trust only applies to HTTPS: a plain http:// page could be tampered with on the way.
      notes.push(`"${trustedMatch}" is in your trusted list, but trust only applies to HTTPS pages, so this page was analyzed normally.`);
    }

    /* ---- Rule-based analysis ---- */
    const usesIp = isIpAddress(hostname);
    const registrable = usesIp ? hostname : getRegistrableDomain(hostname);
    const sld = registrable.split(".")[0];
    const tokens = hostname.split(/[.\-_]/).filter(Boolean);

    // A genuine brand domain over HTTPS: URL wording (keywords, long query strings,
    // redirects) is normal there, so those path-based rules are skipped.
    const isBrandSite = !usesIp && url.protocol === "https:" && isBrandDomain(registrable);

    const indicators = [];
    const add = (id, title, detail, points) =>
      indicators.push({ id, title, detail, points });

    // 1. HTTP instead of HTTPS
    if (url.protocol === "http:") {
      add("http", "No HTTPS", "The connection is not encrypted (http://).", WEIGHTS.http);
    }

    // 2. IP address instead of a domain name
    if (usesIp) {
      add("ip", "IP address URL", "The site uses a raw IP address instead of a domain name.", WEIGHTS.ip);
    }

    // 3. Unusually long URL
    if (!isBrandSite) {
      if (rawUrl.length > CONFIG.veryLongUrl) {
        add("long", "Very long URL", `The URL has ${rawUrl.length} characters.`, WEIGHTS.veryLongUrl);
      } else if (rawUrl.length > CONFIG.longUrl) {
        add("long", "Long URL", `The URL has ${rawUrl.length} characters.`, WEIGHTS.longUrl);
      }
    }

    // 4. '@' symbol
    if (rawUrl.includes("@")) {
      if (url.username) {
        add("at", "'@' hides the real host",
          "Text before '@' is ignored by the browser, which can disguise the real destination.", WEIGHTS.atHidesHost);
      } else {
        add("at", "'@' in URL", "An '@' symbol appears in the path or query.", WEIGHTS.atInUrl);
      }
    }

    // 5. Excessive hyphens in the domain
    const hyphens = (hostname.match(/-/g) || []).length;
    if (hyphens >= 5) {
      add("hyphens", "Excessive hyphens", `The domain contains ${hyphens} hyphens.`, WEIGHTS.excessiveHyphens);
    } else if (hyphens >= 3) {
      add("hyphens", "Many hyphens", `The domain contains ${hyphens} hyphens.`, WEIGHTS.manyHyphens);
    }

    // 6. Misleading subdomains, brand impersonation, look-alike names
    let brandHit = false;
    if (!usesIp) {
      const subCount = hostname.split(".").length - registrable.split(".").length;
      if (subCount >= 4) {
        add("subdomains", "Too many subdomains", `${subCount} subdomain levels can hide the real domain.`, WEIGHTS.tooManySubdomains);
      } else if (subCount === 3) {
        add("subdomains", "Deep subdomain nesting", `${subCount} subdomain levels found.`, WEIGHTS.deepSubdomains);
      }

      // 6a. Exact brand name on a domain that is not the official one
      for (const brand of Object.keys(BRANDS)) {
        if (tokens.includes(brand) && !isOfficial(brand, registrable)) {
          add("brand", "Possible brand impersonation",
            `The domain mentions "${brand}" but the real domain is "${registrable}".`, WEIGHTS.brand);
          brandHit = true;
          break;
        }
      }

      // 6b. Brand glued to a security word inside the domain name (paypalsecure.com)
      if (!brandHit) {
        for (const brand of Object.keys(BRANDS)) {
          if (brand.length < 5 || sld === brand || !sld.includes(brand)) continue;
          if (isOfficial(brand, registrable)) continue;
          const rest = sld.replace(brand, "");
          if (SUSPICIOUS_KEYWORDS.some((k) => rest.includes(k))) {
            add("brand", "Possible brand impersonation",
              `The domain name combines "${brand}" with a security-style word ("${sld}").`, WEIGHTS.brand);
            brandHit = true;
            break;
          }
        }
      }

      // 6c. Misspelled or disguised brand name (paypa1, g00gle, arnazon, goggle)
      if (!brandHit) {
        const hit = findLookalike(tokens, sld, registrable);
        if (hit) {
          add("lookalike", "Look-alike of a known brand",
            `"${hit.token}" looks like a disguised version of "${hit.brand}".`, WEIGHTS.lookalike);
          brandHit = true;
        }
      }

      // 7. Cheap or throwaway top-level domain, and link shorteners
      const tld = hostname.split(".").pop();
      if (RISKY_TLDS.has(tld)) {
        add("tld", "Risky domain ending", `".${tld}" domains are cheap and often used for throwaway sites.`, WEIGHTS.riskyTld);
      }
      if (SHORTENERS.has(registrable)) {
        add("shortener", "Link shortener", "The real destination is hidden behind a shortened link.", WEIGHTS.shortener);
      }
    }

    // 8. Suspicious keywords (host + path + query)
    const searchable = safeDecode(hostname + url.pathname + url.search).toLowerCase();
    const found = SUSPICIOUS_KEYWORDS.filter((k) => searchable.includes(k));
    if (!isBrandSite && found.length > 0) {
      const pts = found.length >= 3 ? WEIGHTS.keywords3 : found.length === 2 ? WEIGHTS.keywords2 : WEIGHTS.keywords1;
      add("keywords", "Suspicious keywords", `Found: ${found.join(", ")}.`, pts);

      // 8a. Brand name in the path of a site that is not the brand
      if (!brandHit && !usesIp) {
        const pathTokens = safeDecode(url.pathname).toLowerCase().split(/[^a-z0-9]+/);
        const pathBrand = Object.keys(BRANDS).find(
          (b) => pathTokens.includes(b) && !isOfficial(b, registrable)
        );
        if (pathBrand) {
          add("brandpath", "Brand name in the page path",
            `The path mentions "${pathBrand}" together with login-style words, but the site is "${registrable}".`, WEIGHTS.brandPath);
        }
      }

      // 8b. Brand impersonation + login wording is the classic phishing pattern
      if (brandHit) {
        add("combo", "Brand + login wording",
          "A well-known brand name together with login or verify words is a classic phishing pattern.", WEIGHTS.combo);
      }
    }

    // 9. Suspicious URL encoding / punycode
    if (!isBrandSite) {
      const encodedCount = (rawUrl.match(/%[0-9a-f]{2}/gi) || []).length;
      const riskyEncoding = /%(40|2e|2f|5c|25)/i.test(rawUrl);
      if (riskyEncoding) {
        add("encoding", "Suspicious encoding",
          "Encoded characters such as @ . / \\ or double-encoding were found.", WEIGHTS.suspiciousEncoding);
      } else if (encodedCount >= 3) {
        add("encoding", "Heavy URL encoding", `${encodedCount} percent-encoded characters found.`, WEIGHTS.heavyEncoding);
      }
    }
    if (hostname.split(".").some((l) => l.startsWith("xn--"))) {
      add("punycode", "Punycode domain",
        "The domain uses punycode, which can imitate look-alike characters.", WEIGHTS.punycode);
    }

    // 10. Another web address hidden inside the URL, and executable downloads
    if (!isBrandSite) {
      if (/https?:\/\//i.test(safeDecode(url.search))) {
        add("redirect", "Link inside the URL",
          "The query contains another web address, which is sometimes used to redirect victims.", WEIGHTS.redirect);
      }
      if (EXECUTABLE_FILE.test(safeDecode(url.pathname))) {
        add("download", "Executable file download", "The URL points directly to a program or installer file.", WEIGHTS.download);
      }
    }

    /* ---------- Scoring ---------- */
    indicators.sort((a, b) => b.points - a.points);
    const rawScore = indicators.reduce((sum, i) => sum + i.points, 0);
    let score = Math.min(rawScore, 100);
    if (rawScore > 100) {
      notes.push("The total is capped at 100.");
    }
    if (indicators.length === 1 && score > CONFIG.singleIndicatorCap) {
      score = CONFIG.singleIndicatorCap;
      notes.push(`Only one indicator was found, so the score is limited to ${CONFIG.singleIndicatorCap}: a single weak signal never makes a site High Risk.`);
    }

    return {
      supported: true,
      url: rawUrl,
      protocol,
      domain: hostname,
      score,
      ...getRiskLevel(score),
      trusted: false,
      indicators,
      rawScore,
      scoreNote: notes.join(" "),
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

  /* ---------- Trusted websites list (chrome.storage.local) ---------- */

  const TRUSTED_KEY = "trustedDomains";

  async function getTrustedDomains() {
    const data = await chrome.storage.local.get(TRUSTED_KEY);
    const list = data[TRUSTED_KEY];
    return Array.isArray(list) ? list.filter((d) => typeof d === "string" && d) : [];
  }

  /**
   * Adds a domain to the trusted list.
   * Returns { ok: true, domain } or { ok: false, error }.
   * Rejects invalid input, duplicates, and domains already covered by an existing entry.
   */
  async function addTrustedDomain(input) {
    const parsed = normalizeDomain(input);
    if (!parsed.ok) return parsed;

    const list = await getTrustedDomains();
    const covering = findTrustedMatch(parsed.domain, list);
    if (covering) {
      return {
        ok: false,
        error: covering === parsed.domain
          ? `${parsed.domain} is already in your trusted list.`
          : `${parsed.domain} is already covered by ${covering}.`,
      };
    }
    if (list.length >= CONFIG.trustedLimit) {
      return { ok: false, error: `The list is full (${CONFIG.trustedLimit} sites). Remove one first.` };
    }

    list.push(parsed.domain);
    list.sort();
    await chrome.storage.local.set({ [TRUSTED_KEY]: list });
    return { ok: true, domain: parsed.domain };
  }

  async function removeTrustedDomain(domain) {
    const list = await getTrustedDomains();
    await chrome.storage.local.set({ [TRUSTED_KEY]: list.filter((d) => d !== domain) });
  }

  /** Analyzes a URL using the saved trusted list. Used by the popup and the background worker. */
  async function scanUrl(rawUrl) {
    let trustedDomains = [];
    try {
      trustedDomains = await getTrustedDomains();
    } catch (e) {
      console.error("PhishGuard could not read the trusted list:", e);
    }
    return analyzeUrl(rawUrl, { trustedDomains });
  }

  global.PhishGuard = {
    analyzeUrl,
    scanUrl,
    getRiskLevel,
    getHistory,
    saveScan,
    clearHistory,
    getTrustedDomains,
    addTrustedDomain,
    removeTrustedDomain,
    normalizeDomain,
    WEIGHTS,
    HISTORY_KEY,
    TRUSTED_KEY,
  };
})(typeof self !== "undefined" ? self : window);