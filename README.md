# PhishGuard Lite

A rule-based phishing detection extension for Google Chrome. It analyzes the URL of the websites you visit, calculates a risk score from 0 to 100, explains every point of that score, and warns you about suspicious pages.

PhishGuard Lite uses **no AI, no machine learning, no backend server and no database**. Every check runs locally in JavaScript, and the extension never sends data anywhere.

Built with HTML5, CSS3, vanilla JavaScript and Chrome Extension Manifest V3.

---

## Features

- **Automatic URL detection:** reads the address of the active tab and extracts the domain and protocol.
- **Rule-based phishing detection** for:
  - IP address URLs (including disguised forms such as `http://3232235777/`)
  - Unusually long URLs
  - Suspicious characters (`@`, excessive hyphens)
  - Misleading subdomains
  - Brand impersonation (`paypal.example.com`, `paypalsecure.com`)
  - Look-alike domains (`paypa1.com`, `g00gle.com`, `arnazon.in`, `pay-pal.com`, `paypall.com`)
  - Suspicious keywords (login, verify, account, update, ...)
  - Suspicious URL encoding and punycode
  - HTTP instead of HTTPS
  - Cheap, throwaway top-level domains (`.top`, `.xyz`, `.tk`, ...)
  - Link shorteners (`bit.ly`, `tinyurl.com`, ...)
  - Another web address hidden inside the URL, and direct downloads of program files
- **Weighted risk scoring** from 0 to 100. Every indicator has its own weight, and all weights are listed in one table at the top of `detector.js`.
- **Detailed explanations:** every detected indicator is listed with the reason it was flagged and the points it added. A breakdown line shows how the total was calculated, for example `Score: 30 + 20 + 10 + 8 = 68`, and a note explains when a cap changed the score.
- **Trusted websites list:** add and remove domains you trust. The list is stored in Chrome Storage and survives restarting Chrome.
- **Fewer false alarms:** genuine brand domains over HTTPS (including country domains such as `amazon.de`) are recognized, so normal pages like `paypal.com/signin` are not penalized.
- **Dashboard popup** with a dark cybersecurity theme, a color-coded gauge, status text and the list of detected indicators.
- **Warning notifications** for high-risk websites (the page is never blocked).
- **Toolbar badge** on risky pages (red `!` for high risk, yellow `!` for medium risk).
- **Scan history** of the last 10 scanned websites, with a clear button.

---

## Risk levels

| Score  | Level       | Color  |
|--------|-------------|--------|
| 0-29   | Low Risk    | Green  |
| 30-59  | Medium Risk | Yellow |
| 60-100 | High Risk   | Red    |

To avoid false alarms, a website that triggers **only one** indicator can never score above 45, so a single weak signal can never make a site High Risk.

### Scoring weights

| Indicator                                  | Points      |
|--------------------------------------------|-------------|
| No HTTPS (`http://`)                       | 10          |
| IP address instead of a domain             | 30          |
| Long URL (over 75 characters)              | 8           |
| Very long URL (over 120 characters)        | 15          |
| `@` that hides the real host               | 25          |
| `@` in the path or query                   | 8           |
| Many hyphens in the domain (3-4)           | 8           |
| Excessive hyphens (5 or more)              | 14          |
| Deep subdomain nesting (3 levels)          | 8           |
| Too many subdomains (4 or more)            | 15          |
| Brand name on an unofficial domain         | 30          |
| Look-alike of a known brand                | 35          |
| Risky top-level domain                     | 8           |
| Link shortener                             | 10          |
| Suspicious keywords (1 / 2 / 3+)           | 8 / 14 / 20 |
| Brand name in the path with login words    | 12          |
| Brand impersonation + login words (combo)  | 15          |
| Heavy URL encoding                         | 8           |
| Suspicious encoding (`%40`, `%2e`, `%2f`, `%5c`, `%25`) | 15 |
| Punycode domain (`xn--`)                   | 12          |
| Another web address inside the URL         | 10          |
| Direct download of a program file          | 12          |

The indicators are added together and the total is capped at 100. In the popup, each indicator's points are colored by weight: red for 25 or more, amber for 12-24, grey for under 12. All weights are in the `WEIGHTS` table, and thresholds, brand lists and keyword lists are at the top of `detector.js`, so they are easy to change.

### How look-alike detection works

For each part of the domain, the detector checks whether it becomes a known brand name after undoing common tricks: digits for letters (`paypa1`, `g00gle`), `rn` for `m` (`arnazon`), and inserted hyphens (`pay-pal`). It also flags names that are exactly one letter away from a long brand name (`paypall`, `goggle`, `mircosoft`), using an edit-distance check.

### Genuine brand domains

If a site is on a known brand's official domain and uses HTTPS, the keyword, long-URL, encoding and redirect rules are skipped, because that wording is normal on real sites (for example `paypal.com/signin`).

---

## Trusted websites

Open the popup and expand **Trusted websites**.

- Type a domain such as `example.com` (a full address such as `https://Example.com/page` also works and is cleaned up automatically), then click **Add** or press Enter.
- **Use current site** fills the box with the domain of the tab you are on.
- Click **Remove** next to an entry to delete it.
- The list is stored with `chrome.storage.local`, so it persists after Chrome is restarted.

### How matching works

An entry covers the domain itself and all of its subdomains, and nothing else:

| Trusted entry | Trusted? |
|---|---|
| `example.com` matches `example.com` | Yes |
| `example.com` matches `www.example.com`, `mail.example.com` | Yes |
| `example.com` matches `evilexample.com` | No |
| `example.com` matches `example.com.evil.net` | No |
| `example.com` matches `example.org` | No |
| `example.com` matches `https://example.com@evil.net/` | No (the real host is `evil.net`) |

### Rules

- Trust applies only to **HTTPS** pages. An `http://` page on a trusted domain is still analyzed normally, and the popup explains why.
- Entries are saved in lowercase without `www` handling tricks, so `Example.COM` and `example.com` are the same entry.
- **Duplicates are rejected.** So is a domain already covered by an existing entry (adding `www.example.com` when `example.com` is trusted).
- **Not allowed:** IP addresses, single words such as `com` or `localhost`, public suffixes such as `co.in`, and shared hosting services such as `github.io` or `blogspot.com`, because trusting them would trust thousands of unrelated pages. Add the specific site (for example `yourname.github.io`) instead.
- The list holds up to 100 entries.
- A trusted site shows as **Trusted Site** with a score of 0, and it never triggers a badge or a warning notification.

---

## Project structure

```
PhishGuard/
  manifest.json     Extension configuration (Manifest V3)
  detector.js       Detection engine, weights, scoring, trusted list and scan-history storage
  popup.html        Dashboard layout
  popup.css         Dashboard styling (dark theme)
  popup.js          Dashboard logic: scan, explanations, trusted websites manager
  background.js     Service worker: automatic scan, toolbar badge, warning notifications
  history.html      Scan history page
  history.js        Scan history logic
  icons/            Extension icons (16, 48, 128 px)
  README.md         This file
```

### How it works

1. `detector.js` contains `analyzeUrl(url, options)`, a pure function that takes a URL string (and optionally the trusted list) and returns a result object: score, level, indicators with points, and a score note. It uses no Chrome APIs, so the popup and the background worker share the same logic. `scanUrl(url)` loads the saved trusted list and then calls `analyzeUrl`.
2. When you click the icon, `popup.js` reads the active tab's URL with the Chrome Tabs API, calls `scanUrl`, saves the scan and shows the dashboard.
3. While you browse, `background.js` scans each page when it finishes loading. It updates the badge, saves Medium and High risk pages to history, and shows a notification for High Risk pages (at most once per URL every 10 minutes).
4. Scan history and the trusted list are stored in `chrome.storage.local`.

---

## Installation

1. Download or copy the `PhishGuard` folder to your computer.
2. Open Google Chrome (version 102 or newer) and go to `chrome://extensions`.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the `PhishGuard` folder.
5. Click the puzzle-piece icon in the toolbar and pin **PhishGuard Lite**.

After editing any file, click the reload arrow on the extension card in `chrome://extensions`.

---

## Usage

- Click the PhishGuard icon on any website to see its risk score, the reasons behind it, and the score breakdown.
- Click **Scan again** to refresh the result.
- Use **Trusted websites** to mark sites you know are safe.
- Click **History** to see your last 10 scans. Use **Clear history** to delete them.
- A red or yellow `!` on the toolbar icon means the current page looks risky.

---

## Testing

Real phishing sites are dangerous, so test with local addresses and the console instead.

### Manual tests

| Test | How | Expected result |
|------|-----|-----------------|
| Safe site | Open `https://example.com`, click the icon | Green, score 0, no indicators |
| Unsupported page | Click the icon on `chrome://extensions` | Grey "Not scanned" message, no crash |
| High risk | Open `http://127.0.0.1:5500/secure-login/verify-account/update?user=a@b.com` (Live Server running), click the icon | Red, score 68, breakdown `Score: 30 + 20 + 10 + 8 = 68`, warning notification, red `!` badge |
| Trust a site | Open `https://www.amazon.science`, click the icon, expand **Trusted websites**, click **Use current site** then **Add** | Medium Risk (30) changes to green "Trusted Site", score 0 |
| Persistence | Close Chrome completely, reopen, open the popup | The trusted list still contains the entry |
| Duplicate | Add the same domain again, or add `www.` + the domain | Rejected with a clear message |
| Remove | Click **Remove** | Entry disappears and the site is analyzed normally again |
| History | Scan a few sites, click **History** | Entries listed newest first, no duplicates, maximum 10 |
| Clear | Click **Clear history** | List empties |

### Console tests for the detection engine

Right-click the popup, choose **Inspect**, open the Console, and run:

```javascript
const t = (u, trusted = []) => { const r = PhishGuard.analyzeUrl(u, { trustedDomains: trusted }); console.log(r.supported ? r.score : "unsupported", r.label, r.indicators.map(i => i.id)); };
t("https://www.paypal.com/signin");                  // 0 Low Risk (real site, not penalized)
t("https://paypal.example.com");                     // 30 Medium Risk (brand impersonation)
t("https://paypa1.com/login");                       // 58 Medium Risk (look-alike + login wording)
t("https://secure-paypal-update.top/signin");        // 73 High Risk
t("http://paypal.com.secure-login.verify-account.example-xyz.top/account/update?id=1"); // 100 High Risk (raw total 114, capped)
t("https://example.com/setup.exe");                  // 12 Low Risk (one weak signal)

// Trusted list matching
t("https://blog.amazon.science/", ["amazon.science"]);        // 0 Trusted Site
t("https://amazon.science.evil.top/", ["amazon.science"]);    // 38 Medium Risk (not trusted)
t("https://evilamazon.science/", ["amazon.science"]);         // 0 Low Risk (analyzed, not trusted)
t("http://amazon.science/", ["amazon.science"]);              // 40 Medium Risk (HTTP is never trusted)
```

---

## Permissions and privacy

| Permission      | Why it is needed |
|-----------------|------------------|
| `activeTab`     | Read the address of the tab you are on when you open the popup |
| `tabs`          | Let the background worker see a page's address when it finishes loading |
| `storage`       | Save the scan history, the trusted websites list and the notification cooldown on your computer |
| `notifications` | Show the warning for high-risk websites |

- Only the **URL text** is analyzed. PhishGuard Lite does not read page content, passwords, cookies or form data.
- Nothing is sent over the network. There is no server and no analytics.
- Scan history stores full URLs, which can sometimes contain tokens in the query string. History and the trusted list are kept only in this browser. History can be deleted with **Clear history**.
- The background scan stores only Medium and High risk pages. Low-risk pages are saved only when you scan them yourself from the popup, so History never becomes a full browsing log.

---

## Limitations

- **This is a heuristic tool, not a guarantee.** A high score means the URL has suspicious features, not that the site is definitely phishing. A low score does not prove a site is safe, because phishing sites can use clean-looking URLs.
- Pages are **never blocked**. The user always decides.
- Only the URL is analyzed. There is no page-content analysis and no live threat database.
- **Trusted sites skip every check.** If you trust a domain by mistake, or a trusted site is later compromised, PhishGuard Lite will not warn you about it. Only add sites you know well.
- Brand detection covers a built-in list of about 20 brands. A brand that is not on the list is not protected, and lesser-known domains owned by a listed brand may be flagged until they are added to the list or to your trusted list.
- Registrable-domain detection is approximate, not a full public-suffix list.
- Genuine brand domains skip path-based rules, so abuse of user-content pages on a real domain (for example a phishing page hosted on a trusted service) will not be caught.
- Local development servers such as `127.0.0.1` score Medium because they use an IP address and HTTP.
- Notifications depend on your operating system settings (for example, Windows Focus assist can hide them).

## Possible improvements

- Add more brands and a full public-suffix list.
- Add a settings page to adjust weights and thresholds.
- Export and import the trusted list and scan history as a file.