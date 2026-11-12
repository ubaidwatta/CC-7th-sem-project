# PhishGuard Lite

A rule-based phishing detection extension for Google Chrome. It analyzes the URL of the websites you visit, calculates a risk score from 0 to 100, and warns you about suspicious pages.

PhishGuard Lite uses **no AI, no machine learning, no backend server and no database**. Every check runs locally in JavaScript, and the extension never sends data anywhere.

Built with HTML5, CSS3, vanilla JavaScript and Chrome Extension Manifest V3.

---

## Features

- **Automatic URL detection:** reads the address of the active tab and extracts the domain and protocol.
- **Rule-based phishing detection** for:
  - IP address URLs
  - Unusually long URLs
  - Suspicious characters (`@`, excessive hyphens)
  - Misleading subdomains and brand impersonation
  - Suspicious keywords (login, verify, account, update, ...)
  - Suspicious URL encoding and punycode (look-alike characters)
  - HTTP instead of HTTPS
- **Risk scoring** from 0 to 100 with a clear explanation of every point added.
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

### Scoring rules

| Indicator                          | Points   |
|------------------------------------|----------|
| No HTTPS (`http://`)               | 10       |
| IP address instead of a domain     | 30       |
| Long URL (over 75 characters)      | 8        |
| Very long URL (over 120 characters)| 15       |
| `@` that hides the real host       | 25       |
| `@` in the path or query           | 8        |
| Many hyphens in the domain (3-4)   | 8        |
| Excessive hyphens (5 or more)      | 14       |
| Deep subdomain nesting (3 levels)  | 8        |
| Too many subdomains (4 or more)    | 15       |
| Brand name on an unofficial domain | 30       |
| Suspicious keywords (1 / 2 / 3+)   | 8 / 14 / 20 |
| Heavy URL encoding                 | 8        |
| Suspicious encoding (`%40`, `%2e`, `%2f`, `%5c`, `%25`) | 15 |
| Punycode domain (`xn--`)           | 12       |

The total is capped at 100. All thresholds and keyword lists are at the top of `detector.js` and are easy to change.

---

## Project structure

```
PhishGuard/
  manifest.json     Extension configuration (Manifest V3)
  detector.js       Detection engine, scoring, and scan-history storage
  popup.html        Dashboard layout
  popup.css         Dashboard styling (dark theme)
  popup.js          Dashboard logic: reads the active tab, runs the scan, renders results
  background.js     Service worker: automatic scan, toolbar badge, warning notifications
  history.html      Scan history page
  history.js        Scan history logic
  icons/            Extension icons (16, 48, 128 px)
  README.md         This file
```

### How it works

1. `detector.js` contains `analyzeUrl(url)`, a pure function that takes a URL string and returns a result object (score, level, indicators). It uses no Chrome APIs, so the popup and the background worker share the same logic.
2. When you click the icon, `popup.js` reads the active tab's URL with the Chrome Tabs API, runs `analyzeUrl`, saves the scan and shows the dashboard.
3. While you browse, `background.js` scans each page when it finishes loading. It updates the badge, saves Medium and High risk pages to history, and shows a notification for High Risk pages (at most once per URL every 10 minutes).
4. Scan history is stored in `chrome.storage.local`.

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

- Click the PhishGuard icon on any website to see its risk score and the reasons behind it.
- Click **Scan again** to refresh the result.
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
| High risk | Open `http://127.0.0.1:5500/secure-login/verify-account/update?user=a@b.com` (Live Server running), click the icon | Red, score 68, warning notification, red `!` badge |
| History | Scan a few sites, click **History** | Entries listed newest first, no duplicates, maximum 10 |
| Clear | Click **Clear history** | List empties |

### Console tests for the detection engine

Right-click the popup, choose **Inspect**, open the Console, and run:

```javascript
const t = (u) => { const r = PhishGuard.analyzeUrl(u); console.log(r.supported ? r.score : "unsupported", r.label, r.indicators.map(i => i.id)); };
t("https://www.google.com");                        // 0 Low Risk
t("http://example.com/login/verify/account");       // 30 Medium Risk
t("http://192.168.1.1/");                           // 40 Medium Risk
t("https://paypal.example.com");                    // 30 Medium Risk
t("http://paypal.com.secure-login.verify-account.example-xyz.top/account/update?id=1"); // 83 High Risk
```

---

## Permissions and privacy

| Permission      | Why it is needed |
|-----------------|------------------|
| `activeTab`     | Read the address of the tab you are on when you open the popup |
| `tabs`          | Let the background worker see a page's address when it finishes loading |
| `storage`       | Save the scan history and the notification cooldown on your computer |
| `notifications` | Show the warning for high-risk websites |

- Only the **URL text** is analyzed. PhishGuard Lite does not read page content, passwords, cookies or form data.
- Nothing is sent over the network. There is no server and no analytics.
- Scan history stores full URLs, which can sometimes contain tokens in the query string. History is kept only in this browser and can be deleted with **Clear history**.
- The background scan stores only Medium and High risk pages. Low-risk pages are saved only when you scan them yourself from the popup, so History never becomes a full browsing log.

---

## Limitations

- **This is a heuristic tool, not a guarantee.** A high score means the URL has suspicious features, not that the site is definitely phishing. A low score does not prove a site is safe, because phishing sites can use clean-looking URLs.
- Pages are **never blocked**. The user always decides.
- Only the URL is analyzed. There is no page-content analysis and no live threat database.
- The brand list is small and the registrable-domain detection is approximate (it handles common cases such as `co.in` and `com.au`, but is not a full public-suffix list).
- Local development servers such as `127.0.0.1` score Medium because they use an IP address and HTTP.
- Notifications depend on your operating system settings (for example, Windows Focus assist can hide them).

## Possible improvements

- Add more brands and a full public-suffix list.
- Let users add trusted websites that are never flagged.
- Add a settings page to adjust thresholds.
- Export scan history as a file.