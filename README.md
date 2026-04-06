# 🔐 Security Writeup Collector

An Obsidian plugin that collects cybersecurity writeups offline into your vault as clean, richly-formatted Markdown notes. It combines RSS feeds, topic-based discovery, Medium fallback handling, duplicate prevention, Egyptian-Arabic summaries, reusable test cases, and local alerts for important findings.

## ✨ Features

### 📡 Multi-Source RSS Fetching
- **8 built-in sources** out of the box:
  - 🎯 **Pentester Land** — Curated bug bounty writeups
  - 📝 **InfoSec Writeups** — Community-driven security articles
  - 🐛 **Bug Bounty Hunting** — Hunting tips and disclosure reports
  - 🔬 **PortSwigger Research** — Web security research
  - 📡 **The Hacker News** — Cybersecurity news and analysis
  - 🧪 **Project Zero** — Google's zero-day research
  - 🛡️ **Assetnote Research** — Attack surface management research
  - 🔒 **Krebs on Security** — Investigative cybersecurity journalism
- **Custom RSS sources** — Add any RSS/Atom feed with a name, URL, and emoji icon
- **Per-source toggle** — Enable or disable individual sources without removing them
- **🏥 Source Health Check** — Live health dots (🟢 online / 🔴 offline / ⏳ checking) next to each source

### 📄 Full Article Scraping
- Fetches the **complete article content** from the original page (not just the RSS snippet)
- Intelligent **article extraction** using configurable CSS selectors per source
- **Medium paywall fallback** — tries the original Medium URL first, detects premium / blocked / incomplete pages, then falls back to Freedium only when needed
- **Fetch provenance tracking** — stores both the original article URL and the actual fetched URL in frontmatter
- Falls back to RSS body when full-content fetch fails
- Toggle full-content mode on/off for faster RSS-only imports

### 🎯 Topic-Based Sources
- **Topic search sources** — add dynamic search endpoints such as `https://medium.com/search?q=` or GitHub search
- **Multi-topic sync** — register one source with multiple topics like `idor, xss, ssrf, sqli`
- **Auto-folder routing** — map topics to folders like `Writeups/Web/IDOR`, with `Writeups/Unsorted/<topic>` as fallback
- **Per-source sync controls** — configure enabled state, auto-sync, and sync frequency
- **Built-in topic packs** — ships with ready-to-use coverage for Web, Mobile, Network, Active Directory, Bug Bounty platforms, Recon, CVE tracking, and zero-day monitoring
- **New CVEs input** — add rolling CVE search terms such as `cve-2026` or exact IDs like `cve-2026-12345` directly from settings

### 🔍 Scan & Preview Workflow
- **Scan** all enabled sources for new writeups before saving
- **Preview modal** with title, source badge, date, severity indicator, and tags
- **🔎 Real-time search** — Filter scanned items by title or source
- **📋 Sort options** — Sort by newest, oldest, severity, source, or title
- **Select / deselect** individual writeups or use batch controls
- **Robust deduplication** — normalizes URLs, strips tracking parameters, checks cached URLs, and checks existing notes in the vault before showing or saving anything
- **Save-time duplicate guard** — even if a duplicate reaches the modal, it is skipped again before file creation

### ⭐ Keyword Watchlist
- Configure a set of **watchlist keywords** (e.g. `rce`, `zero-day`, `authentication bypass`)
- Writeups matching watchlist keywords get a **⭐ star badge** in the preview
- Auto-selected by default so you never miss important topics
- Manage keywords in the Sources Manager or Settings Tab

### 🚨 Important Alerts
- **Critical and CVE alerts** — generate local alerts when a scan finds critical writeups or newly matched CVE content
- **Works on desktop and mobile** — in-app Obsidian notices show on both; desktop system notifications are used when permission is available
- **Best-effort cross-device sync** — alerts can be relayed across devices when plugin data is synced
- **Cooldown controls** — avoid alert spam by throttling repeated notifications for the same writeup
- **Test alert button** — verify the notification path from settings

### 🏷️ Automatic Tagging & Severity Detection
- **Smart tag extraction** from titles and RSS categories — recognizes a broad set of web, mobile, network, AD, bug bounty, and CVE topics
- **Automatic severity classification**: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Info
- **CVE extraction** — Automatically detects CVE IDs in titles and content
- **Platform detection** — Recognizes HackerOne, Bugcrowd, Intigriti, HackTheBox, etc.
- **Severity-colored tag pills** in the preview UI

### 🧹 Content Processing Pipeline
- **Fetch → Clean → Summarize → Generate Test Case → Save Markdown**
- **Aggressive cleanup** — removes ads, newsletter blocks, related-post cards, repeated headers, share buttons, boilerplate, and noisy page chrome
- **Egyptian Arabic summary** — inserts a concise revision-friendly summary directly after the frontmatter
- **Test case generator** — appends a reusable block with objective, steps, payload, vulnerable behavior, secure behavior, and inferred metadata
- **AI-style enrichment heuristics** — fills severity, CWE, OWASP category, attack flow, and extracted CVEs when possible

### 📝 Rich Markdown Output
Each saved writeup includes:
- **Enhanced YAML frontmatter** — `reading_time`, `word_count`, `severity`, `platform`, `cve_ids`, `excerpt`, `original_url`, `fetched_from`, `fallback_used`, `fetch_status`
- **Egyptian Arabic summary block** — concise revision-friendly notes directly after the frontmatter
- **Reusable test case block** — copy-friendly vulnerability checklist with payload, secure behavior, CWE, OWASP, and attack flow
- **Info card callout** — Visual metadata table at the top with all details
- **Table of Contents** — Auto-generated from article headings (3+ headings)
- **Related writeups** — Dataview-compatible query block for cross-references
- **Navigation footer** — Link back to the writeups index

### 📊 Statistics Dashboard
- **Overview cards** — Total fetched, total failed, active sources, cached URLs
- **Bar charts** — Writeups per source, top tags, and monthly trends
- **Reset stats** — Clear analytics data when needed
- Accessible from Sources Manager, Settings Tab, or command palette

### 🗂️ Advanced Filtering
- **Filter by tag** — Dropdown of the built-in recognized security tags
- **Filter by date range** — Set "From" and "To" dates
- Filters applied during scan for efficient results

### 📤 Export / Import Sources
- **Export** — Copy all source configs to clipboard as JSON for backup/sharing
- **Import** — Paste JSON to restore sources from a backup, with deduplication

### 📑 Auto-Generated Index
- `index.md` created/updated after every fetch
- Groups writeups by source with backlinks (`[[...]]`)
- Full tag reference section

### 🔄 Retry Failed Items
- Failed fetches tracked and surfaced in the UI
- One-click retry from the done screen

### ⚙️ Settings
- **Output folder**, **limit per source**, **auto-fetch on startup**
- **Cache management** — Clear seen URLs to re-fetch older writeups
- **Alert controls** — enable/disable alerts for critical findings and CVEs, request desktop notification permission, and test alerts
- **CVE keyword management** — maintain a dedicated list of rolling CVE queries used by the built-in CVE topic source
- Settings accessible from Sources Manager, Settings Tab, or ribbon icons

### 🎨 UI/UX
- **Gradient modal headers** — Purple gradient accent for a premium feel
- **Card-style source rows** — Shadow and hover lift effects
- **Animated progress bar** — Pulsing glow during fetch
- **Fade-in animations** — Smooth content transitions
- **Custom thin scrollbars** — Clean scrolling in lists
- **Two ribbon icons** + **Multiple command palette commands** + **Status bar widget**

## 🚀 Installation

### Manual
1. Download the latest release files (`main.js`, `manifest.json`, `styles.css`).
2. Create a folder named `security-writeup-collector` inside your vault's `.obsidian/plugins/` directory.
3. Copy the downloaded files into this folder.
4. Open Obsidian → Settings → Community Plugins → Enable **Security Writeup Collector**.

## 📁 Project Structure

| File | Purpose |
|---|---|
| `main.js` | Core plugin logic — RSS parsing, HTML→Markdown, fetch engine, modals, stats, settings |
| `styles.css` | UI styles — gradient headers, cards, animated progress, tag colors, stats dashboard |
| `manifest.json` | Plugin metadata (ID, version, description) |
| `data.json` | Persisted settings, seen URLs, source configs, statistics |

## 🛠️ Usage

1. Click the **🛡️ ribbon icon** to open the **Sources Manager** — configure sources, watchlist, and settings.
2. Click the **⬇ ribbon icon** to open the **Collector modal** — scan, search, sort, preview, and save.
3. Use the **📊 Stats** button to view your analytics dashboard.
4. Use **Topic Search Sources** and **New CVEs** from the Sources Manager to expand discovery beyond RSS feeds.
5. Find your writeups in the configured output folder, organized by source or topic category.

## 🧠 How It Works

### Medium Fallback Flow
1. The plugin fetches the original Medium URL first.
2. It validates the response for title, body quality, structure, blocked HTML, and common paywall markers.
3. If the original article is premium, incomplete, or blocked, it retries through `https://freedium-mirror.cfd/<original-url>`.
4. The saved note keeps both `original_url` and `fetched_from` so you can see exactly what happened.

### Duplicate Prevention
1. URLs are normalized before comparison.
2. Tracking parameters and fragments are removed.
3. Existing vault notes are checked through frontmatter fields such as `url`, `original_url`, and `fetched_from`.
4. A second duplicate check runs again during save to prevent accidental re-imports.

### Built-In Commands
- `Open Sources Manager`
- `Collect Writeups (with preview)`
- `Scan Topic Sources`
- `View Statistics`

## 📝 Saved Note Example

```yaml
---
title: SSRF AWS Metadata Writeup
source: Medium
original_url: https://medium.com/@author/ssrf-aws-metadata
fetched_from: https://freedium-mirror.cfd/https://medium.com/@author/ssrf-aws-metadata
fallback_used: true
fetch_status: fetched
severity: high
cwe: CWE-918
owasp: Security Misconfiguration
topic: ssrf
---
```

The body is saved as note-friendly Markdown with:
- a summary callout in Egyptian Arabic
- a cleaned writeup body
- a reusable `Test Case` section
- Dataview-friendly metadata for later filtering

## 📜 License

MIT
