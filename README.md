# 🔐 Security Writeup Collector

An Obsidian plugin that automatically fetches, previews, and saves full-content security writeups from popular bug bounty and infosec platforms — directly into your vault as clean, richly-formatted Markdown notes.

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
- **Medium paywall fallback** — tries the original Medium URL first, then automatically falls back to Freedium only when the article is locked or incomplete
- Falls back to RSS body when full-content fetch fails
- Toggle full-content mode on/off for faster RSS-only imports

### 🎯 Topic-Based Sources
- **Topic search sources** — add dynamic search endpoints such as `https://medium.com/search?q=` or GitHub search
- **Multi-topic sync** — register one source with multiple topics like `idor, xss, ssrf, sqli`
- **Auto-folder routing** — map topics to folders like `Writeups/Web/IDOR`, with `Writeups/Unsorted/<topic>` as fallback
- **Per-source sync controls** — configure enabled state, auto-sync, and sync frequency

### 🔍 Scan & Preview Workflow
- **Scan** all enabled sources for new writeups before saving
- **Preview modal** with title, source badge, date, severity indicator, and tags
- **🔎 Real-time search** — Filter scanned items by title or source
- **📋 Sort options** — Sort by newest, oldest, severity, source, or title
- **Select / deselect** individual writeups or use batch controls
- URL deduplication — only shows truly new writeups

### ⭐ Keyword Watchlist
- Configure a set of **watchlist keywords** (e.g. `rce`, `zero-day`, `authentication bypass`)
- Writeups matching watchlist keywords get a **⭐ star badge** in the preview
- Auto-selected by default so you never miss important topics
- Manage keywords in the Sources Manager or Settings Tab

### 🏷️ Automatic Tagging & Severity Detection
- **Smart tag extraction** from titles and RSS categories — recognizes 24+ security topics
- **Automatic severity classification**: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Info
- **CVE extraction** — Automatically detects CVE IDs in titles and content
- **Platform detection** — Recognizes HackerOne, Bugcrowd, Intigriti, HackTheBox, etc.
- **Severity-colored tag pills** in the preview UI

### 📝 Rich Markdown Output
Each saved writeup includes:
- **Enhanced YAML frontmatter** — `reading_time`, `word_count`, `severity`, `platform`, `cve_ids`, `excerpt`
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
- **Filter by tag** — Dropdown of all 24 recognized security tags
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
- Settings accessible from Sources Manager, Settings Tab, or ribbon icons

### 🎨 UI/UX
- **Gradient modal headers** — Purple gradient accent for a premium feel
- **Card-style source rows** — Shadow and hover lift effects
- **Animated progress bar** — Pulsing glow during fetch
- **Fade-in animations** — Smooth content transitions
- **Custom thin scrollbars** — Clean scrolling in lists
- **Two ribbon icons** + **Three command palette commands** + **Status bar widget**

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
2. Click the **⬇ ribbon icon** to open the **Fetch modal** — scan, search, sort, preview, and save.
3. Use the **📊 Stats** button to view your analytics dashboard.
4. Find your writeups in the configured output folder, organized by source.

## 📜 License

MIT
