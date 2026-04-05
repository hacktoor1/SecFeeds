# 🔐 Security Writeups Fetcher

An Obsidian plugin that automatically fetches, previews, and saves full-content security writeups from popular bug bounty and infosec platforms — directly into your vault as clean Markdown notes.

## ✨ Features

### 📡 Multi-Source RSS Fetching
- **Built-in sources** — Ships with three curated feeds out of the box:
  - 🎯 **Pentester Land** — Curated bug bounty writeups
  - 📝 **InfoSec Writeups** — Community-driven security articles
  - 🐛 **Bug Bounty Hunting** — Hunting tips and disclosure reports
- **Custom RSS sources** — Add any RSS/Atom feed (e.g. PortSwigger Research, personal blogs) with a name, URL, and emoji icon.
- **Per-source toggle** — Enable or disable individual sources without removing them.

### 📄 Full Article Scraping
- Fetches the **complete article content** from the original page (not just the RSS snippet).
- Intelligent **article extraction** using configurable CSS selectors per source — strips nav, footer, ads, sidebars, newsletters, and other noise.
- Falls back to RSS body when full-content fetch fails.
- Toggle full-content mode on/off for faster RSS-only imports.

### 🔍 Scan & Preview Workflow
- **Scan** all enabled sources for new writeups before saving anything.
- **Preview modal** shows every found item with title, source badge, date, and tags.
- **Select / deselect** individual writeups or use "Select all" / "Select none".
- Only fetches writeups you haven't already seen (URL deduplication).

### 🏷️ Automatic Tagging
- **Smart tag extraction** from titles and RSS categories — recognizes 24+ security topics:
  `xss` · `sqli` · `rce` · `ssrf` · `idor` · `csrf` · `xxe` · `lfi` · `open-redirect` · `recon` · `privesc` · `bypass` · `ato` · `api-security` · `auth` · `race-condition` · `ssti` · `deserialization` · `graphql` · `mobile` · `ctf` · `htb` · `bug-bounty` · `cve`
- Every writeup is also tagged with `#writeup`, `#security`, and its source name.

### 🗂️ Advanced Filtering
- **Filter by tag** — Choose from a dropdown of all recognized security tags before scanning.
- **Filter by date range** — Set a "From" and "To" date to narrow results.
- Filters are applied during the scan phase so only relevant items appear in the preview.

### 📝 Clean Markdown Output
- Converts full HTML articles to **well-structured Markdown** — headings, code blocks (with language hints), links, images, tables, blockquotes, lists, and more.
- Each note includes **YAML frontmatter** with `title`, `source`, `url`, `date`, `tags`, and `scraped_at`.
- Real article titles are used as filenames (sanitized for filesystem safety), with collision-safe short hashes when needed.
- Notes are organized into per-source subfolders (e.g. `writeups/pentester-land/`).

### 📑 Auto-Generated Index
- After every fetch, an `index.md` file is created/updated in the output folder.
- Groups writeups by source with backlinks (`[[...]]`) and shows total count.
- Includes a quick-access tag reference section.

### 🔄 Retry Failed Items
- Failed fetches are tracked and surfaced in the UI.
- One-click **retry** button to re-attempt all failed items.
- Status bar shows a warning indicator when failed items exist.

### ⚙️ Configurable Settings
- **Output folder** — Choose where writeups are saved in your vault.
- **Limit per source** — Control how many items are fetched from each feed.
- **Auto-fetch on startup** — Optionally scan and open the preview modal when Obsidian launches.
- **Cache management** — Clear the "seen URLs" cache to re-fetch older writeups.
- All settings accessible from the **Sources Manager modal**, **Settings Tab**, or the **ribbon icons**.

### 🖥️ UI & UX
- **Two ribbon icons** — Quick access to the Sources Manager (🛡️) and Fetch modal (⬇).
- **Two command palette commands** — `Open Sources Manager` and `Fetch Writeups (with preview)`.
- **Status bar widget** — Shows total writeup count and failed item warnings; click to open Sources Manager.
- **Progress bar** with per-item log during fetch — see each writeup being processed in real time.
- **Responsive modals** — Scrollable, sticky footers, works on all screen sizes.

## 🚀 Installation

### Manual
1. Download the latest release files (`main.js`, `manifest.json`, `styles.css`).
2. Create a folder named `security-writeups-fetcher` inside your vault's `.obsidian/plugins/` directory.
3. Copy the downloaded files into this folder.
4. Open Obsidian → Settings → Community Plugins → Enable **Security Writeups Fetcher**.

## 📁 Project Structure

| File | Purpose |
|---|---|
| `main.js` | Core plugin logic — RSS parsing, HTML→Markdown conversion, fetch engine, modals, settings |
| `styles.css` | UI styles for modals, preview list, progress bar, source rows, filters |
| `manifest.json` | Plugin metadata (ID, version, description) |
| `data.json` | Persisted settings, seen URLs cache, source configurations |

## 🛠️ Usage

1. Click the **🛡️ ribbon icon** (or run the `Open Sources Manager` command) to configure sources and settings.
2. Click the **⬇ ribbon icon** (or run `Fetch Writeups`) to scan for new content.
3. Apply optional **tag and date filters**, then click **Scan for new writeups**.
4. **Preview** the results, check/uncheck what you want, then hit **Save selected**.
5. Find your writeups in the configured output folder, organized by source.

## 📜 License

MIT
