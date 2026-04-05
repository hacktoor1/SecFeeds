'use strict';
var obsidian = require('obsidian');

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
    outputFolder: 'writeups',
    limitPerSource: 20,
    autoFetchOnStartup: false,
    fetchFullContent: true,
    lastFetched: '',
    seenUrls: [],
    failedUrls: [],
    sources: [
        { id:'pentester-land',    name:'Pentester Land',     url:'https://pentester.land/writeups/',   feedUrl:'https://pentester.land/writeups/index.xml', icon:'🎯', enabled:true,
          articleSelector:'article, .post-content, .content, main' },
        { id:'infosec-writeups',  name:'InfoSec Writeups',   url:'https://infosecwriteups.com/',       feedUrl:'https://infosecwriteups.com/feed',           icon:'📝', enabled:true,
          articleSelector:'article, .postArticle-content, section[data-field="body"]' },
        { id:'bugbounty-hunting', name:'Bug Bounty Hunting', url:'https://www.bugbountyhunting.com/',  feedUrl:'https://www.bugbountyhunting.com/feed.xml',  icon:'🐛', enabled:true,
          articleSelector:'article, .post-body, .entry-content, main' },
    ],
};

const ALL_TAGS = ['xss','sqli','rce','ssrf','idor','csrf','xxe','lfi','open-redirect','recon',
    'privesc','bypass','ato','api-security','auth','race-condition','ssti','deserialization',
    'graphql','mobile','ctf','htb','bug-bounty','cve'];

// ─── Utilities ────────────────────────────────────────────────────────────────

function safeFilename(title) {
    // Use real title as filename, sanitize for filesystem
    return title
        .replace(/[\\/:*?"<>|#^[\]]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 100);
}

function slugify(t) {
    return t.toLowerCase().replace(/[^\w\s-]/g,'').replace(/[\s_]+/g,'-').replace(/-+/g,'-').slice(0,70);
}

function shortHash(s) {
    let h=0; for(let i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;} return Math.abs(h).toString(16).slice(0,6);
}

function parseDateString(s) {
    if (!s) return new Date().toISOString().slice(0,10);
    try { return new Date(s).toISOString().slice(0,10); } catch { return new Date().toISOString().slice(0,10); }
}

function extractTags(title, categories=[]) {
    const lower = title.toLowerCase();
    const map = [
        [['xss','cross-site scripting'],'xss'],
        [['sqli','sql injection'],'sqli'],
        [['rce','remote code execution','command injection'],'rce'],
        [['ssrf'],'ssrf'],[['idor','insecure direct'],'idor'],[['csrf'],'csrf'],
        [['xxe'],'xxe'],[['lfi','local file'],'lfi'],[['open redirect'],'open-redirect'],
        [['recon','subdomain takeover','enumeration'],'recon'],
        [['privilege escalation','privesc'],'privesc'],[['bypass','waf bypass'],'bypass'],
        [['account takeover','ato'],'ato'],[['api security','api hacking'],'api-security'],
        [['oauth','jwt','token hijack'],'auth'],[['race condition'],'race-condition'],
        [['ssti','template injection'],'ssti'],[['deserialization'],'deserialization'],
        [['graphql'],'graphql'],[['android','ios','mobile app'],'mobile'],
        [['ctf','capture the flag'],'ctf'],[['hack the box','htb'],'htb'],
        [['bug bounty','hackerone','bugcrowd','intigriti'],'bug-bounty'],[['cve-'],'cve'],
    ];
    const tags = ['writeup','security'];
    for (const [kws,tag] of map)
        if (kws.some(k=>lower.includes(k)) && !tags.includes(tag)) tags.push(tag);
    for (const cat of categories) {
        const s = slugify(cat);
        if (s.length > 2 && s.length < 30 && !tags.includes(s)) tags.push(s);
    }
    return tags;
}

// ─── HTML → Markdown ──────────────────────────────────────────────────────────

function htmlToMd(html) {
    if (!html) return '';
    const doc = new DOMParser().parseFromString(html, 'text/html');

    // Remove junk
    for (const sel of ['script','style','nav','footer','header','.sidebar','.ads','.newsletter',
        '.subscribe','[class*="banner"]','[class*="popup"]','[id*="sidebar"]','noscript','iframe']) {
        doc.querySelectorAll(sel).forEach(el => el.remove());
    }

    function nodeToMd(node, depth=0) {
        if (node.nodeType === Node.TEXT_NODE) {
            return node.textContent.replace(/\n+/g,' ');
        }
        if (node.nodeType !== Node.ELEMENT_NODE) return '';
        const tag = node.tagName.toLowerCase();
        const children = () => [...node.childNodes].map(c=>nodeToMd(c,depth)).join('');

        switch(tag) {
            case 'h1': return `\n# ${children().trim()}\n\n`;
            case 'h2': return `\n## ${children().trim()}\n\n`;
            case 'h3': return `\n### ${children().trim()}\n\n`;
            case 'h4': return `\n#### ${children().trim()}\n\n`;
            case 'h5': case 'h6': return `\n##### ${children().trim()}\n\n`;
            case 'p': return `\n${children().trim()}\n\n`;
            case 'br': return '\n';
            case 'hr': return '\n---\n\n';
            case 'strong': case 'b': return `**${children().trim()}**`;
            case 'em': case 'i': return `*${children().trim()}*`;
            case 'del': case 's': return `~~${children().trim()}~~`;
            case 'code': {
                const parent = node.parentElement?.tagName?.toLowerCase();
                if (parent === 'pre') return children();
                return `\`${children().trim()}\``;
            }
            case 'pre': {
                const codeEl = node.querySelector('code');
                const lang = codeEl?.className?.match(/language-(\w+)/)?.[1] || '';
                const content = (codeEl ? codeEl.textContent : node.textContent).trimEnd();
                return `\n\`\`\`${lang}\n${content}\n\`\`\`\n\n`;
            }
            case 'blockquote': return `\n> ${children().trim().replace(/\n/g,'\n> ')}\n\n`;
            case 'a': {
                const href = node.getAttribute('href') || '';
                const text = children().trim() || href;
                if (!href || href.startsWith('#')) return text;
                return `[${text}](${href})`;
            }
            case 'img': {
                const src = node.getAttribute('src') || '';
                const alt = node.getAttribute('alt') || '';
                if (!src || src.startsWith('data:')) return '';
                return `\n![${alt}](${src})\n\n`;
            }
            case 'ul': return `\n${[...node.querySelectorAll(':scope > li')].map(li=>`- ${[...li.childNodes].map(c=>nodeToMd(c,depth+1)).join('').trim()}`).join('\n')}\n\n`;
            case 'ol': return `\n${[...node.querySelectorAll(':scope > li')].map((li,i)=>`${i+1}. ${[...li.childNodes].map(c=>nodeToMd(c,depth+1)).join('').trim()}`).join('\n')}\n\n`;
            case 'li': return children();
            case 'table': {
                const rows = [...node.querySelectorAll('tr')];
                if (!rows.length) return '';
                const toRow = r => '| '+[...r.querySelectorAll('th,td')].map(c=>c.textContent.trim().replace(/\|/g,'\\|')).join(' | ')+' |';
                const header = toRow(rows[0]);
                const sep = '| '+[...rows[0].querySelectorAll('th,td')].map(()=>'---').join(' | ')+' |';
                const body = rows.slice(1).map(toRow).join('\n');
                return `\n${header}\n${sep}\n${body}\n\n`;
            }
            case 'div': case 'section': case 'article': case 'main':
            case 'span': case 'figure': case 'figcaption': case 'aside':
                return children();
            default: return children();
        }
    }

    let md = nodeToMd(doc.body);
    // Clean up
    md = md.replace(/\n{4,}/g, '\n\n\n').trim();
    // Decode leftover entities
    md = md.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&nbsp;/g,' ');
    return md;
}

function extractArticleFromHtml(html, selectors) {
    if (!html) return '';
    const doc = new DOMParser().parseFromString(html, 'text/html');
    // Remove noise
    for (const sel of ['script','style','nav','footer','header','.sidebar','.comments',
        '[class*="related"]','[class*="share"]','[class*="newsletter"]','[class*="subscribe"]',
        '[id*="sidebar"]','noscript','aside']) {
        doc.querySelectorAll(sel).forEach(el=>el.remove());
    }
    // Try custom selectors first, then fallbacks
    const allSelectors = [
        ...selectors.split(',').map(s=>s.trim()),
        'article','[role="main"]','.post-content','.article-body','.entry-content',
        '.content','main','.story-body','#article-body','.article__body','.post-body',
        '.markdown-body','.prose','[itemprop="articleBody"]',
    ];
    for (const sel of allSelectors) {
        try {
            const el = doc.querySelector(sel);
            if (el && el.textContent.trim().length > 300) {
                return htmlToMd(el.innerHTML);
            }
        } catch(e) {}
    }
    // Fallback: whole body
    return htmlToMd(doc.body?.innerHTML || html);
}

// ─── RSS Parser ───────────────────────────────────────────────────────────────

function parseRSS(xmlText) {
    const doc = new DOMParser().parseFromString(xmlText, 'text/xml');
    const items = [];
    for (const node of doc.querySelectorAll('item, entry')) {
        const title = node.querySelector('title')?.textContent?.trim() || '';
        let link = node.querySelector('link')?.textContent?.trim() || '';
        if (!link || !link.startsWith('http')) {
            link = node.querySelector('link')?.getAttribute('href') || '';
        }
        const pubDate = node.querySelector('pubDate, published, updated')?.textContent?.trim() || '';
        const desc = node.querySelector('description')?.textContent?.trim()
            || node.querySelector('content\\:encoded')?.textContent?.trim()
            || node.querySelector('content')?.textContent?.trim() || '';
        const author = node.querySelector('dc\\:creator, creator, author name')?.textContent?.trim() || '';
        const cats = [...node.querySelectorAll('category')].map(c=>c.textContent?.trim()).filter(Boolean);
        if (title && link) items.push({title, link, pubDate, desc, author, cats});
    }
    return items;
}

// ─── Article Fetcher (uses Obsidian requestUrl to bypass CORS) ────────────────

async function fetchArticleContent(url, articleSelector) {
    try {
        const resp = await obsidian.requestUrl({
            url,
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            throw: false,
        });
        if (!resp || resp.status < 200 || resp.status >= 300) return null;
        return extractArticleFromHtml(resp.text, articleSelector);
    } catch(e) {
        return null;
    }
}

async function fetchFeedItems(src) {
    const feedPaths = ['', '/feed', '/feed.xml', '/rss', '/rss.xml', '/atom.xml', '/index.xml'];
    const base = src.feedUrl || src.url;
    const attempts = base.match(/\.(xml|rss|atom)$/) ? [base]
        : [base, ...feedPaths.map(p => src.url.replace(/\/$/,'') + p)];

    for (const url of attempts) {
        try {
            const resp = await obsidian.requestUrl({
                url,
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (Obsidian Plugin)' },
                throw: false,
            });
            if (!resp || resp.status < 200 || resp.status >= 300) continue;
            const text = resp.text;
            if (!text.includes('<item') && !text.includes('<entry')) continue;
            const items = parseRSS(text);
            if (items.length > 0) return items;
        } catch(e) {}
    }
    return [];
}

// ─── Markdown Builder ─────────────────────────────────────────────────────────

function buildMd({title, source, url, date, tags, author, body}) {
    const tagLine = tags.map(t => `#${t}`).join(' ');
    const authorLine = author ? `> **Author:** ${author}\n` : '';
    return `---
title: "${title.replace(/"/g, "'")}"
source: "${source}"
url: "${url}"
date: "${date}"
tags: ${JSON.stringify(tags)}
scraped_at: "${new Date().toISOString().slice(0,16)}"
---

# ${title}

> **Source:** [${source}](${url})
> **Date:** ${date}
${authorLine}> **Tags:** ${tagLine}

---

${body || `[Read the full writeup online](${url})\n`}
`;
}

// ─── Preview + Fetch Modal ────────────────────────────────────────────────────

class FetchPreviewModal extends obsidian.Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
        this.items = [];          // {title, url, source, date, tags, checked, status}
        this.phase = 'idle';      // idle | scanning | fetching | done
        this.progress = 0;
        this.progressTotal = 0;
        this.filterTag = '';
        this.filterDateFrom = '';
        this.filterDateTo = '';
        this.failedItems = [];
        this.savedCount = 0;
    }

    onOpen() {
        this.modalEl.addClass('wm-preview-modal');
        // Set size directly on modalEl — Obsidian ignores CSS width on .modal-content
        this.modalEl.style.cssText = 'width:680px; max-width:95vw;';
        this.contentEl.style.cssText = 'padding:22px 26px 18px; max-height:82vh; overflow-y:auto;';
        this.renderIdle();
    }

    // ── Phase: Idle (filters + start button) ──
    renderIdle() {
        const {contentEl, plugin} = this;
        contentEl.empty();

        contentEl.createEl('h2', {text: '⬇  Fetch Writeups'});

        // Filter row
        const filters = contentEl.createDiv({cls: 'wm-filters'});

        const tagWrap = filters.createDiv({cls: 'wm-filter-field'});
        tagWrap.createEl('label', {text: 'Tag filter'});
        const tagSel = tagWrap.createEl('select');
        tagSel.createEl('option', {text: 'All tags', value: ''});
        for (const t of ALL_TAGS) tagSel.createEl('option', {text: `#${t}`, value: t});
        tagSel.value = this.filterTag;
        tagSel.addEventListener('change', () => { this.filterTag = tagSel.value; });

        const dateFromWrap = filters.createDiv({cls: 'wm-filter-field'});
        dateFromWrap.createEl('label', {text: 'From date'});
        const dateFromIn = dateFromWrap.createEl('input', {type:'date'});
        dateFromIn.value = this.filterDateFrom;
        dateFromIn.addEventListener('change', () => { this.filterDateFrom = dateFromIn.value; });

        const dateToWrap = filters.createDiv({cls: 'wm-filter-field'});
        dateToWrap.createEl('label', {text: 'To date'});
        const dateToIn = dateToWrap.createEl('input', {type:'date'});
        dateToIn.value = this.filterDateTo;
        dateToIn.addEventListener('change', () => { this.filterDateTo = dateToIn.value; });

        // Enabled sources summary
        const enabled = plugin.settings.sources.filter(s=>s.enabled);
        const srcInfo = contentEl.createDiv({cls: 'wm-src-summary'});
        srcInfo.createSpan({text: `${enabled.length} source${enabled.length!==1?'s':''} enabled: `});
        srcInfo.createSpan({text: enabled.map(s=>s.icon+' '+s.name).join('  ·  '), cls: 'wm-src-names'});

        const fullContentRow = contentEl.createDiv({cls: 'wm-toggle-row'});
        const fcToggle = fullContentRow.createEl('input', {type:'checkbox'});
        fcToggle.checked = plugin.settings.fetchFullContent;
        fcToggle.addEventListener('change', async () => {
            plugin.settings.fetchFullContent = fcToggle.checked;
            await plugin.saveSettings();
        });
        fullContentRow.createEl('label', {text: 'Fetch full article content (slower but complete)'});

        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const scanBtn = footer.createEl('button', {text: '🔍  Scan for new writeups', cls: 'wm-btn-primary'});
        scanBtn.addEventListener('click', () => this.startScan());
    }

    // ── Phase: Scanning RSS feeds ──
    async startScan() {
        this.phase = 'scanning';
        const {contentEl, plugin} = this;
        contentEl.empty();
        contentEl.createEl('h2', {text: '🔍 Scanning feeds...'});
        const statusEl = contentEl.createDiv({cls: 'wm-scan-status'});

        const seen = new Set(plugin.settings.seenUrls || []);
        const enabled = plugin.settings.sources.filter(s=>s.enabled);
        const limit = plugin.settings.limitPerSource || 20;
        const foundItems = [];

        for (const src of enabled) {
            statusEl.setText(`Fetching RSS from ${src.name}...`);
            try {
                const rssItems = await fetchFeedItems(src);
                for (const item of rssItems) {
                    if (foundItems.length + (await this.countExisting()) >= limit * enabled.length) break;
                    if (seen.has(item.link)) continue;

                    const date = parseDateString(item.pubDate);

                    // Date filter
                    if (this.filterDateFrom && date < this.filterDateFrom) continue;
                    if (this.filterDateTo && date > this.filterDateTo) continue;

                    const tags = extractTags(item.title, item.cats);
                    tags.push(slugify(src.name));

                    // Tag filter
                    if (this.filterTag && !tags.includes(this.filterTag)) continue;

                    foundItems.push({
                        title: item.title,
                        url: item.link,
                        source: src.name,
                        sourceId: src.id,
                        articleSelector: src.articleSelector || 'article',
                        date,
                        tags,
                        author: item.author,
                        rssBody: htmlToMd(item.desc),
                        checked: true,
                        status: 'pending',
                    });
                }
            } catch(e) {
                statusEl.setText(`⚠️ Failed to fetch ${src.name}`);
                await sleep(800);
            }
        }

        this.items = foundItems;
        if (foundItems.length === 0) {
            this.renderNoResults();
        } else {
            this.renderPreview();
        }
    }

    async countExisting() { return 0; }

    renderNoResults() {
        const {contentEl} = this;
        contentEl.empty();
        contentEl.createEl('h2', {text: 'ℹ️ No new writeups found'});
        contentEl.createEl('p', {text: 'All available writeups have already been downloaded, or no sources returned results.', cls:'wm-hint'});
        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const backBtn = footer.createEl('button', {text: '← Back', cls: 'wm-btn-secondary'});
        backBtn.addEventListener('click', () => this.renderIdle());
    }

    // ── Phase: Preview list ──
    renderPreview() {
        const {contentEl} = this;
        contentEl.empty();

        const total = this.items.length;
        contentEl.createEl('h2', {text: `📋 ${total} new writeup${total!==1?'s':''} found`});

        // Select all / none
        const selRow = contentEl.createDiv({cls: 'wm-sel-row'});
        const selAllBtn = selRow.createEl('button', {text: '✓ Select all', cls: 'wm-btn-sm'});
        const selNoneBtn = selRow.createEl('button', {text: '✕ Select none', cls: 'wm-btn-sm'});
        const countLabel = selRow.createSpan({text: `${this.items.filter(i=>i.checked).length} selected`, cls:'wm-count-label'});

        selAllBtn.addEventListener('click', () => {
            this.items.forEach(i=>i.checked=true);
            this.renderPreview();
        });
        selNoneBtn.addEventListener('click', () => {
            this.items.forEach(i=>i.checked=false);
            this.renderPreview();
        });

        // Item list
        const list = contentEl.createDiv({cls: 'wm-preview-list'});
        for (let i=0; i<this.items.length; i++) {
            const item = this.items[i];
            const row = list.createDiv({cls: `wm-preview-row${item.checked?'':' wm-unchecked'}`});

            const cb = row.createEl('input', {type:'checkbox'});
            cb.checked = item.checked;
            cb.addEventListener('change', () => {
                this.items[i].checked = cb.checked;
                row.toggleClass('wm-unchecked', !cb.checked);
                const n = this.items.filter(x=>x.checked).length;
                countLabel.setText(`${n} selected`);
            });

            const info = row.createDiv({cls: 'wm-preview-info'});
            const titleEl = info.createEl('a', {text: item.title, cls: 'wm-preview-title', href: item.url});

            const meta = info.createDiv({cls: 'wm-preview-meta'});
            meta.createSpan({text: item.source, cls: 'wm-badge-source'});
            meta.createSpan({text: item.date, cls: 'wm-meta-date'});
            // Show first 4 tags
            for (const tag of item.tags.slice(0,4)) {
                meta.createSpan({text: `#${tag}`, cls: 'wm-tag-pill'});
            }
        }

        // Footer
        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const backBtn = footer.createEl('button', {text: '← Back', cls: 'wm-btn-secondary'});
        backBtn.addEventListener('click', () => this.renderIdle());

        const saveBtn = footer.createEl('button', {text: `⬇  Save selected`, cls: 'wm-btn-primary'});
        saveBtn.addEventListener('click', () => this.startFetch());
    }

    // ── Phase: Fetching & saving ──
    async startFetch() {
        const {contentEl, plugin} = this;
        const selected = this.items.filter(i=>i.checked);
        if (!selected.length) { new obsidian.Notice('No items selected'); return; }

        this.phase = 'fetching';
        this.progress = 0;
        this.progressTotal = selected.length;
        this.failedItems = [];
        this.savedCount = 0;
        contentEl.empty();

        contentEl.createEl('h2', {text: `💾 Saving writeups...`});

        // Progress bar
        const progWrap = contentEl.createDiv({cls: 'wm-prog-wrap'});
        const progBar = progWrap.createDiv({cls: 'wm-prog-bar'});
        const progFill = progBar.createDiv({cls: 'wm-prog-fill'});
        const progLabel = progWrap.createSpan({text: `0 / ${selected.length}`, cls:'wm-prog-label'});

        const logEl = contentEl.createDiv({cls: 'wm-log'});

        const folder = plugin.settings.outputFolder || 'writeups';
        await plugin.ensureFolder(folder);

        const seen = [...(plugin.settings.seenUrls || [])];

        for (let i=0; i<selected.length; i++) {
            const item = selected[i];
            const pct = Math.round((i / selected.length) * 100);
            progFill.style.width = pct + '%';
            progLabel.setText(`${i} / ${selected.length}`);

            const logRow = logEl.createDiv({cls: 'wm-log-row'});
            logRow.createSpan({text: '⏳ ', cls:'wm-log-icon'});
            logRow.createSpan({text: item.title.slice(0,60), cls:'wm-log-title'});
            logEl.scrollTop = logEl.scrollHeight;

            let body = item.rssBody;

            if (plugin.settings.fetchFullContent) {
                const fullContent = await fetchArticleContent(item.url, item.articleSelector);
                if (fullContent && fullContent.length > body.length) {
                    body = fullContent;
                    logRow.querySelector('.wm-log-icon').setText('✅ ');
                } else {
                    // Use RSS body as fallback
                    logRow.querySelector('.wm-log-icon').setText('📄 ');
                }
            } else {
                logRow.querySelector('.wm-log-icon').setText('✅ ');
            }

            try {
                await plugin.saveWriteup(folder, {...item, body});
                seen.push(item.url);
                this.savedCount++;
            } catch(e) {
                logRow.querySelector('.wm-log-icon').setText('❌ ');
                this.failedItems.push(item);
            }

            // Small delay to avoid hammering servers
            if (i < selected.length - 1) await sleep(400);
        }

        // Finalize
        progFill.style.width = '100%';
        progLabel.setText(`${this.savedCount} / ${selected.length}`);

        await plugin.updateIndex(folder);
        plugin.settings.seenUrls = seen.slice(-3000);
        plugin.settings.failedUrls = this.failedItems.map(i=>i.url);
        plugin.settings.lastFetched = new Date().toLocaleString();
        await plugin.saveSettings();
        plugin.refreshStatusBar();

        this.renderDone(selected.length);
    }

    // ── Phase: Done ──
    renderDone(total) {
        const {contentEl} = this;
        const failed = this.failedItems.length;
        const saved = this.savedCount;

        contentEl.createEl('hr', {cls: 'wm-hr'});
        const summary = contentEl.createDiv({cls: 'wm-done-summary'});
        summary.createEl('p', {text: `✅ Saved: ${saved}`, cls: 'wm-done-ok'});
        if (failed) summary.createEl('p', {text: `⚠️ Failed: ${failed}`, cls: 'wm-done-fail'});

        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const closeBtn = footer.createEl('button', {text: 'Close', cls: 'wm-btn-secondary'});
        closeBtn.addEventListener('click', () => this.close());

        if (failed > 0) {
            const retryBtn = footer.createEl('button', {text: `🔄 Retry ${failed} failed`, cls: 'wm-btn-primary'});
            retryBtn.addEventListener('click', async () => {
                this.items = this.failedItems.map(i=>({...i, checked:true}));
                await this.startFetch();
            });
        }
    }

    onClose() { this.contentEl.empty(); }
}

// ─── Sources Manager Modal ────────────────────────────────────────────────────

class SourcesModal extends obsidian.Modal {
    constructor(app, plugin) { super(app); this.plugin = plugin; }

    onOpen() {
        this.modalEl.addClass('wm-sources-modal');
        this.modalEl.style.cssText = 'width:660px; max-width:95vw;';
        this.contentEl.style.cssText = 'padding:22px 26px 18px; max-height:82vh; overflow-y:auto;';
        this.render();
    }

    render() {
        const {contentEl, plugin} = this;
        contentEl.empty();

        contentEl.createEl('h2', {text: '🔐 Security Writeups'});

        // Settings bar
        const bar = contentEl.createDiv({cls: 'wm-bar'});

        const folderF = bar.createDiv({cls: 'wm-bar-field'});
        folderF.createEl('label', {text: 'Folder'});
        const folderIn = folderF.createEl('input', {type:'text', placeholder:'writeups'});
        folderIn.value = plugin.settings.outputFolder;
        folderIn.addEventListener('change', async () => { plugin.settings.outputFolder = folderIn.value||'writeups'; await plugin.saveSettings(); });

        const limitF = bar.createDiv({cls: 'wm-bar-field'});
        limitF.createEl('label', {text: 'Limit / source'});
        const limitIn = limitF.createEl('input', {type:'number', placeholder:'20'});
        limitIn.style.width = '70px';
        limitIn.value = String(plugin.settings.limitPerSource);
        limitIn.addEventListener('change', async () => { plugin.settings.limitPerSource = parseInt(limitIn.value)||20; await plugin.saveSettings(); });

        const autoF = bar.createDiv({cls: 'wm-bar-field wm-bar-toggle'});
        const autoTog = autoF.createEl('input', {type:'checkbox'});
        autoTog.checked = plugin.settings.autoFetchOnStartup;
        autoTog.addEventListener('change', async () => { plugin.settings.autoFetchOnStartup = autoTog.checked; await plugin.saveSettings(); });
        autoF.createEl('label', {text: 'Auto-fetch on startup'});

        // Sources list
        contentEl.createEl('h3', {text: 'Sources', cls: 'wm-section-title'});
        const list = contentEl.createDiv({cls: 'wm-list'});
        for (let i=0; i<plugin.settings.sources.length; i++) {
            this.renderSourceRow(list, plugin.settings.sources[i], i);
        }

        // Add source
        contentEl.createEl('h3', {text: 'Add source', cls: 'wm-section-title'});
        const addRow = contentEl.createDiv({cls: 'wm-add'});
        const nameIn = addRow.createEl('input', {type:'text', placeholder:'Name  (e.g. PortSwigger Research)'});
        const urlIn = addRow.createEl('input', {type:'url', placeholder:'URL or RSS  (e.g. https://portswigger.net/research)'});
        const iconIn = addRow.createEl('input', {type:'text', placeholder:'Icon'});
        iconIn.style.width = '65px';
        const addBtn = addRow.createEl('button', {text:'+ Add', cls:'wm-btn-add'});
        addBtn.addEventListener('click', async () => {
            const name = nameIn.value.trim(), url = urlIn.value.trim(), icon = iconIn.value.trim()||'🔗';
            if (!name||!url) { new obsidian.Notice('⚠️ Enter name and URL'); return; }
            try { new URL(url); } catch { new obsidian.Notice('⚠️ Invalid URL'); return; }
            if (plugin.settings.sources.find(s=>s.id===slugify(name))) { new obsidian.Notice('Already exists'); return; }
            plugin.settings.sources.push({id:slugify(name), name, url, feedUrl:url, icon, enabled:true, articleSelector:'article, .post-content, main'});
            await plugin.saveSettings();
            new obsidian.Notice(`✅ Added: ${name}`);
            nameIn.value=''; urlIn.value=''; iconIn.value='';
            this.render();
        });

        // Footer
        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const fetchBtn = footer.createEl('button', {text:'⬇  Fetch writeups', cls:'wm-btn-fetch'});
        fetchBtn.addEventListener('click', () => { this.close(); new FetchPreviewModal(this.app, plugin).open(); });
        const cacheBtn = footer.createEl('button', {text:`🗑  Clear cache (${(plugin.settings.seenUrls||[]).length})`, cls:'wm-btn-cache'});
        cacheBtn.addEventListener('click', async () => { plugin.settings.seenUrls=[]; await plugin.saveSettings(); new obsidian.Notice('Cache cleared'); this.render(); });
        if (plugin.settings.failedUrls?.length) {
            const retryBtn = footer.createEl('button', {text:`🔄 Retry failed (${plugin.settings.failedUrls.length})`, cls:'wm-btn-retry'});
            retryBtn.addEventListener('click', () => { this.close(); /* re-queue failed */ new obsidian.Notice('Retrying failed items...'); });
        }
        if (plugin.settings.lastFetched) footer.createEl('p', {text:`Last fetched: ${plugin.settings.lastFetched}`, cls:'wm-meta'});
    }

    renderSourceRow(container, src, i) {
        const {plugin} = this;
        const row = container.createDiv({cls:`wm-row${src.enabled?'':' wm-row-off'}`});

        const tog = row.createEl('input', {type:'checkbox'});
        tog.checked = src.enabled;
        tog.addEventListener('change', async () => { plugin.settings.sources[i].enabled=tog.checked; row.toggleClass('wm-row-off',!tog.checked); await plugin.saveSettings(); });

        row.createSpan({text: src.icon||'🔗', cls:'wm-icon'});

        const info = row.createDiv({cls:'wm-info'});
        info.createSpan({text: src.name, cls:'wm-name'});
        info.createEl('a', {text: new URL(src.url).hostname, href:src.url, cls:'wm-url'});

        if (i >= 3) {
            const del = row.createEl('button', {text:'✕', cls:'wm-del'});
            del.addEventListener('click', async () => { plugin.settings.sources.splice(i,1); await plugin.saveSettings(); this.render(); });
        }
    }

    onClose() { this.contentEl.empty(); }
}

// ─── Settings Tab ─────────────────────────────────────────────────────────────

class WriteupSettingTab extends obsidian.PluginSettingTab {
    constructor(app, plugin) { super(app, plugin); this.plugin = plugin; }
    display() {
        const {containerEl} = this;
        containerEl.empty();
        containerEl.createEl('h2', {text:'🔐 Security Writeups Fetcher'});
        new obsidian.Setting(containerEl).setName('Sources Manager').setDesc('Manage sources, filters, and settings').addButton(b=>b.setButtonText('Open').onClick(()=>new SourcesModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Fetch Writeups').setDesc('Scan, preview, and download new writeups').addButton(b=>b.setButtonText('Fetch now').setCta().onClick(()=>new FetchPreviewModal(this.app,this.plugin).open()));
        if (this.plugin.settings.lastFetched) containerEl.createEl('p',{text:`Last fetched: ${this.plugin.settings.lastFetched}`, cls:'setting-item-description'});
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Main Plugin ──────────────────────────────────────────────────────────────

class WriteupsFetcherPlugin extends obsidian.Plugin {
    async onload() {
        await this.loadSettings();

        this.addRibbonIcon('shield', 'Security Writeups — Sources', () => new SourcesModal(this.app, this).open());
        this.addRibbonIcon('download', 'Security Writeups — Fetch', () => new FetchPreviewModal(this.app, this).open());

        this.addCommand({id:'open-sources',  name:'Open Sources Manager', callback:()=>new SourcesModal(this.app,this).open()});
        this.addCommand({id:'fetch-preview', name:'Fetch Writeups (with preview)', callback:()=>new FetchPreviewModal(this.app,this).open()});

        this.addSettingTab(new WriteupSettingTab(this.app, this));

        this.statusBarItem = this.addStatusBarItem();
        this.refreshStatusBar();
        this.statusBarItem.onClickEvent(() => new SourcesModal(this.app,this).open());

        if (this.settings.autoFetchOnStartup) setTimeout(()=>new FetchPreviewModal(this.app,this).open(), 4000);
    }

    refreshStatusBar() {
        const n = (this.settings.seenUrls||[]).length;
        const f = (this.settings.failedUrls||[]).length;
        this.statusBarItem?.setText(f>0 ? `🔐 ${n} writeups ⚠️${f}` : `🔐 ${n} writeups`);
    }

    async ensureFolder(path) {
        const parts = path.split('/'); let cur='';
        for (const p of parts) {
            cur = cur ? `${cur}/${p}` : p;
            if (!this.app.vault.getFolderByPath(cur)) await this.app.vault.createFolder(cur);
        }
    }

    async saveWriteup(folder, item) {
        // Use real title as filename
        const filename = safeFilename(item.title);
        const sub = `${folder}/${slugify(item.source)}`;
        await this.ensureFolder(sub);
        // Add short hash only if filename collision possible
        let path = `${sub}/${filename}.md`;
        if (this.app.vault.getFileByPath(path)) {
            path = `${sub}/${filename} (${shortHash(item.url)}).md`;
        }
        if (this.app.vault.getFileByPath(path)) return; // already exists
        await this.app.vault.create(path, buildMd(item));
    }

    async updateIndex(folder) {
        const files = this.app.vault.getFiles().filter(f=>f.path.startsWith(folder+'/')&&f.extension==='md'&&f.name!=='index.md');
        const bySource = {};
        for (const f of files) { const s=f.path.split('/')[1]||'other'; if(!bySource[s])bySource[s]=[]; bySource[s].push(f); }
        const now = new Date().toLocaleString();
        let c = `---\ntitle: "Security Writeups Index"\ntags: ["index","security"]\nupdated: "${now}"\n---\n\n# 🔐 Security Writeups\n\n> Last updated: ${now} | Total: **${files.length}** writeups\n\n`;
        for (const [src,srcFiles] of Object.entries(bySource)) {
            const label = src.replace(/-/g,' ').replace(/\b\w/g,x=>x.toUpperCase());
            c += `### ${label} (${srcFiles.length})\n\n`;
            srcFiles.slice(-20).reverse().forEach(f=>{c+=`- [[${f.basename}]]\n`;});
            c += '\n';
        }
        c += `---\n## 🏷️ Tags\n\n${ALL_TAGS.slice(0,12).map(t=>`\`#${t}\``).join(' ')}\n`;
        const idx = this.app.vault.getFileByPath(`${folder}/index.md`);
        if (idx) await this.app.vault.modify(idx,c); else await this.app.vault.create(`${folder}/index.md`,c);
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        if (!this.settings.seenUrls) this.settings.seenUrls = [];
        if (!this.settings.failedUrls) this.settings.failedUrls = [];
    }
    async saveSettings() { await this.saveData(this.settings); }
}

module.exports = WriteupsFetcherPlugin;
