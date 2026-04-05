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
    watchlistKeywords: ['rce','zero-day','critical','account takeover','authentication bypass','privilege escalation'],
    stats: { totalFetched:0, totalFailed:0, bySource:{}, byTag:{}, byMonth:{} },
    sources: [
        { id:'pentester-land',    name:'Pentester Land',     url:'https://pentester.land/writeups/',   feedUrl:'https://pentester.land/writeups/index.xml', icon:'🎯', enabled:true,
          articleSelector:'article, .post-content, .content, main' },
        { id:'infosec-writeups',  name:'InfoSec Writeups',   url:'https://infosecwriteups.com/',       feedUrl:'https://infosecwriteups.com/feed',           icon:'📝', enabled:true,
          articleSelector:'article, .postArticle-content, section[data-field="body"]' },
        { id:'bugbounty-hunting', name:'Bug Bounty Hunting', url:'https://www.bugbountyhunting.com/',  feedUrl:'https://www.bugbountyhunting.com/feed.xml',  icon:'🐛', enabled:true,
          articleSelector:'article, .post-body, .entry-content, main' },
        { id:'portswigger',       name:'PortSwigger Research', url:'https://portswigger.net/research/', feedUrl:'https://portswigger.net/research/rss',       icon:'🔬', enabled:true,
          articleSelector:'article, .article-body, .content, main' },
        { id:'thehackernews',     name:'The Hacker News',    url:'https://thehackernews.com/',         feedUrl:'https://feeds.feedburner.com/TheHackersNews', icon:'📡', enabled:true,
          articleSelector:'article, .articlebody, .story-details, main' },
        { id:'project-zero',      name:'Project Zero',       url:'https://googleprojectzero.blogspot.com/', feedUrl:'https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss', icon:'🧪', enabled:true,
          articleSelector:'article, .post-body, .entry-content, main' },
        { id:'assetnote',         name:'Assetnote Research', url:'https://blog.assetnote.io/',         feedUrl:'https://blog.assetnote.io/feed.xml',         icon:'🛡️', enabled:true,
          articleSelector:'article, .post-content, .content, main' },
        { id:'krebs',             name:'Krebs on Security',  url:'https://krebsonsecurity.com/',       feedUrl:'https://krebsonsecurity.com/feed/',          icon:'🔒', enabled:true,
          articleSelector:'article, .entry-content, main' },
    ],
};

const ALL_TAGS = ['xss','sqli','rce','ssrf','idor','csrf','xxe','lfi','open-redirect','recon',
    'privesc','bypass','ato','api-security','auth','race-condition','ssti','deserialization',
    'graphql','mobile','ctf','htb','bug-bounty','cve'];

const TAG_SEVERITY_CLASS = {
    'rce':'wm-tag-crit','sqli':'wm-tag-crit','deserialization':'wm-tag-crit','xxe':'wm-tag-crit',
    'xss':'wm-tag-high','ssrf':'wm-tag-high','ssti':'wm-tag-high','auth':'wm-tag-high','ato':'wm-tag-high',
    'idor':'wm-tag-med','csrf':'wm-tag-med','lfi':'wm-tag-med','open-redirect':'wm-tag-med',
    'race-condition':'wm-tag-med','bypass':'wm-tag-med','privesc':'wm-tag-med',
    'recon':'wm-tag-info','ctf':'wm-tag-info','htb':'wm-tag-info','bug-bounty':'wm-tag-info',
    'mobile':'wm-tag-info','graphql':'wm-tag-info','api-security':'wm-tag-info','cve':'wm-tag-info',
};

const SEVERITY_ICON = { critical:'🔴', high:'🟠', medium:'🟡', info:'🔵' };

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

// ─── New Utilities ────────────────────────────────────────────────────────────

function estimateReadingTime(text) {
    const words = (text || '').trim().split(/\s+/).filter(Boolean).length;
    const minutes = Math.max(1, Math.ceil(words / 200));
    return { minutes, words, label: `~${minutes} min` };
}

function detectSeverity(title, tags) {
    const t = title.toLowerCase();
    const crit = ['rce','remote code execution','command injection','deserialization','zero-day','0-day','pre-auth rce'];
    const high = ['sqli','sql injection','xxe','ssrf','ssti','template injection','account takeover','ato','auth bypass','authentication bypass'];
    const med  = ['xss','cross-site scripting','csrf','idor','lfi','local file','open redirect','race condition','privilege escalation','privesc','bypass'];
    if (crit.some(k=>t.includes(k))||['rce','deserialization'].some(x=>tags.includes(x))) return 'critical';
    if (high.some(k=>t.includes(k))||['sqli','xxe','ssrf','ssti','ato'].some(x=>tags.includes(x))) return 'high';
    if (med.some(k=>t.includes(k))||['xss','csrf','idor','lfi'].some(x=>tags.includes(x))) return 'medium';
    return 'info';
}

function extractCVEs(text) {
    const m = (text || '').match(/CVE-\d{4}-\d{4,}/gi) || [];
    return [...new Set(m.map(c=>c.toUpperCase()))];
}

function detectPlatform(url, title) {
    const t = (url+' '+title).toLowerCase();
    if (t.includes('hackerone')) return 'HackerOne';
    if (t.includes('bugcrowd')) return 'Bugcrowd';
    if (t.includes('intigriti')) return 'Intigriti';
    if (t.includes('synack')) return 'Synack';
    if (t.includes('yeswehack')) return 'YesWeHack';
    if (t.includes('tryhackme')||t.includes(' thm ')) return 'TryHackMe';
    if (t.includes('hackthebox')||t.includes(' htb ')) return 'HackTheBox';
    return '';
}

function generateTOC(body) {
    const headings = (body||'').match(/^#{2,3}\s+.+$/gm) || [];
    if (headings.length < 3) return '';
    const toc = headings.map(h => {
        const lvl = h.match(/^(#{2,3})/)[1].length;
        const txt = h.replace(/^#{2,3}\s+/,'').trim();
        const anchor = txt.toLowerCase().replace(/[^\w\s-]/g,'').replace(/\s+/g,'-');
        return `${lvl===3?'  ':''}- [${txt}](#${anchor})`;
    }).join('\n');
    return `## Table of Contents\n\n${toc}\n\n---\n\n`;
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
    const content = body || '';
    const {words, label: readTime} = estimateReadingTime(content);
    const severity = detectSeverity(title, tags);
    const sevIcon = SEVERITY_ICON[severity];
    const cves = extractCVEs(title + ' ' + content);
    const platform = detectPlatform(url, title);
    const excerpt = content.replace(/[#*>\-\[\]`]/g,'').replace(/\n+/g,' ').trim().slice(0,200);
    const tagLine = tags.map(t => `#${t}`).join(' ');
    const toc = generateTOC(content);

    // YAML frontmatter
    let fm = `---\ntitle: "${title.replace(/"/g,"'")}"\nsource: "${source}"\nurl: "${url}"\ndate: "${date}"\n`;
    fm += `tags: ${JSON.stringify(tags)}\nscraped_at: "${new Date().toISOString().slice(0,16)}"\n`;
    fm += `reading_time: "${readTime}"\nword_count: ${words}\nseverity: "${severity}"\n`;
    if (platform) fm += `platform: "${platform}"\n`;
    if (cves.length) fm += `cve_ids: ${JSON.stringify(cves)}\n`;
    if (excerpt) fm += `excerpt: "${excerpt.replace(/"/g,"'").slice(0,200)}"\n`;
    fm += '---\n\n';

    // Info card
    let card = `# ${title}\n\n`;
    card += `> [!info] 📋 Writeup Details\n`;
    card += `> | | |\n> |---|---|\n`;
    card += `> | **Source** | [${source}](${url}) |\n`;
    card += `> | **Date** | ${date} |\n`;
    card += `> | **Reading Time** | ⏱ ${readTime} (${words.toLocaleString()} words) |\n`;
    card += `> | **Severity** | ${sevIcon} ${severity.charAt(0).toUpperCase()+severity.slice(1)} |\n`;
    if (author) card += `> | **Author** | ${author} |\n`;
    if (platform) card += `> | **Platform** | ${platform} |\n`;
    if (cves.length) card += `> | **CVEs** | ${cves.map(c=>'`'+c+'`').join(', ')} |\n`;
    card += `> | **Tags** | ${tagLine} |\n`;
    card += '\n---\n\n';

    // Related writeups (Dataview)
    const relTags = tags.filter(t=>!['writeup','security'].includes(t)).slice(0,3);
    let related = '\n\n---\n\n## 🔗 Related Writeups\n\n';
    if (relTags.length) {
        related += '```dataview\nTABLE date, severity, source\nFROM "writeups"\n';
        related += `WHERE ${relTags.map(t=>`contains(tags, "${t}")`).join(' OR ')}\n`;
        related += 'SORT date DESC\nLIMIT 10\n```\n';
    } else {
        related += '*No related tags to query.*\n';
    }
    related += '\n---\n\n> 📚 [[writeups/index|← Back to Index]]\n';

    return fm + card + toc + (content || `[Read the full writeup online](${url})\n`) + related;
}

// ─── Preview + Fetch Modal ────────────────────────────────────────────────────

class FetchPreviewModal extends obsidian.Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
        this.items = [];
        this.phase = 'idle';
        this.progress = 0;
        this.progressTotal = 0;
        this.filterTag = '';
        this.filterDateFrom = '';
        this.filterDateTo = '';
        this.filterText = '';
        this.sortBy = 'date-desc';
        this.failedItems = [];
        this.savedCount = 0;
    }

    onOpen() {
        this.modalEl.addClass('wm-preview-modal');
        this.modalEl.style.cssText = 'width:720px; max-width:95vw;';
        this.contentEl.style.cssText = 'padding:22px 26px 18px; max-height:82vh; overflow-y:auto;';
        this.renderIdle();
    }

    renderIdle() {
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '⬇  Fetch Writeups'});

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

    async startScan() {
        this.phase = 'scanning';
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '🔍 Scanning feeds...'});
        const statusEl = contentEl.createDiv({cls: 'wm-scan-status'});

        const seen = new Set(plugin.settings.seenUrls || []);
        const enabled = plugin.settings.sources.filter(s=>s.enabled);
        const limit = plugin.settings.limitPerSource || 20;
        const watchlist = (plugin.settings.watchlistKeywords || []).map(k=>k.toLowerCase());
        const foundItems = [];

        for (const src of enabled) {
            statusEl.setText(`Fetching RSS from ${src.name}...`);
            try {
                const rssItems = await fetchFeedItems(src);
                for (const item of rssItems) {
                    if (foundItems.length + (await this.countExisting()) >= limit * enabled.length) break;
                    if (seen.has(item.link)) continue;
                    const date = parseDateString(item.pubDate);
                    if (this.filterDateFrom && date < this.filterDateFrom) continue;
                    if (this.filterDateTo && date > this.filterDateTo) continue;
                    const tags = extractTags(item.title, item.cats);
                    tags.push(slugify(src.name));
                    if (this.filterTag && !tags.includes(this.filterTag)) continue;

                    const titleLower = item.title.toLowerCase();
                    const isWatchlisted = watchlist.some(k => titleLower.includes(k));

                    foundItems.push({
                        title: item.title, url: item.link, source: src.name,
                        sourceId: src.id, articleSelector: src.articleSelector || 'article',
                        date, tags, author: item.author, rssBody: htmlToMd(item.desc),
                        checked: true, status: 'pending', watchlisted: isWatchlisted,
                        severity: detectSeverity(item.title, tags),
                    });
                }
            } catch(e) {
                statusEl.setText(`⚠️ Failed to fetch ${src.name}`);
                await sleep(800);
            }
        }

        this.items = foundItems;
        if (foundItems.length === 0) { this.renderNoResults(); }
        else { this.renderPreview(); }
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

    getFilteredSortedItems() {
        let items = this.items;
        if (this.filterText) {
            const q = this.filterText.toLowerCase();
            items = items.filter(i => i.title.toLowerCase().includes(q) || i.source.toLowerCase().includes(q));
        }
        const sorted = [...items];
        switch (this.sortBy) {
            case 'date-asc': sorted.sort((a,b) => a.date.localeCompare(b.date)); break;
            case 'date-desc': sorted.sort((a,b) => b.date.localeCompare(a.date)); break;
            case 'source': sorted.sort((a,b) => a.source.localeCompare(b.source)); break;
            case 'title': sorted.sort((a,b) => a.title.localeCompare(b.title)); break;
            case 'severity': {
                const o = {critical:0,high:1,medium:2,info:3};
                sorted.sort((a,b) => (o[a.severity]||3) - (o[b.severity]||3));
                break;
            }
        }
        return sorted;
    }

    renderPreview() {
        const {contentEl} = this;
        contentEl.empty();
        const total = this.items.length;
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: `📋 ${total} new writeup${total!==1?'s':''} found`});

        // Search + Sort bar
        const toolbar = contentEl.createDiv({cls: 'wm-toolbar'});
        const searchIn = toolbar.createEl('input', {type:'text', placeholder:'🔎 Search writeups...', cls:'wm-search-input'});
        searchIn.value = this.filterText;
        searchIn.addEventListener('input', () => { this.filterText = searchIn.value; this.renderPreviewList(list, countLabel); });

        const sortSel = toolbar.createEl('select', {cls:'wm-sort-select'});
        for (const [v,l] of [['date-desc','📅 Newest'],['date-asc','📅 Oldest'],['severity','⚠️ Severity'],['source','📡 Source'],['title','🔤 Title']]) {
            sortSel.createEl('option', {text:l, value:v});
        }
        sortSel.value = this.sortBy;
        sortSel.addEventListener('change', () => { this.sortBy = sortSel.value; this.renderPreviewList(list, countLabel); });

        // Select all / none
        const selRow = contentEl.createDiv({cls: 'wm-sel-row'});
        const selAllBtn = selRow.createEl('button', {text: '✓ Select all', cls: 'wm-btn-sm'});
        const selNoneBtn = selRow.createEl('button', {text: '✕ Select none', cls: 'wm-btn-sm'});
        const countLabel = selRow.createSpan({text: '', cls:'wm-count-label'});

        selAllBtn.addEventListener('click', () => { this.items.forEach(i=>i.checked=true); this.renderPreviewList(list, countLabel); });
        selNoneBtn.addEventListener('click', () => { this.items.forEach(i=>i.checked=false); this.renderPreviewList(list, countLabel); });

        const list = contentEl.createDiv({cls: 'wm-preview-list'});
        this.renderPreviewList(list, countLabel);

        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const backBtn = footer.createEl('button', {text: '← Back', cls: 'wm-btn-secondary'});
        backBtn.addEventListener('click', () => this.renderIdle());
        const saveBtn = footer.createEl('button', {text: '⬇  Save selected', cls: 'wm-btn-primary'});
        saveBtn.addEventListener('click', () => this.startFetch());
    }

    renderPreviewList(container, countLabel) {
        container.empty();
        const filtered = this.getFilteredSortedItems();
        countLabel.setText(`${this.items.filter(x=>x.checked).length} selected · ${filtered.length} shown`);

        for (const item of filtered) {
            const idx = this.items.indexOf(item);
            const row = container.createDiv({cls: `wm-preview-row${item.checked?'':' wm-unchecked'}${item.watchlisted?' wm-watchlisted':''}`});

            const cb = row.createEl('input', {type:'checkbox'});
            cb.checked = item.checked;
            cb.addEventListener('change', () => {
                this.items[idx].checked = cb.checked;
                row.toggleClass('wm-unchecked', !cb.checked);
                countLabel.setText(`${this.items.filter(x=>x.checked).length} selected · ${filtered.length} shown`);
            });

            const info = row.createDiv({cls: 'wm-preview-info'});
            const titleRow = info.createDiv({cls:'wm-title-row'});
            if (item.watchlisted) titleRow.createSpan({text:'⭐', cls:'wm-watchlist-star'});
            const sevBadge = titleRow.createSpan({text: SEVERITY_ICON[item.severity], cls:`wm-sev-badge wm-sev-${item.severity}`});
            titleRow.createEl('a', {text: item.title, cls: 'wm-preview-title', href: item.url});

            const meta = info.createDiv({cls: 'wm-preview-meta'});
            meta.createSpan({text: item.source, cls: 'wm-badge-source'});
            meta.createSpan({text: item.date, cls: 'wm-meta-date'});
            for (const tag of item.tags.slice(0,4)) {
                const cls = TAG_SEVERITY_CLASS[tag] || 'wm-tag-pill';
                meta.createSpan({text: `#${tag}`, cls: `wm-tag-pill ${cls}`});
            }
        }
    }

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
        contentEl.createEl('h2', {text: '💾 Saving writeups...'});

        const progWrap = contentEl.createDiv({cls: 'wm-prog-wrap'});
        const progBar = progWrap.createDiv({cls: 'wm-prog-bar'});
        const progFill = progBar.createDiv({cls: 'wm-prog-fill'});
        const progLabel = progWrap.createSpan({text: `0 / ${selected.length}`, cls:'wm-prog-label'});
        const logEl = contentEl.createDiv({cls: 'wm-log'});

        const folder = plugin.settings.outputFolder || 'writeups';
        await plugin.ensureFolder(folder);
        const seen = [...(plugin.settings.seenUrls || [])];

        // Ensure stats object exists
        if (!plugin.settings.stats) plugin.settings.stats = {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};

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
                    logRow.querySelector('.wm-log-icon').setText('📄 ');
                }
            } else {
                logRow.querySelector('.wm-log-icon').setText('✅ ');
            }

            try {
                await plugin.saveWriteup(folder, {...item, body});
                seen.push(item.url);
                this.savedCount++;
                // Update stats
                const s = plugin.settings.stats;
                s.totalFetched++;
                s.bySource[item.source] = (s.bySource[item.source]||0) + 1;
                for (const tag of item.tags) s.byTag[tag] = (s.byTag[tag]||0) + 1;
                const month = item.date.slice(0,7);
                s.byMonth[month] = (s.byMonth[month]||0) + 1;
            } catch(e) {
                logRow.querySelector('.wm-log-icon').setText('❌ ');
                this.failedItems.push(item);
                plugin.settings.stats.totalFailed++;
            }
            if (i < selected.length - 1) await sleep(400);
        }

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
    constructor(app, plugin) { super(app); this.plugin = plugin; this.healthMap = new Map(); }

    onOpen() {
        this.modalEl.addClass('wm-sources-modal');
        this.modalEl.style.cssText = 'width:700px; max-width:95vw;';
        this.contentEl.style.cssText = 'padding:22px 26px 18px; max-height:82vh; overflow-y:auto;';
        this.render();
        this.checkHealth();
    }

    async checkHealth() {
        for (const src of this.plugin.settings.sources) {
            this.healthMap.set(src.id, 'checking');
            this.updateHealthDots();
            try {
                const resp = await obsidian.requestUrl({ url: src.feedUrl || src.url, method:'GET',
                    headers:{'User-Agent':'Mozilla/5.0 (Obsidian Plugin)'}, throw:false });
                this.healthMap.set(src.id, (resp && resp.status >= 200 && resp.status < 400) ? 'online' : 'offline');
            } catch(e) { this.healthMap.set(src.id, 'offline'); }
            this.updateHealthDots();
        }
    }

    updateHealthDots() {
        for (const [id, status] of this.healthMap) {
            const dot = this.contentEl.querySelector(`.wm-health-${id}`);
            if (dot) {
                dot.setText(status==='online'?'🟢':status==='offline'?'🔴':'⏳');
                dot.className = `wm-health wm-health-${id}${status==='checking'?' wm-health-pulse':''}`;
            }
        }
    }

    render() {
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '🔐 Security Writeups'});

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
            this.render(); this.checkHealth();
        });

        // Watchlist
        contentEl.createEl('h3', {text: 'Watchlist Keywords', cls: 'wm-section-title'});
        const watchRow = contentEl.createDiv({cls: 'wm-add'});
        const watchIn = watchRow.createEl('input', {type:'text', placeholder:'Add keyword (e.g. race condition)'});
        watchIn.style.flex = '1';
        const watchAddBtn = watchRow.createEl('button', {text:'+ Add', cls:'wm-btn-add'});
        watchAddBtn.addEventListener('click', async () => {
            const kw = watchIn.value.trim().toLowerCase();
            if (!kw) return;
            if (!plugin.settings.watchlistKeywords) plugin.settings.watchlistKeywords = [];
            if (plugin.settings.watchlistKeywords.includes(kw)) { new obsidian.Notice('Already exists'); return; }
            plugin.settings.watchlistKeywords.push(kw);
            await plugin.saveSettings();
            watchIn.value = '';
            this.render();
        });
        const watchList = contentEl.createDiv({cls:'wm-watchlist-tags'});
        for (const kw of (plugin.settings.watchlistKeywords||[])) {
            const pill = watchList.createSpan({cls:'wm-watchlist-pill'});
            pill.createSpan({text: `⭐ ${kw}`});
            const del = pill.createSpan({text:' ✕', cls:'wm-watchlist-del'});
            del.addEventListener('click', async () => {
                plugin.settings.watchlistKeywords = plugin.settings.watchlistKeywords.filter(k=>k!==kw);
                await plugin.saveSettings();
                this.render();
            });
        }

        // Footer
        const footer = contentEl.createDiv({cls: 'wm-footer'});
        const fetchBtn = footer.createEl('button', {text:'⬇  Fetch writeups', cls:'wm-btn-fetch'});
        fetchBtn.addEventListener('click', () => { this.close(); new FetchPreviewModal(this.app, plugin).open(); });

        const statsBtn = footer.createEl('button', {text:'📊 Stats', cls:'wm-btn-secondary'});
        statsBtn.addEventListener('click', () => { this.close(); new StatsModal(this.app, plugin).open(); });

        const exportBtn = footer.createEl('button', {text:'📤 Export', cls:'wm-btn-secondary'});
        exportBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(JSON.stringify(plugin.settings.sources, null, 2));
            new obsidian.Notice('✅ Sources copied to clipboard');
        });

        const importBtn = footer.createEl('button', {text:'📥 Import', cls:'wm-btn-secondary'});
        importBtn.addEventListener('click', () => this.showImport());

        const cacheBtn = footer.createEl('button', {text:`🗑 Cache (${(plugin.settings.seenUrls||[]).length})`, cls:'wm-btn-cache'});
        cacheBtn.addEventListener('click', async () => { plugin.settings.seenUrls=[]; await plugin.saveSettings(); new obsidian.Notice('Cache cleared'); this.render(); });

        if (plugin.settings.lastFetched) footer.createEl('p', {text:`Last fetched: ${plugin.settings.lastFetched}`, cls:'wm-meta'});
    }

    showImport() {
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '📥 Import Sources'});
        contentEl.createEl('p', {text:'Paste the exported JSON below:', cls:'wm-hint'});
        const ta = contentEl.createEl('textarea', {cls:'wm-import-textarea'});
        ta.style.cssText = 'width:100%;height:200px;font-family:monospace;font-size:12px;border-radius:8px;padding:10px;border:1px solid var(--background-modifier-border);background:var(--background-secondary);color:var(--text-normal);resize:vertical;';
        const footer = contentEl.createDiv({cls:'wm-footer'});
        const backBtn = footer.createEl('button', {text:'← Back', cls:'wm-btn-secondary'});
        backBtn.addEventListener('click', () => this.render());
        const doImport = footer.createEl('button', {text:'Import', cls:'wm-btn-primary'});
        doImport.addEventListener('click', async () => {
            try {
                const arr = JSON.parse(ta.value);
                if (!Array.isArray(arr)) throw new Error('Expected array');
                let added = 0;
                for (const s of arr) {
                    if (s.name && s.url && !plugin.settings.sources.find(x=>x.id===(s.id||slugify(s.name)))) {
                        plugin.settings.sources.push({...s, id:s.id||slugify(s.name), enabled:s.enabled!==false});
                        added++;
                    }
                }
                await plugin.saveSettings();
                new obsidian.Notice(`✅ Imported ${added} source${added!==1?'s':''}`);
                this.render(); this.checkHealth();
            } catch(e) { new obsidian.Notice('❌ Invalid JSON'); }
        });
    }

    renderSourceRow(container, src, i) {
        const {plugin} = this;
        const row = container.createDiv({cls:`wm-row${src.enabled?'':' wm-row-off'}`});

        const tog = row.createEl('input', {type:'checkbox'});
        tog.checked = src.enabled;
        tog.addEventListener('change', async () => { plugin.settings.sources[i].enabled=tog.checked; row.toggleClass('wm-row-off',!tog.checked); await plugin.saveSettings(); });

        const healthStatus = this.healthMap.get(src.id) || 'checking';
        row.createSpan({text: healthStatus==='online'?'🟢':healthStatus==='offline'?'🔴':'⏳',
            cls:`wm-health wm-health-${src.id}${healthStatus==='checking'?' wm-health-pulse':''}`});

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

// ─── Statistics Modal ─────────────────────────────────────────────────────────

class StatsModal extends obsidian.Modal {
    constructor(app, plugin) { super(app); this.plugin = plugin; }

    onOpen() {
        this.modalEl.addClass('wm-stats-modal');
        this.modalEl.style.cssText = 'width:600px; max-width:95vw;';
        this.contentEl.style.cssText = 'padding:22px 26px 18px; max-height:82vh; overflow-y:auto;';
        this.render();
    }

    render() {
        const {contentEl, plugin} = this;
        const s = plugin.settings.stats || {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '📊 Statistics Dashboard'});

        // Overview cards
        const overview = contentEl.createDiv({cls:'wm-stats-overview'});
        this.statCard(overview, '📥', 'Total Fetched', s.totalFetched);
        this.statCard(overview, '❌', 'Total Failed', s.totalFailed);
        this.statCard(overview, '📡', 'Sources', plugin.settings.sources.length);
        this.statCard(overview, '🔗', 'Cached URLs', (plugin.settings.seenUrls||[]).length);

        // By source
        if (Object.keys(s.bySource).length) {
            contentEl.createEl('h3', {text:'By Source', cls:'wm-section-title'});
            this.renderBarChart(contentEl, s.bySource);
        }
        // By tag (top 12)
        if (Object.keys(s.byTag).length) {
            contentEl.createEl('h3', {text:'Top Tags', cls:'wm-section-title'});
            const sorted = Object.entries(s.byTag).sort((a,b)=>b[1]-a[1]).slice(0,12);
            this.renderBarChart(contentEl, Object.fromEntries(sorted));
        }
        // By month
        if (Object.keys(s.byMonth).length) {
            contentEl.createEl('h3', {text:'By Month', cls:'wm-section-title'});
            const sorted = Object.entries(s.byMonth).sort((a,b)=>a[0].localeCompare(b[0]));
            this.renderBarChart(contentEl, Object.fromEntries(sorted));
        }

        const footer = contentEl.createDiv({cls:'wm-footer'});
        const closeBtn = footer.createEl('button', {text:'Close', cls:'wm-btn-secondary'});
        closeBtn.addEventListener('click', () => this.close());
        const resetBtn = footer.createEl('button', {text:'🗑 Reset Stats', cls:'wm-btn-cache'});
        resetBtn.addEventListener('click', async () => {
            plugin.settings.stats = {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};
            await plugin.saveSettings();
            new obsidian.Notice('Stats reset');
            this.render();
        });
    }

    statCard(container, icon, label, value) {
        const card = container.createDiv({cls:'wm-stat-card'});
        card.createSpan({text:icon, cls:'wm-stat-icon'});
        card.createDiv({cls:'wm-stat-body'}).innerHTML = `<span class="wm-stat-value">${value}</span><span class="wm-stat-label">${label}</span>`;
    }

    renderBarChart(container, data) {
        const max = Math.max(...Object.values(data), 1);
        const chart = container.createDiv({cls:'wm-bar-chart'});
        for (const [label, val] of Object.entries(data)) {
            const row = chart.createDiv({cls:'wm-chart-row'});
            row.createSpan({text:label, cls:'wm-chart-label'});
            const barWrap = row.createDiv({cls:'wm-chart-bar-wrap'});
            const bar = barWrap.createDiv({cls:'wm-chart-bar'});
            bar.style.width = `${Math.round((val/max)*100)}%`;
            row.createSpan({text:String(val), cls:'wm-chart-val'});
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
        new obsidian.Setting(containerEl).setName('Statistics').setDesc('View fetch statistics and analytics').addButton(b=>b.setButtonText('View').onClick(()=>new StatsModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Watchlist Keywords').setDesc('Comma-separated keywords to highlight in scan results')
            .addText(t => {
                t.setPlaceholder('rce, zero-day, critical');
                t.setValue((this.plugin.settings.watchlistKeywords||[]).join(', '));
                t.onChange(async v => {
                    this.plugin.settings.watchlistKeywords = v.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
                    await this.plugin.saveSettings();
                });
            });
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
        this.addCommand({id:'open-stats',    name:'View Statistics', callback:()=>new StatsModal(this.app,this).open()});

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
        const filename = safeFilename(item.title);
        const sub = `${folder}/${slugify(item.source)}`;
        await this.ensureFolder(sub);
        let path = `${sub}/${filename}.md`;
        if (this.app.vault.getFileByPath(path)) {
            path = `${sub}/${filename} (${shortHash(item.url)}).md`;
        }
        if (this.app.vault.getFileByPath(path)) return;
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
        c += `---\n## 🏷️ Tags\n\n${ALL_TAGS.map(t=>`\`#${t}\``).join(' ')}\n`;
        const idx = this.app.vault.getFileByPath(`${folder}/index.md`);
        if (idx) await this.app.vault.modify(idx,c); else await this.app.vault.create(`${folder}/index.md`,c);
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        if (!this.settings.seenUrls) this.settings.seenUrls = [];
        if (!this.settings.failedUrls) this.settings.failedUrls = [];
        if (!this.settings.watchlistKeywords) this.settings.watchlistKeywords = DEFAULT_SETTINGS.watchlistKeywords;
        if (!this.settings.stats) this.settings.stats = {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};
    }
    async saveSettings() { await this.saveData(this.settings); }
}

module.exports = WriteupsFetcherPlugin;
