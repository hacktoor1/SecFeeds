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
    topicSyncHistory: {},
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
    topicSources: [
        { id:'medium-idor',  name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'idor', topics:['idor'], category:'Web/IDOR',  syncFrequency:'daily', autoSync:true, enabled:true },
        { id:'medium-xss',   name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'xss', topics:['xss'], category:'Web/XSS', syncFrequency:'daily', autoSync:true, enabled:true },
        { id:'medium-ssrf',  name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'ssrf', topics:['ssrf'], category:'Web/SSRF', syncFrequency:'daily', autoSync:true, enabled:true },
        { id:'medium-sqli',  name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'sqli', topics:['sqli'], category:'Web/SQLi', syncFrequency:'daily', autoSync:true, enabled:true },
        { id:'medium-rce',   name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'rce', topics:['rce'], category:'Web/RCE', syncFrequency:'daily', autoSync:true, enabled:true },
        { id:'medium-bug-bounty', name:'Medium', type:'search_source', baseUrl:'https://medium.com/search?q=', topic:'bug bounty writeup', topics:['bug bounty writeup'], category:'Bug-Bounty', syncFrequency:'weekly', autoSync:true, enabled:true },
    ],
    topicFolderMap: {
        'idor': 'Web/IDOR', 'xss': 'Web/XSS', 'ssrf': 'Web/SSRF',
        'sqli': 'Web/SQLi', 'rce': 'Web/RCE', 'csrf': 'Web/CSRF',
        'xxe': 'Web/XXE', 'lfi': 'Web/LFI', 'ssti': 'Web/SSTI',
        'deserialization': 'Web/Deserialization', 'race-condition': 'Web/Race-Condition',
        'auth': 'Web/Auth', 'ato': 'Web/ATO', 'privesc': 'Web/Privesc',
        'open-redirect': 'Web/Open-Redirect', 'api-security': 'Web/API',
        'graphql': 'Web/GraphQL', 'mobile': 'Mobile',
        'bug bounty writeup': 'Bug-Bounty', 'bug-bounty': 'Bug-Bounty',
        'ctf': 'CTF', 'htb': 'CTF/HTB', 'cve': 'CVE',
    },
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
        .replace(/[\\/:*?"<>|#^\[\]]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 100);
}

function debounce(fn, ms) {
    let timer; return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

function yamlSafe(s) {
    if (!s) return '';
    return String(s).replace(/\\/g, '\\\\').replace(/"/g, "'").replace(/\n/g, ' ').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
}

function sanitizeHref(href) {
    if (!href) return '';
    const lower = href.trim().toLowerCase();
    if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/html')) return '';
    return href;
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

function uniqueValues(items) {
    return [...new Set((items || []).filter(Boolean))];
}

function titleCase(text) {
    return String(text || '')
        .split(/[\s/_-]+/)
        .filter(Boolean)
        .map(part => /^[a-z0-9]{2,5}$/i.test(part) ? part.toUpperCase() : part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
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
        '.subscribe','[class*="banner"]','[class*="popup"]','[id*="sidebar"]','noscript','iframe',
        '.author-bio','[class*="author-bio"]','[class*="related"]','[class*="recommend"]',
        '[class*="share"]','[class*="social"]','[class*="comment"]','[class*="footer"]',
        '[aria-label*="share"]','[aria-label*="recommend"]']) {
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
                const href = sanitizeHref(node.getAttribute('href') || '');
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
        '[class*="recommend"]','[class*="social"]','[class*="comment"]','[class*="author-bio"]',
        '[class*="bio"]','[class*="footer"]','[id*="sidebar"]','noscript','aside']) {
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
        let link = '';
        // For Atom feeds, prefer rel="alternate"; for RSS, use textContent
        const altLink = node.querySelector('link[rel="alternate"]');
        if (altLink) {
            link = altLink.getAttribute('href') || '';
        } else {
            const firstLink = node.querySelector('link');
            link = firstLink?.textContent?.trim() || firstLink?.getAttribute('href') || '';
        }
        const pubDate = node.querySelector('pubDate, published, updated')?.textContent?.trim() || '';
        let desc = '';
        const descEl = node.querySelector('description');
        if (descEl) desc = descEl.textContent?.trim() || '';
        if (!desc) { try { desc = node.getElementsByTagName('content:encoded')[0]?.textContent?.trim() || ''; } catch(e) {} }
        if (!desc) desc = node.querySelector('content')?.textContent?.trim() || '';
        let author = '';
        try { author = node.getElementsByTagName('dc:creator')[0]?.textContent?.trim() || ''; } catch(e) {}
        if (!author) author = node.querySelector('creator, author name')?.textContent?.trim() || '';
        const cats = [...node.querySelectorAll('category')].map(c=>c.textContent?.trim()).filter(Boolean);
        if (title && link) items.push({title, link, pubDate, desc, author, cats});
    }
    return items;
}

// ─── Medium Fallback Service ──────────────────────────────────────────────────

const FREEDIUM_MIRROR = 'https://freedium-mirror.cfd/';

const MEDIUM_HOSTS = ['medium.com', 'betterprogramming.pub', 'towardsdatascience.com',
    'infosecwriteups.com', 'blog.devgenius.io', 'levelup.gitconnected.com',
    'javascript.plainenglish.io', 'python.plainenglish.io', 'aws.plainenglish.io',
    'systemweakness.com', 'osintteam.blog', 'faun.pub'];

const PAYWALL_MARKERS = [
    'Member-only story', 'member-only story',
    'metered-content', 'meteredContent',
    'Your membership supports', 'Become a member',
    'Sign in to read', 'Open in app',
    'lo-highlight-meter-1-', 'paywall',
    'locked-content', 'premium-lock',
];

const MEDIUM_BLOCKED_SELECTORS = [
    '[data-testid="loginWall"]',
    '.meteredContent',
    '[class*="paywall"]',
    '[class*="premium"]',
    '[class*="memberOnly"]',
    '[class*="locked"]',
    'form[action*="login"]',
];

const ERROR_PAGE_MARKERS = [
    'page not found',
    'this page is no longer available',
    'this story is unavailable',
    'something went wrong',
    'access denied',
    'just a moment',
    'captcha',
    'temporarily unavailable',
];

const MEDIUM_VALIDATION_RULES = {
    minHtmlLength: 200,
    minArticleTextLength: 500,
    minMarkdownLength: 300,
    minStructuredBlocks: 2,
};

class MediumFallbackService {
    detectMediumUrl(url) {
        if (!url) return false;
        try {
            const hostname = new URL(url).hostname.toLowerCase();
            if (hostname === 'medium.com' || hostname.endsWith('.medium.com')) return true;
            if (MEDIUM_HOSTS.some(h => hostname === h || hostname.endsWith('.' + h))) return true;
            return url.includes('medium.com/');
        } catch(e) {
            return false;
        }
    }

    isPremiumBlocked(html) {
        if (!html || html.length < MEDIUM_VALIDATION_RULES.minHtmlLength) return true;
        const lower = html.toLowerCase();

        for (const marker of PAYWALL_MARKERS) {
            if (lower.includes(marker.toLowerCase())) return true;
        }

        const doc = new DOMParser().parseFromString(html, 'text/html');
        if (doc.querySelector(MEDIUM_BLOCKED_SELECTORS.join(', '))) return true;

        const article = this.selectArticleNode(doc, 'article, [role="main"], .postArticle-content, .section-content, main');
        const articleText = article?.textContent?.trim() || '';
        const bodyText = doc.body?.textContent?.trim() || '';

        if (article && articleText.length < MEDIUM_VALIDATION_RULES.minArticleTextLength) return true;
        if (!article && bodyText.length < 300) return true;

        return false;
    }

    buildFreediumUrl(originalUrl) {
        return FREEDIUM_MIRROR + originalUrl;
    }

    extractTitle(doc) {
        return doc.querySelector('meta[property="og:title"]')?.getAttribute('content')?.trim()
            || doc.querySelector('meta[name="twitter:title"]')?.getAttribute('content')?.trim()
            || doc.querySelector('h1')?.textContent?.trim()
            || doc.querySelector('title')?.textContent?.trim()
            || '';
    }

    selectArticleNode(doc, articleSelector) {
        const selectors = [
            ...(articleSelector || '').split(',').map(s => s.trim()).filter(Boolean),
            'article',
            '[role="main"]',
            '.postArticle-content',
            'section[data-field="body"]',
            '.story-body',
            '.entry-content',
            '.post-content',
            'main',
        ];

        for (const sel of selectors) {
            try {
                const node = doc.querySelector(sel);
                if (node && (node.textContent?.trim().length || 0) >= 100) return node;
            } catch(e) {}
        }

        return doc.body || null;
    }

    validateContent(html, articleSelector) {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const title = this.extractTitle(doc);
        const article = this.selectArticleNode(doc, articleSelector);
        const markdown = extractArticleFromHtml(html, articleSelector);
        const articleText = article?.textContent?.trim() || '';
        const lowerSignals = `${title}\n${articleText}`.toLowerCase();
        const paragraphCount = article?.querySelectorAll('p').length || 0;
        const headingCount = article?.querySelectorAll('h1, h2, h3, h4').length || 0;
        const structuredBlocks = article?.querySelectorAll('p, pre, code, li, blockquote, h2, h3, h4').length || 0;
        const reasons = [];

        if (!title) reasons.push('missing-title');
        if (!markdown || markdown.trim().length < MEDIUM_VALIDATION_RULES.minMarkdownLength) reasons.push('content-too-short');
        if (!articleText || articleText.length < MEDIUM_VALIDATION_RULES.minArticleTextLength) reasons.push('article-body-too-short');
        if (structuredBlocks < MEDIUM_VALIDATION_RULES.minStructuredBlocks && paragraphCount + headingCount === 0) {
            reasons.push('insufficient-structure');
        }
        if (ERROR_PAGE_MARKERS.some(marker => lowerSignals.includes(marker))) reasons.push('error-page');
        if (this.isPremiumBlocked(html)) reasons.push('premium-or-blocked');

        return {
            valid: reasons.length === 0,
            content: markdown,
            title,
            reasons,
            stats: {
                articleTextLength: articleText.length,
                markdownLength: markdown.trim().length,
                paragraphCount,
                headingCount,
                structuredBlocks,
            },
        };
    }

    logValidationFailure(sourceLabel, url, validation) {
        const details = [
            `reasons=${validation.reasons.join(',') || 'unknown'}`,
            `articleText=${validation.stats.articleTextLength}`,
            `markdown=${validation.stats.markdownLength}`,
            `paragraphs=${validation.stats.paragraphCount}`,
            `headings=${validation.stats.headingCount}`,
        ].join(' ');
        console.warn(`SecFeeds: Medium ${sourceLabel} validation failed for ${url} ${details}`);
    }

    async request(url) {
        return obsidian.requestUrl({
            url,
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            throw: false,
            timeout: REQUEST_TIMEOUT,
        });
    }

    async trySource(url, articleSelector, sourceLabel) {
        try {
            const resp = await this.request(url);
            if (!resp || resp.status < 200 || resp.status >= 300 || !resp.text) {
                const status = resp?.status || 'request-failed';
                console.warn(`SecFeeds: Medium ${sourceLabel} request failed for ${url} status=${status}`);
                return { ok: false, reasons: [`http-${status}`], fetchedFrom: url };
            }

            const validation = this.validateContent(resp.text, articleSelector);
            if (!validation.valid) {
                this.logValidationFailure(sourceLabel, url, validation);
                return {
                    ok: false,
                    reasons: validation.reasons,
                    fetchedFrom: url,
                    content: validation.content,
                };
            }

            return {
                ok: true,
                content: validation.content,
                fetchedFrom: url,
                reasons: [],
            };
        } catch(e) {
            console.error(`SecFeeds: Medium ${sourceLabel} fetch crashed for ${url}:`, e?.message || e);
            return { ok: false, reasons: ['request-exception'], fetchedFrom: url };
        }
    }

    async fetchWithFallback(url, articleSelector) {
        const original = await this.trySource(url, articleSelector, 'original');
        if (original.ok) {
            return {
                content: original.content,
                originalUrl: url,
                fetchedFrom: url,
                fallbackUsed: false,
                fetchStatus: 'original',
                failureReason: '',
            };
        }

        console.log('SecFeeds: Medium original was blocked or incomplete, trying Freedium:', url);
        const mirrorUrl = this.buildFreediumUrl(url);
        const mirror = await this.trySource(mirrorUrl, articleSelector, 'mirror');
        if (mirror.ok) {
            return {
                content: mirror.content,
                originalUrl: url,
                fetchedFrom: mirrorUrl,
                fallbackUsed: true,
                fetchStatus: 'freedium-mirror',
                failureReason: '',
            };
        }

        const combinedReasons = [...new Set([...(original.reasons || []), ...(mirror.reasons || [])])];
        console.error(`SecFeeds: Medium fetch failed for ${url} reasons=${combinedReasons.join(',') || 'unknown'}`);
        return {
            content: null,
            originalUrl: url,
            fetchedFrom: url,
            fallbackUsed: false,
            fetchStatus: 'failed',
            failureReason: combinedReasons.join(', '),
        };
    }
}

const mediumFallbackService = new MediumFallbackService();

function detectMediumUrl(url) {
    return mediumFallbackService.detectMediumUrl(url);
}

function isPremiumBlocked(html) {
    return mediumFallbackService.isPremiumBlocked(html);
}

function buildFreediumUrl(originalUrl) {
    return mediumFallbackService.buildFreediumUrl(originalUrl);
}

async function fetchWithMediumFallback(url, articleSelector) {
    return mediumFallbackService.fetchWithFallback(url, articleSelector);
}

// ─── Article Fetcher (uses Obsidian requestUrl to bypass CORS) ────────────────

const REQUEST_TIMEOUT = 15000;

async function fetchArticleContent(url, articleSelector) {
    // Route Medium URLs through fallback service
    if (detectMediumUrl(url)) {
        const result = await fetchWithMediumFallback(url, articleSelector);
        return {
            content: result.content,
            originalUrl: result.originalUrl,
            fetchedFrom: result.fetchedFrom,
            fallbackUsed: result.fallbackUsed,
            fetchStatus: result.fetchStatus,
            failureReason: result.failureReason,
        };
    }

    // Normal fetch for non-Medium URLs
    try {
        const resp = await obsidian.requestUrl({
            url,
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            throw: false,
            timeout: REQUEST_TIMEOUT,
        });
        if (!resp || resp.status < 200 || resp.status >= 300) {
            return {
                content: null,
                originalUrl: url,
                fetchedFrom: url,
                fallbackUsed: false,
                fetchStatus: 'failed',
                failureReason: `http-${resp?.status || 'request-failed'}`,
            };
        }
        return {
            content: extractArticleFromHtml(resp.text, articleSelector),
            originalUrl: url,
            fetchedFrom: url,
            fallbackUsed: false,
            fetchStatus: 'original',
            failureReason: '',
        };
    } catch(e) {
        console.error('SecFeeds: fetchArticle failed:', url, e?.message || e);
        return {
            content: null,
            originalUrl: url,
            fetchedFrom: url,
            fallbackUsed: false,
            fetchStatus: 'failed',
            failureReason: 'request-exception',
        };
    }
}

async function fetchFeedItems(src) {
    const feedPaths = ['/feed', '/feed.xml', '/rss', '/rss.xml', '/atom.xml', '/index.xml'];
    const base = src.feedUrl || src.url;
    // If feedUrl is explicitly set, try it first (and only use fallbacks if it fails)
    const attempts = src.feedUrl
        ? [src.feedUrl, ...feedPaths.map(p => src.url.replace(/\/$/,'') + p)]
        : [base, ...feedPaths.map(p => src.url.replace(/\/$/,'') + p)];

    for (const url of attempts) {
        try {
            const resp = await obsidian.requestUrl({
                url,
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (Obsidian Plugin)' },
                throw: false,
                timeout: REQUEST_TIMEOUT,
            });
            if (!resp || resp.status < 200 || resp.status >= 300) continue;
            const text = resp.text;
            if (!text.includes('<item') && !text.includes('<entry')) continue;
            const items = parseRSS(text);
            if (items.length > 0) return items;
        } catch(e) { console.error('SecFeeds: feed fetch failed:', url, e?.message || e); }
    }
    return [];
}

// ─── Topic Source Engine ──────────────────────────────────────────────────────

const TOPIC_SYNC_INTERVALS = {
    startup: 0,
    hourly: 60 * 60 * 1000,
    daily: 24 * 60 * 60 * 1000,
    weekly: 7 * 24 * 60 * 60 * 1000,
    manual: Infinity,
};

function normalizeTopicList(source) {
    if (Array.isArray(source?.topics) && source.topics.length) {
        return uniqueValues(source.topics.map(t => String(t || '').trim().toLowerCase()).filter(Boolean));
    }
    const raw = String(source?.topic || '')
        .split(/[,\n]/)
        .map(t => t.trim().toLowerCase())
        .filter(Boolean);
    return uniqueValues(raw);
}

function normalizeTopicSource(source) {
    const topics = normalizeTopicList(source);
    return Object.assign({}, source, {
        topic: source?.topic || topics[0] || '',
        topics,
        category: String(source?.category || '').trim(),
        type: source?.type || 'search_source',
        syncFrequency: source?.syncFrequency || 'daily',
        autoSync: source?.autoSync !== false,
        enabled: source?.enabled !== false,
    });
}

function defaultArticleSelectorForTopicSource(source) {
    try {
        const host = new URL(source.baseUrl || '').hostname.toLowerCase();
        if (detectMediumUrl(source.baseUrl)) return 'article, .postArticle-content, .post-content, section[data-field="body"], main';
        if (host.includes('github.com')) return '.markdown-body, article, main, .Box-sc-g0xbh4-0';
    } catch(e) {}
    return 'article, .post-content, .entry-content, .markdown-body, .prose, main';
}

function buildTopicUrl(source, topicOverride) {
    const topic = String(topicOverride || source.topic || '').trim();
    return `${source.baseUrl}${encodeURIComponent(topic)}`;
}

function formatTopicFolderSegment(topic) {
    return /^[a-z0-9-]{2,5}$/i.test(topic) ? topic.toUpperCase() : titleCase(topic).replace(/\s+/g, '-');
}

function getTopicFolder(topic, folderMap, outputFolder, categoryOverride) {
    const rawCategory = String(categoryOverride || '').trim();
    if (rawCategory) {
        const category = rawCategory.replace(/\{topic\}/gi, formatTopicFolderSegment(topic)).replace(/^\/+|\/+$/g, '');
        if (category.toLowerCase().startsWith(`${outputFolder.toLowerCase()}/`)) return category;
        return `${outputFolder}/${category}`;
    }
    const key = topic.toLowerCase().trim();
    const mapped = folderMap[key];
    if (mapped) return `${outputFolder}/${mapped}`;
    if (key.startsWith('cve-') && folderMap.cve) return `${outputFolder}/${folderMap.cve}`;
    if (key.startsWith('bug-bounty') && folderMap['bug-bounty']) return `${outputFolder}/${folderMap['bug-bounty']}`;
    if (key.includes('bug bounty') && folderMap['bug bounty writeup']) return `${outputFolder}/${folderMap['bug bounty writeup']}`;
    return `${outputFolder}/Unsorted/${slugify(key)}`;
}

function getTopicSyncKey(sourceId, topic) {
    return `${sourceId}::${slugify(topic)}`;
}

function shouldSyncTopicSource(topicSource, topic, syncHistory, respectSchedule) {
    if (!respectSchedule) return true;
    if (topicSource.autoSync === false) return false;
    const intervalMs = TOPIC_SYNC_INTERVALS[topicSource.syncFrequency] ?? 0;
    if (!Number.isFinite(intervalMs)) return false;
    const lastSynced = syncHistory?.[getTopicSyncKey(topicSource.id, topic)];
    if (!lastSynced) return true;
    if (intervalMs === 0) return true;
    const lastTs = new Date(lastSynced).getTime();
    if (!Number.isFinite(lastTs)) return true;
    return (Date.now() - lastTs) >= intervalMs;
}

function markTopicSourceSynced(topicSource, topic, syncHistory) {
    if (!syncHistory) return;
    syncHistory[getTopicSyncKey(topicSource.id, topic)] = new Date().toISOString();
}

function extractLinksFromSearchPage(html, baseHostname) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const links = new Set();

    // Medium-specific: article links from search results
    if (baseHostname.includes('medium.com') || MEDIUM_HOSTS.some(h => baseHostname.includes(h))) {
        // Medium search results have links to articles with long path slugs
        const allAnchors = doc.querySelectorAll('a[href]');
        for (const a of allAnchors) {
            const href = sanitizeHref(a.getAttribute('href') || '');
            // Medium article URLs contain a hex hash at the end (e.g. -a1b2c3d4e5f6)
            if (href.match(/\/@[^/]+\/[^/]+-[a-f0-9]{8,}/) ||
                href.match(/\/[^/]+-[a-f0-9]{8,}(\?|$)/) ||
                (href.includes('medium.com/') && href.split('/').length >= 5)) {
                try {
                    const fullUrl = href.startsWith('http') ? href : `https://${baseHostname}${href}`;
                    // Filter out non-article pages
                    if (!fullUrl.includes('/search?') && !fullUrl.includes('/tag/') &&
                        !fullUrl.includes('/about') && !fullUrl.includes('/archive') &&
                        !fullUrl.endsWith('/followers') && !fullUrl.endsWith('/following')) {
                        links.add(fullUrl.split('?')[0]); // Remove query params for dedup
                    }
                } catch(e) {}
            }
        }
    }

    // GitHub-specific: repo/file links from search results
    if (baseHostname.includes('github.com')) {
        for (const a of doc.querySelectorAll('a[href*="/blob/"], a[href*="/tree/"]')) {
            const href = sanitizeHref(a.getAttribute('href') || '');
            if (href.startsWith('/')) links.add(`https://github.com${href}`);
            else if (href.startsWith('http')) links.add(href);
        }
    }

    // Generic fallback: grab all http links that look like articles
    if (links.size === 0) {
        for (const a of doc.querySelectorAll('a[href^="http"]')) {
            const href = sanitizeHref(a.getAttribute('href') || '');
            if (!href) continue;
            // Skip navigation, auth, and social links
            if (href.includes('/login') || href.includes('/signup') || href.includes('/register') ||
                href.includes('twitter.com') || href.includes('facebook.com') ||
                href.includes('/tag/') || href.includes('/search'))  continue;
            try {
                const path = new URL(href).pathname;
                if (path.split('/').filter(Boolean).length >= 2) {
                    links.add(href.split('?')[0]);
                }
            } catch(e) {}
        }
    }

    return [...links];
}

async function fetchTopicResults(topicSourceInput, seenUrls, folderMap, outputFolder, options = {}) {
    const topicSource = normalizeTopicSource(topicSourceInput);
    const results = [];
    const topics = normalizeTopicList(topicSource);
    const respectSchedule = options.respectSchedule === true;

    for (const topic of topics) {
        if (!shouldSyncTopicSource(topicSource, topic, options.syncHistory, respectSchedule)) continue;
        const url = buildTopicUrl(topicSource, topic);

        try {
            const resp = await obsidian.requestUrl({
                url, method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
                throw: false, timeout: REQUEST_TIMEOUT,
            });
            if (!resp || resp.status < 200 || resp.status >= 300) {
                console.error('SecFeeds: topic fetch failed:', url, resp?.status);
                continue;
            }

            const hostname = new URL(url).hostname;
            const articleLinks = extractLinksFromSearchPage(resp.text, hostname);
            const doc = new DOMParser().parseFromString(resp.text, 'text/html');

            for (const link of articleLinks) {
                if (seenUrls.has(link) || results.some(item => item.url === link)) continue;

                let title = '';
                const safeLink = link.replace(/"/g, '\\"');
                const matchingAnchor = doc.querySelector(`a[href="${safeLink}"], a[href="${safeLink.replace('https://', '').replace('http://', '')}"]`);
                if (matchingAnchor) {
                    title = matchingAnchor.textContent?.trim() || '';
                }
                if (!title || title.length < 5) {
                    const slug = link.split('/').pop() || '';
                    title = slug.replace(/-[a-f0-9]{8,}$/, '').replace(/[-_]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                }
                if (!title || title.length < 3) continue;

                const tags = uniqueValues([...extractTags(title, [topic]), slugify(topicSource.name), slugify(topic)]);
                const folder = getTopicFolder(topic, folderMap, outputFolder, topicSource.category);

                results.push({
                    title,
                    url: link,
                    source: topicSource.name,
                    sourceId: topicSource.id,
                    sourceType: topicSource.type,
                    topic,
                    category: topicSource.category || '',
                    syncFrequency: topicSource.syncFrequency,
                    articleSelector: defaultArticleSelectorForTopicSource(topicSource),
                    date: parseDateString(new Date().toISOString()),
                    tags,
                    author: '',
                    rssBody: '',
                    checked: true,
                    status: 'pending',
                    watchlisted: false,
                    severity: detectSeverity(title, tags),
                    topicFolder: folder,
                });
            }

            markTopicSourceSynced(topicSource, topic, options.syncHistory);
        } catch(e) {
            console.error('SecFeeds: topic source error:', topicSource.name, e?.message || e);
        }
    }

    return results;
}

// ─── Content Processing Pipeline ──────────────────────────────────────────────

const NOISE_SECTION_RE = /^(about the author|author bio|bio|newsletter|recommended|related posts?|read more|more from|share this|follow me|comments?|discussion|support my work|sponsored|advertisement|you may also like|recommended articles?)$/i;
const NOISE_BLOCK_RE = /(subscribe|newsletter|follow me|share this|recommended (for you|articles)|read more|leave a comment|sign up|open in app|member-only story|advertisement|sponsor|cookie policy|privacy policy)/i;

const VULN_PROFILES = {
    idor: {
        label: 'IDOR',
        cwe: 'CWE-639',
        owasp: 'Broken Access Control',
        objective: 'Verify whether direct object references are properly authorized.',
        steps: [
            'Login with a low-privilege user.',
            'Intercept a request that references an object identifier.',
            'Modify the identifier to another predictable value.',
            'Replay the request and inspect the response.',
            'Confirm whether data or actions from another account become accessible.',
        ],
        payloadLang: 'http',
        payload: 'GET /api/user?id=2\nAuthorization: Bearer TOKEN',
        vulnerable: 'Application returns another user\'s data or allows unauthorized actions.',
        secure: 'Application enforces object-level authorization and returns 403 or an equivalent denial.',
        attackFlow: 'Enumerate object IDs -> tamper with the target identifier -> replay request -> receive unauthorized resource access.',
        arType: 'ثغرة IDOR أو broken access control على مستوى الـ object',
        arExploit: 'الاستغلال بيحصل لما المهاجم يغيّر الـ ID أو الـ reference في الطلب والسيرفر مايراجعش صلاحياته على نفس الـ object.',
        arPayload: 'فكرة الـ payload غالبًا بتكون تعديل رقم أو identifier في request موجود بالفعل بدل ما نخلق request جديد من الصفر.',
        arLearning: 'الـ authorization لازم يتراجع على السيرفر لكل object بشكل صريح، مش مجرد الاعتماد على إن الـ user سجل دخول.',
    },
    xss: {
        label: 'XSS',
        cwe: 'CWE-79',
        owasp: 'Injection',
        objective: 'Verify whether untrusted input is safely encoded before rendering in the browser.',
        steps: [
            'Find an input or reflection point that reaches HTML or JavaScript context.',
            'Inject a harmless probe payload and submit it.',
            'Reload the vulnerable page or trigger the render path.',
            'Inspect whether the payload executes in the victim context.',
            'Check whether session data, DOM access, or privileged actions become possible.',
        ],
        payloadLang: 'html',
        payload: '<script>alert(document.domain)</script>',
        vulnerable: 'User-controlled input executes as JavaScript in the browser.',
        secure: 'Application outputs the value as plain text with proper contextual encoding or sanitization.',
        attackFlow: 'Inject script payload -> render unsanitized input -> execute in victim browser -> steal data or perform actions.',
        arType: 'ثغرة XSS',
        arExploit: 'الاستغلال بيحصل لما التطبيق يعرض input جاي من اليوزر جوه الصفحة من غير encoding أو sanitization مناسب.',
        arPayload: 'الفكرة الأساسية هي حقن JavaScript أو HTML صغير يثبت إن الـ browser نفّذ المحتوى بدل ما يعرضه كنص عادي.',
        arLearning: 'لازم الـ output encoding يبقى حسب الـ context، ومعاه sanitization وسياسات زي CSP لو السيناريو محتاج.',
    },
    ssrf: {
        label: 'SSRF',
        cwe: 'CWE-918',
        owasp: 'Server-Side Request Forgery',
        objective: 'Verify whether the server can be tricked into making unintended outbound requests.',
        steps: [
            'Locate functionality that accepts a URL, webhook, import target, or remote resource.',
            'Supply a benign external URL first to confirm outbound requests.',
            'Replace it with an internal or metadata endpoint.',
            'Observe response differences, timing, or fetched content.',
            'Confirm whether internal services or cloud metadata become reachable.',
        ],
        payloadLang: 'text',
        payload: 'http://169.254.169.254/latest/meta-data/',
        vulnerable: 'Server retrieves internal resources or metadata that should not be reachable by the user.',
        secure: 'Application blocks internal destinations and only allows approved outbound targets.',
        attackFlow: 'Control server-side URL -> redirect request to internal service -> read sensitive response or pivot deeper.',
        arType: 'ثغرة SSRF',
        arExploit: 'الاستغلال بيتم لما التطبيق يجيب URL نيابة عن اليوزر من غير فلترة حقيقية للـ destination.',
        arPayload: 'أشهر فكرة payload هنا هي توجيه السيرفر على internal service أو cloud metadata بدل URL خارجي عادي.',
        arLearning: 'لازم يبقى فيه allowlist وفصل للشبكات ومنع الوصول لـ localhost والـ metadata endpoints.',
    },
    sqli: {
        label: 'SQL Injection',
        cwe: 'CWE-89',
        owasp: 'Injection',
        objective: 'Verify whether database queries are safely parameterized.',
        steps: [
            'Identify parameters that influence database-backed responses.',
            'Send a quote or boolean probe to detect query manipulation.',
            'Escalate with time-based or union-based techniques where safe.',
            'Observe response changes, errors, or timing differences.',
            'Confirm whether data extraction or authentication bypass is possible.',
        ],
        payloadLang: 'sql',
        payload: "' OR 1=1--",
        vulnerable: 'Application behavior changes because attacker-controlled input alters the SQL query.',
        secure: 'Input is handled through parameterized queries and the payload is treated as data only.',
        attackFlow: 'Inject SQL syntax into input -> backend concatenates it into query -> database executes attacker logic -> data exposure or auth bypass.',
        arType: 'ثغرة SQL Injection',
        arExploit: 'الاستغلال بيحصل لما input اليوزر يدخل جوه query بشكل مباشر من غير parameterization أو escaping سليم.',
        arPayload: 'فكرة الـ payload بتكون تجربة boolean أو quote صغير يبين هل الـ query اتكسرت أو اتعدلت.',
        arLearning: 'الحل الأساسي هو prepared statements ومراجعة كل الأماكن اللي فيها dynamic queries.',
    },
    rce: {
        label: 'Remote Code Execution',
        cwe: 'CWE-78',
        owasp: 'Injection',
        objective: 'Verify whether user input can reach OS commands, templates, or execution sinks.',
        steps: [
            'Map all features that execute commands, jobs, interpreters, or uploaded content.',
            'Inject a harmless probe such as a sleep or echo payload.',
            'Observe execution side effects or timing delays.',
            'Check whether the payload runs with elevated server privileges.',
            'Assess command execution boundaries, environment access, and persistence opportunities.',
        ],
        payloadLang: 'bash',
        payload: 'sleep 5',
        vulnerable: 'Attacker input reaches an execution sink and arbitrary commands or code run on the server.',
        secure: 'Input is strictly validated or never reaches a code execution path.',
        attackFlow: 'Reach execution sink -> supply controlled command or code -> obtain server-side execution -> escalate impact.',
        arType: 'ثغرة RCE',
        arExploit: 'السيناريو هنا بيوصل input اليوزر لمكان بينفذ أوامر أو كود على السيرفر.',
        arPayload: 'البدايات الآمنة عادة بتكون payload بسيط يثبت التنفيذ زي delay أو echo قبل أي خطوة أعنف.',
        arLearning: 'أي execution sink لازم يتقفل أو يتحط وراه validation قوي وعزل للبيئة والصلاحيات.',
    },
    deserialization: {
        label: 'Insecure Deserialization',
        cwe: 'CWE-502',
        owasp: 'Software and Data Integrity Failures',
        objective: 'Verify whether serialized user-controlled data can trigger dangerous gadget chains.',
        steps: [
            'Locate cookies, tokens, or parameters carrying serialized objects.',
            'Identify format and whether integrity checks exist.',
            'Modify the serialized object with a harmless gadget or property change.',
            'Replay the request and monitor server behavior.',
            'Confirm whether gadget execution or unsafe object reconstruction is possible.',
        ],
        payloadLang: 'text',
        payload: 'serialized-object-with-controlled-gadget-chain',
        vulnerable: 'Server deserializes attacker-controlled data and triggers unsafe object behavior.',
        secure: 'Serialized data is signed, validated, or replaced with safe data formats and allowlisted types.',
        attackFlow: 'Control serialized blob -> pass tampered object to deserializer -> trigger gadget chain or unsafe state -> gain code execution or logic abuse.',
        arType: 'ثغرة insecure deserialization',
        arExploit: 'الاستغلال بيعتمد على إن التطبيق يفك object جاي من اليوزر من غير ما يتأكد من النوع أو السلامة أو التوقيع.',
        arPayload: 'الفكرة الأساسية بتكون التلاعب في الـ serialized object نفسه عشان يشغّل behavior خطر وقت الفك.',
        arLearning: 'الأفضل نتجنب deserialization للـ input غير الموثوق أو نقيّده بأنواع مضمونة وموقعة.',
    },
    ssti: {
        label: 'SSTI',
        cwe: 'CWE-1336',
        owasp: 'Injection',
        objective: 'Verify whether template expressions from user input execute on the server.',
        steps: [
            'Find parameters that are rendered in server-side templates.',
            'Inject a template expression probe for the target engine.',
            'Observe arithmetic evaluation or syntax errors.',
            'Escalate to object traversal or command execution if confirmed.',
            'Document reachable context objects and sandbox escapes.',
        ],
        payloadLang: 'jinja2',
        payload: '{{7*7}}',
        vulnerable: 'Template expressions evaluate on the server using attacker-controlled input.',
        secure: 'Application treats user input as data only and disables dangerous template evaluation paths.',
        attackFlow: 'Inject template syntax -> server evaluates expression -> pivot to context objects or execution primitives.',
        arType: 'ثغرة SSTI',
        arExploit: 'المهاجم بيحط expression جوه input التطبيق بيرسّمه من خلال template engine على السيرفر.',
        arPayload: 'أول payload غالبًا بيكون expression حسابي بسيط يثبت إن الـ engine نفّذ الكلام فعلاً.',
        arLearning: 'الفصل بين الـ templates والـ user input مهم جدًا، ومعاه sandboxing أو تعطيل الخصائص الخطرة.',
    },
    xxe: {
        label: 'XXE',
        cwe: 'CWE-611',
        owasp: 'Security Misconfiguration',
        objective: 'Verify whether XML parsers accept attacker-controlled external entities.',
        steps: [
            'Locate XML upload, SOAP, SAML, or import endpoints.',
            'Inject a minimal XML document that references an external entity.',
            'Observe parser behavior, errors, or out-of-band interactions.',
            'Attempt safe file read or SSRF-style resolution paths.',
            'Confirm whether external entities are processed server-side.',
        ],
        payloadLang: 'xml',
        payload: '<!DOCTYPE x [ <!ENTITY test SYSTEM "file:///etc/passwd"> ]><root>&test;</root>',
        vulnerable: 'XML parser resolves attacker-controlled external entities.',
        secure: 'External entity resolution is disabled and the parser rejects unsafe DTD processing.',
        attackFlow: 'Send XML with external entity -> parser resolves attacker-controlled resource -> read files or reach internal services.',
        arType: 'ثغرة XXE',
        arExploit: 'الاستغلال بيبقى من خلال XML parser بيسمح بتحميل external entities أو DTDs.',
        arPayload: 'الفكرة هنا إننا نعرّف entity خارجي ونخلي التطبيق يفكّه على السيرفر.',
        arLearning: 'تعطيل DTDs وexternal entities هو خط الدفاع الأول، مع استخدام parsers آمنة.',
    },
    csrf: {
        label: 'CSRF',
        cwe: 'CWE-352',
        owasp: 'Identification and Authentication Failures',
        objective: 'Verify whether state-changing actions are protected against cross-site request forgery.',
        steps: [
            'Find state-changing requests that rely on browser credentials.',
            'Remove or tamper with CSRF defenses if present.',
            'Trigger the same action from a third-party origin.',
            'Observe whether the action succeeds without an anti-CSRF token or origin validation.',
            'Confirm whether user interaction or additional secrets are required.',
        ],
        payloadLang: 'html',
        payload: '<form action="https://target/app/change-email" method="POST"><input name="email" value="attacker@example.com"></form><script>document.forms[0].submit()</script>',
        vulnerable: 'Browser-authenticated state changes succeed from an untrusted origin.',
        secure: 'Application requires anti-CSRF tokens and validates origin or same-site protections.',
        attackFlow: 'Trick victim browser into sending authenticated request -> missing CSRF defenses -> unwanted state change occurs.',
        arType: 'ثغرة CSRF',
        arExploit: 'الاستغلال بيحصل لما المتصفح يبعث request موثّق تلقائيًا من origin خارجي من غير حماية كفاية.',
        arPayload: 'الـ payload بيكون صفحة أو form صغير يخلّي الضحية تبعت request وهي مسجلة دخول.',
        arLearning: 'لازم anti-CSRF token وSameSite وorigin checks يتستخدموا مع أي request بيغيّر state.',
    },
    lfi: {
        label: 'LFI',
        cwe: 'CWE-98',
        owasp: 'Security Misconfiguration',
        objective: 'Verify whether file path input is safely constrained.',
        steps: [
            'Find parameters that select or include local files.',
            'Probe with traversal sequences or alternate encodings.',
            'Observe whether arbitrary files are read or included.',
            'Check for log poisoning or wrapper abuse opportunities.',
            'Confirm whether sensitive local resources are exposed.',
        ],
        payloadLang: 'text',
        payload: '../../../../etc/passwd',
        vulnerable: 'Application reads unintended local files based on attacker-controlled paths.',
        secure: 'Application constrains file access to an allowlisted directory and normalizes paths safely.',
        attackFlow: 'Control file path -> traverse outside intended directory -> read local file or chain into code execution.',
        arType: 'ثغرة LFI',
        arExploit: 'المهاجم بيتحكم في path أو include parameter والتطبيق بيفتح الملف من غير تقييد كفاية.',
        arPayload: 'الفكرة المعتادة هي path traversal أو wrapper حسب اللغة والإطار المستخدم.',
        arLearning: 'لازم المسارات تبقى allowlisted ويتعمل canonicalization قبل أي file access.',
    },
    'open-redirect': {
        label: 'Open Redirect',
        cwe: 'CWE-601',
        owasp: 'Security Misconfiguration',
        objective: 'Verify whether redirect destinations are allowlisted.',
        steps: [
            'Locate redirect or return URL parameters.',
            'Replace the destination with an attacker-controlled URL.',
            'Trigger the flow and inspect the final redirect target.',
            'Check whether encoding tricks, double slashes, or subdomain confusion bypass validation.',
            'Assess phishing or token leakage impact.',
        ],
        payloadLang: 'text',
        payload: 'https://attacker.example/phish',
        vulnerable: 'Application redirects users to arbitrary attacker-controlled destinations.',
        secure: 'Application redirects only to allowlisted internal destinations or signed return URLs.',
        attackFlow: 'Tamper redirect parameter -> bypass validation -> redirect victim to attacker-controlled destination.',
        arType: 'ثغرة open redirect',
        arExploit: 'الاستغلال بيعتمد على parameter بيرجع اليوزر لمكان معين من غير allowlist محترمة.',
        arPayload: 'غالبًا payload بسيط جدًا عبارة عن URL خارجي أو bypass صغير للفلاتر.',
        arLearning: 'التحويل لازم يبقى على destinations معروفة أو signed values فقط.',
    },
    auth: {
        label: 'Authentication/Authorization Bypass',
        cwe: 'CWE-306',
        owasp: 'Broken Access Control',
        objective: 'Verify whether protected flows can be reached without the intended authentication or authorization checks.',
        steps: [
            'Identify the control that is supposed to restrict access.',
            'Attempt direct navigation or API access without the expected credential.',
            'Tamper with headers, roles, tokens, or feature flags tied to the flow.',
            'Observe whether the server enforces the same check independently.',
            'Confirm whether sensitive functionality becomes reachable.',
        ],
        payloadLang: 'http',
        payload: 'GET /admin\nX-Original-URL: /admin',
        vulnerable: 'Protected functionality is reachable without the intended identity or authorization checks.',
        secure: 'Server verifies identity and authorization for every protected action regardless of client state.',
        attackFlow: 'Find access gate -> bypass client-side or weak server-side check -> reach protected functionality.',
        arType: 'ثغرة bypass في الـ authentication أو authorization',
        arExploit: 'الفكرة إن فيه check ناقص أو قابل للتجاوز فالمهاجم بيوصل لوظيفة مفروض تكون محمية.',
        arPayload: 'أحيانًا الـ payload بيكون header أو role أو token tampering أو direct request للمسار المحمي.',
        arLearning: 'الحماية الحقيقية لازم تبقى server-side وعلى كل endpoint أو action حساس.',
    },
    ato: {
        label: 'Account Takeover',
        cwe: 'CWE-287',
        owasp: 'Broken Authentication',
        objective: 'Verify whether attacker-controlled actions can compromise another user account.',
        steps: [
            'Map login, password reset, email change, and session management flows.',
            'Look for weak verification or token binding issues.',
            'Attempt reuse, prediction, or tampering of recovery artifacts.',
            'Check whether account ownership can be changed without proper proof.',
            'Confirm whether full account control becomes possible.',
        ],
        payloadLang: 'http',
        payload: 'POST /reset-password\nemail=victim@example.com&token=weak-token',
        vulnerable: 'Attacker obtains control over another user account through weak identity validation.',
        secure: 'Sensitive account flows require strong token validation and proof of ownership.',
        attackFlow: 'Abuse weak identity flow -> reset or hijack session -> gain control over victim account.',
        arType: 'سيناريو account takeover',
        arExploit: 'الاستغلال هنا بيركز على خطأ في login أو reset أو session handling يوصل لسيطرة كاملة على الحساب.',
        arPayload: 'الـ payload غالبًا بيكون token ضعيف أو قابل لإعادة الاستخدام أو تعديل flow خاص باسترجاع الحساب.',
        arLearning: 'كل flows الخاصة بالحساب لازم تبقى مرتبطة بملكية حقيقية وتوكينات قوية قصيرة العمر.',
    },
    'race-condition': {
        label: 'Race Condition',
        cwe: 'CWE-362',
        owasp: 'Insecure Design',
        objective: 'Verify whether concurrent requests can break consistency or bypass security checks.',
        steps: [
            'Identify actions that reserve, redeem, or mutate shared state.',
            'Send parallel requests for the same resource.',
            'Observe inconsistent responses or duplicated effects.',
            'Check whether authorization or business rules are evaluated only once.',
            'Confirm whether concurrency creates security impact.',
        ],
        payloadLang: 'http',
        payload: 'POST /redeem-coupon\ncoupon=SUMMER2026',
        vulnerable: 'Concurrent requests bypass business or security checks and create inconsistent state.',
        secure: 'Server uses locking, idempotency, or transactional checks to prevent duplicate effects.',
        attackFlow: 'Send competing requests in parallel -> bypass single-use or sequence check -> obtain repeated unauthorized outcome.',
        arType: 'ثغرة race condition',
        arExploit: 'المشكلة بتحصل لما كذا request يوصلوا في نفس الوقت والتطبيق مايديرش التزامن بشكل آمن.',
        arPayload: 'الفكرة عادة مش payload معقد بقدر ما هي إعادة نفس الطلب بسرعة أو بتوازي عالي.',
        arLearning: 'الـ locking والـ transactions والـ idempotency مهمين جدًا في الـ security-sensitive flows.',
    },
    generic: {
        label: 'Security Misconfiguration / Logic Issue',
        cwe: 'CWE-284',
        owasp: 'Security Misconfiguration',
        objective: 'Verify whether the documented security assumption actually holds under attacker-controlled input.',
        steps: [
            'Identify the trust boundary or validation assumption in the workflow.',
            'Replay the request while changing one input at a time.',
            'Observe whether the backend response changes in a security-relevant way.',
            'Document the exact condition that turns the flow vulnerable.',
            'Confirm what control should have prevented the issue.',
        ],
        payloadLang: 'text',
        payload: 'attacker-controlled-input',
        vulnerable: 'Application behavior changes in a way that breaks the intended security boundary.',
        secure: 'Security assumptions are enforced server-side with explicit validation and least privilege.',
        attackFlow: 'Reach trust boundary -> tamper controlled input -> missing validation or logic check -> unauthorized outcome.',
        arType: 'مشكلة أمنية أو منطقية في التطبيق',
        arExploit: 'الكاتب بيشرح flow أمني حصل فيه trust زائد أو validation ناقص ففتح باب للاستغلال.',
        arPayload: 'فكرة الـ payload هنا مرتبطة بالـ input اللي بيكسر الفرضية الأمنية الأساسية في الـ flow.',
        arLearning: 'لازم كل فرضية أمنية تبقى enforced على السيرفر بشكل واضح وقابل للاختبار.',
    },
};

function extractRepresentativeCodeBlock(markdown) {
    const blocks = [...String(markdown || '').matchAll(/```(\w+)?\n([\s\S]*?)```/g)];
    for (const match of blocks) {
        const lang = match[1] || '';
        const body = match[2].trim();
        const lines = body.split('\n').map(l => l.trimEnd()).filter(Boolean);
        if (lines.length >= 1 && lines.length <= 14 && body.length <= 900) {
            return { lang, body: lines.join('\n') };
        }
    }
    return null;
}

function protectCodeBlocks(text) {
    const blocks = [];
    const protectedText = String(text || '').replace(/```[\s\S]*?```/g, block => {
        const token = `@@CODE_BLOCK_${blocks.length}@@`;
        blocks.push(block);
        return token;
    });
    return { protectedText, blocks };
}

function restoreCodeBlocks(text, blocks) {
    return blocks.reduce((acc, block, index) => acc.replace(`@@CODE_BLOCK_${index}@@`, block), text);
}

function blockHeadingLevel(block) {
    const match = String(block || '').trim().match(/^(#{1,6})\s+/);
    return match ? match[1].length : 0;
}

function normalizedBlockText(block) {
    return String(block || '')
        .toLowerCase()
        .replace(/https?:\/\/\S+/g, '')
        .replace(/[`*_>#\[\]\(\)\-:|]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

class WriteupPostProcessor {
    detectPrimaryProfile(title, tags, body) {
        const haystack = `${title}\n${body}`.toLowerCase();
        const priority = ['rce', 'deserialization', 'sqli', 'ssrf', 'ssti', 'xxe', 'auth', 'ato', 'idor', 'xss', 'csrf', 'lfi', 'open-redirect', 'privesc', 'race-condition'];
        for (const tag of priority) {
            if ((tags || []).includes(tag)) return VULN_PROFILES[tag] || VULN_PROFILES.generic;
        }
        if (haystack.includes('authorization bypass')) return VULN_PROFILES.auth;
        if (haystack.includes('idor')) return VULN_PROFILES.idor;
        if (haystack.includes('xss')) return VULN_PROFILES.xss;
        if (haystack.includes('ssrf')) return VULN_PROFILES.ssrf;
        if (haystack.includes('sql injection')) return VULN_PROFILES.sqli;
        return VULN_PROFILES.generic;
    }

    cleanMarkdown(markdown, title) {
        const { protectedText, blocks } = protectCodeBlocks(markdown);
        const rawBlocks = protectedText
            .replace(/\r\n/g, '\n')
            .replace(/\n{3,}/g, '\n\n')
            .split(/\n{2,}/)
            .map(block => block.trim())
            .filter(Boolean);

        const output = [];
        const seen = new Set();
        let skipLevel = 0;
        const normalizedTitle = normalizedBlockText(title);

        for (const block of rawBlocks) {
            const headingLevel = blockHeadingLevel(block);
            const headingText = headingLevel ? block.replace(/^#{1,6}\s+/, '').trim() : '';
            const normalized = normalizedBlockText(block);

            if (skipLevel) {
                if (headingLevel > 0 && headingLevel <= skipLevel) {
                    skipLevel = 0;
                } else {
                    continue;
                }
            }

            if (headingLevel && NOISE_SECTION_RE.test(headingText)) {
                skipLevel = headingLevel;
                continue;
            }
            if (headingLevel && normalizedBlockText(headingText) === normalizedTitle) continue;
            if (!headingLevel && NOISE_BLOCK_RE.test(block)) continue;
            if (!headingLevel && normalized && normalized === normalizedTitle) continue;
            if (!headingLevel && normalized.length < 3) continue;
            if (!headingLevel && /^by\s+[a-z0-9 _.-]{2,80}$/i.test(block)) continue;
            if (!headingLevel && /^\[(read more|source|original article)\]\(/i.test(block)) continue;

            if (!headingLevel && normalized.length > 10) {
                if (seen.has(normalized)) continue;
                seen.add(normalized);
            }

            output.push(block);
        }

        let cleaned = restoreCodeBlocks(output.join('\n\n'), blocks);
        cleaned = cleaned
            .replace(/\n{4,}/g, '\n\n\n')
            .replace(/[ \t]+\n/g, '\n')
            .replace(/\n+$/g, '')
            .trim();
        return cleaned;
    }

    buildEgyptianSummary(context) {
        return [
            `المقال ده بيتكلم عن ${context.profile.arType}.`,
            context.profile.arExploit,
            context.profile.arPayload,
            `أهم حاجة تطلع بيها هنا إن ${context.profile.arLearning}`,
        ].join('\n');
    }

    buildSummaryCallout(summary) {
        return `> [!summary] ملخص سريع بالمصري\n> ${summary.split('\n').join('\n> ')}\n\n`;
    }

    buildTestCaseSection(context, cleanedBody) {
        const sample = extractRepresentativeCodeBlock(cleanedBody) || {
            lang: context.profile.payloadLang,
            body: context.profile.payload,
        };

        return [
            '> [!bug] Test Case',
            '> قالب سريع تقدر تنسخه وتعدله وقت المراجعة.',
            '',
            '## Test Case',
            '### Vulnerability Type',
            context.profile.label,
            '',
            '### Objective',
            context.profile.objective,
            '',
            '### Test Steps',
            ...context.profile.steps.map((step, index) => `${index + 1}. ${step}`),
            '',
            '### Example Payload',
            `\`\`\`${sample.lang || context.profile.payloadLang || 'text'}`,
            sample.body,
            '```',
            '',
            '### Expected Vulnerable Behavior',
            context.profile.vulnerable,
            '',
            '### Expected Secure Behavior',
            context.profile.secure,
            '',
            '### Attack Flow',
            context.profile.attackFlow,
            '',
            '### CWE',
            context.profile.cwe,
            '',
            '### OWASP Category',
            context.profile.owasp,
            '',
            '### Severity',
            context.severity.charAt(0).toUpperCase() + context.severity.slice(1),
            '',
        ].join('\n');
    }

    process(item) {
        const cleanedCandidate = this.cleanMarkdown(item.body || '', item.title);
        const cleanedBody = cleanedCandidate.length >= 120 ? cleanedCandidate : String(item.body || '').trim();
        const profile = this.detectPrimaryProfile(item.title, item.tags || [], cleanedBody);
        const severity = detectSeverity(item.title, item.tags || []);
        const context = {
            title: item.title,
            url: item.originalUrl || item.url,
            tags: item.tags || [],
            severity,
            profile,
            topic: item.topic || '',
            cwe: profile.cwe,
            owasp: profile.owasp,
            attackFlow: profile.attackFlow,
        };
        const summary = this.buildEgyptianSummary(context);
        return {
            cleanedBody,
            summary,
            summaryCallout: this.buildSummaryCallout(summary),
            testCaseSection: this.buildTestCaseSection(context, cleanedBody),
            context,
        };
    }
}

const writeupPostProcessor = new WriteupPostProcessor();

// ─── Markdown Builder ─────────────────────────────────────────────────────────

function buildMd({title, source, url, date, tags, author, body, topic, originalUrl, fetchedFrom, fallbackUsed, fetchStatus}) {
    tags = uniqueValues(tags || []);
    const processed = writeupPostProcessor.process({ title, tags, body, url, originalUrl, topic });
    const content = processed.cleanedBody || '';
    const canonicalUrl = originalUrl || url;
    const resolvedFetchUrl = fetchedFrom || canonicalUrl;
    const {words, label: readTime} = estimateReadingTime(content);
    const severity = detectSeverity(title, tags);
    const sevIcon = SEVERITY_ICON[severity];
    const cves = extractCVEs(title + ' ' + content);
    const platform = detectPlatform(canonicalUrl, title);
    const excerpt = content.replace(/[#*>\-\[\]`]/g,'').replace(/\n+/g,' ').trim().slice(0,200);
    const tagLine = tags.map(t => `#${t}`).join(' ');
    const toc = generateTOC(content);

    // YAML frontmatter
    let fm = `---\ntitle: "${yamlSafe(title)}"\nsource: "${yamlSafe(source)}"\nurl: "${canonicalUrl}"\ndate: "${date}"\n`;
    fm += `tags: ${JSON.stringify(tags)}\nscraped_at: "${new Date().toISOString().slice(0,16)}"\n`;
    fm += `reading_time: "${readTime}"\nword_count: ${words}\nseverity: "${severity}"\n`;
    if (platform) fm += `platform: "${yamlSafe(platform)}"\n`;
    if (cves.length) fm += `cve_ids: ${JSON.stringify(cves)}\n`;
    if (processed.context.cwe) fm += `cwe: "${processed.context.cwe}"\n`;
    if (processed.context.owasp) fm += `owasp: "${yamlSafe(processed.context.owasp)}"\n`;
    if (processed.context.topic) fm += `topic: "${yamlSafe(processed.context.topic)}"\n`;
    if (excerpt) fm += `excerpt: "${yamlSafe(excerpt).slice(0,200)}"\n`;
    fm += `original_url: "${canonicalUrl}"\nfetched_from: "${resolvedFetchUrl}"\nfallback_used: ${fallbackUsed ? 'true' : 'false'}\n`;
    if (fetchStatus) fm += `fetch_status: "${fetchStatus}"\n`;
    fm += '---\n\n';

    // Info card
    let card = processed.summaryCallout;
    card += `# ${title}\n\n`;
    card += `> [!info] 📋 Writeup Details\n`;
    card += `> | | |\n> |---|---|\n`;
    card += `> | **Source** | [${source}](${canonicalUrl}) |\n`;
    card += `> | **Date** | ${date} |\n`;
    card += `> | **Reading Time** | ⏱ ${readTime} (${words.toLocaleString()} words) |\n`;
    card += `> | **Severity** | ${sevIcon} ${severity.charAt(0).toUpperCase()+severity.slice(1)} |\n`;
    if (processed.context.topic) card += `> | **Topic** | ${processed.context.topic} |\n`;
    card += `> | **Fetched From** | ${fallbackUsed ? `[Mirror](${resolvedFetchUrl})` : `[Original](${resolvedFetchUrl})`} |\n`;
    if (author) card += `> | **Author** | ${author} |\n`;
    if (platform) card += `> | **Platform** | ${platform} |\n`;
    if (cves.length) card += `> | **CVEs** | ${cves.map(c=>'`'+c+'`').join(', ')} |\n`;
    if (processed.context.cwe) card += `> | **CWE** | ${processed.context.cwe} |\n`;
    if (processed.context.owasp) card += `> | **OWASP** | ${processed.context.owasp} |\n`;
    card += `> | **Tags** | ${tagLine} |\n`;
    card += '\n---\n\n';

    // Related writeups (Dataview)
    const relTags = tags.filter(t=>!['writeup','security'].includes(t)).slice(0,3);
    let related = `\n\n---\n\n${processed.testCaseSection}\n\n---\n\n## References\n\n- Original: [${canonicalUrl}](${canonicalUrl})\n- Fetched From: [${resolvedFetchUrl}](${resolvedFetchUrl})\n`;
    related += '\n\n---\n\n## 🔗 Related Writeups\n\n';
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
        this._cancelled = false;
    }

    onOpen() {
        this.modalEl.addClass('wm-preview-modal');
        this.contentEl.style.cssText = 'max-height:82vh; overflow-y:auto;';
        this.renderIdle();
    }

    renderIdle() {
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '⬇  Collect Writeups'});

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
        const scanBtn = footer.createEl('button', {text: '🔍  Scan RSS feeds', cls: 'wm-btn-primary'});
        scanBtn.addEventListener('click', () => this.startScan(false));

        const topicEnabled = (plugin.settings.topicSources || []).filter(s => s.enabled);
        if (topicEnabled.length > 0) {
            const topicInfo = contentEl.createDiv({cls: 'wm-src-summary'});
            topicInfo.createSpan({text: `🎯 ${topicEnabled.length} topic source${topicEnabled.length!==1?'s':''}: `});
            topicInfo.createSpan({text: uniqueValues(topicEnabled.flatMap(s => normalizeTopicList(s))).join(', '), cls: 'wm-src-names'});
            const topicBtn = footer.createEl('button', {text: '🎯  Scan topics', cls: 'wm-btn-secondary'});
            topicBtn.addEventListener('click', () => this.startScan(true));
        }

        const scanAllBtn = footer.createEl('button', {text: '⚡ Scan all', cls: 'wm-btn-fetch'});
        scanAllBtn.addEventListener('click', () => this.startScan('all'));
    }

    async startScan(mode = false) {
        this.phase = 'scanning';
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        const scanLabel = mode === true ? '🔍 Scanning topic sources...' : mode === 'all' ? '🔍 Scanning all sources...' : '🔍 Scanning feeds...';
        hdr.createEl('h2', {text: scanLabel});
        const statusEl = contentEl.createDiv({cls: 'wm-scan-status'});

        const seen = new Set((plugin.settings.seenUrls || []).slice(-3000));
        const enabled = plugin.settings.sources.filter(s=>s.enabled);
        const limit = plugin.settings.limitPerSource || 20;
        const watchlist = (plugin.settings.watchlistKeywords || []).map(k=>k.toLowerCase());
        const foundItems = [];

        const scanRss = (mode !== true);
        if (scanRss) {
            for (const src of enabled) {
                if (this._cancelled) break;
                statusEl.setText(`Fetching RSS from ${src.name}...`);
                let srcCount = 0;
                try {
                    const rssItems = await fetchFeedItems(src);
                    for (const item of rssItems) {
                        if (srcCount >= limit) break;
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
                        srcCount++;
                    }
                } catch(e) {
                    console.error('SecFeeds: scan failed for', src.name, e?.message || e);
                    statusEl.setText(`⚠️ Failed to fetch ${src.name}`);
                    await sleep(800);
                }
            }
        }

        // ── Topic Sources scan ──
        const scanTopics = (mode === true || mode === 'all');
        if (scanTopics) {
            const topicEnabled = (plugin.settings.topicSources || []).filter(s => s.enabled);
            for (const ts of topicEnabled) {
                if (this._cancelled) break;
                statusEl.setText(`Scanning topics: ${normalizeTopicList(ts).join(', ')} (${ts.name})...`);
                try {
                    const topicItems = await fetchTopicResults(
                        ts, seen,
                        plugin.settings.topicFolderMap || {},
                        plugin.settings.outputFolder || 'writeups',
                        { syncHistory: plugin.settings.topicSyncHistory || {}, respectSchedule: false }
                    );
                    for (const item of topicItems) {
                        if (foundItems.length >= limit * 10) break; // overall cap
                        const titleLower = item.title.toLowerCase();
                        if (this.filterTag && !item.tags.includes(this.filterTag)) continue;
                        item.watchlisted = watchlist.some(k => titleLower.includes(k));
                        if (item.watchlisted) item.checked = true;
                        foundItems.push(item);
                    }
                } catch(e) {
                    console.error('SecFeeds: topic scan failed:', ts.name, e?.message || e);
                    statusEl.setText(`⚠️ Topic scan failed: ${ts.name}`);
                    await sleep(500);
                }
            }
            await plugin.saveSettings();
        }

        this.items = foundItems;
        if (foundItems.length === 0) { this.renderNoResults(); }
        else { this.renderPreview(); }
    }



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
        const debouncedSearch = debounce(() => { this.filterText = searchIn.value; this.renderPreviewList(list, countLabel); }, 250);
        searchIn.addEventListener('input', debouncedSearch);

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
            titleRow.createSpan({text: SEVERITY_ICON[item.severity], cls:`wm-sev-badge wm-sev-${item.severity}`});
            titleRow.createEl('a', {text: item.title, cls: 'wm-preview-title', href: item.url});

            const meta = info.createDiv({cls: 'wm-preview-meta'});
            meta.createSpan({text: item.source, cls: 'wm-badge-source'});
            meta.createSpan({text: item.date, cls: 'wm-meta-date'});
            if (item.topic) meta.createSpan({text: `topic: ${item.topic}`, cls: 'wm-meta-date'});
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
        this._cancelled = false;
        contentEl.empty();
        contentEl.createEl('h2', {text: '💾 Saving writeups...'});

        const progWrap = contentEl.createDiv({cls: 'wm-prog-wrap'});
        const progBar = progWrap.createDiv({cls: 'wm-prog-bar'});
        const progFill = progBar.createDiv({cls: 'wm-prog-fill'});
        const progLabel = progWrap.createSpan({text: `0 / ${selected.length}`, cls:'wm-prog-label'});
        const cancelBtn = contentEl.createEl('button', {text: '✕ Cancel', cls: 'wm-btn-secondary'});
        cancelBtn.style.cssText = 'margin-bottom:8px;';
        cancelBtn.addEventListener('click', () => { this._cancelled = true; cancelBtn.setText('Cancelling...'); cancelBtn.disabled = true; });
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
            let originalUrl = item.url;
            let fetchedFrom = item.url;
            let fallbackUsed = false;
            let fetchStatus = 'original';
            if (plugin.settings.fetchFullContent) {
                const result = await fetchArticleContent(item.url, item.articleSelector);
                originalUrl = result.originalUrl || item.url;
                fetchStatus = result.fetchStatus || 'failed';
                if (result.content && result.content.length > body.length) {
                    body = result.content;
                    fetchedFrom = result.fetchedFrom;
                    fallbackUsed = result.fallbackUsed;
                    logRow.querySelector('.wm-log-icon').setText(fallbackUsed ? '🔄 ' : '✅ ');
                } else {
                    logRow.querySelector('.wm-log-icon').setText(body ? '📄 ' : '⚠️ ');
                    if (result.failureReason) logRow.title = `Fetch issue: ${result.failureReason}`;
                }
            } else {
                logRow.querySelector('.wm-log-icon').setText('✅ ');
            }

            try {
                await plugin.saveWriteup(folder, {...item, body, originalUrl, fetchedFrom, fallbackUsed, fetchStatus});
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
                console.error('SecFeeds: save failed:', item.title, e?.message || e);
                logRow.querySelector('.wm-log-icon').setText('❌ ');
                this.failedItems.push(item);
                plugin.settings.stats.totalFailed++;
            }
            if (this._cancelled) break;
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
        this.contentEl.style.cssText = 'max-height:82vh; overflow-y:auto;';
        this.render();
        this.checkHealth();
    }

    async checkHealth() {
        // Parallel health checks for all sources
        const sources = this.plugin.settings.sources;
        sources.forEach(src => this.healthMap.set(src.id, 'checking'));
        this.updateHealthDots();
        await Promise.allSettled(sources.map(async (src) => {
            try {
                const resp = await obsidian.requestUrl({ url: src.feedUrl || src.url, method:'GET',
                    headers:{'User-Agent':'Mozilla/5.0 (Obsidian Plugin)'}, throw:false, timeout: REQUEST_TIMEOUT });
                this.healthMap.set(src.id, (resp && resp.status >= 200 && resp.status < 400) ? 'online' : 'offline');
            } catch(e) { this.healthMap.set(src.id, 'offline'); }
            this.updateHealthDots();
        }));
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
        hdr.createEl('h2', {text: '🔐 Security Writeup Collector'});

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

        // Topic-based search sources
        contentEl.createEl('h3', {text: 'Topic Search Sources', cls: 'wm-section-title'});
        const topicHint = contentEl.createEl('p', {
            text: 'Each topic source builds URLs as baseUrl + encodeURIComponent(topic). Leave Folder Category empty to use the automatic topic folder map.',
            cls: 'wm-hint',
        });
        topicHint.style.marginTop = '0';
        const topicList = contentEl.createDiv({cls: 'wm-list'});
        for (let i=0; i<(plugin.settings.topicSources || []).length; i++) {
            this.renderTopicSourceRow(topicList, plugin.settings.topicSources[i], i);
        }

        contentEl.createEl('h3', {text: 'Add Topic Source', cls: 'wm-section-title'});
        const topicAdd = contentEl.createDiv({cls: 'wm-add wm-topic-add'});
        const topicNameIn = topicAdd.createEl('input', {type:'text', placeholder:'Source Name  (e.g. Medium)'});
        const topicBaseIn = topicAdd.createEl('input', {type:'url', placeholder:'Base URL  (e.g. https://medium.com/search?q=)'});
        const topicValuesIn = topicAdd.createEl('input', {type:'text', placeholder:'Topics  (e.g. idor, xss, ssrf)'});
        const topicCategoryIn = topicAdd.createEl('input', {type:'text', placeholder:'Folder Category  (e.g. Web/{topic} or Web/IDOR)'});

        const topicTypeSel = topicAdd.createEl('select', {cls:'wm-topic-select'});
        for (const [value, label] of [['search_source','Search Source'],['github_search','GitHub Search'],['google_dork','Google Dork'],['rss_keyword','RSS Keyword']]) {
            topicTypeSel.createEl('option', {value, text: label});
        }

        const topicFreqSel = topicAdd.createEl('select', {cls:'wm-topic-select'});
        for (const [value, label] of [['daily','Daily'],['hourly','Hourly'],['weekly','Weekly'],['startup','Every Startup'],['manual','Manual Only']]) {
            topicFreqSel.createEl('option', {value, text: `Sync: ${label}`});
        }

        const topicOpts = topicAdd.createDiv({cls:'wm-topic-options'});
        const topicAutoWrap = topicOpts.createEl('label', {cls:'wm-topic-toggle'});
        const topicAutoIn = topicAutoWrap.createEl('input', {type:'checkbox'});
        topicAutoIn.checked = true;
        topicAutoWrap.createSpan({text:'Auto Sync'});
        const topicEnabledWrap = topicOpts.createEl('label', {cls:'wm-topic-toggle'});
        const topicEnabledIn = topicEnabledWrap.createEl('input', {type:'checkbox'});
        topicEnabledIn.checked = true;
        topicEnabledWrap.createSpan({text:'Enabled'});

        const topicAddBtn = topicAdd.createEl('button', {text:'+ Add Topic Source', cls:'wm-btn-add'});
        topicAddBtn.addEventListener('click', async () => {
            const name = topicNameIn.value.trim();
            const baseUrl = topicBaseIn.value.trim();
            const topics = normalizeTopicList({ topic: topicValuesIn.value });
            const category = topicCategoryIn.value.trim();
            if (!name || !baseUrl || topics.length === 0) {
                new obsidian.Notice('⚠️ Enter source name, base URL, and at least one topic');
                return;
            }
            try { new URL(baseUrl); } catch { new obsidian.Notice('⚠️ Invalid base URL'); return; }

            const idBase = slugify(`${name}-${topics.join('-')}`) || slugify(name) || 'topic-source';
            const id = plugin.settings.topicSources.find(s => s.id === idBase) ? `${idBase}-${shortHash(baseUrl + topics.join(','))}` : idBase;
            plugin.settings.topicSources.push({
                id,
                name,
                type: topicTypeSel.value,
                baseUrl,
                topic: topics[0],
                topics,
                category,
                syncFrequency: topicFreqSel.value,
                autoSync: topicAutoIn.checked,
                enabled: topicEnabledIn.checked,
            });
            await plugin.saveSettings();
            new obsidian.Notice(`✅ Added topic source for ${topics.join(', ')}`);
            topicNameIn.value = '';
            topicBaseIn.value = '';
            topicValuesIn.value = '';
            topicCategoryIn.value = '';
            topicTypeSel.value = 'search_source';
            topicFreqSel.value = 'daily';
            topicAutoIn.checked = true;
            topicEnabledIn.checked = true;
            this.render();
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
        const fetchBtn = footer.createEl('button', {text:'⬇  Collect writeups', cls:'wm-btn-fetch'});
        fetchBtn.addEventListener('click', () => { this.close(); new FetchPreviewModal(this.app, plugin).open(); });

        const statsBtn = footer.createEl('button', {text:'📊 Stats', cls:'wm-btn-secondary'});
        statsBtn.addEventListener('click', () => { this.close(); new StatsModal(this.app, plugin).open(); });

        const exportBtn = footer.createEl('button', {text:'📤 Export', cls:'wm-btn-secondary'});
        exportBtn.addEventListener('click', async () => {
            const json = JSON.stringify({
                version: 1,
                sources: plugin.settings.sources || [],
                topicSources: plugin.settings.topicSources || [],
                topicFolderMap: plugin.settings.topicFolderMap || {},
                watchlistKeywords: plugin.settings.watchlistKeywords || [],
            }, null, 2);
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(json);
                } else {
                    // Fallback for mobile: create a temporary textarea
                    const ta = document.createElement('textarea');
                    ta.value = json;
                    ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;';
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                }
                new obsidian.Notice('✅ Sources copied to clipboard');
            } catch(e) {
                new obsidian.Notice('⚠️ Could not copy — use Export to File instead');
                // Fallback: show in a modal for manual copy
                const m = new obsidian.Modal(plugin.app);
                m.contentEl.createEl('h3', {text: '📤 Exported Source Config'});
                m.contentEl.createEl('p', {text: 'Select all and copy manually:', cls: 'wm-hint'});
                const area = m.contentEl.createEl('textarea', {cls: 'wm-import-textarea'});
                area.value = json;
                area.style.cssText = 'width:100%;height:250px;font-family:monospace;font-size:12px;border-radius:8px;padding:10px;border:1px solid var(--background-modifier-border);background:var(--background-secondary);color:var(--text-normal);resize:vertical;';
                m.open();
            }
        });

        const importBtn = footer.createEl('button', {text:'📥 Import', cls:'wm-btn-secondary'});
        importBtn.addEventListener('click', () => this.showImport());

        const cacheBtn = footer.createEl('button', {text:`🗑 Cache (${(plugin.settings.seenUrls||[]).length})`, cls:'wm-btn-cache'});
        cacheBtn.addEventListener('click', async () => {
            if (!confirm('Clear all cached URLs? This will allow re-fetching previously downloaded writeups.')) return;
            plugin.settings.seenUrls=[]; await plugin.saveSettings(); new obsidian.Notice('Cache cleared'); this.render();
        });

        if (plugin.settings.lastFetched) footer.createEl('p', {text:`Last fetched: ${plugin.settings.lastFetched}`, cls:'wm-meta'});
    }

    showImport() {
        const {contentEl, plugin} = this;
        contentEl.empty();
        const hdr = contentEl.createDiv({cls:'wm-modal-header'});
        hdr.createEl('h2', {text: '📥 Import Source Config'});
        contentEl.createEl('p', {text:'Paste an exported config JSON below. RSS sources, topic sources, watchlist keywords, and folder mappings are supported.', cls:'wm-hint'});
        const ta = contentEl.createEl('textarea', {cls:'wm-import-textarea'});
        ta.style.cssText = 'width:100%;height:200px;font-family:monospace;font-size:12px;border-radius:8px;padding:10px;border:1px solid var(--background-modifier-border);background:var(--background-secondary);color:var(--text-normal);resize:vertical;';
        const footer = contentEl.createDiv({cls:'wm-footer'});
        const backBtn = footer.createEl('button', {text:'← Back', cls:'wm-btn-secondary'});
        backBtn.addEventListener('click', () => this.render());
        const doImport = footer.createEl('button', {text:'Import', cls:'wm-btn-primary'});
        doImport.addEventListener('click', async () => {
            try {
                const parsed = JSON.parse(ta.value);
                const rssSources = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.sources) ? parsed.sources : []);
                const topicSources = Array.isArray(parsed?.topicSources) ? parsed.topicSources : [];
                let added = 0;
                let addedTopics = 0;
                for (const s of rssSources) {
                    if (!s.name || !s.url) continue;
                    // Validate URL format and protocol
                    try { const u = new URL(s.url); if (!['http:','https:'].includes(u.protocol)) continue; } catch { continue; }
                    const id = s.id || slugify(s.name);
                    if (plugin.settings.sources.find(x => x.id === id)) continue;
                    plugin.settings.sources.push({
                        id, name: String(s.name).slice(0,60), url: s.url,
                        feedUrl: s.feedUrl || s.url, icon: (s.icon || '🔗').slice(0,4),
                        enabled: s.enabled !== false, articleSelector: s.articleSelector || 'article, .post-content, main',
                    });
                    added++;
                }
                for (const src of topicSources) {
                    if (!src.name || !src.baseUrl) continue;
                    try { const u = new URL(src.baseUrl); if (!['http:','https:'].includes(u.protocol)) continue; } catch { continue; }
                    const normalized = normalizeTopicSource(src);
                    if (!normalized.topics.length) continue;
                    const id = normalized.id || slugify(`${normalized.name}-${normalized.topics.join('-')}`);
                    if (plugin.settings.topicSources.find(x => x.id === id)) continue;
                    plugin.settings.topicSources.push(Object.assign({}, normalized, { id }));
                    addedTopics++;
                }
                if (parsed?.topicFolderMap && typeof parsed.topicFolderMap === 'object') {
                    plugin.settings.topicFolderMap = Object.assign({}, plugin.settings.topicFolderMap || {}, parsed.topicFolderMap);
                }
                if (Array.isArray(parsed?.watchlistKeywords)) {
                    plugin.settings.watchlistKeywords = uniqueValues([
                        ...(plugin.settings.watchlistKeywords || []),
                        ...parsed.watchlistKeywords.map(k => String(k || '').trim().toLowerCase()).filter(Boolean),
                    ]);
                }
                await plugin.saveSettings();
                new obsidian.Notice(`✅ Imported ${added} source${added!==1?'s':''} and ${addedTopics} topic source${addedTopics!==1?'s':''}`);
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

        if (!src.isBuiltIn) {
            const del = row.createEl('button', {text:'✕', cls:'wm-del'});
            del.addEventListener('click', async () => {
                if (!confirm(`Remove source "${src.name}"?`)) return;
                plugin.settings.sources.splice(i,1); await plugin.saveSettings(); this.render();
            });
        }
    }

    renderTopicSourceRow(container, srcInput, i) {
        const {plugin} = this;
        const src = normalizeTopicSource(srcInput);
        const row = container.createDiv({cls:`wm-row${src.enabled?'':' wm-row-off'} wm-topic-row`});

        const tog = row.createEl('input', {type:'checkbox'});
        tog.checked = src.enabled;
        tog.addEventListener('change', async () => {
            plugin.settings.topicSources[i].enabled = tog.checked;
            row.toggleClass('wm-row-off', !tog.checked);
            await plugin.saveSettings();
        });

        row.createSpan({text:'🎯', cls:'wm-icon'});

        const info = row.createDiv({cls:'wm-info'});
        info.createSpan({text: `${src.name} · ${src.type.replace(/_/g, ' ')}`, cls:'wm-name'});
        const host = (() => {
            try { return new URL(src.baseUrl).hostname; } catch(e) { return src.baseUrl; }
        })();
        info.createEl('a', {text: host, href: src.baseUrl, cls:'wm-url'});

        const meta = info.createDiv({cls:'wm-preview-meta'});
        meta.createSpan({text: `topics: ${normalizeTopicList(src).join(', ')}`, cls:'wm-badge-source'});
        meta.createSpan({text: `folder: ${src.category || 'auto-map'}`, cls:'wm-meta-date'});
        meta.createSpan({text: src.autoSync ? `auto: ${src.syncFrequency}` : 'auto: off', cls:'wm-meta-date'});

        if (!src.isBuiltIn) {
            const del = row.createEl('button', {text:'✕', cls:'wm-del'});
            del.addEventListener('click', async () => {
                if (!confirm(`Remove topic source "${src.name}"?`)) return;
                plugin.settings.topicSources.splice(i, 1);
                await plugin.saveSettings();
                this.render();
            });
        }
    }

    onClose() { this.contentEl.empty(); }
}

// ─── Statistics Modal ─────────────────────────────────────────────────────────

class StatsModal extends obsidian.Modal {
    constructor(app, plugin) { super(app); this.plugin = plugin; }

    onOpen() {
        this.modalEl.addClass('wm-stats-modal');
        this.contentEl.style.cssText = 'max-height:82vh; overflow-y:auto;';
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
        this.statCard(overview, '📡', 'Sources', (plugin.settings.sources.length || 0) + ((plugin.settings.topicSources || []).length || 0));
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
            if (!confirm('Reset all statistics? This cannot be undone.')) return;
            plugin.settings.stats = {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};
            await plugin.saveSettings();
            new obsidian.Notice('Stats reset');
            this.render();
        });
    }

    statCard(container, icon, label, value) {
        const card = container.createDiv({cls:'wm-stat-card'});
        card.createSpan({text:icon, cls:'wm-stat-icon'});
        const body = card.createDiv({cls:'wm-stat-body'});
        body.createSpan({text: String(value), cls:'wm-stat-value'});
        body.createSpan({text: label, cls:'wm-stat-label'});
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
        containerEl.createEl('h2', {text:'🔐 Security Writeup Collector'});
        new obsidian.Setting(containerEl).setName('Sources Manager').setDesc('Manage RSS sources, topic sources, filters, and output settings').addButton(b=>b.setButtonText('Open').onClick(()=>new SourcesModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Collect Writeups').setDesc('Scan, preview, and download new writeups').addButton(b=>b.setButtonText('Open Collector').setCta().onClick(()=>new FetchPreviewModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Topic Sources').setDesc(`${(this.plugin.settings.topicSources || []).length} topic source(s) configured for keyword-based discovery`).addButton(b=>b.setButtonText('Manage').onClick(()=>new SourcesModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Statistics').setDesc('View fetch statistics and analytics').addButton(b=>b.setButtonText('View').onClick(()=>new StatsModal(this.app,this.plugin).open()));
        new obsidian.Setting(containerEl).setName('Watchlist Keywords').setDesc('Comma-separated keywords to highlight in scan results')
            .addText(t => {
                t.setPlaceholder('rce, zero-day, critical');
                t.setValue((this.plugin.settings.watchlistKeywords||[]).join(', '));
                const debouncedSave = debounce(async (v) => {
                    this.plugin.settings.watchlistKeywords = v.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
                    await this.plugin.saveSettings();
                }, 500);
                t.onChange(debouncedSave);
            });
        if (this.plugin.settings.lastFetched) containerEl.createEl('p',{text:`Last fetched: ${this.plugin.settings.lastFetched}`, cls:'setting-item-description'});
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Main Plugin ──────────────────────────────────────────────────────────────

class SecurityWriteupCollectorPlugin extends obsidian.Plugin {
    async onload() {
        await this.loadSettings();

        this.addRibbonIcon('shield', 'Security Writeup Collector — Sources', () => new SourcesModal(this.app, this).open());
        this.addRibbonIcon('download', 'Security Writeup Collector — Collect', () => new FetchPreviewModal(this.app, this).open());

        this.addCommand({id:'open-sources',  name:'Open Sources Manager', callback:()=>new SourcesModal(this.app,this).open()});
        this.addCommand({id:'fetch-preview', name:'Collect Writeups (with preview)', callback:()=>new FetchPreviewModal(this.app,this).open()});
        this.addCommand({id:'scan-topic-sources', name:'Scan Topic Sources', callback:()=>{ const modal = new FetchPreviewModal(this.app,this); modal.open(); setTimeout(() => modal.startScan(true), 50); }});
        this.addCommand({id:'open-stats',    name:'View Statistics', callback:()=>new StatsModal(this.app,this).open()});

        this.addSettingTab(new WriteupSettingTab(this.app, this));

        this.statusBarItem = this.addStatusBarItem();
        this.refreshStatusBar();
        this.statusBarItem.onClickEvent(() => new SourcesModal(this.app,this).open());

        if (this.settings.autoFetchOnStartup) {
            this._autoFetchTimer = setTimeout(async () => {
                try {
                    const enabled = this.settings.sources.filter(s=>s.enabled);
                    const seen = new Set((this.settings.seenUrls || []).slice(-3000));
                    let newCount = 0;
                    for (const src of enabled) {
                        try {
                            const items = await fetchFeedItems(src);
                            newCount += items.filter(i => !seen.has(i.link)).length;
                        } catch(e) {}
                    }
                    const topicEnabled = (this.settings.topicSources || []).filter(s => s.enabled);
                    for (const topicSource of topicEnabled) {
                        try {
                            const items = await fetchTopicResults(
                                topicSource,
                                seen,
                                this.settings.topicFolderMap || {},
                                this.settings.outputFolder || 'writeups',
                                { syncHistory: this.settings.topicSyncHistory || {}, respectSchedule: true }
                            );
                            newCount += items.length;
                        } catch(e) {}
                    }
                    await this.saveSettings();
                    if (newCount > 0) {
                        new obsidian.Notice(`🔐 ${newCount} new writeup${newCount!==1?'s':''} available. Open Fetch to download.`);
                    }
                } catch(e) { console.error('SecFeeds: auto-fetch failed:', e); }
            }, 5000);
        }
    }

    onunload() {
        if (this._autoFetchTimer) clearTimeout(this._autoFetchTimer);
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
            try {
                if (!this.app.vault.getAbstractFileByPath(cur)) await this.app.vault.createFolder(cur);
            } catch(e) { /* folder may already exist from concurrent call */ }
        }
    }

    async saveWriteup(baseFolder, item) {
        const filename = safeFilename(item.title);
        // Use topicFolder if available, else build from baseFolder + source
        const sub = item.topicFolder ? item.topicFolder : `${baseFolder}/${slugify(item.source)}`;
        await this.ensureFolder(sub);
        let path = `${sub}/${filename}.md`;
        if (this.app.vault.getFileByPath(path)) {
            path = `${sub}/${filename} (${shortHash(item.url)}).md`;
        }
        if (this.app.vault.getFileByPath(path)) return;
        await this.app.vault.create(path, buildMd(item));
    }

    async updateIndex(folder) {
        const allFiles = this.app.vault.getMarkdownFiles().filter(f=>f.path.startsWith(folder+'/')&&f.name!=='index.md');
        const folderDepth = folder.split('/').length;
        const bySource = {};
        for (const f of allFiles) { const s=f.path.split('/')[folderDepth]||'other'; if(!bySource[s])bySource[s]=[]; bySource[s].push(f); }
        const now = new Date().toLocaleString();
        let c = `---\ntitle: "Security Writeup Collector Index"\ntags: ["index","security"]\nupdated: "${now}"\n---\n\n# 🔐 Security Writeup Collector\n\n> Last updated: ${now} | Total: **${allFiles.length}** writeups\n\n`;
        for (const [src,srcFiles] of Object.entries(bySource)) {
            const label = src.replace(/-/g,' ').replace(/\b\w/g,x=>x.toUpperCase());
            c += `### ${label} (${srcFiles.length})\n\n`;
            srcFiles.slice(-20).reverse().forEach(f=>{c+=`- [[${f.basename}]]\n`;});
            c += '\n';
        }
        c += `---\n## 🏷️ Tags\n\n${ALL_TAGS.map(t=>`\`#${t}\``).join(' ')}\n`;
        const idx = this.app.vault.getAbstractFileByPath(`${folder}/index.md`);
        if (idx) await this.app.vault.modify(idx,c); else await this.app.vault.create(`${folder}/index.md`,c);
    }

    async loadSettings() {
        const saved = (await this.loadData()) || {};
        this.settings = Object.assign({}, DEFAULT_SETTINGS, saved);
        // Deep merge: restore missing default sources by ID
        const defaultIds = new Set(DEFAULT_SETTINGS.sources.map(s => s.id));
        const savedIds = new Set((saved.sources || []).map(s => s.id));
        if (saved.sources) {
            // Keep user's saved sources + add any missing defaults
            const missingSources = DEFAULT_SETTINGS.sources.filter(s => !savedIds.has(s.id));
            this.settings.sources = [...saved.sources, ...missingSources.map(s => ({...s, isBuiltIn: true}))];
        } else {
            this.settings.sources = DEFAULT_SETTINGS.sources.map(s => ({...s, isBuiltIn: true}));
        }
        // Mark built-in sources
        for (const src of this.settings.sources) {
            if (defaultIds.has(src.id)) src.isBuiltIn = true;
        }
        if (!this.settings.seenUrls) this.settings.seenUrls = [];
        if (!this.settings.failedUrls) this.settings.failedUrls = [];
        if (!this.settings.topicSyncHistory || typeof this.settings.topicSyncHistory !== 'object') this.settings.topicSyncHistory = {};
        if (!this.settings.watchlistKeywords) this.settings.watchlistKeywords = [...DEFAULT_SETTINGS.watchlistKeywords];
        if (!this.settings.stats) this.settings.stats = {totalFetched:0,totalFailed:0,bySource:{},byTag:{},byMonth:{}};
        // Deep merge topic sources
        const defaultTopicIds = new Set(DEFAULT_SETTINGS.topicSources.map(s => s.id));
        if (!this.settings.topicSources) {
            this.settings.topicSources = DEFAULT_SETTINGS.topicSources.map(s => ({...normalizeTopicSource(s), isBuiltIn: true}));
        } else {
            const savedTopicIds = new Set(this.settings.topicSources.map(s => s.id));
            const missingTopics = DEFAULT_SETTINGS.topicSources.filter(s => !savedTopicIds.has(s.id));
            this.settings.topicSources = [
                ...this.settings.topicSources.map(s => normalizeTopicSource(s)),
                ...missingTopics.map(s => ({...normalizeTopicSource(s), isBuiltIn: true})),
            ];
        }
        for (const src of this.settings.topicSources) {
            if (defaultTopicIds.has(src.id)) src.isBuiltIn = true;
        }
        // Merge topic folder map (user overrides take priority)
        this.settings.topicFolderMap = Object.assign({}, DEFAULT_SETTINGS.topicFolderMap, this.settings.topicFolderMap || {});
    }
    async saveSettings() { await this.saveData(this.settings); }
}

module.exports = SecurityWriteupCollectorPlugin;
