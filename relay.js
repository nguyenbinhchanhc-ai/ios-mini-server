const express = require('express');
const http = require('http');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const https = require('https');
const WebSocket = require('ws');
const os = require('os');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const CONFIG_PATH = path.join(__dirname, 'dns_config.json');
const SUB_CACHE_PATH = path.join(__dirname, 'subscription_blocklist.txt');
const AI_LEARNED_PATH = path.join(__dirname, 'ai_learned_examples.json');
const AI_CACHE_PATH = path.join(__dirname, 'ai_decision_cache.json');

// State variables
let config = {};
let customBlockedSet = new Set();
let whitelistSet = new Set();
let subscriptionBlockedSet = new Set();
let isUpdatingList = false;
let logs = [];

// WebSocket client registry
const wsClients = new Set();

// AI Learned Examples (Few-Shot In-context training)
let learnedExamples = [];

// Performance Metrics & Local DNS Cache
const dnsCache = new Map(); // Key: domain + '_' + qtype, Value: { responseBuffer, expiresAt }
const MAX_CACHE_SIZE = 15000;
const activeUpstreamQueries = new Map(); // Key: domain + '_' + qtype, Value: Array of waiting client callbacks
const aiDecisionCache = new Map(); // Key: domain, Value: true/false

// Load/Save functions for AI persistence
function loadAILearning() {
    try {
        if (fs.existsSync(AI_LEARNED_PATH)) {
            const data = fs.readFileSync(AI_LEARNED_PATH, 'utf8');
            const list = JSON.parse(data);
            if (Array.isArray(list)) {
                learnedExamples.length = 0;
                list.forEach(ex => {
                    if (ex && typeof ex.domain === 'string') {
                        learnedExamples.push({
                            domain: ex.domain,
                            blocked: !!ex.blocked,
                            reason: ex.reason || "Mối nguy hại"
                        });
                    }
                });
                console.log(`Loaded ${learnedExamples.length} AI learned examples.`);
                return;
            }
        }
    } catch (e) {
        console.error("Failed to load AI learned examples:", e);
    }
    seedDefaultAILearning();
}

function seedDefaultAILearning() {
    const defaults = [
        { domain: "doubleclick.net", blocked: true, reason: "Quảng cáo Google" },
        { domain: "log.tiktokv.com", blocked: true, reason: "Theo dõi TikTok" },
        { domain: "graph.facebook.com/tr", blocked: true, reason: "Facebook Pixel Tracker" },
        { domain: "google-analytics.com", blocked: true, reason: "Theo dõi Google Analytics" },
        { domain: "techcombank-verify.cfd", blocked: true, reason: "Giả mạo Techcombank" },
        { domain: "momo-nhan-qua.xyz", blocked: true, reason: "Lừa đảo Momo" },
        { domain: "shopee-tri-an.top", blocked: true, reason: "Lừa đảo Shopee" },
        { domain: "mbcheck-auth.cc", blocked: true, reason: "Giả mạo MB Bank" },
        { domain: "admicro.vn", blocked: true, reason: "Quảng cáo Việt Nam" },
        { domain: "adtima.vn", blocked: true, reason: "Quảng cáo Zalo/Adtima" },
        { domain: "v3.tiktokcdn.com", blocked: false, reason: "CDN Tiktok Video" },
        { domain: "gateway.fe2.apple-dns.net", blocked: false, reason: "Hệ thống Apple" },
        { domain: "graph.facebook.com", blocked: false, reason: "API Facebook hợp lệ" },
        { domain: "sp.shopee.vn", blocked: false, reason: "Dịch vụ Shopee chính" },
        { domain: "momo.vn", blocked: false, reason: "Dịch vụ ví Momo chính" }
    ];
    learnedExamples.length = 0;
    defaults.forEach(d => learnedExamples.push(d));
    saveAILearning();
}

let lastLearningSaveTimeout = null;
function saveAILearning() {
    if (lastLearningSaveTimeout) return;
    lastLearningSaveTimeout = setTimeout(() => {
        lastLearningSaveTimeout = null;
        try {
            fs.writeFileSync(AI_LEARNED_PATH, JSON.stringify(learnedExamples, null, 2), 'utf8');
        } catch (e) {
            console.error("Failed to save AI learned examples:", e);
        }
    }, 2000);
}

function loadAICache() {
    try {
        if (fs.existsSync(AI_CACHE_PATH)) {
            const data = fs.readFileSync(AI_CACHE_PATH, 'utf8');
            const obj = JSON.parse(data);
            aiDecisionCache.clear();
            for (const [k, v] of Object.entries(obj)) {
                aiDecisionCache.set(k, !!v);
            }
            console.log(`Loaded ${aiDecisionCache.size} domains in AI decision cache.`);
        }
    } catch (e) {
        console.error("Failed to load AI decision cache:", e);
    }
}

let lastCacheSaveTimeout = null;
function saveAICache() {
    if (lastCacheSaveTimeout) return;
    lastCacheSaveTimeout = setTimeout(() => {
        lastCacheSaveTimeout = null;
        try {
            const obj = {};
            for (const [k, v] of aiDecisionCache.entries()) {
                obj[k] = v;
            }
            fs.writeFileSync(AI_CACHE_PATH, JSON.stringify(obj, null, 2), 'utf8');
        } catch (e) {
            console.error("Failed to save AI decision cache:", e);
        }
    }, 5000);
}

// Groq AI Guard Queue Variables
const groqQueue = [];
let activeGroqRequests = 0;
const GROQ_CONCURRENCY_PER_KEY = 5;
let groqKeyIndex = 0;
let isQueuePaused = false;
let queueTimeoutId = null;
const QUEUE_DELAY_MS = 4000;

// Shared Upstream UDP Client Sockets
let upstreamSocket = null;
const pendingRequests = new Map(); // Key: upstreamTxId, Value: { callback, originalIDBytes, timer, timestamp }
let nextTxId = 0;

// Local/Internal Domain Safeguard
const IGNORED_DOMAINS = new Set([
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "0.0.0.0", "127.0.0.1", "::1", "local.host"
]);

let cacheHits = 0;
let cacheMisses = 0;
let totalLatency = 0;
let latencyCount = 0;

// WebSocket connection handler
wss.on('connection', (ws) => {
    wsClients.add(ws);
    
    // Send initial configuration and stats
    try {
        const payload = getWSUpdatePayload();
        ws.send(JSON.stringify(payload));
    } catch (e) {
        console.error("Error sending initial WS state:", e);
    }

    ws.on('close', () => {
        wsClients.delete(ws);
    });
    
    ws.on('error', (err) => {
        console.error("WS client error:", err);
        wsClients.delete(ws);
    });
});

function broadcastUpdate() {
    if (wsClients.size === 0) return;
    try {
        const payload = getWSUpdatePayload();
        const data = JSON.stringify(payload);
        for (const ws of wsClients) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(data);
            }
        }
    } catch (e) {
        console.error("Error broadcasting WS update:", e);
    }
}

function getServerStatus() {
    const memUsage = process.memoryUsage().heapUsed; // bytes
    const memUsageMb = Math.round(memUsage / 1024 / 1024);
    const avgLat = latencyCount > 0 ? (totalLatency / latencyCount) : 0;
    
    let status = "Ổn định";
    let statusClass = "stable"; // stable, warning, overloaded
    
    if (memUsageMb > 400 || avgLat > 250) {
        status = "Quá tải";
        statusClass = "overloaded";
    } else if (memUsageMb > 250 || avgLat > 120) {
        status = "Tải cao";
        statusClass = "warning";
    }
    
    return {
        status,
        statusClass,
        memoryUsage: memUsageMb,
        memoryLimit: 512,
        cpuLoad: Math.round(os.loadavg()[0] * 100) / 100
    };
}

function getWSUpdatePayload() {
    const blocked = Array.from(customBlockedSet);
    const whitelist = Array.from(whitelistSet);
    const subscriptions = config.subscriptionURLs || [];
    const upstream = config.upstreamDNS || "1.1.1.1";
    const isUpdating = isUpdatingList;
    const stats = {
        total: config.stats.total,
        blocked: config.stats.blocked,
        allowed: config.stats.allowed,
        blockedPercent: config.stats.total > 0 ? (config.stats.blocked / config.stats.total * 100) : 0,
        cacheHitRate: (cacheHits + cacheMisses) > 0 ? (cacheHits / (cacheHits + cacheMisses) * 100) : 0,
        avgLatency: latencyCount > 0 ? (totalLatency / latencyCount) : 0
    };
    return {
        type: 'update',
        running: true,
        blocked: blocked,
        blockedCount: customBlockedSet.size + subscriptionBlockedSet.size,
        whitelist: whitelist,
        subscriptions: subscriptions,
        upstream: upstream,
        logs: logs,
        stats: stats,
        isUpdating: isUpdating,
        aiEnabled: !!config.aiEnabled,
        groqApiKeys: (config.groqApiKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqApiKeysCount: (config.groqApiKeys || []).length,
        groqModel: config.groqModel || "llama-3.3-70b-versatile",
        groqMaxConcurrent: (config.groqApiKeys || []).length * GROQ_CONCURRENCY_PER_KEY,
        learnedExamples: learnedExamples,
        aiCacheCount: aiDecisionCache.size,
        aiQueueLength: groqQueue.length,
        activeGroqRequests: activeGroqRequests,
        serverStatus: getServerStatus()
    };
}

// Load config and caches
loadConfig();
loadAILearning();
loadAICache();

// Load the blocklists on startup
setTimeout(() => {
    if (subscriptionBlockedSet.size === 0) {
        updateBlocklists();
    }
}, 2000);

// Raw body parser middleware for DNS binary payloads
app.use((req, res, next) => {
    const data = [];
    req.on('data', chunk => data.push(chunk));
    req.on('end', () => {
        req.rawBody = Buffer.concat(data);
        next();
    });
});

// Serve static dashboard web page
app.use(express.static(path.join(__dirname, 'public')));

// MARK: - DNS Configuration & Cache Load/Save

function loadConfig() {
    const defaultSubs = [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        "https://v.firebog.net/hosts/AdguardDNS.txt",
        "https://v.firebog.net/hosts/Easyprivacy.txt",
        "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        "https://v.firebog.net/hosts/Prigent-Crypto.txt",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        "https://small.oisd.nl",
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts"
    ];

    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const data = fs.readFileSync(CONFIG_PATH, 'utf8');
            config = JSON.parse(data);
        } else {
            config = {
                customBlockedDomains: [
                    "doubleclick.net",
                    "pagead2.googlesyndication.com",
                    "adservice.google.com",
                    "ads.youtube.com",
                    "telemetry.apple.com",
                    "app-measurement.com"
                ],
                whitelistDomains: [],
                subscriptionURLs: defaultSubs,
                upstreamDNS: "1.1.1.1",
                stats: { total: 0, blocked: 0, allowed: 0 },
                aiEnabled: false,
                groqApiKeys: [],
                groqModel: "llama-3.3-70b-versatile"
            };
            saveConfig();
        }
    } catch (e) {
        console.error("Failed to load config, using defaults:", e);
        config = {
            customBlockedDomains: [
                "doubleclick.net",
                "pagead2.googlesyndication.com",
                "adservice.google.com",
                "ads.youtube.com",
                "telemetry.apple.com",
                "app-measurement.com"
            ],
            whitelistDomains: [],
            subscriptionURLs: defaultSubs,
            upstreamDNS: "1.1.1.1",
            stats: { total: 0, blocked: 0, allowed: 0 },
            aiEnabled: false,
            groqApiKeys: [],
            groqModel: "llama-3.3-70b-versatile"
        };
    }
    
    // Ensure all variables are fully seeded
    config.aiEnabled = config.aiEnabled || false;
    config.groqModel = "llama-3.3-70b-versatile"; // Enforce 70B model only
    // Migrate legacy single key to array
    if (config.groqApiKey && !config.groqApiKeys) {
        config.groqApiKeys = [config.groqApiKey];
        delete config.groqApiKey;
    }
    if (!Array.isArray(config.groqApiKeys)) {
        config.groqApiKeys = [];
    }
    config.groqApiKeys = config.groqApiKeys.filter(k => k && k.trim().length > 0);
    if (!config.subscriptionURLs || config.subscriptionURLs.length <= 1) {
        config.subscriptionURLs = defaultSubs;
    }
    
    // Automatically inject BigDargon Vietnam host list if not present
    const vnList = "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts";
    if (!config.subscriptionURLs.includes(vnList)) {
        config.subscriptionURLs.push(vnList);
        saveConfig();
    }
    
    customBlockedSet = new Set(config.customBlockedDomains.map(d => d.toLowerCase()));
    whitelistSet = new Set(config.whitelistDomains.map(d => d.toLowerCase()));
    
    // Load cached blocklists if available
    loadSubscriptionBlocklistFromDisk();
}

function saveConfig() {
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (e) {
        console.error("Failed to save config:", e);
    }
}

function saveSubscriptionBlocklistToDisk() {
    try {
        const data = Array.from(subscriptionBlockedSet).join('\n');
        fs.writeFileSync(SUB_CACHE_PATH, data, 'utf8');
    } catch (e) {
        console.error("Failed to save cached subscription blocklist:", e);
    }
}

function loadSubscriptionBlocklistFromDisk() {
    try {
        if (fs.existsSync(SUB_CACHE_PATH)) {
            const data = fs.readFileSync(SUB_CACHE_PATH, 'utf8');
            const domains = data.split('\n').map(d => d.trim().toLowerCase()).filter(d => d.length > 0);
            subscriptionBlockedSet = new Set(domains);
            console.log(`Loaded ${subscriptionBlockedSet.size} cached subscription domains.`);
        }
    } catch (e) {
        console.error("Failed to load cached subscription blocklist:", e);
    }
}

// MARK: - Local DNS Cache

function checkCache(domain, qtype) {
    const key = `${domain.toLowerCase()}_${qtype}`;
    const cached = dnsCache.get(key);
    if (cached) {
        if (Date.now() < cached.expiresAt) {
            cacheHits++;
            // Move to end of Map (most recently used) to preserve LRU order
            dnsCache.delete(key);
            dnsCache.set(key, cached);
            return cached.responseBuffer;
        } else {
            dnsCache.delete(key);
        }
    }
    cacheMisses++;
    return null;
}

function setCache(domain, qtype, responseBuffer, ttl) {
    const minTtl = 60; // Enforce 60 seconds minimum cache TTL
    const finalTtl = ttl < minTtl ? minTtl : ttl;
    const key = `${domain.toLowerCase()}_${qtype}`;
    if (dnsCache.has(key)) {
        dnsCache.delete(key);
    } else if (dnsCache.size >= MAX_CACHE_SIZE) {
        const oldestKey = dnsCache.keys().next().value;
        if (oldestKey) {
            dnsCache.delete(oldestKey);
        }
    }
    dnsCache.set(key, {
        responseBuffer: responseBuffer,
        expiresAt: Date.now() + (finalTtl * 1000)
    });
}

// MARK: - DNS Packet Parsers & Builders

function parseDNSQuery(buffer) {
    if (buffer.length < 12) return null;
    
    let domainParts = [];
    let offset = 12;
    
    while (offset < buffer.length) {
        let len = buffer[offset];
        if (len === 0) {
            offset += 1;
            break;
        }
        
        // Handle DNS compression pointers
        if ((len & 0xC0) === 0xC0) {
            offset += 2;
            break;
        }
        
        offset += 1;
        if (offset + len > buffer.length) {
            return null;
        }
        
        let part = buffer.toString('utf8', offset, offset + len);
        domainParts.push(part);
        offset += len;
    }
    
    const domain = domainParts.join('.');
    if (offset + 4 > buffer.length) {
        return null;
    }
    
    const qtype = buffer.readUInt16BE(offset);
    const qclass = buffer.readUInt16BE(offset + 2);
    
    return {
        domain: domain,
        qtype: qtype,
        qclass: qclass,
        questionEndOffset: offset
    };
}

function buildBlockResponse(queryBuffer, questionEndOffset) {
    const header = Buffer.alloc(12);
    // Copy transaction ID
    queryBuffer.copy(header, 0, 0, 2);
    // Flags: 0x8180 (Standard response, no error)
    header.writeUInt16BE(0x8180, 2);
    // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(1, 6);
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(0, 10);
    
    // Copy the question from the query
    const questionLength = (questionEndOffset + 4) - 12;
    const question = Buffer.alloc(questionLength);
    queryBuffer.copy(question, 0, 12, questionEndOffset + 4);
    
    // Answer block pointing back to the query name (offset 12), Type A, Class IN, TTL 300, Length 4, IP 0.0.0.0
    const answer = Buffer.alloc(16);
    answer.writeUInt16BE(0xc00c, 0); // Name pointer to question
    answer.writeUInt16BE(1, 2);      // Type A
    answer.writeUInt16BE(1, 4);      // Class IN
    answer.writeUInt32BE(300, 6);    // TTL 300 seconds
    answer.writeUInt16BE(4, 10);     // Data length = 4
    answer.writeUInt32BE(0, 12);     // IP Address = 0.0.0.0
    
    return Buffer.concat([header, question, answer]);
}

function extractTTL(responseBuffer, questionEndOffset) {
    try {
        let offset = questionEndOffset + 4; // Start of Answer Section
        if (offset + 10 > responseBuffer.length) return 300;
        
        let nameByte = responseBuffer[offset];
        if ((nameByte & 0xC0) === 0xC0) {
            offset += 2; // Pointer
        } else {
            while (offset < responseBuffer.length) {
                let len = responseBuffer[offset];
                if (len === 0) {
                    offset += 1;
                    break;
                }
                if ((len & 0xC0) === 0xC0) {
                    offset += 2;
                    break;
                }
                offset += 1 + len;
            }
        }
        
        if (offset + 8 > responseBuffer.length) return 300;
        
        const ttl = responseBuffer.readUInt32BE(offset + 4);
        return ttl > 0 ? ttl : 300;
    } catch (e) {
        return 300;
    }
}

// MARK: - Ad-Blocking Tra cứu (Optimized O(K))

function hasDomainOrParent(set, domain) {
    if (set.has(domain)) return true;
    let idx = domain.indexOf('.');
    while (idx !== -1) {
        const parent = domain.substring(idx + 1);
        if (set.has(parent)) return true;
        idx = domain.indexOf('.', idx + 1);
    }
    return false;
}

function shouldBlock(domain) {
    const lowercaseDomain = domain.toLowerCase();
    
    // 0. Safeguard: Local / internal networks are allowed
    if (IGNORED_DOMAINS.has(lowercaseDomain)) return false;
    if (lowercaseDomain.endsWith('.local') || lowercaseDomain.endsWith('.localhost')) return false;
    
    // 1. Whitelist Check (exact or parent subdomain)
    if (hasDomainOrParent(whitelistSet, lowercaseDomain)) return false;
    
    // 2. Custom Blocklist Check
    if (hasDomainOrParent(customBlockedSet, lowercaseDomain)) return true;
    
    // 3. Subscription Blocklist Check
    if (hasDomainOrParent(subscriptionBlockedSet, lowercaseDomain)) return true;
    
    return false;
}

// MARK: - Upstream DNS Resolver (UDP) and Deduplication

function initUpstreamSocket() {
    if (upstreamSocket) return;
    
    upstreamSocket = dgram.createSocket('udp4');
    
    upstreamSocket.on('message', (msg) => {
        if (msg.length < 2) return;
        const txId = msg.readUInt16BE(0);
        const req = pendingRequests.get(txId);
        if (req) {
            pendingRequests.delete(txId);
            if (req.timer) clearTimeout(req.timer);
            
            // Restore original client Transaction ID
            const clientResponse = Buffer.from(msg);
            clientResponse[0] = req.originalIDBytes[0];
            clientResponse[1] = req.originalIDBytes[1];
            
            req.callback(clientResponse);
        }
    });
    
    upstreamSocket.on('error', (err) => {
        console.error("Shared upstream UDP socket error:", err);
        try {
            upstreamSocket.close();
        } catch (e) {}
        upstreamSocket = null;
        // Delay re-initialization slightly to avoid tight loop
        setTimeout(initUpstreamSocket, 1000);
    });
}

function queryUpstream(dnsQueryBuffer, upstreamIP, callback) {
    initUpstreamSocket();
    
    if (!upstreamSocket) {
        callback(null);
        return;
    }
    
    // Find a free Tx ID
    let txId = nextTxId;
    let attempts = 0;
    while (pendingRequests.has(txId) && attempts < 65536) {
        txId = (txId + 1) % 65536;
        attempts++;
    }
    nextTxId = (txId + 1) % 65536;
    
    const originalIDBytes = Buffer.from([dnsQueryBuffer[0], dnsQueryBuffer[1]]);
    
    // Clone the buffer so we don't modify the client's query buffer in-place
    const upstreamQueryBuffer = Buffer.from(dnsQueryBuffer);
    // Write the new transaction ID
    upstreamQueryBuffer.writeUInt16BE(txId, 0);
    
    const timer = setTimeout(() => {
        const req = pendingRequests.get(txId);
        if (req) {
            pendingRequests.delete(txId);
            callback(null);
        }
    }, 4000); // 4 seconds query timeout
    
    pendingRequests.set(txId, {
        callback,
        originalIDBytes,
        timer,
        timestamp: Date.now()
    });
    
    upstreamSocket.send(upstreamQueryBuffer, 0, upstreamQueryBuffer.length, 53, upstreamIP, (err) => {
        if (err) {
            console.error(`Failed to send DNS request to upstream ${upstreamIP}:`, err);
            const req = pendingRequests.get(txId);
            if (req) {
                pendingRequests.delete(txId);
                clearTimeout(timer);
                callback(null);
            }
        }
    });
}

function fetchFromUpstreamDeduplicated(queryData, domain, qtype, upstreamDNS, callback) {
    const key = `${domain.toLowerCase()}_${qtype}`;
    const originalIDBytes = Buffer.from([queryData[0], queryData[1]]);
    
    if (activeUpstreamQueries.has(key)) {
        activeUpstreamQueries.get(key).push({ callback, originalIDBytes });
        return;
    }
    
    activeUpstreamQueries.set(key, [{ callback, originalIDBytes }]);
    
    queryUpstream(queryData, upstreamDNS, (response) => {
        const queue = activeUpstreamQueries.get(key) || [];
        activeUpstreamQueries.delete(key);
        
        queue.forEach(item => {
            if (response && response.length >= 2) {
                const clientResponse = Buffer.from(response);
                clientResponse[0] = item.originalIDBytes[0];
                clientResponse[1] = item.originalIDBytes[1];
                item.callback(clientResponse);
            } else {
                item.callback(null);
            }
        });
    });
}

// MARK: - Groq AI Security Guard

function getNextGroqKey() {
    const keys = config.groqApiKeys;
    if (!keys || keys.length === 0) return null;
    const key = keys[groqKeyIndex % keys.length];
    groqKeyIndex = (groqKeyIndex + 1) % keys.length;
    return key;
}

function getMaxConcurrentGroq() {
    const keys = config.groqApiKeys;
    if (!keys || keys.length === 0) return 0;
    return keys.length * GROQ_CONCURRENCY_PER_KEY;
}

// Famous safe networks/systems that do not need AI scanning to conserve tokens
const SAFE_DOMAINS_SUFFIXES = [
    ".google.com", ".googleapis.com", ".gstatic.com", ".googleusercontent.com",
    ".apple.com", ".icloud.com", ".mzstatic.com", ".apple-dns.net", ".itunes.com", ".itunes.apple.com",
    ".microsoft.com", ".windows.com", ".live.com", ".office.com", ".msn.com", ".windows.net", ".windowsupdate.com",
    ".cloudflare.com", ".cloudflare-dns.com",
    ".facebook.com", ".fbcdn.net", ".instagram.com",
    ".youtube.com", ".ytimg.com", ".ggpht.com",
    ".netflix.com", ".nflxext.com", ".nflximg.net", ".nflxvideo.net",
    ".tiktok.com", ".tiktokcdn.com", ".byteoversea.com",
    ".github.com", ".githubusercontent.com",
    ".wikipedia.org", ".wikimedia.org",
    ".zalo.me", ".zaloapp.com", ".zalopay.vn",
    ".momo.vn",
    // Major CDNs
    ".akamai.net", ".akamaihd.net", ".akamaized.net", ".edgesuite.net", ".edgekey.net",
    ".cloudfront.net", ".fastly.net", ".map.fastly.net",
    // Safe services
    ".twimg.com", ".t.co", ".spotify.com", ".scdn.co", ".discord.gg", ".discordapp.com", ".discordapp.net", ".zoom.us",
    // Safe Vietnamese Banks
    ".vietcombank.com.vn", ".bidv.com.vn", ".techcombank.com.vn", ".vietinbank.vn", ".sacombank.com.vn", ".agribank.com.vn"
];

function isSafeDomain(domain) {
    const d = domain.trim().toLowerCase();
    const exactMatches = [
        "google.com", "apple.com", "microsoft.com", "cloudflare.com",
        "facebook.com", "youtube.com", "netflix.com", "tiktok.com",
        "github.com", "wikipedia.org", "zalo.me", "momo.vn"
    ];
    if (exactMatches.includes(d)) return true;
    
    for (const suffix of SAFE_DOMAINS_SUFFIXES) {
        if (d.endsWith(suffix)) return true;
    }
    return false;
}

function enqueueGroqCheck(domain) {
    const d = domain.trim().toLowerCase();
    if (!d || d.includes('localhost') || d.includes('127.0.0.1') || IGNORED_DOMAINS.has(d)) return;
    if (d.endsWith('.local') || d.endsWith('.localhost')) return;
    if (aiDecisionCache.has(d)) return;
    if (whitelistSet.has(d)) return;
    
    // 1. Skip if already blocked by our blocklists
    if (shouldBlock(d)) {
        aiDecisionCache.set(d, true);
        saveAICache();
        return;
    }
    
    // 2. Skip if it is a well-known safe domain
    if (isSafeDomain(d)) {
        aiDecisionCache.set(d, false);
        saveAICache();
        return;
    }
    
    if (!config.groqApiKeys || config.groqApiKeys.length === 0) return;
    
    // Mark as scanned immediately to avoid duplicate queue insertions
    aiDecisionCache.set(d, false);
    
    groqQueue.push(d);
    processGroqQueue();
}

function processGroqQueue() {
    if (isQueuePaused) return;
    
    const maxConcurrent = getMaxConcurrentGroq();
    if (activeGroqRequests >= maxConcurrent || groqQueue.length === 0) return;
    
    if (queueTimeoutId) return;
    
    const domain = groqQueue.shift();
    activeGroqRequests++;
    
    const apiKey = getNextGroqKey();
    checkDomainWithGroq(domain, apiKey, () => {
        activeGroqRequests--;
        processGroqQueue();
    });
    
    // Schedule the next check after QUEUE_DELAY_MS to space out queries sequentially
    queueTimeoutId = setTimeout(() => {
        queueTimeoutId = null;
        processGroqQueue();
    }, QUEUE_DELAY_MS);
}

function checkDomainWithGroq(domain, apiKey, callback) {
    if (!apiKey) {
        aiDecisionCache.delete(domain);
        if (callback) callback();
        return;
    }
    const model = "llama-3.3-70b-versatile";
    
    console.log(`[AI Guard] Scanning domain: ${domain} via Groq (Llama 3.3 70B)...`);
    
    // Select exactly 4 dynamic examples (2 blocked, 2 allowed) to keep prompt size small (~350 tokens) and prevent 429 TPM exhaustion
    const blockedEx = learnedExamples.filter(ex => ex.blocked === true).slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.blocked === false).slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"blocked": ${ex.blocked}, "reason": "${ex.reason}"}`).join('\n');

    const systemContent = "You are a DNS Firewall security expert. Classify the domain name. Analyze if it is used for tracking, advertising, telemetry, phishing, malware, scam, or other harmful activities.\n\n" +
                          "Strict Rules:\n" +
                          "1. Block: trackers, advertising, telemetry, analytics, scams, malware, phishing (especially fake brands, fake banks, fake government sites targeting Vietnamese users).\n" +
                          "2. Allow: CDNs, media streams, API services, official app backends, static assets, and essential services (e.g. *.tiktokcdn.com, *.fbcdn.net, *.akamai.net are allowed CDNs; but log.tiktokv.com, graph.facebook.com/tr, ads.youtube.com are blocked trackers/ads).\n" +
                          "3. Watch out for Typosquatting/Phishing: If the domain contains a famous brand (like techcombank, shopee, momo, mbcheck, apple-dns, bidv, vietcombank, sacombank, facebook) but looks suspicious or uses a cheap/non-standard TLD (like .cfd, .xyz, .cc, .top, .site, .icu, .vip, .win, .online, .tech, .click), block it.\n" +
                          "4. Watch out for ad networks and trackers in Vietnam: e.g. admicro, eclick, adtima, ants, yomedia, ad.gonet.vn, and other telemetry/tracking subdomains.\n" +
                          "5. Allow legitimate primary domains and their structural subdomains (e.g. static assets, images, logins) unless they are explicitly ad servers.\n" +
                          "6. Respond in strict JSON: { \"blocked\": true/false, \"reason\": \"1-3 words in Vietnamese\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: model,
        messages: [
            {
                role: "system",
                content: systemContent
            },
            {
                role: "user",
                content: `Analyze this domain: ${domain}`
            }
        ],
        response_format: { type: "json_object" }
    });
    
    const options = {
        hostname: 'api.groq.com',
        port: 443,
        path: '/openai/v1/chat/completions',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
            'Content-Length': Buffer.byteLength(postData)
        }
    };
    
    let completed = false;
    const done = () => {
        if (!completed) {
            completed = true;
            callback();
        }
    };
    
    try {
        const req = https.request(options, (res) => {
            let body = [];
            res.on('data', chunk => body.push(chunk));
            res.on('end', () => {
                try {
                    if (res.statusCode !== 200) {
                        if (res.statusCode === 429) {
                            console.warn(`[AI Guard] Rate limit hit (429) for ${domain}. Pausing AI queue for 60s...`);
                            isQueuePaused = true;
                            // Re-insert at the beginning of the queue if not already there
                            if (!groqQueue.includes(domain)) {
                                groqQueue.unshift(domain);
                            }
                            aiDecisionCache.delete(domain);
                            
                            if (queueTimeoutId) clearTimeout(queueTimeoutId);
                            queueTimeoutId = setTimeout(() => {
                                isQueuePaused = false;
                                queueTimeoutId = null;
                                console.log("[AI Guard] Resuming AI queue after rate limit cooldown.");
                                processGroqQueue();
                            }, 60000); // 60 seconds cooldown
                        } else {
                            console.error(`[AI Guard] Groq returned status ${res.statusCode}`);
                            aiDecisionCache.delete(domain);
                        }
                        done();
                        return;
                    }
                    
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        if (decision.blocked === true) {
                            aiDecisionCache.set(domain, true);
                            saveAICache(); // Save AI classification cache to disk
                            console.log(`[AI Guard] Groq classified ${domain} as BLOCKED. Reason: ${decision.reason}`);
                            
                            // Auto block the domain
                            customBlockedSet.add(domain);
                            config.customBlockedDomains = Array.from(customBlockedSet);
                            
                            // Retroactively adjust stats: convert 1 allowed to blocked
                            config.stats.blocked += 1;
                            if (config.stats.allowed > 0) {
                                config.stats.allowed -= 1;
                            }
                            saveConfig();
                            
                            // Learn from this block dynamically
                            learnedExamples.push({ domain, blocked: true, reason: decision.reason || "Mối nguy hại" });
                            if (learnedExamples.length > 50) {
                                learnedExamples.shift();
                            }
                            saveAILearning(); // Save AI dynamic learning log to disk
                            
                            logQuery(domain, true, "AI Guard (Auto Blocked)", "blocked");
                        } else {
                            aiDecisionCache.set(domain, false);
                            saveAICache(); // Save AI classification cache to disk
                            console.log(`[AI Guard] Groq classified ${domain} as ALLOWED.`);
                            
                            // Learn from this allowed domain dynamically
                            learnedExamples.push({ domain, blocked: false, reason: decision.reason || "CDN / Hợp lệ" });
                            if (learnedExamples.length > 50) {
                                learnedExamples.shift();
                            }
                            saveAILearning(); // Save AI dynamic learning log to disk
                            
                            broadcastUpdate();
                        }
                    } else {
                        aiDecisionCache.delete(domain);
                    }
                } catch (e) {
                    console.error("[AI Guard] Failed to parse Groq response:", e);
                    aiDecisionCache.delete(domain);
                }
                done();
            });
        });
        
        req.on('error', (e) => {
            console.error("[AI Guard] Groq API error:", e);
            aiDecisionCache.delete(domain);
            done();
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        console.error("[AI Guard] Groq API request exception:", e);
        aiDecisionCache.delete(domain);
        done();
    }
}

// MARK: - Logs and Stats Logging

function logQuery(domain, blocked, clientIP, source = "upstream") {
    const now = new Date();
    // Vietnam timezone (UTC+7)
    const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
    const timeStr = vnTime.toISOString().substring(11, 19); // HH:mm:ss
    
    let statusText = "✅ ALLOWED";
    if (blocked) {
        statusText = "❌ BLOCKED";
    } else if (source === "cache") {
        statusText = "⚡ CACHED";
    }
    
    const msg = `[${timeStr}] [${clientIP}] ${statusText} - ${domain}`;
    
    logs.push(msg);
    if (logs.length > 100) {
        logs.shift();
    }
    broadcastUpdate(); // Instant real-time UI updates
}

let lastSaveTimeout = null;
function incrementStats(blocked) {
    config.stats.total += 1;
    if (blocked) {
        config.stats.blocked += 1;
    } else {
        config.stats.allowed += 1;
    }
    
    // Throttle config writes to once every 5 seconds under heavy load
    if (!lastSaveTimeout) {
        lastSaveTimeout = setTimeout(() => {
            lastSaveTimeout = null;
            saveConfig();
        }, 5000);
    }
}

// MARK: - Subscription Sync and Parsers

function updateBlocklists(callback) {
    if (isUpdatingList) {
        if (callback) callback();
        return;
    }
    isUpdatingList = true;
    broadcastUpdate(); // Instant real-time UI notification
    console.log("Starting blocklist subscription sync sequentially to preserve memory...");
    
    const urls = config.subscriptionURLs || [];
    let newBlocked = new Set();
    let index = 0;
    
    if (urls.length === 0) {
        isUpdatingList = false;
        broadcastUpdate();
        if (callback) callback();
        return;
    }
    
    function downloadNext() {
        if (index >= urls.length) {
            isUpdatingList = false;
            if (newBlocked.size > 0) {
                subscriptionBlockedSet = newBlocked;
                saveSubscriptionBlocklistToDisk();
            }
            console.log(`Sync completed. Total active rules: ${subscriptionBlockedSet.size}`);
            broadcastUpdate();
            if (callback) callback();
            return;
        }
        
        const urlString = urls[index];
        console.log(`[Sync] Downloading ${index + 1}/${urls.length}: ${urlString}...`);
        downloadURL(urlString, (content) => {
            if (content) {
                const lines = content.split(/\r?\n/);
                let parsedCount = 0;
                lines.forEach(line => {
                    let trimmed = line.trim();
                    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) {
                        return;
                    }
                    
                    let parts = trimmed.split(/\s+/);
                    if (parts.length >= 2) {
                        let ip = parts[0];
                        let domain = parts[1].toLowerCase();
                        if ((ip === "0.0.0.0" || ip === "127.0.0.1") && isValidDomain(domain)) {
                            if (!IGNORED_DOMAINS.has(domain) && !domain.endsWith('.local') && !domain.endsWith('.localhost')) {
                                newBlocked.add(domain);
                                parsedCount++;
                            }
                        }
                    } else if (parts.length === 1) {
                        let domain = parts[0].toLowerCase();
                        if (domain.startsWith('||') && domain.endsWith('^')) {
                            domain = domain.substring(2, domain.length - 1);
                        }
                        if (isValidDomain(domain)) {
                            if (!IGNORED_DOMAINS.has(domain) && !domain.endsWith('.local') && !domain.endsWith('.localhost')) {
                                newBlocked.add(domain);
                                parsedCount++;
                            }
                        }
                    }
                });
                console.log(`[Sync] Successfully parsed ${parsedCount} domains from ${urlString}`);
            } else {
                console.error(`[Sync] Failed to download or parse from ${urlString}`);
            }
            
            index++;
            // Yield execution to allow garbage collection and event processing
            setTimeout(downloadNext, 100);
        });
    }
    
    downloadNext();
}

function downloadURL(urlString, callback) {
    const fetch = (targetUrl) => {
        try {
            const req = https.get(targetUrl, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    // Follow redirects (like raw.githubusercontent.com)
                    fetch(res.headers.location);
                    return;
                }
                
                if (res.statusCode !== 200) {
                    console.error(`Failed to download ${targetUrl}, Status: ${res.statusCode}`);
                    callback(null);
                    return;
                }
                
                let data = [];
                res.on('data', chunk => data.push(chunk));
                res.on('end', () => {
                    callback(Buffer.concat(data).toString('utf8'));
                });
            });
            
            req.on('error', (err) => {
                console.error(`Error downloading ${targetUrl}:`, err);
                callback(null);
            });
            
            req.end();
        } catch (e) {
            console.error(`Exception during download from ${targetUrl}:`, e);
            callback(null);
        }
    };
    
    fetch(urlString);
}

function isValidDomain(domain) {
    const domainRegEx = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$/;
    return domainRegEx.test(domain);
}

// MARK: - DNS-over-HTTPS (DoH) Route Handler

function handleDoH(queryData, clientIP, hostHeader, callback) {
    const startTime = Date.now();
    
    const parsed = parseDNSQuery(queryData);
    if (!parsed) {
        callback(Buffer.alloc(0));
        return;
    }
    
    const originalDomain = parsed.domain;
    const qtype = parsed.qtype;
    
    // Clean domain by removing local and host-header search suffixes
    let domain = originalDomain.trim().toLowerCase();
    if (hostHeader) {
        const host = hostHeader.toLowerCase().split(':')[0];
        if (host && host !== 'localhost' && host !== '127.0.0.1') {
            const suffix = '.' + host;
            if (domain.endsWith(suffix) && domain.length > suffix.length) {
                domain = domain.substring(0, domain.length - suffix.length);
            }
        }
    }
    const commonSuffixes = ['.onrender.com', '.lan', '.localdomain', '.home', '.corp', '.internal', '.home.arpa'];
    for (const suf of commonSuffixes) {
        if (domain.endsWith(suf) && domain.length > suf.length) {
            domain = domain.substring(0, domain.length - suf.length);
            break;
        }
    }
    
    const isBlocked = shouldBlock(domain);
    
    const completeQuery = (responseBuffer, fromCache = false, isBlockedQuery = false) => {
        const latency = Date.now() - startTime;
        totalLatency += latency;
        latencyCount++;
        
        // Log both clean and original domain for better transparency
        const logDomain = (domain !== originalDomain) ? `${domain} (${originalDomain})` : domain;
        const source = isBlockedQuery ? "blocked" : (fromCache ? "cache" : "upstream");
        logQuery(logDomain, isBlockedQuery, clientIP, source);
        incrementStats(isBlockedQuery);
        
        callback(responseBuffer);
        
        // Trigger background AI Guard check for ALL domains (blocked or not, cached or not)
        if (config.aiEnabled && config.groqApiKeys && config.groqApiKeys.length > 0) {
            enqueueGroqCheck(domain);
        }
    };
    
    if (isBlocked) {
        const blockResponse = buildBlockResponse(queryData, parsed.questionEndOffset);
        completeQuery(blockResponse, false, true);
    } else {
        // 1. Check local memory DNS Cache using originalDomain to ensure matching transaction name
        const cachedResponse = checkCache(originalDomain, qtype);
        if (cachedResponse) {
            // Rewrite transaction ID
            const clientResponse = Buffer.from(cachedResponse);
            clientResponse[0] = queryData[0];
            clientResponse[1] = queryData[1];
            completeQuery(clientResponse, true, false);
        } else {
            // 2. Fetch using Upstream request coalescing
            fetchFromUpstreamDeduplicated(queryData, originalDomain, qtype, config.upstreamDNS, (response) => {
                if (response) {
                    const ttl = extractTTL(response, parsed.questionEndOffset);
                    setCache(originalDomain, qtype, response, ttl);
                    completeQuery(response, false, false);
                } else {
                    completeQuery(Buffer.alloc(0), false, false);
                }
            });
        }
    }
}

// DoH POST endpoint
app.post('/dns-query', (req, res) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || req.ip;
    const queryData = req.rawBody;
    if (!queryData || queryData.length === 0) {
        res.status(400).send("Bad Request: Empty binary payload");
        return;
    }
    
    handleDoH(queryData, clientIP, req.headers.host, (responseData) => {
        res.setHeader('Content-Type', 'application/dns-message');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(responseData);
    });
});

// DoH GET endpoint
app.get('/dns-query', (req, res) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || req.ip;
    const dnsParam = req.query.dns;
    if (!dnsParam) {
        res.status(400).send("Bad Request: Missing 'dns' parameter");
        return;
    }
    
    // Decode base64url to Buffer
    let base64 = dnsParam
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const mod = base64.length % 4;
    if (mod > 0) {
        base64 += "=".repeat(4 - mod);
    }
    
    const queryData = Buffer.from(base64, 'base64');
    
    handleDoH(queryData, clientIP, req.headers.host, (responseData) => {
        res.setHeader('Content-Type', 'application/dns-message');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(responseData);
    });
});

// MARK: - Dashboard Config and API Endpoints

app.get('/dns/config', (req, res) => {
    const blocked = Array.from(customBlockedSet);
    const whitelist = Array.from(whitelistSet);
    const subscriptions = config.subscriptionURLs || [];
    const upstream = config.upstreamDNS || "1.1.1.1";
    const isUpdating = isUpdatingList;
    
    const stats = {
        total: config.stats.total,
        blocked: config.stats.blocked,
        allowed: config.stats.allowed,
        blockedPercent: config.stats.total > 0 ? (config.stats.blocked / config.stats.total * 100) : 0,
        cacheHitRate: (cacheHits + cacheMisses) > 0 ? (cacheHits / (cacheHits + cacheMisses) * 100) : 0,
        avgLatency: latencyCount > 0 ? (totalLatency / latencyCount) : 0
    };
    
    res.json({
        running: true,
        blocked: blocked,
        blockedCount: customBlockedSet.size + subscriptionBlockedSet.size,
        whitelist: whitelist,
        subscriptions: subscriptions,
        upstream: upstream,
        logs: logs,
        stats: stats,
        isUpdating: isUpdating,
        aiEnabled: !!config.aiEnabled,
        groqApiKeys: (config.groqApiKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqApiKeysCount: (config.groqApiKeys || []).length,
        groqModel: config.groqModel || "llama-3.3-70b-versatile",
        groqMaxConcurrent: (config.groqApiKeys || []).length * GROQ_CONCURRENCY_PER_KEY,
        learnedExamples: learnedExamples,
        serverStatus: getServerStatus()
    });
});

app.post('/dns/block', (req, res) => {
    const domain = req.query.domain;
    if (domain) {
        const d = domain.trim().toLowerCase();
        if (d) {
            customBlockedSet.add(d);
            config.customBlockedDomains = Array.from(customBlockedSet);
            saveConfig();
            broadcastUpdate();
            res.send(`Blocked ${d}`);
        } else {
            res.status(400).send("Invalid Domain");
        }
    } else {
        res.status(400).send("Missing domain parameter");
    }
});

app.post('/dns/unblock', (req, res) => {
    const domain = req.query.domain;
    if (domain) {
        const d = domain.trim().toLowerCase();
        customBlockedSet.delete(d);
        config.customBlockedDomains = Array.from(customBlockedSet);
        saveConfig();
        broadcastUpdate();
        res.send(`Unblocked ${d}`);
    } else {
        res.status(400).send("Missing domain parameter");
    }
});

app.post('/dns/whitelist/add', (req, res) => {
    const domain = req.query.domain;
    if (domain) {
        const d = domain.trim().toLowerCase();
        if (d) {
            whitelistSet.add(d);
            config.whitelistDomains = Array.from(whitelistSet);
            saveConfig();
            broadcastUpdate();
            res.send(`Whitelisted ${d}`);
        } else {
            res.status(400).send("Invalid Domain");
        }
    } else {
        res.status(400).send("Missing domain parameter");
    }
});

app.post('/dns/whitelist/remove', (req, res) => {
    const domain = req.query.domain;
    if (domain) {
        const d = domain.trim().toLowerCase();
        whitelistSet.delete(d);
        config.whitelistDomains = Array.from(whitelistSet);
        saveConfig();
        broadcastUpdate();
        res.send(`Removed ${d} from Whitelist`);
    } else {
        res.status(400).send("Missing domain parameter");
    }
});

app.post('/dns/sub/add', (req, res) => {
    const url = req.query.url;
    if (url) {
        const trimmed = url.trim();
        if (trimmed && !config.subscriptionURLs.includes(trimmed)) {
            config.subscriptionURLs.push(trimmed);
            saveConfig();
            broadcastUpdate();
            res.send("Subscription added");
        } else {
            res.status(400).send("Invalid or duplicate URL");
        }
    } else {
        res.status(400).send("Missing url parameter");
    }
});

app.post('/dns/sub/remove', (req, res) => {
    const url = req.query.url;
    if (url) {
        const trimmed = url.trim();
        config.subscriptionURLs = config.subscriptionURLs.filter(u => u !== trimmed);
        saveConfig();
        broadcastUpdate();
        res.send("Subscription removed");
    } else {
        res.status(400).send("Missing url parameter");
    }
});

app.post('/dns/sub/refresh', (req, res) => {
    updateBlocklists(() => {
        res.send("Refreshed");
    });
});

app.post('/dns/upstream', (req, res) => {
    const ip = req.query.ip;
    if (ip) {
        const trimmed = ip.trim();
        const ipRegEx = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipRegEx.test(trimmed)) {
            config.upstreamDNS = trimmed;
            saveConfig();
            broadcastUpdate();
            res.send("Upstream updated");
        } else {
            res.status(400).send("Invalid IP format");
        }
    } else {
        res.status(400).send("Missing ip parameter");
    }
});

app.post('/dns/groq', (req, res) => {
    const enabled = req.query.enabled === 'true';
    const model = req.query.model || "llama-3.1-8b-instant";
    
    config.aiEnabled = enabled;
    config.groqModel = model;
    
    saveConfig();
    broadcastUpdate();
    res.send("Groq configuration updated");
});

app.post('/dns/groq/keys/add', (req, res) => {
    const key = req.query.key;
    if (!key || !key.trim()) {
        return res.status(400).json({ error: 'Missing key parameter' });
    }
    const trimmedKey = key.trim();
    if (!Array.isArray(config.groqApiKeys)) config.groqApiKeys = [];
    if (config.groqApiKeys.includes(trimmedKey)) {
        return res.status(400).json({ error: 'Key already exists' });
    }
    config.groqApiKeys.push(trimmedKey);
    saveConfig();
    broadcastUpdate();
    res.json({ count: config.groqApiKeys.length, maxConcurrent: config.groqApiKeys.length * GROQ_CONCURRENCY_PER_KEY });
});

app.post('/dns/groq/keys/remove', (req, res) => {
    const index = parseInt(req.query.index, 10);
    if (isNaN(index) || index < 0) {
        return res.status(400).json({ error: 'Invalid index' });
    }
    if (!Array.isArray(config.groqApiKeys) || index >= config.groqApiKeys.length) {
        return res.status(400).json({ error: 'Index out of range' });
    }
    config.groqApiKeys.splice(index, 1);
    saveConfig();
    broadcastUpdate();
    res.json({ count: config.groqApiKeys.length, maxConcurrent: config.groqApiKeys.length * GROQ_CONCURRENCY_PER_KEY });
});

app.get('/dns/groq/test', (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: "Missing domain parameter" });
    }
    const apiKey = getNextGroqKey();
    if (!apiKey) {
        return res.status(400).json({ error: "No API Keys configured. Add at least one Groq API Key." });
    }
    
    const model = "llama-3.3-70b-versatile";
    // Select exactly 4 dynamic examples (2 blocked, 2 allowed) to keep prompt size small (~350 tokens) and prevent 429 TPM exhaustion
    const blockedEx = learnedExamples.filter(ex => ex.blocked === true).slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.blocked === false).slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"blocked": ${ex.blocked}, "reason": "${ex.reason}"}`).join('\n');

    const systemContent = "You are a DNS Firewall security expert. Classify the domain name. Analyze if it is used for tracking, advertising, telemetry, phishing, malware, scam, or other harmful activities.\n\n" +
                          "Strict Rules:\n" +
                          "1. Block: trackers, advertising, telemetry, analytics, scams, malware, phishing (especially fake brands, fake banks, fake government sites targeting Vietnamese users).\n" +
                          "2. Allow: CDNs, media streams, API services, official app backends, static assets, and essential services (e.g. *.tiktokcdn.com, *.fbcdn.net, *.akamai.net are allowed CDNs; but log.tiktokv.com, graph.facebook.com/tr, ads.youtube.com are blocked trackers/ads).\n" +
                          "3. Watch out for Typosquatting/Phishing: If the domain contains a famous brand (like techcombank, shopee, momo, mbcheck, apple-dns, bidv, vietcombank, sacombank, facebook) but looks suspicious or uses a cheap/non-standard TLD (like .cfd, .xyz, .cc, .top, .site, .icu, .vip, .win, .online, .tech, .click), block it.\n" +
                          "4. Watch out for ad networks and trackers in Vietnam: e.g. admicro, eclick, adtima, ants, yomedia, ad.gonet.vn, and other telemetry/tracking subdomains.\n" +
                          "5. Allow legitimate primary domains and their structural subdomains (e.g. static assets, images, logins) unless they are explicitly ad servers.\n" +
                          "6. Respond in strict JSON: { \"blocked\": true/false, \"reason\": \"1-3 words in Vietnamese\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: model,
        messages: [
            {
                role: "system",
                content: systemContent
            },
            {
                role: "user",
                content: `Analyze this domain: ${domain}`
            }
        ],
        response_format: { type: "json_object" }
    });
    
    const options = {
        hostname: 'api.groq.com',
        port: 443,
        path: '/openai/v1/chat/completions',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
            'Content-Length': Buffer.byteLength(postData)
        }
    };
    
    const request = https.request(options, (response) => {
        let body = [];
        response.on('data', chunk => body.push(chunk));
        response.on('end', () => {
            try {
                const responseString = Buffer.concat(body).toString('utf8');
                if (response.statusCode !== 200) {
                    return res.status(500).json({ error: `Groq returned status ${response.statusCode}`, raw: responseString });
                }
                const resData = JSON.parse(responseString);
                const replyStr = resData.choices?.[0]?.message?.content;
                if (replyStr) {
                    const decision = JSON.parse(replyStr);
                    return res.json(decision);
                } else {
                    return res.status(500).json({ error: "Empty response from Groq", raw: responseString });
                }
            } catch (e) {
                return res.status(500).json({ error: "Failed to parse Groq response", details: e.message });
            }
        });
    });
    
    request.on('error', (e) => {
        res.status(500).json({ error: "Groq API request error", details: e.message });
    });
    
    request.write(postData);
    request.end();
});

app.post('/dns/ai/learning/remove', (req, res) => {
    const domain = req.query.domain;
    if (domain) {
        const d = domain.trim().toLowerCase();
        learnedExamples = learnedExamples.filter(ex => ex.domain.toLowerCase() !== d);
        saveAILearning();
        broadcastUpdate();
        res.send(`Removed ${d} from AI learning log.`);
    } else {
        res.status(400).send("Missing domain parameter");
    }
});

app.post('/dns/ai/learning/clear', (req, res) => {
    learnedExamples.length = 0;
    seedDefaultAILearning();
    broadcastUpdate();
    res.send("AI learning log reset to defaults.");
});

app.post('/dns/ai/cache/clear', (req, res) => {
    aiDecisionCache.clear();
    saveAICache();
    broadcastUpdate();
    res.send("AI classification cache cleared.");
});

app.post('/dns/stats/reset', (req, res) => {
    config.stats = { total: 0, blocked: 0, allowed: 0 };
    cacheHits = 0;
    cacheMisses = 0;
    totalLatency = 0;
    latencyCount = 0;
    saveConfig();
    broadcastUpdate();
    res.send("Stats reset");
});

app.post('/dns/toggle', (req, res) => {
    // Persistent Cloud DNS server is always active
    res.json({ running: true });
});

// Graceful shutdown hooks to persist data immediately on exit
function gracefulShutdown() {
    console.log("Shutting down. Saving config and caches...");
    if (lastLearningSaveTimeout) {
        clearTimeout(lastLearningSaveTimeout);
        try {
            fs.writeFileSync(AI_LEARNED_PATH, JSON.stringify(learnedExamples, null, 2), 'utf8');
        } catch (e) {
            console.error("Graceful shutdown failed to write AI learning examples:", e);
        }
    }
    if (lastCacheSaveTimeout) {
        clearTimeout(lastCacheSaveTimeout);
        try {
            const obj = {};
            for (const [k, v] of aiDecisionCache.entries()) {
                obj[k] = v;
            }
            fs.writeFileSync(AI_CACHE_PATH, JSON.stringify(obj, null, 2), 'utf8');
        } catch (e) {
            console.error("Graceful shutdown failed to write AI cache:", e);
        }
    }
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (e) {
        console.error("Graceful shutdown failed to write config:", e);
    }
    process.exit(0);
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Render Cloud DNS Blocker running on port ${PORT}`);
});
