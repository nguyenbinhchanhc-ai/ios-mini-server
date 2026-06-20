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

// Register global error handlers to prevent process crashes under network drops
process.on('uncaughtException', (err) => {
    console.error("CRITICAL: Uncaught Exception:", err);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error("CRITICAL: Unhandled Rejection at:", promise, "reason:", reason);
});

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

// AI Training State
const aiTrainingStatus = {
    isRunning: false,
    totalCandidates: 0,
    currentIndex: 0,
    currentDomain: null,
    currentKey: null,
    trainedList: []
};

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
const FALLBACK_MODELS = [
    "llama-3.1-8b-instant",
    "gemma2-9b-it"
];

// Shared Upstream UDP Client Sockets
let upstreamSocket = null;
const pendingRequests = new Map(); // Key: upstreamTxId, Value: { callback, originalIDBytes, timer, timestamp }
let nextTxId = 0;

// Local/Internal Domain Safeguard
const IGNORED_DOMAINS = new Set([
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "0.0.0.0", "127.0.0.1", "::1", "local.host"
]);

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
                ws.send(data, (err) => {
                    if (err) {
                        console.error("WS write error, removing client:", err);
                        wsClients.delete(ws);
                    }
                });
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
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
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
        groqTrainKeys: (config.groqTrainKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqTrainKeysCount: (config.groqTrainKeys || []).length,
        aiTrainingStatus: aiTrainingStatus,
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        groqMaxConcurrent: (config.groqApiKeys || []).length * GROQ_CONCURRENCY_PER_KEY,
        learnedExamples: learnedExamples,
        aiCacheCount: aiDecisionCache.size,
        aiQueueLength: groqQueue.length,
        activeGroqRequests: activeGroqRequests,
        serverStatus: getServerStatus()
    };
}

let trainingTimeoutId = null;

function runStartupAITraining() {
    if (!config.aiEnabled || !config.groqTrainKeys || config.groqTrainKeys.length === 0) {
        aiTrainingStatus.isRunning = false;
        aiTrainingStatus.currentDomain = null;
        aiTrainingStatus.currentKey = null;
        broadcastUpdate();
        return;
    }
    
    console.log("[AI Training] Starting background training loop using dedicated Training API Keys...");
    
    const trainingList = [
        "ads.tiktok.com", "analytics.google.com", "ads.youtube.com", "pixel.facebook.com",
        "telemetry.microsoft.com", "stats.g.doubleclick.net", "adserver.admicro.vn", "ad.adtima.vn",
        "scam-banking-verify.xyz", "vietcombank-login-online.cc", "momo-nhan-qua.top",
        "shopee-gift-lucky.site", "eclick.vn", "ants.vn", "yomedia.vn", "ad.gonet.vn",
        "api-auth.mbbank.cc", "shopee-tri-an.xyz", "mbcheck-banking.info", "adservice.google.com.vn"
    ];
    
    aiTrainingStatus.isRunning = true;
    aiTrainingStatus.totalCandidates = trainingList.length;
    
    let index = 0;
    let keyRotationIndex = 0;
    
    if (trainingTimeoutId) clearTimeout(trainingTimeoutId);
    
    function trainNext() {
        if (!config.aiEnabled || !config.groqTrainKeys || config.groqTrainKeys.length === 0) {
            aiTrainingStatus.isRunning = false;
            aiTrainingStatus.currentDomain = null;
            aiTrainingStatus.currentKey = null;
            broadcastUpdate();
            return;
        }
        
        if (index >= trainingList.length) {
            console.log("[AI Training] Training loop completed.");
            aiTrainingStatus.isRunning = false;
            aiTrainingStatus.currentDomain = null;
            aiTrainingStatus.currentKey = null;
            broadcastUpdate();
            return;
        }
        
        const domain = trainingList[index];
        aiTrainingStatus.currentIndex = index + 1;
        
        // Only train if not already in learnedExamples to avoid wasting tokens
        const alreadyLearned = learnedExamples.some(ex => ex.domain.toLowerCase() === domain.toLowerCase());
        if (alreadyLearned) {
            index++;
            trainNext();
            return;
        }
        
        const keys = config.groqTrainKeys;
        const rawKey = keys[keyRotationIndex % keys.length];
        keyRotationIndex = (keyRotationIndex + 1) % keys.length;
        
        const maskedKey = rawKey.substring(0, 8) + '...' + rawKey.substring(rawKey.length - 4);
        aiTrainingStatus.currentDomain = domain;
        aiTrainingStatus.currentKey = maskedKey;
        broadcastUpdate();
        
        console.log(`[AI Training] Pre-training on domain: ${domain} using key: ${maskedKey}...`);
        
        checkDomainWithGroqForTraining(domain, rawKey, (success, decision) => {
            const now = new Date();
            const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
            const timeStr = vnTime.toISOString().substring(11, 19);
            
            aiTrainingStatus.trainedList.unshift({
                domain: domain,
                keyUsed: maskedKey,
                time: timeStr,
                success: success,
                blocked: decision ? decision.blocked : false,
                reason: decision ? decision.reason : "Lỗi kết nối"
            });
            if (aiTrainingStatus.trainedList.length > 50) {
                aiTrainingStatus.trainedList.pop();
            }
            
            index++;
            
            // Rotate keys to speed up training. Safe delay per key is 15 seconds.
            const delayPerKey = 15000;
            const delay = Math.max(3000, Math.round(delayPerKey / keys.length));
            
            trainingTimeoutId = setTimeout(trainNext, delay);
        });
    }
    
    // Start after 10 seconds delay to let the server boot up completely
    trainingTimeoutId = setTimeout(trainNext, 10000);
}

function checkDomainWithGroqForTraining(domain, apiKey, callback) {
    const blockedEx = learnedExamples.filter(ex => ex.blocked === true).slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.blocked === false).slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"blocked": ${ex.blocked}, "reason": "${ex.reason}"}`).join('\n');

    const systemContent = "You are a DNS Firewall security expert. Classify the domain name. Analyze if it is used for tracking, advertising, telemetry, phishing, malware, scam, or other harmful activities.\n\n" +
                          "Strict Rules:\n" +
                          "1. Block: trackers, advertising, telemetry, analytics, scams, malware, phishing (especially fake brands, fake banks, fake government sites targeting Vietnamese users).\n" +
                          "2. Allow: CDNs, media streams, API services, official app backends, static assets, and essential services.\n" +
                          "3. Watch out for Typosquatting/Phishing: If the domain contains a famous brand but looks suspicious or uses a cheap/non-standard TLD, block it.\n" +
                          "4. Respond in strict JSON: { \"blocked\": true/false, \"reason\": \"1-3 words in Vietnamese\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
            { role: "system", content: systemContent },
            { role: "user", content: buildAIAnalysisContext(domain) }
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
    
    try {
        const req = https.request(options, (res) => {
            let body = [];
            res.on('data', chunk => body.push(chunk));
            res.on('end', () => {
                try {
                    if (res.statusCode !== 200) {
                        callback(false, null);
                        return;
                    }
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        if (decision.blocked === true) {
                            aiDecisionCache.set(domain, true);
                            saveAICache();
                            
                            customBlockedSet.add(domain);
                            config.customBlockedDomains = Array.from(customBlockedSet);
                            
                            config.stats.blocked += 1;
                            if (config.stats.allowed > 0) {
                                config.stats.allowed -= 1;
                            }
                            saveConfig();
                            
                            learnedExamples.push({ domain, blocked: true, reason: decision.reason || "Mối nguy hại" });
                            if (learnedExamples.length > 100) learnedExamples.shift();
                            saveAILearning();
                        } else {
                            aiDecisionCache.set(domain, false);
                            saveAICache();
                            
                            learnedExamples.push({ domain, blocked: false, reason: decision.reason || "CDN / Hợp lệ" });
                            if (learnedExamples.length > 100) learnedExamples.shift();
                            saveAILearning();
                        }
                        callback(true, decision);
                    } else {
                        callback(false, null);
                    }
                } catch (e) {
                    callback(false, null);
                }
            });
        });
        
        req.on('error', () => {
            callback(false, null);
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        callback(false, null);
    }
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

// Schedule AI background pre-training loop on startup
setTimeout(runStartupAITraining, 15000);

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
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
        "https://abpvn.com/android/abpvn.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        "https://raw.githubusercontent.com/neodevpro/neodevhost/master/host"
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
                stats: { total: 0, blocked: 0, allowed: 0, cacheHits: 0, cacheMisses: 0 },
                aiEnabled: false,
                groqApiKeys: [],
                groqTrainKeys: [],
                groqModel: "llama-3.1-8b-instant"
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
            stats: { total: 0, blocked: 0, allowed: 0, cacheHits: 0, cacheMisses: 0 },
            aiEnabled: false,
            groqApiKeys: [],
            groqTrainKeys: [],
            groqModel: "llama-3.1-8b-instant"
        };
    }
    
    // Ensure all variables are fully seeded
    config.stats = config.stats || {};
    config.stats.total = config.stats.total || 0;
    config.stats.blocked = config.stats.blocked || 0;
    config.stats.allowed = config.stats.allowed || 0;
    config.stats.cacheHits = config.stats.cacheHits || 0;
    config.stats.cacheMisses = config.stats.cacheMisses || 0;
    config.aiEnabled = config.aiEnabled || false;
    config.groqModel = "llama-3.1-8b-instant"; // Enforce 8B model only to avoid 429 rate limits
    // Migrate legacy single key to array
    if (config.groqApiKey && !config.groqApiKeys) {
        config.groqApiKeys = [config.groqApiKey];
        delete config.groqApiKey;
    }
    if (!Array.isArray(config.groqApiKeys)) {
        config.groqApiKeys = [];
    }
    if (!Array.isArray(config.groqTrainKeys)) {
        config.groqTrainKeys = [];
    }
    
    // Load keys from environment variable GROQ_API_KEYS (comma separated)
    if (process.env.GROQ_API_KEYS) {
        const envKeys = process.env.GROQ_API_KEYS.split(',')
            .map(k => k.trim())
            .filter(k => k.length > 0);
        
        envKeys.forEach(k => {
            if (!config.groqApiKeys.includes(k)) {
                config.groqApiKeys.push(k);
            }
        });
        console.log(`Loaded ${envKeys.length} Groq API keys from environment variable.`);
    }

    config.groqApiKeys = config.groqApiKeys.filter(k => k && k.trim().length > 0);

    // Load training keys from environment variable GROQ_TRAIN_KEYS (comma separated)
    if (process.env.GROQ_TRAIN_KEYS) {
        const envKeys = process.env.GROQ_TRAIN_KEYS.split(',')
            .map(k => k.trim())
            .filter(k => k.length > 0);
        
        envKeys.forEach(k => {
            if (!config.groqTrainKeys.includes(k)) {
                config.groqTrainKeys.push(k);
            }
        });
        console.log(`Loaded ${envKeys.length} Groq Training API keys from environment variable.`);
    }

    config.groqTrainKeys = config.groqTrainKeys.filter(k => k && k.trim().length > 0);
    if (!config.subscriptionURLs || config.subscriptionURLs.length <= 1) {
        config.subscriptionURLs = [...defaultSubs];
    }
    
    // Automatically inject any missing default subscriptions and prune legacy ones
    let configUpdated = false;
    defaultSubs.forEach(sub => {
        if (!config.subscriptionURLs.includes(sub)) {
            config.subscriptionURLs.push(sub);
            configUpdated = true;
        }
    });
    
    // Clean up legacy 404 URLs if they exist in subscriptionURLs
    const legacy404Urls = [
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Vietnamese/filter.txt",
        "https://abpvn.com/filter/abpvn.txt"
    ];
    legacy404Urls.forEach(legacyUrl => {
        if (config.subscriptionURLs.includes(legacyUrl)) {
            config.subscriptionURLs = config.subscriptionURLs.filter(u => u !== legacyUrl);
            configUpdated = true;
        }
    });
    
    if (configUpdated) {
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
            config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
            // Move to end of Map (most recently used) to preserve LRU order
            dnsCache.delete(key);
            dnsCache.set(key, cached);
            return cached.responseBuffer;
        } else {
            dnsCache.delete(key);
        }
    }
    config.stats.cacheMisses = (config.stats.cacheMisses || 0) + 1;
    return null;
}

function setCache(domain, qtype, responseBuffer, ttl) {
    const minTtl = 60; // Enforce 60 seconds minimum cache TTL
    const parsedTtl = Number(ttl);
    const finalTtl = (isNaN(parsedTtl) || parsedTtl < minTtl) ? minTtl : parsedTtl;
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

function buildAIAnalysisContext(domain) {
    const d = domain.trim().toLowerCase();
    const parts = d.split('.');
    const tld = parts[parts.length - 1];
    
    // Famous suspicious/low-cost TLDs often used for phishing/scams
    const suspiciousTlds = new Set(['cfd', 'xyz', 'cc', 'top', 'site', 'icu', 'vip', 'win', 'online', 'tech', 'click', 'info', 'biz', 'tk', 'ml', 'ga', 'cf', 'gq']);
    
    // Famous Vietnamese and international brands targeted by phishing
    const famousBrands = [
        { brand: 'techcombank', matches: ['techcombank', 'tcb'] },
        { brand: 'shopee', matches: ['shopee'] },
        { brand: 'momo', matches: ['momo'] },
        { brand: 'mbcheck', matches: ['mbcheck', 'mbbank', 'mbb'] },
        { brand: 'bidv', matches: ['bidv'] },
        { brand: 'vietcombank', matches: ['vietcombank', 'vcb'] },
        { brand: 'sacombank', matches: ['sacombank'] },
        { brand: 'agribank', matches: ['agribank'] },
        { brand: 'facebook', matches: ['facebook', 'fb'] },
        { brand: 'apple', matches: ['apple', 'icloud'] },
        { brand: 'netflix', matches: ['netflix'] },
        { brand: 'tiktok', matches: ['tiktok'] }
    ];

    let brandDetected = null;
    for (const b of famousBrands) {
        for (const match of b.matches) {
            if (d.includes(match)) {
                // Confirm it is not the legitimate primary domain of the brand
                const isLegit = (d === `${b.brand}.com` || d.endsWith(`.${b.brand}.com`) || d === `${b.brand}.vn` || d.endsWith(`.${b.brand}.vn`) || d === `${b.brand}.com.vn` || d.endsWith(`.${b.brand}.com.vn`));
                if (!isLegit) {
                    brandDetected = b.brand;
                    break;
                }
            }
        }
        if (brandDetected) break;
    }

    let contextualPrompt = `Domain to analyze: ${domain}\n`;
    contextualPrompt += `Metadata:\n`;
    contextualPrompt += `- TLD: .${tld} (Suspicious: ${suspiciousTlds.has(tld) ? "YES" : "NO"})\n`;
    if (brandDetected) {
        contextualPrompt += `- Brand abuse detected: Domain contains brand keywords referencing "${brandDetected}" but is NOT the official domain of ${brandDetected}. (Potential phishing/brand impersonation: YES)\n`;
    }
    
    // Check if the domain length is abnormally long (common for dynamically generated ad/tracking hosts)
    if (parts[0] && parts[0].length > 25) {
        contextualPrompt += `- Subdomain pattern: Abnormally long host label (Potential DGA/tracking endpoint: YES)\n`;
    }
    
    return contextualPrompt;
}

function checkDomainWithGroq(domain, apiKey, callback, modelIndex = 0) {
    if (!apiKey) {
        aiDecisionCache.delete(domain);
        if (callback) callback();
        return;
    }
    
    // Check if we exhausted all fallback models
    if (modelIndex >= FALLBACK_MODELS.length) {
        console.warn(`[AI Guard] All Groq models exhausted for ${domain}. Pausing AI queue for 60s...`);
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
        
        if (callback) callback();
        return;
    }
    
    const model = FALLBACK_MODELS[modelIndex];
    console.log(`[AI Guard] Scanning domain: ${domain} via Groq (${model}) [Try #${modelIndex + 1}]...`);
    
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
                content: buildAIAnalysisContext(domain)
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
    
    let fallbackCalled = false;
    const triggerFallback = (reason) => {
        if (!fallbackCalled) {
            fallbackCalled = true;
            console.warn(`[AI Guard] Groq model ${model} failed for ${domain} (${reason}). Trying fallback...`);
            checkDomainWithGroq(domain, apiKey, callback, modelIndex + 1);
        }
    };
    
    try {
        const req = https.request(options, (res) => {
            let body = [];
            res.on('data', chunk => body.push(chunk));
            res.on('end', () => {
                try {
                    if (res.statusCode !== 200) {
                        triggerFallback(`Status ${res.statusCode}`);
                        return;
                    }
                    
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        if (decision.blocked === true) {
                            aiDecisionCache.set(domain, true);
                            saveAICache(); // Save AI classification cache to disk
                            console.log(`[AI Guard] Groq classified ${domain} as BLOCKED via ${model}. Reason: ${decision.reason}`);
                            
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
                            console.log(`[AI Guard] Groq classified ${domain} as ALLOWED via ${model}.`);
                            
                            // Learn from this allowed domain dynamically
                            learnedExamples.push({ domain, blocked: false, reason: decision.reason || "CDN / Hợp lệ" });
                            if (learnedExamples.length > 50) {
                                learnedExamples.shift();
                            }
                            saveAILearning(); // Save AI dynamic learning log to disk
                            
                            broadcastUpdate();
                        }
                        if (callback) callback();
                    } else {
                        triggerFallback("Empty response message content");
                    }
                } catch (e) {
                    console.error("[AI Guard] Failed to parse Groq response:", e);
                    triggerFallback(`Parse error: ${e.message}`);
                }
            });
        });
        
        req.on('error', (e) => {
            console.error("[AI Guard] Groq API error:", e);
            triggerFallback(`Request error: ${e.message}`);
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        console.error("[AI Guard] Groq API request exception:", e);
        triggerFallback(`Exception: ${e.message}`);
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
                        if (domain.startsWith('||')) {
                            let endIdx = domain.search(/[\^\/\$]/);
                            if (endIdx !== -1) {
                                domain = domain.substring(2, endIdx);
                            } else {
                                domain = domain.substring(2);
                            }
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
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
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
        groqTrainKeys: (config.groqTrainKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqTrainKeysCount: (config.groqTrainKeys || []).length,
        aiTrainingStatus: aiTrainingStatus,
        groqModel: config.groqModel || "llama-3.1-8b-instant",
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
            
            // Teach the AI immediately (RL-Admin)
            const exists = learnedExamples.some(ex => ex.domain.toLowerCase() === d);
            if (!exists) {
                learnedExamples.push({ domain: d, blocked: true, reason: "Chặn thủ công (RL-Admin)" });
                if (learnedExamples.length > 100) learnedExamples.shift();
                saveAILearning();
            }
            
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
            
            // Teach the AI immediately (RL-Admin)
            const exists = learnedExamples.some(ex => ex.domain.toLowerCase() === d);
            if (!exists) {
                learnedExamples.push({ domain: d, blocked: false, reason: "Tin cậy thủ công (RL-Admin)" });
                if (learnedExamples.length > 100) learnedExamples.shift();
                saveAILearning();
            }
            
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
    if (enabled) {
        setTimeout(runStartupAITraining, 2000);
    }
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

app.post('/dns/groq/train-keys/add', (req, res) => {
    const key = req.query.key;
    if (!key || !key.trim()) {
        return res.status(400).json({ error: 'Missing key parameter' });
    }
    const trimmedKey = key.trim();
    if (!Array.isArray(config.groqTrainKeys)) config.groqTrainKeys = [];
    if (config.groqTrainKeys.includes(trimmedKey)) {
        return res.status(400).json({ error: 'Key already exists' });
    }
    config.groqTrainKeys.push(trimmedKey);
    saveConfig();
    broadcastUpdate();
    if (config.aiEnabled) {
        setTimeout(runStartupAITraining, 2000);
    }
    res.json({ count: config.groqTrainKeys.length });
});

app.post('/dns/groq/train-keys/remove', (req, res) => {
    const index = parseInt(req.query.index, 10);
    if (isNaN(index) || index < 0) {
        return res.status(400).json({ error: 'Invalid index' });
    }
    if (!Array.isArray(config.groqTrainKeys) || index >= config.groqTrainKeys.length) {
        return res.status(400).json({ error: 'Index out of range' });
    }
    config.groqTrainKeys.splice(index, 1);
    saveConfig();
    broadcastUpdate();
    res.json({ count: config.groqTrainKeys.length });
});

function runTestWithFallback(domain, apiKey, res, modelIndex = 0) {
    if (modelIndex >= FALLBACK_MODELS.length) {
        return res.status(500).json({ error: "Tất cả các mô hình Groq trong chuỗi đều bị quá tải (Rate Limit) hoặc gặp lỗi. Vui lòng thử lại sau." });
    }
    
    const model = FALLBACK_MODELS[modelIndex];
    
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
                content: buildAIAnalysisContext(domain)
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
    
    let fallbackCalled = false;
    const triggerFallback = (reason) => {
        if (!fallbackCalled) {
            fallbackCalled = true;
            console.warn(`[AI Test] Groq model ${model} failed for ${domain} (${reason}). Trying fallback...`);
            runTestWithFallback(domain, apiKey, res, modelIndex + 1);
        }
    };
    
    try {
        const request = https.request(options, (response) => {
            let body = [];
            response.on('data', chunk => body.push(chunk));
            response.on('end', () => {
                try {
                    const responseString = Buffer.concat(body).toString('utf8');
                    if (response.statusCode !== 200) {
                        triggerFallback(`Status ${response.statusCode}: ${responseString}`);
                        return;
                    }
                    const resData = JSON.parse(responseString);
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        decision.modelUsed = model;
                        return res.json(decision);
                    } else {
                        triggerFallback("Empty response content");
                    }
                } catch (e) {
                    triggerFallback(`Parse error: ${e.message}`);
                }
            });
        });
        
        request.on('error', (e) => {
            triggerFallback(`Request error: ${e.message}`);
        });
        
        request.write(postData);
        request.end();
    } catch (e) {
        triggerFallback(`Exception: ${e.message}`);
    }
}

app.get('/dns/groq/test', (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: "Missing domain parameter" });
    }
    const apiKey = getNextGroqKey();
    if (!apiKey) {
        return res.status(400).json({ error: "No API Keys configured. Add at least one Groq API Key." });
    }
    
    runTestWithFallback(domain, apiKey, res, 0);
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

app.post('/dns/ai/learning/sync', (req, res) => {
    try {
        if (!req.rawBody || req.rawBody.length === 0) {
            return res.status(400).send("Empty payload");
        }
        const list = JSON.parse(req.rawBody.toString('utf8'));
        if (Array.isArray(list)) {
            list.forEach(item => {
                if (item && typeof item.domain === 'string') {
                    const domainLower = item.domain.toLowerCase().trim();
                    const exists = learnedExamples.some(ex => ex.domain.toLowerCase().trim() === domainLower);
                    if (!exists) {
                        learnedExamples.push({
                            domain: item.domain.trim(),
                            blocked: !!item.blocked,
                            reason: item.reason || "Trí tuệ nhân tạo học ngầm"
                        });
                    }
                }
            });
            if (learnedExamples.length > 100) {
                learnedExamples.splice(0, learnedExamples.length - 100); // keep last 100
            }
            saveAILearning();
            broadcastUpdate();
            return res.json({ success: true, count: learnedExamples.length });
        }
    } catch(e) {
        console.error("Failed to parse learning sync payload:", e);
    }
    res.status(400).send("Invalid JSON payload");
});

app.post('/dns/stats/reset', (req, res) => {
    config.stats = { total: 0, blocked: 0, allowed: 0, cacheHits: 0, cacheMisses: 0 };
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
