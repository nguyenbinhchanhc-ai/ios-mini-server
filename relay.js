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

// Register global error handlers to prevent process crashes
process.on('uncaughtException', (err) => {
    console.error("CRITICAL: Uncaught Exception:", err);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error("CRITICAL: Unhandled Rejection at:", promise, "reason:", reason);
});

const CONFIG_PATH = path.join(__dirname, 'dns_config.json');
const AI_LEARNED_PATH = path.join(__dirname, 'ai_learned_examples.json');
const AI_CACHE_PATH = path.join(__dirname, 'ai_decision_cache.json');

// State variables
let config = {};
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

let trainingQueue = [];
let totalTrainingEnqueued = 0;
let totalTrainingProcessed = 0;

// WebSocket client registry
const wsClients = new Set();

// AI Learned Examples (Few-Shot In-context training)
let learnedExamples = [];

// Performance Metrics & Local DNS Cache
const dnsCache = new Map(); // Key: domain + '_' + qtype, Value: { responseBuffer, createdAt, expiresAt }
const MAX_CACHE_SIZE = 15000;
const activeUpstreamQueries = new Map(); // Key: domain + '_' + qtype, Value: Array of waiting client callbacks
const aiDecisionCache = new Map(); // Key: domain, Value: category string or JSON string

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
                            category: ex.category || "General/Search",
                            reason: ex.reason || "Phân loại chung"
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
        { domain: "doubleclick.net", category: "Security", reason: "Mạng quảng cáo" },
        { domain: "log.tiktokv.com", category: "Security", reason: "Theo dõi hành vi" },
        { domain: "google-analytics.com", category: "Security", reason: "Thống kê phân tích" },
        { domain: "techcombank-verify.cfd", category: "Security", reason: "Giả mạo ngân hàng" },
        { domain: "youtube.com", category: "Media/CDN", reason: "Xem video trực tuyến" },
        { domain: "v3.tiktokcdn.com", category: "Media/CDN", reason: "CDN Video TikTok" },
        { domain: "google.com", category: "General/Search", reason: "Tìm kiếm Google" },
        { domain: "wikipedia.org", category: "General/Search", reason: "Bách khoa toàn thư" },
        { domain: "api.facebook.com", category: "API/App", reason: "Cổng API Facebook" },
        { domain: "momo.vn", category: "API/App", reason: "Cổng dịch vụ Momo" }
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
                aiDecisionCache.set(k, String(v));
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
const FALLBACK_MODELS = [
    "llama-3.1-8b-instant",
    "gemma2-9b-it"
];

const keyCooldowns = new Map(); // key -> timestamp of cooldown expiration
function isKeyAvailable(key) {
    if (!key) return false;
    const cooldownUntil = keyCooldowns.get(key);
    if (cooldownUntil && Date.now() < cooldownUntil) {
        return false;
    }
    return true;
}

// Upstream UDP Client Sockets Pool
const SOCKET_POOL_SIZE = 5;
const upstreamSocketPool = [];
let nextSocketIndex = 0;
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

let broadcastTimeout = null;
function throttledBroadcastUpdate() {
    if (broadcastTimeout) return;
    broadcastTimeout = setTimeout(() => {
        broadcastTimeout = null;
        broadcastUpdate();
    }, 1000);
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
    const stats = {
        total: config.stats.total,
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
        avgLatency: latencyCount > 0 ? (totalLatency / latencyCount) : 0
    };
    return {
        type: 'update',
        running: true,
        logs: logs,
        stats: stats,
        aiEnabled: !!config.aiEnabled,
        groqApiKeys: (config.groqApiKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqApiKeysCooldown: (config.groqApiKeys || []).map(k => keyCooldowns.has(k) && Date.now() < keyCooldowns.get(k)),
        groqApiKeysCount: (config.groqApiKeys || []).length,
        groqTrainKeys: (config.groqTrainKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqTrainKeysCooldown: (config.groqTrainKeys || []).map(k => keyCooldowns.has(k) && Date.now() < keyCooldowns.get(k)),
        groqTrainKeysCount: (config.groqTrainKeys || []).length,
        aiTrainingStatus: aiTrainingStatus,
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        groqMaxConcurrent: (config.groqApiKeys || []).length * GROQ_CONCURRENCY_PER_KEY,
        learnedExamples: learnedExamples,
        aiCacheCount: aiDecisionCache.size,
        aiQueueLength: groqQueue.length,
        activeGroqRequests: activeGroqRequests,
        serverStatus: getServerStatus(),
        
        // Load Balancer fields
        upstreamPool: config.upstreamPool || [],
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
        dnsRacingEnabled: !!config.dnsRacingEnabled,
        dnsRacingDelayMs: config.dnsRacingDelayMs || 15
    };
}

let trainingWorkerTimeouts = [];
let activeWorkers = {};

function runStartupAITraining() {
    if (!config.aiEnabled || !config.groqTrainKeys || config.groqTrainKeys.length === 0) {
        aiTrainingStatus.isRunning = false;
        aiTrainingStatus.currentDomain = null;
        aiTrainingStatus.currentKey = null;
        broadcastUpdate();
        return;
    }
    
    console.log(`[AI Training] Starting background training loop using ${config.groqTrainKeys.length} parallel workers...`);
    
    const staticCandidates = [
        "ads.tiktok.com", "analytics.google.com", "ads.youtube.com", "pixel.facebook.com",
        "telemetry.microsoft.com", "stats.g.doubleclick.net", "adserver.admicro.vn", "ad.adtima.vn",
        "scam-banking-verify.xyz", "vietcombank-login-online.cc", "momo-nhan-qua.top",
        "shopee-gift-lucky.site", "eclick.vn", "ants.vn", "yomedia.vn", "ad.gonet.vn",
        "api-auth.mbbank.cc", "shopee-tri-an.xyz", "mbcheck-banking.info", "adservice.google.com.vn"
    ];
    
    // Seed queue with static candidates if it's completely fresh
    if (trainingQueue.length === 0 && totalTrainingEnqueued === 0) {
        staticCandidates.forEach(domain => {
            const d = domain.trim().toLowerCase();
            const alreadyLearned = learnedExamples.some(ex => ex.domain.toLowerCase() === d);
            if (!alreadyLearned) {
                trainingQueue.push(d);
                totalTrainingEnqueued++;
            }
        });
    }
    
    aiTrainingStatus.totalCandidates = totalTrainingEnqueued;
    
    // Clear any existing workers
    trainingWorkerTimeouts.forEach(clearTimeout);
    trainingWorkerTimeouts = [];
    activeWorkers = {};
    
    // Start a worker loop for each key
    config.groqTrainKeys.forEach((apiKey, idx) => {
        const startDelay = idx * 1500; 
        const timeoutId = setTimeout(() => {
            runWorker(apiKey);
        }, startDelay);
        trainingWorkerTimeouts.push(timeoutId);
    });
}

function runWorker(apiKey) {
    if (!config.aiEnabled || !config.groqTrainKeys || !config.groqTrainKeys.includes(apiKey)) {
        delete activeWorkers[apiKey];
        updateTrainingUIStatus();
        return;
    }
    
    if (!isKeyAvailable(apiKey)) {
        delete activeWorkers[apiKey];
        updateTrainingUIStatus();
        const timeoutId = setTimeout(() => runWorker(apiKey), 5000);
        trainingWorkerTimeouts.push(timeoutId);
        return;
    }
    
    if (trainingQueue.length === 0) {
        delete activeWorkers[apiKey];
        updateTrainingUIStatus();
        const timeoutId = setTimeout(() => runWorker(apiKey), 3000);
        trainingWorkerTimeouts.push(timeoutId);
        return;
    }
    
    const domain = trainingQueue.shift();
    totalTrainingProcessed++;
    
    aiTrainingStatus.currentIndex = totalTrainingProcessed;
    aiTrainingStatus.totalCandidates = totalTrainingEnqueued;
    
    const learnedItem = learnedExamples.find(ex => ex.domain.toLowerCase() === domain.toLowerCase());
    if (learnedItem) {
        const now = new Date();
        const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
        const timeStr = vnTime.toISOString().substring(11, 19);
        
        aiTrainingStatus.trainedList.unshift({
            domain: domain,
            keyUsed: "N/A (Đã lưu bộ nhớ)",
            time: timeStr,
            success: true,
            category: learnedItem.category || "General/Search",
            reason: `Đã phân loại (${learnedItem.reason || learnedItem.category})`
        });
        if (aiTrainingStatus.trainedList.length > 50) {
            aiTrainingStatus.trainedList.pop();
        }
        
        throttledBroadcastUpdate();
        const timeoutId = setTimeout(() => runWorker(apiKey), 100);
        trainingWorkerTimeouts.push(timeoutId);
        return;
    }
    
    activeWorkers[apiKey] = domain;
    updateTrainingUIStatus();
    
    const maskedKey = apiKey.substring(0, 8) + '...' + apiKey.substring(apiKey.length - 4);
    console.log(`[AI Training Worker] Training domain: ${domain} using key: ${maskedKey}...`);
    
    checkDomainWithGroqForTraining(domain, apiKey, (success, decision) => {
        const now = new Date();
        const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
        const timeStr = vnTime.toISOString().substring(11, 19);
        
        aiTrainingStatus.trainedList.unshift({
            domain: domain,
            keyUsed: maskedKey,
            time: timeStr,
            success: success,
            category: decision ? decision.category : "General/Search",
            reason: decision ? decision.reason : "Lỗi kết nối"
        });
        if (aiTrainingStatus.trainedList.length > 50) {
            aiTrainingStatus.trainedList.pop();
        }
        
        delete activeWorkers[apiKey];
        updateTrainingUIStatus();
        
        const timeoutId = setTimeout(() => runWorker(apiKey), 15000);
        trainingWorkerTimeouts.push(timeoutId);
    });
}

function updateTrainingUIStatus() {
    const activeKeys = Object.keys(activeWorkers);
    if (activeKeys.length > 0) {
        aiTrainingStatus.isRunning = true;
        aiTrainingStatus.currentDomain = activeKeys.map(k => activeWorkers[k]).join(' | ');
        aiTrainingStatus.currentKey = activeKeys.map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)).join(' | ');
    } else {
        aiTrainingStatus.currentDomain = null;
        aiTrainingStatus.currentKey = null;
        if (trainingQueue.length === 0) {
            aiTrainingStatus.isRunning = false;
        }
    }
    throttledBroadcastUpdate();
}

function enqueueDomainForTraining(domain) {
    const d = domain.trim().toLowerCase();
    if (!d || d.includes('localhost') || d.includes('127.0.0.1') || IGNORED_DOMAINS.has(d)) return;
    if (d.endsWith('.local') || d.endsWith('.localhost')) return;
    if (isSafeDomain(d)) return;
    
    const alreadyLearned = learnedExamples.some(ex => ex.domain.toLowerCase() === d);
    if (alreadyLearned) return;
    
    if (trainingQueue.includes(d)) return;
    
    console.log(`[AI Training] Enqueuing domain for real-time training: ${d}`);
    trainingQueue.unshift(d);
    totalTrainingEnqueued++;
    
    if (!aiTrainingStatus.isRunning) {
        runStartupAITraining();
    }
}

function checkDomainWithGroqForTraining(domain, apiKey, callback, internetContext = null) {
    if (process.env.MOCK_GROQ === 'true' || apiKey.startsWith('gsk_train')) {
        setTimeout(() => {
            let category = "General/Search";
            if (domain.includes('ad') || domain.includes('track') || domain.includes('pixel') || domain.includes('telemetry') || domain.includes('bank') || domain.includes('pay') || domain.includes('verify')) {
                category = "Security";
            } else if (domain.includes('cdn') || domain.includes('media') || domain.includes('video') || domain.includes('stream') || domain.includes('youtube') || domain.includes('tiktok')) {
                category = "Media/CDN";
            }
            
            let targetIP = "1.1.1.1";
            if (category === "Security") targetIP = "9.9.9.9";
            else if (category === "Media/CDN") targetIP = "8.8.8.8";
            else {
                const sorted = [...(config.upstreamPool || [])].sort((a,b) => (a.latency || 0) - (b.latency || 0));
                if (sorted.length > 0) targetIP = sorted[0].ip;
            }
            
            const decision = {
                category: category,
                targetIP: targetIP,
                reason: category === "Security" ? "Bảo mật định tuyến" : (category === "Media/CDN" ? "Tối ưu hóa CDN" : "Định tuyến Least-Latency")
            };
            const cacheVal = JSON.stringify({ category, targetIP });
            aiDecisionCache.set(domain, cacheVal);
            saveAICache();
            learnedExamples.push({ domain, category, reason: decision.reason });
            if (learnedExamples.length > 1000) learnedExamples.shift();
            saveAILearning();
            callback(true, decision);
        }, 6000);
        return;
    }

    if (internetContext === null) {
        gatherInternetContext(domain).then((context) => {
            checkDomainWithGroqForTraining(domain, apiKey, callback, context);
        });
        return;
    }
    
    const blockedEx = learnedExamples.filter(ex => ex.category === "Security").slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.category !== "Security").slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"category": "${ex.category}", "reason": "${ex.reason}"}`).join('\n');

    const poolContext = getUpstreamPoolPromptContext();
    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Analyze the domain name and determine the best upstream DNS IP to route the query based on the current upstream pool status and latency:\n\n" +
                          "Current Upstream Pool Status:\n" + poolContext + "\n\n" +
                          "Strict Routing Logic Rules:\n" +
                          "1. Category 'Security' (ad, tracker, telemetry, scam, phishing): Route to Quad9 (9.9.9.9) for security filtering. If Quad9 is OFFLINE or latency is extremely high (>300ms), fallback and route to OpenDNS (208.67.222.222) or Cloudflare (1.1.1.1).\n" +
                          "2. Category 'Media/CDN' (streaming, video, images, static assets): Route to Google (8.8.8.8) or Cloudflare (1.1.1.1) depending on which is faster (lower latency).\n" +
                          "3. Category 'General/Search' or 'API/App': Route to the DNS server with the lowest latency in the pool.\n\n" +
                          "Respond in strict JSON format: { \"category\": \"Security\" | \"Media/CDN\" | \"General/Search\" | \"API/App\", \"targetIP\": \"[chosen DNS server IP]\", \"reason\": \"1-3 words in Vietnamese explaining routing choice\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
            { role: "system", content: systemContent },
            { role: "user", content: buildAIAnalysisContext(domain, internetContext) }
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
                        if (res.statusCode === 429 || res.statusCode === 401) {
                            console.warn(`[AI Training] Key ${apiKey.substring(0, 8)}... error ${res.statusCode}. Cool down active for 60s.`);
                            keyCooldowns.set(apiKey, Date.now() + 60000);
                        }
                        callback(false, null);
                        return;
                    }
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        const category = decision.category || "General/Search";
                        const targetIP = decision.targetIP || "1.1.1.1";
                        const cacheVal = JSON.stringify({ category, targetIP });
                        aiDecisionCache.set(domain, cacheVal);
                        saveAICache();
                        
                        learnedExamples.push({ domain, category, reason: decision.reason || "Huấn luyện AI" });
                        if (learnedExamples.length > 1000) learnedExamples.shift();
                        saveAILearning();
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

// Local DNS Cache with prefetching
function checkCache(domain, qtype) {
    const key = `${domain.toLowerCase()}_${qtype}`;
    const cached = dnsCache.get(key);
    if (cached) {
        const now = Date.now();
        if (now < cached.expiresAt) {
            config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
            
            // Smart Cache Prefetching:
            // Trigger prefetch if remaining TTL < 20% of total TTL
            const totalTTL = (cached.expiresAt - cached.createdAt) / 1000;
            const remainingTTL = (cached.expiresAt - now) / 1000;
            if (totalTTL > 10 && remainingTTL < (totalTTL * 0.2)) {
                const prefetchKey = `prefetch_${key}`;
                if (!activeUpstreamQueries.has(prefetchKey)) {
                    activeUpstreamQueries.set(prefetchKey, true);
                    console.log(`[Cache Prefetch] Triggering background prefetch for: ${domain} (remaining TTL: ${Math.round(remainingTTL)}s / ${Math.round(totalTTL)}s)`);
                    
                    const targetDNS = selectUpstreamDNS(domain);
                    const prefetchQueryBuffer = buildQueryBufferForMeasure(domain);
                    
                    fetchFromUpstreamDeduplicated(prefetchQueryBuffer, domain, qtype, targetDNS, (response) => {
                        activeUpstreamQueries.delete(prefetchKey);
                        if (response) {
                            const newTtl = extractTTL(response, 12);
                            setCache(domain, qtype, response, newTtl);
                            console.log(`[Cache Prefetch] Asynchronously updated cache for: ${domain} (New TTL: ${newTtl}s)`);
                        }
                    });
                }
            }

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
    const minTtl = 300; // Enforce 300 seconds (5 minutes) minimum cache TTL
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
        createdAt: Date.now(),
        expiresAt: Date.now() + (finalTtl * 1000)
    });
}

// DNS Packet Parsers & Builders
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

function buildGslbResponse(queryBuffer, questionEndOffset, ips) {
    const header = Buffer.alloc(12);
    queryBuffer.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2); // Standard response, no error
    header.writeUInt16BE(1, 4); // QDCOUNT = 1
    header.writeUInt16BE(ips.length, 6); // ANCOUNT = ips.length
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(0, 10);
    
    const questionLength = (questionEndOffset + 4) - 12;
    const question = Buffer.alloc(questionLength);
    queryBuffer.copy(question, 0, 12, questionEndOffset + 4);
    
    const answers = [];
    ips.forEach(ip => {
        const answer = Buffer.alloc(16);
        answer.writeUInt16BE(0xc00c, 0); // Name pointer to question
        answer.writeUInt16BE(1, 2);      // Type A
        answer.writeUInt16BE(1, 4);      // Class IN
        answer.writeUInt32BE(60, 6);     // TTL 60s
        answer.writeUInt16BE(4, 10);     // Length = 4
        
        const parts = ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            answer[12 + i] = parts[i] || 0;
        }
        answers.push(answer);
    });
    
    return Buffer.concat([header, question, ...answers]);
}

function extractTTL(responseBuffer, questionEndOffset) {
    try {
        let offset = questionEndOffset + 4; // Start of Answer Section
        if (offset + 10 > responseBuffer.length) return 300;
        
        let nameByte = responseBuffer[offset];
        if ((nameByte & 0xC0) === 0xC0) {
            offset += 2;
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

// Upstream UDP Client Sockets Pool Initialization
function initUpstreamSocketPool() {
    for (let i = 0; i < SOCKET_POOL_SIZE; i++) {
        if (upstreamSocketPool[i]) continue;
        
        const socket = dgram.createSocket('udp4');
        upstreamSocketPool[i] = socket;
        
        socket.on('message', (msg) => {
            if (msg.length < 2) return;
            const txId = msg.readUInt16BE(0);
            const req = pendingRequests.get(txId);
            if (req) {
                pendingRequests.delete(txId);
                if (req.timer) clearTimeout(req.timer);
                
                const clientResponse = Buffer.from(msg);
                clientResponse[0] = req.originalIDBytes[0];
                clientResponse[1] = req.originalIDBytes[1];
                req.callback(clientResponse);
            }
        });
        
        socket.on('error', (err) => {
            console.error(`Upstream UDP socket pool index ${i} error:`, err);
            try { socket.close(); } catch (e) {}
            upstreamSocketPool[i] = null;
            setTimeout(initUpstreamSocketPool, 1000);
        });
    }
}

function queryUpstream(dnsQueryBuffer, upstreamIP, callback) {
    initUpstreamSocketPool();
    
    // Distribute via socket pool in round-robin fashion
    const socket = upstreamSocketPool[nextSocketIndex % SOCKET_POOL_SIZE];
    nextSocketIndex = (nextSocketIndex + 1) % SOCKET_POOL_SIZE;
    
    if (!socket) {
        callback(null);
        return;
    }
    
    let txId = nextTxId;
    let attempts = 0;
    while (pendingRequests.has(txId) && attempts < 65536) {
        txId = (txId + 1) % 65536;
        attempts++;
    }
    nextTxId = (txId + 1) % 65536;
    
    const originalIDBytes = Buffer.from([dnsQueryBuffer[0], dnsQueryBuffer[1]]);
    const upstreamQueryBuffer = Buffer.from(dnsQueryBuffer);
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
    
    socket.send(upstreamQueryBuffer, 0, upstreamQueryBuffer.length, 53, upstreamIP, (err) => {
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
    
    // Perform Racing
    const pool = config.upstreamPool || [];
    const onlinePool = pool.filter(s => s.online !== false && s.ip !== upstreamDNS);
    const sorted = [...onlinePool].sort((a, b) => (a.latency || 0) - (b.latency || 0));
    const secondUpstreamDNS = sorted.length > 0 ? sorted[0].ip : null;
    
    let resolved = false;
    let queriesActive = 1;
    
    const onResponse = (response) => {
        if (resolved) return;
        
        if (response) {
            resolved = true;
            const queue = activeUpstreamQueries.get(key) || [];
            activeUpstreamQueries.delete(key);
            
            queue.forEach(item => {
                const clientResponse = Buffer.from(response);
                clientResponse[0] = item.originalIDBytes[0];
                clientResponse[1] = item.originalIDBytes[1];
                item.callback(clientResponse);
            });
        } else {
            queriesActive--;
            if (queriesActive === 0) {
                resolved = true;
                const queue = activeUpstreamQueries.get(key) || [];
                activeUpstreamQueries.delete(key);
                queue.forEach(item => item.callback(null));
            }
        }
    };
    
    queryUpstream(queryData, upstreamDNS, onResponse);
    
    if (config.dnsRacingEnabled && secondUpstreamDNS) {
        queriesActive++;
        const racingDelay = config.dnsRacingDelayMs || 15;
        setTimeout(() => {
            if (!resolved) {
                queryUpstream(queryData, secondUpstreamDNS, onResponse);
            } else {
                queriesActive--;
            }
        }, racingDelay);
    }
}

// Groq API helpers
function getNextGroqKey() {
    const keys = config.groqApiKeys || [];
    const availableKeys = keys.filter(isKeyAvailable);
    if (availableKeys.length === 0) return null;
    const key = availableKeys[groqKeyIndex % availableKeys.length];
    groqKeyIndex = (groqKeyIndex + 1) % availableKeys.length;
    return key;
}

function getMaxConcurrentGroq() {
    const keys = config.groqApiKeys;
    if (!keys || keys.length === 0) return 0;
    return keys.length * GROQ_CONCURRENCY_PER_KEY;
}

// Load Balancer DNS Selector
function selectUpstreamDNS(domain) {
    const pool = config.upstreamPool || [];
    if (pool.length === 0) return "1.1.1.1";
    
    const onlinePool = pool.filter(s => s.online !== false);
    const activePool = onlinePool.length > 0 ? onlinePool : pool;
    
    const algo = config.lbAlgorithm || "least-latency";
    
    if (algo === "round-robin") {
        if (selectUpstreamDNS.index === undefined) selectUpstreamDNS.index = 0;
        const server = activePool[selectUpstreamDNS.index % activePool.length];
        selectUpstreamDNS.index = (selectUpstreamDNS.index + 1) % activePool.length;
        return server.ip;
    }
    
    if (algo === "random") {
        const idx = Math.floor(Math.random() * activePool.length);
        return activePool[idx].ip;
    }
    
    if (algo === "ai-routing" && config.aiEnabled) {
        const cacheVal = aiDecisionCache.get(domain);
        if (cacheVal) {
            try {
                if (cacheVal.startsWith('{')) {
                    const parsed = JSON.parse(cacheVal);
                    if (parsed && parsed.targetIP) {
                        const s = activePool.find(x => x.ip === parsed.targetIP);
                        if (s && s.online !== false) return s.ip;
                    }
                }
            } catch(e) {}
        }
    }
    
    // Default: least-latency
    const sorted = [...activePool].sort((a, b) => (a.latency || 0) - (b.latency || 0));
    return sorted[0].ip;
}

// Famous safe networks
const SAFE_DOMAINS_SUFFIXES = [
    ".google.com", ".googleapis.com", ".gstatic.com", ".googleusercontent.com",
    ".apple.com", ".icloud.com", ".mzstatic.com", ".apple-dns.net", ".itunes.com",
    ".microsoft.com", ".windows.com", ".live.com", ".office.com", ".msn.com",
    ".cloudflare.com", ".facebook.com", ".fbcdn.net", ".instagram.com",
    ".youtube.com", ".ytimg.com", ".ggpht.com", ".github.com"
];

function isSafeDomain(domain) {
    const d = domain.trim().toLowerCase();
    const exactMatches = ["google.com", "apple.com", "microsoft.com", "cloudflare.com", "facebook.com", "youtube.com"];
    if (exactMatches.includes(d)) return true;
    for (const suffix of SAFE_DOMAINS_SUFFIXES) {
        if (d.endsWith(suffix)) return true;
    }
    return false;
}

// Heuristics Fast-Path Rules
function getFastPathCategory(domain) {
    const d = domain.trim().toLowerCase();
    
    if (d.includes('cdn') || d.includes('static') || d.includes('image') || d.includes('media') || 
        d.includes('video') || d.includes('stream') || d.includes('fbcdn') || d.includes('tiktokcdn') ||
        d.includes('akamai') || d.includes('cloudfront') || d.includes('fastly') || d.includes('ytimg') ||
        d.endsWith('.png') || d.endsWith('.jpg') || d.endsWith('.mp4') || d.endsWith('.mp3')) {
        return "Media/CDN";
    }
    
    if (d.includes('api') || d.includes('auth') || d.includes('login') || d.includes('service') ||
        d.includes('oauth') || d.includes('backend') || d.includes('sign-in') || d.endsWith('signup')) {
        return "API/App";
    }
    
    if (d.includes('ad') || d.includes('track') || d.includes('telemetry') || d.includes('analytic') ||
        d.includes('doubleclick') || d.includes('pixel') || d.includes('scam') || d.includes('phish') ||
        d.includes('fake') || d.includes('verify')) {
        return "Security";
    }
    
    return null;
}

function enqueueGroqCheck(domain) {
    const d = domain.trim().toLowerCase();
    if (!d || d.includes('localhost') || d.includes('127.0.0.1') || IGNORED_DOMAINS.has(d)) return;
    if (d.endsWith('.local') || d.endsWith('.localhost')) return;
    if (aiDecisionCache.has(d)) return;
    
    // 1. Fast-Path Heuristic Check
    const fastPath = getFastPathCategory(d);
    if (fastPath) {
        let targetIP = "1.1.1.1";
        if (fastPath === "Security") targetIP = "9.9.9.9";
        else if (fastPath === "Media/CDN") targetIP = "8.8.8.8";
        else {
            const sorted = [...(config.upstreamPool || [])].sort((a,b) => (a.latency || 0) - (b.latency || 0));
            if (sorted.length > 0) targetIP = sorted[0].ip;
        }
        aiDecisionCache.set(d, JSON.stringify({ category: fastPath, targetIP }));
        saveAICache();
        return;
    }
    
    // 2. Safe domains check
    if (isSafeDomain(d)) {
        aiDecisionCache.set(d, JSON.stringify({ category: "General/Search", targetIP: "1.1.1.1" }));
        saveAICache();
        return;
    }
    
    if (!config.groqApiKeys || config.groqApiKeys.length === 0) return;
    aiDecisionCache.set(d, JSON.stringify({ category: "General/Search", targetIP: "1.1.1.1" }));
    
    groqQueue.push(d);
    // processGroqQueue will be triggered asynchronously by live queue workers
}

// Live Queue Multi-Key Concurrency Workers
let liveWorkerTimeouts = [];
function runLiveGroqQueue() {
    if (!config.aiEnabled || !config.groqApiKeys || config.groqApiKeys.length === 0) {
        liveWorkerTimeouts.forEach(clearTimeout);
        liveWorkerTimeouts = [];
        return;
    }
    
    liveWorkerTimeouts.forEach(clearTimeout);
    liveWorkerTimeouts = [];
    
    console.log(`[AI Live Queue] Starting ${config.groqApiKeys.length} concurrent live workers...`);
    config.groqApiKeys.forEach((apiKey, idx) => {
        const startDelay = idx * 1000;
        const timeoutId = setTimeout(() => {
            runLiveWorker(apiKey);
        }, startDelay);
        liveWorkerTimeouts.push(timeoutId);
    });
}

function runLiveWorker(apiKey) {
    if (!config.aiEnabled || !config.groqApiKeys || !config.groqApiKeys.includes(apiKey)) {
        return;
    }
    
    if (!isKeyAvailable(apiKey)) {
        const timeoutId = setTimeout(() => runLiveWorker(apiKey), 5000);
        liveWorkerTimeouts.push(timeoutId);
        return;
    }
    
    if (groqQueue.length === 0 || isQueuePaused) {
        const timeoutId = setTimeout(() => runLiveWorker(apiKey), 2000);
        liveWorkerTimeouts.push(timeoutId);
        return;
    }
    
    const domain = groqQueue.shift();
    activeGroqRequests++;
    
    checkDomainWithGroq(domain, apiKey, () => {
        activeGroqRequests--;
        const timeoutId = setTimeout(() => runLiveWorker(apiKey), 15000);
        liveWorkerTimeouts.push(timeoutId);
    });
}

function gatherInternetContext(domain) {
    return new Promise((resolve) => {
        const result = {
            resolvedIPs: [],
            resolvedCNAMEs: [],
            resolvedNSs: [],
            httpStatus: null,
            serverHeader: null,
            contentType: null,
            htmlTitle: null,
            error: null
        };
        const dns = require('dns');
        
        let pending = 3;
        const checkDone = () => {
            pending--;
            if (pending === 0) {
                probeHTTP();
            }
        };
        
        dns.resolve4(domain, (err, addresses) => {
            if (!err && addresses) {
                result.resolvedIPs = addresses.slice(0, 3);
            }
            checkDone();
        });
        
        dns.resolveCname(domain, (err, addresses) => {
            if (!err && addresses) {
                result.resolvedCNAMEs = addresses.slice(0, 3);
            }
            checkDone();
        });
        
        dns.resolveNs(domain, (err, addresses) => {
            if (!err && addresses) {
                result.resolvedNSs = addresses.slice(0, 3);
            }
            checkDone();
        });
        
        function probeHTTP() {
            const http = require('http');
            const url = `http://${domain}/`;
            let reqFinished = false;
            const req = http.get(url, { timeout: 1200 }, (res) => {
                reqFinished = true;
                result.httpStatus = res.statusCode;
                result.serverHeader = res.headers['server'] || null;
                result.contentType = res.headers['content-type'] || null;
                let data = '';
                res.on('data', chunk => {
                    data += chunk.toString('utf8');
                    if (data.length > 2000) res.destroy();
                });
                res.on('end', () => {
                    const match = data.match(/<title>([^<]+)<\/title>/i);
                    if (match && match[1]) result.htmlTitle = match[1].trim();
                    resolve(result);
                });
            });
            req.on('error', (err) => {
                reqFinished = true;
                result.error = err.code || err.message;
                resolve(result);
            });
            req.on('timeout', () => {
                if (!reqFinished) {
                    req.destroy();
                    result.error = "TIMEOUT";
                    resolve(result);
                }
            });
        }
    });
}

function buildAIAnalysisContext(domain, internetContext = null) {
    const d = domain.trim().toLowerCase();
    const parts = d.split('.');
    const tld = parts[parts.length - 1];
    let prompt = `Domain to analyze: ${domain}\nTLD: .${tld}\n`;
    if (internetContext) {
        prompt += `Live Probe Data:\n- IPs: ${JSON.stringify(internetContext.resolvedIPs)}\n`;
        if (internetContext.resolvedCNAMEs && internetContext.resolvedCNAMEs.length > 0) {
            prompt += `- CNAMEs: ${JSON.stringify(internetContext.resolvedCNAMEs)}\n`;
        }
        if (internetContext.resolvedNSs && internetContext.resolvedNSs.length > 0) {
            prompt += `- Name Servers (NS): ${JSON.stringify(internetContext.resolvedNSs)}\n`;
        }
        prompt += `- HTTP: ${internetContext.httpStatus}, Server: ${internetContext.serverHeader}, Title: "${internetContext.htmlTitle || 'N/A'}"\n- Error: ${internetContext.error || 'None'}\n`;
    }
    return prompt;
}

function getUpstreamPoolPromptContext() {
    const pool = config.upstreamPool || [];
    return pool.map(s => `- ${s.name} (${s.ip}): latency ${s.latency || 0}ms, status: ${s.online !== false ? 'ONLINE' : 'OFFLINE'}`).join('\n');
}

function checkDomainWithGroq(domain, apiKey, callback, modelIndex = 0, internetContext = null) {
    if (process.env.MOCK_GROQ === 'true' || apiKey.startsWith('gsk_mock')) {
        setTimeout(() => {
            let category = "General/Search";
            if (domain.includes('ad') || domain.includes('track') || domain.includes('pixel') || domain.includes('telemetry') || domain.includes('bank') || domain.includes('pay') || domain.includes('verify')) {
                category = "Security";
            } else if (domain.includes('cdn') || domain.includes('media') || domain.includes('video') || domain.includes('stream') || domain.includes('youtube') || domain.includes('tiktok')) {
                category = "Media/CDN";
            }
            
            let targetIP = "1.1.1.1";
            if (category === "Security") targetIP = "9.9.9.9";
            else if (category === "Media/CDN") targetIP = "8.8.8.8";
            else {
                const sorted = [...(config.upstreamPool || [])].sort((a,b) => (a.latency || 0) - (b.latency || 0));
                if (sorted.length > 0) targetIP = sorted[0].ip;
            }
            
            const cacheVal = JSON.stringify({ category, targetIP });
            aiDecisionCache.set(domain, cacheVal);
            saveAICache();
            learnedExamples.push({ domain, category, reason: "Phân loại giả lập" });
            if (learnedExamples.length > 1000) learnedExamples.shift();
            saveAILearning();
            logQuery(domain, category, "System", "Local Cache", "cache");
            if (callback) callback();
        }, 1000);
        return;
    }

    if (internetContext === null) {
        gatherInternetContext(domain).then((context) => {
            checkDomainWithGroq(domain, apiKey, callback, modelIndex, context);
        });
        return;
    }
    
    if (!apiKey) {
        aiDecisionCache.delete(domain);
        if (callback) callback();
        return;
    }
    
    if (modelIndex >= FALLBACK_MODELS.length) {
        isQueuePaused = true;
        if (!groqQueue.includes(domain)) groqQueue.unshift(domain);
        aiDecisionCache.delete(domain);
        if (queueTimeoutId) clearTimeout(queueTimeoutId);
        queueTimeoutId = setTimeout(() => {
            isQueuePaused = false;
            queueTimeoutId = null;
            runLiveGroqQueue();
        }, 60000);
        if (callback) callback();
        return;
    }
    
    const model = FALLBACK_MODELS[modelIndex];
    const blockedEx = learnedExamples.filter(ex => ex.category === "Security").slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.category !== "Security").slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"category": "${ex.category}", "reason": "${ex.reason}"}`).join('\n');

    const poolContext = getUpstreamPoolPromptContext();
    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Analyze the domain name and determine the best upstream DNS IP to route the query based on the current upstream pool status and latency:\n\n" +
                          "Current Upstream Pool Status:\n" + poolContext + "\n\n" +
                          "Strict Routing Logic Rules:\n" +
                          "1. Category 'Security' (ad, tracker, telemetry, scam, phishing): Route to Quad9 (9.9.9.9) for security filtering. If Quad9 is OFFLINE or latency is extremely high (>300ms), fallback and route to OpenDNS (208.67.222.222) or Cloudflare (1.1.1.1).\n" +
                          "2. Category 'Media/CDN' (streaming, video, images, static assets): Route to Google (8.8.8.8) or Cloudflare (1.1.1.1) depending on which is faster (lower latency).\n" +
                          "3. Category 'General/Search' or 'API/App': Route to the DNS server with the lowest latency in the pool.\n\n" +
                          "Respond in strict JSON format: { \"category\": \"Security\" | \"Media/CDN\" | \"General/Search\" | \"API/App\", \"targetIP\": \"[chosen DNS server IP]\", \"reason\": \"1-3 words in Vietnamese explaining routing choice\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: model,
        messages: [
            { role: "system", content: systemContent },
            { role: "user", content: buildAIAnalysisContext(domain, internetContext) }
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
    const triggerFallback = () => {
        if (!fallbackCalled) {
            fallbackCalled = true;
            checkDomainWithGroq(domain, apiKey, callback, modelIndex + 1, internetContext);
        }
    };
    
    try {
        const req = https.request(options, (res) => {
            let body = [];
            res.on('data', chunk => body.push(chunk));
            res.on('end', () => {
                try {
                    if (res.statusCode !== 200) {
                        if (res.statusCode === 429 || res.statusCode === 401) {
                            console.warn(`[AI Live] Key ${apiKey.substring(0, 8)}... error ${res.statusCode}. Cool down active for 60s.`);
                            keyCooldowns.set(apiKey, Date.now() + 60000);
                        }
                        triggerFallback();
                        return;
                    }
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        const category = decision.category || "General/Search";
                        const targetIP = decision.targetIP || "1.1.1.1";
                        const cacheVal = JSON.stringify({ category, targetIP });
                        aiDecisionCache.set(domain, cacheVal);
                        saveAICache();
                        
                        learnedExamples.push({ domain, category, reason: decision.reason || "AI Cân bằng tải" });
                        if (learnedExamples.length > 1000) learnedExamples.shift();
                        saveAILearning();
                        
                        broadcastUpdate();
                        if (callback) callback();
                    } else {
                        triggerFallback();
                    }
                } catch (e) {
                    triggerFallback();
                }
            });
        });
        req.on('error', triggerFallback);
        req.write(postData);
        req.end();
    } catch (e) {
        triggerFallback();
    }
}

// Logs and Stats
function logQuery(domain, category, clientIP, targetIP, source = "upstream") {
    const now = new Date();
    const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
    const timeStr = vnTime.toISOString().substring(11, 19);
    
    let statusText = `✈️ ROUTED [${targetIP}]`;
    if (source === "cache") {
        statusText = `⚡ CACHED`;
    } else if (source === "gslb") {
        statusText = `🔄 GSLB [${targetIP}]`;
    }
    
    const categoryText = category ? `[${category}]` : "[General/Search]";
    const msg = `[${timeStr}] [${clientIP}] ${statusText} ${categoryText} - ${domain}`;
    
    logs.push(msg);
    if (logs.length > 100) {
        logs.shift();
    }
    throttledBroadcastUpdate();
}

// DNS Configuration & Cache Load/Save
function loadConfig() {
    const defaultPool = [
        { ip: "1.1.1.1", name: "Cloudflare", latency: 0, online: true },
        { ip: "8.8.8.8", name: "Google", latency: 0, online: true },
        { ip: "9.9.9.9", name: "Quad9", latency: 0, online: true },
        { ip: "208.67.222.222", name: "OpenDNS", latency: 0, online: true }
    ];

    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const data = fs.readFileSync(CONFIG_PATH, 'utf8');
            config = JSON.parse(data);
        } else {
            config = {
                upstreamPool: defaultPool,
                lbAlgorithm: "least-latency",
                gslbRecords: {},
                stats: { total: 0, cacheHits: 0, cacheMisses: 0 },
                aiEnabled: false,
                groqApiKeys: [],
                groqTrainKeys: [],
                groqModel: "llama-3.1-8b-instant",
                dnsRacingEnabled: true,
                dnsRacingDelayMs: 15
            };
            saveConfig();
        }
    } catch (e) {
        console.error("Failed to load config, using defaults:", e);
        config = {
            upstreamPool: defaultPool,
            lbAlgorithm: "least-latency",
            gslbRecords: {},
            stats: { total: 0, cacheHits: 0, cacheMisses: 0 },
            aiEnabled: false,
            groqApiKeys: [],
            groqTrainKeys: [],
            groqModel: "llama-3.1-8b-instant",
            dnsRacingEnabled: true,
            dnsRacingDelayMs: 15
        };
    }
    
    config.stats = config.stats || {};
    config.stats.total = config.stats.total || 0;
    config.stats.cacheHits = config.stats.cacheHits || 0;
    config.stats.cacheMisses = config.stats.cacheMisses || 0;
    config.aiEnabled = config.aiEnabled || false;
    config.groqModel = "llama-3.1-8b-instant";
    config.upstreamPool = config.upstreamPool || defaultPool;
    config.lbAlgorithm = config.lbAlgorithm || "least-latency";
    config.gslbRecords = config.gslbRecords || {};
    config.dnsRacingEnabled = config.dnsRacingEnabled !== undefined ? config.dnsRacingEnabled : true;
    config.dnsRacingDelayMs = config.dnsRacingDelayMs !== undefined ? config.dnsRacingDelayMs : 15;
    
    if (!Array.isArray(config.groqApiKeys)) config.groqApiKeys = [];
    if (!Array.isArray(config.groqTrainKeys)) config.groqTrainKeys = [];
    
    if (process.env.GROQ_API_KEYS) {
        const envKeys = process.env.GROQ_API_KEYS.split(',').map(k => k.trim()).filter(k => k.length > 0);
        envKeys.forEach(k => {
            if (!config.groqApiKeys.includes(k)) config.groqApiKeys.push(k);
        });
    }
    config.groqApiKeys = config.groqApiKeys.filter(k => k && k.trim().length > 0);

    if (process.env.GROQ_TRAIN_KEYS) {
        const envKeys = process.env.GROQ_TRAIN_KEYS.split(',').map(k => k.trim()).filter(k => k.length > 0);
        envKeys.forEach(k => {
            if (!config.groqTrainKeys.includes(k)) config.groqTrainKeys.push(k);
        });
    }
    config.groqTrainKeys = config.groqTrainKeys.filter(k => k && k.trim().length > 0);
}

function saveConfig() {
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (e) {
        console.error("Failed to save config:", e);
    }
}

// Background latency measurements
function buildQueryBufferForMeasure(domain) {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(Math.floor(Math.random() * 65535), 0);
    header.writeUInt16BE(0x0100, 2);
    header.writeUInt16BE(1, 4);
    
    const parts = domain.split('.');
    const buffers = [header];
    parts.forEach(part => {
        buffers.push(Buffer.from([part.length]));
        buffers.push(Buffer.from(part, 'ascii'));
    });
    buffers.push(Buffer.from([0]));
    buffers.push(Buffer.from([0, 1])); // Type A
    buffers.push(Buffer.from([0, 1])); // Class IN
    
    return Buffer.concat(buffers);
}

function measureUpstreamLatency(ip) {
    const queryBuffer = buildQueryBufferForMeasure("google.com");
    const start = Date.now();
    queryUpstream(queryBuffer, ip, (response) => {
        const elapsed = Date.now() - start;
        const server = config.upstreamPool.find(s => s.ip === ip);
        if (server) {
            if (response) {
                server.latency = elapsed;
                server.online = true;
            } else {
                server.latency = 9999;
                server.online = false;
            }
            broadcastUpdate();
        }
    });
}

function measureUpstreamPool() {
    if (!config.upstreamPool || config.upstreamPool.length === 0) return;
    config.upstreamPool.forEach(server => {
        measureUpstreamLatency(server.ip);
    });
}

// Startup Initialization
loadConfig();
loadAILearning();
loadAICache();

// Periodic Latency Checking
setInterval(measureUpstreamPool, 30000);
setTimeout(measureUpstreamPool, 3000); // Check shortly after start
setInterval(runCacheGC, 60000); // Cache Garbage Collector every 60s

setTimeout(runStartupAITraining, 15000);
setTimeout(runLiveGroqQueue, 16000);

function runCacheGC() {
    const now = Date.now();
    let deletedCount = 0;
    for (const [key, value] of dnsCache.entries()) {
        if (now >= value.expiresAt) {
            dnsCache.delete(key);
            deletedCount++;
        }
    }
    if (deletedCount > 0) {
        console.log(`[Cache GC] Cleared ${deletedCount} expired cache entries. Current cache size: ${dnsCache.size}`);
    }
}

// Raw body parser middleware for DNS binary payloads
app.use((req, res, next) => {
    const data = [];
    req.on('data', chunk => data.push(chunk));
    req.on('end', () => {
        req.rawBody = Buffer.concat(data);
        next();
    });
});

app.use(express.static(path.join(__dirname, 'public')));

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
    
    const targetDNS = selectUpstreamDNS(domain);
    
    const completeQuery = (responseBuffer, fromCache = false, isGslb = false, gslbIPs = "") => {
        const latency = Date.now() - startTime;
        totalLatency += latency;
        latencyCount++;
        
        const logDomain = (domain !== originalDomain) ? `${domain} (${originalDomain})` : domain;
        const source = isGslb ? "gslb" : (fromCache ? "cache" : "upstream");
        const targetIP = isGslb ? gslbIPs : (fromCache ? "Local Cache" : targetDNS);
        
        // Retrieve category from decision cache
        let category = "General/Search";
        const cacheVal = aiDecisionCache.get(domain);
        if (cacheVal) {
            try {
                if (cacheVal.startsWith('{')) {
                    category = JSON.parse(cacheVal).category || "General/Search";
                } else {
                    category = cacheVal;
                }
            } catch(e) {}
        }
        
        logQuery(logDomain, category, clientIP, targetIP, source);
        config.stats.total += 1;
        
        let lastSaveTimeout = null;
        if (!lastSaveTimeout) {
            lastSaveTimeout = setTimeout(() => {
                lastSaveTimeout = null;
                saveConfig();
            }, 5000);
        }
        
        callback(responseBuffer);
        
        if (config.aiEnabled && config.groqApiKeys && config.groqApiKeys.length > 0) {
            enqueueGroqCheck(domain);
        }
        if (config.aiEnabled && config.groqTrainKeys && config.groqTrainKeys.length > 0) {
            enqueueDomainForTraining(domain);
        }
    };
    
    // Check GSLB records (only Type A IPv4 queries)
    if (qtype === 1 && config.gslbRecords && config.gslbRecords[domain]) {
        const ips = config.gslbRecords[domain];
        if (ips && ips.length > 0) {
            const rotated = [...ips];
            const first = rotated.shift();
            rotated.push(first);
            config.gslbRecords[domain] = rotated;
            
            const gslbResponse = buildGslbResponse(queryData, parsed.questionEndOffset, rotated);
            completeQuery(gslbResponse, false, true, rotated.join(', '));
            return;
        }
    }
    
    // 1. Check local cache
    const cachedResponse = checkCache(originalDomain, qtype);
    if (cachedResponse) {
        const clientResponse = Buffer.from(cachedResponse);
        clientResponse[0] = queryData[0];
        clientResponse[1] = queryData[1];
        completeQuery(clientResponse, true, false);
    } else {
        // 2. Fetch from chosen upstream DNS
        fetchFromUpstreamDeduplicated(queryData, originalDomain, qtype, targetDNS, (response) => {
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

// POST endpoint for DoH
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

// GET endpoint for DoH
app.get('/dns-query', (req, res) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || req.ip;
    const dnsParam = req.query.dns;
    if (!dnsParam) {
        res.status(400).send("Bad Request: Missing 'dns' parameter");
        return;
    }
    let base64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
    const mod = base64.length % 4;
    if (mod > 0) base64 += "=".repeat(4 - mod);
    const queryData = Buffer.from(base64, 'base64');
    handleDoH(queryData, clientIP, req.headers.host, (responseData) => {
        res.setHeader('Content-Type', 'application/dns-message');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(responseData);
    });
});

// MARK: - Dashboard API Endpoints
app.get('/dns/config', (req, res) => {
    const stats = {
        total: config.stats.total,
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
        avgLatency: latencyCount > 0 ? (totalLatency / latencyCount) : 0
    };
    res.json({
        running: true,
        logs: logs,
        stats: stats,
        aiEnabled: !!config.aiEnabled,
        groqApiKeys: (config.groqApiKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqApiKeysCooldown: (config.groqApiKeys || []).map(k => keyCooldowns.has(k) && Date.now() < keyCooldowns.get(k)),
        groqApiKeysCount: (config.groqApiKeys || []).length,
        groqTrainKeys: (config.groqTrainKeys || []).map(k => k.substring(0, 8) + '...' + k.substring(k.length - 4)),
        groqTrainKeysCooldown: (config.groqTrainKeys || []).map(k => keyCooldowns.has(k) && Date.now() < keyCooldowns.get(k)),
        groqTrainKeysCount: (config.groqTrainKeys || []).length,
        aiTrainingStatus: aiTrainingStatus,
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        groqMaxConcurrent: (config.groqApiKeys || []).length * GROQ_CONCURRENCY_PER_KEY,
        learnedExamples: learnedExamples,
        serverStatus: getServerStatus(),
        
        // Load Balancer fields
        upstreamPool: config.upstreamPool || [],
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
        aiCacheCount: aiDecisionCache.size,
        aiQueueLength: groqQueue.length,
        dnsRacingEnabled: !!config.dnsRacingEnabled,
        dnsRacingDelayMs: config.dnsRacingDelayMs || 15
    });
});

// Upstream pool endpoints
app.get('/dns/upstream/pool', (req, res) => {
    res.json(config.upstreamPool || []);
});

app.post('/dns/upstream/pool/add', (req, res) => {
    const ip = req.query.ip;
    const name = req.query.name || "DNS Server";
    if (!ip) return res.status(400).send("Missing ip parameter");
    
    config.upstreamPool = config.upstreamPool || [];
    if (config.upstreamPool.some(s => s.ip === ip)) {
        return res.status(400).send("IP already exists in pool");
    }
    
    config.upstreamPool.push({ ip, name, latency: 0, online: true });
    saveConfig();
    measureUpstreamLatency(ip);
    broadcastUpdate();
    res.send(`Added ${ip} to pool`);
});

app.post('/dns/upstream/pool/remove', (req, res) => {
    const ip = req.query.ip;
    if (!ip) return res.status(400).send("Missing ip parameter");
    
    config.upstreamPool = (config.upstreamPool || []).filter(s => s.ip !== ip);
    saveConfig();
    broadcastUpdate();
    res.send(`Removed ${ip} from pool`);
});

app.post('/dns/lb/algorithm', (req, res) => {
    const algo = req.query.algo;
    const validAlgos = ["round-robin", "least-latency", "random", "ai-routing"];
    if (!algo || !validAlgos.includes(algo)) {
        return res.status(400).send("Invalid algorithm");
    }
    config.lbAlgorithm = algo;
    saveConfig();
    broadcastUpdate();
    res.send(`Updated LB algorithm to ${algo}`);
});

// GSLB endpoints
app.get('/dns/gslb', (req, res) => {
    res.json(config.gslbRecords || {});
});

app.post('/dns/gslb/add', (req, res) => {
    const domain = req.query.domain;
    const ip = req.query.ip;
    if (!domain || !ip) return res.status(400).send("Missing domain or ip parameter");
    
    const d = domain.trim().toLowerCase();
    const cleanIp = ip.trim();
    
    config.gslbRecords = config.gslbRecords || {};
    config.gslbRecords[d] = config.gslbRecords[d] || [];
    if (!config.gslbRecords[d].includes(cleanIp)) {
        config.gslbRecords[d].push(cleanIp);
    }
    saveConfig();
    broadcastUpdate();
    res.send(`Added GSLB mapping: ${d} -> ${cleanIp}`);
});

app.post('/dns/gslb/remove', (req, res) => {
    const domain = req.query.domain;
    const ip = req.query.ip;
    if (!domain) return res.status(400).send("Missing domain parameter");
    
    const d = domain.trim().toLowerCase();
    config.gslbRecords = config.gslbRecords || {};
    
    if (ip) {
        const cleanIp = ip.trim();
        if (config.gslbRecords[d]) {
            config.gslbRecords[d] = config.gslbRecords[d].filter(x => x !== cleanIp);
            if (config.gslbRecords[d].length === 0) {
                delete config.gslbRecords[d];
            }
        }
    } else {
        delete config.gslbRecords[d];
    }
    saveConfig();
    broadcastUpdate();
    res.send(`Removed GSLB mapping for ${d}`);
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
        setTimeout(runLiveGroqQueue, 2000);
    } else {
        liveWorkerTimeouts.forEach(clearTimeout);
        liveWorkerTimeouts = [];
    }
    res.send("Groq configuration updated");
});

app.post('/dns/racing', (req, res) => {
    const enabled = req.query.enabled === 'true';
    const delay = parseInt(req.query.delay, 10);
    config.dnsRacingEnabled = enabled;
    if (!isNaN(delay) && delay >= 0) {
        config.dnsRacingDelayMs = delay;
    }
    saveConfig();
    broadcastUpdate();
    res.send("DNS Racing configuration updated");
});

app.post('/dns/groq/keys/add', (req, res) => {
    const key = req.query.key;
    if (!key || !key.trim()) return res.status(400).json({ error: 'Missing key parameter' });
    const trimmedKey = key.trim();
    if (!Array.isArray(config.groqApiKeys)) config.groqApiKeys = [];
    if (config.groqApiKeys.includes(trimmedKey)) return res.status(400).json({ error: 'Key already exists' });
    config.groqApiKeys.push(trimmedKey);
    saveConfig();
    broadcastUpdate();
    if (config.aiEnabled) runLiveGroqQueue();
    res.json({ count: config.groqApiKeys.length, maxConcurrent: config.groqApiKeys.length * GROQ_CONCURRENCY_PER_KEY });
});

app.post('/dns/groq/keys/remove', (req, res) => {
    const index = parseInt(req.query.index, 10);
    if (isNaN(index) || index < 0) return res.status(400).json({ error: 'Invalid index' });
    if (!Array.isArray(config.groqApiKeys) || index >= config.groqApiKeys.length) return res.status(400).json({ error: 'Index out of range' });
    config.groqApiKeys.splice(index, 1);
    saveConfig();
    broadcastUpdate();
    if (config.aiEnabled) runLiveGroqQueue();
    res.json({ count: config.groqApiKeys.length, maxConcurrent: config.groqApiKeys.length * GROQ_CONCURRENCY_PER_KEY });
});

app.post('/dns/groq/train-keys/add', (req, res) => {
    const key = req.query.key;
    if (!key || !key.trim()) return res.status(400).json({ error: 'Missing key parameter' });
    const trimmedKey = key.trim();
    if (!Array.isArray(config.groqTrainKeys)) config.groqTrainKeys = [];
    if (config.groqTrainKeys.includes(trimmedKey)) return res.status(400).json({ error: 'Key already exists' });
    config.groqTrainKeys.push(trimmedKey);
    saveConfig();
    broadcastUpdate();
    if (config.aiEnabled) setTimeout(runStartupAITraining, 2000);
    res.json({ count: config.groqTrainKeys.length });
});

app.post('/dns/groq/train-keys/remove', (req, res) => {
    const index = parseInt(req.query.index, 10);
    if (isNaN(index) || index < 0) return res.status(400).json({ error: 'Invalid index' });
    if (!Array.isArray(config.groqTrainKeys) || index >= config.groqTrainKeys.length) return res.status(400).json({ error: 'Index out of range' });
    config.groqTrainKeys.splice(index, 1);
    saveConfig();
    broadcastUpdate();
    res.json({ count: config.groqTrainKeys.length });
});

function runTestWithFallback(domain, apiKey, res, modelIndex = 0) {
    if (modelIndex >= FALLBACK_MODELS.length) {
        return res.status(500).json({ error: "Tất cả các mô hình Groq đều gặp lỗi. Vui lòng thử lại sau." });
    }
    const model = FALLBACK_MODELS[modelIndex];
    const blockedEx = learnedExamples.filter(ex => ex.category === "Security").slice(-2);
    const allowedEx = learnedExamples.filter(ex => ex.category !== "Security").slice(-2);
    const recentExamples = [...blockedEx, ...allowedEx];
    const examplesText = "\n\nVí dụ phân loại đã học gần đây để tuân theo:\n" + 
        recentExamples.map(ex => `- ${ex.domain} -> {"category": "${ex.category}", "reason": "${ex.reason}"}`).join('\n');

    const poolContext = getUpstreamPoolPromptContext();
    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Analyze the domain name and determine the best upstream DNS IP to route the query based on the current upstream pool status and latency:\n\n" +
                          "Current Upstream Pool Status:\n" + poolContext + "\n\n" +
                          "Strict Routing Logic Rules:\n" +
                          "1. Category 'Security' (ad, tracker, telemetry, scam, phishing): Route to Quad9 (9.9.9.9) for security filtering. If Quad9 is OFFLINE or latency is extremely high (>300ms), fallback and route to OpenDNS (208.67.222.222) or Cloudflare (1.1.1.1).\n" +
                          "2. Category 'Media/CDN' (streaming, video, images, static assets): Route to Google (8.8.8.8) or Cloudflare (1.1.1.1) depending on which is faster (lower latency).\n" +
                          "3. Category 'General/Search' or 'API/App': Route to the DNS server with the lowest latency in the pool.\n\n" +
                          "Respond in strict JSON format: { \"category\": \"Security\" | \"Media/CDN\" | \"General/Search\" | \"API/App\", \"targetIP\": \"[chosen DNS server IP]\", \"reason\": \"1-3 words in Vietnamese explaining routing choice\" }." +
                          examplesText;

    const postData = JSON.stringify({
        model: model,
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
    
    let fallbackCalled = false;
    const triggerFallback = () => {
        if (!fallbackCalled) {
            fallbackCalled = true;
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
                        if (response.statusCode === 429 || response.statusCode === 401) {
                            console.warn(`[AI Test] Key ${apiKey.substring(0, 8)}... error ${response.statusCode}. Cool down active for 60s.`);
                            keyCooldowns.set(apiKey, Date.now() + 60000);
                        }
                        triggerFallback();
                        return;
                    }
                    const resData = JSON.parse(responseString);
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        decision.modelUsed = model;
                        return res.json(decision);
                    } else {
                        triggerFallback();
                    }
                } catch (e) {
                    triggerFallback();
                }
            });
        });
        request.on('error', triggerFallback);
        request.write(postData);
        request.end();
    } catch (e) {
        triggerFallback();
    }
}

app.get('/dns/groq/test', (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: "Missing domain parameter" });
    const apiKey = getNextGroqKey();
    if (!apiKey) return res.status(400).json({ error: "No API Keys configured." });
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
    aiTrainingStatus.trainedList = [];
    trainingQueue = [];
    totalTrainingEnqueued = 0;
    totalTrainingProcessed = 0;
    broadcastUpdate();
    res.send("AI learning log reset to defaults.");
    if (config.aiEnabled) setTimeout(runStartupAITraining, 1000);
});

app.post('/dns/ai/cache/clear', (req, res) => {
    aiDecisionCache.clear();
    saveAICache();
    broadcastUpdate();
    res.send("AI classification cache cleared.");
});

app.post('/dns/ai/learning/sync', (req, res) => {
    try {
        if (!req.rawBody || req.rawBody.length === 0) return res.status(400).send("Empty payload");
        const list = JSON.parse(req.rawBody.toString('utf8'));
        if (Array.isArray(list)) {
            list.forEach(item => {
                if (item && typeof item.domain === 'string') {
                    const domainLower = item.domain.toLowerCase().trim();
                    const exists = learnedExamples.some(ex => ex.domain.toLowerCase().trim() === domainLower);
                    if (!exists) {
                        learnedExamples.push({
                            domain: item.domain.trim(),
                            category: item.category || "General/Search",
                            reason: item.reason || "Đồng bộ hóa"
                        });
                    }
                }
            });
            if (learnedExamples.length > 1000) {
                learnedExamples.splice(0, learnedExamples.length - 1000);
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
    config.stats = { total: 0, cacheHits: 0, cacheMisses: 0 };
    totalLatency = 0;
    latencyCount = 0;
    saveConfig();
    broadcastUpdate();
    res.send("Stats reset");
});

app.post('/dns/toggle', (req, res) => {
    res.json({ running: true });
});

// Graceful shutdown hooks
function gracefulShutdown() {
    console.log("Shutting down. Saving config and caches...");
    if (lastLearningSaveTimeout) {
        clearTimeout(lastLearningSaveTimeout);
        try {
            fs.writeFileSync(AI_LEARNED_PATH, JSON.stringify(learnedExamples, null, 2), 'utf8');
        } catch (e) {}
    }
    if (lastCacheSaveTimeout) {
        clearTimeout(lastCacheSaveTimeout);
        try {
            const obj = {};
            for (const [k, v] of aiDecisionCache.entries()) {
                obj[k] = v;
            }
            fs.writeFileSync(AI_CACHE_PATH, JSON.stringify(obj, null, 2), 'utf8');
        } catch (e) {}
    }
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (e) {}
    process.exit(0);
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Render DNS Load Balancer & AI Router running on port ${PORT}`);
});
