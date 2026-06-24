const express = require('express');
const http = require('http');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const https = require('https');
const WebSocket = require('ws');
const os = require('os');
const crypto = require('crypto');

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

// State variables
let config = {};
let logs = [];
const domainQueryWeights = new Map();
let lastSeenClientIP = "115.79.0.1"; // Track client IP for background queries
const clientRegistry = new Map(); // Key: clientIP, Value: { ip, firstSeen, lastSeen, queryCount, totalLatency, userAgent, lastDomain }

// WebSocket client registry
const wsClients = new Set();

// Performance Metrics & Local DNS Cache
const dnsCache = new Map(); // Key: domain + '_' + qtype, Value: { responseBuffer, createdAt, expiresAt }
let MAX_CACHE_SIZE = 250000;
const activeUpstreamQueries = new Map(); // Key: domain + '_' + qtype, Value: Array of waiting client callbacks

// Event Loop Lag Monitor (Precise Process CPU Load Tracking)
let eventLoopLag = 0;
function measureEventLoopLag() {
    const start = Date.now();
    setImmediate(() => {
        const lag = Date.now() - start;
        eventLoopLag = eventLoopLag * 0.9 + lag * 0.1; // Exponential Moving Average (EMA)
    });
}
setInterval(measureEventLoopLag, 1000);

// Pre-warmed Vietnamese & Global domains list to build always-hot memory cache
const BASE_POPULAR_DOMAINS = [
    // Global Tech & Search
    "google.com", "google.com.vn", "google.ad", "google.ae", "google.com.sg", "google.co.jp",
    "dns.google", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "bing.com",
    "apple.com", "icloud.com", "itunes.com", "mzstatic.com", "apple-dns.net",
    "amazon.com", "aws.amazon.com", "amazonaws.com", "cloudflare.com", "one.one.one.one",

    // Social Media & Video
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "youtube.com", "youtu.be", "ggpht.com", "ytimg.com",
    "tiktok.com", "tiktokv.com", "ibyteimg.com", "byteoversea.com",
    "twitter.com", "twimg.com", "t.co",
    "netflix.com", "nflxvideo.net", "nflxext.com",
    "twitch.tv", "github.com", "wikipedia.org",

    // Vietnamese News & Media
    "vnexpress.net", "zingnews.vn", "zing.vn", "tuoitre.vn", "thanhnien.vn", "dantri.com.vn",
    "kenh14.vn", "vietnamnet.vn", "tinhte.vn", "vtv.vn", "vov.vn", "sggp.org.vn",
    "zalo.me", "zaloapp.com", "zalocdn.com", "nhaccuatui.com", "mp3.zing.vn",

    // Vietnamese E-commerce & Logistics
    "shopee.vn", "shopeemobile.com", "shopeepay.vn", "lazada.vn", "tiki.vn", "sendo.vn",
    "ghn.vn", "ghtk.vn", "viettelpost.com.vn", "vnpost.vn", "grab.com", "be.com.vn",

    // Vietnamese Banking & Finance
    "vietcombank.com.vn", "bidv.com.vn", "vietinbank.co", "vietinbank.vn", "agribank.com.vn",
    "techcombank.com", "mbbank.com.vn", "sacombank.com.vn", "acb.com.vn", "vpbank.com.vn",
    "vps.com.vn", "ssi.com.vn", "vndirect.com.vn", "momo.vn", "vnpay.vn", "zalopay.vn",

    // Telco & ISP CDN
    "viettel.com.vn", "vietteltelecom.vn", "vnpt.com.vn", "mobifone.vn", "vinaphone.com.vn",
    "fpt.com.vn", "fptplay.vn", "fpt.vn",

    // Games
    "garena.vn", "lienquan.garena.vn", "fifaaddict.com", "roblox.com", "steamcommunity.com",
    "steampowered.com", "pubgmobile.com", "moonton.com", "freefiremobile.com"
];

const SUBDOMAINS = [
    "www", "m", "api", "apis", "cdn", "static", "media", "img", "images", 
    "assets", "video", "auth", "login", "accounts", "app", "status",
    "chat", "dev", "shop", "portal", "news", "mail", "secure", "cloud", 
    "download", "upload", "test", "register"
];

// Programmatically generate over 2,400 popular subdomains to populate memory cache
const POPULAR_DOMAINS = [];
BASE_POPULAR_DOMAINS.forEach(domain => {
    POPULAR_DOMAINS.push(domain);
    SUBDOMAINS.forEach(sub => {
        POPULAR_DOMAINS.push(`${sub}.${domain}`);
    });
});

function prewarmCache() {
    console.log(`[Always-Hot Cache] Starting rate-limited pre-warming of ${POPULAR_DOMAINS.length} popular domains...`);
    
    let index = 0;
    const batchSize = 100; // 100 domains (200 records) per batch
    const intervalMs = 800; // every 800ms for faster pre-warming using RAM
    
    function processBatch() {
        const batch = POPULAR_DOMAINS.slice(index, index + batchSize);
        if (batch.length === 0) {
            console.log(`[Always-Hot Cache] Pre-warming fully completed. Current cache size: ${dnsCache.size}`);
            return;
        }
        
        batch.forEach(domain => {
            [1, 28].forEach(qtype => {
                const subnet = getClientSubnetPrefix(lastSeenClientIP || "115.79.0.1");
                const cacheKey = `${domain}_${qtype}_${subnet}`;
                if (!dnsCache.has(cacheKey)) {
                    // Populate query weights to mark them as popular on startup
                    domainQueryWeights.set(domain, 3);
                    
                    const targetDNS = selectUpstreamDNS(domain, true);
                    const queryBuffer = addECS(buildQueryBufferForMeasure(domain), lastSeenClientIP || "115.79.0.1");
                    fetchFromUpstreamDeduplicated(queryBuffer, domain, qtype, targetDNS, (response) => {
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl, lastSeenClientIP || "115.79.0.1");
                        }
                    }, true);
                }
            });
        });
        
        index += batchSize;
        setTimeout(processBatch, intervalMs);
    }
    
    processBatch();
}

function getClientSubnetPrefix(ip) {
    if (!ip || ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip.endsWith("127.0.0.1")) return "local";
    if (ip.includes(':')) {
        const parts = ip.split(':');
        return parts.slice(0, 3).join(':'); // /48 prefix
    } else {
        const parts = ip.split('.');
        if (parts.length === 4) {
            return `${parts[0]}.${parts[1]}.${parts[2]}`; // /24 prefix
        }
        return ip;
    }
}

const PREDICTIVE_MAP = {
    "vnexpress.net": ["s.vnecdn.net", "e.vnecdn.net", "b.vnecdn.net", "s1.vnecdn.net", "vnecdn.net"],
    "zingnews.vn": ["znews-static.zadn.vn", "znews-photo.zadn.vn", "zadn.vn"],
    "zing.vn": ["znews-static.zadn.vn", "znews-photo.zadn.vn", "zadn.vn"],
    "zalo.me": ["zalocdn.com", "wpa.zalo.me", "chat.zalo.me"],
    "facebook.com": ["static.xx.fbcdn.net", "scontent.xx.fbcdn.net", "video.xx.fbcdn.net", "connect.facebook.net", "fbcdn.net"],
    "youtube.com": ["ytimg.com", "i.ytimg.com", "s.ytimg.com", "ggpht.com", "googlevideo.com"],
    "shopee.vn": ["cf.shopee.vn", "deo.shopeemobile.com", "shopeemobile.com"],
    "lazada.vn": ["g.alicdn.com", "img.alicdn.com", "laz-img-cdn.alicdn.com", "sg-live-01.slatic.net"],
    "tiktok.com": ["lf16-pkgcdn.pitcontent.com", "v16.tiktokcdn.com", "sf16-muse-va.ibytedtos.com"],
    "google.com": ["gstatic.com", "apis.google.com", "googleusercontent.com", "dns.google"]
};

function triggerPredictivePrefetch(domain) {
    if (!domain) return;
    const d = domain.toLowerCase();
    const assets = PREDICTIVE_MAP[d];
    if (assets && assets.length > 0) {
        console.log(`[Predictive Cache] Main domain ${domain} queried. Prefetching ${assets.length} associated asset domains...`);
        assets.forEach(asset => {
            [1, 28].forEach(qtype => {
                const subnet = getClientSubnetPrefix(lastSeenClientIP || "115.79.0.1");
                const cacheKey = `${asset}_${qtype}_${subnet}`;
                if (!dnsCache.has(cacheKey)) {
                    const targetDNS = selectUpstreamDNS(asset, true);
                    const queryBuffer = addECS(buildQueryBufferForMeasure(asset), lastSeenClientIP || "115.79.0.1");
                    fetchFromUpstreamDeduplicated(queryBuffer, asset, qtype, targetDNS, (response) => {
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(asset, qtype, response, newTtl, lastSeenClientIP || "115.79.0.1");
                        }
                    }, true);
                }
            });
        });
    }
}

function recordServerHealth(server, isSuccess) {
    if (!server) return;
    if (!server.history) server.history = [];
    server.history.push(isSuccess);
    if (server.history.length > 20) {
        server.history.shift();
    }
    const successes = server.history.filter(h => h === true).length;
    server.successRate = Math.round((successes / server.history.length) * 100);
}

function parseUserAgent(ua) {
    if (!ua) return "Không xác định";
    const lowercase = ua.toLowerCase();
    
    // Command line tools or APIs
    if (lowercase.includes("curl") || lowercase.includes("wget")) {
        return "⚙️ CLI Client (curl/wget)";
    }
    if (lowercase.includes("go-http-client") || lowercase.includes("okhttp") || lowercase.includes("python-requests") || lowercase.includes("node-fetch") || lowercase.includes("axios")) {
        return "☕ API/Library Client";
    }
    
    // Main OS
    if (lowercase.includes("iphone") || lowercase.includes("ipad") || lowercase.includes("ipod") || lowercase.includes("cfnetwork") || lowercase.includes("darwin")) {
        return "📱 iOS / Apple Device";
    }
    if (lowercase.includes("android")) {
        return "🤖 Android Device";
    }
    if (lowercase.includes("windows")) {
        return "💻 Windows PC";
    }
    if (lowercase.includes("macintosh") || lowercase.includes("mac os")) {
        return "🖥️ macOS Device";
    }
    if (lowercase.includes("linux")) {
        return "🐧 Linux Client";
    }
    return "🌐 Web/HTTP Client";
}

function maskIP(ip) {
    if (!ip) return "Unknown";
    if (ip.includes(':')) {
        const parts = ip.split(':');
        return parts.slice(0, 3).join(':') + '::xxxx';
    } else {
        const parts = ip.split('.');
        if (parts.length === 4) {
            return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
        }
        return ip;
    }
}

function recordClientQuery(ip, userAgent, elapsed, domain, reqSize = 0, resSize = 0, fromCache = false, isError = false, targetDNS = "") {
    if (!ip || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.0.0.")) return;
    const now = Date.now();
    const parsedUA = parseUserAgent(userAgent);
    
    let client = clientRegistry.get(ip);
    if (!client) {
        client = {
            ip: ip,
            firstSeen: now,
            lastSeen: now,
            queryCount: 0,
            totalLatency: 0,
            minLatency: elapsed,
            maxLatency: elapsed,
            userAgent: parsedUA,
            rawUA: userAgent,
            lastDomain: domain,
            cacheHits: 0,
            cacheMisses: 0,
            successCount: 0,
            errorCount: 0,
            bytesReceived: 0,
            bytesSent: 0,
            upstreams: {},
            timestamps: [],
            upstreamStats: {},
            clientToServerRTT: null
        };
        clientRegistry.set(ip, client);
    }
    
    client.queryCount++;
    client.totalLatency += elapsed;
    client.minLatency = Math.min(client.minLatency, elapsed);
    client.maxLatency = Math.max(client.maxLatency, elapsed);
    client.lastSeen = now;
    client.lastDomain = domain;
    
    if (fromCache) {
        client.cacheHits++;
    } else {
        client.cacheMisses++;
    }
    
    if (isError) {
        client.errorCount++;
    } else {
        client.successCount++;
    }
    
    client.bytesReceived += reqSize;
    client.bytesSent += resSize;
    
    if (targetDNS) {
        client.upstreams[targetDNS] = (client.upstreams[targetDNS] || 0) + 1;
        
        // Record client-specific upstream latency stats
        if (targetDNS !== "Local Cache" && targetDNS !== "GSLB Load Balancer") {
            if (!client.upstreamStats) client.upstreamStats = {};
            if (!client.upstreamStats[targetDNS]) {
                client.upstreamStats[targetDNS] = { totalLatency: 0, count: 0, avg: 0 };
            }
            const stats = client.upstreamStats[targetDNS];
            stats.totalLatency += elapsed;
            stats.count++;
            stats.avg = Math.round(stats.totalLatency / stats.count * 10) / 10;
        }
    }
    
    client.timestamps.push(now);
    if (client.timestamps.length > 20) {
        client.timestamps.shift();
    }
    
    // Auto-prune old clients if the registry grows too large
    if (clientRegistry.size > 1000) {
        const pruneThreshold = now - 24 * 3600 * 1000;
        for (const [key, value] of clientRegistry.entries()) {
            if (value.lastSeen < pruneThreshold) {
                clientRegistry.delete(key);
            }
        }
    }
}

function getClientsList() {
    // Calculate average RTT of active clients who have clientToServerRTT
    let sumRtt = 0;
    let rttCount = 0;
    for (const cl of clientRegistry.values()) {
        if (cl.clientToServerRTT !== null && cl.clientToServerRTT !== undefined) {
            sumRtt += cl.clientToServerRTT;
            rttCount++;
        }
    }
    const avgClientRtt = rttCount > 0 ? Math.round(sumRtt / rttCount) : 50; // default 50ms mobile baseline

    return Array.from(clientRegistry.values()).map(c => {
        const effectiveRtt = (c.clientToServerRTT !== null && c.clientToServerRTT !== undefined) 
            ? c.clientToServerRTT 
            : avgClientRtt;

        const avgLat = c.queryCount > 0 ? Math.round(c.totalLatency / c.queryCount * 10) / 10 : 0;
        
        let qps = 0;
        if (c.timestamps && c.timestamps.length > 1) {
            const timeDiff = (c.timestamps[c.timestamps.length - 1] - c.timestamps[0]) / 1000;
            if (timeDiff > 0.5) {
                qps = Math.round((c.timestamps.length - 1) / timeDiff * 10) / 10;
            }
        }
        
        let prefUpstream = "-";
        let maxCount = 0;
        if (c.upstreams) {
            for (const [up, count] of Object.entries(c.upstreams)) {
                if (count > maxCount) {
                    maxCount = count;
                    prefUpstream = up;
                }
            }
        }
        
        const cacheHitRate = (c.cacheHits + c.cacheMisses) > 0 
            ? Math.round(c.cacheHits / (c.cacheHits + c.cacheMisses) * 100) 
            : 0;
            
        const successRate = (c.successCount + c.errorCount) > 0
            ? Math.round(c.successCount / (c.successCount + c.errorCount) * 100)
            : 100;
            
        let healthScore = 100;
        if (c.queryCount > 0) {
            const errorRate = c.errorCount / c.queryCount;
            healthScore -= errorRate * 50;
            const latPenalty = Math.min(30, (avgLat / 150) * 30);
            healthScore -= latPenalty;
            const jitter = (c.maxLatency || 0) - (c.minLatency || 0);
            const jitterPenalty = Math.min(20, (jitter / 200) * 20);
            healthScore -= jitterPenalty;
            healthScore = Math.max(10, Math.round(healthScore));
        }
        
        return {
            ip: maskIP(c.ip),
            queryCount: c.queryCount,
            avgLatency: Math.round((avgLat + effectiveRtt) * 10) / 10,
            minLatency: Math.round(((c.minLatency !== undefined ? c.minLatency : avgLat) + effectiveRtt) * 10) / 10,
            maxLatency: Math.round(((c.maxLatency !== undefined ? c.maxLatency : avgLat) + effectiveRtt) * 10) / 10,
            userAgent: c.userAgent,
            lastDomain: c.lastDomain,
            lastSeenAgoSeconds: Math.round((Date.now() - c.lastSeen) / 1000),
            cacheHits: c.cacheHits || 0,
            cacheMisses: c.cacheMisses || 0,
            cacheHitRate: cacheHitRate,
            successRate: successRate,
            bytesReceived: c.bytesReceived || 0,
            bytesSent: c.bytesSent || 0,
            qps: qps,
            prefUpstream: prefUpstream,
            healthScore: healthScore,
            clientToServerRTT: c.clientToServerRTT !== undefined ? c.clientToServerRTT : null
        };
    }).sort((a, b) => b.queryCount - a.queryCount).slice(0, 50);
}

// Upstream UDP Client Sockets Pool
let SOCKET_POOL_SIZE = 100;
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

// Precalculated LLES routing pool to optimize selection performance to O(1)
let precalculatedLlesPool = [];
let precalculatedLlesTotalWeight = 0;

function rebuildLlesRoutingPool() {
    const pool = config.upstreamPool || [];
    // Only include servers that are online, not quarantined, and NOT stabilizing
    const onlinePool = pool.filter(s => s.online !== false && !s.quarantined && !s.stabilizing && (s.latency || 0) < 9999);
    
    if (onlinePool.length === 0) {
        // Fallback to any online, non-quarantined servers (including stabilizing ones) to avoid complete outage
        const fallbackPool = pool.filter(s => s.online !== false && !s.quarantined);
        const finalPool = fallbackPool.length > 0 ? fallbackPool : pool;
        precalculatedLlesPool = finalPool.map(s => ({ ip: s.ip, weight: 1.0 }));
        precalculatedLlesTotalWeight = precalculatedLlesPool.length;
        return;
    }
    
    let minLatency = Infinity;
    for (let i = 0; i < onlinePool.length; i++) {
        const s = onlinePool[i];
        if (typeof s.latency === 'number' && s.latency < minLatency && s.latency > 0) {
            minLatency = s.latency;
        }
    }
    if (minLatency === Infinity) minLatency = 20;
    
    const threshold = config.llesThresholdMs !== undefined ? config.llesThresholdMs : 150;
    
    precalculatedLlesPool = onlinePool.map(s => {
        const isLowLat = s.latency <= minLatency + threshold;
        return {
            ip: s.ip,
            weight: isLowLat ? 1.0 : 0.05
        };
    });
    
    precalculatedLlesTotalWeight = precalculatedLlesPool.reduce((sum, item) => sum + item.weight, 0);
}

// Background timer to check and expire quarantined servers every 5 seconds,
// completely offloading it from the hot query path.
function checkExpiredQuarantines() {
    const pool = config.upstreamPool || [];
    const now = Date.now();
    let changed = false;
    pool.forEach(s => {
        if (s.quarantined && now > (s.quarantineUntil || 0)) {
            s.quarantined = false;
            s.consecutiveFailures = 0;
            s.stabilizing = true;
            s.consecutiveStablePings = 0;
            changed = true;
            console.log(`[Upstream Autopilot] Quarantine expired for ${s.name} (${s.ip}). Entering stabilizing phase.`);
        }
    });

    // Requirement 2: Emergency Recovery / Self-Healing
    // If all servers are quarantined, offline, or stabilizing, reset them to prevent a complete outage.
    const activeServers = pool.filter(s => s.online !== false && !s.quarantined && !s.stabilizing);
    if (activeServers.length === 0 && pool.length > 0) {
        console.warn(`[Upstream Autopilot] EMERGENCY: All upstream DNS servers are quarantined or offline! Triggering emergency recovery.`);
        pool.forEach(s => {
            s.online = true;
            s.quarantined = false;
            s.quarantineUntil = 0;
            s.consecutiveFailures = 0;
            s.stabilizing = false;
            s.consecutiveStablePings = 0;
            s.latency = Math.floor(Math.random() * 20) + 30; // Reset to a low baseline (30ms - 50ms) to trigger healthy probing
            s.successRate = 100;
            s.history = [];
        });
        changed = true;
    }

    if (changed) {
        rebuildLlesRoutingPool();
        throttledBroadcastUpdate();
    }
}
setInterval(checkExpiredQuarantines, 5000);

// WebSocket connection handler
wss.on('connection', (ws, req) => {
    const clientIP = req ? (req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress) : null;
    ws._socketIP = clientIP;
    wsClients.add(ws);
    
    // Send initial configuration and stats
    try {
        const payload = getWSUpdatePayload();
        ws.send(JSON.stringify(payload));
    } catch (e) {
        console.error("Error sending initial WS state:", e);
    }

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong', id: data.id }));
            } else if (data.type === 'client-rtt') {
                if (ws._socketIP && clientRegistry.has(ws._socketIP)) {
                    const client = clientRegistry.get(ws._socketIP);
                    client.clientToServerRTT = data.rtt;
                }
            }
        } catch (e) {
            // Ignore parse errors
        }
    });

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
    const memUsage = process.memoryUsage().rss; // bytes
    const memUsageMb = Math.round(memUsage / 1024 / 1024);
    const avgLat = latencyCount > 0 ? (totalLatency / latencyCount) : 0;
    
    let status = "Ổn định";
    let statusClass = "stable"; // stable, warning, overloaded
    
    // Evaluate status using event loop lag as well
    if (memUsageMb > 400 || avgLat > 250 || eventLoopLag > 100) {
        status = "Quá tải";
        statusClass = "overloaded";
    } else if (memUsageMb > 250 || avgLat > 120 || eventLoopLag > 30) {
        status = "Tải cao";
        statusClass = "warning";
    }
    
    const cpuLoadPct = Math.round(Math.min(100, (eventLoopLag / 50) * 100) * 10) / 10;
    
    return {
        status,
        statusClass,
        memoryUsage: memUsageMb,
        memoryLimit: 512,
        cpuLoad: cpuLoadPct
    };
}

function getCongestionLevel() {
    const memUsage = process.memoryUsage().rss; // bytes
    const memUsageMb = Math.round(memUsage / 1024 / 1024);
    const avgLat = latencyCount > 0 ? (totalLatency / latencyCount) : 0;
    
    const latCont = Math.min(100, (avgLat / 200) * 100);
    const ramCont = Math.min(100, (memUsageMb / 380) * 100);
    const cpuCont = Math.min(100, (eventLoopLag / 50) * 100); // 50ms lag = 100% congestion
    
    return Math.round(Math.max(latCont, ramCont, cpuCont));
}

function isNetworkCongested() {
    return getCongestionLevel() > 70;
}

function isUpstreamCongested() {
    const pool = config.upstreamPool || [];
    const activeServers = pool.filter(s => s.online !== false && !s.quarantined);
    if (activeServers.length === 0) return true; // All down/quarantined -> treated as congested/in crisis
    
    let sumLatency = 0;
    let count = 0;
    activeServers.forEach(s => {
        if (typeof s.latency === 'number' && s.latency > 0 && s.latency < 9999) {
            sumLatency += s.latency;
            count++;
        }
    });
    const avgUpstreamLatency = count > 0 ? (sumLatency / count) : 0;
    return avgUpstreamLatency > 400;
}

function getWSUpdatePayload() {
    // Calculate average RTT of active clients who have clientToServerRTT
    let sumRtt = 0;
    let rttCount = 0;
    for (const cl of clientRegistry.values()) {
        if (cl.clientToServerRTT !== null && cl.clientToServerRTT !== undefined) {
            sumRtt += cl.clientToServerRTT;
            rttCount++;
        }
    }
    const avgClientRtt = rttCount > 0 ? Math.round(sumRtt / rttCount) : 50;

    const baseAvgLatency = latencyCount > 0 ? (totalLatency / latencyCount) : 0;
    const stats = {
        total: config.stats.total,
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
        avgLatency: baseAvgLatency + avgClientRtt
    };
    
    const clientsList = getClientsList();

    return {
        type: 'update',
        running: true,
        logs: logs,
        stats: stats,
        serverStatus: getServerStatus(),
        minCacheTtlSeconds: config.minCacheTtlSeconds || 300,
        activeDevicesCount: clientRegistry.size,
        clientsList: clientsList,
        congestionLevel: getCongestionLevel(),
        
        // Load Balancer fields
        upstreamPool: (config.upstreamPool || []).map(s => {
            const { history, ...rest } = s;
            return rest;
        }),
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
        dnsRacingEnabled: !!config.dnsRacingEnabled,
        dnsRacingDelayMs: config.dnsRacingDelayMs || 15,
        llesThresholdMs: config.llesThresholdMs || 150,
        pingIntervalSeconds: config.pingIntervalSeconds || 3
    };
}



// Local DNS Cache with prefetching and Stale-While-Revalidate (SWR)
function checkCache(domain, qtype, queryData = null, hasECS = false, clientIP = "") {
    const subnet = hasECS ? getClientSubnetPrefix(clientIP || lastSeenClientIP || "115.79.0.1") : "local";
    const key = `${domain.toLowerCase()}_${qtype}_${subnet}`;
    const cached = dnsCache.get(key);
    if (cached) {
        const now = Date.now();
        if (now < cached.expiresAt) {
            
            // Smart Cache Prefetching:
            // Trigger prefetch if remaining TTL < 20% of total TTL
            const totalTTL = (cached.expiresAt - cached.createdAt) / 1000;
            const remainingTTL = (cached.expiresAt - now) / 1000;
            if (totalTTL > 10 && remainingTTL < (totalTTL * 0.2)) {
                const prefetchKey = `prefetch_${key}`;
                if (!activeUpstreamQueries.has(prefetchKey)) {
                    if (isNetworkCongested() || isUpstreamCongested()) {
                        // Skip prefetching to mitigate network/CPU congestion
                        return { responseBuffer: cached.responseBuffer, fromStale: false };
                    }
                    activeUpstreamQueries.set(prefetchKey, true);
                    console.log(`[Cache Prefetch] Triggering background prefetch for: ${domain} (remaining TTL: ${Math.round(remainingTTL)}s / ${Math.round(totalTTL)}s)`);
                    
                    const targetDNS = selectUpstreamDNS(domain, hasECS);
                    const prefetchQueryBuffer = hasECS ? addECS(queryData || buildQueryBufferForMeasure(domain), clientIP || lastSeenClientIP || "115.79.0.1") : (queryData ? Buffer.from(queryData) : buildQueryBufferForMeasure(domain));
                    
                    fetchFromUpstreamDeduplicated(prefetchQueryBuffer, domain, qtype, targetDNS, (response) => {
                        activeUpstreamQueries.delete(prefetchKey);
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl, hasECS ? (clientIP || lastSeenClientIP || "115.79.0.1") : "");
                            console.log(`[Cache Prefetch] Asynchronously updated cache for: ${domain} (New TTL: ${newTtl}s)`);
                        }
                    }, hasECS);
                }
            }

            dnsCache.delete(key);
            dnsCache.set(key, cached);
            return { responseBuffer: cached.responseBuffer, fromStale: false };
        } else {
            // Serve stale cache for up to 12 hours (43200 seconds)
            const staleTtlLimitMs = 12 * 3600 * 1000;
            if (queryData && (now - cached.expiresAt < staleTtlLimitMs)) {
                const revalidateKey = `revalidate_${key}`;
                if (!activeUpstreamQueries.has(revalidateKey)) {
                    if (isNetworkCongested() || isUpstreamCongested()) {
                        // Serve stale directly without revalidating to reduce network queries
                        return { responseBuffer: cached.responseBuffer, fromStale: true };
                    }
                    activeUpstreamQueries.set(revalidateKey, true);
                    console.log(`[Cache SWR] Serving stale cache for: ${domain} (expired ${Math.round((now - cached.expiresAt) / 1000)}s ago). Triggering background revalidate...`);
                    
                    const targetDNS = selectUpstreamDNS(domain, hasECS);
                    const revalidateQueryBuffer = hasECS ? addECS(queryData, clientIP || lastSeenClientIP || "115.79.0.1") : Buffer.from(queryData);
                    
                    fetchFromUpstreamDeduplicated(revalidateQueryBuffer, domain, qtype, targetDNS, (response) => {
                        activeUpstreamQueries.delete(revalidateKey);
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl, hasECS ? (clientIP || lastSeenClientIP || "115.79.0.1") : "");
                            console.log(`[Cache SWR] Background revalidated cache for: ${domain} (New TTL: ${newTtl}s)`);
                        }
                    }, hasECS);
                }
                return { responseBuffer: cached.responseBuffer, fromStale: true };
            }
        }
    }
    return null;
}

function setCache(domain, qtype, responseBuffer, ttl, clientIP = "") {
    const minTtl = config.minCacheTtlSeconds !== undefined ? config.minCacheTtlSeconds : 300;
    const parsedTtl = Number(ttl);
    let finalTtl = (isNaN(parsedTtl) || parsedTtl < minTtl) ? minTtl : parsedTtl;

    // Congestion-Adaptive TTL Boost: shield upstreams during congestion
    if (isNetworkCongested() || isUpstreamCongested()) {
        finalTtl = Math.min(3600, finalTtl * 2);
    }

    const subnet = clientIP ? getClientSubnetPrefix(clientIP) : "local";
    const key = `${domain.toLowerCase()}_${qtype}_${subnet}`;
    if (dnsCache.has(key)) {
        dnsCache.delete(key);
    } else if (dnsCache.size >= MAX_CACHE_SIZE) {
        // Smart Eviction: Avoid evicting popular domains if possible
        let evicted = false;
        const cacheKeys = dnsCache.keys();
        for (let i = 0; i < 50; i++) { // scan up to 50 oldest entries
            const candidateKey = cacheKeys.next().value;
            if (!candidateKey) break;
            const candidateDomain = candidateKey.split('_')[0];
            const weight = domainQueryWeights.get(candidateDomain) || 0;
            if (weight < 2) { // not popular
                dnsCache.delete(candidateKey);
                evicted = true;
                break;
            }
        }
        if (!evicted) {
            // Fallback to basic FIFO if all sampled are popular
            const oldestKey = dnsCache.keys().next().value;
            if (oldestKey) dnsCache.delete(oldestKey);
        }
    }
    dnsCache.set(key, {
        responseBuffer: responseBuffer,
        createdAt: Date.now(),
        expiresAt: Date.now() + (finalTtl * 1000)
    });
}

// Parse IP address to byte array (supports IPv4 and IPv6)
function parseIPToBytes(ip) {
    try {
        if (ip.includes(':')) {
            let address = ip.trim();
            const zoneIdx = address.indexOf('%');
            if (zoneIdx !== -1) {
                address = address.substring(0, zoneIdx);
            }
            
            const parts = address.split(':');
            let result = [];
            
            let nonEmptyCount = parts.filter(p => p !== '').length;
            let missingCount = 8 - nonEmptyCount;
            
            let inserted = false;
            for (let i = 0; i < parts.length; i++) {
                if (parts[i] === '') {
                    if (!inserted) {
                        for (let j = 0; j < missingCount; j++) {
                            result.push(0);
                            result.push(0);
                        }
                        inserted = true;
                    }
                } else {
                    const val = parseInt(parts[i], 16);
                    result.push((val >> 8) & 0xff);
                    result.push(val & 0xff);
                }
            }
            
            while (result.length < 16) {
                result.push(0);
            }
            return result;
        } else {
            const parts = ip.split('.');
            if (parts.length !== 4) return null;
            const bytes = [];
            for (let i = 0; i < 4; i++) {
                const val = parseInt(parts[i], 10);
                if (isNaN(val) || val < 0 || val > 255) return null;
                bytes.push(val);
            }
            return bytes;
        }
    } catch (e) {
        return null;
    }
}

// Add EDNS Client Subnet (ECS) option to DNS query buffer
function addECS(dnsQueryBuffer, clientIP) {
    try {
        if (!clientIP || clientIP === "127.0.0.1" || clientIP === "::1") {
            return dnsQueryBuffer;
        }
        
        const parsed = parseDNSQuery(dnsQueryBuffer);
        if (!parsed) return dnsQueryBuffer;
        
        const questionEnd = parsed.questionEndOffset + 4;
        let cleanQuery = Buffer.alloc(questionEnd);
        dnsQueryBuffer.copy(cleanQuery, 0, 0, questionEnd);
        
        cleanQuery.writeUInt16BE(0, 10); // Clear ARCOUNT in header
        
        const isIPv6 = clientIP.includes(':');
        let family = 1;
        let prefix = 24;
        let ipBytes = parseIPToBytes(clientIP);
        
        if (!ipBytes) return dnsQueryBuffer;
        
        if (isIPv6) {
            family = 2;
            prefix = 48; // /48 subnet for IPv6 GeoIP
            ipBytes = ipBytes.slice(0, 6);
        } else {
            family = 1;
            prefix = config.ecsIPv4PrefixLength !== undefined ? config.ecsIPv4PrefixLength : 24; // /24 or /32 subnet for IPv4 GeoIP
            const sliceLen = Math.min(4, Math.ceil(prefix / 8));
            ipBytes = ipBytes.slice(0, sliceLen);
        }
        
        const ecsOptionLen = 4 + ipBytes.length; // family (2) + source (1) + scope (1) + address
        const ecsOption = Buffer.alloc(4 + ecsOptionLen);
        ecsOption.writeUInt16BE(8, 0); // Option Code 8
        ecsOption.writeUInt16BE(ecsOptionLen, 2); // Option Length
        ecsOption.writeUInt16BE(family, 4); // Family
        ecsOption[6] = prefix; // Source Prefix
        ecsOption[7] = 0; // Scope Prefix
        for (let i = 0; i < ipBytes.length; i++) {
            ecsOption[8 + i] = ipBytes[i];
        }
        
        const optRrHeader = Buffer.alloc(11);
        optRrHeader[0] = 0; // Name .
        optRrHeader.writeUInt16BE(41, 1); // Type OPT
        optRrHeader.writeUInt16BE(4096, 3); // Payload size 4096
        optRrHeader.writeUInt32BE(0, 5); // Extended RCODE & Flags
        optRrHeader.writeUInt16BE(ecsOption.length, 9); // RDATA Length
        
        const finalQuery = Buffer.concat([cleanQuery, optRrHeader, ecsOption]);
        finalQuery.writeUInt16BE(1, 10); // Set ARCOUNT to 1
        
        return finalQuery;
    } catch (e) {
        console.error("[ECS] Failed to add EDNS Client Subnet:", e);
        return dnsQueryBuffer;
    }
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

function buildServfailResponse(queryBuffer) {
    if (!queryBuffer || queryBuffer.length < 12) return Buffer.alloc(0);
    const response = Buffer.from(queryBuffer);
    response.writeUInt16BE(0x8182, 2); // Set flags to SERVFAIL response
    response.writeUInt16BE(0, 4); // QDCOUNT remains 1 (same as query)
    response.writeUInt16BE(0, 6); // ANCOUNT = 0
    response.writeUInt16BE(0, 8); // NSCOUNT = 0
    response.writeUInt16BE(0, 10); // ARCOUNT = 0
    return response;
}

function extractTTL(responseBuffer) {
    try {
        if (!responseBuffer || responseBuffer.length < 12) return 300;
        
        // Skip DNS header (12 bytes)
        let offset = 12;
        
        // Skip Question Section
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
        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        offset += 4;
        
        // Start of Answer Section
        if (offset + 10 > responseBuffer.length) return 300;
        
        // Skip Answer Name
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
                
                // Real-time latency measurement using EMA (Exponential Moving Average)
                const elapsed = Date.now() - req.timestamp;
                const server = config.upstreamPool.find(s => s.ip === req.targetIP);
                if (server) {
                    const oldOnline = server.online;
                    const oldLatency = server.latency || 0;
                    
                    server.lastLatency = oldLatency;
                    const alpha = config.latencyEMAWeight !== undefined ? config.latencyEMAWeight : 0.3;
                    server.latency = Math.round((server.latency || 0) * (1 - alpha) + elapsed * alpha);
                    server.online = true;
                    recordServerHealth(server, true);
                    
                    // Reset consecutive failures on success
                    server.consecutiveFailures = 0;
                    
                    // Real-time latency measurement spike / quarantine logic
                    // Dynamic spike threshold: slide the threshold up if the network is globally slow
                    const activeOnlinePool = config.upstreamPool.filter(s => s.online && !s.quarantined && (s.latency || 0) < 9999);
                    const poolMinLatency = activeOnlinePool.length > 0 ? Math.min(...activeOnlinePool.map(s => s.latency || 15)) : 15;
                    const maxAllowedLatency = Math.max(250, poolMinLatency + (config.llesThresholdMs !== undefined ? config.llesThresholdMs : 150));
                    
                    // Smart Spike Detection:
                    // 1. Absolute threshold check: raw elapsed latency is greater than maxAllowedLatency
                    // 2. Relative spike check: raw elapsed latency is more than 2.5x the server's previous average latency (oldLatency), and elapsed is > 50ms
                    const isSpike = (elapsed > maxAllowedLatency) || (oldLatency > 0 && elapsed > oldLatency * 2.5 && elapsed > 50);
                    
                    if (isSpike && !server.quarantined) {
                        if (!server.stabilizing) {
                            server.stabilizing = true;
                            server.consecutiveStablePings = 0;
                            console.warn(`[Upstream Autopilot] Server ${server.name} (${server.ip}) latency spiked to ${elapsed}ms (previous avg: ${oldLatency}ms). Downgraded to stabilizing pool.`);
                        } else {
                            server.consecutiveStablePings = 0; // Reset count on new spike
                        }
                    }

                    // Stabilization logic: must record 3 consecutive stable pings before returning to pool
                    if (server.stabilizing && !server.quarantined && !isSpike) {
                        const isStable = (elapsed <= maxAllowedLatency) && (elapsed <= Math.max(50, oldLatency * 1.3));
                        if (isStable) {
                            server.consecutiveStablePings = (server.consecutiveStablePings || 0) + 1;
                            console.log(`[Upstream Autopilot] Server ${server.name} (${server.ip}) recorded stable ping: ${elapsed}ms (${server.consecutiveStablePings}/3)`);
                            if (server.consecutiveStablePings >= 3) {
                                server.stabilizing = false;
                                console.log(`[Upstream Autopilot] Server ${server.name} (${server.ip}) has stabilized. Returning to client routing pool.`);
                            }
                        } else {
                            server.consecutiveStablePings = 0; // Reset on any unstable ping
                        }
                    }

                    if (elapsed > 800 && !server.quarantined) {
                        const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                        server.quarantined = true;
                        server.quarantineUntil = Date.now() + Math.round(qDuration / 2); // Half duration for latency spikes
                        server.stabilizing = true;
                        server.consecutiveStablePings = 0;
                        console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 2000)}s due to extremely high latency (${elapsed}ms).`);
                    } else if (server.quarantined && Date.now() > (server.quarantineUntil || 0)) {
                        server.quarantined = false;
                        server.stabilizing = true;
                        server.consecutiveStablePings = 0;
                        console.log(`[Upstream Autopilot] Lifted quarantine for ${server.name} (${server.ip}). Entering stabilizing phase.`);
                    }

                    if (req.isClientQuery) {
                        server.queryCount = (server.queryCount || 0) + 1;
                    }
                    
                    rebuildLlesRoutingPool();
                    throttledBroadcastUpdate();
                }
                
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

function queryUpstream(dnsQueryBuffer, upstreamIP, callback, isClientQuery = false) {
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
            // Real-time timeout penalty: set server as offline / high latency
            const server = config.upstreamPool.find(s => s.ip === upstreamIP);
            if (server) {
                const oldOnline = server.online;
                 server.latency = 9999;
                 server.online = false;
                 recordServerHealth(server, false);
                 
                 // Immediately downgrade to stabilizing
                 server.stabilizing = true;
                 server.consecutiveStablePings = 0;
                
                // Autopilot quarantine: increment consecutive failures
                server.consecutiveFailures = (server.consecutiveFailures || 0) + 1;
                if (server.consecutiveFailures >= 3 && !server.quarantined) {
                    const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                    server.quarantined = true;
                    server.quarantineUntil = Date.now() + qDuration;
                    console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 1000)}s due to 3 consecutive timeouts.`);
                }
                
                rebuildLlesRoutingPool();
                throttledBroadcastUpdate();
            }
            callback(null);
        }
    }, 4000); // 4 seconds query timeout
    
    pendingRequests.set(txId, {
        callback,
        originalIDBytes,
        timer,
        timestamp: Date.now(),
        targetIP: upstreamIP,
        isClientQuery
    });
    
    socket.send(upstreamQueryBuffer, 0, upstreamQueryBuffer.length, 53, upstreamIP, (err) => {
        if (err) {
            console.error(`Failed to send DNS request to upstream ${upstreamIP}:`, err);
            const req = pendingRequests.get(txId);
            if (req) {
                pendingRequests.delete(txId);
                clearTimeout(timer);
                const server = config.upstreamPool.find(s => s.ip === upstreamIP);
                if (server) {
                    const oldOnline = server.online;
                    server.latency = 9999;
                    server.online = false;
                    recordServerHealth(server, false);
                    
                    // Immediately downgrade to stabilizing
                    server.stabilizing = true;
                    server.consecutiveStablePings = 0;
                    
                    // Autopilot quarantine: increment consecutive failures
                    server.consecutiveFailures = (server.consecutiveFailures || 0) + 1;
                    if (server.consecutiveFailures >= 3 && !server.quarantined) {
                        const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                        server.quarantined = true;
                        server.quarantineUntil = Date.now() + qDuration;
                        console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 1000)}s due to consecutive send errors.`);
                    }
                    
                    rebuildLlesRoutingPool();
                    throttledBroadcastUpdate();
                }
                callback(null);
            }
        }
    });
}

function isHighPerformanceDomain(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    return d.includes("speedtest") || 
           d.includes("ookla") || 
           d.includes("fast.com") || 
           d.includes("cdn") ||
           d.includes("vnexpress") ||
           d.includes("zing") ||
           d.includes("tiktok") ||
           d.includes("netflix") ||
           d.includes("facebook") ||
           d.includes("youtube") ||
           d.includes("google");
}

function fetchFromUpstreamDeduplicated(queryData, domain, qtype, upstreamDNS, callback, hasECS = false, clientIP = "") {
    const key = `${domain.toLowerCase()}_${qtype}`;
    const originalIDBytes = Buffer.from([queryData[0], queryData[1]]);
    
    if (activeUpstreamQueries.has(key)) {
        activeUpstreamQueries.get(key).push({ callback, originalIDBytes, isSecondary: true });
        return;
    }
    
    activeUpstreamQueries.set(key, [{ callback, originalIDBytes, isSecondary: false }]);
    
    const pool = config.upstreamPool || [];
    let onlinePool = pool.filter(s => s.online !== false && !s.quarantined && !s.stabilizing);
    if (onlinePool.length === 0) onlinePool = pool.filter(s => s.online !== false && !s.quarantined);
    if (onlinePool.length === 0) onlinePool = pool.filter(s => s.online !== false);
    if (onlinePool.length === 0) onlinePool = pool;
    
    // Note: We no longer exclude non-ECS servers from the online pool to ensure all stable DNS (like Cloudflare) receive load.
    
    // CUSTOM PATH: All-Racing algorithm queries all online servers concurrently
    if (config.lbAlgorithm === "all-racing" && onlinePool.length > 1) {
        let resolved = false;
        let queriesActive = onlinePool.length;
        
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
                    item.callback(clientResponse, item.isSecondary);
                });
            } else {
                queriesActive--;
                if (queriesActive === 0) {
                    resolved = true;
                    const queue = activeUpstreamQueries.get(key) || [];
                    activeUpstreamQueries.delete(key);
                    queue.forEach(item => item.callback(null, item.isSecondary));
                }
            }
        };
        
        onlinePool.forEach(server => {
            queryUpstream(queryData, server.ip, (res) => {
                if (res && !resolved) {
                    server.queryCount = (server.queryCount || 0) + 1;
                }
                onResponse(res);
            }, false); // Pass false so the socket message handler does not increment queryCount again
        });
        return;
    }
    
    // Standard path with potential 2-server racing
    const otherOnlinePool = onlinePool.filter(s => s.ip !== upstreamDNS);
    const sorted = [...otherOnlinePool].sort((a, b) => (a.latency || 0) - (b.latency || 0));
    const secondUpstreamDNS = sorted.length > 0 ? sorted[0].ip : null;
    
    let resolved = false;
    let queriesActive = 1;
    
    const onResponse = (response, respondingIP) => {
        if (resolved) return;
        
        if (response) {
            resolved = true;
            
            // Check if secondary DNS won the race
            if (secondUpstreamDNS && respondingIP === secondUpstreamDNS) {
                config.stats.racingWins = (config.stats.racingWins || 0) + 1;
                console.log(`[DNS Racing] Secondary DNS ${respondingIP} won the race against ${upstreamDNS}!`);
            }

            const winningServer = config.upstreamPool.find(s => s.ip === respondingIP);
            if (winningServer) {
                winningServer.queryCount = (winningServer.queryCount || 0) + 1;
            }
            const queue = activeUpstreamQueries.get(key) || [];
            activeUpstreamQueries.delete(key);
            
            queue.forEach(item => {
                const clientResponse = Buffer.from(response);
                clientResponse[0] = item.originalIDBytes[0];
                clientResponse[1] = item.originalIDBytes[1];
                item.callback(clientResponse, item.isSecondary);
            });
        } else {
            queriesActive--;
            if (queriesActive === 0) {
                resolved = true;
                const queue = activeUpstreamQueries.get(key) || [];
                activeUpstreamQueries.delete(key);
                queue.forEach(item => item.callback(null, item.isSecondary));
            }
        }
    };
    
    queryUpstream(queryData, upstreamDNS, (res) => onResponse(res, upstreamDNS), false);
    
    if (config.dnsRacingEnabled && secondUpstreamDNS) {
        queriesActive++;
        
        // Evaluate client health score for dynamic racing optimization
        let bypassRacingDelay = false;
        if (clientIP && clientRegistry.has(clientIP)) {
            const client = clientRegistry.get(clientIP);
            let healthScore = 100;
            if (client.queryCount > 0) {
                const errorRate = client.errorCount / client.queryCount;
                healthScore -= errorRate * 50;
                const avgLat = client.totalLatency / client.queryCount;
                const latPenalty = Math.min(30, (avgLat / 150) * 30);
                healthScore -= latPenalty;
                const jitter = (client.maxLatency || 0) - (client.minLatency || 0);
                const jitterPenalty = Math.min(20, (jitter / 200) * 20);
                healthScore -= jitterPenalty;
                const clientHealth = Math.max(10, Math.round(healthScore));
                
                // Optimize: If client health is poor (< 80%), reduce racing delay to 2ms
                if (clientHealth < 80) {
                    bypassRacingDelay = true;
                }
            }
        }
        
        // Calculate Adaptive Racing Delay based on jitter of primary server
        const primaryServer = config.upstreamPool.find(s => s.ip === upstreamDNS);
        let racingDelay = config.dnsRacingDelayMs || 15;
        
        const congested = isNetworkCongested();
        
        if (congested) {
            // Under network congestion, increase racing delay to 150ms to prevent packet overhead
            racingDelay = Math.max(racingDelay * 4, 150);
        }
        
        if (bypassRacingDelay && !congested) {
            racingDelay = 2; // parallel query immediately with a 2ms gap
        }
        
        const isPopular = POPULAR_DOMAINS.includes(domain.toLowerCase()) || (domainQueryWeights.get(domain.toLowerCase()) || 0) >= 2;
        if ((isHighPerformanceDomain(domain) || isPopular) && !congested) {
            racingDelay = 0; // Force immediate parallel query for speedtest/CDN/popular domains!
            console.log(`[DNS Racing] Ultra-low latency mode activated for: ${domain}. Racing delay set to 0ms.`);
        } else if (primaryServer && !congested && !bypassRacingDelay) {
            const jitter = Math.abs((primaryServer.latency || 0) - (primaryServer.lastLatency || 0));
            const primaryLatency = primaryServer.latency || 15;
            // Adaptive delay: shrink delay if latency is unstable
            const adaptiveDelay = Math.max(3, Math.round(primaryLatency - jitter * 1.5));
            racingDelay = Math.min(config.dnsRacingDelayMs || 15, adaptiveDelay);
        }
        
        setTimeout(() => {
            if (!resolved) {
                config.stats.racingTotal = (config.stats.racingTotal || 0) + 1;
                queryUpstream(queryData, secondUpstreamDNS, (res) => onResponse(res, secondUpstreamDNS), false);
            } else {
                queriesActive--;
            }
        }, racingDelay);
    }
}



// Low-Latency Equal Share (LLES) Load Balancer DNS Selector
function selectWeightedDNS(clientIP = "") {
    if (precalculatedLlesPool.length === 0) {
        rebuildLlesRoutingPool();
    }
    
    let pool = precalculatedLlesPool;
    let totalWeight = precalculatedLlesTotalWeight;
    
    // Client-specific routing optimization
    if (clientIP && clientRegistry.has(clientIP)) {
        const client = clientRegistry.get(clientIP);
        const upStats = client.upstreamStats;
        
        // Only optimize if client has gathered stats for at least 2 servers
        const hasStats = upStats && Object.keys(upStats).length >= 2;
        if (hasStats) {
            let minClientLat = Infinity;
            const globalPool = config.upstreamPool || [];
            const activeServers = globalPool.filter(s => s.online !== false && !s.quarantined && !s.stabilizing);
            
            activeServers.forEach(s => {
                const stats = upStats[s.ip];
                if (stats && stats.avg > 0 && stats.avg < minClientLat) {
                    minClientLat = stats.avg;
                }
            });
            
            if (minClientLat !== Infinity) {
                const threshold = config.llesThresholdMs !== undefined ? config.llesThresholdMs : 150;
                let clientWeights = [];
                let clientTotalWeight = 0;
                
                activeServers.forEach(s => {
                    const stats = upStats[s.ip];
                    let isLowLat = false;
                    
                    if (stats && stats.avg > 0) {
                        isLowLat = stats.avg <= minClientLat + threshold;
                    } else {
                        // Fallback to global server latency
                        const minGlobalLat = Math.min(...activeServers.map(srv => srv.latency || 20));
                        isLowLat = (s.latency || 20) <= minGlobalLat + threshold;
                    }
                    
                    const weight = isLowLat ? 1.0 : 0.05;
                    clientWeights.push({ ip: s.ip, weight });
                    clientTotalWeight += weight;
                });
                
                if (clientWeights.length > 0) {
                    pool = clientWeights;
                    totalWeight = clientTotalWeight;
                }
            }
        }
    }
    
    if (pool.length === 0) return "1.1.1.1";
    if (pool.length === 1) return pool[0].ip;
    
    let r = Math.random() * totalWeight;
    for (let i = 0; i < pool.length; i++) {
        r -= pool[i].weight;
        if (r <= 0) {
            return pool[i].ip;
        }
    }
    
    return pool[0] ? pool[0].ip : "1.1.1.1";
}

// Load Balancer DNS Selector
function selectUpstreamDNS(domain, hasECS = false, clientIP = "") {
    const algo = config.lbAlgorithm || "least-latency";
    
    // Fast path: Least Latency is default and directly uses precalculated LLES pool
    if (algo === "least-latency") {
        return selectWeightedDNS(clientIP);
    }
    
    const pool = config.upstreamPool || [];
    if (pool.length === 0) return "1.1.1.1";
    
    let onlinePool = pool.filter(s => s.online !== false && !s.quarantined && !s.stabilizing);
    if (onlinePool.length === 0) {
        onlinePool = pool.filter(s => s.online !== false && !s.quarantined);
    }
    if (onlinePool.length === 0) {
        onlinePool = pool.filter(s => s.online !== false);
    }
    if (onlinePool.length === 0) {
        onlinePool = pool;
    }
    
    let activePool = onlinePool;
    
    if (algo === "round-robin") {
        if (selectUpstreamDNS.index === undefined) selectUpstreamDNS.index = 0;
        const server = activePool[selectUpstreamDNS.index % activePool.length];
        selectUpstreamDNS.index = (selectUpstreamDNS.index + 1) % activePool.length;
        return server.ip;
    }
    
    if (algo === "weighted-round-robin") {
        if (selectUpstreamDNS.wrrIndex === undefined) selectUpstreamDNS.wrrIndex = 0;
        
        let wrrList = [];
        const activeFilter = activePool.filter(s => s.online !== false && (s.latency || 0) < 9999);
        if (activeFilter.length === 0) return activePool[0].ip;
        
        const minLat = Math.min(...activeFilter.map(s => Math.max(s.latency || 5, 2)));
        activeFilter.forEach(s => {
            const lat = Math.max(s.latency || 5, 2);
            const weight = Math.max(1, Math.round((minLat / lat) * 10));
            for (let i = 0; i < weight; i++) {
                wrrList.push(s.ip);
            }
        });
        
        if (wrrList.length === 0) return activePool[0].ip;
        const chosenIp = wrrList[selectUpstreamDNS.wrrIndex % wrrList.length];
        selectUpstreamDNS.wrrIndex = (selectUpstreamDNS.wrrIndex + 1) % wrrList.length;
        return chosenIp;
    }
    
    if (algo === "failover") {
        const s = activePool[0];
        return s ? s.ip : "1.1.1.1";
    }
    
    if (algo === "all-racing") {
        return activePool[0].ip;
    }
    
    if (algo === "random") {
        const idx = Math.floor(Math.random() * activePool.length);
        return activePool[idx].ip;
    }
    
    return selectWeightedDNS();
}

// Logs and Stats
function logQuery(domain, category, clientIP, targetIP, source = "upstream") {
    const now = new Date();
    const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
    const timeStr = vnTime.toISOString().substring(11, 19);
    
    let statusText = `✈️ ROUTED [${targetIP}]`;
    if (source === "cache") {
        statusText = `⚡ CACHED`;
    } else if (source === "stale") {
        statusText = `⏳ STALE (SWR)`;
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
        { ip: "1.1.1.1", name: "Cloudflare Primary", latency: 0, online: true, ecsSupported: false },
        { ip: "1.0.0.1", name: "Cloudflare Secondary", latency: 0, online: true, ecsSupported: false },
        { ip: "8.8.8.8", name: "Google Primary", latency: 0, online: true, ecsSupported: true },
        { ip: "8.8.4.4", name: "Google Secondary", latency: 0, online: true, ecsSupported: true },
        { ip: "9.9.9.9", name: "Quad9 Primary", latency: 0, online: true, ecsSupported: true },
        { ip: "149.112.112.112", name: "Quad9 Secondary", latency: 0, online: true, ecsSupported: true },
        { ip: "208.67.222.222", name: "OpenDNS Primary", latency: 0, online: true, ecsSupported: true },
        { ip: "208.67.220.220", name: "OpenDNS Secondary", latency: 0, online: true, ecsSupported: true },
        { ip: "94.140.14.14", name: "AdGuard DNS Primary", latency: 0, online: true, ecsSupported: true },
        { ip: "94.140.15.15", name: "AdGuard DNS Secondary", latency: 0, online: true, ecsSupported: true }
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
                stats: { total: 0, cacheHits: 0, cacheMisses: 0, racingWins: 0, racingTotal: 0 },
                dnsRacingEnabled: true,
                dnsRacingDelayMs: 15,
                minCacheTtlSeconds: 300,
                latencyEMAWeight: 0.3,
                quarantineDurationSeconds: 60,
                staleCacheWindowSeconds: 604800,
                ecsIPv4PrefixLength: 24
            };
            saveConfig();
        }
    } catch (e) {
        console.error("Failed to load config, using defaults:", e);
        config = {
            upstreamPool: defaultPool,
            lbAlgorithm: "least-latency",
            gslbRecords: {},
            stats: { total: 0, cacheHits: 0, cacheMisses: 0, racingWins: 0, racingTotal: 0 },
            dnsRacingEnabled: true,
            dnsRacingDelayMs: 15,
            minCacheTtlSeconds: 300,
            latencyEMAWeight: 0.3,
            quarantineDurationSeconds: 60,
            staleCacheWindowSeconds: 604800,
            ecsIPv4PrefixLength: 24
        };
    }
    
    config.stats = config.stats || {};
    config.stats.total = config.stats.total || 0;
    config.stats.cacheHits = config.stats.cacheHits || 0;
    config.stats.cacheMisses = config.stats.cacheMisses || 0;
    config.stats.racingWins = config.stats.racingWins || 0;
    config.stats.racingTotal = config.stats.racingTotal || 0;
    config.upstreamPool = config.upstreamPool || [];
    // Ensure all defaultPool servers are present in the pool
    defaultPool.forEach(defaultServer => {
        if (!config.upstreamPool.some(s => s.ip === defaultServer.ip)) {
            config.upstreamPool.push(defaultServer);
        }
    });
    config.upstreamPool.forEach(server => {
        server.queryCount = server.queryCount || 0;
        server.history = [];
        server.successRate = 100;
        if (server.ecsSupported === undefined) {
            const noEcsIps = ["1.1.1.1", "1.0.0.1"];
            server.ecsSupported = !noEcsIps.includes(server.ip);
        }
    });
    config.lbAlgorithm = config.lbAlgorithm || "least-latency";
    config.gslbRecords = config.gslbRecords || {};
    config.dnsRacingEnabled = config.dnsRacingEnabled !== undefined ? config.dnsRacingEnabled : true;
    config.dnsRacingDelayMs = config.dnsRacingDelayMs !== undefined ? config.dnsRacingDelayMs : 15;
    config.minCacheTtlSeconds = config.minCacheTtlSeconds !== undefined ? config.minCacheTtlSeconds : 300;
    config.latencyEMAWeight = config.latencyEMAWeight !== undefined ? config.latencyEMAWeight : 0.3;
    config.quarantineDurationSeconds = config.quarantineDurationSeconds !== undefined ? config.quarantineDurationSeconds : 60;
    config.staleCacheWindowSeconds = config.staleCacheWindowSeconds !== undefined ? config.staleCacheWindowSeconds : 604800;
    config.ecsIPv4PrefixLength = config.ecsIPv4PrefixLength !== undefined ? config.ecsIPv4PrefixLength : 24;
    config.llesThresholdMs = config.llesThresholdMs !== undefined ? config.llesThresholdMs : 150;
    config.pingIntervalSeconds = config.pingIntervalSeconds !== undefined ? config.pingIntervalSeconds : 3;
    rebuildLlesRoutingPool();
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
    // Prevent duplicate active background pings for the same IP
    for (const [txId, req] of pendingRequests.entries()) {
        if (req.targetIP === ip && !req.isClientQuery) {
            return;
        }
    }
    
    const domain = "google.com";
    const queryBuffer = buildQueryBufferForMeasure(domain);
    queryUpstream(queryBuffer, ip, (response) => {
        // Note: queryUpstream response/timeout/error handlers will automatically
        // calculate latency, online status, and success rates.
    }, false);
}

function measureUpstreamPool() {
    if (!config.upstreamPool || config.upstreamPool.length === 0) return;
    config.upstreamPool.forEach(server => {
        measureUpstreamLatency(server.ip);
    });
}

// Startup Initialization
loadConfig();

// Periodic Latency Checking
let pingIntervalId = null;
function startPingInterval() {
    if (pingIntervalId) clearInterval(pingIntervalId);
    const intervalMs = (config.pingIntervalSeconds || 3) * 1000;
    pingIntervalId = setInterval(measureUpstreamPool, intervalMs);
}
startPingInterval();
setTimeout(measureUpstreamPool, 1000); // Check shortly after start
setTimeout(prewarmCache, 2000); // Pre-warm RAM cache shortly after start
setInterval(runCacheGC, 60000); // Cache Garbage Collector every 60s
setInterval(runPopularKeepAlive, 20000); // Always-Hot Cache prefetch and decay (every 20s)
let dynamicPrewarmLevel = 1;
setInterval(runRAMCacheOptimizer, 30000); // Dynamic RAM cache optimizer (every 30s)

function runCacheGC() {
    const now = Date.now();
    let deletedCount = 0;
    const maxStaleLimitMs = (config.staleCacheWindowSeconds || 86400) * 1000;
    for (const [key, value] of dnsCache.entries()) {
        if (now >= value.expiresAt + maxStaleLimitMs) {
            dnsCache.delete(key);
            deletedCount++;
        }
    }
    if (deletedCount > 0) {
        console.log(`[Cache GC] Cleared ${deletedCount} extremely stale cache entries. Current cache size: ${dnsCache.size}`);
    }
}

function runPopularKeepAlive() {
    const minPopularThreshold = 2;
    for (const [domain, count] of domainQueryWeights.entries()) {
        if (count >= minPopularThreshold) {
            [1, 28].forEach(qtype => {
                const subnetsToRefresh = new Set(["local"]);
                if (lastSeenClientIP) {
                    subnetsToRefresh.add(getClientSubnetPrefix(lastSeenClientIP));
                }
                
                for (const subnet of subnetsToRefresh) {
                    const key = `${domain.toLowerCase()}_${qtype}_${subnet}`;
                    const cached = dnsCache.get(key);
                    if (cached) {
                        const now = Date.now();
                        const remainingTTL = (cached.expiresAt - now) / 1000;
                        const totalTTL = (cached.expiresAt - cached.createdAt) / 1000;
                        if (remainingTTL < (totalTTL * 0.3)) {
                            console.log(`[Always-Hot Cache] Refreshing popular domain cache: ${domain} (Qtype: ${qtype}, Subnet: ${subnet}, Queries: ${count})`);
                            const hasECS = subnet !== "local";
                            const clientIPForEcs = hasECS ? (lastSeenClientIP || "115.79.0.1") : "";
                            const targetDNS = selectUpstreamDNS(domain, hasECS, clientIPForEcs);
                            const queryBuffer = hasECS ? addECS(buildQueryBufferForMeasure(domain), clientIPForEcs) : buildQueryBufferForMeasure(domain);
                            
                            fetchFromUpstreamDeduplicated(queryBuffer, domain, qtype, targetDNS, (response) => {
                                if (response) {
                                    const newTtl = extractTTL(response);
                                    setCache(domain, qtype, response, newTtl, clientIPForEcs);
                                }
                            }, hasECS, clientIPForEcs);
                        }
                    }
                }
            });
        }
        
        // Decay query count (half-life)
        if (count <= 1) {
            domainQueryWeights.delete(domain);
        } else {
            domainQueryWeights.set(domain, Math.floor(count * 0.5));
        }
    }
}

function resizeUpstreamSocketPool(newSize) {
    if (newSize > SOCKET_POOL_SIZE) {
        SOCKET_POOL_SIZE = newSize;
        initUpstreamSocketPool();
    } else if (newSize < SOCKET_POOL_SIZE) {
        // Close and clean up excess sockets
        for (let i = newSize; i < SOCKET_POOL_SIZE; i++) {
            if (upstreamSocketPool[i]) {
                try {
                    upstreamSocketPool[i].close();
                } catch (e) {}
                upstreamSocketPool[i] = null;
            }
        }
        upstreamSocketPool.length = newSize;
        SOCKET_POOL_SIZE = newSize;
    }
}

function pruneCacheToSize(targetSize) {
    if (dnsCache.size <= targetSize) return;
    const toDelete = dnsCache.size - targetSize;
    let deleted = 0;
    const cacheKeys = dnsCache.keys();
    
    // Evict cold/old entries first
    for (const key of cacheKeys) {
        if (deleted >= toDelete) break;
        const domain = key.split('_')[0];
        const weight = domainQueryWeights.get(domain) || 0;
        if (weight < 2) {
            dnsCache.delete(key);
            deleted++;
        }
    }
    
    // If still need to delete, evict FIFO
    if (deleted < toDelete) {
        for (const key of dnsCache.keys()) {
            if (deleted >= toDelete) break;
            dnsCache.delete(key);
            deleted++;
        }
    }
    console.log(`[RAM Optimizer] Pruned ${deleted} entries to reach target size ${targetSize}. Current size: ${dnsCache.size}`);
}

function triggerExtendedPrewarm() {
    console.log(`[Always-Hot Cache] RAM is abundant. Dynamic pre-warming activated. Launching Extended Tier (Tier 2) pre-warming...`);
    
    const EXTENDED_POPULAR_DOMAINS = [
        "cloudfront.net", "fastly.net", "akamaihd.net", "edgecastcdn.net",
        "doubleclick.net", "google-analytics.com", "googletagmanager.com",
        "facebook.net", "adnxs.com", "rubiconproject.com", "pubmatic.com",
        "openx.net", "appnexus.com", "outbrain.com", "taboola.com",
        "criteo.com", "hotjar.com", "amplitude.com", "mixpanel.com",
        "segment.io", "optimizely.com", "sentry.io", "bugsnag.com",
        "vng.com.vn", "vinagame.com.vn", "admicro.vn", "eclick.vn",
        "novaon.vn", "cleverads.vn", "mgid.com", "popads.net",
        "shopee.co.th", "shopee.sg", "shopee.my", "shopee.id",
        "githubusercontent.com", "npmjs.com", "yarnpkg.com",
        "stackoverflow.com", "medium.com", "reddit.com", "imgur.com",
        "vimeo.com", "dailymotion.com", "zoom.us", "slack.com",
        "discord.com", "discord.gg", "spotify.com", "pinterest.com"
    ];

    const EXTENDED_SUBDOMAINS = [
        "graph", "connect", "creative", "ads", "analytics", "pixel",
        "tracker", "log", "telemetry", "events", "metrics", "stats",
        "static-xx", "scontent", "scontent.xx", "video.xx",
        "s1", "s2", "s3", "s4", "s5", "vnecdn", "zadn",
        "znews-photo", "znews-static", "wpa", "zalocdn"
    ];

    const extDomains = [];
    EXTENDED_POPULAR_DOMAINS.forEach(domain => {
        extDomains.push(domain);
        EXTENDED_SUBDOMAINS.forEach(sub => {
            extDomains.push(`${sub}.${domain}`);
        });
    });

    console.log(`[Always-Hot Cache] Generated ${extDomains.length} Extended Tier domains to warm up in RAM.`);

    let index = 0;
    const batchSize = 100;
    const intervalMs = 800;

    function processExtBatch() {
        const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
        if (rssMb >= 250) {
            console.log(`[Always-Hot Cache] RAM usage reached ${rssMb}MB. Halting Extended Tier pre-warming.`);
            return;
        }

        const batch = extDomains.slice(index, index + batchSize);
        if (batch.length === 0) {
            console.log(`[Always-Hot Cache] Extended Tier pre-warming fully completed. Current cache size: ${dnsCache.size}`);
            return;
        }

        batch.forEach(domain => {
            [1, 28].forEach(qtype => {
                const subnet = getClientSubnetPrefix(lastSeenClientIP || "115.79.0.1");
                const cacheKey = `${domain}_${qtype}_${subnet}`;
                if (!dnsCache.has(cacheKey)) {
                    domainQueryWeights.set(domain, 3);
                    const targetDNS = selectUpstreamDNS(domain, true);
                    const queryBuffer = addECS(buildQueryBufferForMeasure(domain), lastSeenClientIP || "115.79.0.1");
                    fetchFromUpstreamDeduplicated(queryBuffer, domain, qtype, targetDNS, (response) => {
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl, lastSeenClientIP || "115.79.0.1");
                        }
                    }, true);
                }
            });
        });

        index += batchSize;
        setTimeout(processExtBatch, intervalMs);
    }

    processExtBatch();
}

function runRAMCacheOptimizer() {
    const mem = process.memoryUsage();
    const rssMb = Math.round(mem.rss / 1024 / 1024);
    const heapUsedMb = Math.round(mem.heapUsed / 1024 / 1024);
    
    console.log(`[RAM Optimizer] Current RSS: ${rssMb}MB, Heap Used: ${heapUsedMb}MB, Cache Size: ${dnsCache.size}`);
    
    if (rssMb < 150) {
        if (MAX_CACHE_SIZE < 1000000) {
            MAX_CACHE_SIZE = 1000000;
            console.log(`[RAM Optimizer] RSS is low (${rssMb}MB). Upgraded MAX_CACHE_SIZE to 1,000,000.`);
        }
        if (!config.staleCacheWindowSeconds || config.staleCacheWindowSeconds < 2592000) {
            config.staleCacheWindowSeconds = 2592000; // 30 days
            console.log(`[RAM Optimizer] Extended SWR stale window to 30 days.`);
        }
        if (SOCKET_POOL_SIZE < 300) {
            resizeUpstreamSocketPool(300);
            console.log(`[RAM Optimizer] Upgraded SOCKET_POOL_SIZE to 300 sockets.`);
        }
        if (dynamicPrewarmLevel < 2) {
            dynamicPrewarmLevel = 2;
            triggerExtendedPrewarm();
        }
    } else if (rssMb < 300) {
        if (MAX_CACHE_SIZE !== 500000) {
            MAX_CACHE_SIZE = 500000;
            console.log(`[RAM Optimizer] RSS is moderate (${rssMb}MB). Adjusted MAX_CACHE_SIZE to 500,000.`);
        }
    } else if (rssMb >= 300 && rssMb < 400) {
        if (MAX_CACHE_SIZE > 200000) {
            MAX_CACHE_SIZE = 200000;
            console.log(`[RAM Optimizer] RSS is high (${rssMb}MB). Reduced MAX_CACHE_SIZE to 200,000.`);
            pruneCacheToSize(200000);
        }
        if (config.staleCacheWindowSeconds > 86400) {
            config.staleCacheWindowSeconds = 86400; // 24 hours
            console.log(`[RAM Optimizer] Reduced SWR stale window to 24 hours.`);
        }
    } else {
        console.warn(`[RAM Optimizer] CRITICAL RSS limit hit (${rssMb}MB)! Reclaiming RAM immediately...`);
        MAX_CACHE_SIZE = 50000;
        config.staleCacheWindowSeconds = 3600; // 1 hour
        pruneCacheToSize(50000);
        if (SOCKET_POOL_SIZE > 50) {
            resizeUpstreamSocketPool(50);
        }
        if (global.gc) {
            try {
                global.gc();
                console.log(`[RAM Optimizer] Executed V8 global GC.`);
            } catch (e) {
                console.error(`[RAM Optimizer] GC failed:`, e);
            }
        }
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
function handleDoH(queryData, clientIP, hostHeader, userAgent, callback) {
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
    
    const hasECS = !!(clientIP && clientIP !== "127.0.0.1" && clientIP !== "::1" && clientIP !== "::ffff:127.0.0.1" && !clientIP.endsWith("127.0.0.1"));
    
    const completeQuery = (responseBuffer, fromCache = false, isGslb = false, gslbIPs = "", sourceOverride = "", targetDNS = "") => {
        const latency = Date.now() - startTime;
        totalLatency += latency;
        latencyCount++;
        
        let isError = false;
        if (responseBuffer && responseBuffer.length >= 4) {
            const rcode = responseBuffer[3] & 0x0F;
            if (rcode !== 0) {
                isError = true;
            }
        } else {
            isError = true;
        }

        let destLabel = targetDNS;
        if (isGslb) {
            destLabel = "GSLB Load Balancer";
        } else if (fromCache || sourceOverride === "stale" || sourceOverride === "cache") {
            destLabel = "Local Cache";
        }
        if (!destLabel) {
            destLabel = "Unknown Upstream";
        }

        // Record client query metrics
        recordClientQuery(
            clientIP, 
            userAgent, 
            latency, 
            domain, 
            queryData ? queryData.length : 0, 
            responseBuffer ? responseBuffer.length : 0, 
            fromCache || sourceOverride === "stale" || sourceOverride === "cache", 
            isError, 
            destLabel
        );
        
        const logDomain = (domain !== originalDomain) ? `${domain} (${originalDomain})` : domain;
        let source = isGslb ? "gslb" : (fromCache ? "cache" : "upstream");
        if (sourceOverride) {
            source = sourceOverride;
        }
        const targetIP = isGslb ? gslbIPs : ((fromCache || sourceOverride === "stale") ? "Local Cache" : targetDNS);
        
        let category = config.lbAlgorithm || "Balanced";
        
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
    
    // Increment query popularity weight
    domainQueryWeights.set(originalDomain, (domainQueryWeights.get(originalDomain) || 0) + 1);

    // Trigger predictive prefetch for associated CDN/asset domains asynchronously in background
    triggerPredictivePrefetch(originalDomain);

    // 1. Check local cache (using raw queryData first, avoiding addECS overhead for hits)
    const cachedResponseObj = checkCache(originalDomain, qtype, queryData, hasECS, clientIP);
    if (cachedResponseObj) {
        config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
        const clientResponse = Buffer.from(cachedResponseObj.responseBuffer);
        clientResponse[0] = queryData[0];
        clientResponse[1] = queryData[1];
        completeQuery(clientResponse, true, false, "", cachedResponseObj.fromStale ? "stale" : "cache");
    } else {
        // Upstream Circuit Breaker: if upstreams are congested (>400ms) or all down,
        // and we have a stale cache entry of any age, serve it immediately to bypass slow query overhead.
        if (isUpstreamCongested()) {
            const subnet = hasECS ? getClientSubnetPrefix(clientIP || lastSeenClientIP || "115.79.0.1") : "local";
            const key = `${originalDomain.toLowerCase()}_${qtype}_${subnet}`;
            const cached = dnsCache.get(key);
            if (cached) {
                config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
                const clientResponse = Buffer.from(cached.responseBuffer);
                clientResponse[0] = queryData[0];
                clientResponse[1] = queryData[1];
                console.warn(`[Circuit Breaker] Upstreams congested. Serving stale cache immediately for: ${originalDomain}`);
                completeQuery(clientResponse, true, false, "", "stale", "");
                return;
            }
        }

        // 2. Fetch from chosen upstream DNS (lazy-inject ECS on cache miss)
        let queryWithEcs = queryData;
        if (hasECS) {
            queryWithEcs = addECS(queryData, clientIP);
            lastSeenClientIP = clientIP; // Update last seen client IP for background queries
        }
        
        const targetDNS = selectUpstreamDNS(domain, hasECS, clientIP);
        
        fetchFromUpstreamDeduplicated(queryWithEcs, originalDomain, qtype, targetDNS, (response, isSecondary) => {
            if (response) {
                if (isSecondary) {
                    config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
                    completeQuery(response, true, false, "", "cache", targetDNS);
                } else {
                    config.stats.cacheMisses = (config.stats.cacheMisses || 0) + 1;
                    
                    // Parse response flags for negative caching (rcode === 2 (SERVFAIL) or rcode === 5 (REFUSED))
                    const flags = response.length >= 4 ? response.readUInt16BE(2) : 0;
                    const rcode = flags & 0x000f;
                    let ttl = extractTTL(response);
                    if (rcode === 2 || rcode === 5) {
                        ttl = 10; // Negative cache temporary failures for 10 seconds
                    }
                    
                    setCache(originalDomain, qtype, response, ttl, hasECS ? clientIP : "");
                    completeQuery(response, false, false, "", "", targetDNS);
                }
            } else {
                if (!isSecondary) {
                    config.stats.cacheMisses = (config.stats.cacheMisses || 0) + 1;
                    
                    // RFC 8767 Last-Resort Stale Cache Fallback:
                    const subnet = hasECS ? getClientSubnetPrefix(clientIP || lastSeenClientIP || "115.79.0.1") : "local";
                    const key = `${originalDomain.toLowerCase()}_${qtype}_${subnet}`;
                    const cached = dnsCache.get(key);
                    if (cached) {
                        const clientResponse = Buffer.from(cached.responseBuffer);
                        clientResponse[0] = queryData[0];
                        clientResponse[1] = queryData[1];
                        console.warn(`[Cache RFC8767] All upstreams failed/timed out for ${originalDomain}. Serving expired stale cache as last-resort fallback.`);
                        completeQuery(clientResponse, true, false, "", "stale", targetDNS);
                        return;
                    }
                    
                    // Negative caching for timeouts: cache a synthetic SERVFAIL response for 10s
                    const servfailRes = buildServfailResponse(queryWithEcs);
                    if (servfailRes.length > 0) {
                        setCache(originalDomain, qtype, servfailRes, 10, hasECS ? clientIP : "");
                    }
                }
                completeQuery(Buffer.alloc(0), false, false, "", "", targetDNS);
            }
        }, hasECS, clientIP);
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
    handleDoH(queryData, clientIP, req.headers.host, req.headers['user-agent'] || '', (responseData) => {
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
    handleDoH(queryData, clientIP, req.headers.host, req.headers['user-agent'] || '', (responseData) => {
        res.setHeader('Content-Type', 'application/dns-message');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(responseData);
    });
});

app.get('/dns/mobileconfig', (req, res) => {
    const host = req.headers.host || 'localhost:3000';
    const secureUrl = `https://${host}/dns-query`;
    const uuid1 = crypto.randomUUID ? crypto.randomUUID() : 'e01ea4df-25fd-4268-ba30-8cd9f68013b8';
    const uuid2 = crypto.randomUUID ? crypto.randomUUID() : 'f92f9b8c-529a-4c28-98e3-cf859b8c2810';
    
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${secureUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Cấu hình DNS Load Balancer &amp; AI Router qua HTTPS cho iOS</string>
            <key>PayloadDisplayName</key>
            <string>Gemini DNS DoH Load Balancer</string>
            <key>PayloadIdentifier</key>
            <string>com.gemini.dns.doh</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid1}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Gemini DNS Load Balancer</string>
    <key>PayloadIdentifier</key>
    <string>com.gemini.dns</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader('Content-Disposition', 'attachment; filename="gemini-dns.mobileconfig"');
    res.send(plist);
});

// MARK: - Dashboard API Endpoints
app.get('/dns/config', (req, res) => {
    let sumRtt = 0;
    let rttCount = 0;
    for (const cl of clientRegistry.values()) {
        if (cl.clientToServerRTT !== null && cl.clientToServerRTT !== undefined) {
            sumRtt += cl.clientToServerRTT;
            rttCount++;
        }
    }
    const avgClientRtt = rttCount > 0 ? Math.round(sumRtt / rttCount) : 50;

    const baseAvgLatency = latencyCount > 0 ? (totalLatency / latencyCount) : 0;
    const stats = {
        total: config.stats.total,
        cacheHitRate: ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) > 0 ? ((config.stats.cacheHits || 0) / ((config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0)) * 100) : 0,
        avgLatency: baseAvgLatency + avgClientRtt
    };
    
    const clientsList = getClientsList();

    res.json({
        running: true,
        logs: logs,
        stats: stats,
        aiEnabled: false,
        groqApiKeys: [],
        groqApiKeysCooldown: [],
        groqApiKeysCount: 0,
        groqModel: "",
        serverStatus: getServerStatus(),
        minCacheTtlSeconds: config.minCacheTtlSeconds || 300,
        activeDevicesCount: clientRegistry.size,
        clientsList: clientsList,
        congestionLevel: getCongestionLevel(),
        
        // AI Load Balancer Brain fields
        isAILBRunning: false,
        aiLBReason: "AI đã được gỡ bỏ hoàn toàn.",
        lastAiLBTime: 0,
        
        // Load Balancer fields
        upstreamPool: (config.upstreamPool || []).map(s => {
            const { history, ...rest } = s;
            return rest;
        }),
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
        dnsRacingEnabled: !!config.dnsRacingEnabled,
        dnsRacingDelayMs: config.dnsRacingDelayMs || 15,
        llesThresholdMs: config.llesThresholdMs || 150,
        pingIntervalSeconds: config.pingIntervalSeconds || 3
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
    
    const noEcsIps = ["1.1.1.1", "1.0.0.1"];
    const ecsSupported = !noEcsIps.includes(ip);
    
    config.upstreamPool.push({ ip, name, latency: 0, online: true, ecsSupported });
    saveConfig();
    rebuildLlesRoutingPool();
    measureUpstreamLatency(ip);
    broadcastUpdate();
    res.send(`Added ${ip} to pool`);
});

app.post('/dns/upstream/pool/remove', (req, res) => {
    const ip = req.query.ip;
    if (!ip) return res.status(400).send("Missing ip parameter");
    
    config.upstreamPool = (config.upstreamPool || []).filter(s => s.ip !== ip);
    saveConfig();
    rebuildLlesRoutingPool();
    broadcastUpdate();
    res.send(`Removed ${ip} from pool`);
});

app.post('/dns/lb/algorithm', (req, res) => {
    const algo = req.query.algo;
    const validAlgos = ["round-robin", "least-latency", "random", "weighted-round-robin", "failover", "all-racing"];
    if (!algo || !validAlgos.includes(algo)) {
        return res.status(400).send("Invalid algorithm");
    }
    config.lbAlgorithm = algo;
    saveConfig();
    rebuildLlesRoutingPool();
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

app.post('/dns/lles/config', (req, res) => {
    const threshold = parseInt(req.query.threshold, 10);
    const pingInterval = parseInt(req.query.pingInterval, 10);
    
    if (!isNaN(threshold) && threshold >= 15 && threshold <= 1000) {
        config.llesThresholdMs = threshold;
    }
    if (!isNaN(pingInterval) && pingInterval >= 2 && pingInterval <= 300) {
        config.pingIntervalSeconds = pingInterval;
        if (typeof startPingInterval === 'function') {
            startPingInterval();
        }
    }
    saveConfig();
    rebuildLlesRoutingPool();
    broadcastUpdate();
    res.send("LLES config updated");
});



app.post('/dns/stats/reset', (req, res) => {
    config.stats = { total: 0, cacheHits: 0, cacheMisses: 0 };
    totalLatency = 0;
    latencyCount = 0;
    saveConfig();
    broadcastUpdate();
    res.send("Stats reset");
});

app.post('/dns/cache/inject', (req, res) => {
    const domain = req.query.domain;
    const expiresOffsetMs = parseInt(req.query.expiresOffsetMs, 10) || 0;
    
    if (!domain) {
        return res.status(400).send("Missing domain parameter");
    }
    
    // Build a dummy DNS A record query buffer and then the response
    const queryBuffer = buildQueryBufferForMeasure(domain);
    const parsed = parseDNSQuery(queryBuffer);
    const dummyIps = ["1.2.3.4"];
    const responseBuffer = buildGslbResponse(queryBuffer, parsed.questionEndOffset, dummyIps);
    
    const key = `${domain.toLowerCase()}_1_local`; // Qtype 1 (A) with local subnet
    
    dnsCache.set(key, {
        responseBuffer: responseBuffer,
        createdAt: Date.now(),
        expiresAt: Date.now() + expiresOffsetMs
    });
    
    res.send(`Injected cache entry for ${domain} with expiresOffsetMs ${expiresOffsetMs}`);
});

app.post('/dns/toggle', (req, res) => {
    res.json({ running: true });
});

// Graceful shutdown hooks
function gracefulShutdown() {
    console.log("Shutting down. Saving config...");
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
