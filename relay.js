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
let precomputedAiPool = [];
let precomputedAiTotalWeight = 0;
const domainQueryWeights = new Map();
let lastSeenClientIP = "115.79.0.1"; // Track client IP for background queries

function rebuildAiRoutingCache() {
    const pool = config.upstreamPool || [];
    precomputedAiPool = pool.filter(s => s.online !== false).map(s => ({
        ip: s.ip,
        weight: typeof s.aiWeight === 'number' ? s.aiWeight : 10
    }));
    precomputedAiTotalWeight = precomputedAiPool.reduce((sum, item) => sum + item.weight, 0);
}

// WebSocket client registry
const wsClients = new Set();

// Performance Metrics & Local DNS Cache
const dnsCache = new Map(); // Key: domain + '_' + qtype, Value: { responseBuffer, createdAt, expiresAt }
const MAX_CACHE_SIZE = 15000;
const activeUpstreamQueries = new Map(); // Key: domain + '_' + qtype, Value: Array of waiting client callbacks

// AI Load Balancer Brain State
let aiLoadBalancerTimeout = null;
let isAILBRunning = false;
const AI_LB_INTERVAL_MS = 900000; // Run every 15 minutes
let groqKeyIndex = 0;
const keyCooldowns = new Map(); // key -> timestamp of cooldown expiration

function isKeyAvailable(key) {
    if (!key) return false;
    const cooldownUntil = keyCooldowns.get(key);
    if (cooldownUntil && Date.now() < cooldownUntil) {
        return false;
    }
    return true;
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

// Upstream UDP Client Sockets Pool
const SOCKET_POOL_SIZE = 15;
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
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        serverStatus: getServerStatus(),
        minCacheTtlSeconds: config.minCacheTtlSeconds || 300,
        
        // AI Load Balancer Brain fields
        isAILBRunning: isAILBRunning,
        aiLBReason: config.aiLBReason || "Chưa có phân tích tải nào.",
        lastAiLBTime: config.lastAiLBTime || 0,
        
        // Load Balancer fields
        upstreamPool: (config.upstreamPool || []).map(s => {
            const { history, ...rest } = s;
            return rest;
        }),
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
        dnsRacingEnabled: !!config.dnsRacingEnabled,
        dnsRacingDelayMs: config.dnsRacingDelayMs || 15
    };
}



// Local DNS Cache with prefetching and Stale-While-Revalidate (SWR)
function checkCache(domain, qtype, queryData = null, hasECS = false) {
    const key = `${domain.toLowerCase()}_${qtype}`;
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
                    activeUpstreamQueries.set(prefetchKey, true);
                    console.log(`[Cache Prefetch] Triggering background prefetch for: ${domain} (remaining TTL: ${Math.round(remainingTTL)}s / ${Math.round(totalTTL)}s)`);
                    
                    const targetDNS = selectUpstreamDNS(domain, hasECS);
                    const prefetchQueryBuffer = queryData ? Buffer.from(queryData) : buildQueryBufferForMeasure(domain);
                    
                    fetchFromUpstreamDeduplicated(prefetchQueryBuffer, domain, qtype, targetDNS, (response) => {
                        activeUpstreamQueries.delete(prefetchKey);
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl);
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
                    activeUpstreamQueries.set(revalidateKey, true);
                    console.log(`[Cache SWR] Serving stale cache for: ${domain} (expired ${Math.round((now - cached.expiresAt) / 1000)}s ago). Triggering background revalidate...`);
                    
                    const targetDNS = selectUpstreamDNS(domain, hasECS);
                    const revalidateQueryBuffer = Buffer.from(queryData);
                    
                    fetchFromUpstreamDeduplicated(revalidateQueryBuffer, domain, qtype, targetDNS, (response) => {
                        activeUpstreamQueries.delete(revalidateKey);
                        if (response) {
                            const newTtl = extractTTL(response);
                            setCache(domain, qtype, response, newTtl);
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

function setCache(domain, qtype, responseBuffer, ttl) {
    const minTtl = config.minCacheTtlSeconds !== undefined ? config.minCacheTtlSeconds : 300;
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
                    
                    // Quarantine only on extremely high latency (> 800ms) which indicates severe network congestion or server issues
                    if (elapsed > 800 && !server.quarantined) {
                        const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                        server.quarantined = true;
                        server.quarantineUntil = Date.now() + Math.round(qDuration / 2); // Half duration for latency spikes
                        console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 2000)}s due to extremely high latency (${elapsed}ms).`);
                    } else if (server.quarantined && Date.now() > (server.quarantineUntil || 0)) {
                        // Lift quarantine if we get a successful response and time expired
                        server.quarantined = false;
                        console.log(`[Upstream Autopilot] Lifted quarantine for ${server.name} (${server.ip}) on successful response.`);
                    }

                    if (req.isClientQuery) {
                        server.queryCount = (server.queryCount || 0) + 1;
                    }
                    
                    const onlineChanged = (oldOnline === false);
                    
                    if (onlineChanged) {
                        rebuildAiRoutingCache();
                    }
                    
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
                
                // Autopilot quarantine: increment consecutive failures
                server.consecutiveFailures = (server.consecutiveFailures || 0) + 1;
                if (server.consecutiveFailures >= 3 && !server.quarantined) {
                    const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                    server.quarantined = true;
                    server.quarantineUntil = Date.now() + qDuration;
                    console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 1000)}s due to 3 consecutive timeouts.`);
                }
                
                if (oldOnline !== false) {
                    rebuildAiRoutingCache();
                }
                
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
                    
                    // Autopilot quarantine: increment consecutive failures
                    server.consecutiveFailures = (server.consecutiveFailures || 0) + 1;
                    if (server.consecutiveFailures >= 3 && !server.quarantined) {
                        const qDuration = (config.quarantineDurationSeconds || 60) * 1000;
                        server.quarantined = true;
                        server.quarantineUntil = Date.now() + qDuration;
                        console.warn(`[Upstream Autopilot] Quarantined server ${server.name} (${server.ip}) for ${Math.round(qDuration / 1000)}s due to consecutive send errors.`);
                    }
                    
                    if (oldOnline !== false) {
                        rebuildAiRoutingCache();
                    }
                    
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

function fetchFromUpstreamDeduplicated(queryData, domain, qtype, upstreamDNS, callback, hasECS = false) {
    const key = `${domain.toLowerCase()}_${qtype}`;
    const originalIDBytes = Buffer.from([queryData[0], queryData[1]]);
    
    if (activeUpstreamQueries.has(key)) {
        activeUpstreamQueries.get(key).push({ callback, originalIDBytes, isSecondary: true });
        return;
    }
    
    activeUpstreamQueries.set(key, [{ callback, originalIDBytes, isSecondary: false }]);
    
    const pool = config.upstreamPool || [];
    let onlinePool = pool.filter(s => s.online !== false && !s.quarantined);
    if (onlinePool.length === 0) onlinePool = pool.filter(s => s.online !== false);
    if (onlinePool.length === 0) onlinePool = pool;
    
    if (hasECS) {
        const ecsPool = onlinePool.filter(s => s.ecsSupported !== false);
        if (ecsPool.length > 0) {
            onlinePool = ecsPool;
        }
    }
    
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
        
        // Calculate Adaptive Racing Delay based on jitter of primary server
        const primaryServer = config.upstreamPool.find(s => s.ip === upstreamDNS);
        let racingDelay = config.dnsRacingDelayMs || 15;
        
        if (isHighPerformanceDomain(domain)) {
            racingDelay = 0; // Force immediate parallel query for speedtest/CDN domains!
            console.log(`[DNS Racing] Ultra-low latency mode activated for: ${domain}. Racing delay set to 0ms.`);
        } else if (primaryServer) {
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

// Groq API helpers
function getNextGroqKey() {
    const keys = config.groqApiKeys || [];
    const availableKeys = keys.filter(isKeyAvailable);
    if (availableKeys.length === 0) return null;
    const key = availableKeys[groqKeyIndex % availableKeys.length];
    groqKeyIndex = (groqKeyIndex + 1) % availableKeys.length;
    return key;
}

let lastAIBrainRunTime = 0;

// AI Load Balancer Brain implementation
function runAILoadBalancerBrain() {
    if (aiLoadBalancerTimeout) {
        clearTimeout(aiLoadBalancerTimeout);
        aiLoadBalancerTimeout = null;
    }
    
    if (!config.aiEnabled || !config.groqApiKeys || config.groqApiKeys.length === 0) {
        isAILBRunning = false;
        broadcastUpdate();
        // Do NOT schedule a retry. We will be triggered when config/keys are updated.
        return;
    }
    
    isAILBRunning = true;
    lastAIBrainRunTime = Date.now();
    broadcastUpdate();
    
    const apiKey = getNextGroqKey();
    if (!apiKey) {
        let nextAvailableTime = Date.now() + AI_LB_INTERVAL_MS;
        for (const [key, cooldownUntil] of keyCooldowns.entries()) {
            if (config.groqApiKeys.includes(key)) {
                if (cooldownUntil < nextAvailableTime) {
                    nextAvailableTime = cooldownUntil;
                }
            }
        }
        const delay = Math.max(15000, nextAvailableTime - Date.now());
        console.warn(`[AI LB Brain] No API keys available. Retrying in ${Math.round(delay/1000)}s.`);
        
        isAILBRunning = false;
        config.aiLBReason = `Tất cả API Keys đang tạm khóa. Sẽ tự động thử lại sau ${Math.round(delay/1000)} giây.`;
        broadcastUpdate();
        
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, delay);
        return;
    }
    
    console.log(`[AI LB Brain] Triggering analysis using API Key: ${apiKey.substring(0, 8)}...`);
    
    const pool = config.upstreamPool || [];
    const onlinePool = pool.filter(s => s.online !== false);
    
    if (onlinePool.length === 0) {
        console.log("[AI LB Brain] No online DNS servers in pool. Skipping analysis.");
        isAILBRunning = false;
        broadcastUpdate();
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 30000);
        return;
    }
    
    // Construct the pool status context for the prompt
    const poolStatusContext = pool.map(s => {
        const rate = typeof s.successRate === 'number' ? s.successRate + '%' : '100%';
        const ecs = s.ecsSupported !== false ? 'CÓ' : 'KHÔNG';
        const quarantine = s.quarantined ? 'ĐANG CÁCH LY' : 'HOẠT ĐỘNG';
        return `- ${s.name} (${s.ip}): Trạng thái = ${s.online !== false ? 'ONLINE' : 'OFFLINE'} (${quarantine}), RTT = ${s.online !== false ? (s.latency || 0) + 'ms' : 'N/A'}, Hỗ trợ ECS = ${ecs}, Tỷ lệ thành công = ${rate}, Tổng lượt truy vấn = ${s.queryCount || 0}`;
    }).join('\n');
    
    const cacheTotal = (config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0);
    const clientCacheHitRate = cacheTotal > 0 ? ((config.stats.cacheHits || 0) / cacheTotal * 100).toFixed(1) + '%' : '0%';
    const clientAvgLatency = latencyCount > 0 ? (totalLatency / latencyCount).toFixed(1) + 'ms' : '0ms';
    const clientRacingWinRate = (config.stats.racingTotal || 0) > 0 ? ((config.stats.racingWins || 0) / config.stats.racingTotal * 100).toFixed(1) + '%' : '0%';
    
    const clientMetricsContext = `\nChỉ số hiệu năng phía Client thực tế:\n` +
                                 `- Tỷ lệ Cache Hit của client: ${clientCacheHitRate}\n` +
                                 `- Độ trễ client trung bình: ${clientAvgLatency}\n` +
                                 `- Tỷ lệ server phụ thắng Đua DNS: ${clientRacingWinRate} (Tổng lượt đua: ${config.stats.racingTotal || 0})\n`;

    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Your task is to analyze the performance (RTT latency, online status, success rate, quarantine status, and ECS support) of the upstream DNS servers and distribute traffic weights among the ONLINE servers, dynamically optimize the DNS Racing configuration, and suggest the optimal minimum cache TTL, quarantine cooldown, stale cache window, and ECS prefix length.\n\n" +
                          "Instructions:\n" +
                          "1. Only assign weights to ONLINE and non-quarantined servers. Assign 0 weight to OFFLINE or QUARANTINED (ĐANG CÁCH LY) servers.\n" +
                          "2. MONITOR QUERY COUNTS & DISTRIBUTE LOAD EVENLY: Monitor the total query count and the queries distributed to each server. You MUST assign weights such that traffic is distributed evenly (equal weights) among the group of lowest-latency servers (having ecsSupported = true). For example, if Google (8.8.8.8) and Quad9 (9.9.9.9) both have stable low latency, assign them equal weights (e.g. 50% each) to split the load. If a server receives too many queries or its latency spikes, reduce its weight slightly to balance the load, or adjust other parameters. Slower or non-ECS servers must receive 0% weight.\n" +
                          "3. Decide whether DNS Racing (querying the second fastest server if the first is slow) should be enabled (\"dnsRacingEnabled\": true/false). Enable it if the primary DNS is unstable or has success rate < 95%, or if RTTs are fluctuating.\n" +
                          "4. Suggest the optimal DNS Racing delay in ms (\"dnsRacingDelayMs\": integer, between 5 and 50). Look at the client's DNS Racing win rate: if the win rate is high (> 30%), suggest a tight delay (8-12ms).\n" +
                          "5. Suggest the optimal minimum cache TTL in seconds (\"minCacheTtlSeconds\": integer, between 300 and 43200). Increase it aggressively if the cache hit rate is low and server RTTs are stable.\n" +
                          "6. Suggest the optimal latency EMA smoothing factor (\"latencyEMAWeight\": float, between 0.1 and 0.9). Suggest lower values (0.1 - 0.2) to smooth out random latency spikes, or higher values (0.4 - 0.7) to adapt rapidly to server latency state transitions.\n" +
                          "7. Suggest the optimal quarantine duration in seconds (\"quarantineDurationSeconds\": integer, between 15 and 600) when server timeouts/spikes occur. Suggest higher values if a server is persistently failing.\n" +
                          "8. Suggest the optimal stale cache retention window in seconds (\"staleCacheWindowSeconds\": integer, between 3600 and 86400). Suggest higher values if upstream servers are unstable to ensure a fallback record exists.\n" +
                          "9. Suggest the optimal IPv4 ECS prefix length (\"ecsIPv4PrefixLength\": integer, 24 or 32). Use 24 for privacy and maximum cache hit rate sharing, or 32 for extremely accurate location routing.\n" +
                          "10. Keep the output clean and return a strict JSON response containing \"weights\", \"dnsRacingEnabled\", \"dnsRacingDelayMs\", \"minCacheTtlSeconds\", \"latencyEMAWeight\", \"quarantineDurationSeconds\", \"staleCacheWindowSeconds\", \"ecsIPv4PrefixLength\", and \"reason\" (Vietnamese explanation, 10-15 words).\n\n" +
                          "JSON response format:\n" +
                          "{\n" +
                          "  \"weights\": {\n" +
                          "    \"8.8.8.8\": 50,\n" +
                          "    \"9.9.9.9\": 50,\n" +
                          "    \"1.1.1.1\": 0,\n" +
                          "    \"208.67.222.222\": 0\n" +
                          "  },\n" +
                          "  \"dnsRacingEnabled\": true,\n" +
                          "  \"dnsRacingDelayMs\": 15,\n" +
                          "  \"minCacheTtlSeconds\": 14400,\n" +
                          "  \"latencyEMAWeight\": 0.3,\n" +
                          "  \"quarantineDurationSeconds\": 60,\n" +
                          "  \"staleCacheWindowSeconds\": 86400,\n" +
                          "  \"ecsIPv4PrefixLength\": 24,\n" +
                          "  \"reason\": \"Giải thích lý do điều phối tải và tối ưu DNS bằng tiếng Việt\"\n" +
                          "}";
                           
    const userContent = `Dưới đây là thông tin trạng thái hiện tại của Upstream DNS Pool:\n\n${poolStatusContext}\n${clientMetricsContext}\nHãy trả về trọng số tối ưu nhất cho từng IP máy chủ dưới dạng JSON.`;
    
    const postData = JSON.stringify({
        model: config.groqModel || "llama-3.1-8b-instant",
        messages: [
            { role: "system", content: systemContent },
            { role: "user", content: userContent }
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
                        let errMsg = `Lỗi Groq API: Status ${res.statusCode}`;
                        if (res.statusCode === 429) {
                            errMsg = "Lỗi Groq API: Rate limited (429) - Hết hạn mức request.";
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... rate limited (429). Cooling down for 10m.`);
                            keyCooldowns.set(apiKey, Date.now() + 600000);
                        } else if (res.statusCode === 401 || res.statusCode === 403) {
                            errMsg = `Lỗi Groq API: Key không hợp lệ (${res.statusCode}) - Khóa API không hợp lệ.`;
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... unauthorized/invalid (${res.statusCode}). Cooling down for 24h.`);
                            keyCooldowns.set(apiKey, Date.now() + 24 * 3600 * 1000);
                        } else {
                            console.warn(`[AI LB Brain] Groq API returned status code ${res.statusCode}`);
                        }
                        config.aiLBReason = errMsg;
                        saveConfig();
                        isAILBRunning = false;
                        broadcastUpdate();
                        // Retry shortly with next key
                        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 10000);
                        return;
                    }
                    
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        const weights = decision.weights || {};
                        const reason = decision.reason || "Cân bằng tải AI";
                        
                        console.log(`[AI LB Brain] Weight recommendation received:`, weights);
                        console.log(`[AI LB Brain] Rationale: ${reason}`);
                        
                        // Update config
                        pool.forEach(server => {
                            if (weights[server.ip] !== undefined) {
                                server.aiWeight = Math.max(0, parseInt(weights[server.ip], 10) || 0);
                            } else {
                                // Default fallback weight for online or missing
                                server.aiWeight = server.online !== false ? 10 : 0;
                            }
                        });
                        
                        if (decision.dnsRacingEnabled !== undefined) {
                            config.dnsRacingEnabled = !!decision.dnsRacingEnabled;
                        }
                        if (typeof decision.dnsRacingDelayMs === 'number') {
                            config.dnsRacingDelayMs = Math.max(0, Math.min(1000, decision.dnsRacingDelayMs));
                        }
                        if (typeof decision.minCacheTtlSeconds === 'number') {
                            config.minCacheTtlSeconds = Math.max(300, Math.min(43200, decision.minCacheTtlSeconds));
                        }
                        if (typeof decision.latencyEMAWeight === 'number') {
                            config.latencyEMAWeight = Math.max(0.1, Math.min(0.9, decision.latencyEMAWeight));
                        }
                        if (typeof decision.quarantineDurationSeconds === 'number') {
                            config.quarantineDurationSeconds = Math.max(15, Math.min(600, decision.quarantineDurationSeconds));
                        }
                        if (typeof decision.staleCacheWindowSeconds === 'number') {
                            config.staleCacheWindowSeconds = Math.max(3600, Math.min(86400, decision.staleCacheWindowSeconds));
                        }
                        if (decision.ecsIPv4PrefixLength === 24 || decision.ecsIPv4PrefixLength === 32) {
                            config.ecsIPv4PrefixLength = decision.ecsIPv4PrefixLength;
                        }
                        
                        config.aiLBReason = reason;
                        config.lastAiLBTime = Date.now();
                        saveConfig();
                        
                        // Log locally
                        const now = new Date();
                        const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
                        const timeStr = vnTime.toISOString().substring(11, 19);
                        const statusMessage = `[${timeStr}] [AI BRAIN] Phân phối tải: ` + 
                            pool.map(s => `${s.name}: ${s.aiWeight || 0}%`).join(', ') + 
                            ` | Racing: ${config.dnsRacingEnabled ? 'Bật (' + config.dnsRacingDelayMs + 'ms)' : 'Tắt'} - ${reason}`;
                        
                        logs.push(statusMessage);
                        if (logs.length > 100) logs.shift();
                        
                        isAILBRunning = false;
                        rebuildAiRoutingCache();
                        broadcastUpdate();
                    } else {
                        isAILBRunning = false;
                        broadcastUpdate();
                    }
                    
                    // Run next analysis after interval
                    aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, AI_LB_INTERVAL_MS);
                } catch (e) {
                    console.error("[AI LB Brain] Error parsing response body:", e);
                    config.aiLBReason = `Lỗi phân tích cú pháp: ${e.message}`;
                    saveConfig();
                    isAILBRunning = false;
                    broadcastUpdate();
                    aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
                }
            });
        });
        
        req.on('error', (err) => {
            console.error("[AI LB Brain] HTTP request error:", err);
            config.aiLBReason = `Lỗi kết nối Groq: ${err.message}`;
            saveConfig();
            isAILBRunning = false;
            broadcastUpdate();
            aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        console.error("[AI LB Brain] Execution error:", e);
        config.aiLBReason = `Lỗi thực thi: ${e.message}`;
        saveConfig();
        isAILBRunning = false;
        broadcastUpdate();
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
    }
}

function selectAIWeightedDNS(activePool) {
    if (activePool.length === 0) return "1.1.1.1";
    if (activePool.length === 1) return activePool[0].ip;
    
    // Find the minimum latency among activePool servers
    let minLatency = Infinity;
    for (let i = 0; i < activePool.length; i++) {
        const s = activePool[i];
        if (s.online !== false && typeof s.latency === 'number' && s.latency < minLatency && s.latency > 0) {
            minLatency = s.latency;
        }
    }
    if (minLatency === Infinity) minLatency = 20;
    
    // Filter to lowest-latency servers (LLES logic)
    const threshold = Math.max(15, minLatency * 0.5);
    const lowLatencyServers = activePool.filter(s => s.online !== false && (s.latency || 0) < 9999 && (s.latency <= minLatency + threshold));
    
    if (lowLatencyServers.length === 0) {
        // Fallback to the absolute fastest server
        let fastest = activePool[0];
        let bestLat = Infinity;
        for (let i = 0; i < activePool.length; i++) {
            const s = activePool[i];
            if (s.online !== false && (s.latency || 9999) < bestLat) {
                bestLat = s.latency || 9999;
                fastest = s;
            }
        }
        return fastest ? fastest.ip : activePool[0].ip;
    }
    
    if (lowLatencyServers.length === 1) {
        return lowLatencyServers[0].ip;
    }
    
    // Filter precomputedAiPool to only include the low-latency servers
    const lowLatencyIps = new Set(lowLatencyServers.map(s => s.ip));
    const pool = precomputedAiPool.filter(item => lowLatencyIps.has(item.ip));
    
    if (pool.length === 0) {
        // Fallback to equal distribution among low-latency servers (LLES)
        const idx = Math.floor(Math.random() * lowLatencyServers.length);
        return lowLatencyServers[idx].ip;
    }
    
    const totalWeight = pool.reduce((sum, item) => sum + item.weight, 0);
    if (totalWeight <= 0) {
        // Fallback to equal distribution among low-latency servers (LLES)
        const idx = Math.floor(Math.random() * lowLatencyServers.length);
        return lowLatencyServers[idx].ip;
    }
    
    let rand = Math.random() * totalWeight;
    for (let i = 0; i < pool.length; i++) {
        const item = pool[i];
        rand -= item.weight;
        if (rand <= 0) {
            return item.ip;
        }
    }
    return pool[0].ip;
}

// Low-Latency Equal Share (LLES) Load Balancer DNS Selector
function selectWeightedDNS(activePool) {
    if (activePool.length === 0) return "1.1.1.1";
    if (activePool.length === 1) return activePool[0].ip;
    
    // Find the minimum latency among online, non-quarantined servers
    let minLatency = Infinity;
    for (let i = 0; i < activePool.length; i++) {
        const s = activePool[i];
        if (s.online !== false && typeof s.latency === 'number' && s.latency < minLatency && s.latency > 0) {
            minLatency = s.latency;
        }
    }
    
    // Fallback if no latency measured yet
    if (minLatency === Infinity) minLatency = 20;
    
    // Identify low-latency servers: latency <= minLatency + threshold
    // Threshold is 50% of minLatency, but at least 15ms absolute
    const threshold = Math.max(15, minLatency * 0.5);
    const lowLatencyServers = activePool.filter(s => s.online !== false && (s.latency || 0) < 9999 && (s.latency <= minLatency + threshold));
    
    if (lowLatencyServers.length === 0) {
        // Fallback to the absolute fastest server if the filter results in empty pool
        let fastest = activePool[0];
        let bestLat = Infinity;
        for (let i = 0; i < activePool.length; i++) {
            const s = activePool[i];
            if (s.online !== false && (s.latency || 9999) < bestLat) {
                bestLat = s.latency || 9999;
                fastest = s;
            }
        }
        return fastest ? fastest.ip : activePool[0].ip;
    }
    
    // Divide traffic evenly among low-latency servers
    const idx = Math.floor(Math.random() * lowLatencyServers.length);
    return lowLatencyServers[idx].ip;
}

// Load Balancer DNS Selector
function selectUpstreamDNS(domain, hasECS = false) {
    const pool = config.upstreamPool || [];
    if (pool.length === 0) return "1.1.1.1";
    
    const now = Date.now();
    
    // Clear expired quarantines
    pool.forEach(s => {
        if (s.quarantined && now > (s.quarantineUntil || 0)) {
            s.quarantined = false;
            s.consecutiveFailures = 0;
            console.log(`[Upstream Autopilot] Quarantine expired. Server ${s.name} (${s.ip}) returned to active pool.`);
        }
    });
    
    // Filter out quarantined servers unless they are all quarantined
    let onlinePool = pool.filter(s => s.online !== false && !s.quarantined);
    if (onlinePool.length === 0) {
        onlinePool = pool.filter(s => s.online !== false);
    }
    if (onlinePool.length === 0) {
        onlinePool = pool;
    }
    
    let activePool = onlinePool;
    
    // ECS-aware filtering: if hasECS is true, prefer servers that support ECS
    if (hasECS) {
        const ecsPool = activePool.filter(s => s.ecsSupported !== false);
        if (ecsPool.length > 0) {
            activePool = ecsPool;
        }
    }
    
    const algo = config.lbAlgorithm || "least-latency";
    
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
    
    if (algo === "ai-routing") {
        if (config.aiEnabled) {
            return selectAIWeightedDNS(activePool);
        } else {
            return selectWeightedDNS(activePool);
        }
    }
    
    // Default fallback (least-latency)
    return selectWeightedDNS(activePool);
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
                lbAlgorithm: "ai-routing",
                gslbRecords: {},
                stats: { total: 0, cacheHits: 0, cacheMisses: 0, racingWins: 0, racingTotal: 0 },
                aiEnabled: true,
                groqApiKeys: [],
                groqModel: "llama-3.1-8b-instant",
                dnsRacingEnabled: true,
                dnsRacingDelayMs: 15,
                minCacheTtlSeconds: 300,
                latencyEMAWeight: 0.3,
                quarantineDurationSeconds: 60,
                staleCacheWindowSeconds: 86400,
                ecsIPv4PrefixLength: 24
            };
            saveConfig();
        }
    } catch (e) {
        console.error("Failed to load config, using defaults:", e);
        config = {
            upstreamPool: defaultPool,
            lbAlgorithm: "ai-routing",
            gslbRecords: {},
            stats: { total: 0, cacheHits: 0, cacheMisses: 0, racingWins: 0, racingTotal: 0 },
            aiEnabled: true,
            groqApiKeys: [],
            groqModel: "llama-3.1-8b-instant",
            dnsRacingEnabled: true,
            dnsRacingDelayMs: 15,
            minCacheTtlSeconds: 300,
            latencyEMAWeight: 0.3,
            quarantineDurationSeconds: 60,
            staleCacheWindowSeconds: 86400,
            ecsIPv4PrefixLength: 24
        };
    }
    
    config.stats = config.stats || {};
    config.stats.total = config.stats.total || 0;
    config.stats.cacheHits = config.stats.cacheHits || 0;
    config.stats.cacheMisses = config.stats.cacheMisses || 0;
    config.stats.racingWins = config.stats.racingWins || 0;
    config.stats.racingTotal = config.stats.racingTotal || 0;
    config.aiEnabled = config.aiEnabled !== undefined ? config.aiEnabled : true;
    config.groqModel = "llama-3.1-8b-instant";
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
    config.lbAlgorithm = config.lbAlgorithm || "ai-routing";
    config.gslbRecords = config.gslbRecords || {};
    config.dnsRacingEnabled = config.dnsRacingEnabled !== undefined ? config.dnsRacingEnabled : true;
    config.dnsRacingDelayMs = config.dnsRacingDelayMs !== undefined ? config.dnsRacingDelayMs : 15;
    config.minCacheTtlSeconds = config.minCacheTtlSeconds !== undefined ? config.minCacheTtlSeconds : 300;
    config.latencyEMAWeight = config.latencyEMAWeight !== undefined ? config.latencyEMAWeight : 0.3;
    config.quarantineDurationSeconds = config.quarantineDurationSeconds !== undefined ? config.quarantineDurationSeconds : 60;
    config.staleCacheWindowSeconds = config.staleCacheWindowSeconds !== undefined ? config.staleCacheWindowSeconds : 86400;
    config.ecsIPv4PrefixLength = config.ecsIPv4PrefixLength !== undefined ? config.ecsIPv4PrefixLength : 24;
    
    if (!Array.isArray(config.groqApiKeys)) config.groqApiKeys = [];
    
    if (process.env.GROQ_API_KEYS) {
        const envKeys = process.env.GROQ_API_KEYS.split(',').map(k => k.trim()).filter(k => k.length > 0);
        envKeys.forEach(k => {
            if (!config.groqApiKeys.includes(k)) config.groqApiKeys.push(k);
        });
    }
    config.groqApiKeys = config.groqApiKeys.filter(k => k && k.trim().length > 0);
    rebuildAiRoutingCache();
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
setInterval(measureUpstreamPool, 30000);
setTimeout(measureUpstreamPool, 3000); // Check shortly after start
setInterval(runCacheGC, 60000); // Cache Garbage Collector every 60s
setInterval(runPopularKeepAlive, 60000); // Always-Hot Cache prefetch and decay

setTimeout(runAILoadBalancerBrain, 5000);

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
    const minPopularThreshold = 5;
    for (const [domain, count] of domainQueryWeights.entries()) {
        if (count >= minPopularThreshold) {
            [1, 28].forEach(qtype => {
                const key = `${domain}_${qtype}`;
                const cached = dnsCache.get(key);
                if (cached) {
                    const now = Date.now();
                    const remainingTTL = (cached.expiresAt - now) / 1000;
                    const totalTTL = (cached.expiresAt - cached.createdAt) / 1000;
                    if (remainingTTL < (totalTTL * 0.3)) {
                        console.log(`[Always-Hot Cache] Refreshing popular domain cache: ${domain} (Qtype: ${qtype}, Queries: ${count})`);
                        // Pass true for hasECS because client queries benefit from local geo-routing
                        const targetDNS = selectUpstreamDNS(domain, true);
                        // Inject ECS using lastSeenClientIP to prevent US IP caching
                        const queryBuffer = addECS(buildQueryBufferForMeasure(domain), lastSeenClientIP || "115.79.0.1");
                        fetchFromUpstreamDeduplicated(queryBuffer, domain, qtype, targetDNS, (response) => {
                            if (response) {
                                const newTtl = extractTTL(response);
                                setCache(domain, qtype, response, newTtl);
                            }
                        }, true);
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
    
    // Inject EDNS Client Subnet (ECS) to preserve local GeoDNS routing for the client
    let queryWithEcs = queryData;
    const hasECS = !!(clientIP && clientIP !== "127.0.0.1" && clientIP !== "::1");
    if (hasECS) {
        queryWithEcs = addECS(queryData, clientIP);
        lastSeenClientIP = clientIP; // Update last seen client IP for background queries
    }
    
    const parsed = parseDNSQuery(queryWithEcs);
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
    
    const targetDNS = selectUpstreamDNS(domain, hasECS);
    
    const completeQuery = (responseBuffer, fromCache = false, isGslb = false, gslbIPs = "", sourceOverride = "") => {
        const latency = Date.now() - startTime;
        totalLatency += latency;
        latencyCount++;
        
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
            
            const gslbResponse = buildGslbResponse(queryWithEcs, parsed.questionEndOffset, rotated);
            completeQuery(gslbResponse, false, true, rotated.join(', '));
            return;
        }
    }
    
    // Increment query popularity weight
    domainQueryWeights.set(originalDomain, (domainQueryWeights.get(originalDomain) || 0) + 1);

    // 1. Check local cache
    const cachedResponseObj = checkCache(originalDomain, qtype, queryWithEcs, hasECS);
    if (cachedResponseObj) {
        config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
        const clientResponse = Buffer.from(cachedResponseObj.responseBuffer);
        clientResponse[0] = queryWithEcs[0];
        clientResponse[1] = queryWithEcs[1];
        completeQuery(clientResponse, true, false, "", cachedResponseObj.fromStale ? "stale" : "cache");
    } else {
        // 2. Fetch from chosen upstream DNS
        fetchFromUpstreamDeduplicated(queryWithEcs, originalDomain, qtype, targetDNS, (response, isSecondary) => {
            if (response) {
                if (isSecondary) {
                    config.stats.cacheHits = (config.stats.cacheHits || 0) + 1;
                    completeQuery(response, true, false, "", "cache");
                } else {
                    config.stats.cacheMisses = (config.stats.cacheMisses || 0) + 1;
                    
                    // Parse response flags for negative caching (rcode === 2 (SERVFAIL) or rcode === 5 (REFUSED))
                    const flags = response.length >= 4 ? response.readUInt16BE(2) : 0;
                    const rcode = flags & 0x000f;
                    let ttl = extractTTL(response);
                    if (rcode === 2 || rcode === 5) {
                        ttl = 10; // Negative cache temporary failures for 10 seconds
                    }
                    
                    setCache(originalDomain, qtype, response, ttl);
                    completeQuery(response, false, false);
                }
            } else {
                if (!isSecondary) {
                    config.stats.cacheMisses = (config.stats.cacheMisses || 0) + 1;
                    
                    // RFC 8767 Last-Resort Stale Cache Fallback:
                    // Look for ANY cache entry for this domain and qtype, even if expired.
                    const key = `${originalDomain.toLowerCase()}_${qtype}`;
                    const cached = dnsCache.get(key);
                    if (cached) {
                        const clientResponse = Buffer.from(cached.responseBuffer);
                        clientResponse[0] = queryWithEcs[0];
                        clientResponse[1] = queryWithEcs[1];
                        console.warn(`[Cache RFC8767] All upstreams failed/timed out for ${originalDomain}. Serving expired stale cache as last-resort fallback.`);
                        completeQuery(clientResponse, true, false, "", "stale");
                        return;
                    }
                    
                    // Negative caching for timeouts: cache a synthetic SERVFAIL response for 10s
                    const servfailRes = buildServfailResponse(queryWithEcs);
                    if (servfailRes.length > 0) {
                        setCache(originalDomain, qtype, servfailRes, 10);
                    }
                }
                completeQuery(Buffer.alloc(0), false, false);
            }
        }, hasECS);
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
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        serverStatus: getServerStatus(),
        minCacheTtlSeconds: config.minCacheTtlSeconds || 300,
        
        // AI Load Balancer Brain fields
        isAILBRunning: isAILBRunning,
        aiLBReason: config.aiLBReason || "Chưa có phân tích tải nào.",
        lastAiLBTime: config.lastAiLBTime || 0,
        
        // Load Balancer fields
        upstreamPool: (config.upstreamPool || []).map(s => {
            const { history, ...rest } = s;
            return rest;
        }),
        lbAlgorithm: config.lbAlgorithm || "least-latency",
        gslbRecords: config.gslbRecords || {},
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
    
    const noEcsIps = ["1.1.1.1", "1.0.0.1"];
    const ecsSupported = !noEcsIps.includes(ip);
    
    config.upstreamPool.push({ ip, name, latency: 0, online: true, ecsSupported });
    saveConfig();
    rebuildAiRoutingCache();
    measureUpstreamLatency(ip);
    broadcastUpdate();
    res.send(`Added ${ip} to pool`);
});

app.post('/dns/upstream/pool/remove', (req, res) => {
    const ip = req.query.ip;
    if (!ip) return res.status(400).send("Missing ip parameter");
    
    config.upstreamPool = (config.upstreamPool || []).filter(s => s.ip !== ip);
    saveConfig();
    rebuildAiRoutingCache();
    broadcastUpdate();
    res.send(`Removed ${ip} from pool`);
});

app.post('/dns/lb/algorithm', (req, res) => {
    const algo = req.query.algo;
    const validAlgos = ["round-robin", "least-latency", "random", "ai-routing", "weighted-round-robin", "failover", "all-racing"];
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
    
    if (enabled) {
        config.lbAlgorithm = "ai-routing";
        keyCooldowns.clear();
    } else {
        if (config.lbAlgorithm === "ai-routing") {
            config.lbAlgorithm = "least-latency";
        }
    }
    
    saveConfig();
    broadcastUpdate();
    if (enabled) {
        setTimeout(runAILoadBalancerBrain, 2000);
    } else {
        if (aiLoadBalancerTimeout) {
            clearTimeout(aiLoadBalancerTimeout);
            aiLoadBalancerTimeout = null;
        }
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

app.post('/dns/groq/keys/update', (req, res) => {
    try {
        if (!req.rawBody || req.rawBody.length === 0) {
            return res.status(400).send("Empty body");
        }
        const keys = JSON.parse(req.rawBody.toString('utf8'));
        if (Array.isArray(keys)) {
            config.groqApiKeys = keys.map(k => k.trim()).filter(k => k.length > 0);
            keyCooldowns.clear();
            saveConfig();
            broadcastUpdate();
            if (config.aiEnabled) setTimeout(runAILoadBalancerBrain, 2000);
            return res.json({ count: config.groqApiKeys.length });
        }
    } catch(e) {
        console.error("Failed to update groq keys:", e);
    }
    res.status(400).send("Invalid JSON payload");
});

app.get('/dns/groq/test', (req, res) => {
    const apiKey = getNextGroqKey();
    if (!apiKey) return res.status(400).json({ error: "Không có API Keys nào được cấu hình hoặc tất cả đang bị khóa tạm thời." });
    
    const pool = config.upstreamPool || [];
    const onlinePool = pool.filter(s => s.online !== false);
    if (onlinePool.length === 0) return res.status(400).json({ error: "Không có máy chủ DNS online." });
    
    isAILBRunning = true;
    broadcastUpdate();
    
    const poolStatusContext = pool.map(s => {
        const rate = typeof s.successRate === 'number' ? s.successRate + '%' : '100%';
        const ecs = s.ecsSupported !== false ? 'CÓ' : 'KHÔNG';
        const quarantine = s.quarantined ? 'ĐANG CÁCH LY' : 'HOẠT ĐỘNG';
        return `- ${s.name} (${s.ip}): Trạng thái = ${s.online !== false ? 'ONLINE' : 'OFFLINE'} (${quarantine}), RTT = ${s.online !== false ? (s.latency || 0) + 'ms' : 'N/A'}, Hỗ trợ ECS = ${ecs}, Tỷ lệ thành công = ${rate}, Tổng lượt truy vấn = ${s.queryCount || 0}`;
    }).join('\n');
    
    const cacheTotal = (config.stats.cacheHits || 0) + (config.stats.cacheMisses || 0);
    const clientCacheHitRate = cacheTotal > 0 ? ((config.stats.cacheHits || 0) / cacheTotal * 100).toFixed(1) + '%' : '0%';
    const clientAvgLatency = latencyCount > 0 ? (totalLatency / latencyCount).toFixed(1) + 'ms' : '0ms';
    const clientRacingWinRate = (config.stats.racingTotal || 0) > 0 ? ((config.stats.racingWins || 0) / config.stats.racingTotal * 100).toFixed(1) + '%' : '0%';
    
    const clientMetricsContext = `\nChỉ số hiệu năng phía Client thực tế:\n` +
                                 `- Tỷ lệ Cache Hit của client: ${clientCacheHitRate}\n` +
                                 `- Độ trễ client trung bình: ${clientAvgLatency}\n` +
                                 `- Tỷ lệ server phụ thắng Đua DNS: ${clientRacingWinRate} (Tổng lượt đua: ${config.stats.racingTotal || 0})\n`;

    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Your task is to analyze the performance (RTT latency, online status, success rate, quarantine status, and ECS support) of the upstream DNS servers and distribute traffic weights among the ONLINE servers, dynamically optimize the DNS Racing configuration, and suggest the optimal minimum cache TTL, quarantine cooldown, stale cache window, and ECS prefix length.\n\n" +
                          "Instructions:\n" +
                          "1. Only assign weights to ONLINE and non-quarantined servers. Assign 0 weight to OFFLINE or QUARANTINED (ĐANG CÁCH LY) servers.\n" +
                          "2. MONITOR QUERY COUNTS & DISTRIBUTE LOAD EVENLY: Monitor the total query count and the queries distributed to each server. You MUST assign weights such that traffic is distributed evenly (equal weights) among the group of lowest-latency servers (having ecsSupported = true). For example, if Google (8.8.8.8) and Quad9 (9.9.9.9) both have stable low latency, assign them equal weights (e.g. 50% each) to split the load. If a server receives too many queries or its latency spikes, reduce its weight slightly to balance the load, or adjust other parameters. Slower or non-ECS servers must receive 0% weight.\n" +
                          "3. Decide whether DNS Racing (querying the second fastest server if the first is slow) should be enabled (\"dnsRacingEnabled\": true/false). Enable it if the primary DNS is unstable or has success rate < 95%, or if RTTs are fluctuating.\n" +
                          "4. Suggest the optimal DNS Racing delay in ms (\"dnsRacingDelayMs\": integer, between 5 and 50). Look at the client's DNS Racing win rate: if the win rate is high (> 30%), suggest a tight delay (8-12ms).\n" +
                          "5. Suggest the optimal minimum cache TTL in seconds (\"minCacheTtlSeconds\": integer, between 300 and 43200). Increase it aggressively if the cache hit rate is low and server RTTs are stable.\n" +
                          "6. Suggest the optimal latency EMA smoothing factor (\"latencyEMAWeight\": float, between 0.1 and 0.9). Suggest lower values (0.1 - 0.2) to smooth out random latency spikes, or higher values (0.4 - 0.7) to adapt rapidly to server latency state transitions.\n" +
                          "7. Suggest the optimal quarantine duration in seconds (\"quarantineDurationSeconds\": integer, between 15 and 600) when server timeouts/spikes occur. Suggest higher values if a server is persistently failing.\n" +
                          "8. Suggest the optimal stale cache retention window in seconds (\"staleCacheWindowSeconds\": integer, between 3600 and 86400). Suggest higher values if upstream servers are unstable to ensure a fallback record exists.\n" +
                          "9. Suggest the optimal IPv4 ECS prefix length (\"ecsIPv4PrefixLength\": integer, 24 or 32). Use 24 for privacy and maximum cache hit rate sharing, or 32 for extremely accurate location routing.\n" +
                          "10. Keep the output clean and return a strict JSON response containing \"weights\", \"dnsRacingEnabled\", \"dnsRacingDelayMs\", \"minCacheTtlSeconds\", \"latencyEMAWeight\", \"quarantineDurationSeconds\", \"staleCacheWindowSeconds\", \"ecsIPv4PrefixLength\", and \"reason\" (Vietnamese explanation, 10-15 words).\n\n" +
                          "JSON response format:\n" +
                          "{\n" +
                          "  \"weights\": {\n" +
                          "    \"8.8.8.8\": 50,\n" +
                          "    \"9.9.9.9\": 50,\n" +
                          "    \"1.1.1.1\": 0,\n" +
                          "    \"208.67.222.222\": 0\n" +
                          "  },\n" +
                          "  \"dnsRacingEnabled\": true,\n" +
                          "  \"dnsRacingDelayMs\": 15,\n" +
                          "  \"minCacheTtlSeconds\": 14400,\n" +
                          "  \"latencyEMAWeight\": 0.3,\n" +
                          "  \"quarantineDurationSeconds\": 60,\n" +
                          "  \"staleCacheWindowSeconds\": 86400,\n" +
                          "  \"ecsIPv4PrefixLength\": 24,\n" +
                          "  \"reason\": \"Giải thích lý do điều phối tải và tối ưu DNS bằng tiếng Việt\"\n" +
                          "}";
                          
    const userContent = `Dưới đây là thông tin trạng thái hiện tại của Upstream DNS Pool:\n\n${poolStatusContext}\n${clientMetricsContext}\nHãy trả về trọng số tối ưu nhất cho từng IP máy chủ dưới dạng JSON.`;
    
    const postData = JSON.stringify({
        model: config.groqModel || "llama-3.1-8b-instant",
        messages: [
            { role: "system", content: systemContent },
            { role: "user", content: userContent }
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
        const groqReq = https.request(options, (groqRes) => {
            let body = [];
            groqRes.on('data', chunk => body.push(chunk));
            groqRes.on('end', () => {
                try {
                    if (groqRes.statusCode !== 200) {
                        let errMsg = `Lỗi Groq API: Status ${groqRes.statusCode}`;
                        if (groqRes.statusCode === 429) {
                            errMsg = "Lỗi Groq API: Rate limited (429) - Hết hạn mức request.";
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... rate limited (429) on test. Cooling down for 10m.`);
                            keyCooldowns.set(apiKey, Date.now() + 600000);
                        } else if (groqRes.statusCode === 401 || groqRes.statusCode === 403) {
                            errMsg = `Lỗi Groq API: Key không hợp lệ (${groqRes.statusCode}) - Khóa API không hợp lệ.`;
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... unauthorized/invalid (${groqRes.statusCode}) on test. Cooling down for 24h.`);
                            keyCooldowns.set(apiKey, Date.now() + 24 * 3600 * 1000);
                        }
                        config.aiLBReason = errMsg;
                        saveConfig();
                        isAILBRunning = false;
                        broadcastUpdate();
                        return res.status(500).json({ error: errMsg });
                    }
                    const resData = JSON.parse(Buffer.concat(body).toString('utf8'));
                    const replyStr = resData.choices?.[0]?.message?.content;
                    if (replyStr) {
                        const decision = JSON.parse(replyStr);
                        const weights = decision.weights || {};
                        const reason = decision.reason || "Cân bằng tải AI";
                        
                        pool.forEach(server => {
                            if (weights[server.ip] !== undefined) {
                                server.aiWeight = Math.max(0, parseInt(weights[server.ip], 10) || 0);
                            } else {
                                server.aiWeight = server.online !== false ? 10 : 0;
                            }
                        });
                        
                        if (decision.dnsRacingEnabled !== undefined) {
                            config.dnsRacingEnabled = !!decision.dnsRacingEnabled;
                        }
                        if (typeof decision.dnsRacingDelayMs === 'number') {
                            config.dnsRacingDelayMs = Math.max(0, Math.min(1000, decision.dnsRacingDelayMs));
                        }
                        if (typeof decision.minCacheTtlSeconds === 'number') {
                            config.minCacheTtlSeconds = Math.max(300, Math.min(43200, decision.minCacheTtlSeconds));
                        }
                        if (typeof decision.latencyEMAWeight === 'number') {
                            config.latencyEMAWeight = Math.max(0.1, Math.min(0.9, decision.latencyEMAWeight));
                        }
                        if (typeof decision.quarantineDurationSeconds === 'number') {
                            config.quarantineDurationSeconds = Math.max(15, Math.min(600, decision.quarantineDurationSeconds));
                        }
                        if (typeof decision.staleCacheWindowSeconds === 'number') {
                            config.staleCacheWindowSeconds = Math.max(3600, Math.min(86400, decision.staleCacheWindowSeconds));
                        }
                        if (decision.ecsIPv4PrefixLength === 24 || decision.ecsIPv4PrefixLength === 32) {
                            config.ecsIPv4PrefixLength = decision.ecsIPv4PrefixLength;
                        }
                        
                        config.aiLBReason = reason;
                        config.lastAiLBTime = Date.now();
                        saveConfig();
                        
                        isAILBRunning = false;
                        rebuildAiRoutingCache();
                        broadcastUpdate();
                        
                        decision.modelUsed = config.groqModel || "llama-3.1-8b-instant";
                        return res.json(decision);
                    } else {
                        isAILBRunning = false;
                        broadcastUpdate();
                        return res.status(500).json({ error: "Không nhận được phản hồi từ Groq." });
                    }
                } catch(e) {
                    config.aiLBReason = `Lỗi test Groq: ${e.message}`;
                    saveConfig();
                    isAILBRunning = false;
                    broadcastUpdate();
                    return res.status(500).json({ error: e.message });
                }
            });
        });
        groqReq.on('error', (err) => {
            config.aiLBReason = `Lỗi kết nối test Groq: ${err.message}`;
            saveConfig();
            isAILBRunning = false;
            broadcastUpdate();
            res.status(500).json({ error: err.message });
        });
        groqReq.write(postData);
        groqReq.end();
    } catch(e) {
        config.aiLBReason = `Lỗi thực thi test Groq: ${e.message}`;
        saveConfig();
        isAILBRunning = false;
        broadcastUpdate();
        return res.status(500).json({ error: e.message });
    }
});



app.post('/dns/stats/reset', (req, res) => {
    config.stats = { total: 0, cacheHits: 0, cacheMisses: 0 };
    totalLatency = 0;
    latencyCount = 0;
    keyCooldowns.clear();
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
    
    const key = `${domain.toLowerCase()}_1`; // Qtype 1 (A)
    
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
