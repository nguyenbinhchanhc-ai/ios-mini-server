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
const AI_LB_INTERVAL_MS = 60000; // Run every 60 seconds
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
        groqModel: config.groqModel || "llama-3.1-8b-instant",
        serverStatus: getServerStatus(),
        
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
                
                // Real-time latency measurement using EMA (Exponential Moving Average)
                const elapsed = Date.now() - req.timestamp;
                const server = config.upstreamPool.find(s => s.ip === req.targetIP);
                if (server) {
                    const oldOnline = server.online;
                    const oldLatency = server.latency || 0;
                    
                    server.latency = Math.round((server.latency || 0) * 0.7 + elapsed * 0.3);
                    server.online = true;
                    recordServerHealth(server, true);
                    if (req.isClientQuery) {
                        server.queryCount = (server.queryCount || 0) + 1;
                    }
                    
                    const onlineChanged = (oldOnline === false);
                    const latencyDelta = Math.abs(server.latency - oldLatency);
                    const latencyPct = oldLatency > 0 ? (latencyDelta / oldLatency) : 0;
                    const significantLatencyChange = latencyDelta > 30 && latencyPct > 0.4;
                    
                    if (onlineChanged) {
                        rebuildAiRoutingCache();
                        triggerAIBrainOnEvent(`Server ${server.name} (${server.ip}) went ONLINE`);
                    } else if (significantLatencyChange) {
                        triggerAIBrainOnEvent(`Server ${server.name} (${server.ip}) latency changed significantly (${oldLatency}ms -> ${server.latency}ms)`);
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
                
                if (oldOnline !== false) {
                    rebuildAiRoutingCache();
                    triggerAIBrainOnEvent(`Server ${server.name} (${server.ip}) went OFFLINE (Timeout)`);
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
                    
                    if (oldOnline !== false) {
                        rebuildAiRoutingCache();
                        triggerAIBrainOnEvent(`Server ${server.name} (${server.ip}) went OFFLINE (Send error)`);
                    }
                    
                    throttledBroadcastUpdate();
                }
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
    
    const pool = config.upstreamPool || [];
    const onlinePool = pool.filter(s => s.online !== false);
    
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
    
    queryUpstream(queryData, upstreamDNS, (res) => onResponse(res, upstreamDNS), false);
    
    if (config.dnsRacingEnabled && secondUpstreamDNS) {
        queriesActive++;
        const racingDelay = config.dnsRacingDelayMs || 15;
        setTimeout(() => {
            if (!resolved) {
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
let aiBrainTriggerTimeout = null;

function triggerAIBrainOnEvent(reason) {
    if (!config.aiEnabled || !config.groqApiKeys || config.groqApiKeys.length === 0) return;
    
    const now = Date.now();
    const minInterval = 15000; // Throttle to at most once per 15 seconds
    const timeSinceLastRun = now - lastAIBrainRunTime;
    
    if (timeSinceLastRun >= minInterval) {
        if (aiBrainTriggerTimeout) {
            clearTimeout(aiBrainTriggerTimeout);
            aiBrainTriggerTimeout = null;
        }
        console.log(`[AI LB Brain] Triggering immediate analysis. Reason: ${reason}`);
        runAILoadBalancerBrain();
    } else {
        // Schedule it to run as soon as the throttle expires
        const delay = minInterval - timeSinceLastRun;
        if (!aiBrainTriggerTimeout) {
            console.log(`[AI LB Brain] Event trigger throttled. Scheduled in ${Math.round(delay/1000)}s. Reason: ${reason}`);
            aiBrainTriggerTimeout = setTimeout(() => {
                aiBrainTriggerTimeout = null;
                runAILoadBalancerBrain();
            }, delay);
        }
    }
}

// AI Load Balancer Brain implementation
function runAILoadBalancerBrain() {
    if (aiLoadBalancerTimeout) {
        clearTimeout(aiLoadBalancerTimeout);
        aiLoadBalancerTimeout = null;
    }
    
    if (!config.aiEnabled || !config.groqApiKeys || config.groqApiKeys.length === 0) {
        isAILBRunning = false;
        broadcastUpdate();
        // Check again in 10s if it gets enabled
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 10000);
        return;
    }
    
    isAILBRunning = true;
    lastAIBrainRunTime = Date.now();
    broadcastUpdate();
    
    const apiKey = getNextGroqKey();
    if (!apiKey) {
        console.warn("[AI LB Brain] No API keys available (all cooling down or none set). Retrying in 15s.");
        isAILBRunning = false;
        broadcastUpdate();
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
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
        return `- ${s.name} (${s.ip}): Trạng thái = ${s.online !== false ? 'ONLINE' : 'OFFLINE'}, Độ trễ RTT = ${s.online !== false ? (s.latency || 0) + 'ms' : 'N/A'}, Tỷ lệ thành công = ${rate}, Tổng lượt truy vấn = ${s.queryCount || 0}`;
    }).join('\n');
    
    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Your task is to analyze the performance (RTT latency, online status, success rate, and query counts) of the upstream DNS servers and distribute traffic weights among the ONLINE servers, and dynamically optimize the DNS Racing configuration.\n\n" +
                          "Instructions:\n" +
                          "1. Only assign weights to ONLINE servers. Assign 0 weight to OFFLINE servers.\n" +
                          "2. Distribute weights (from 0 to 100, summing up to 100) such that faster servers (lower RTT latencies) and more reliable servers (higher success rates) receive a higher proportion of the traffic, while slower or degraded servers receive very low or 0 weight. Be aggressive with assigning more weight to lower latency servers.\n" +
                          "3. Decide whether DNS Racing (querying the second fastest server if the first is slow) should be enabled (\"dnsRacingEnabled\": true/false). Enable it if the primary DNS is unstable or has success rate < 95%, or if RTTs are fluctuating. Disable it to save resources only if all active servers are 100% stable and fast.\n" +
                          "4. Suggest the optimal DNS Racing delay in ms (\"dnsRacingDelayMs\": integer, between 5 and 50). Set it lower (e.g., 8-15ms) if the primary server is fast but needs a tight safety net, or higher (e.g., 20-35ms) if RTTs are naturally higher.\n" +
                          "5. Keep the output clean and return a strict JSON response containing \"weights\", \"dnsRacingEnabled\", \"dnsRacingDelayMs\", and \"reason\" (Vietnamese explanation, 10-15 words).\n\n" +
                          "JSON response format:\n" +
                          "{\n" +
                          "  \"weights\": {\n" +
                          "    \"1.1.1.1\": 60,\n" +
                          "    \"8.8.8.8\": 30,\n" +
                          "    \"9.9.9.9\": 10,\n" +
                          "    \"208.67.222.222\": 0\n" +
                          "  },\n" +
                          "  \"dnsRacingEnabled\": true,\n" +
                          "  \"dnsRacingDelayMs\": 15,\n" +
                          "  \"reason\": \"Giải thích lý do điều phối tải và tối ưu DNS Racing bằng tiếng Việt\"\n" +
                          "}";
                          
    const userContent = `Dưới đây là thông tin trạng thái hiện tại của Upstream DNS Pool:\n\n${poolStatusContext}\n\nHãy trả về trọng số tối ưu nhất cho từng IP máy chủ dưới dạng JSON.`;
    
    const postData = JSON.stringify({
        model: "llama-3.1-8b-instant",
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
                        if (res.statusCode === 429) {
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... rate limited (429). Cooling down for 90s.`);
                            keyCooldowns.set(apiKey, Date.now() + 90000);
                        } else if (res.statusCode === 401) {
                            console.warn(`[AI LB Brain] Key ${apiKey.substring(0, 8)}... unauthorized (401). Cooling down for 120s.`);
                            keyCooldowns.set(apiKey, Date.now() + 120000);
                        } else {
                            console.warn(`[AI LB Brain] Groq API returned status code ${res.statusCode}`);
                        }
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
                    isAILBRunning = false;
                    broadcastUpdate();
                    aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
                }
            });
        });
        
        req.on('error', (err) => {
            console.error("[AI LB Brain] HTTP request error:", err);
            isAILBRunning = false;
            broadcastUpdate();
            aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        console.error("[AI LB Brain] Execution error:", e);
        isAILBRunning = false;
        broadcastUpdate();
        aiLoadBalancerTimeout = setTimeout(runAILoadBalancerBrain, 15000);
    }
}

function selectAIWeightedDNS(activePool) {
    if (precomputedAiPool.length === 0) {
        return selectWeightedDNS(activePool);
    }
    if (precomputedAiPool.length === 1) {
        return precomputedAiPool[0].ip;
    }
    if (precomputedAiTotalWeight <= 0) {
        return selectWeightedDNS(activePool);
    }
    
    let rand = Math.random() * precomputedAiTotalWeight;
    for (let i = 0; i < precomputedAiPool.length; i++) {
        const item = precomputedAiPool[i];
        rand -= item.weight;
        if (rand <= 0) {
            return item.ip;
        }
    }
    return precomputedAiPool[0].ip;
}

// Probability-weighted selector (Inverse Latency Squared)
function selectWeightedDNS(activePool) {
    if (activePool.length === 0) return "1.1.1.1";
    if (activePool.length === 1) return activePool[0].ip;
    
    let totalWeight = 0;
    for (let i = 0; i < activePool.length; i++) {
        const s = activePool[i];
        if (s.online !== false && (s.latency || 0) < 9999) {
            const lat = Math.max(s.latency || 5, 2);
            const weight = Math.round(100000 / (lat * lat));
            totalWeight += weight;
        }
    }
    
    if (totalWeight <= 0) return activePool[0].ip;
    
    let rand = Math.random() * totalWeight;
    for (let i = 0; i < activePool.length; i++) {
        const s = activePool[i];
        if (s.online !== false && (s.latency || 0) < 9999) {
            const lat = Math.max(s.latency || 5, 2);
            const weight = Math.round(100000 / (lat * lat));
            rand -= weight;
            if (rand <= 0) {
                return s.ip;
            }
        }
    }
    return activePool[0].ip;
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
    
    if (algo === "weighted-round-robin") {
        if (selectUpstreamDNS.wrrIndex === undefined) selectUpstreamDNS.wrrIndex = 0;
        
        let wrrList = [];
        const pool = activePool.filter(s => s.online !== false && (s.latency || 0) < 9999);
        if (pool.length === 0) return activePool[0].ip;
        
        const minLat = Math.min(...pool.map(s => Math.max(s.latency || 5, 2)));
        pool.forEach(s => {
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
    config.upstreamPool.forEach(server => {
        server.queryCount = server.queryCount || 0;
        server.history = [];
        server.successRate = 100;
    });
    config.lbAlgorithm = config.lbAlgorithm || "least-latency";
    config.gslbRecords = config.gslbRecords || {};
    config.dnsRacingEnabled = config.dnsRacingEnabled !== undefined ? config.dnsRacingEnabled : true;
    config.dnsRacingDelayMs = config.dnsRacingDelayMs !== undefined ? config.dnsRacingDelayMs : 15;
    
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
    const domains = ["google.com", "cloudflare.com", "facebook.com"];
    domains.forEach(domain => {
        const queryBuffer = buildQueryBufferForMeasure(domain);
        queryUpstream(queryBuffer, ip, (response) => {
            // Note: queryUpstream response/timeout/error handlers will automatically
            // calculate latency, online status, and success rates.
        }, false);
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

// Periodic Latency Checking
setInterval(measureUpstreamPool, 30000);
setTimeout(measureUpstreamPool, 3000); // Check shortly after start
setInterval(runCacheGC, 60000); // Cache Garbage Collector every 60s

setTimeout(runAILoadBalancerBrain, 5000);

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
    
    config.upstreamPool.push({ ip, name, latency: 0, online: true });
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
        return `- ${s.name} (${s.ip}): Trạng thái = ${s.online !== false ? 'ONLINE' : 'OFFLINE'}, Độ trễ RTT = ${s.online !== false ? (s.latency || 0) + 'ms' : 'N/A'}, Tỷ lệ thành công = ${rate}, Tổng lượt truy vấn = ${s.queryCount || 0}`;
    }).join('\n');
    
    const systemContent = "You are a DNS Traffic Load Balancer & AI Routing expert.\n" +
                          "Your task is to analyze the performance (RTT latency, online status, success rate, and query counts) of the upstream DNS servers and distribute traffic weights among the ONLINE servers, and dynamically optimize the DNS Racing configuration.\n\n" +
                          "Instructions:\n" +
                          "1. Only assign weights to ONLINE servers. Assign 0 weight to OFFLINE servers.\n" +
                          "2. Distribute weights (from 0 to 100, summing up to 100) such that faster servers (lower RTT latencies) and more reliable servers (higher success rates) receive a higher proportion of the traffic, while slower or degraded servers receive very low or 0 weight. Be aggressive with assigning more weight to lower latency servers.\n" +
                          "3. Decide whether DNS Racing (querying the second fastest server if the first is slow) should be enabled (\"dnsRacingEnabled\": true/false). Enable it if the primary DNS is unstable or has success rate < 95%, or if RTTs are fluctuating. Disable it to save resources only if all active servers are 100% stable and fast.\n" +
                          "4. Suggest the optimal DNS Racing delay in ms (\"dnsRacingDelayMs\": integer, between 5 and 50). Set it lower (e.g., 8-15ms) if the primary server is fast but needs a tight safety net, or higher (e.g., 20-35ms) if RTTs are naturally higher.\n" +
                          "5. Keep the output clean and return a strict JSON response containing \"weights\", \"dnsRacingEnabled\", \"dnsRacingDelayMs\", and \"reason\" (Vietnamese explanation, 10-15 words).\n\n" +
                          "JSON response format:\n" +
                          "{\n" +
                          "  \"weights\": {\n" +
                          "    \"1.1.1.1\": 60,\n" +
                          "    \"8.8.8.8\": 30,\n" +
                          "    \"9.9.9.9\": 10,\n" +
                          "    \"208.67.222.222\": 0\n" +
                          "  },\n" +
                          "  \"dnsRacingEnabled\": true,\n" +
                          "  \"dnsRacingDelayMs\": 15,\n" +
                          "  \"reason\": \"Giải thích lý do điều phối tải và tối ưu DNS Racing bằng tiếng Việt\"\n" +
                          "}";
                          
    const userContent = `Dưới đây là thông tin trạng thái hiện tại của Upstream DNS Pool:\n\n${poolStatusContext}\n\nHãy trả về trọng số tối ưu nhất cho từng IP máy chủ dưới dạng JSON.`;
    
    const postData = JSON.stringify({
        model: "llama-3.1-8b-instant",
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
                        isAILBRunning = false;
                        broadcastUpdate();
                        return res.status(500).json({ error: `Groq API error status: ${groqRes.statusCode}` });
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
                        
                        config.aiLBReason = reason;
                        config.lastAiLBTime = Date.now();
                        saveConfig();
                        
                        isAILBRunning = false;
                        rebuildAiRoutingCache();
                        broadcastUpdate();
                        
                        decision.modelUsed = "llama-3.1-8b-instant";
                        return res.json(decision);
                    } else {
                        isAILBRunning = false;
                        broadcastUpdate();
                        return res.status(500).json({ error: "Không nhận được phản hồi từ Groq." });
                    }
                } catch(e) {
                    isAILBRunning = false;
                    broadcastUpdate();
                    return res.status(500).json({ error: e.message });
                }
            });
        });
        groqReq.on('error', (err) => {
            isAILBRunning = false;
            broadcastUpdate();
            res.status(500).json({ error: err.message });
        });
        groqReq.write(postData);
        groqReq.end();
    } catch(e) {
        isAILBRunning = false;
        broadcastUpdate();
        return res.status(500).json({ error: e.message });
    }
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
