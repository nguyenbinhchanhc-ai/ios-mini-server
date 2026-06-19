const express = require('express');
const http = require('http');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
const server = http.createServer(app);

const CONFIG_PATH = path.join(__dirname, 'dns_config.json');
const SUB_CACHE_PATH = path.join(__dirname, 'subscription_blocklist.txt');

// State variables
let config = {};
let customBlockedSet = new Set();
let whitelistSet = new Set();
let subscriptionBlockedSet = new Set();
let isUpdatingList = false;
let logs = [];

// Load config and caches
loadConfig();

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
                subscriptionURLs: [
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                ],
                upstreamDNS: "1.1.1.1",
                stats: { total: 0, blocked: 0, allowed: 0 }
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
            subscriptionURLs: [
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            ],
            upstreamDNS: "1.1.1.1",
            stats: { total: 0, blocked: 0, allowed: 0 }
        };
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
    return {
        domain: domain,
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

// MARK: - Ad-Blocking Tra cứu (Optimized O(K))

function shouldBlock(domain) {
    const lowercaseDomain = domain.toLowerCase();
    
    // 1. Whitelist Check (exact or parent subdomain)
    if (whitelistSet.has(lowercaseDomain)) return false;
    let parts = lowercaseDomain.split('.');
    if (parts.length > 1) {
        for (let i = 1; i < parts.length; i++) {
            let parent = parts.slice(i).join('.');
            if (whitelistSet.has(parent)) return false;
        }
    }
    
    // 2. Custom Blocklist Check (exact or parent subdomain)
    if (customBlockedSet.has(lowercaseDomain)) return true;
    if (parts.length > 1) {
        for (let i = 1; i < parts.length; i++) {
            let parent = parts.slice(i).join('.');
            if (customBlockedSet.has(parent)) return true;
        }
    }
    
    // 3. Subscription Blocklist Check (exact or parent subdomain)
    if (subscriptionBlockedSet.has(lowercaseDomain)) return true;
    if (parts.length > 1) {
        for (let i = 1; i < parts.length; i++) {
            let parent = parts.slice(i).join('.');
            if (subscriptionBlockedSet.has(parent)) return true;
        }
    }
    
    return false;
}

// MARK: - Upstream DNS Resolver (UDP)

function queryUpstream(dnsQueryBuffer, upstreamIP, callback) {
    const client = dgram.createSocket('udp4');
    let closed = false;
    
    const safeClose = () => {
        if (!closed) {
            closed = true;
            try { client.close(); } catch(e) {}
        }
    };
    
    let timer = setTimeout(() => {
        safeClose();
        callback(null);
    }, 4000); // 4 seconds query timeout
    
    client.on('message', (msg) => {
        clearTimeout(timer);
        safeClose();
        callback(msg);
    });
    
    client.on('error', (err) => {
        console.error("Upstream UDP Socket Error:", err);
        clearTimeout(timer);
        safeClose();
        callback(null);
    });
    
    client.send(dnsQueryBuffer, 0, dnsQueryBuffer.length, 53, upstreamIP, (err) => {
        if (err) {
            console.error("Failed to send DNS request to upstream:", err);
            clearTimeout(timer);
            safeClose();
            callback(null);
        }
    });
}

// MARK: - Logs and Stats Logging

function logQuery(domain, blocked, clientIP) {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0]; // HH:mm:ss
    const status = blocked ? "❌ BLOCKED" : "✅ ALLOWED";
    const msg = `[${timeStr}] [${clientIP}] ${status} - ${domain}`;
    
    logs.push(msg);
    if (logs.length > 100) {
        logs.shift();
    }
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
    console.log("Starting blocklist subscription sync...");
    
    const urls = config.subscriptionURLs || [];
    let newBlocked = new Set();
    let completed = 0;
    
    if (urls.length === 0) {
        isUpdatingList = false;
        if (callback) callback();
        return;
    }
    
    urls.forEach(urlString => {
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
                            newBlocked.add(domain);
                            parsedCount++;
                        }
                    } else if (parts.length === 1) {
                        let domain = parts[0].toLowerCase();
                        if (domain.startsWith('||') && domain.endsWith('^')) {
                            domain = domain.substring(2, domain.length - 1);
                        }
                        if (isValidDomain(domain)) {
                            newBlocked.add(domain);
                            parsedCount++;
                        }
                    }
                });
                console.log(`Successfully parsed ${parsedCount} domains from ${urlString}`);
            }
            
            completed++;
            if (completed === urls.length) {
                isUpdatingList = false;
                if (newBlocked.size > 0) {
                    subscriptionBlockedSet = newBlocked;
                    saveSubscriptionBlocklistToDisk();
                }
                console.log(`Sync completed. Total active rules: ${subscriptionBlockedSet.size}`);
                if (callback) callback();
            }
        });
    });
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

function handleDoH(queryData, clientIP, callback) {
    const parsed = parseDNSQuery(queryData);
    if (!parsed) {
        callback(Buffer.alloc(0));
        return;
    }
    
    const domain = parsed.domain;
    const isBlocked = shouldBlock(domain);
    
    logQuery(domain, isBlocked, clientIP);
    incrementStats(isBlocked);
    
    if (isBlocked) {
        const blockResponse = buildBlockResponse(queryData, parsed.questionEndOffset);
        callback(blockResponse);
    } else {
        queryUpstream(queryData, config.upstreamDNS, (response) => {
            if (response) {
                callback(response);
            } else {
                callback(Buffer.alloc(0));
            }
        });
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
    
    handleDoH(queryData, clientIP, (responseData) => {
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
    
    handleDoH(queryData, clientIP, (responseData) => {
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
        blockedPercent: config.stats.total > 0 ? (config.stats.blocked / config.stats.total * 100) : 0
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
        isUpdating: isUpdating
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
            res.send("Upstream updated");
        } else {
            res.status(400).send("Invalid IP format");
        }
    } else {
        res.status(400).send("Missing ip parameter");
    }
});

app.post('/dns/stats/reset', (req, res) => {
    config.stats = { total: 0, blocked: 0, allowed: 0 };
    saveConfig();
    res.send("Stats reset");
});

app.post('/dns/toggle', (req, res) => {
    // Persistent Cloud DNS server is always active
    res.json({ running: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Render Cloud DNS Blocker running on port ${PORT}`);
});
