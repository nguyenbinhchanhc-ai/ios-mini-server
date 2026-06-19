const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// Store the active iPhone connection
let iphoneSocket = null;

// Store pending HTTP requests waiting for iPhone responses
// Key: requestId (String), Value: { res, timeout }
const pendingRequests = new Map();

// Helper to parse raw body buffer for uploads
app.use((req, res, next) => {
    const data = [];
    req.on('data', chunk => data.push(chunk));
    req.on('end', () => {
        req.rawBody = Buffer.concat(data);
        next();
    });
});

// Upgrade HTTP connection to WebSocket for the /tunnel endpoint
server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname === '/tunnel') {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else {
        socket.destroy();
    }
});

// Handle WebSocket connections
wss.on('connection', (ws, request) => {
    console.log('iPhone connected via WebSocket tunnel!');
    
    // If there is an existing connection, close it
    if (iphoneSocket) {
        iphoneSocket.terminate();
    }
    
    iphoneSocket = ws;
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // Handle response from iPhone
            if (data.type === 'response') {
                const pending = pendingRequests.get(data.id);
                if (pending) {
                    clearTimeout(pending.timeout);
                    pendingRequests.delete(data.id);
                    
                    const res = pending.res;
                    
                    // Set status and headers
                    res.status(data.statusCode || 200);
                    if (data.headers) {
                        Object.keys(data.headers).forEach(key => {
                            res.setHeader(key, data.headers[key]);
                        });
                    }
                    
                    // Decode base64 body if present
                    if (data.body) {
                        const bodyBuffer = Buffer.from(data.body, 'base64');
                        res.send(bodyBuffer);
                    } else {
                        res.end();
                    }
                }
            } else if (data.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
            }
        } catch (err) {
            console.error('Failed to parse WebSocket message:', err);
        }
    });
    
    ws.on('close', () => {
        console.log('iPhone disconnected.');
        if (iphoneSocket === ws) {
            iphoneSocket = null;
        }
        
        // Fail all pending requests
        pendingRequests.forEach((pending, id) => {
            clearTimeout(pending.timeout);
            pending.res.status(503).send('iPhone Server offline (Tunnel connection lost)');
        });
        pendingRequests.clear();
    });
    
    ws.on('error', (err) => {
        console.error('WebSocket tunnel error:', err);
    });
});

// Handle all incoming HTTP requests and forward them to the iPhone
app.all('*', (req, res) => {
    // Skip /tunnel path which is handled by WebSocket upgrade
    if (req.path === '/tunnel') return;
    
    if (!iphoneSocket || iphoneSocket.readyState !== WebSocket.OPEN) {
        res.status(503).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Server Offline</title>
                <style>
                    body { background: #0b0f19; color: #f3f4f6; font-family: system-ui, sans-serif; text-align: center; padding: 5rem 1rem; }
                    .card { max-width: 500px; margin: 0 auto; background: rgba(255,255,255,0.05); padding: 2.5rem; border-radius: 20px; border: 1px solid rgba(255,255,255,0.08); }
                    h1 { color: #ef4444; margin-bottom: 1rem; }
                    p { color: #9ca3af; line-height: 1.5; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>iPhone Server Offline 📱❌</h1>
                    <p>Ứng dụng máy chủ trên iPhone hiện chưa kết nối đến đường truyền đám mây. Vui lòng bật tính năng "Mạng công cộng" trong ứng dụng trên điện thoại của bạn.</p>
                </div>
            </body>
            </html>
        `);
        return;
    }
    
    // Create unique request ID
    const requestId = crypto.randomBytes(16).toString('hex');
    
    // Package request
    const requestPayload = {
        type: 'request',
        id: requestId,
        method: req.method,
        path: req.path,
        query: req.url.split('?')[1] || '',
        headers: req.headers,
        body: req.rawBody ? req.rawBody.toString('base64') : ''
    };
    
    // Set response timeout (30 seconds)
    const timeout = setTimeout(() => {
        pendingRequests.delete(requestId);
        res.status(504).send('Gateway Timeout: iPhone server took too long to respond.');
    }, 30000);
    
    // Store response object
    pendingRequests.set(requestId, { res, timeout });
    
    // Send to iPhone
    iphoneSocket.send(JSON.stringify(requestPayload));
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Relay Server running on port ${PORT}`);
});
