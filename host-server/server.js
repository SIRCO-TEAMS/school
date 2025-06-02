const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const bodyParser = require('body-parser');

const app = express();
const PORT = 4000;

// --- SECURITY CONFIG ---
const KEY_FILE = path.join(__dirname, 'server.key'); // Provide your SSL key
const CERT_FILE = path.join(__dirname, 'server.cert'); // Provide your SSL cert
const AUTH_KEY = fs.existsSync(path.join(__dirname, 'auth.key'))
    ? fs.readFileSync(path.join(__dirname, 'auth.key'), 'utf8').trim()
    : null;

// --- MIDDLEWARE ---
app.use(bodyParser.json());

// --- STATIC OWNER PANEL ---
app.use('/owner', express.static(path.join(__dirname, 'html')));

// --- AUTHENTICATION MIDDLEWARE ---
function requireKey(req, res, next) {
    const clientKey = req.headers['x-auth-key'];
    if (!AUTH_KEY || clientKey !== AUTH_KEY) {
        return res.status(403).json({ error: 'Forbidden: Invalid key' });
    }
    next();
}

// --- ROUTES ---
app.get('/', (req, res) => {
    res.send('Main server is running. Visit /owner for the owner panel.');
});

// Notification endpoint (requires key)
app.post('/notify', requireKey, (req, res) => {
    console.log("Alert received: ", req.body);
    res.sendStatus(200);
});

// Storage endpoint for logs (requires key)
app.post('/storage/upload', requireKey, (req, res) => {
    const { filename, content } = req.body;
    if (!filename || !content) return res.status(400).json({ error: 'Missing filename or content' });
    const storageDir = path.join(__dirname, 'storage');
    if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir);
    fs.writeFileSync(path.join(storageDir, filename), content);
    res.json({ status: 'ok' });
});

// --- HTTPS SERVER ---
if (fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE)) {
    https.createServer({
        key: fs.readFileSync(KEY_FILE),
        cert: fs.readFileSync(CERT_FILE)
    }, app).listen(PORT, () => {
        console.log(`Main server running securely on https://localhost:${PORT}`);
    });
} else {
    app.listen(PORT, () => {
        console.log(`Main server running (INSECURE) on http://localhost:${PORT}`);
        console.log('WARNING: SSL cert/key not found, running without HTTPS!');
    });
}
