const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = 4000;

// --- SECURITY CONFIG ---
const KEY_FILE = path.join(__dirname, 'server.key');
const CERT_FILE = path.join(__dirname, 'server.cert');
const AUTH_KEY_FILE = path.join(__dirname, 'auth.key');
const CONFIG_FILE = path.join(__dirname, 'config.json');

// Generate auth.key if missing
if (!fs.existsSync(AUTH_KEY_FILE)) {
    const key = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(AUTH_KEY_FILE, key);
}
const AUTH_KEY = fs.readFileSync(AUTH_KEY_FILE, 'utf8').trim();

// Generate config.json if missing
if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
        masterPassword: "admin",
        securityPhrase: "secure"
    }, null, 2));
}

// --- MIDDLEWARE ---
app.use(bodyParser.json());

// --- STATIC OWNER PANEL ---
app.use('/owner', express.static(path.join(__dirname, 'html')));

// --- API for owner panel authentication and settings ---
function loadOwnerSettings() {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
}
function saveOwnerSettings(settings) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(settings, null, 2));
}

// Endpoint to get the current auth key (for download)
app.get('/owner/api/auth-key', (req, res) => {
    res.type('text/plain').send(AUTH_KEY);
});

// Endpoint to authenticate owner panel
app.post('/owner/api/login', (req, res) => {
    const { password, phrase } = req.body;
    const settings = loadOwnerSettings();
    if (password === settings.masterPassword && phrase === settings.securityPhrase) {
        res.json({ success: true });
    } else {
        res.json({ success: false, error: "Invalid credentials" });
    }
});

// Endpoint to update owner settings (password/phrase)
app.post('/owner/api/update-settings', (req, res) => {
    const { oldPassword, oldPhrase, newPassword, newPhrase } = req.body;
    const settings = loadOwnerSettings();
    if (oldPassword === settings.masterPassword && oldPhrase === settings.securityPhrase) {
        settings.masterPassword = newPassword || settings.masterPassword;
        settings.securityPhrase = newPhrase || settings.securityPhrase;
        saveOwnerSettings(settings);
        res.json({ success: true });
    } else {
        res.json({ success: false, error: "Invalid current credentials" });
    }
});

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

// Track last heartbeat per user
const lastHeartbeat = {};

app.post('/heartbeat', requireKey, (req, res) => {
    const { user } = req.body;
    if (user) {
        lastHeartbeat[user] = Date.now();
        console.log(`Heartbeat received from ${user} at ${new Date().toISOString()}`);
        res.json({ status: "ok" });
    } else {
        res.status(400).json({ error: "Missing user" });
    }
});

// Endpoint for explicit shutdown notification
app.post('/notify-shutdown', requireKey, (req, res) => {
    const { user } = req.body;
    if (user) {
        console.log(`Shutdown notification from ${user} at ${new Date().toISOString()}`);
        res.json({ status: "ok" });
    } else {
        res.status(400).json({ error: "Missing user" });
    }
});

// Periodically check for missed heartbeats (every 2 minutes)
setInterval(() => {
    const now = Date.now();
    Object.entries(lastHeartbeat).forEach(([user, ts]) => {
        if (now - ts > 5 * 60 * 1000) { // 5 minutes
            console.log(`WARNING: No heartbeat from ${user} for over 5 minutes!`);
        }
    });
}, 2 * 60 * 1000);

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
