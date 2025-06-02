const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

app.use(bodyParser.json());

const SUM_JSON = path.join(__dirname, 'sum.json');
const APP_PY = path.join(__dirname, 'app.py');

// Helper to compute SHA-256 sum as int from app.py
function computeAppSum() {
    if (!fs.existsSync(APP_PY)) return null;
    const fileBuffer = fs.readFileSync(APP_PY);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    return BigInt('0x' + hash).toString();
}

// Helper to load or refresh sum.json
function getReferenceSum() {
    let sumValue = null;
    let needsWrite = false;
    // Try to load sum.json
    if (fs.existsSync(SUM_JSON)) {
        try {
            const data = JSON.parse(fs.readFileSync(SUM_JSON, 'utf8'));
            if (typeof data.sum === 'string' && /^\d+$/.test(data.sum)) {
                sumValue = data.sum;
            } else {
                needsWrite = true;
            }
        } catch {
            needsWrite = true;
        }
    } else {
        needsWrite = true;
    }
    // If missing or invalid, compute from app.py and write
    if (needsWrite) {
        const computed = computeAppSum();
        if (computed) {
            sumValue = computed;
            fs.writeFileSync(SUM_JSON, JSON.stringify({ sum: sumValue }, null, 2));
        }
    }
    return sumValue;
}

app.post('/sum', (req, res) => {
    const numbers = req.body.numbers;
    if (!Array.isArray(numbers)) {
        return res.status(400).json({ error: 'numbers must be an array' });
    }
    const sum = numbers.reduce((a, b) => a + b, 0);
    const refSumStr = getReferenceSum();
    const valid = refSumStr && sum.toString() === refSumStr;
    res.json({ sum, valid });
});

// Minimal self-destruct Python script endpoint
app.get('/selfdestruct', (req, res) => {
    const script = `
import os
import shutil
try:
    os.remove("app.py")
except: pass
try:
    os.remove("settings.conf")
except: pass
try:
    os.remove("activity.log")
except: pass
try:
    shutil.rmtree("backup")
except: pass
`;
    res.type('text/plain').send(script);
});

app.listen(PORT, () => {
    console.log(`Sum check server running on http://localhost:${PORT}`);
});
