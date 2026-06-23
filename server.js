const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const DB_FILE = './database.json';

// Admin Panel ko browser me dikhane ke liye
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Database read/write helpers
const readDB = () => {
    if (!fs.existsSync(DB_FILE)) return [];
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
};
const writeDB = (data) => {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
};

// 🔑 API: Key Generate Karein
app.post('/api/generate', (req, res) => {
    const { durationDays } = req.body;
    if (!durationDays) return res.status(400).json({ error: "Duration zaroori hai!" });

    const rawKey = crypto.randomBytes(6).toString('hex').toUpperCase();
    const formattedKey = rawKey.match(/.{1,4}/g).join('-');

    const db = readDB();
    db.push({ key: formattedKey, durationDays: parseInt(durationDays), status: "Unused", hwid: null, expiryDate: null });
    writeDB(db);

    res.json({ success: true, key: formattedKey });
});

// 📋 API: Saari Keys Dekhein
app.get('/api/keys', (req, res) => {
    res.json(readDB());
});

// 🔓 API: Loader se Key Verify Karein
app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.status(400).json({ status: "failed", message: "Key aur HWID required!" });

    let db = readDB();
    let keyIndex = db.findIndex(k => k.key === key);

    if (keyIndex === -1) return res.json({ status: "failed", message: "Invalid Key!" });

    let keyData = db[keyIndex];

    if (keyData.status === "Expired" || (keyData.expiryDate && new Date() > new Date(keyData.expiryDate))) {
        keyData.status = "Expired"; writeDB(db);
        return res.json({ status: "failed", message: "Key Expired!" });
    }

    if (keyData.status === "Unused") {
        let expiry = new Date(); expiry.setDate(expiry.getDate() + keyData.durationDays);
        keyData.status = "Active"; keyData.hwid = hwid; keyData.expiryDate = expiry.toISOString();
        writeDB(db);
        return res.json({ status: "success", message: "Activated!", expiry: keyData.expiryDate });
    }

    if (keyData.status === "Active") {
        if (keyData.hwid !== hwid) return res.json({ status: "failed", message: "HWID Mismatch!" });
        return res.json({ status: "success", message: "Access Granted!", expiry: keyData.expiryDate });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server started! Browser me open karein: http://localhost:${PORT}`);
});
