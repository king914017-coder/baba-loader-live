const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Files ke naam
const DB_FILE = './database.json';
const USERS_FILE = './users.json';
const INVITES_FILE = './invites.json';

// Helper: File read aur write karne ke liye (Agar file na ho toh khud bana dega)
const readJSON = (file, defaultData) => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify(defaultData, null, 2));
        return defaultData;
    }
    return JSON.parse(fs.readFileSync(file, 'utf8'));
};
const writeJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

// Start hote hi files setup karein (Aapka Main Admin Account Yahan Hai 👇)
readJSON(DB_FILE, []);
readJSON(USERS_FILE, [{ username: "admin", password: "Baba@123", role: "admin" }]);
readJSON(INVITES_FILE, []);

// 🛡️ SECURITY MIDDLEWARE (Check karega ki user asli hai ya nahi)
const authenticate = (req, res, next) => {
    const username = req.headers['x-username'];
    const password = req.headers['x-password'];
    
    const users = readJSON(USERS_FILE, []);
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) return res.status(401).json({ success: false, message: "Login required!" });
    
    req.user = user; // Request me user ka data jod diya
    next();
};

// 🌐 HTML Page Serve Karein
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 🔑 API: LOGIN System
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(USERS_FILE, []);
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        res.json({ success: true, role: user.role, message: "Login Successful!" });
    } else {
        res.json({ success: false, message: "Galat Username ya Password!" });
    }
});

// 📝 API: REGISTER System (Invite Code Ke Sath)
app.post('/api/register', (req, res) => {
    const { username, password, inviteCode } = req.body;
    if(!username || !password || !inviteCode) return res.json({ success: false, message: "Saari details bharein!" });

    let invites = readJSON(INVITES_FILE, []);
    let users = readJSON(USERS_FILE, []);

    // Check 1: Kya username pehle se hai?
    if (users.find(u => u.username === username)) {
        return res.json({ success: false, message: "Ye Username pehle se kisi aur ne liya hai!" });
    }
    // Check 2: Kya invite code sahi hai?
    const inviteIndex = invites.indexOf(inviteCode);
    if (inviteIndex === -1) {
        return res.json({ success: false, message: "Galat ya Expired Invite Code!" });
    }

    // Naya user banayein aur invite code ko delete kar dein
    invites.splice(inviteIndex, 1);
    users.push({ username: username, password: password, role: "user" });
    
    writeJSON(INVITES_FILE, invites);
    writeJSON(USERS_FILE, users);
    
    res.json({ success: true, message: "Account ban gaya! Ab aap Login kar sakte hain." });
});

// 🎟️ API: Naya Invite Code Banayein (Sirf Main Admin Ke Liye)
app.post('/api/create_invite', authenticate, (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Sirf Admin ye kar sakta hai!" });
    
    const newInvite = "BABA-" + crypto.randomBytes(3).toString('hex').toUpperCase();
    let invites = readJSON(INVITES_FILE, []);
    invites.push(newInvite);
    writeJSON(INVITES_FILE, invites);
    
    res.json({ success: true, invite: newInvite });
});

// ➕ API: Key Generate Karein
app.post('/api/generate', authenticate, (req, res) => {
    const { durationDays } = req.body;
    if (!durationDays) return res.status(400).json({ error: "Duration zaroori hai!" });

    const formattedKey = crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
    const db = readJSON(DB_FILE, []);
    
    db.push({ 
        key: formattedKey, 
        durationDays: parseInt(durationDays), 
        status: "Unused", 
        hwid: null, 
        expiryDate: null,
        owner: req.user.username // 👈 Jisne banaya, uska naam save hoga
    });
    writeJSON(DB_FILE, db);

    res.json({ success: true, key: formattedKey });
});

// 📋 API: Keys Dekhein
app.get('/api/keys', authenticate, (req, res) => {
    const db = readJSON(DB_FILE, []);
    // Admin saari keys dekhega, ordinary user sirf apni banayi hui keys dekhega
    if (req.user.role === "admin") {
        res.json(db);
    } else {
        const myKeys = db.filter(k => k.owner === req.user.username);
        res.json(myKeys);
    }
});

// 🔓 API: Loader Validation (ISME KOI AUTH NAHI HAI)
app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.status(400).json({ status: "failed", message: "Key aur HWID required!" });

    let db = readJSON(DB_FILE, []);
    let keyIndex = db.findIndex(k => k.key === key);

    if (keyIndex === -1) return res.json({ status: "failed", message: "Invalid Key!" });

    let keyData = db[keyIndex];

    if (keyData.status === "Expired" || (keyData.expiryDate && new Date() > new Date(keyData.expiryDate))) {
        keyData.status = "Expired"; writeJSON(DB_FILE, db);
        return res.json({ status: "failed", message: "Key Expired!" });
    }

    if (keyData.status === "Unused") {
        let expiry = new Date(); expiry.setDate(expiry.getDate() + keyData.durationDays);
        keyData.status = "Active"; keyData.hwid = hwid; keyData.expiryDate = expiry.toISOString();
        writeJSON(DB_FILE, db);
        return res.json({ status: "success", message: "Activated!", expiry: keyData.expiryDate });
    }

    if (keyData.status === "Active") {
        if (keyData.hwid !== hwid) return res.json({ status: "failed", message: "HWID Mismatch!" });
        return res.json({ status: "success", message: "Access Granted!", expiry: keyData.expiryDate });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server is running on ${PORT}`));
