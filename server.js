const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const DB_FILE = './database.json';
const USERS_FILE = './users.json';
const INVITES_FILE = './invites.json';

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


readJSON(DB_FILE, []);
readJSON(USERS_FILE, [{ username: "Admin", password: "Mishra@123", role: "admin", status: "active" }]);
readJSON(INVITES_FILE, []);


const authenticate = (req, res, next) => {
    const username = req.headers['x-username'];
    const password = req.headers['x-password'];
    
    const users = readJSON(USERS_FILE, []);
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) return res.status(401).json({ success: false, message: "Login required!" });
    
    
    if (user.status === "blocked") return res.status(403).json({ success: false, message: "🚫 Your account is blocked!" });
    
    req.user = user;
    next();
};

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(USERS_FILE, []);
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        if (user.status === "blocked") return res.json({ success: false, message: "🚫 Your account is BLOCKED!" });
        res.json({ success: true, role: user.role, message: "Login Successful!" });
    } else {
        res.json({ success: false, message: "Wrong Username or Password!" });
    }
});

app.post('/api/register', (req, res) => {
    const { username, password, inviteCode } = req.body;
    if(!username || !password || !inviteCode) return res.json({ success: false, message: "Fill the details!" });

    let invites = readJSON(INVITES_FILE, []);
    let users = readJSON(USERS_FILE, []);

    if (users.find(u => u.username === username)) return res.json({ success: false, message: "Username already exist!" });
    
    const inviteIndex = invites.indexOf(inviteCode);
    if (inviteIndex === -1) return res.json({ success: false, message: "Code Expired!" });

    invites.splice(inviteIndex, 1);
    users.push({ username: username, password: password, role: "user", status: "active" });
    
    writeJSON(INVITES_FILE, invites);
    writeJSON(USERS_FILE, users);
    
    res.json({ success: true, message: "Account created" });
});

app.post('/api/create_invite', authenticate, (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Only Admin!" });
    const newInvite = "BABA-" + crypto.randomBytes(3).toString('hex').toUpperCase();
    let invites = readJSON(INVITES_FILE, []);
    invites.push(newInvite);
    writeJSON(INVITES_FILE, invites);
    res.json({ success: true, invite: newInvite });
});


app.get('/api/users', authenticate, (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json([]);
    const users = readJSON(USERS_FILE, []);
    const resellers = users.filter(u => u.role !== "admin");
    res.json(resellers);
});


app.post('/api/toggle_user', authenticate, (req, res) => {
    if (req.user.role !== "admin") return res.json({ success: false, message: "User Blocked" });
    
    const { targetUser } = req.body;
    let users = readJSON(USERS_FILE, []);
    let user = users.find(u => u.username === targetUser);
    
    if (user) {
        user.status = (user.status === "blocked") ? "active" : "blocked";
        writeJSON(USERS_FILE, users);
        res.json({ success: true, message: `User ${targetUser} ab ${user.status} hai!` });
    } else {
        res.json({ success: false, message: "User not found!" });
    }
});


app.post('/api/generate', authenticate, (req, res) => {
    const { durationDays, customKey } = req.body;
    if (!durationDays) return res.status(400).json({ error: "Duration needed!" });

    const db = readJSON(DB_FILE, []);
    
    
    let finalKey = (customKey && customKey.trim() !== "") 
                   ? customKey.trim() 
                   : crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');

    
    if (db.find(k => k.key === finalKey)) {
        return res.json({ success: false, message: "❌ This key is already exist try new" });
    }

    db.push({ 
        key: finalKey, 
        durationDays: parseInt(durationDays), 
        status: "Unused", 
        hwid: null, 
        expiryDate: null,
        owner: req.user.username
    });
    writeJSON(DB_FILE, db);

    res.json({ success: true, key: finalKey });
});

app.get('/api/keys', authenticate, (req, res) => {
    const db = readJSON(DB_FILE, []);
    if (req.user.role === "admin") res.json(db);
    else res.json(db.filter(k => k.owner === req.user.username));
});


app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.status(400).json({ status: "failed", message: "Key and HWID required!" });

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
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on ${PORT}`));
