const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
// 🌐 Serve Index.html on main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});


// 🛡️ ANTI-SPAM (1 Min me max 10 requests)
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, max: 10,
    message: { status: "failed", message: "🚫 Limit Reached! Try again later." }
});
// 🚀 MONGODB CONNECTION (Cloud Database)
const MONGO_URI = "mongodb+srv://BABA:Admin_baba@cluster0.avswfsi.mongodb.net/?appName=Cluster0";
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Super Database Connected!"))
    .catch(err => console.log("❌ DB Error:", err));

// 📊 DATABASE STRUCTURES (Schemas)
const User = mongoose.model('User', new mongoose.Schema({ username: String, password: String, role: String, status: { type: String, default: "active" } }));
const Key = mongoose.model('Key', new mongoose.Schema({ key: String, durationDays: Number, status: String, hwid: String, expiryDate: Date, owner: String }));
const Invite = mongoose.model('Invite', new mongoose.Schema({ code: String }));

// 🛡️ SECURITY MIDDLEWARE
const authenticate = async (req, res, next) => {
    const user = await User.findOne({ username: req.headers['x-username'], password: req.headers['x-password'] });
    if (!user) return res.status(401).json({ success: false, message: "Login required!" });
    if (user.status === "blocked") return res.status(403).json({ success: false, message: "🚫 Account Blocked!" });
    req.user = user; next();
};

// ⚙️ API ROUTES
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username, password: req.body.password });
    if (!user) return res.json({ success: false, message: "Invalid Username or Password!" });
    if (user.status === "blocked") return res.json({ success: false, message: "🚫 Account Blocked!" });
    res.json({ success: true, role: user.role, message: "Login Successful!" });
});

app.post('/api/register', async (req, res) => {
    const { username, password, inviteCode } = req.body;
    if (await User.findOne({ username })) return res.json({ success: false, message: "Username already exist!" });
    
    const invite = await Invite.findOne({ code: inviteCode });
    if (!invite) return res.json({ success: false, message: "Invalid Invite Code!" });

    await Invite.deleteOne({ code: inviteCode }); // Code use hone par delete
    await User.create({ username, password, role: "user" });
    res.json({ success: true, message: "Account Created!" });
});

app.post('/api/create_invite', authenticate, async (req, res) => {
    if (req.user.role !== "admin") return res.json({ success: false });
    const code = "BABA-" + crypto.randomBytes(3).toString('hex').toUpperCase();
    await Invite.create({ code });
    res.json({ success: true, invite: code });
});

app.get('/api/users', authenticate, async (req, res) => {
    if (req.user.role !== "admin") return res.json([]);
    const users = await User.find({ role: "user" });
    res.json(users);
});

app.post('/api/toggle_user', authenticate, async (req, res) => {
    if (req.user.role !== "admin") return res.json({ success: false });
    const user = await User.findOne({ username: req.body.targetUser });
    if (user) {
        user.status = user.status === "blocked" ? "active" : "blocked";
        await user.save();
        res.json({ success: true, message: `User ab ${user.status} hai!` });
    }
});

app.post('/api/generate', authenticate, async (req, res) => {
    const { durationDays, customKey } = req.body;
    let finalKey = (customKey && customKey.trim()) ? customKey.trim() : crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
    
    if (await Key.findOne({ key: finalKey })) return res.json({ success: false, message: "❌ Key already exists!" });

    await Key.create({ key: finalKey, durationDays, status: "Unused", owner: req.user.username });
    res.json({ success: true, key: finalKey });
});

app.get('/api/keys', authenticate, async (req, res) => {
    const keys = req.user.role === "admin" ? await Key.find() : await Key.find({ owner: req.user.username });
    res.json(keys);
});

app.post('/api/toggle_key', authenticate, async (req, res) => {
    const keyData = await Key.findOne({ key: req.body.key });
    if (!keyData) return res.json({ success: false, message: "Key nahi mili!" });
    if (req.user.role !== "admin" && keyData.owner !== req.user.username) return res.json({ success: false, message: "Not allowed!" });

    keyData.status = keyData.status === "Blocked" ? (keyData.hwid ? "Active" : "Unused") : "Blocked";
    await keyData.save();
    res.json({ success: true, message: `Key is now ${keyData.status}` });
});

// 🔓 MAIN LOADER VALIDATION (Ultra Fast & Anti-Spam)
app.post('/api/validate', apiLimiter, async (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ status: "failed", message: "Key required!" });

    const keyData = await Key.findOne({ key });
    if (!keyData) return res.json({ status: "failed", message: "Invalid Key!" });
    if (keyData.status === "Blocked") return res.json({ status: "failed", message: "Key is Blocked!" });

    if (keyData.status === "Expired" || (keyData.expiryDate && new Date() > new Date(keyData.expiryDate))) {
        keyData.status = "Expired"; await keyData.save();
        return res.json({ status: "failed", message: "Key Expired!" });
    }

    if (keyData.status === "Unused") {
        let expiry = new Date(); expiry.setDate(expiry.getDate() + keyData.durationDays);
        keyData.status = "Active"; keyData.hwid = hwid; keyData.expiryDate = expiry;
        await keyData.save();
        return res.json({ status: "success", message: "Activated!", expiry: keyData.expiryDate });
    }

    if (keyData.status === "Active") {
        if (keyData.hwid !== hwid) return res.json({ status: "failed", message: "HWID Mismatch!" });
        return res.json({ status: "success", message: "Access Granted!", expiry: keyData.expiryDate });
    }
});

// Admin Account Auto-Create logic
async function initAdmin() {
    const adminExists = await User.findOne({ username: "admin" });
    if (!adminExists) {
        // Apna khud ka ID PASSWORD Yahan Set Karein 👇
        await User.create({ username: "Admin", password: "Baba@123", role: "admin", status: "active" });
        console.log("Admin account created!");
    }
}
mongoose.connection.once('open', () => initAdmin());

app.listen(process.env.PORT || 5000, '0.0.0.0', () => console.log("Server Running..."));
    
