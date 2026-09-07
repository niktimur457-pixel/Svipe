require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const WebSocket = require("ws");
const multer = require("multer");
const nodemailer = require("nodemailer");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "svipe-secret-key-change-me";

const publicDir = path.join(__dirname, "public");
const uploadsDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadsDir));

// =========================
// MAIL.RU
// =========================

const mailer = nodemailer.createTransport({
    host: "smtp.mail.ru",
    port: 465,
    secure: true,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD
    },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 15000
});

async function sendVerificationEmail(email, code) {
    if (!process.env.MAIL_USER || !process.env.MAIL_PASSWORD) {
        throw new Error("MAIL_USER или MAIL_PASSWORD не настроены");
    }

    await mailer.sendMail({
        from: `"Svipe" <${process.env.MAIL_USER}>`,
        to: email,
        subject: "Код подтверждения Svipe",
        text:
            `Ваш код подтверждения Svipe: ${code}\n\n` +
            `Код действует 10 минут.`
    });

    console.log(`MAIL SENT: ${email}`);
}

// =========================
// DATABASE
// =========================

const db = new Database(path.join(__dirname, "svipe.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    avatar TEXT DEFAULT '',
    about TEXT DEFAULT '',
    username TEXT,
    notifications INTEGER DEFAULT 1,
    sounds INTEGER DEFAULT 1,
    privacy TEXT DEFAULT 'everyone',
    language TEXT DEFAULT 'ru',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    text TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'text',
    file_url TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    mime_type TEXT DEFAULT '',
    created_at INTEGER NOT NULL
);
`);

function columnExists(table, column) {
    return db.prepare(`PRAGMA table_info(${table})`).all()
        .some(info => info.name === column);
}

function addColumnIfMissing(table, column, definition) {
    if (!columnExists(table, column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
}

addColumnIfMissing("users", "username", "TEXT");
addColumnIfMissing("users", "notifications", "INTEGER DEFAULT 1");
addColumnIfMissing("users", "sounds", "INTEGER DEFAULT 1");
addColumnIfMissing("users", "privacy", "TEXT DEFAULT 'everyone'");
addColumnIfMissing("users", "language", "TEXT DEFAULT 'ru'");

addColumnIfMissing("messages", "type", "TEXT NOT NULL DEFAULT 'text'");
addColumnIfMissing("messages", "file_url", "TEXT DEFAULT ''");
addColumnIfMissing("messages", "file_name", "TEXT DEFAULT ''");
addColumnIfMissing("messages", "mime_type", "TEXT DEFAULT ''");

// =========================
// USERNAME
// =========================

function cleanUsername(value) {
    return String(value || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "")
        .slice(0, 24);
}

function isValidUsername(username) {
    return /^[a-z0-9_]{3,24}$/.test(username);
}

function makeUsernameFromName(name) {
    let username = String(name || "")
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "")
        .slice(0, 20);

    if (username.length < 3) username = "user";

    const base = username;
    let number = 1;

    while (db.prepare("SELECT id FROM users WHERE username = ?").get(username)) {
        username = `${base}${number}`;
        number++;
    }

    return username.slice(0, 24);
}

for (const user of db.prepare(`
    SELECT id, name FROM users
    WHERE username IS NULL OR username = ''
`).all()) {
    db.prepare("UPDATE users SET username = ? WHERE id = ?")
        .run(makeUsernameFromName(user.name), user.id);
}

try {
    db.exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username
        ON users(username)
    `);
} catch (error) {
    console.log("Username index:", error.message);
}

// =========================
// AUTH
// =========================

function getUser(id) {
    return db.prepare(`
        SELECT id, name, username, email, verified, avatar, about,
               notifications, sounds, privacy, language, created_at
        FROM users WHERE id = ?
    `).get(id);
}

function createToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
}

function auth(req, res, next) {
    try {
        const header = req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {
            return res.status(401).json({ error: "Нет токена" });
        }

        const decoded = jwt.verify(header.slice(7), JWT_SECRET);
        req.userId = Number(decoded.userId);

        if (!req.userId) {
            return res.status(401).json({ error: "Недействительный токен" });
        }

        next();
    } catch {
        return res.status(401).json({ error: "Недействительный токен" });
    }
}

// =========================
// ROOT / STATUS
// =========================

app.get("/", (req, res) => {
    res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/api", (req, res) => {
    res.json({
        success: true,
        message: "Svipe server is running"
    });
});

// =========================
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).json({ error: "Заполни все поля" });
        }

        if (!email.includes("@")) {
            return res.status(400).json({ error: "Неверный email" });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Пароль должен быть минимум 6 символов"
            });
        }

        const exists = db.prepare(`
            SELECT id, verified FROM users WHERE email = ?
        `).get(email);

        if (exists) {
            if (exists.verified) {
                return res.status(400).json({
                    error: "Пользователь с такой почтой уже существует"
                });
            }

            db.prepare("DELETE FROM verification_codes WHERE email = ?").run(email);
            db.prepare("DELETE FROM users WHERE id = ?").run(exists.id);
        }

        const hash = await bcrypt.hash(password, 10);
        const username = makeUsernameFromName(name);
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = Date.now() + 10 * 60 * 1000;

        // Сначала отправляем письмо. Пользователь создаётся только после успеха.
        await sendVerificationEmail(email, code);

        db.prepare(`
            INSERT INTO users
            (name, email, password, verified, username, created_at)
            VALUES (?, ?, ?, 0, ?, ?)
        `).run(name, email, hash, username, Date.now());

        db.prepare("DELETE FROM verification_codes WHERE email = ?").run(email);

        db.prepare(`
            INSERT INTO verification_codes (email, code, expires_at)
            VALUES (?, ?, ?)
        `).run(email, code, expiresAt);

        console.log(`Verification code sent to ${email}`);

        res.json({
            success: true,
            message: "Код отправлен на почту",
            email
        });
    } catch (error) {
        console.error("REGISTER ERROR:", error);
        res.status(500).json({
            error: "Не удалось отправить код на почту. Проверь настройки Mail.ru."
        });
    }
});

// =========================
// VERIFY
// =========================

app.post("/api/verify", (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const code = String(req.body.code || "").trim();

        const verification = db.prepare(`
            SELECT * FROM verification_codes
            WHERE email = ?
            ORDER BY id DESC LIMIT 1
        `).get(email);

        if (!verification) {
            return res.status(400).json({ error: "Код не найден" });
        }

        if (Date.now() > verification.expires_at) {
            return res.status(400).json({ error: "Код истёк" });
        }

        if (verification.code !== code) {
            return res.status(400).json({ error: "Неверный код" });
        }

        db.prepare("UPDATE users SET verified = 1 WHERE email = ?").run(email);
        db.prepare("DELETE FROM verification_codes WHERE email = ?").run(email);

        const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);

        if (!user) {
            return res.status(404).json({ error: "Пользователь не найден" });
        }

        res.json({
            success: true,
            token: createToken(user.id)
        });
    } catch (error) {
        console.error("VERIFY ERROR:", error);
        res.status(500).json({ error: "Ошибка подтверждения" });
    }
});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

        if (!user) {
            return res.status(400).json({ error: "Пользователь не найден" });
        }

        const valid = await bcrypt.compare(password, user.password);

        if (!valid) {
            return res.status(400).json({ error: "Неверный пароль" });
        }

        if (!user.verified) {
            return res.status(403).json({ error: "Подтвердите почту" });
        }

        res.json({
            success: true,
            token: createToken(user.id)
        });
    } catch (error) {
        console.error("LOGIN ERROR:", error);
        res.status(500).json({ error: "Ошибка входа" });
    }
});

// =========================
// ME / PROFILE
// =========================

app.get("/api/me", auth, (req, res) => {
    const user = getUser(req.userId);

    if (!user) {
        return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.json(user);
});

app.put("/api/me", auth, (req, res) => {
    const name = req.body.name !== undefined
        ? String(req.body.name).trim()
        : null;

    const about = req.body.about !== undefined
        ? String(req.body.about)
        : null;

    let username = null;

    if (req.body.username !== undefined) {
        username = cleanUsername(req.body.username);

        if (!isValidUsername(username)) {
            return res.status(400).json({
                error: "Username: 3-24 символа, латинские буквы, цифры или _"
            });
        }

        const exists = db.prepare(`
            SELECT id FROM users
            WHERE username = ? AND id != ?
        `).get(username, req.userId);

        if (exists) {
            return res.status(400).json({ error: "Такой username уже занят" });
        }
    }

    if (name !== null && !name) {
        return res.status(400).json({ error: "Имя не может быть пустым" });
    }

    const current = getUser(req.userId);
    username = username === null ? current.username : username;

    db.prepare(`
        UPDATE users
        SET name = COALESCE(?, name),
            username = ?,
            about = COALESCE(?, about)
        WHERE id = ?
    `).run(name, username, about, req.userId);

    res.json({
        success: true,
        user: getUser(req.userId)
    });
});

// =========================
// USERS
// =========================

app.get("/api/users", auth, (req, res) => {
    const q = String(req.query.q || "").trim().toLowerCase();

    let users;

    if (q) {
        const search = `%${q.replace(/^@/, "")}%`;

        users = db.prepare(`
            SELECT id, name, username, avatar, about
            FROM users
            WHERE id != ? AND verified = 1
              AND (
                  LOWER(name) LIKE ?
                  OR LOWER(username) LIKE ?
                  OR LOWER(email) LIKE ?
              )
            ORDER BY name COLLATE NOCASE
            LIMIT 50
        `).all(req.userId, search, search, search);
    } else {
        users = db.prepare(`
            SELECT id, name, username, avatar, about
            FROM users
            WHERE id != ? AND verified = 1
            ORDER BY name COLLATE NOCASE
            LIMIT 50
        `).all(req.userId);
    }

    res.json(users);
});

app.get("/api/users/@:username", auth, (req, res) => {
    const username = cleanUsername(req.params.username);

    if (!isValidUsername(username)) {
        return res.status(400).json({ error: "Неверный username" });
    }

    const user = db.prepare(`
        SELECT id, name, username, avatar, about
        FROM users
        WHERE username = ? AND verified = 1
    `).get(username);

    if (!user) {
        return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.json(user);
});

// =========================
// MESSAGES
// =========================

app.get("/api/messages/:userId", auth, (req, res) => {
    const otherUserId = Number(req.params.userId);

    if (!Number.isInteger(otherUserId) || otherUserId <= 0) {
        return res.status(400).json({ error: "Неверный пользователь" });
    }

    const messages = db.prepare(`
        SELECT id, sender_id, receiver_id, text,
               type, file_url, file_name, mime_type, created_at
        FROM messages
        WHERE
            (sender_id = ? AND receiver_id = ?)
            OR
            (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    `).all(
        req.userId,
        otherUserId,
        otherUserId,
        req.userId
    );

    res.json(messages);
});

// =========================
// FILE UPLOAD: IMAGE / VIDEO
// =========================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },

    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName =
            `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`;

        cb(null, safeName);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 50 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        if (
            file.mimetype.startsWith("image/") ||
            file.mimetype.startsWith("video/")
        ) {
            return cb(null, true);
        }

        cb(new Error("Можно отправлять только изображения и видео"));
    }
});

app.post("/api/upload", auth, upload.single("file"), (req, res) => {
    try {
        const receiverId = Number(req.body.receiverId);

        if (!receiverId) {
            if (req.file) fs.unlink(req.file.path, () => {});
            return res.status(400).json({ error: "Не указан получатель" });
        }

        const receiver = db.prepare(`
            SELECT id FROM users
            WHERE id = ? AND verified = 1
        `).get(receiverId);

        if (!receiver) {
            if (req.file) fs.unlink(req.file.path, () => {});
            return res.status(404).json({ error: "Получатель не найден" });
        }

        if (!req.file) {
            return res.status(400).json({ error: "Файл не выбран" });
        }

        const type = req.file.mimetype.startsWith("image/")
            ? "image"
            : "video";

        const fileUrl = `/uploads/${req.file.filename}`;
        const createdAt = Date.now();

        const result = db.prepare(`
            INSERT INTO messages
            (
                sender_id, receiver_id, text,
                type, file_url, file_name, mime_type, created_at
            )
            VALUES (?, ?, '', ?, ?, ?, ?, ?)
        `).run(
            req.userId,
            receiverId,
            type,
            fileUrl,
            req.file.originalname,
            req.file.mimetype,
            createdAt
        );

        const message = {
            id: Number(result.lastInsertRowid),
            sender_id: req.userId,
            receiver_id: receiverId,
            text: "",
            type,
            file_url: fileUrl,
            file_name: req.file.originalname,
            mime_type: req.file.mimetype,
            created_at: createdAt
        };

        sendToUser(req.userId, {
            type: "message",
            message
        });

        sendToUser(receiverId, {
            type: "message",
            message
        });

        res.json({
            success: true,
            message
        });
    } catch (error) {
        console.error("UPLOAD ERROR:", error);

        if (req.file) fs.unlink(req.file.path, () => {});

        res.status(400).json({
            error: error.message || "Ошибка загрузки файла"
        });
    }
});

// =========================
// SETTINGS
// =========================

app.get("/api/settings", auth, (req, res) => {
    const user = db.prepare(`
        SELECT notifications, sounds, privacy, language
        FROM users WHERE id = ?
    `).get(req.userId);

    if (!user) {
        return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.json(user);
});

app.put("/api/settings", auth, (req, res) => {
    const current = getUser(req.userId);

    let notifications =
        req.body.notifications === undefined
            ? current.notifications
            : (req.body.notifications ? 1 : 0);

    let sounds =
        req.body.sounds === undefined
            ? current.sounds
            : (req.body.sounds ? 1 : 0);

    let privacy =
        req.body.privacy === undefined
            ? current.privacy
            : String(req.body.privacy);

    let language =
        req.body.language === undefined
            ? current.language
            : String(req.body.language);

    if (!["everyone", "contacts", "nobody"].includes(privacy)) {
        privacy = "everyone";
    }

    if (!["ru", "en"].includes(language)) {
        language = "ru";
    }

    db.prepare(`
        UPDATE users
        SET notifications = ?,
            sounds = ?,
            privacy = ?,
            language = ?
        WHERE id = ?
    `).run(
        notifications,
        sounds,
        privacy,
        language,
        req.userId
    );

    res.json({
        success: true,
        settings: {
            notifications: Boolean(notifications),
            sounds: Boolean(sounds),
            privacy,
            language
        }
    });
});

// =========================
// WEBSOCKET
// =========================

const clients = new Map();

function sendToUser(userId, data) {
    const socket = clients.get(Number(userId));

    if (
        socket &&
        socket.readyState === WebSocket.OPEN
    ) {
        socket.send(JSON.stringify(data));
    }
}

wss.on("connection", (socket, req) => {
    let userId = null;

    try {
        const url = new URL(
            req.url,
            `http://${req.headers.host}`
        );

        const token = url.searchParams.get("token");

        if (!token) {
            socket.close();
            return;
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        userId = Number(decoded.userId);

        if (!userId || !getUser(userId)) {
            socket.close();
            return;
        }

        const oldSocket = clients.get(userId);

        if (oldSocket && oldSocket !== socket) {
            try {
                oldSocket.close();
            } catch {}
        }

        clients.set(userId, socket);

        console.log(`WebSocket connected: ${userId}`);

        socket.send(JSON.stringify({
            type: "connected"
        }));

        socket.on("message", raw => {
            try {
                const data = JSON.parse(raw.toString());

                if (data.type !== "message") return;

                const receiverId = Number(data.receiverId);
                const text = String(data.text || "").trim();

                if (!receiverId || !text) return;
                if (receiverId === userId) return;

                const receiver = db.prepare(`
                    SELECT id FROM users
                    WHERE id = ? AND verified = 1
                `).get(receiverId);

                if (!receiver) return;

                const createdAt = Date.now();

                const result = db.prepare(`
                    INSERT INTO messages
                    (
                        sender_id, receiver_id, text,
                        type, file_url, file_name, mime_type, created_at
                    )
                    VALUES (?, ?, ?, 'text', '', '', '', ?)
                `).run(
                    userId,
                    receiverId,
                    text,
                    createdAt
                );

                const message = {
                    id: Number(result.lastInsertRowid),
                    sender_id: userId,
                    receiver_id: receiverId,
                    text,
                    type: "text",
                    file_url: "",
                    file_name: "",
                    mime_type: "",
                    created_at: createdAt
                };

                sendToUser(userId, {
                    type: "message",
                    message
                });

                sendToUser(receiverId, {
                    type: "message",
                    message
                });

            } catch (error) {
                console.error("WebSocket message error:", error);
            }
        });

        socket.on("close", () => {
            if (clients.get(userId) === socket) {
                clients.delete(userId);
            }

            console.log(`WebSocket disconnected: ${userId}`);
        });

    } catch (error) {
        console.error("WebSocket connection error:", error.message);

        try {
            socket.close();
        } catch {}
    }
});

// =========================
// MULTER / GENERAL ERRORS
// =========================

app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({
                error: "Файл слишком большой. Максимум 50 МБ."
            });
        }

        return res.status(400).json({
            error: error.message
        });
    }

    if (error) {
        return res.status(400).json({
            error: error.message
        });
    }

    next();
});

app.use("/api", (req, res) => {
    res.status(404).json({
        error: "API endpoint not found"
    });
});

// =========================
// START
// =========================

server.listen(PORT, "0.0.0.0", async () => {
    console.log("================================");
    console.log("          SVIPE SERVER");
    console.log("================================");
    console.log(`Svipe server started on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || "development"}`);

    try {
        await mailer.verify();
        console.log("SMTP OK: Mail.ru");
    } catch (error) {
        console.error("SMTP ERROR:", error.message);
    }
});
'''
path = "/mnt/data/server.js"
with open(path, "w", encoding="utf-8") as f:
    f.write(server_code)
print(path)
