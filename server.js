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
const nodemailer = require("nodemailer");
const multer = require("multer");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// =========================
// CONFIG
// =========================

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET || "svipe-secret-key-change-me";

// =========================
// MAIL
// =========================

const mailer = nodemailer.createTransport({
    host: "smtp.mail.ru",
    port: 587,
    secure: false,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD
    }
});

// Проверяем SMTP при запуске
mailer.verify()
    .then(() => {
        console.log("Mail server: OK");
    })
    .catch((error) => {
        console.error("Mail server error:", error.message);
    });

// =========================
// EXPRESS
// =========================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(__dirname, "public");
const uploadsDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, {
        recursive: true
    });
}

app.use(express.static(publicDir));

app.use(
    "/uploads",
    express.static(uploadsDir)
);

// =========================
// DATABASE
// =========================

const db = new Database("svipe.db");

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
    created_at INTEGER NOT NULL
);
`);

// =========================
// DATABASE MIGRATIONS
// =========================

function columnExists(table, column) {
    const columns = db
        .prepare(`PRAGMA table_info(${table})`)
        .all();

    return columns.some(
        columnInfo => columnInfo.name === column
    );
}

function addColumnIfMissing(
    table,
    column,
    definition
) {
    if (!columnExists(table, column)) {
        db.exec(
            `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
        );
    }
}

// Messages
addColumnIfMissing(
    "messages",
    "type",
    "TEXT NOT NULL DEFAULT 'text'"
);

addColumnIfMissing(
    "messages",
    "file_url",
    "TEXT DEFAULT ''"
);

addColumnIfMissing(
    "messages",
    "file_name",
    "TEXT DEFAULT ''"
);

addColumnIfMissing(
    "messages",
    "mime_type",
    "TEXT DEFAULT ''"
);

// Users
addColumnIfMissing(
    "users",
    "username",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "notifications",
    "INTEGER DEFAULT 1"
);

addColumnIfMissing(
    "users",
    "sounds",
    "INTEGER DEFAULT 1"
);

addColumnIfMissing(
    "users",
    "privacy",
    "TEXT DEFAULT 'everyone'"
);

addColumnIfMissing(
    "users",
    "language",
    "TEXT DEFAULT 'ru'"
);

// =========================
// USERNAME
// =========================

function cleanUsername(value) {
    return String(value || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();
}

function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,24}$/.test(username);
}

function makeUsernameFromName(name) {
    let username = String(name || "")
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "");

    if (username.length < 3) {
        username = "user";
    }

    username = username.substring(0, 20);

    const base = username;
    let number = 1;

    while (
        db
            .prepare(
                "SELECT id FROM users WHERE username = ?"
            )
            .get(username)
    ) {
        username = `${base}${number}`;
        number++;
    }

    return username;
}

// Создаём username старым пользователям
const oldUsers = db
    .prepare(`
        SELECT id, name
        FROM users
        WHERE username IS NULL
        OR username = ''
    `)
    .all();

for (const user of oldUsers) {
    const username = makeUsernameFromName(
        user.name
    );

    db.prepare(`
        UPDATE users
        SET username = ?
        WHERE id = ?
    `).run(
        username,
        user.id
    );
}

// Уникальность username
try {
    db.exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_username
        ON users(username)
    `);
} catch (error) {
    console.log(
        "Username index:",
        error.message
    );
}

// =========================
// AUTH
// =========================

function getUser(id) {
    return db.prepare(`
        SELECT
            id,
            name,
            username,
            email,
            verified,
            avatar,
            about,
            notifications,
            sounds,
            privacy,
            language,
            created_at
        FROM users
        WHERE id = ?
    `).get(id);
}

function createToken(userId) {
    return jwt.sign(
        {
            userId
        },
        JWT_SECRET,
        {
            expiresIn: "30d"
        }
    );
}

function auth(req, res, next) {
    try {
        const header =
            req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Нет токена"
            });
        }

        const token = header.slice(7);

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.userId = Number(
            decoded.userId
        );

        next();

    } catch (error) {
        return res.status(401).json({
            error: "Недействительный токен"
        });
    }
}

// =========================
// ROOT
// =========================

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            publicDir,
            "index.html"
        )
    );
});

// =========================
// API STATUS
// =========================

app.get("/api", (req, res) => {
    res.json({
        success: true,
        message: "Svipe server is running"
    });
});

// =========================
// REGISTER
// =========================

app.post(
    "/api/register",
    async (req, res) => {

        try {
            const name = String(
                req.body.name || ""
            ).trim();

            const email = String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

            const password = String(
                req.body.password || ""
            );

            if (!name || !email || !password) {
                return res.status(400).json({
                    error: "Заполни все поля"
                });
            }

            if (password.length < 6) {
                return res.status(400).json({
                    error:
                        "Пароль должен быть минимум 6 символов"
                });
            }

            // Проверяем существующего пользователя
            const exists = db.prepare(`
                SELECT id, verified
                FROM users
                WHERE email = ?
            `).get(email);

            if (exists) {

                // Аккаунт уже подтверждён
                if (exists.verified) {
                    return res.status(400).json({
                        error:
                            "Пользователь с такой почтой уже существует"
                    });
                }

                // Старую незавершённую регистрацию удаляем
                db.prepare(`
                    DELETE FROM verification_codes
                    WHERE email = ?
                `).run(email);

                db.prepare(`
                    DELETE FROM users
                    WHERE id = ?
                `).run(exists.id);
            }

            const hash = await bcrypt.hash(
                password,
                10
            );

            const username =
                makeUsernameFromName(name);

            const code = String(
                Math.floor(
                    100000 +
                    Math.random() * 900000
                )
            );

            const expiresAt =
                Date.now() + 10 * 60 * 1000;

            // Сначала отправляем письмо
            await mailer.sendMail({
                from: process.env.MAIL_USER,
                to: email,
                subject: "Код подтверждения Svipe",

                text:
                    `Ваш код подтверждения Svipe: ${code}\n\n` +
                    `Код действует 10 минут.`
            });

            console.log(
                `Verification code sent to ${email}`
            );

            // После успешной отправки создаём пользователя
            db.prepare(`
                INSERT INTO users
                (
                    name,
                    email,
                    password,
                    verified,
                    username,
                    created_at
                )
                VALUES (?, ?, ?, 0, ?, ?)
            `).run(
                name,
                email,
                hash,
                username,
                Date.now()
            );

            // Удаляем старый код
            db.prepare(`
                DELETE FROM verification_codes
                WHERE email = ?
            `).run(email);

            // Сохраняем новый код
            db.prepare(`
                INSERT INTO verification_codes
                (
                    email,
                    code,
                    expires_at
                )
                VALUES (?, ?, ?)
            `).run(
                email,
                code,
                expiresAt
            );

            return res.json({
                success: true,
                message: "Код отправлен на почту",
                email
            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "Не удалось отправить код на почту. Проверь настройки почты."
            });
        }
    }
);

// =========================
// VERIFY
// =========================

app.post(
    "/api/verify",
    (req, res) => {

        try {
            const email = String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

            const code = String(
                req.body.code || ""
            ).trim();

            if (!email || !code) {
                return res.status(400).json({
                    error:
                        "Введите почту и код"
                });
            }

            const verification =
                db.prepare(`
                    SELECT *
                    FROM verification_codes
                    WHERE email = ?
                    ORDER BY id DESC
                    LIMIT 1
                `).get(email);

            if (!verification) {
                return res.status(400).json({
                    error:
                        "Код не найден"
                });
            }

            if (
                Date.now() >
                verification.expires_at
            ) {
                return res.status(400).json({
                    error:
                        "Код истёк"
                });
            }

            if (
                verification.code !== code
            ) {
                return res.status(400).json({
                    error:
                        "Неверный код"
                });
            }

            db.prepare(`
                UPDATE users
                SET verified = 1
                WHERE email = ?
            `).run(email);

            db.prepare(`
                DELETE FROM verification_codes
                WHERE email = ?
            `).run(email);

            const user = db
                .prepare(`
                    SELECT id
                    FROM users
                    WHERE email = ?
                `)
                .get(email);

            if (!user) {
                return res.status(404).json({
                    error:
                        "Пользователь не найден"
                });
            }

            const token =
                createToken(user.id);

            return res.json({
                success: true,
                token
            });

        } catch (error) {

            console.error(
                "VERIFY ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "Ошибка подтверждения"
            });
        }
    }
);

// =========================
// LOGIN
// =========================

app.post(
    "/api/login",
    async (req, res) => {

        try {
            const email = String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

            const password = String(
                req.body.password || ""
            );

            if (!email || !password) {
                return res.status(400).json({
                    error:
                        "Заполни все поля"
                });
            }

            const user = db
                .prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                `)
                .get(email);

            if (!user) {
                return res.status(400).json({
                    error:
                        "Пользователь не найден"
                });
            }

            const valid =
                await bcrypt.compare(
                    password,
                    user.password
                );

            if (!valid) {
                return res.status(400).json({
                    error:
                        "Неверный пароль"
                });
            }

            if (!user.verified) {
                return res.status(403).json({
                    error:
                        "Подтвердите почту"
                });
            }

            const token =
                createToken(user.id);

            return res.json({
                success: true,
                token
            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "Ошибка входа"
            });
        }
    }
);

// =========================
// ME
// =========================

app.get(
    "/api/me",
    auth,
    (req, res) => {

        const user =
            getUser(req.userId);

        if (!user) {
            return res.status(404).json({
                error:
                    "Пользователь не найден"
            });
        }

        res.json(user);
    }
);

// =========================
// USERS
// =========================

app.get(
    "/api/users",
    auth,
    (req, res) => {

        const users = db.prepare(`
            SELECT
                id,
                name,
                username,
                avatar,
                about
            FROM users
            WHERE id != ?
            AND verified = 1
            ORDER BY name COLLATE NOCASE
        `).all(req.userId);

        res.json(users);
    }
);

app.get(
    "/api/users/@:username",
    auth,
    (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );

        if (!isValidUsername(username)) {
            return res.status(400).json({
                error:
                    "Неверный username"
            });
        }

        const user = db.prepare(`
            SELECT
                id,
                name,
                username,
                avatar,
                about
            FROM users
            WHERE username = ?
            AND verified = 1
        `).get(username);

        if (!user) {
            return res.status(404).json({
                error:
                    "Пользователь не найден"
            });
        }

        res.json(user);
    }
);

// =========================
// MESSAGES
// =========================

app.get(
    "/api/messages/:userId",
    auth,
    (req, res) => {

        const otherUserId =
            Number(req.params.userId);

        if (!otherUserId) {
            return res.status(400).json({
                error:
                    "Неверный пользователь"
            });
        }

        const messages = db.prepare(`
            SELECT
                id,
                sender_id,
                receiver_id,
                text,
                type,
                file_url,
                file_name,
                mime_type,
                created_at
            FROM messages
            WHERE
                (
                    sender_id = ?
                    AND receiver_id = ?
                )
                OR
                (
                    sender_id = ?
                    AND receiver_id = ?
                )
            ORDER BY created_at ASC
        `).all(
            req.userId,
            otherUserId,
            otherUserId,
            req.userId
        );

        res.json(messages);
    }
);

// =========================
// FILE UPLOAD
// =========================

const storage =
    multer.diskStorage({

        destination: (
            req,
            file,
            cb
        ) => {
            cb(
                null,
                uploadsDir
            );
        },

        filename: (
            req,
            file,
            cb
        ) => {

            const ext =
                path.extname(
                    file.originalname
                ).toLowerCase();

            const filename =
                `${Date.now()}-${crypto
                    .randomBytes(8)
                    .toString("hex")}${ext}`;

            cb(
                null,
                filename
            );
        }
    });

const upload = multer({

    storage,

    limits: {
        fileSize:
            50 * 1024 * 1024
    },

    fileFilter: (
        req,
        file,
        cb
    ) => {

        if (
            file.mimetype.startsWith(
                "image/"
            ) ||
            file.mimetype.startsWith(
                "video/"
            )
        ) {
            cb(
                null,
                true
            );
        } else {
            cb(
                new Error(
                    "Можно отправлять только изображения и видео"
                )
            );
        }
    }
});

app.post(
    "/api/upload",
    auth,
    upload.single("file"),
    (req, res) => {

        try {

            const receiverId =
                Number(
                    req.body.receiverId
                );

            if (!receiverId) {

                if (req.file) {
                    fs.unlink(
                        req.file.path,
                        () => {}
                    );
                }

                return res.status(400).json({
                    error:
                        "Не указан получатель"
                });
            }

            const receiver =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE id = ?
                    AND verified = 1
                `).get(receiverId);

            if (!receiver) {

                if (req.file) {
                    fs.unlink(
                        req.file.path,
                        () => {}
                    );
                }

                return res.status(404).json({
                    error:
                        "Получатель не найден"
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    error:
                        "Файл не выбран"
                });
            }

            const type =
                req.file.mimetype.startsWith(
                    "image/"
                )
                    ? "image"
                    : "video";

            const fileUrl =
                `/uploads/${req.file.filename}`;

            const createdAt =
                Date.now();

            const result =
                db.prepare(`
                    INSERT INTO messages
                    (
                        sender_id,
                        receiver_id,
                        text,
                        type,
                        file_url,
                        file_name,
                        mime_type,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `).run(
                    req.userId,
                    receiverId,
                    "",
                    type,
                    fileUrl,
                    req.file.originalname,
                    req.file.mimetype,
                    createdAt
                );

            const message = {
                id:
                    result.lastInsertRowid,

                sender_id:
                    req.userId,

                receiver_id:
                    receiverId,

                text: "",

                type,

                file_url:
                    fileUrl,

                file_name:
                    req.file.originalname,

                mime_type:
                    req.file.mimetype,

                created_at:
                    createdAt
            };

            sendToUser(
                req.userId,
                {
                    type: "message",
                    message
                }
            );

            sendToUser(
                receiverId,
                {
                    type: "message",
                    message
                }
            );

            res.json({
                success: true,
                message
            });

        } catch (error) {

            console.error(
                "UPLOAD ERROR:",
                error
            );

            if (req.file) {
                fs.unlink(
                    req.file.path,
                    () => {}
                );
            }

            res.status(500).json({
                error:
                    error.message ||
                    "Ошибка загрузки файла"
            });
        }
    }
);

// =========================
// SETTINGS
// =========================

app.get(
    "/api/settings",
    auth,
    (req, res) => {

        const user =
            db.prepare(`
                SELECT
                    notifications,
                    sounds,
                    privacy,
                    language
                FROM users
                WHERE id = ?
            `).get(req.userId);

        if (!user) {
            return res.status(404).json({
                error:
                    "Пользователь не найден"
            });
        }

        res.json(user);
    }
);

app.put(
    "/api/settings",
    auth,
    (req, res) => {

        const {
            notifications,
            sounds,
            privacy,
            language
        } = req.body;

        db.prepare(`
            UPDATE users
            SET
                notifications =
                    COALESCE(
                        ?,
                        notifications
                    ),

                sounds =
                    COALESCE(
                        ?,
                        sounds
                    ),

                privacy =
                    COALESCE(
                        ?,
                        privacy
                    ),

                language =
                    COALESCE(
                        ?,
                        language
                    )

            WHERE id = ?
        `).run(
            notifications,
            sounds,
            privacy,
            language,
            req.userId
        );

        res.json({
            success: true
        });
    }
);

// =========================
// UPDATE PROFILE
// =========================

app.put(
    "/api/me",
    auth,
    (req, res) => {

        const name =
            req.body.name !== undefined
                ? String(
                    req.body.name
                ).trim()
                : null;

        const about =
            req.body.about !== undefined
                ? String(
                    req.body.about
                )
                : null;

        if (
            name !== null &&
            !name
        ) {
            return res.status(400).json({
                error:
                    "Имя не может быть пустым"
            });
        }

        db.prepare(`
            UPDATE users
            SET
                name =
                    COALESCE(
                        ?,
                        name
                    ),

                about =
                    COALESCE(
                        ?,
                        about
                    )

            WHERE id = ?
        `).run(
            name,
            about,
            req.userId
        );

        res.json({
            success: true,
            user:
                getUser(req.userId)
        });
    }
);

// =========================
// WEBSOCKET
// =========================

const clients = new Map();

function sendToUser(
    userId,
    data
) {

    const socket =
        clients.get(
            Number(userId)
        );

    if (
        socket &&
        socket.readyState ===
            WebSocket.OPEN
    ) {
        socket.send(
            JSON.stringify(data)
        );
    }
}

wss.on(
    "connection",
    (socket, req) => {

        try {

            const url =
                new URL(
                    req.url,
                    `http://${req.headers.host}`
                );

            const token =
                url.searchParams.get(
                    "token"
                );

            if (!token) {
                socket.close();
                return;
            }

            const decoded =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            const userId =
                Number(
                    decoded.userId
                );

            if (!userId) {
                socket.close();
                return;
            }

            const oldSocket =
                clients.get(userId);

            if (oldSocket) {
                try {
                    oldSocket.close();
                } catch {}
            }

            clients.set(
                userId,
                socket
            );

            socket.send(
                JSON.stringify({
                    type: "connected"
                })
            );

            socket.on(
                "message",
                raw => {

                    try {

                        const data =
                            JSON.parse(raw);

                        if (
                            data.type !==
                            "message"
                        ) {
                            return;
                        }

                        const receiverId =
                            Number(
                                data.receiverId
                            );

                        const text =
                            String(
                                data.text || ""
                            ).trim();

                        if (
                            !receiverId ||
                            !text
                        ) {
                            return;
                        }

                        const receiver =
                            db.prepare(`
                                SELECT id
                                FROM users
                                WHERE id = ?
                                AND verified = 1
                            `).get(
                                receiverId
                            );

                        if (!receiver) {
                            return;
                        }

                        const createdAt =
                            Date.now();

                        const result =
                            db.prepare(`
                                INSERT INTO messages
                                (
                                    sender_id,
                                    receiver_id,
                                    text,
                                    type,
                                    file_url,
                                    file_name,
                                    mime_type,
                                    created_at
                                )
                                VALUES (
                                    ?,
                                    ?,
                                    ?,
                                    'text',
                                    '',
                                    '',
                                    '',
                                    ?
                                )
                            `).run(
                                userId,
                                receiverId,
                                text,
                                createdAt
                            );

                        const message = {
                            id:
                                result.lastInsertRowid,

                            sender_id:
                                userId,

                            receiver_id:
                                receiverId,

                            text,

                            type:
                                "text",

                            file_url:
                                "",

                            file_name:
                                "",

                            mime_type:
                                "",

                            created_at:
                                createdAt
                        };

                        sendToUser(
                            userId,
                            {
                                type:
                                    "message",
                                message
                            }
                        );

                        sendToUser(
                            receiverId,
                            {
                                type:
                                    "message",
                                message
                            }
                        );

                    } catch (error) {

                        console.error(
                            "WebSocket message error:",
                            error
                        );
                    }
                }
            );

            socket.on(
                "close",
                () => {

                    if (
                        clients.get(
                            userId
                        ) === socket
                    ) {
                        clients.delete(
                            userId
                        );
                    }
                }
            );

        } catch (error) {

            console.error(
                "WebSocket connection error:",
                error
            );

            try {
                socket.close();
            } catch {}
        }
    }
);

// =========================
// MULTER ERRORS
// =========================

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        if (
            error instanceof
            multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {
                return res
                    .status(400)
                    .json({
                        error:
                            "Файл слишком большой. Максимум 50 МБ."
                    });
            }

            return res
                .status(400)
                .json({
                    error:
                        error.message
                });
        }

        if (error) {

            return res
                .status(400)
                .json({
                    error:
                        error.message
                });
        }

        next();
    }
);

// =========================
// 404 API
// =========================

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({
            error:
                "API endpoint not found"
        });
    }
);

// =========================
// START
// =========================

server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Svipe server started on port ${PORT}`
        );

        console.log(
            `Environment: ${
                process.env.NODE_ENV ||
                "development"
            }`
        );
    }
);