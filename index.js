'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');

const PORT = 3000
const ACCESS_TOK_NAME = "Access-Token";
const REFRESH_TOK_NAME = "Refresh-Token";

if (!('ACCESS_TOK_SECRET' in process.env)) {
    console.error("ACCESS_TOK_SECRET не указан!");
    process.exit(1);
}
const ACCESS_TOK_SECRET = process.env.ACCESS_TOK_SECRET;

if (!('REFRESH_TOK_SECRET' in process.env)) {
    console.error("REFRESH_TOK_SECRET не указан!");
    process.exit(1);
}
const REFRESH_TOK_SECRET = process.env.REFRESH_TOK_SECRET;

const db = new sqlite3.Database('data.db');
db.run("CREATE TABLE IF NOT EXISTS users (login, password, salt)");

const app = express();
app.use(express.urlencoded());
app.use(cookieParser());

function hashxshalt(password, salt) {
    return crypto.createHash("sha256")
        .update(password)
        .update(crypto.createHash("sha256").update(salt, "utf8").digest("hex"))
        .digest("hex");
}

app.post('/registrate', (req, res) => {
    db.get("SELECT login, password FROM users WHERE login = ?", [req.body.usr], (err, row) => {
        if (err)
            throw err;
        if (row) { // Уже есть такой пользователь
            res.sendStatus(400);
            return;
        }
        // Запись пользователя в БД
        const salt = crypto.randomBytes(16).toString('hex');
        const hashed = hashxshalt(req.body.pwd, salt);
        db.run("INSERT INTO users (login, password, salt) VALUES (?, ?, ?)", [req.body.usr, hashed, salt]);
        res.sendStatus(201);
    });
});
app.post('/auth', (req, res) => {
    db.get("SELECT login, password, salt FROM users WHERE login = ?", [req.body.usr], (err, row) => {
        if (err)
            throw err;
        if (!row) { // Пользователя с таким логином нет
            res.sendStatus(400);
            return;
        }
        // Проверка пароля
        const hashed = hashxshalt(req.body.pwd, row.salt);
        if (row.password != hashed) {
            res.sendStatus(403);
            return;
        }
        const payload = { login: row.login };
        res.cookie(ACCESS_TOK_NAME, jwt.sign(payload, ACCESS_TOK_SECRET, { expiresIn: "1h" }), { httpOnly: true });
        res.cookie(REFRESH_TOK_NAME, jwt.sign(payload, REFRESH_TOK_SECRET, { expiresIn: "1m" }), { path: "/refresh", httpOnly: true });
        res.sendStatus(200);
    });
});
app.post('/refresh', (req, res) => {
    if (!(REFRESH_TOK_NAME in req.cookies)) {
        res.sendStatus(400);
        return;
    }
    jwt.verify(req.cookies[REFRESH_TOK_NAME], REFRESH_TOK_SECRET, (err, payload) => {
        if (err) {
            res.sendStatus(403);
            return;
        }
        const new_payload = { login: payload.login };
        res.cookie(ACCESS_TOK_NAME, jwt.sign(new_payload, ACCESS_TOK_SECRET, { expiresIn: "1h" }), { httpOnly: true });
        res.cookie(REFRESH_TOK_NAME, jwt.sign(new_payload, REFRESH_TOK_SECRET, { expiresIn: "1m" }), { path: "/refresh", httpOnly: true });
        res.sendStatus(200);
    });
});

app.get('/', (req, res) => {
    console.log(req.cookies);
    res.send("Welcome to auth service!");
});

app.listen(PORT, () => {
    console.log(`Сервис запущен на порту ${PORT}`);
});

const cleanup = () => {
    db.close();
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);