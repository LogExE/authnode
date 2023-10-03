'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');

const PORT = 3000
const ACCESS_TOK_COOKIE = "Access-Token";
const REFRESH_TOK_COOKIE = "Refresh-Token";

let env_vars = {}
for (let env_var of ['ACCESS_TOK_SECRET', 'REFRESH_TOK_SECRET']) {
    if (!(env_var in process.env)) {
        console.error(`Переменная окружающей среды ${env_var} не задана! Без нее сервис не запустится.`);
        process.exit(1);
    }
    env_vars[env_var] = process.env[env_var];
}
const { ACCESS_TOK_SECRET, REFRESH_TOK_SECRET } = env_vars;

const db = new sqlite3.Database('data.db');
db.run("CREATE TABLE IF NOT EXISTS users (login, password, salt)");

const app = express();
app.use(express.urlencoded()); // для доступа к элементам формы через req.body
app.use(cookieParser()); // для доступа к печенькам через req.cookies

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

function gen_tokens(payload) {
    return [
        jwt.sign(payload, ACCESS_TOK_SECRET, { expiresIn: "5m" }), { httpOnly: true },
        jwt.sign(payload, REFRESH_TOK_SECRET, { expiresIn: "1h" }), { path: "/refresh", httpOnly: true }
    ];
}
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
        [access_tok, refresh_tok] = gen_tokens(payload);
        res.cookie(ACCESS_TOK_COOKIE, access_tok);
        res.cookie(REFRESH_TOK_COOKIE, refresh_tok);
        res.sendStatus(200);
    });
});
app.post('/refresh', (req, res) => {
    if (!(REFRESH_TOK_COOKIE in req.cookies)) {
        res.sendStatus(400);
        return;
    }
    jwt.verify(req.cookies[REFRESH_TOK_COOKIE], REFRESH_TOK_SECRET, (err, payload) => {
        if (err) {
            res.sendStatus(403);
            return;
        }
        const new_payload = { login: payload.login };
        [access_tok, refresh_tok] = gen_tokens(new_payload);
        res.cookie(ACCESS_TOK_COOKIE, access_tok);
        res.cookie(REFRESH_TOK_COOKIE, refresh_tok);
        res.sendStatus(200);
    });
});

app.get('/', (req, res) => {
    console.log(req.cookies);
    let msg = "root";
    if (ACCESS_TOK_COOKIE in req.cookies) {
        try {
            const payload = jwt.verify(req.cookies[ACCESS_TOK_COOKIE], ACCESS_TOK_SECRET);
            msg = `root (${payload.login})`;
        } catch (err) {
            msg = `root, access token error: \"${err.message}\"`;
        }
    }
    res.send(msg);
});

app.listen(PORT, () => {
    console.log(`Сервис запущен на порту ${PORT}`);
});

function cleanup() {
    console.log("Завершаем работу...");
    db.close();
    process.exit(0);
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);