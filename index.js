'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');

const PORT = 3000

const db = new sqlite3.Database('data.db');
db.run("CREATE TABLE IF NOT EXISTS users (login, password, salt)");

const app = express();
app.use(express.urlencoded());
app.use(cookieParser());

app.get('/', (req, res) => {
    console.log(req.cookies);
    res.send("Welcome to auth service!");
});
app.post('/registrate', (req, res) => {
    db.all("SELECT login, password FROM users WHERE login = ?", [req.body.usr], (err, rows) => {
        if (err)
            throw err;
        if (rows.length != 0)
            res.sendStatus(400);
        else {
            const salt = crypto.randomBytes(16).toString('hex');
            const hashed = crypto.createHash("sha256")
                .update(req.body.pwd)
                .update(crypto.createHash("sha256").update(salt, "utf8").digest("hex"))
                .digest("hex");
            db.run("INSERT INTO users (login, password, salt) VALUES (?, ?, ?)", [req.body.usr, hashed, salt]);
            res.sendStatus(201);
        }
    });
});
app.post('/auth', (req, res) => {

});
app.post('/refresh', (req, res) => {

});

app.listen(PORT, () => {
    console.log(`Сервис запущен на порту ${PORT}`);
});

const cleanup = () => {
    db.close();
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);