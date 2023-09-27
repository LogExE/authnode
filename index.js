'use strict';

const express = require('express');

const PORT = 3000

const app = express();
app.get('/', (req, res) => {
    res.send("Hello, from docker!");
});

app.listen(PORT, () => {
    console.log(`Сервис запущен на порту ${PORT}`);
});