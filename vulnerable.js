const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const bodyParser = require('body-parser');
app.use(bodyParser.json());

/**
 * 🚨 Vulnerability 1: Command Injection
 * - Uses `exec()` to run shell commands with user input.
 * - Attackers can execute arbitrary system commands.
 */
app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    exec(`ping -c 3 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${stderr}`);
        } else {
            res.send(stdout);
        }
    });
});

/**
 * 🚨 Vulnerability 2: Local File Inclusion (LFI)
 * - Uses `fs.readFileSync()` with user input.
 * - Attackers can read arbitrary files (e.g., `/etc/passwd`).
 */
app.get('/readfile', (req, res) => {
    const filename = req.query.filename;
    try {
        const data = fs.readFileSync(filename, 'utf8'); // ⚠️ UNSAFE: No input validation
        res.send(data);
    } catch (error) {
        res.status(500).send('Error reading file');
    }
});

/**
 * 🚨 Vulnerability 3: Insecure Deserialization
 * - Uses `JSON.parse()` directly on user input.
 * - Attackers can craft malicious JSON input leading to unexpected behavior.
 */
app.post('/deserialize', (req, res) => {
    try {
        const userInput = req.body.data;
        const parsedData = JSON.parse(userInput); // ⚠️ UNSAFE: No validation or sanitization
        res.json({ message: "Data processed", data: parsedData });
    } catch (error) {
        res.status(400).send('Invalid JSON format');
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
