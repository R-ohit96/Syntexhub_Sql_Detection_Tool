const express = require('express');
const app = express();
const PORT = 4000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Allow JSON payloads from scanner

app.get('/', (req, res) => {
    res.send(`
        <h1>Login Page</h1>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    `);
});

app.post('/login', (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';
    
    // VULNERABLE LOGIC: Simulating a SQL error if a quote is present
    if (username.includes("'") || password.includes("'")) {
        return res.status(500).send("SQL syntax error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1");
    }

    if (username === 'admin' && password === 'password') {
        res.send("Welcome Admin!");
    } else {
        res.send("Login Failed");
    }
});

app.listen(PORT, () => {
    console.log(`Vulnerable test server running on http://localhost:${PORT}`);
});
