require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'ad_analytics',
    password: 'Pandalogo',
    port: 5432,
});

const app = express();
const PORT = process.env.PORT || 5432;

// Middleware
app.use(cors());
app.use(express.json()); // parse JSON bodies

pool.connect()
    .then(() => console.log('PostgreSQL connected'))
    .catch(err => console.error('PostgreSQL connection error:', err));

// Initialize tables if not exists and hash plain-text passwords
const initDB = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ads (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            type VARCHAR(100),
            impressions INT DEFAULT 0,
            clicks INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    const users = await pool.query('SELECT * FROM users');
    for (const user of users.rows) {
        if (!user.password.startsWith('$2b$')) { // plain-text detected
            const hashed = await bcrypt.hash(user.password, 10);
            await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hashed, user.id]);
            console.log(`Hashed password for user: ${user.username}`);
        }
    }
};
initDB();

// JWT secret
const JWT_SECRET = "supersecretkey";

// Signup
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username & password required' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, role || 'user']
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username & password required' });

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(400).json({ error: 'User not found' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ token, username: user.username, role: user.role });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Auth middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Ads routes
app.post('/api/ads', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

        const { name, type } = req.body;
        if (!name) return res.status(400).json({ error: 'Ad name required' });

        const result = await pool.query(
            'INSERT INTO ads (name, type) VALUES ($1, $2) RETURNING *',
            [name, type]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/ads', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM ads ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/ads/:id/impression', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE ads SET impressions = impressions + 1 WHERE id = $1 RETURNING *',
            [id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/ads/:id/click', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'UPDATE ads SET clicks = clicks + 1 WHERE id = $1 RETURNING *',
            [id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/analytics', async (req, res) => {
    try {
        const { type, sort } = req.query;
        let query = 'SELECT * FROM ads';
        const values = [];

        if (type) {
            values.push(type);
            query += ` WHERE type = $${values.length}`;
        }

        query += ' ORDER BY id ASC';

        const result = await pool.query(query, values);

        let analytics = result.rows.map(ad => ({
            id: ad.id,
            name: ad.name,
            type: ad.type,
            impressions: ad.impressions,
            clicks: ad.clicks,
            CTR: ad.impressions > 0 ? ((ad.clicks / ad.impressions) * 100).toFixed(2) : 0
        }));

        if (sort && ['impressions','clicks','CTR'].includes(sort)) {
            analytics.sort((a, b) => b[sort] - a[sort]);
        }

        res.json(analytics);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Catch-all 404 JSON response
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
