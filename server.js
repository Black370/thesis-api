require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const app = express();

// --- 1. ENTERPRISE CORS CONFIGURATION ---
const allowedOrigins = [
    'http://localhost:5173',
    'https://black370.github.io'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS. Access strictly limited to official portal.'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true // MANDATORY: Allows HttpOnly cookies
}));

app.use(express.json());
app.use(cookieParser());

// --- 2. DATABASE CONNECTION ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- 3. CRYPTOGRAPHIC KEYS ---
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-thesis-key-2026';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'super-secret-refresh-key-2026';

// --- 4. SECURE AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- 5. SECURE LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = result.rows[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const accessToken = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ username: user.username, role: user.role }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        const cookieConfig = { httpOnly: true, secure: true, sameSite: 'none' };
        res.cookie('access_token', accessToken, { ...cookieConfig, maxAge: 15 * 60 * 1000 });
        res.cookie('refresh_token', refreshToken, { ...cookieConfig, maxAge: 7 * 24 * 60 * 60 * 1000 });

        // Note: Change 'official_id' to 'id' here if your Neon DB uses 'id' as the column name
        res.json({ user: { username: user.username, role: user.role, name: user.name, id: user.official_id } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 6. SILENT REFRESH ROUTE ---
app.post('/api/refresh', (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) return res.sendStatus(401);

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        const newAccessToken = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '15m' });

        res.cookie('access_token', newAccessToken, {
            httpOnly: true, secure: true, sameSite: 'none', maxAge: 15 * 60 * 1000
        });

        res.sendStatus(200);
    });
});

// --- 7. LOGOUT ROUTE ---
app.post('/api/logout', (req, res) => {
    const cookieConfig = { httpOnly: true, secure: true, sameSite: 'none' };
    res.clearCookie('access_token', cookieConfig);
    res.clearCookie('refresh_token', cookieConfig);
    res.sendStatus(200);
});

// --- 8. DATA FETCHING ---
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const users = await pool.query('SELECT username, role, name, official_id FROM users');
        const classes = await pool.query('SELECT * FROM classes');
        const topics = await pool.query('SELECT * FROM topics');
        const access = await pool.query('SELECT * FROM class_access');
        const registrations = await pool.query('SELECT * FROM registrations');

        res.json({
            // Note: Change 'official_id' to 'id' here if your Neon DB uses 'id' as the column name
            users: users.rows.map(u => ({ username: u.username, role: u.role, name: u.name, id: u.official_id })),
            classes: classes.rows,
            topics: topics.rows.map(t => ({ id: t.id, classId: t.class_id, title: t.title, isArchived: t.is_archived })),
            classAccess: access.rows.map(a => ({ student: a.student, classId: a.class_id, status: a.status })),
            registrations: registrations.rows.map(r => ({ student: r.student, topicId: r.topic_id, status: r.status, reason: r.reason }))
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PAGINATION ROUTE WITH ID MAPPING FIX
app.get('/api/users/paginated', authenticateToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;

    try {
        const countResult = await pool.query('SELECT COUNT(*) FROM users');
        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        const result = await pool.query(
            // Note: Change 'official_id' to 'id' here if your Neon DB uses 'id' as the column name
            'SELECT username, role, name, official_id FROM users ORDER BY username LIMIT $1 OFFSET $2',
            [limit, offset]
        );

        res.json({
            users: result.rows.map(u => ({
                username: u.username,
                role: u.role,
                name: u.name,
                id: u.official_id // <-- Translates DB column so React can read it
            })),
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 9. ADMIN ROUTES ---
app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { username, password, role, name, id } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, role, name, official_id) VALUES ($1, $2, $3, $4, $5)', [username, hashedPassword, role, name, id]);
        res.sendStatus(201);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { password, role, name, id } = req.body;
    const targetUser = req.params.username;
    try {
        const oldUser = await pool.query('SELECT role FROM users WHERE username=$1', [targetUser]);
        if (oldUser.rows.length > 0 && oldUser.rows[0].role === 'professor' && role === 'student') {
            await pool.query('DELETE FROM classes WHERE professor=$1', [targetUser]);
        }
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query('UPDATE users SET password=$1, role=$2, name=$3, official_id=$4 WHERE username=$5', [hashedPassword, role, name, id, targetUser]);
        } else {
            await pool.query('UPDATE users SET role=$1, name=$2, official_id=$3 WHERE username=$4', [role, name, id, targetUser]);
        }
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    try {
        await pool.query('DELETE FROM users WHERE username=$1', [req.params.username]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- 10. PROFESSOR ROUTES ---
app.post('/api/classes', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('INSERT INTO classes (id, title, professor) VALUES ($1, $2, $3)', [req.body.id, req.body.title, req.user.username]);
        res.sendStatus(201);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/classes/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('UPDATE classes SET title=$1 WHERE id=$2 AND professor=$3', [req.body.title, req.params.id, req.user.username]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/classes/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('DELETE FROM classes WHERE id=$1 AND professor=$2', [req.params.id, req.user.username]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/topics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('INSERT INTO topics (id, class_id, title) VALUES ($1, $2, $3)', [req.body.id, req.body.classId, req.body.title]);
        res.sendStatus(201);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/topics/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('UPDATE topics SET class_id=$1, title=$2 WHERE id=$3', [req.body.classId, req.body.title, req.params.id]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/topics/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    try {
        await pool.query('UPDATE topics SET is_archived = TRUE WHERE id=$1', [req.params.id]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- 11. ACCESS & REGISTRATIONS ---
app.post('/api/access', authenticateToken, async (req, res) => {
    try {
        const studentCheck = await pool.query('SELECT username FROM users WHERE username=$1', [req.body.student]);
        if (studentCheck.rows.length === 0) return res.status(404).json({ error: "Student account no longer exists." });
        await pool.query('INSERT INTO class_access (student, class_id, status) VALUES ($1, $2, $3) ON CONFLICT (student, class_id) DO UPDATE SET status = EXCLUDED.status', [req.body.student, req.body.classId, req.body.status]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/registrations', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'student' && req.body.student !== req.user.username) return res.sendStatus(403);
        await pool.query('INSERT INTO registrations (student, topic_id, status, reason) VALUES ($1, $2, $3, $4) ON CONFLICT (student) DO UPDATE SET topic_id = EXCLUDED.topic_id, status = EXCLUDED.status, reason = EXCLUDED.reason', [req.body.student, req.body.topicId, req.body.status, req.body.reason]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/registrations/:student', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'student' && req.params.student !== req.user.username) return res.sendStatus(403);
        await pool.query('DELETE FROM registrations WHERE student=$1', [req.params.student]);
        res.sendStatus(200);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));