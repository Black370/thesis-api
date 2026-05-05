require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-thesis-key-2026';

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 1. SECURE LOGIN ROUTE
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username=$1 AND password=$2', [username, password]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = result.rows[0];
        const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        // Don't send password back to frontend
        res.json({ token, user: { username: user.username, role: user.role, name: user.name, id: user.official_id } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. SAFE DATA FETCH (No passwords exposed)
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const users = await pool.query('SELECT username, role, name, official_id FROM users');
        const classes = await pool.query('SELECT * FROM classes');
        const topics = await pool.query('SELECT * FROM topics');
        const access = await pool.query('SELECT * FROM class_access');
        const registrations = await pool.query('SELECT * FROM registrations');

        res.json({
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

// --- ADMIN ROUTES ---
app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { username, password, role, name, id } = req.body;
    await pool.query('INSERT INTO users (username, password, role, name, official_id) VALUES ($1, $2, $3, $4, $5)', [username, password, role, name, id]);
    res.sendStatus(201);
});

app.put('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { password, role, name, id } = req.body;
    const targetUser = req.params.username;

    // Fix: Role-Change Data Orphan (If Professor becomes Student, delete their classes)
    const oldUser = await pool.query('SELECT role FROM users WHERE username=$1', [targetUser]);
    if (oldUser.rows.length > 0 && oldUser.rows[0].role === 'professor' && role === 'student') {
        await pool.query('DELETE FROM classes WHERE professor=$1', [targetUser]);
    }

    // Fix: Admin Plaintext Password (Only update if new password provided)
    if (password) {
        await pool.query('UPDATE users SET password=$1, role=$2, name=$3, official_id=$4 WHERE username=$5', [password, role, name, id, targetUser]);
    } else {
        await pool.query('UPDATE users SET role=$1, name=$2, official_id=$3 WHERE username=$4', [role, name, id, targetUser]);
    }
    res.sendStatus(200);
});

app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    await pool.query('DELETE FROM users WHERE username=$1', [req.params.username]);
    res.sendStatus(200);
});

// --- PROFESSOR ROUTES ---
app.post('/api/classes', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    await pool.query('INSERT INTO classes (id, title, professor) VALUES ($1, $2, $3)', [req.body.id, req.body.title, req.user.username]);
    res.sendStatus(201);
});

app.put('/api/classes/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    await pool.query('UPDATE classes SET title=$1 WHERE id=$2 AND professor=$3', [req.body.title, req.params.id, req.user.username]);
    res.sendStatus(200);
});

app.delete('/api/classes/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    await pool.query('DELETE FROM classes WHERE id=$1 AND professor=$2', [req.params.id, req.user.username]);
    res.sendStatus(200);
});

app.post('/api/topics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    await pool.query('INSERT INTO topics (id, class_id, title) VALUES ($1, $2, $3)', [req.body.id, req.body.classId, req.body.title]);
    res.sendStatus(201);
});

app.put('/api/topics/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    await pool.query('UPDATE topics SET class_id=$1, title=$2 WHERE id=$3', [req.body.classId, req.body.title, req.params.id]);
    res.sendStatus(200);
});

app.delete('/api/topics/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.sendStatus(403);
    // Fix: Soft Delete (Archive instead of drop so students see the alert)
    await pool.query('UPDATE topics SET is_archived = TRUE WHERE id=$1', [req.params.id]);
    res.sendStatus(200);
});

// --- ACCESS & REGISTRATIONS ---
app.post('/api/access', authenticateToken, async (req, res) => {
    // Fix: Ghost Student Trap (Ensure student exists before acting)
    const studentCheck = await pool.query('SELECT username FROM users WHERE username=$1', [req.body.student]);
    if (studentCheck.rows.length === 0) return res.status(404).json({ error: "Student account no longer exists." });

    await pool.query('INSERT INTO class_access (student, class_id, status) VALUES ($1, $2, $3) ON CONFLICT (student, class_id) DO UPDATE SET status = EXCLUDED.status',
        [req.body.student, req.body.classId, req.body.status]);
    res.sendStatus(200);
});

app.post('/api/registrations', authenticateToken, async (req, res) => {
    // API Security: Students can only register themselves. Profs can update anyone's status.
    if (req.user.role === 'student' && req.body.student !== req.user.username) return res.sendStatus(403);

    await pool.query('INSERT INTO registrations (student, topic_id, status, reason) VALUES ($1, $2, $3, $4) ON CONFLICT (student) DO UPDATE SET topic_id = EXCLUDED.topic_id, status = EXCLUDED.status, reason = EXCLUDED.reason',
        [req.body.student, req.body.topicId, req.body.status, req.body.reason]);
    res.sendStatus(200);
});

app.delete('/api/registrations/:student', authenticateToken, async (req, res) => {
    if (req.user.role === 'student' && req.params.student !== req.user.username) return res.sendStatus(403);
    await pool.query('DELETE FROM registrations WHERE student=$1', [req.params.student]);
    res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));