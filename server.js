require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for most online Postgres hosts
});

// GET /api/data - Fetches the entire state to mimic the old Firebase object
app.get('/api/data', async (req, res) => {
    try {
        const users = await pool.query('SELECT * FROM users');
        const courses = await pool.query('SELECT * FROM courses');
        const topics = await pool.query('SELECT * FROM topics');
        const access = await pool.query('SELECT * FROM course_access');
        const registrations = await pool.query('SELECT * FROM registrations');

        res.json({
            users: users.rows.map(u => ({ username: u.username, password: u.password, role: u.role, name: u.name, id: u.official_id })),
            courses: courses.rows,
            topics: topics.rows.map(t => ({ id: t.id, courseId: t.course_id, title: t.title })),
            courseAccess: access.rows.map(a => ({ student: a.student, courseId: a.course_id, status: a.status })),
            registrations: registrations.rows.map(r => ({ student: r.student, topicId: r.topic_id, status: r.status, reason: r.reason }))
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN ROUTES ---
app.post('/api/users', async (req, res) => {
    const { username, password, role, name, id } = req.body;
    await pool.query('INSERT INTO users (username, password, role, name, official_id) VALUES ($1, $2, $3, $4, $5)', [username, password, role, name, id]);
    res.sendStatus(201);
});
app.put('/api/users/:username', async (req, res) => {
    const { password, role, name, id } = req.body;
    await pool.query('UPDATE users SET password=$1, role=$2, name=$3, official_id=$4 WHERE username=$5', [password, role, name, id, req.params.username]);
    res.sendStatus(200);
});
app.delete('/api/users/:username', async (req, res) => {
    await pool.query('DELETE FROM users WHERE username=$1', [req.params.username]);
    res.sendStatus(200);
});

// --- PROFESSOR ROUTES ---
app.post('/api/courses', async (req, res) => {
    await pool.query('INSERT INTO courses (id, title, professor) VALUES ($1, $2, $3)', [req.body.id, req.body.title, req.body.professor]);
    res.sendStatus(201);
});
app.delete('/api/courses/:id', async (req, res) => {
    await pool.query('DELETE FROM courses WHERE id=$1', [req.params.id]);
    res.sendStatus(200);
});
app.post('/api/topics', async (req, res) => {
    await pool.query('INSERT INTO topics (id, course_id, title) VALUES ($1, $2, $3)', [req.body.id, req.body.courseId, req.body.title]);
    res.sendStatus(201);
});
app.put('/api/topics/:id', async (req, res) => {
    await pool.query('UPDATE topics SET course_id=$1, title=$2 WHERE id=$3', [req.body.courseId, req.body.title, req.params.id]);
    res.sendStatus(200);
});
app.delete('/api/topics/:id', async (req, res) => {
    await pool.query('DELETE FROM topics WHERE id=$1', [req.params.id]);
    res.sendStatus(200);
});

// --- ACCESS & REGISTRATIONS ---
app.post('/api/access', async (req, res) => {
    await pool.query('INSERT INTO course_access (student, course_id, status) VALUES ($1, $2, $3) ON CONFLICT (student, course_id) DO UPDATE SET status = EXCLUDED.status',
        [req.body.student, req.body.courseId, req.body.status]);
    res.sendStatus(200);
});
app.post('/api/registrations', async (req, res) => {
    await pool.query('INSERT INTO registrations (student, topic_id, status, reason) VALUES ($1, $2, $3, $4) ON CONFLICT (student) DO UPDATE SET topic_id = EXCLUDED.topic_id, status = EXCLUDED.status, reason = EXCLUDED.reason',
        [req.body.student, req.body.topicId, req.body.status, req.body.reason]);
    res.sendStatus(200);
});
app.delete('/api/registrations/:student', async (req, res) => {
    await pool.query('DELETE FROM registrations WHERE student=$1', [req.params.student]);
    res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));