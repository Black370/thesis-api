require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { GoogleGenAI } = require('@google/genai');

const app = express();

// --- 1. ENTERPRISE CORS CONFIGURATION ---
const isProduction = process.env.NODE_ENV === 'production' || Boolean(process.env.RENDER);
const isLocalOrigin = (origin) =>
    typeof origin === 'string' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);

const extraOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

const allowedOrigins = [
    'https://thesis-portal-ochre.vercel.app',
    ...extraOrigins
];

const getCookieConfig = (req) => {
    const useLocalCookies = !isProduction && isLocalOrigin(req.headers.origin);
    return useLocalCookies
        ? { httpOnly: true, secure: false, sameSite: 'lax' }
        : { httpOnly: true, secure: true, sameSite: 'none' };
};

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin) || (!isProduction && isLocalOrigin(origin))) {
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
const dbUrl = process.env.DATABASE_URL || '';
const useSsl = !/(localhost|127\.0\.0\.1|sslmode=disable)/i.test(dbUrl);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ...(useSsl ? { ssl: { rejectUnauthorized: false } } : {})
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

        const cookieConfig = getCookieConfig(req);
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
            ...getCookieConfig(req), maxAge: 15 * 60 * 1000
        });

        res.sendStatus(200);
    });
});

// --- 7. LOGOUT ROUTE ---
app.post('/api/logout', (req, res) => {
    const cookieConfig = getCookieConfig(req);
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
            users: users.rows.map(u => ({ username: u.username, role: u.role, name: u.name, id: u.official_id || u.id || "Error: Missing ID" })),
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

// --- 12. AI ASSISTANT (@google/genai) ---
const GEMINI_MODELS = process.env.GEMINI_MODEL
    ? [process.env.GEMINI_MODEL]
    : ['gemini-3.5-flash-lite', 'gemini-3.1-flash-lite', 'gemini-3.8-flash'];
const aiClient = process.env.GEMINI_API_KEY
    ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
    : null;

const SYSTEM_OVERVIEW = [
    'Welcome to the **Graduation Thesis Portal (Tester Version)**! Here is a quick guide to how everything works:',
    '',
    '### Getting Started (Demo Login)',
    '- Sign in with the tester admin account — **Username:** `admin`, **Password:** `123`.',
    '- From the Admin Dashboard, you can create test **Professor** and **Student** accounts to try out all three roles!',
    '',
    '### For Students',
    '- **Look for Classes to Join:** Browse available classes and click **Request Access**.',
    '- **Pick a Topic for Your Thesis:** Once a professor approves your class request, choose one available thesis topic and click **Register for Topic**.',
    '- **My Thesis Status:** Check whether your topic is Pending, Approved, or Denied, read any feedback from your professor, or withdraw if you need to pick a different topic.',
    '',
    '### For Professors',
    '- **Manage Classes:** Create, rename, or remove your thesis classes.',
    '- **Manage Topics:** Publish thesis topics under your classes, edit them, or archive topics that are no longer offered.',
    '- **Approve Class Access:** Approve, deny, or reset student requests to join your classes.',
    '- **Approve Thesis Choices:** Approve or deny student topic registrations (with a short note explaining why if denied).',
    '',
    '### For Admins',
    '- **Create New Account:** Add accounts for students, professors, or admins.',
    '- **Modify Accounts:** Search for users by name or ID, update their details or password, or remove accounts.',
    '',
    'Feel free to ask how to do anything in the portal!'
].join('\n');

const ASSISTANT_SYSTEM_INSTRUCTION = `You are a warm, friendly support assistant for the Graduation Thesis Portal (Tester Version).
Your job is to guide testers and everyday users (students, professors, and admins) in simple, plain language on how to explore and use each feature in the portal.

Tester version login info:
- This is a tester/demo version of the portal.
- If a user asks how to log in or test the system, share the tester Admin account: Username \`admin\`, Password \`123\`.
- Mention that once signed in as Admin, they can open "Create New Account" to create test Professor and Student accounts and try every dashboard.

What users can do in the portal:
- Signing In & Out:
  - Enter your Username and Password on the Portal Login screen and click Sign In.
  - Click Logout in the top-right bar anytime to sign out safely.
- Student Dashboard:
  - "Look for Classes to Join": Browse available classes with each professor's name and ID, then click Request Access. You will see a Pending, Approved, or Denied status badge on the class card.
  - "Pick a Topic for Your Thesis": After your professor approves you for a class, its available topics appear here. Click Register for Topic to apply. You can only register for one topic at a time (other topics show "Registration Locked" while you already have a registration).
  - "My Thesis Status": Shows your chosen topic, class, status badge (Pending, Approved, or Denied), and any Faculty Feedback if denied. You can click Withdraw Registration (or Acknowledge & Clear Status if denied) to free up your slot and pick another topic. If a professor cancels or archives your topic, you will see an alert with an "Acknowledge & Choose New Topic" button.
- Professor Dashboard:
  - "Create, Edit, or Delete Classes": Enter a class title to create a class, or edit/delete your existing classes. Deleting a class also removes its topics and student registrations.
  - "Create, Edit, or Delete Topics": Select one of your classes, enter a thesis topic title, and click Publish (create at least one class first). You can Edit a topic anytime, or click Archive to retire it so new students cannot pick it and currently registered students are notified to choose a new topic.
  - "Approve or Deny Students to Join Your Class": Review student requests to join your classes. Click Approve or Deny, or use Reset Status to move a decision back to Pending.
  - "Approve or Deny Student Thesis Choices": Review student topic registrations. Click Approve, or enter a short reason and click Deny so the student receives helpful feedback. You can also click Reset to Pending if you need to change a decision.
- Admin Dashboard:
  - "Create New Account": Select a Role (Student, Professor, or Admin), choose a unique Username and Password, and enter Full Name and Official ID Number for students and professors.
  - "Modify Accounts": Browse accounts using Previous and Next buttons, search by Full Name or ID on the current page, click Edit to update someone's role, name, ID, or password (leave New Password blank to keep their current password), or click Delete to remove an account. Note: changing a professor's role to student removes their classes, and you cannot delete the admin account you are currently signed into.

Style and behavior rules:
- Be friendly, clear, and concise — write for non-technical users using short paragraphs, clean headings (###), or bullet points with blank lines between separate main ideas.
- NEVER mention technical or backend details (do not mention cookies, JWT, tokens, APIs, servers, databases, code, components, or HTTP).
- Only explain features that actually exist in the portal. If someone asks about something not available (such as uploading thesis PDFs, emailing professors, or resetting forgotten passwords on their own), politely let them know the portal does not support that yet (for forgotten passwords, suggest asking a system administrator).
- You cannot look up personal account details or click buttons for users — gently guide them to the exact section and button to use.`;

const assistantRateLimit = new Map();
const ASSISTANT_WINDOW_MS = 60 * 1000;
const ASSISTANT_MAX_REQUESTS = 20;

const checkAssistantRateLimit = (ip) => {
    const now = Date.now();
    if (assistantRateLimit.size > 1000) {
        for (const [key, timestamps] of assistantRateLimit.entries()) {
            const recent = timestamps.filter(t => now - t < ASSISTANT_WINDOW_MS);
            if (recent.length === 0) assistantRateLimit.delete(key);
            else assistantRateLimit.set(key, recent);
        }
    }
    const existing = (assistantRateLimit.get(ip) || []).filter(t => now - t < ASSISTANT_WINDOW_MS);
    if (existing.length >= ASSISTANT_MAX_REQUESTS) {
        assistantRateLimit.set(ip, existing);
        return false;
    }
    existing.push(now);
    assistantRateLimit.set(ip, existing);
    return true;
};

app.post('/api/assistant', async (req, res) => {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
    if (!checkAssistantRateLimit(clientIp)) {
        return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
    }

    const rawMessage = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!rawMessage) {
        return res.status(400).json({ error: 'Message cannot be empty.' });
    }
    if (rawMessage.length > 1000) {
        return res.status(400).json({ error: 'Message is too long (max 1000 characters).' });
    }

    if (/^\/?overview[.!?]*$/i.test(rawMessage)) {
        return res.json({ reply: SYSTEM_OVERVIEW });
    }

    if (!aiClient) {
        console.error('AI assistant error: GEMINI_API_KEY is not configured.');
        return res.status(503).json({
            error: 'The assistant is temporarily unavailable right now. You can still type "overview" for a quick guide to the portal.'
        });
    }

    const allowedRoles = ['admin', 'professor', 'student', 'guest'];
    const viewerRole = allowedRoles.includes(req.body?.role) ? req.body.role : 'guest';

    const rawHistory = Array.isArray(req.body?.history) ? req.body.history : [];
    const sanitizedHistory = [];
    for (const item of rawHistory.slice(-10)) {
        if (!item || (item.role !== 'user' && item.role !== 'model') || typeof item.text !== 'string') continue;
        const text = item.text.trim().slice(0, 1000);
        if (!text) continue;
        if (sanitizedHistory.length === 0 && item.role !== 'user') continue;
        if (sanitizedHistory.length > 0 && sanitizedHistory[sanitizedHistory.length - 1].role === item.role) continue;
        sanitizedHistory.push({ role: item.role, parts: [{ text }] });
    }
    if (sanitizedHistory.length > 0 && sanitizedHistory[sanitizedHistory.length - 1].role === 'user') {
        sanitizedHistory.pop();
    }

    try {
        let response = null;
        let lastErr = null;

        for (const model of GEMINI_MODELS) {
            try {
                response = await aiClient.models.generateContent({
                    model,
                    contents: [
                        ...sanitizedHistory,
                        { role: 'user', parts: [{ text: rawMessage }] }
                    ],
                    config: {
                        systemInstruction: `${ASSISTANT_SYSTEM_INSTRUCTION}\n\nCurrent viewer role: ${viewerRole}.`,
                        temperature: 0.4,
                        maxOutputTokens: 600
                    }
                });
                break;
            } catch (err) {
                lastErr = err;
                const retryable = err.status === 503 || err.status === 429 || err.status === 404;
                console.error(`AI assistant error (${model}):`, err.message);
                if (!retryable) throw err;
            }
        }

        if (!response) throw lastErr;

        const reply = (response.text || '').trim() || 'Sorry, I could not generate a response right now. Please try again.';
        res.json({ reply });
    } catch (err) {
        const status = err.status === 429 ? 429 : (err.status === 503 ? 503 : 502);
        const msg = err.status === 429
            ? 'The assistant is a bit busy right now. Please wait a few seconds and try again.'
            : err.status === 503
                ? 'The assistant is temporarily busy. Please try again in a few seconds.'
                : 'Sorry, I am having trouble answering right now. Please try again in a moment.';
        res.status(status).json({ error: msg });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, (err) => {
    if (err) {
        console.error(`Failed to start server on port ${port}:`, err.message);
        process.exit(1);
    }
    console.log(`Server running on port ${port}`);
});