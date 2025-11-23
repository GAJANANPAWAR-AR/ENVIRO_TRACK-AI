// server.js - EnviroTrack Production Ready
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const PORT = process.env.PORT || 3000;
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ========== UTILITIES ==========
function validateGPS(latString, lngString) {
    const lat = parseFloat(latString);
    const lng = parseFloat(lngString);
    
    if (isNaN(lat) || isNaN(lng)) return { valid: false, error: 'Invalid GPS coordinates' };
    if (lat < -90 || lat > 90) return { valid: false, error: 'Latitude out of range' };
    if (lng < -180 || lng > 180) return { valid: false, error: 'Longitude out of range' };
    
    return { valid: true, latitude: lat, longitude: lng };
}

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const types = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp' };
    return types[ext] || 'image/jpeg';
}

// ========== AI FUNCTIONS ==========
async function analyzeWaste(filePath) {
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash", generationConfig: { temperature: 0.3, maxOutputTokens: 100 }});
        const imageData = fs.readFileSync(filePath);
        const imagePart = { inlineData: { data: imageData.toString('base64'), mimeType: getMimeType(filePath) }};
        const result = await model.generateContent(['Does this image contain visible waste, garbage, trash, or litter? Answer only "Yes" or "No".', imagePart]);
        const text = result.response.text().trim().toLowerCase();
        return { isWaste: text.includes('yes'), text: text };
    } catch (error) {
        console.error('AI Error:', error.message);
        return { isWaste: true, text: 'AI unavailable' };
    }
}

async function verifyCleanup(beforePath, afterPath) {
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash-exp", generationConfig: { temperature: 0.3, maxOutputTokens: 200 }});
        const before = { inlineData: { data: fs.readFileSync(beforePath).toString('base64'), mimeType: getMimeType(beforePath) }};
        const after = { inlineData: { data: fs.readFileSync(afterPath).toString('base64'), mimeType: getMimeType(afterPath) }};
        const result = await model.generateContent(['Compare images. First has waste. Second should show same location cleaned. Is waste removed? Are they similar? Answer: Cleaned: Yes/No, Similar: Yes/No', before, after]);
        const text = result.response.text().toLowerCase();
        return { verified: text.includes('cleaned: yes') && text.includes('similar: yes'), text: text };
    } catch (error) {
        console.error('Verification Error:', error.message);
        return { verified: false, text: 'Verification failed' };
    }
}

// ========== DATABASE ==========
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS waste_reports (
                id SERIAL PRIMARY KEY,
                latitude DECIMAL(10, 8) NOT NULL,
                longitude DECIMAL(11, 8) NOT NULL,
                description TEXT,
                image_url VARCHAR(500) NOT NULL,
                reported_by VARCHAR(255),
                reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_cleaned BOOLEAN DEFAULT FALSE,
                cleaned_at TIMESTAMP,
                cleaned_image_url VARCHAR(500),
                points INTEGER DEFAULT 10
            );
        `);
        console.log('✅ Database initialized');
    } catch (error) {
        console.error('❌ DB Error:', error.message);
    }
}

initDB();

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const upload = multer({ 
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, 'uploads/'),
        filename: (req, file, cb) => cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
    }),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|gif|webp/;
        if (allowed.test(path.extname(file.originalname).toLowerCase()) && allowed.test(file.mimetype)) {
            return cb(null, true);
        }
        cb(new Error('Only images allowed'));
    }
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ========== API ENDPOINTS ==========

// Register
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hash, role || 'user']
        );
        res.status(201).json({ message: 'User registered', user: result.rows[0] });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ message: 'Username exists' });
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
        
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ message: 'Invalid credentials' });
        
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Login successful', accessToken: token, role: user.role, username: user.username });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Report Waste
app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
    const { latitude, longitude, description, reportedBy } = req.body;
    
    if (!req.file) return res.status(400).json({ message: 'Image required' });
    
    const gps = validateGPS(latitude, longitude);
    if (!gps.valid) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: gps.error });
    }

    try {
        const analysis = await analyzeWaste(req.file.path);
        
        if (!analysis.isWaste) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'No waste detected in image' });
        }

        const imageUrl = '/uploads/' + req.file.filename;
        const result = await pool.query(
            'INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [gps.latitude, gps.longitude, description, imageUrl, reportedBy || 'Anonymous']
        );
        
        res.status(201).json({ message: 'Report submitted!', report: result.rows[0] });
    } catch (error) {
        if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        console.error('Report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Active Reports
app.get('/api/waste-reports', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Single Report
app.get('/api/waste-reports/:id', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Report not found' });
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Mark as Cleaned (NO AUTH REQUIRED - Open for municipal workers)
app.put('/api/clean-report/:id', upload.single('cleanedImage'), async (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'Cleaned image required' });

    try {
        const report = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
        if (report.rows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Report not found' });
        }
        
        const beforePath = path.join(__dirname, report.rows[0].image_url);
        const afterPath = req.file.path;
        
        const verification = await verifyCleanup(beforePath, afterPath);
        const cleanedUrl = '/uploads/' + req.file.filename;
        
        // Mark as cleaned (don't delete - keep for leaderboard)
        await pool.query(
            'UPDATE waste_reports SET is_cleaned = TRUE, cleaned_at = CURRENT_TIMESTAMP, cleaned_image_url = $1 WHERE id = $2',
            [cleanedUrl, req.params.id]
        );
        
        res.json({ message: 'Report marked as cleaned!', verification: verification });
    } catch (error) {
        if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        console.error('Cleanup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Leaderboard (Fixed - counts all reports by reporter)
app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                reported_by, 
                SUM(points) as total_points, 
                COUNT(*) as total_reports 
            FROM waste_reports 
            WHERE reported_by IS NOT NULL 
                AND reported_by != '' 
                AND reported_by != 'Anonymous'
            GROUP BY reported_by 
            ORDER BY total_points DESC 
            LIMIT 10
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Statistics
app.get('/api/statistics', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                COUNT(*) as total_reports,
                COUNT(CASE WHEN is_cleaned = TRUE THEN 1 END) as cleaned_reports,
                COUNT(CASE WHEN is_cleaned = FALSE THEN 1 END) as pending_reports,
                COALESCE(SUM(points), 0) as total_points,
                COUNT(DISTINCT reported_by) as unique_reporters
            FROM waste_reports
        `);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Health Check
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'healthy', database: 'connected', timestamp: new Date().toISOString() });
    } catch (error) {
        res.status(500).json({ status: 'unhealthy', error: error.message });
    }
});

// Error Handler
app.use((error, req, res, next) => {
    console.error('Error:', error);
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ message: 'File too large (10MB max)' });
        return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: error.message || 'Server error' });
});

app.listen(PORT, () => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🚀 ENVIROTRACK PRODUCTION SERVER');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🌐 Server: http://localhost:' + PORT);
    console.log('🔓 Municipal: NO AUTH (Open cleanup access)');
    console.log('📊 Leaderboard: Fixed - counts all user reports');
    console.log('✅ Reports: Marked as cleaned (not deleted)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
