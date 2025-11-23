// @ts-nocheck
// server.js - EnviroTrack Complete System with Auto Municipal User
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

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ========== GPS VALIDATION ==========
function validateAndParseGPS(latString, lngString) {
    const lat = parseFloat(latString);
    const lng = parseFloat(lngString);
    
    if (isNaN(lat) || isNaN(lng)) {
        return { 
            valid: false, 
            error: 'GPS coordinates must be valid numbers. Received: lat=' + latString + ', lng=' + lngString 
        };
    }
    
    if (lat < -90 || lat > 90) {
        return { 
            valid: false, 
            error: 'Latitude must be between -90 and 90. Got: ' + lat 
        };
    }
    
    if (lng < -180 || lng > 180) {
        return { 
            valid: false, 
            error: 'Longitude must be between -180 and 180. Got: ' + lng 
        };
    }
    
    return { 
        valid: true, 
        latitude: lat, 
        longitude: lng 
    };
}

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp'
    };
    return mimeTypes[ext] || 'image/jpeg';
}

// ========== AI FUNCTIONS ==========
async function analyzeImageForWaste(filePath) {
    console.log('🔍 Starting AI analysis for:', filePath);
    const startTime = Date.now();
    
    try {
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 100,
                topP: 0.9,
            }
        });

        const imageData = fs.readFileSync(filePath);
        const base64Image = imageData.toString('base64');
        
        const imagePart = {
            inlineData: {
                data: base64Image,
                mimeType: getMimeType(filePath)
            },
        };

        const prompt = 'Look at this image carefully. Does it contain any visible waste, garbage, trash, litter, pollution, or debris? Answer with ONLY one word: "Yes" or "No".';

        const result = await model.generateContent([prompt, imagePart]);
        const response = await result.response;
        const text = response.text().trim();
        
        const elapsed = Date.now() - startTime;
        const normalizedText = text.toLowerCase();
        
        const isWaste = normalizedText.includes('yes') || 
                       normalizedText.startsWith('yes') ||
                       (normalizedText.includes('waste') && !normalizedText.includes('no'));
        
        console.log('🤖 AI Result: "' + text + '" - Waste: ' + (isWaste ? 'YES' : 'NO') + ' (' + elapsed + 'ms)');
        
        return {
            isWaste: isWaste,
            text: text,
            confidence: isWaste ? 'high' : 'low',
            elapsed: elapsed
        };

    } catch (error) {
        console.error('❌ AI Error:', error.message);
        return {
            isWaste: true,
            text: 'AI unavailable - manual review required',
            confidence: 'unknown',
            elapsed: Date.now() - startTime
        };
    }
}

async function verifyCleanup(beforeImagePath, afterImagePath) {
    console.log('🔍 Starting cleanup verification...');
    const startTime = Date.now();
    
    try {
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash-exp",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 250,
            }
        });

        const beforeData = fs.readFileSync(beforeImagePath);
        const afterData = fs.readFileSync(afterImagePath);
        
        const beforeImage = {
            inlineData: {
                data: beforeData.toString('base64'),
                mimeType: getMimeType(beforeImagePath)
            }
        };
        
        const afterImage = {
            inlineData: {
                data: afterData.toString('base64'),
                mimeType: getMimeType(afterImagePath)
            }
        };

        const prompt = 'Compare these two images. First image shows waste. Second image should show the same location cleaned. Answer: Is waste removed? Are images similar? Format: Cleaned: Yes/No, Similar: Yes/No, Confidence: High/Medium/Low';

        const result = await model.generateContent([prompt, beforeImage, afterImage]);
        const response = await result.response;
        const text = response.text().trim();
        
        const normalizedText = text.toLowerCase();
        const isCleaned = normalizedText.includes('cleaned: yes');
        const similarImages = normalizedText.includes('similar: yes') || normalizedText.includes('similar images: yes');
        const confidence = normalizedText.includes('high') ? 'high' : normalizedText.includes('medium') ? 'medium' : 'low';
        
        console.log('🔍 Verification: Cleaned=' + isCleaned + ', Similar=' + similarImages + ', Confidence=' + confidence);
        
        return {
            verified: isCleaned && similarImages,
            aiResponse: text,
            confidence: confidence,
            similarImages: similarImages,
            elapsed: Date.now() - startTime
        };

    } catch (error) {
        console.error('❌ Verification Error:', error.message);
        return {
            verified: false,
            aiResponse: 'Verification failed: ' + error.message,
            confidence: 'unknown',
            similarImages: false,
            elapsed: Date.now() - startTime
        };
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

// Auto-create tables and dummy municipal user
const initializeDatabase = async () => {
    try {
        // Create tables
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
                cleaned_by_user_id INTEGER REFERENCES users(id),
                cleaned_image_url VARCHAR(500),
                cleaned_at TIMESTAMP,
                points INTEGER DEFAULT 10,
                cleanup_verified BOOLEAN DEFAULT FALSE,
                verification_confidence VARCHAR(20),
                ai_comparison_result TEXT
            );
        `);
        console.log('✅ Tables created/verified');

        // Create dummy municipal user if doesn't exist
        const checkUser = await pool.query("SELECT * FROM users WHERE username = 'municipal'");
        if (checkUser.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('password123', 10);
            await pool.query(
                "INSERT INTO users (username, password_hash, role) VALUES ('municipal', $1, 'municipal')",
                [hashedPassword]
            );
            console.log('✅ Municipal user created - Username: municipal | Password: password123');
        } else {
            console.log('✅ Municipal user already exists');
        }

    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
};

initializeDatabase();

pool.on('connect', () => {
    console.log('✅ Connected to PostgreSQL');
});

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) return cb(null, true);
        cb(new Error('Only images allowed'));
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
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
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, role || 'user']
        );
        res.status(201).json({ message: 'User registered', user: result.rows[0] });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Username exists' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ 
            message: 'Login successful', 
            accessToken: accessToken, 
            role: user.role, 
            username: user.username 
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Report Waste
app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
    const { latitude, longitude, description, reportedBy } = req.body;
    
    if (!req.file) {
        return res.status(400).json({ message: 'Image required' });
    }
    
    const gps = validateAndParseGPS(latitude, longitude);
    if (!gps.valid) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: gps.error });
    }

    try {
        const analysisResult = await analyzeImageForWaste(req.file.path);
        
        if (!analysisResult.isWaste) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                message: 'AI did not detect waste in this image.',
                aiAnalysis: analysisResult
            });
        }

        const imageUrl = '/uploads/' + req.file.filename;
        const result = await pool.query(
            'INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [gps.latitude, gps.longitude, description, imageUrl, reportedBy || 'Anonymous']
        );
        
        console.log('✅ Report saved - ID:', result.rows[0].id);
        
        res.status(201).json({ 
            message: 'Waste report submitted successfully!', 
            report: result.rows[0],
            aiAnalysis: analysisResult
        });
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('❌ Report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Reports
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
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Report not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Clean Report (DELETES after verification)
app.put('/api/clean-report/:id', authenticateToken, upload.single('cleanedImage'), async (req, res) => {
    if (req.user.role !== 'municipal') {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ message: 'Municipal users only' });
    }
    
    if (!req.file) {
        return res.status(400).json({ message: 'Cleaned image required' });
    }

    try {
        const reportQuery = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
        
        if (reportQuery.rows.length === 0) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Report not found' });
        }
        
        const originalReport = reportQuery.rows[0];
        const beforeImagePath = path.join(__dirname, originalReport.image_url);
        const afterImagePath = req.file.path;
        
        const verification = await verifyCleanup(beforeImagePath, afterImagePath);
        
        // DELETE the report
        const result = await pool.query(
            'DELETE FROM waste_reports WHERE id = $1 RETURNING *',
            [req.params.id]
        );
        
        console.log('✅ Report deleted - ID:', req.params.id);
        
        res.json({ 
            message: 'Report cleaned and removed successfully!',
            report: result.rows[0],
            verification: verification
        });
        
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('❌ Cleanup error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Leaderboard
app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT reported_by, SUM(points) AS total_points, COUNT(*) AS total_reports FROM waste_reports WHERE reported_by IS NOT NULL AND reported_by != '' AND reported_by != 'Anonymous' GROUP BY reported_by ORDER BY total_points DESC LIMIT 10"
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Statistics
app.get('/api/statistics', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT COUNT(*) as total_reports, COUNT(CASE WHEN is_cleaned = TRUE THEN 1 END) as cleaned_reports, COUNT(CASE WHEN is_cleaned = FALSE THEN 1 END) as pending_reports, SUM(points) as total_points, COUNT(DISTINCT reported_by) as unique_reporters FROM waste_reports'
        );
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
        res.json({ 
            status: 'healthy', 
            database: 'connected',
            gemini: process.env.GEMINI_API_KEY ? 'configured' : 'missing',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ status: 'unhealthy', error: error.message });
    }
});

// Municipal Endpoints
app.get('/api/municipal/pending', authenticateToken, async (req, res) => {
    if (req.user.role !== 'municipal') {
        return res.status(403).json({ message: 'Access denied' });
    }
    try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/municipal/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'municipal') {
        return res.status(403).json({ message: 'Access denied' });
    }
    try {
        const stats = await pool.query(
            "SELECT COUNT(*) as total_cleaned FROM waste_reports WHERE is_cleaned = TRUE"
        );
        res.json(stats.rows[0]);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.use((error, req, res, next) => {
    console.error('Error:', error);
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large (10MB max)' });
        }
        return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: error.message || 'Server error' });
});

app.listen(PORT, () => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🚀 ENVIROTRACK SERVER STARTED');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🌐 Server: http://localhost:' + PORT);
    console.log('👤 Municipal Login: municipal / password123');
    console.log('✅ GPS Validation: Active');
    console.log('🤖 AI Model: gemini-2.0-flash');
    console.log('🔑 Gemini API: ' + (process.env.GEMINI_API_KEY ? 'Configured ✅' : 'Missing ❌'));
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
