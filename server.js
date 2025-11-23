// @ts-nocheck
// ═══════════════════════════════════════════════════════════════════════════════
// 🌍 ENVIROTRACK - PRODUCTION-READY WASTE MANAGEMENT SYSTEM v2.0
// ═══════════════════════════════════════════════════════════════════════════════
app.set('trust proxy', 1); // Fix X-Forwarded-For error with express-rate-limit
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const sharp = require('sharp');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════════════════════
// 🔒 SECURITY & MIDDLEWARE SETUP
// ═══════════════════════════════════════════════════════════════════════════════

app.use(helmet({
    contentSecurityPolicy: false, // Allow inline scripts for now
    crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true
});

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ═══════════════════════════════════════════════════════════════════════════════
// 📊 DATABASE SETUP WITH CONNECTION POOLING
// ═══════════════════════════════════════════════════════════════════════════════

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: process.env.DB_HOST !== 'localhost' ? { rejectUnauthorized: false } : false,
    max: 20, // Maximum pool size
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Database initialization with enhanced schema
const initializeDatabase = async () => {
    try {
        await pool.query(`
            -- Users table with points tracking
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                total_points INTEGER DEFAULT 0,
                reports_count INTEGER DEFAULT 0,
                cleanups_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Waste reports with enhanced tracking
            CREATE TABLE IF NOT EXISTS waste_reports (
                id SERIAL PRIMARY KEY,
                latitude DECIMAL(10, 8) NOT NULL,
                longitude DECIMAL(11, 8) NOT NULL,
                description TEXT,
                image_url VARCHAR(500) NOT NULL,
                thumbnail_url VARCHAR(500),
                reported_by VARCHAR(255),
                reported_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_cleaned BOOLEAN DEFAULT FALSE,
                cleaned_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                cleaned_image_url VARCHAR(500),
                cleaned_thumbnail_url VARCHAR(500),
                cleaned_at TIMESTAMP,
                base_points INTEGER DEFAULT 10,
                bonus_points INTEGER DEFAULT 0,
                total_points INTEGER DEFAULT 10,
                cleanup_verified BOOLEAN DEFAULT FALSE,
                verification_confidence VARCHAR(20),
                ai_comparison_result TEXT,
                ai_waste_detection_result TEXT,
                severity_level VARCHAR(20) DEFAULT 'medium',
                waste_type VARCHAR(100),
                status VARCHAR(50) DEFAULT 'pending'
            );

            -- Activity logs for audit trail
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                action VARCHAR(100) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Notifications table
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR(50) DEFAULT 'info',
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Create indexes for performance
            CREATE INDEX IF NOT EXISTS idx_waste_reports_status ON waste_reports(status, reported_at DESC);
            CREATE INDEX IF NOT EXISTS idx_waste_reports_location ON waste_reports(latitude, longitude);
            CREATE INDEX IF NOT EXISTS idx_users_points ON users(total_points DESC);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at DESC);
        `);

        console.log('✅ Database tables initialized successfully');

        // Create default municipal user if not exists
        const municipalCheck = await pool.query("SELECT * FROM users WHERE username = 'municipal'");
        if (municipalCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Municipal@123', 10);
            await pool.query(
                'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)',
                ['municipal', hashedPassword, 'municipal']
            );
            console.log('✅ Default municipal user created (Username: municipal, Password: Municipal@123)');
        }

    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
};

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection error:', err.stack);
        process.exit(1);
    }
    client.query('SELECT NOW()', (err, result) => {
        release();
        if (err) {
            console.error('❌ Query error:', err.stack);
            process.exit(1);
        }
        console.log('✅ PostgreSQL connected:', result.rows[0].now);
        initializeDatabase();
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 📁 FILE UPLOAD CONFIGURATION WITH IMAGE OPTIMIZATION
// ═══════════════════════════════════════════════════════════════════════════════

const uploadsDir = path.join(__dirname, 'uploads');
const thumbnailsDir = path.join(__dirname, 'uploads', 'thumbnails');

[uploadsDir, thumbnailsDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) return cb(null, true);
    cb(new Error('Only JPEG, PNG, and WebP images allowed'));
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: fileFilter
});

// Image optimization function
async function optimizeImage(inputPath, outputPath, thumbnail = false) {
    try {
        const size = thumbnail ? 300 : 1200;
        await sharp(inputPath)
            .resize(size, size, { fit: 'inside', withoutEnlargement: true })
            .jpeg({ quality: 85 })
            .toFile(outputPath);
        return true;
    } catch (error) {
        console.error('Image optimization error:', error);
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔐 AUTHENTICATION MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Access denied: insufficient permissions' });
        }
        next();
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// 🤖 AI ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

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

async function analyzeImageForWaste(filePath) {
    console.log('🔍 AI Analysis: Starting waste detection...');
    const startTime = Date.now();

    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 150,
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

        const prompt = `Analyze this image for waste/garbage. Respond in JSON format ONLY:
{
  "hasWaste": true/false,
  "wasteType": "plastic/organic/mixed/electronic/construction/paper/metal/glass/other",
  "severity": "low/medium/high",
  "description": "brief description"
}`;

        const result = await model.generateContent([prompt, imagePart]);
        const response = await result.response;
        const text = response.text().trim();

        // Parse AI response
        let analysis = {
            isWaste: false,
            wasteType: 'mixed',
            severity: 'medium',
            description: 'Analysis unavailable',
            confidence: 'low'
        };

        try {
            // Try to extract JSON from response
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                analysis.isWaste = parsed.hasWaste === true;
                analysis.wasteType = parsed.wasteType || 'mixed';
                analysis.severity = parsed.severity || 'medium';
                analysis.description = parsed.description || text;
                analysis.confidence = analysis.isWaste ? 'high' : 'low';
            }
        } catch (parseError) {
            // Fallback to text analysis
            const normalizedText = text.toLowerCase();
            analysis.isWaste = normalizedText.includes('yes') || 
                              normalizedText.includes('waste') ||
                              normalizedText.includes('garbage') ||
                              normalizedText.includes('trash') ||
                              normalizedText.includes('litter');
            analysis.description = text;
        }

        const elapsed = Date.now() - startTime;
        console.log(`✅ AI Analysis Complete: ${analysis.isWaste ? 'WASTE DETECTED' : 'NO WASTE'} (${elapsed}ms)`);

        return {
            ...analysis,
            rawResponse: text,
            elapsed: elapsed
        };

    } catch (error) {
        console.error('❌ AI Analysis Error:', error.message);
        return {
            isWaste: true, // Allow submission on AI failure
            wasteType: 'mixed',
            severity: 'medium',
            description: 'AI analysis unavailable - manual review required',
            confidence: 'unknown',
            elapsed: Date.now() - startTime
        };
    }
}

async function verifyCleanup(beforeImagePath, afterImagePath) {
    console.log('🔍 AI Verification: Starting cleanup verification...');
    const startTime = Date.now();

    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-2.0-flash-exp",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 200,
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

        const prompt = `Compare these two images:
Image 1: Location with waste/garbage
Image 2: Should be the same location after cleanup

Respond in JSON format ONLY:
{
  "wasteCleaned": true/false,
  "similarLocation": true/false,
  "confidence": "high/medium/low",
  "notes": "brief explanation"
}`;

        const result = await model.generateContent([prompt, beforeImage, afterImage]);
        const response = await result.response;
        const text = response.text().trim();

        // Parse verification response
        let verification = {
            verified: false,
            similarImages: false,
            confidence: 'low',
            aiResponse: text
        };

        try {
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                verification.verified = parsed.wasteCleaned && parsed.similarLocation;
                verification.similarImages = parsed.similarLocation;
                verification.confidence = parsed.confidence || 'low';
                verification.aiResponse = parsed.notes || text;
            }
        } catch (parseError) {
            // Fallback to text analysis
            const normalizedText = text.toLowerCase();
            const isCleaned = normalizedText.includes('cleaned') || 
                             normalizedText.includes('removed') ||
                             normalizedText.includes('waste') && normalizedText.includes('gone');
            const isSimilar = normalizedText.includes('similar') || 
                             normalizedText.includes('same location');
            verification.verified = isCleaned && isSimilar;
            verification.similarImages = isSimilar;
        }

        const elapsed = Date.now() - startTime;
        console.log(`✅ Verification Complete: ${verification.verified ? 'VERIFIED' : 'NOT VERIFIED'} (${elapsed}ms)`);

        return {
            ...verification,
            elapsed: elapsed
        };

    } catch (error) {
        console.error('❌ Verification Error:', error.message);
        return {
            verified: false,
            similarImages: false,
            confidence: 'unknown',
            aiResponse: 'Verification failed: ' + error.message,
            elapsed: Date.now() - startTime
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🎯 UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function validateGPS(latString, lngString) {
    const lat = parseFloat(latString);
    const lng = parseFloat(lngString);

    if (isNaN(lat) || isNaN(lng)) {
        return { valid: false, error: 'Invalid GPS coordinates' };
    }
    if (lat < -90 || lat > 90) {
        return { valid: false, error: 'Latitude must be between -90 and 90' };
    }
    if (lng < -180 || lng > 180) {
        return { valid: false, error: 'Longitude must be between -180 and 180' };
    }

    return { valid: true, latitude: lat, longitude: lng };
}

async function updateUserPoints(userId, points, action) {
    try {
        if (action === 'report') {
            await pool.query(
                'UPDATE users SET total_points = total_points + $1, reports_count = reports_count + 1, last_active = CURRENT_TIMESTAMP WHERE id = $2',
                [points, userId]
            );
        } else if (action === 'cleanup') {
            await pool.query(
                'UPDATE users SET total_points = total_points + $1, cleanups_count = cleanups_count + 1, last_active = CURRENT_TIMESTAMP WHERE id = $2',
                [points, userId]
            );
        }
    } catch (error) {
        console.error('Error updating user points:', error);
    }
}

async function createNotification(userId, title, message, type = 'info') {
    try {
        await pool.query(
            'INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
            [userId, title, message, type]
        );
    } catch (error) {
        console.error('Error creating notification:', error);
    }
}

async function logActivity(userId, action, details, ipAddress) {
    try {
        await pool.query(
            'INSERT INTO activity_logs (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
            [userId, action, details, ipAddress]
        );
    } catch (error) {
        console.error('Error logging activity:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🌐 API ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 👤 AUTHENTICATION ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

app.post('/api/register', authLimiter, async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    if (password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, total_points',
            [username, hashedPassword, role || 'user']
        );

        await logActivity(result.rows[0].id, 'REGISTER', `New user registered: ${username}`, req.ip);

        res.status(201).json({
            message: 'Registration successful',
            user: result.rows[0]
        });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Username already exists' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Update last active
        await pool.query(
            'UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );

        await logActivity(user.id, 'LOGIN', `User logged in: ${username}`, req.ip);

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            accessToken: accessToken,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                totalPoints: user.total_points,
                reportsCount: user.reports_count,
                cleanupsCount: user.cleanups_count
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 📝 WASTE REPORT ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📥 NEW WASTE REPORT');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    const { latitude, longitude, description, reportedBy } = req.body;

    if (!req.file) {
        return res.status(400).json({ message: 'Image required' });
    }

    const gps = validateGPS(latitude, longitude);
    if (!gps.valid) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: gps.error });
    }

    let thumbnailPath = null;
    let reportId = null;

    try {
        // Optimize image and create thumbnail
        const optimizedPath = req.file.path.replace(path.extname(req.file.path), '-optimized.jpg');
        thumbnailPath = path.join(thumbnailsDir, path.basename(req.file.path, path.extname(req.file.path)) + '-thumb.jpg');

        await optimizeImage(req.file.path, optimizedPath, false);
        await optimizeImage(req.file.path, thumbnailPath, true);

        // Delete original, use optimized
        fs.unlinkSync(req.file.path);
        fs.renameSync(optimizedPath, req.file.path);

        // AI Analysis
        const analysis = await analyzeImageForWaste(req.file.path);

        if (!analysis.isWaste) {
            fs.unlinkSync(req.file.path);
            if (fs.existsSync(thumbnailPath)) fs.unlinkSync(thumbnailPath);
            
            return res.status(400).json({
                message: 'No waste detected in this image. Please upload an image clearly showing garbage or litter.',
                aiAnalysis: {
                    result: analysis.description,
                    confidence: analysis.confidence
                }
            });
        }

        // Calculate points based on severity
        let basePoints = 10;
        if (analysis.severity === 'high') basePoints = 15;
        else if (analysis.severity === 'low') basePoints = 5;

        const imageUrl = '/uploads/' + path.basename(req.file.path);
        const thumbnailUrl = '/uploads/thumbnails/' + path.basename(thumbnailPath);

        // Save report to database
        const result = await pool.query(
            `INSERT INTO waste_reports (
                latitude, longitude, description, image_url, thumbnail_url,
                reported_by, base_points, total_points, severity_level,
                waste_type, ai_waste_detection_result, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
            RETURNING *`,
            [
                gps.latitude, gps.longitude, description, imageUrl, thumbnailUrl,
                reportedBy || 'Anonymous', basePoints, basePoints, analysis.severity,
                analysis.wasteType, analysis.description, 'pending'
            ]
        );

        reportId = result.rows[0].id;

        // Award points to user if not anonymous
        if (reportedBy && reportedBy !== 'Anonymous') {
            const userResult = await pool.query(
                'SELECT id FROM users WHERE username = $1',
                [reportedBy]
            );
            if (userResult.rows.length > 0) {
                await updateUserPoints(userResult.rows[0].id, basePoints, 'report');
                await createNotification(
                    userResult.rows[0].id,
                    '🎉 Report Submitted!',
                    `Your waste report earned you ${basePoints} points!`,
                    'success'
                );
            }
        }

        console.log(`✅ Report #${reportId} saved successfully`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        res.status(201).json({
            message: 'Waste report submitted successfully!',
            report: result.rows[0],
            aiAnalysis: {
                wasteType: analysis.wasteType,
                severity: analysis.severity,
                description: analysis.description,
                confidence: analysis.confidence,
                pointsAwarded: basePoints
            }
        });

    } catch (error) {
        // Cleanup on error
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        if (thumbnailPath && fs.existsSync(thumbnailPath)) fs.unlinkSync(thumbnailPath);
        
        console.error('❌ Report submission error:', error);
        res.status(500).json({ message: 'Failed to submit report' });
    }
});

app.get('/api/waste-reports', async (req, res) => {
    const { status, limit, offset } = req.query;

    try {
        let query = 'SELECT * FROM waste_reports';
        const params = [];

        if (status && status !== 'all') {
            query += ' WHERE status = $1';
            params.push(status);
        } else {
            query += ' WHERE status IN ($1, $2)';
            params.push('pending', 'in_progress');
        }

        query += ' ORDER BY reported_at DESC';

        if (limit) {
            query += ` LIMIT $${params.length + 1}`;
            params.push(parseInt(limit));
        }
        if (offset) {
            query += ` OFFSET $${params.length + 1}`;
            params.push(parseInt(offset));
        }

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Fetch reports error:', error);
        res.status(500).json({ message: 'Failed to fetch reports' });
    }
});

app.get('/api/waste-reports/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM waste_reports WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Report not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Fetch report error:', error);
        res.status(500).json({ message: 'Failed to fetch report' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 🧹 CLEANUP ENDPOINTS (MUNICIPAL ONLY)
// ─────────────────────────────────────────────────────────────────────────────

app.put('/api/clean-report/:id', authenticateToken, requireRole('municipal'), upload.single('cleanedImage'), async (req, res) => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🧹 CLEANUP SUBMISSION');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    if (!req.file) {
        return res.status(400).json({ message: 'Cleaned image required' });
    }

    let cleanedThumbnailPath = null;

    try {
        const reportQuery = await pool.query(
            'SELECT * FROM waste_reports WHERE id = $1',
            [req.params.id]
        );

        if (reportQuery.rows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Report not found' });
        }

        const originalReport = reportQuery.rows[0];

        if (originalReport.is_cleaned) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'Report already marked as cleaned' });
        }

        // Optimize cleaned image
        const optimizedPath = req.file.path.replace(path.extname(req.file.path), '-optimized.jpg');
        cleanedThumbnailPath = path.join(thumbnailsDir, path.basename(req.file.path, path.extname(req.file.path)) + '-thumb.jpg');

        await optimizeImage(req.file.path, optimizedPath, false);
        await optimizeImage(req.file.path, cleanedThumbnailPath, true);

        fs.unlinkSync(req.file.path);
        fs.renameSync(optimizedPath, req.file.path);

        // AI Verification
        const beforeImagePath = path.join(__dirname, 'public', originalReport.image_url);
        const afterImagePath = req.file.path;

        const verification = await verifyCleanup(beforeImagePath, afterImagePath);

        // Calculate bonus points
        let bonusPoints = 0;
        if (verification.verified) {
            if (verification.confidence === 'high') bonusPoints = 20;
            else if (verification.confidence === 'medium') bonusPoints = 15;
            else bonusPoints = 10;
        }

        const totalPoints = originalReport.base_points + bonusPoints;
        const cleanedImageUrl = '/uploads/' + path.basename(req.file.path);
        const cleanedThumbnailUrl = '/uploads/thumbnails/' + path.basename(cleanedThumbnailPath);

        // Update report
        const updateResult = await pool.query(
            `UPDATE waste_reports SET 
                is_cleaned = TRUE,
                cleaned_by_user_id = $1,
                cleaned_image_url = $2,
                cleaned_thumbnail_url = $3,
                cleaned_at = CURRENT_TIMESTAMP,
                cleanup_verified = $4,
                verification_confidence = $5,
                ai_comparison_result = $6,
                bonus_points = $7,
                total_points = $8,
                status = $9
            WHERE id = $10 RETURNING *`,
            [
                req.user.id, cleanedImageUrl, cleanedThumbnailUrl,
                verification.verified, verification.confidence,
                verification.aiResponse, bonusPoints, totalPoints,
                verification.verified ? 'completed' : 'needs_review',
                req.params.id
            ]
        );

        // Award points to municipal user
        await updateUserPoints(req.user.id, totalPoints, 'cleanup');

        // Notify reporter if not anonymous
        if (originalReport.reported_by_user_id) {
            await createNotification(
                originalReport.reported_by_user_id,
                '✅ Cleanup Verified!',
                `Your reported waste has been cleaned. +${totalPoints} points awarded!`,
                'success'
            );
        }

        await logActivity(req.user.id, 'CLEANUP', `Cleaned report #${req.params.id}`, req.ip);

        console.log(`✅ Cleanup verified for report #${req.params.id}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        res.json({
            message: verification.verified ? 
                'Cleanup verified successfully!' : 
                'Cleanup submitted - pending manual review',
            report: updateResult.rows[0],
            verification: {
                verified: verification.verified,
                confidence: verification.confidence,
                similarImages: verification.similarImages,
                pointsAwarded: totalPoints,
                breakdown: {
                    basePoints: originalReport.base_points,
                    bonusPoints: bonusPoints
                }
            }
        });

    } catch (error) {
        // Cleanup on error
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        if (cleanedThumbnailPath && fs.existsSync(cleanedThumbnailPath)) fs.unlinkSync(cleanedThumbnailPath);

        console.error('❌ Cleanup submission error:', error);
        res.status(500).json({ message: 'Failed to submit cleanup' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 🏆 LEADERBOARD & STATISTICS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/leaderboard', async (req, res) => {
    const { limit = 10, period = 'all' } = req.query;

    try {
        let dateFilter = '';
        if (period === 'week') {
            dateFilter = "AND created_at >= NOW() - INTERVAL '7 days'";
        } else if (period === 'month') {
            dateFilter = "AND created_at >= NOW() - INTERVAL '30 days'";
        }

        const result = await pool.query(`
            SELECT 
                username,
                total_points,
                reports_count,
                cleanups_count,
                created_at
            FROM users
            WHERE role = 'user' ${dateFilter}
            ORDER BY total_points DESC, reports_count DESC
            LIMIT $1
        `, [parseInt(limit)]);

        res.json(result.rows);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ message: 'Failed to fetch leaderboard' });
    }
});

app.get('/api/statistics', async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT 
                COUNT(*) as total_reports,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_reports,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reports,
                COUNT(CASE WHEN cleanup_verified = TRUE THEN 1 END) as verified_cleanups,
                SUM(total_points) as total_points_awarded,
                COUNT(DISTINCT reported_by) as unique_reporters,
                COUNT(DISTINCT cleaned_by_user_id) as unique_cleaners,
                AVG(total_points) as avg_points_per_report
            FROM waste_reports
        `);

        const userStats = await pool.query(`
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN role = 'municipal' THEN 1 END) as municipal_users,
                SUM(total_points) as total_user_points
            FROM users
        `);

        res.json({
            reports: stats.rows[0],
            users: userStats.rows[0]
        });
    } catch (error) {
        console.error('Statistics error:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 🏛️ MUNICIPAL-SPECIFIC ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/municipal/dashboard', authenticateToken, requireRole('municipal'), async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT 
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress_count,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
                COUNT(*) FILTER (WHERE cleaned_by_user_id = $1) as my_cleanups,
                SUM(total_points) FILTER (WHERE cleaned_by_user_id = $1) as my_points,
                COUNT(*) FILTER (WHERE cleanup_verified = TRUE AND cleaned_by_user_id = $1) as my_verified_cleanups
            FROM waste_reports
        `, [req.user.id]);

        const recentReports = await pool.query(`
            SELECT * FROM waste_reports
            WHERE status IN ('pending', 'in_progress')
            ORDER BY reported_at DESC
            LIMIT 10
        `);

        res.json({
            stats: stats.rows[0],
            recentReports: recentReports.rows
        });
    } catch (error) {
        console.error('Municipal dashboard error:', error);
        res.status(500).json({ message: 'Failed to fetch dashboard data' });
    }
});

app.get('/api/municipal/history', authenticateToken, requireRole('municipal'), async (req, res) => {
    const { limit = 50, offset = 0 } = req.query;

    try {
        const result = await pool.query(`
            SELECT * FROM waste_reports
            WHERE cleaned_by_user_id = $1
            ORDER BY cleaned_at DESC
            LIMIT $2 OFFSET $3
        `, [req.user.id, parseInt(limit), parseInt(offset)]);

        res.json(result.rows);
    } catch (error) {
        console.error('Municipal history error:', error);
        res.status(500).json({ message: 'Failed to fetch history' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 🔔 NOTIFICATIONS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/notifications', authenticateToken, async (req, res) => {
    const { limit = 20, unread_only = false } = req.query;

    try {
        let query = 'SELECT * FROM notifications WHERE user_id = $1';
        if (unread_only === 'true') {
            query += ' AND is_read = FALSE';
        }
        query += ' ORDER BY created_at DESC LIMIT $2';

        const result = await pool.query(query, [req.user.id, parseInt(limit)]);
        res.json(result.rows);
    } catch (error) {
        console.error('Notifications error:', error);
        res.status(500).json({ message: 'Failed to fetch notifications' });
    }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.id]
        );
        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('Mark notification error:', error);
        res.status(500).json({ message: 'Failed to update notification' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 👤 USER PROFILE
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userResult = await pool.query(
            'SELECT id, username, role, total_points, reports_count, cleanups_count, created_at FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userResult.rows[0];

        // Get user's reports
        const reportsResult = await pool.query(
            'SELECT * FROM waste_reports WHERE reported_by_user_id = $1 ORDER BY reported_at DESC LIMIT 10',
            [req.user.id]
        );

        // Get user's rank
        const rankResult = await pool.query(
            'SELECT COUNT(*) + 1 as rank FROM users WHERE total_points > $1',
            [user.total_points]
        );

        res.json({
            user: user,
            recentReports: reportsResult.rows,
            rank: parseInt(rankResult.rows[0].rank)
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Failed to fetch profile' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 💚 HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({
            status: 'healthy',
            database: 'connected',
            gemini: process.env.GEMINI_API_KEY ? 'configured' : 'missing',
            timestamp: new Date().toISOString(),
            version: '2.0.0'
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ⚠️ ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

app.use((error, req, res, next) => {
    console.error('Global error handler:', error);

    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large (10MB max)' });
        }
        return res.status(400).json({ message: error.message });
    }

    res.status(500).json({
        message: process.env.NODE_ENV === 'production' ? 
            'Internal server error' : 
            error.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Endpoint not found' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🚀 SERVER STARTUP
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log('\n' + '═'.repeat(60));
    console.log('🌍 ENVIROTRACK v2.0 - PRODUCTION SERVER');
    console.log('═'.repeat(60));
    console.log(`🌐 Server: http://localhost:${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔑 Gemini AI: ${process.env.GEMINI_API_KEY ? '✅ Configured' : '❌ Missing'}`);
    console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? '✅ Configured' : '❌ Missing'}`);
    console.log('═'.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, closing server...');
    pool.end(() => {
        console.log('Database pool closed');
        process.exit(0);
    });
});
