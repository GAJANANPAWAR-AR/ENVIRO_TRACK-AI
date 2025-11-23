// server.js
require('dotenv').config(); // Load environment variables from .env file
// @ts-nocheck
// server.js - FINAL PERFECT Complete Waste Management System
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

// PostgreSQL Connection Pool
// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ========== GPS VALIDATION FUNCTIONS ==========

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
        console.log('📦 Initializing Gemini model...');
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 100,
                topP: 0.9,
            }
        });

        console.log('📂 Reading image file...');
        const imageData = fs.readFileSync(filePath);
        const base64Image = imageData.toString('base64');
        console.log('✅ Image converted to base64, size:', base64Image.length, 'chars');
        
        const imagePart = {
            inlineData: {
                data: base64Image,
                mimeType: getMimeType(filePath)
            },
        };

        const prompt = 'Look at this image carefully. Does it contain any visible waste, garbage, trash, litter, pollution, or debris (such as plastic bottles, food waste, paper, cans, bags, construction waste, or any form of rubbish)? Answer with ONLY one word: "Yes" or "No".';

        console.log('🤖 Sending request to Gemini AI...');
        const result = await model.generateContent([prompt, imagePart]);
        const response = await result.response;
        const text = response.text().trim();
        
        const elapsed = Date.now() - startTime;
        const normalizedText = text.toLowerCase();
        
        const isWaste = normalizedText.includes('yes') || 
                       normalizedText.startsWith('yes') ||
                       (normalizedText.includes('waste') && !normalizedText.includes('no'));
        
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('🤖 AI ANALYSIS COMPLETE');
        console.log('   Response: "' + text + '"');
        console.log('   Waste Detected: ' + (isWaste ? '✅ YES' : '❌ NO'));
        console.log('   Processing Time: ' + elapsed + 'ms');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        
        return {
            isWaste: isWaste,
            text: text,
            confidence: isWaste ? 'high' : 'low',
            elapsed: elapsed
        };

    } catch (error) {
        const elapsed = Date.now() - startTime;
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.error('❌ AI ANALYSIS ERROR');
        console.error('   Error:', error.message);
        console.error('   Time Elapsed:', elapsed + 'ms');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        
        return {
            isWaste: true,
            text: 'AI analysis unavailable - manual review required',
            confidence: 'unknown',
            elapsed: elapsed
        };
    }
}

// FIXED: Simplified cleanup verification - only checks image similarity, NO GPS
async function verifyCleanup(beforeImagePath, afterImagePath) {
    console.log('🔍 Starting cleanup verification...');
    const startTime = Date.now();
    
    try {
        console.log('📦 Initializing Gemini model for verification...');
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash-exp",
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 250,
            }
        });

        if (!fs.existsSync(beforeImagePath)) {
            throw new Error('Before image not found: ' + beforeImagePath);
        }
        if (!fs.existsSync(afterImagePath)) {
            throw new Error('After image not found: ' + afterImagePath);
        }

        console.log('📂 Reading before/after images...');
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

        // FIXED: Simplified prompt - only checks image similarity
        const prompt = 'Compare these two images:\n\nFirst image: Shows a location with waste/garbage.\nSecond image: Should show the same location after cleanup.\n\nAnswer these questions:\n1. Is the waste/garbage removed or significantly reduced in the second image?\n2. Do both images have similar features, background, or surroundings?\n\nRespond ONLY in this exact format:\nCleaned: Yes/No\nSimilar Images: Yes/No\nConfidence: High/Medium/Low';

        console.log('🤖 Sending verification request to Gemini AI...');
        const result = await model.generateContent([prompt, beforeImage, afterImage]);
        const response = await result.response;
        const text = response.text().trim();
        
        const elapsed = Date.now() - startTime;
        
        const normalizedText = text.toLowerCase();
        const isCleaned = normalizedText.includes('cleaned: yes') || 
                         (normalizedText.includes('cleaned') && normalizedText.includes('yes'));
        
        const similarImages = normalizedText.includes('similar images: yes') || 
                             normalizedText.includes('similar: yes');
        
        const confidence = normalizedText.includes('high') ? 'high' : 
                          normalizedText.includes('medium') ? 'medium' : 'low';
        
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('🔍 CLEANUP VERIFICATION COMPLETE');
        console.log('   AI Response: "' + text + '"');
        console.log('   Cleaned: ' + (isCleaned ? '✅ YES' : '❌ NO'));
        console.log('   Similar Images: ' + (similarImages ? '✅ YES' : '❌ NO'));
        console.log('   Confidence: ' + confidence.toUpperCase());
        console.log('   Processing Time: ' + elapsed + 'ms');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        
        return {
            verified: isCleaned && similarImages,
            aiResponse: text,
            confidence: confidence,
            similarImages: similarImages,
            elapsed: elapsed
        };

    } catch (error) {
        const elapsed = Date.now() - startTime;
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.error('❌ CLEANUP VERIFICATION ERROR');
        console.error('   Error:', error.message);
        console.error('   Time Elapsed:', elapsed + 'ms');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        
        return {
            verified: false,
            aiResponse: 'Verification failed: ' + error.message,
            confidence: 'unknown',
            similarImages: false,
            elapsed: elapsed
        };
    }
}

// ========== DATABASE ==========

const pool = new Pool({
user: process.env.DB_USER,
host: process.env.DB_HOST,
@@ -20,238 +241,390 @@ const pool = new Pool({
port: process.env.DB_PORT,
});

// Test database connection
pool.connect((err, client, release) => {
if (err) {
        return console.error('Error acquiring client', err.stack);
        return console.error('❌ Database connection error:', err.stack);
}
client.query('SELECT NOW()', (err, result) => {
release();
if (err) {
            return console.error('Error executing query', err.stack);
            return console.error('❌ Query error:', err.stack);
}
        console.log('Connected to PostgreSQL database:', result.rows[0].now);
        console.log('✅ Connected to PostgreSQL:', result.rows[0].now);
});
});

// Middleware
app.use(express.json()); // For parsing JSON request bodies
app.use(express.urlencoded({ extended: true })); // For parsing URL-encoded request bodies
// ========== MIDDLEWARE ==========

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
fs.mkdirSync(uploadsDir);
}
// Serve uploaded images statically
app.use('/uploads', express.static(uploadsDir));

// Serve static files from the 'public' directory
// This needs to be AFTER the uploads static serving if you have overlapping paths,
// or just before your API routes.
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Images will be stored in the 'uploads' directory
        cb(null, 'uploads/');
},
filename: (req, file, cb) => {
        // Generate a unique filename: fieldname-timestamp.ext
cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
}
});

const upload = multer({ storage: storage });
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
        return cb(null, true);
    }
    cb(new Error('Only images allowed'));
};

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: fileFilter
});

// JWT Authentication Middleware (for municipal users)
const authenticateToken = (req, res, next) => {
const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expected format: Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token provided

    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.sendStatus(403); // Invalid or expired token
        }
        req.user = user; // Attach user payload to request
        next(); // Proceed to the next middleware/route handler
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
});
};

// --- API Endpoints ---
// ========== API ENDPOINTS ==========

// 1. Register a new user (for municipal staff)
// IMPORTANT: In a real production app, this registration route
// should be protected or managed by an admin interface.
// For local development, we'll keep it open for easy testing.
// 1. Register
app.post('/api/register', async (req, res) => {
const { username, password, role } = req.body;
if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
        return res.status(400).json({ message: 'Username and password required' });
}

try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
const result = await pool.query(
'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, role || 'user'] // Default role to 'user' if not specified
            [username, hashedPassword, role || 'user']
);
        res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
        res.status(201).json({ message: 'User registered', user: result.rows[0] });
} catch (error) {
        if (error.code === '23505') { // Unique violation error code for duplicate username
            return res.status(409).json({ message: 'Username already exists.' });
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Username exists' });
}
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error during registration.' });
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 2. User Login (for municipal staff)
// 2. Login
app.post('/api/login', async (req, res) => {
const { username, password } = req.body;
try {
const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
const user = result.rows[0];

if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
            return res.status(400).json({ message: 'Invalid credentials' });
}

const isMatch = await bcrypt.compare(password, user.password_hash);
if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
            return res.status(400).json({ message: 'Invalid credentials' });
}

        // Generate JWT
const accessToken = jwt.sign(
{ id: user.id, username: user.username, role: user.role },
process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
            { expiresIn: '7d' }
);

        res.json({ message: 'Logged in successfully!', accessToken: accessToken, role: user.role });
        res.json({ message: 'Login successful', accessToken: accessToken, role: user.role, username: user.username });
} catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 3. Submit a new waste report
// 3. Report Waste
app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📥 NEW WASTE REPORT RECEIVED');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
const { latitude, longitude, description, reportedBy } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!latitude || !longitude || !imageUrl) {
        // Delete the uploaded file if validation fails
    
    console.log('📍 GPS Data - Lat:', latitude, 'Lng:', longitude);
    console.log('📝 Description:', description || 'None');
    console.log('👤 Reporter:', reportedBy || 'Anonymous');
    console.log('📸 File received:', req.file ? '✅ Yes (' + req.file.filename + ')' : '❌ No');
    
    if (!req.file) {
        console.log('❌ ERROR: No image file received');
        return res.status(400).json({ message: 'Image required' });
    }
    
    const gps = validateAndParseGPS(latitude, longitude);
    if (!gps.valid) {
        console.log('❌ GPS VALIDATION FAILED:', gps.error);
if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: 'Latitude, longitude, and an image are required.' });
        return res.status(400).json({ message: gps.error });
}
    
    console.log('✅ GPS Validated - Lat:', gps.latitude, 'Lng:', gps.longitude);

try {
        const analysisResult = await analyzeImageForWaste(req.file.path);
        
        if (!analysisResult.isWaste) {
            console.log('🚫 REPORT REJECTED - No waste detected in image');
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                message: 'AI did not detect waste in this image. Please upload an image clearly showing garbage, litter, or trash.',
                aiAnalysis: {
                    result: analysisResult.text,
                    confidence: analysisResult.confidence,
                    processingTime: analysisResult.elapsed + 'ms'
                }
            });
        }

        const imageUrl = '/uploads/' + req.file.filename;
const result = await pool.query(
            `INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [latitude, longitude, description, imageUrl, reportedBy || null]
            'INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [gps.latitude, gps.longitude, description, imageUrl, reportedBy || 'Anonymous']
);
        res.status(201).json({ message: 'Waste report submitted successfully!', report: result.rows[0] });
        
        console.log('✅ REPORT SAVED TO DATABASE');
        console.log('   Report ID:', result.rows[0].id);
        console.log('   GPS:', gps.latitude + ', ' + gps.longitude);
        console.log('   Image:', imageUrl);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        
        res.status(201).json({ 
            message: 'Waste report submitted successfully!', 
            report: result.rows[0],
            aiAnalysis: {
                result: analysisResult.text,
                confidence: analysisResult.confidence,
                processingTime: analysisResult.elapsed + 'ms'
            }
        });
} catch (error) {
        // Delete the uploaded file if database insertion fails
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Error submitting waste report:', error);
        res.status(500).json({ message: 'Internal server error submitting report.' });
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('❌ REPORT ERROR:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 4. Get all active waste reports (not cleaned)
// 4. Get Reports
app.get('/api/waste-reports', async (req, res) => {
try {
const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
res.json(result.rows);
} catch (error) {
        console.error('Error fetching waste reports:', error);
        res.status(500).json({ message: 'Internal server error fetching reports.' });
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 5. Get a specific waste report by ID
// 5. Get Single Report
app.get('/api/waste-reports/:id', async (req, res) => {
    const { id } = req.params;
try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [id]);
        const result = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Report not found.' });
            return res.status(404).json({ message: 'Report not found' });
}
res.json(result.rows[0]);
} catch (error) {
        console.error('Error fetching single report:', error);
        res.status(500).json({ message: 'Internal server error fetching report.' });
        console.error('Fetch error:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 6. Mark a waste report as cleaned (by municipal user)
// 6. Clean Report (FIXED: No GPS required, only image similarity)
app.put('/api/clean-report/:id', authenticateToken, upload.single('cleanedImage'), async (req, res) => {
    const { id } = req.params;
    const cleanedImageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🧹 CLEANUP SUBMISSION RECEIVED');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
if (req.user.role !== 'municipal') {
        // Delete the uploaded file if not authorized
if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ message: 'Access denied. Only municipal users can clean reports.' });
        return res.status(403).json({ message: 'Municipal users only' });
}
    if (!cleanedImageUrl) {
         // Delete the uploaded file if validation fails
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: 'A cleaned image is required.' });
    
    console.log('📸 Cleaned image:', req.file ? '✅ Yes' : '❌ No');
    console.log('👤 Municipal User:', req.user.username);
    
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
        
        // FIXED: Only pass image paths, no GPS
        const verification = await verifyCleanup(beforeImagePath, afterImagePath);
        
        const cleanedImageUrl = '/uploads/' + req.file.filename;
        
        // FIXED: Updated database columns - removed location_match
const result = await pool.query(
            `UPDATE waste_reports
             SET is_cleaned = TRUE, cleaned_by_user_id = $1, cleaned_image_url = $2, cleaned_at = CURRENT_TIMESTAMP
             WHERE id = $3 RETURNING *`,
            [req.user.id, cleanedImageUrl, id]
            'UPDATE waste_reports SET is_cleaned = TRUE, cleaned_by_user_id = $1, cleaned_image_url = $2, cleaned_at = CURRENT_TIMESTAMP, cleanup_verified = $3, verification_confidence = $4, ai_comparison_result = $5 WHERE id = $6 RETURNING *',
            [req.user.id, cleanedImageUrl, verification.verified, verification.confidence, verification.aiResponse, req.params.id]
);

        if (result.rows.length === 0) {
            // Delete the uploaded file if report not found
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Waste report not found.' });
        
        console.log('✅ CLEANUP RECORD UPDATED IN DATABASE');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        
        res.json({ 
            message: verification.verified ? 'Cleanup verified successfully!' : 'Cleanup submitted - manual review may be required',
            report: result.rows[0],
            verification: {
                verified: verification.verified,
                confidence: verification.confidence,
                similarImages: verification.similarImages,
                aiResponse: verification.aiResponse,
                processingTime: verification.elapsed + 'ms'
            }
        });
        
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
}
        console.error('❌ CLEANUP ERROR:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

        res.json({ message: 'Waste report marked as cleaned!', report: result.rows[0] });
// 7. Leaderboard (FIXED)
app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT reported_by, SUM(points) AS total_points, COUNT(*) AS total_reports FROM waste_reports WHERE reported_by IS NOT NULL AND reported_by != \'\' AND reported_by != \'Anonymous\' GROUP BY reported_by ORDER BY total_points DESC LIMIT 10'
        );
        console.log('🏆 Leaderboard query result:', result.rows.length, 'entries');
        res.json(result.rows);
} catch (error) {
        // Delete the uploaded file if database update fails
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Error marking report as cleaned:', error);
        res.status(500).json({ message: 'Internal server error marking report as cleaned.' });
        console.error('❌ Leaderboard error:', error);
        res.status(500).json({ message: 'Server error' });
}
});

// 7. Get Leaderboard (Top Reporters)
app.get('/api/leaderboard', async (req, res) => {
// 8. Statistics
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

// 9. Health Check
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

// 10. Municipal Endpoints
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
            'SELECT COUNT(*) as total_cleaned, COUNT(CASE WHEN cleanup_verified = TRUE THEN 1 END) as verified_cleanups, COUNT(CASE WHEN cleanup_verified = FALSE THEN 1 END) as unverified_cleanups, COUNT(CASE WHEN verification_confidence = \'high\' THEN 1 END) as high_confidence, COUNT(CASE WHEN verification_confidence = \'medium\' THEN 1 END) as medium_confidence, COUNT(CASE WHEN verification_confidence = \'low\' THEN 1 END) as low_confidence FROM waste_reports WHERE is_cleaned = TRUE'
        );
        res.json(stats.rows[0]);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/municipal/history', authenticateToken, async (req, res) => {
    if (req.user.role !== 'municipal') {
        return res.status(403).json({ message: 'Access denied' });
    }
try {
const result = await pool.query(
            `SELECT reported_by, SUM(points) AS total_points
             FROM waste_reports
             WHERE reported_by IS NOT NULL AND reported_by != ''
             GROUP BY reported_by
             ORDER BY total_points DESC
             LIMIT 10` // Top 10 reporters
            'SELECT * FROM waste_reports WHERE cleaned_by_user_id = $1 ORDER BY cleaned_at DESC LIMIT 50',
            [req.user.id]
);
res.json(result.rows);
} catch (error) {
        console.error('Error fetching leaderboard:', error);
        res.status(500).json({ message: 'Internal server error fetching leaderboard.' });
        console.error('History error:', error);
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

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser`);
});
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🚀 ENVIROTRACK SERVER STARTED');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🌐 Server: http://localhost:' + PORT);
    console.log('📊 API: Ready');
    console.log('✅ GPS Validation: Active');
    console.log('🤖 AI Model: gemini-2.0-flash-exp');
    console.log('🔑 Gemini API: ' + (process.env.GEMINI_API_KEY ? 'Configured ✅' : 'Missing ❌'));
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
