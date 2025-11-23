// server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Connection Pool
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    client.query('SELECT NOW()', (err, result) => {
        release();
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        console.log('Connected to PostgreSQL database:', result.rows[0].now);
    });
});

// Middleware
app.use(express.json()); // For parsing JSON request bodies
app.use(express.urlencoded({ extended: true })); // For parsing URL-encoded request bodies

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


// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Images will be stored in the 'uploads' directory
    },
    filename: (req, file, cb) => {
        // Generate a unique filename: fieldname-timestamp.ext
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// JWT Authentication Middleware (for municipal users)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expected format: Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token provided

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.sendStatus(403); // Invalid or expired token
        }
        req.user = user; // Attach user payload to request
        next(); // Proceed to the next middleware/route handler
    });
};

// --- API Endpoints ---

// 1. Register a new user (for municipal staff)
// IMPORTANT: In a real production app, this registration route
// should be protected or managed by an admin interface.
// For local development, we'll keep it open for easy testing.
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, role || 'user'] // Default role to 'user' if not specified
        );
        res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
    } catch (error) {
        if (error.code === '23505') { // Unique violation error code for duplicate username
            return res.status(409).json({ message: 'Username already exists.' });
        }
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

// 2. User Login (for municipal staff)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.json({ message: 'Logged in successfully!', accessToken: accessToken, role: user.role });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

// 3. Submit a new waste report
app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
    const { latitude, longitude, description, reportedBy } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!latitude || !longitude || !imageUrl) {
        // Delete the uploaded file if validation fails
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: 'Latitude, longitude, and an image are required.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [latitude, longitude, description, imageUrl, reportedBy || null]
        );
        res.status(201).json({ message: 'Waste report submitted successfully!', report: result.rows[0] });
    } catch (error) {
        // Delete the uploaded file if database insertion fails
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Error submitting waste report:', error);
        res.status(500).json({ message: 'Internal server error submitting report.' });
    }
});

// 4. Get all active waste reports (not cleaned)
app.get('/api/waste-reports', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching waste reports:', error);
        res.status(500).json({ message: 'Internal server error fetching reports.' });
    }
});

// 5. Get a specific waste report by ID
app.get('/api/waste-reports/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Report not found.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching single report:', error);
        res.status(500).json({ message: 'Internal server error fetching report.' });
    }
});

// 6. Mark a waste report as cleaned (by municipal user)
app.put('/api/clean-report/:id', authenticateToken, upload.single('cleanedImage'), async (req, res) => {
    const { id } = req.params;
    const cleanedImageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (req.user.role !== 'municipal') {
        // Delete the uploaded file if not authorized
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ message: 'Access denied. Only municipal users can clean reports.' });
    }
    if (!cleanedImageUrl) {
         // Delete the uploaded file if validation fails
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: 'A cleaned image is required.' });
    }

    try {
        const result = await pool.query(
            `UPDATE waste_reports
             SET is_cleaned = TRUE, cleaned_by_user_id = $1, cleaned_image_url = $2, cleaned_at = CURRENT_TIMESTAMP
             WHERE id = $3 RETURNING *`,
            [req.user.id, cleanedImageUrl, id]
        );

        if (result.rows.length === 0) {
            // Delete the uploaded file if report not found
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Waste report not found.' });
        }

        res.json({ message: 'Waste report marked as cleaned!', report: result.rows[0] });
    } catch (error) {
        // Delete the uploaded file if database update fails
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Error marking report as cleaned:', error);
        res.status(500).json({ message: 'Internal server error marking report as cleaned.' });
    }
});

// 7. Get Leaderboard (Top Reporters)
app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT reported_by, SUM(points) AS total_points
             FROM waste_reports
             WHERE reported_by IS NOT NULL AND reported_by != ''
             GROUP BY reported_by
             ORDER BY total_points DESC
             LIMIT 10` // Top 10 reporters
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        res.status(500).json({ message: 'Internal server error fetching leaderboard.' });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser`);
});