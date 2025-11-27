const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: 'gombe-health-secret-2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Database initialization
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

// Initialize database tables
function initializeDatabase() {
    // Users table with workplace fields for health workers
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT CHECK(role IN ('admin', 'citizen', 'health_worker')),
        is_verified INTEGER DEFAULT 0,
        profile_photo TEXT,
        security_question1 TEXT,
        security_answer1 TEXT,
        security_question2 TEXT,
        security_answer2 TEXT,
        lga TEXT,
        full_name TEXT,
        phone TEXT,
        workplace_type TEXT,
        workplace_name TEXT,
        workplace_lga TEXT,
        workplace_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Alerts table
    db.run(`CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        alert_image TEXT,
        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
        locations TEXT,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    // Reports table
    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        description TEXT,
        report_image TEXT,
        location TEXT,
        status TEXT CHECK(status IN ('pending', 'under_review', 'verified', 'rejected', 'action_taken')) DEFAULT 'pending',
        admin_notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Notifications table
    db.run(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        message TEXT,
        is_read INTEGER DEFAULT 0,
        type TEXT,
        related_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Create default admin user
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.get("SELECT * FROM users WHERE role = 'admin'", (err, row) => {
        if (!row) {
            db.run(`INSERT INTO users (username, email, password, role, is_verified, full_name) 
                    VALUES (?, ?, ?, ?, ?, ?)`, 
                ['admin', 'admin@gombehealth.gov.ng', adminPassword, 'admin', 1, 'System Administrator']);
            console.log('Default admin user created');
        }
    });
}

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Routes
app.use('/api/admin', require('./routes/admin')(db, upload, io));
app.use('/api/citizen', require('./routes/citizen')(db, upload, io));
app.use('/api/health-worker', require('./routes/health-worker')(db, upload, io));
app.use('/api/public', require('./routes/public')(db, io));

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/alerts', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'alerts.html'));
});

// Admin routes
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin', 'login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'dashboard.html'));
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/verification', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'verification.html'));
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/reports', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'reports.html'));
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/alerts', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'alerts.html'));
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/users', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'users.html'));
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/profile', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin', 'profile.html'));
    } else {
        res.redirect('/admin/login');
    }
});

// Citizen routes
app.get('/citizen/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/citizen', 'login.html'));
});

app.get('/citizen/registration', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/citizen', 'registration.html'));
});

app.get('/citizen/dashboard', (req, res) => {
    if (req.session.user && req.session.user.role === 'citizen' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/citizen', 'dashboard.html'));
    } else {
        res.redirect('/citizen/login');
    }
});

// ADD THIS MISSING ROUTE FOR REPORTS PAGE
app.get('/citizen/reports', (req, res) => {
    if (req.session.user && req.session.user.role === 'citizen' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/citizen', 'reports.html'));
    } else {
        res.redirect('/citizen/login');
    }
});

app.get('/citizen/profile', (req, res) => {
    if (req.session.user && req.session.user.role === 'citizen' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/citizen', 'profile.html'));
    } else {
        res.redirect('/citizen/login');
    }
});

app.get('/citizen/report-submission', (req, res) => {
    if (req.session.user && req.session.user.role === 'citizen' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/citizen', 'report-submission.html'));
    } else {
        res.redirect('/citizen/login');
    }
});

app.get('/citizen/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/citizen', 'forgot-password.html'));
});

// Health Worker routes
app.get('/health-worker/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/health-worker', 'login.html'));
});

app.get('/health-worker/registration', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/health-worker', 'registration.html'));
});

app.get('/health-worker/dashboard', (req, res) => {
    if (req.session.user && req.session.user.role === 'health_worker' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/health-worker', 'dashboard.html'));
    } else {
        res.redirect('/health-worker/login');
    }
});

// ADD THIS FOR HEALTH WORKER REPORTS PAGE
app.get('/health-worker/reports', (req, res) => {
    if (req.session.user && req.session.user.role === 'health_worker' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/health-worker', 'reports.html'));
    } else {
        res.redirect('/health-worker/login');
    }
});

app.get('/health-worker/profile', (req, res) => {
    if (req.session.user && req.session.user.role === 'health_worker' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/health-worker', 'profile.html'));
    } else {
        res.redirect('/health-worker/login');
    }
});

app.get('/health-worker/report-submission', (req, res) => {
    if (req.session.user && req.session.user.role === 'health_worker' && req.session.user.is_verified) {
        res.sendFile(path.join(__dirname, 'public/health-worker', 'report-submission.html'));
    } else {
        res.redirect('/health-worker/login');
    }
});

app.get('/health-worker/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/health-worker', 'forgot-password.html'));
});

// Socket.io for real-time notifications
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('join-user-room', (userId) => {
        socket.join(`user-${userId}`);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Gombe Health Alert System running on port ${PORT}`);
    console.log(`📍 Visit: http://localhost:${PORT}`);
    console.log(`🔑 Admin Login: http://localhost:${PORT}/admin/login`);
    console.log(`   Username: admin, Password: admin123`);
});