const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

module.exports = (db, upload, io) => {
    
    // Citizen registration
    router.post('/register', async (req, res) => {
        const { username, email, password, full_name, phone, lga, security_question1, security_answer1, security_question2, security_answer2 } = req.body;

        try {
            // Check if user already exists
            const existingUser = await new Promise((resolve, reject) => {
                db.get("SELECT id FROM users WHERE username = ? OR email = ?", [username, email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (existingUser) {
                return res.status(400).json({ error: 'Username or email already exists' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            const hashedAnswer1 = await bcrypt.hash(security_answer1.toLowerCase(), 10);
            const hashedAnswer2 = await bcrypt.hash(security_answer2.toLowerCase(), 10);

            db.run(
                `INSERT INTO users (username, email, password, role, full_name, phone, lga, security_question1, security_answer1, security_question2, security_answer2) 
                 VALUES (?, ?, ?, 'citizen', ?, ?, ?, ?, ?, ?, ?)`,
                [username, email, hashedPassword, full_name, phone, lga, security_question1, hashedAnswer1, security_question2, hashedAnswer2],
                function(err) {
                    if (err) {
                        console.error('Registration error:', err);
                        return res.status(500).json({ error: 'Registration failed' });
                    }

                                        res.json({ 
                        message: 'Registration successful. Please wait for administrator verification.',
                        userId: this.lastID
                    });
                }
            );

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ error: 'Registration failed' });
        }

    });

    // Citizen login
    router.post('/login', async (req, res) => {
        const { username, password } = req.body;

        try {
            const user = await new Promise((resolve, reject) => {
                db.get("SELECT * FROM users WHERE username = ? AND role = 'citizen'", [username], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            if (!user.is_verified) {
                return res.status(403).json({ error: 'Your account is pending verification. Please wait for administrator approval.' });
            }

            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            req.session.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                full_name: user.full_name,
                is_verified: user.is_verified,
                lga: user.lga,
                phone: user.phone
            };

            res.json({ 
                message: 'Login successful', 
                user: req.session.user 
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    // Get citizen dashboard data
    router.get('/dashboard', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const dashboardData = {
            userReports: 0,
            pendingReports: 0,
            recentAlerts: [],
            recentReports: []
        };

        // Get user report counts
        db.get("SELECT COUNT(*) as count FROM reports WHERE user_id = ?", [req.session.user.id], (err, row) => {
            if (!err) dashboardData.userReports = row.count;

            db.get("SELECT COUNT(*) as count FROM reports WHERE user_id = ? AND status = 'pending'", [req.session.user.id], (err, row) => {
                if (!err) dashboardData.pendingReports = row.count;

                // Get recent alerts
                db.all(`
                    SELECT * FROM alerts 
                    WHERE severity IN ('medium', 'high', 'critical')
                    ORDER BY created_at DESC LIMIT 5
                `, [], (err, alerts) => {
                    if (!err) dashboardData.recentAlerts = alerts;

                    // Get recent reports
                    db.all(`
                        SELECT * FROM reports 
                        WHERE user_id = ? 
                        ORDER BY created_at DESC LIMIT 5
                    `, [req.session.user.id], (err, reports) => {
                        if (!err) dashboardData.recentReports = reports;

                        res.json(dashboardData);
                    });
                });
            });
        });
    });

    // Submit report
    router.post('/reports/submit', upload.single('report_image'), (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { title, description, location } = req.body;
        const report_image = req.file ? `/uploads/${req.file.filename}` : null;

        db.run(
            `INSERT INTO reports (user_id, title, description, report_image, location) 
             VALUES (?, ?, ?, ?, ?)`,
            [req.session.user.id, title, description, report_image, location],
            function(err) {
                if (err) {
                    console.error('Error submitting report:', err);
                    return res.status(500).json({ error: 'Failed to submit report' });
                }

                // After creating the report, create notifications for all admins
db.all("SELECT id FROM users WHERE role = 'admin'", [], (err, admins) => {
    if (!err && admins) {
        admins.forEach(admin => {
            db.run(
                `INSERT INTO notifications (user_id, title, message, type, related_id) 
                 VALUES (?, 'New Report Submitted', '${req.session.user.full_name} submitted a new report: ${title}', 'report', ?)`,
                [admin.id, this.lastID]
            );
        });

        // Emit real-time event to admin dashboards
        io.emit('new-report', {
            reportId: this.lastID,
            title,
            user: req.session.user.full_name,
            location
        });
        
        // Emit notification update to all admin clients
        admins.forEach(admin => {
            io.emit('notification-update', { userId: admin.id });
        });
    }
});
                res.json({ 
                    message: 'Report submitted successfully', 
                    reportId: this.lastID 
                });
            }
        );
    });

    // Get citizen reports
    router.get('/reports', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT * FROM reports 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `;

        db.all(query, [req.session.user.id], (err, rows) => {
            if (err) {
                console.error('Error fetching reports:', err);
                return res.status(500).json({ error: 'Failed to fetch reports' });
            }
            res.json(rows);
        });
    });

    // Get citizen profile
    router.get('/profile', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, row) => {
            if (err) {
                console.error('Error fetching profile:', err);
                return res.status(500).json({ error: 'Failed to fetch profile' });
            }

            // Remove password and security answers from response
            const { password, security_answer1, security_answer2, ...user } = row;
            res.json(user);
        });
    });

    // Update citizen profile
    router.post('/profile/update', upload.single('profile_photo'), (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { full_name, email, phone, lga } = req.body;
        const profile_photo = req.file ? `/uploads/${req.file.filename}` : undefined;

        let query, params;

        if (profile_photo) {
            query = `UPDATE users SET full_name = ?, email = ?, phone = ?, lga = ?, profile_photo = ? WHERE id = ?`;
            params = [full_name, email, phone, lga, profile_photo, req.session.user.id];
        } else {
            query = `UPDATE users SET full_name = ?, email = ?, phone = ?, lga = ? WHERE id = ?`;
            params = [full_name, email, phone, lga, req.session.user.id];
        }

        db.run(query, params, function(err) {
            if (err) {
                console.error('Error updating profile:', err);
                return res.status(500).json({ error: 'Failed to update profile' });
            }

            // Update session
            req.session.user.full_name = full_name;
            req.session.user.email = email;
            req.session.user.phone = phone;
            req.session.user.lga = lga;

            res.json({ message: 'Profile updated successfully' });
        });
    });

    // Get notifications
    router.get('/notifications', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50
        `;

        db.all(query, [req.session.user.id], (err, rows) => {
            if (err) {
                console.error('Error fetching notifications:', err);
                return res.status(500).json({ error: 'Failed to fetch notifications' });
            }
            res.json(rows);
        });
    });

    // Mark notification as read
    router.post('/notifications/mark-read', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { notificationId } = req.body;

        db.run("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", [notificationId, req.session.user.id], function(err) {
            if (err) {
                console.error('Error marking notification as read:', err);
                return res.status(500).json({ error: 'Failed to update notification' });
            }

            res.json({ message: 'Notification marked as read' });
        });
    });

    // Forgot password - step 1: verify security questions
    router.post('/forgot-password/verify', async (req, res) => {
        const { username, security_answer1, security_answer2 } = req.body;

        try {
            const user = await new Promise((resolve, reject) => {
                db.get("SELECT * FROM users WHERE username = ? AND role = 'citizen'", [username], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            const isValidAnswer1 = await bcrypt.compare(security_answer1.toLowerCase(), user.security_answer1);
            const isValidAnswer2 = await bcrypt.compare(security_answer2.toLowerCase(), user.security_answer2);

            if (!isValidAnswer1 || !isValidAnswer2) {
                return res.status(400).json({ error: 'Security answers are incorrect' });
            }

            // Store temporary reset token in session (in production, use a proper token system)
            req.session.passwordResetUser = user.id;

            res.json({ 
                message: 'Security questions verified successfully',
                security_question1: user.security_question1,
                security_question2: user.security_question2
            });

        } catch (error) {
            console.error('Forgot password error:', error);
            res.status(500).json({ error: 'Password reset failed' });
        }
    });

    // Forgot password - step 2: reset password
    router.post('/forgot-password/reset', async (req, res) => {
        const { newPassword } = req.body;

        if (!req.session.passwordResetUser) {
            return res.status(400).json({ error: 'Password reset session expired' });
        }

        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.run("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, req.session.passwordResetUser], function(err) {
                if (err) {
                    console.error('Error resetting password:', err);
                    return res.status(500).json({ error: 'Failed to reset password' });
                }

                // Clear reset session
                delete req.session.passwordResetUser;

                res.json({ message: 'Password reset successfully' });
            });

        } catch (error) {
            console.error('Password reset error:', error);
            res.status(500).json({ error: 'Password reset failed' });
        }
    });

    // Change password (authenticated)
    router.post('/change-password', async (req, res) => {
        if (!req.session.user || req.session.user.role !== 'citizen') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { currentPassword, newPassword } = req.body;

        try {
            // Verify current password
            const user = await new Promise((resolve, reject) => {
                db.get("SELECT password FROM users WHERE id = ?", [req.session.user.id], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            const isValid = await bcrypt.compare(currentPassword, user.password);
            if (!isValid) {
                return res.status(400).json({ error: 'Current password is incorrect' });
            }

            // Hash new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.run("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, req.session.user.id], function(err) {
                if (err) {
                    console.error('Error changing password:', err);
                    return res.status(500).json({ error: 'Failed to change password' });
                }

                res.json({ message: 'Password changed successfully' });
            });

        } catch (error) {
            console.error('Password change error:', error);
            res.status(500).json({ error: 'Password change failed' });
        }
    });

    // Add these routes to your existing citizen.js file

// Forgot password - find account
router.post('/forgot-password', (req, res) => {
    const { identifier } = req.body;
    
    const query = `
        SELECT id, username, email, security_question1, security_question2 
        FROM users 
        WHERE (email = ? OR username = ?) AND role = 'citizen' AND is_verified = 1
    `;
    
    db.get(query, [identifier, identifier], (err, user) => {
        if (err) {
            console.error('Error finding account:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'Account not found or not verified' });
        }
        
        res.json({ 
            user: {
                id: user.id,
                security_question1: user.security_question1,
                security_question2: user.security_question2
            }
        });
    });
});

// Verify security answers
router.post('/verify-security-answers', (req, res) => {
    const { userId, answer1, answer2 } = req.body;
    
    const query = `
        SELECT security_answer1, security_answer2 
        FROM users 
        WHERE id = ? AND role = 'citizen'
    `;
    
    db.get(query, [userId], (err, user) => {
        if (err) {
            console.error('Error verifying answers:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Case-insensitive comparison
        const answer1Match = user.security_answer1.toLowerCase().trim() === answer1.toLowerCase().trim();
        const answer2Match = user.security_answer2.toLowerCase().trim() === answer2.toLowerCase().trim();
        
        if (!answer1Match || !answer2Match) {
            return res.status(400).json({ error: 'Security answers do not match' });
        }
        
        res.json({ success: true });
    });
});

// Reset password
router.post('/reset-password', (req, res) => {
    const { userId, newPassword } = req.body;
    
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Error resetting password' });
        }
        
        const query = `UPDATE users SET password = ? WHERE id = ? AND role = 'citizen'`;
        
        db.run(query, [hashedPassword, userId], function(err) {
            if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ error: 'Error resetting password' });
            }
            
            res.json({ success: true, message: 'Password reset successfully' });
        });
    });
});

    return router;
};