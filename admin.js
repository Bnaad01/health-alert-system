const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

module.exports = (db, upload, io) => {
    
    // Admin login
    router.post('/login', async (req, res) => {
        const { username, password } = req.body;

        try {
            const user = await new Promise((resolve, reject) => {
                db.get("SELECT * FROM users WHERE username = ? AND role = 'admin'", [username], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
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
                is_verified: user.is_verified
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

    // Get dashboard statistics
    router.get('/dashboard/stats', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const stats = {
            totalUsers: 0,
            pendingVerifications: 0,
            totalReports: 0,
            pendingReports: 0,
            totalAlerts: 0,
            criticalAlerts: 0
        };

        // Get total users
        db.get("SELECT COUNT(*) as count FROM users WHERE role != 'admin'", (err, row) => {
            if (!err) stats.totalUsers = row.count;

            // Get pending verifications
            db.get("SELECT COUNT(*) as count FROM users WHERE is_verified = 0 AND role != 'admin'", (err, row) => {
                if (!err) stats.pendingVerifications = row.count;

                // Get total reports
                db.get("SELECT COUNT(*) as count FROM reports", (err, row) => {
                    if (!err) stats.totalReports = row.count;

                    // Get pending reports
                    db.get("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'", (err, row) => {
                        if (!err) stats.pendingReports = row.count;

                        // Get total alerts
                        db.get("SELECT COUNT(*) as count FROM alerts", (err, row) => {
                            if (!err) stats.totalAlerts = row.count;

                            // Get critical alerts
                            db.get("SELECT COUNT(*) as count FROM alerts WHERE severity = 'critical'", (err, row) => {
                                if (!err) stats.criticalAlerts = row.count;
                                
                                res.json(stats);
                            });
                        });
                    });
                });
            });
        });
    });

    // Get users for verification
    router.get('/users/pending', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT id, username, email, role, full_name, lga, phone, 
                   workplace_type, workplace_name, workplace_lga, created_at
            FROM users 
            WHERE is_verified = 0 AND role != 'admin'
            ORDER BY created_at DESC
        `;

        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching pending users:', err);
                return res.status(500).json({ error: 'Failed to fetch users' });
            }
            res.json(rows);
        });
    });

    // Verify user
    router.post('/users/verify', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { userId } = req.body;

        db.run("UPDATE users SET is_verified = 1 WHERE id = ?", [userId], function(err) {
            if (err) {
                console.error('Error verifying user:', err);
                return res.status(500).json({ error: 'Failed to verify user' });
            }

            // Create notification for the user
            db.run(
                `INSERT INTO notifications (user_id, title, message, type) 
                 VALUES (?, 'Account Verified', 'Your account has been verified by the administrator. You can now access all features.', 'verification')`,
                [userId]
            );

            // Emit real-time event
            io.emit('user-verified', { userId, verified: true });

            res.json({ message: 'User verified successfully' });
        });
    });

    // Reject user verification
    router.post('/users/reject', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { userId, reason } = req.body;

        db.run("DELETE FROM users WHERE id = ? AND is_verified = 0", [userId], function(err) {
            if (err) {
                console.error('Error rejecting user:', err);
                return res.status(500).json({ error: 'Failed to reject user' });
            }

            res.json({ message: 'User registration rejected' });
        });
    });

    // Get all reports
    router.get('/reports', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT r.*, u.username, u.full_name, u.role as user_role
            FROM reports r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        `;

        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching reports:', err);
                return res.status(500).json({ error: 'Failed to fetch reports' });
            }
            res.json(rows);
        });
    });

    // Update report status
    router.post('/reports/update-status', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { reportId, status, notes } = req.body;

        db.run(
            "UPDATE reports SET status = ?, admin_notes = ? WHERE id = ?",
            [status, notes, reportId],
            function(err) {
                if (err) {
                    console.error('Error updating report:', err);
                    return res.status(500).json({ error: 'Failed to update report' });
                }

                // Get report to send notification
                db.get("SELECT user_id, title FROM reports WHERE id = ?", [reportId], (err, report) => {
                    if (!err && report) {
                        // Create notification
                        db.run(
                            `INSERT INTO notifications (user_id, title, message, type, related_id) 
                             VALUES (?, 'Report Status Updated', 'Your report "${report.title}" status has been updated to ${status}.', 'report', ?)`,
                            [report.user_id, reportId]
                        );

                        // Emit real-time event
                        io.emit('report-updated', { reportId, status, userId: report.user_id });
                    }
                });

                res.json({ message: 'Report status updated successfully' });
            }
        );
    });

    // Create alert
    router.post('/alerts/create', upload.single('alert_image'), (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { title, description, severity, locations } = req.body;
        const alert_image = req.file ? `/uploads/${req.file.filename}` : null;

        db.run(
            `INSERT INTO alerts (title, description, alert_image, severity, locations, created_by) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [title, description, alert_image, severity, locations, req.session.user.id],
            function(err) {
                if (err) {
                    console.error('Error creating alert:', err);
                    return res.status(500).json({ error: 'Failed to create alert' });
                }

                // Create notifications for all verified users
                db.all("SELECT id FROM users WHERE is_verified = 1", [], (err, users) => {
                    if (!err && users) {
                        users.forEach(user => {
                            db.run(
                                `INSERT INTO notifications (user_id, title, message, type, related_id) 
                                 VALUES (?, 'New Health Alert', '${title} - ${description.substring(0, 100)}...', 'alert', ?)`,
                                [user.id, this.lastID]
                            );
                        });

                        // Emit real-time event to all connected clients
                        io.emit('new-alert', {
                            id: this.lastID,
                            title,
                            description,
                            severity,
                            locations,
                            created_at: new Date()
                        });
                    }
                });

                res.json({ message: 'Alert created successfully', alertId: this.lastID });
            }
        );
    });

        // Get admin notifications
    router.get('/notifications', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT * FROM notifications 
            WHERE user_id = ? OR user_id IS NULL
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

    // Mark notification as read (admin)
    router.post('/notifications/mark-read', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { notificationId } = req.body;

        db.run("UPDATE notifications SET is_read = 1 WHERE id = ?", [notificationId], function(err) {
            if (err) {
                console.error('Error marking notification as read:', err);
                return res.status(500).json({ error: 'Failed to update notification' });
            }

            res.json({ message: 'Notification marked as read' });
        });
    });

    // Get all alerts
    router.get('/alerts', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT a.*, u.full_name as created_by_name 
            FROM alerts a 
            LEFT JOIN users u ON a.created_by = u.id 
            ORDER BY a.created_at DESC
        `;

        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching alerts:', err);
                return res.status(500).json({ error: 'Failed to fetch alerts' });
            }
            res.json(rows);
        });
    });

    // Update alert
    router.post('/alerts/update', upload.single('alert_image'), (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { alertId, title, description, severity, locations } = req.body;
        let alert_image = null;

        // If new image uploaded, use it. Otherwise keep existing
        if (req.file) {
            alert_image = `/uploads/${req.file.filename}`;
        }

        let query, params;

        if (alert_image) {
            query = `UPDATE alerts SET title = ?, description = ?, alert_image = ?, severity = ?, locations = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
            params = [title, description, alert_image, severity, locations, alertId];
        } else {
            query = `UPDATE alerts SET title = ?, description = ?, severity = ?, locations = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
            params = [title, description, severity, locations, alertId];
        }

        db.run(query, params, function(err) {
            if (err) {
                console.error('Error updating alert:', err);
                return res.status(500).json({ error: 'Failed to update alert' });
            }

            // Emit real-time event
            io.emit('alert-updated', { alertId, title, severity });

            res.json({ message: 'Alert updated successfully' });
        });
    });

    // Delete alert
    router.post('/alerts/delete', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { alertId } = req.body;

        db.run("DELETE FROM alerts WHERE id = ?", [alertId], function(err) {
            if (err) {
                console.error('Error deleting alert:', err);
                return res.status(500).json({ error: 'Failed to delete alert' });
            }

            res.json({ message: 'Alert deleted successfully' });
        });
    });

    // Get all users
    router.get('/users', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const query = `
            SELECT id, username, email, role, is_verified, full_name, lga, phone, 
                   workplace_type, workplace_name, workplace_lga, created_at
            FROM users 
            WHERE role != 'admin'
            ORDER BY created_at DESC
        `;

        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching users:', err);
                return res.status(500).json({ error: 'Failed to fetch users' });
            }
            res.json(rows);
        });
    });

    // Get admin profile
    router.get('/profile', (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, row) => {
            if (err) {
                console.error('Error fetching profile:', err);
                return res.status(500).json({ error: 'Failed to fetch profile' });
            }

            // Remove password from response
            const { password, ...user } = row;
            res.json(user);
        });
    });

    // Update admin profile
    router.post('/profile/update', upload.single('profile_photo'), (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { full_name, email, phone } = req.body;
        const profile_photo = req.file ? `/uploads/${req.file.filename}` : undefined;

        let query, params;

        if (profile_photo) {
            query = `UPDATE users SET full_name = ?, email = ?, phone = ?, profile_photo = ? WHERE id = ?`;
            params = [full_name, email, phone, profile_photo, req.session.user.id];
        } else {
            query = `UPDATE users SET full_name = ?, email = ?, phone = ? WHERE id = ?`;
            params = [full_name, email, phone, req.session.user.id];
        }

        db.run(query, params, function(err) {
            if (err) {
                console.error('Error updating profile:', err);
                return res.status(500).json({ error: 'Failed to update profile' });
            }

            // Update session
            req.session.user.full_name = full_name;
            req.session.user.email = email;

            res.json({ message: 'Profile updated successfully' });
        });
    });

    // Change password
    router.post('/change-password', async (req, res) => {
        if (!req.session.user || req.session.user.role !== 'admin') {
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

    return router;
};