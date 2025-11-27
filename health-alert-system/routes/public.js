const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

module.exports = (db, io) => {
    
    // Get public alerts
    router.get('/alerts', (req, res) => {
        const query = `
            SELECT a.*, u.full_name as created_by_name 
            FROM alerts a 
            LEFT JOIN users u ON a.created_by = u.id 
            WHERE a.severity IN ('medium', 'high', 'critical')
            ORDER BY a.created_at DESC 
            LIMIT 6
        `;
        
        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching alerts:', err);
                return res.status(500).json({ error: 'Failed to fetch alerts' });
            }
            res.json(rows);
        });
    });

    // Get all alerts for alerts page
    router.get('/alerts/all', (req, res) => {
        const query = `
            SELECT a.*, u.full_name as created_by_name 
            FROM alerts a 
            LEFT JOIN users u ON a.created_by = u.id 
            ORDER BY 
                CASE a.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END,
                a.created_at DESC
        `;
        
        db.all(query, [], (err, rows) => {
            if (err) {
                console.error('Error fetching all alerts:', err);
                return res.status(500).json({ error: 'Failed to fetch alerts' });
            }
            res.json(rows);
        });
    });

    // Logout endpoint
    router.post('/logout', (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                console.error('Logout error:', err);
                return res.status(500).json({ error: 'Logout failed' });
            }
            res.json({ message: 'Logged out successfully' });
        });
    });

    // System statistics (public)
    router.get('/statistics', (req, res) => {
        const stats = {
            totalAlerts: 0,
            activeAlerts: 0,
            totalReports: 0,
            verifiedUsers: 0
        };

        // Get total alerts
        db.get("SELECT COUNT(*) as count FROM alerts", (err, row) => {
            if (!err) stats.totalAlerts = row.count;

            // Get active alerts (last 30 days)
            db.get("SELECT COUNT(*) as count FROM alerts WHERE created_at >= datetime('now', '-30 days')", (err, row) => {
                if (!err) stats.activeAlerts = row.count;

                // Get total reports
                db.get("SELECT COUNT(*) as count FROM reports", (err, row) => {
                    if (!err) stats.totalReports = row.count;

                    // Get verified users
                    db.get("SELECT COUNT(*) as count FROM users WHERE is_verified = 1", (err, row) => {
                        if (!err) stats.verifiedUsers = row.count;
                        
                        res.json(stats);
                    });
                });
            });
        });
    });

    return router;
};