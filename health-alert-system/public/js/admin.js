// Admin-specific JavaScript functionality
class AdminManager {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAdminAuth();
    }

    setupEventListeners() {
        // Global admin event listeners
        document.addEventListener('click', (e) => {
            // Handle verification actions
            if (e.target.closest('.verify-user-btn')) {
                this.verifyUser(e.target.closest('.verify-user-btn'));
            }
            
            if (e.target.closest('.reject-user-btn')) {
                this.rejectUser(e.target.closest('.reject-user-btn'));
            }

            // Handle report status updates
            if (e.target.closest('.update-report-status')) {
                this.updateReportStatus(e.target.closest('.update-report-status'));
            }

            // Handle alert actions
            if (e.target.closest('.delete-alert-btn')) {
                this.deleteAlert(e.target.closest('.delete-alert-btn'));
            }
        });
    }

    checkAdminAuth() {
        // Check if user is authenticated as admin
        // This would typically verify with the server
        console.log('Admin authentication check');
    }

    async verifyUser(button) {
        const userId = button.getAttribute('data-user-id');
        const userRow = button.closest('tr');

        if (!confirm('Are you sure you want to verify this user?')) {
            return;
        }

        healthSystem.setLoadingState(button, true);

        try {
            const response = await fetch('/api/admin/users/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ userId })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('User verified successfully', 'success');
                userRow.remove();
                
                // Update dashboard stats
                if (typeof loadDashboardStats === 'function') {
                    loadDashboardStats();
                }
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error verifying user:', error);
            healthSystem.showNotification('Error verifying user', 'error');
        } finally {
            healthSystem.setLoadingState(button, false);
        }
    }

    async rejectUser(button) {
        const userId = button.getAttribute('data-user-id');
        const reason = prompt('Please provide a reason for rejection:');

        if (!reason) {
            healthSystem.showNotification('Rejection reason is required', 'warning');
            return;
        }

        if (!confirm('Are you sure you want to reject this user registration?')) {
            return;
        }

        healthSystem.setLoadingState(button, true);

        try {
            const response = await fetch('/api/admin/users/reject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ userId, reason })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('User registration rejected', 'success');
                button.closest('tr').remove();
                
                // Update dashboard stats
                if (typeof loadDashboardStats === 'function') {
                    loadDashboardStats();
                }
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error rejecting user:', error);
            healthSystem.showNotification('Error rejecting user', 'error');
        } finally {
            healthSystem.setLoadingState(button, false);
        }
    }

    async updateReportStatus(button) {
        const reportId = button.getAttribute('data-report-id');
        const currentStatus = button.getAttribute('data-current-status');
        
        const newStatus = prompt('Enter new status (pending, under_review, verified, rejected, action_taken):', currentStatus);
        
        if (!newStatus || !['pending', 'under_review', 'verified', 'rejected', 'action_taken'].includes(newStatus)) {
            healthSystem.showNotification('Invalid status provided', 'error');
            return;
        }

        const notes = prompt('Enter admin notes (optional):');

        healthSystem.setLoadingState(button, true);

        try {
            const response = await fetch('/api/admin/reports/update-status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    reportId,
                    status: newStatus,
                    notes: notes || ''
                })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Report status updated successfully', 'success');
                
                // Update UI
                button.setAttribute('data-current-status', newStatus);
                button.textContent = newStatus.replace('_', ' ');
                button.className = `btn btn-sm btn-${this.getStatusBadgeColor(newStatus)}`;
                
                // Refresh reports if on reports page
                if (typeof loadReports === 'function') {
                    loadReports();
                }
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error updating report status:', error);
            healthSystem.showNotification('Error updating report status', 'error');
        } finally {
            healthSystem.setLoadingState(button, false);
        }
    }

    async deleteAlert(button) {
        const alertId = button.getAttribute('data-alert-id');
        const alertTitle = button.getAttribute('data-alert-title');

        if (!confirm(`Are you sure you want to delete the alert "${alertTitle}"?`)) {
            return;
        }

        healthSystem.setLoadingState(button, true);

        try {
            const response = await fetch('/api/admin/alerts/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ alertId })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Alert deleted successfully', 'success');
                button.closest('tr').remove();
                
                // Refresh alerts if on alerts page
                if (typeof loadAlerts === 'function') {
                    loadAlerts();
                }
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error deleting alert:', error);
            healthSystem.showNotification('Error deleting alert', 'error');
        } finally {
            healthSystem.setLoadingState(button, false);
        }
    }

    getStatusBadgeColor(status) {
        const colors = {
            'pending': 'warning',
            'under_review': 'info',
            'verified': 'success',
            'rejected': 'danger',
            'action_taken': 'primary'
        };
        return colors[status] || 'secondary';
    }

    // Method to create new alert
    async createAlert(alertData) {
        try {
            const response = await fetch('/api/admin/alerts/create', {
                method: 'POST',
                body: alertData // FormData with file
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Alert created successfully', 'success');
                return result;
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Error creating alert:', error);
            healthSystem.showNotification('Error creating alert: ' + error.message, 'error');
            throw error;
        }
    }

    // Method to update user profile
    async updateProfile(profileData) {
        try {
            const response = await fetch('/api/admin/profile/update', {
                method: 'POST',
                body: profileData // FormData with file
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Profile updated successfully', 'success');
                return result;
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Error updating profile:', error);
            healthSystem.showNotification('Error updating profile: ' + error.message, 'error');
            throw error;
        }
    }

    // Method to change password
    async changePassword(currentPassword, newPassword) {
        try {
            const response = await fetch('/api/admin/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    currentPassword,
                    newPassword
                })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Password changed successfully', 'success');
                return result;
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Error changing password:', error);
            healthSystem.showNotification('Error changing password: ' + error.message, 'error');
            throw error;
        }
    }
}

// Initialize admin manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.adminManager = new AdminManager();
});

// Utility functions for admin pages
window.loadUsersForVerification = async function() {
    try {
        const response = await fetch('/api/admin/users/pending');
        const users = await response.json();

        if (response.ok) {
            return users;
        } else {
            throw new Error(users.error);
        }
    } catch (error) {
        console.error('Error loading users:', error);
        healthSystem.showNotification('Error loading users', 'error');
        return [];
    }
};

window.loadAllReports = async function() {
    try {
        const response = await fetch('/api/admin/reports');
        const reports = await response.json();

        if (response.ok) {
            return reports;
        } else {
            throw new Error(reports.error);
        }
    } catch (error) {
        console.error('Error loading reports:', error);
        healthSystem.showNotification('Error loading reports', 'error');
        return [];
    }
};

window.loadAllAlerts = async function() {
    try {
        const response = await fetch('/api/admin/alerts');
        const alerts = await response.json();

        if (response.ok) {
            return alerts;
        } else {
            throw new Error(alerts.error);
        }
    } catch (error) {
        console.error('Error loading alerts:', error);
        healthSystem.showNotification('Error loading alerts', 'error');
        return [];
    }
};

window.loadAllUsers = async function() {
    try {
        const response = await fetch('/api/admin/users');
        const users = await response.json();

        if (response.ok) {
            return users;
        } else {
            throw new Error(users.error);
        }
    } catch (error) {
        console.error('Error loading users:', error);
        healthSystem.showNotification('Error loading users', 'error');
        return [];
    }
};