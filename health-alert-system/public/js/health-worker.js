// Health Worker-specific JavaScript functionality
class HealthWorkerManager {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkHealthWorkerAuth();
    }

    setupEventListeners() {
        // Health worker-specific event listeners
        document.addEventListener('click', (e) => {
            // Handle report submission
            if (e.target.closest('#submitReportBtn')) {
                this.submitReport(e);
            }

            // Handle notification actions
            if (e.target.closest('.mark-notification-read')) {
                this.markNotificationAsRead(e.target.closest('.mark-notification-read'));
            }
        });
    }

    checkHealthWorkerAuth() {
        // Check if user is authenticated as health worker
        console.log('Health worker authentication check');
    }

    async submitReport(e) {
        e.preventDefault();
        
        const form = document.getElementById('reportSubmissionForm');
        if (!form) return;

        const submitButton = form.querySelector('button[type="submit"]');
        const formData = new FormData(form);

        // Basic validation
        const title = formData.get('title');
        const description = formData.get('description');
        const location = formData.get('location');

        if (!title || !description || !location) {
            healthSystem.showNotification('Please fill in all required fields', 'error');
            return;
        }

        healthSystem.setLoadingState(submitButton, true);

        try {
            const response = await fetch('/api/health-worker/reports/submit', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Report submitted successfully! Admin will review it shortly.', 'success');
                form.reset();
                
                // Clear any image preview
                const preview = document.querySelector('.image-preview');
                if (preview) preview.remove();
                
                // Redirect to reports page after delay
                setTimeout(() => {
                    window.location.href = '/health-worker/reports';
                }, 2000);
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error submitting report:', error);
            healthSystem.showNotification('Error submitting report. Please try again.', 'error');
        } finally {
            healthSystem.setLoadingState(submitButton, false);
        }
    }

    async markNotificationAsRead(button) {
        const notificationId = button.getAttribute('data-notification-id');

        try {
            const response = await fetch('/api/health-worker/notifications/mark-read', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ notificationId })
            });

            const result = await response.json();

            if (response.ok) {
                button.closest('.notification-item').classList.remove('unread');
                button.remove();
                
                // Update notification badge
                const badge = document.querySelector('.notification-badge');
                if (badge) {
                    const currentCount = parseInt(badge.textContent) || 0;
                    if (currentCount > 0) {
                        badge.textContent = currentCount - 1;
                    }
                    if (currentCount - 1 === 0) {
                        badge.style.display = 'none';
                    }
                }
            } else {
                healthSystem.showNotification(result.error, 'error');
            }
        } catch (error) {
            console.error('Error marking notification as read:', error);
        }
    }

    // Method to load health worker reports
    async loadHealthWorkerReports() {
        try {
            const response = await fetch('/api/health-worker/reports');
            const reports = await response.json();

            if (response.ok) {
                return reports;
            } else {
                throw new Error(reports.error);
            }
        } catch (error) {
            console.error('Error loading reports:', error);
            healthSystem.showNotification('Error loading your reports', 'error');
            return [];
        }
    }

    // Method to update health worker profile
    async updateProfile(profileData) {
        try {
            const response = await fetch('/api/health-worker/profile/update', {
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
            const response = await fetch('/api/health-worker/change-password', {
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

    // Method for forgot password flow
    async verifySecurityQuestions(username, answer1, answer2) {
        try {
            const response = await fetch('/api/health-worker/forgot-password/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username,
                    security_answer1: answer1,
                    security_answer2: answer2
                })
            });

            const result = await response.json();

            if (response.ok) {
                return result;
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Error verifying security questions:', error);
            healthSystem.showNotification('Error: ' + error.message, 'error');
            throw error;
        }
    }

    async resetPassword(newPassword) {
        try {
            const response = await fetch('/api/health-worker/forgot-password/reset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ newPassword })
            });

            const result = await response.json();

            if (response.ok) {
                healthSystem.showNotification('Password reset successfully', 'success');
                return result;
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Error resetting password:', error);
            healthSystem.showNotification('Error resetting password: ' + error.message, 'error');
            throw error;
        }
    }
}

// Initialize health worker manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.healthWorkerManager = new HealthWorkerManager();
});

// Utility functions for health worker pages
window.loadHealthWorkerProfile = async function() {
    try {
        const response = await fetch('/api/health-worker/profile');
        const profile = await response.json();

        if (response.ok) {
            return profile;
        } else {
            throw new Error(profile.error);
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        healthSystem.showNotification('Error loading profile', 'error');
        return null;
    }
};

window.loadHealthWorkerNotifications = async function() {
    try {
        const response = await fetch('/api/health-worker/notifications');
        const notifications = await response.json();

        if (response.ok) {
            return notifications;
        } else {
            throw new Error(notifications.error);
        }
    } catch (error) {
        console.error('Error loading notifications:', error);
        healthSystem.showNotification('Error loading notifications', 'error');
        return [];
    }
};