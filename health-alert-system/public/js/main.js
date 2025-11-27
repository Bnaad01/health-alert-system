// Main JavaScript for Gombe Health Alert System

class HealthAlertSystem {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthentication();
        this.setupRealTimeUpdates();
    }

    setupEventListeners() {
        // Global logout handler
        document.addEventListener('click', (e) => {
            if (e.target.closest('.logout-btn')) {
                e.preventDefault();
                this.logout();
            }
        });

        // File upload handlers
        document.addEventListener('change', (e) => {
            if (e.target.type === 'file') {
                this.handleFileSelection(e.target);
            }
        });

        // Drag and drop for file uploads
        document.addEventListener('dragover', (e) => {
            if (e.target.classList.contains('file-upload')) {
                e.preventDefault();
                e.target.classList.add('dragover');
            }
        });

        document.addEventListener('dragleave', (e) => {
            if (e.target.classList.contains('file-upload')) {
                e.preventDefault();
                e.target.classList.remove('dragover');
            }
        });

        document.addEventListener('drop', (e) => {
            if (e.target.classList.contains('file-upload')) {
                e.preventDefault();
                e.target.classList.remove('dragover');
                this.handleFileDrop(e.dataTransfer.files, e.target);
            }
        });
    }

    async logout() {
        try {
            const response = await fetch('/api/public/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                window.location.href = '/';
            } else {
                this.showNotification('Error logging out. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Logout error:', error);
            this.showNotification('Error logging out. Please try again.', 'error');
        }
    }

    handleFileSelection(input) {
        const file = input.files[0];
        if (file) {
            this.validateAndPreviewFile(file, input);
        }
    }

    handleFileDrop(files, target) {
        const file = files[0];
        if (file) {
            const input = target.querySelector('input[type="file"]');
            if (input) {
                const dt = new DataTransfer();
                dt.items.add(file);
                input.files = dt.files;
                this.validateAndPreviewFile(file, input);
            }
        }
    }

    validateAndPreviewFile(file, input) {
        const maxSize = 5 * 1024 * 1024; // 5MB
        const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];

        if (!validTypes.includes(file.type)) {
            this.showNotification('Please select a valid image file (JPEG, PNG, GIF).', 'error');
            input.value = '';
            return;
        }

        if (file.size > maxSize) {
            this.showNotification('File size must be less than 5MB.', 'error');
            input.value = '';
            return;
        }

        // Show preview if it's an image
        if (file.type.startsWith('image/')) {
            this.showImagePreview(file, input);
        }
    }

    showImagePreview(file, input) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const previewContainer = input.closest('.file-upload-container') || input.parentElement;
            let preview = previewContainer.querySelector('.image-preview');
            
            if (!preview) {
                preview = document.createElement('div');
                preview.className = 'image-preview mt-3';
                previewContainer.appendChild(preview);
            }

            preview.innerHTML = `
                <div class="preview-container position-relative d-inline-block">
                    <img src="${e.target.result}" alt="Preview" class="img-thumbnail" style="max-height: 150px;">
                    <button type="button" class="btn btn-sm btn-danger position-absolute top-0 end-0" onclick="this.closest('.image-preview').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
        };
        reader.readAsDataURL(file);
    }

    showNotification(message, type = 'info', duration = 5000) {
        // Remove existing notifications
        const existingAlerts = document.querySelectorAll('.global-alert');
        existingAlerts.forEach(alert => alert.remove());

        const alertClass = {
            'success': 'alert-success',
            'error': 'alert-danger',
            'warning': 'alert-warning',
            'info': 'alert-info'
        }[type] || 'alert-info';

        const alertHtml = `
            <div class="global-alert alert ${alertClass} alert-dismissible fade show position-fixed"
                 style="top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
                <div class="d-flex align-items-center">
                    <i class="fas fa-${this.getNotificationIcon(type)} me-2"></i>
                    <div class="flex-grow-1">${message}</div>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', alertHtml);

        // Auto remove after duration
        setTimeout(() => {
            const alert = document.querySelector('.global-alert');
            if (alert) {
                alert.remove();
            }
        }, duration);
    }

    getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-triangle',
            'warning': 'exclamation-circle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    checkAuthentication() {
        // Check if user is authenticated and update UI accordingly
        const authElements = document.querySelectorAll('[data-auth]');
        authElements.forEach(element => {
            const requiredAuth = element.getAttribute('data-auth');
            // This would typically check against actual authentication status
            // For now, we'll handle this in individual page scripts
        });
    }

    setupRealTimeUpdates() {
        // Real-time updates would be handled by socket.io
        // This is a placeholder for real-time functionality
    }

    // Utility function to format dates
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    // Utility function to handle API errors
    handleApiError(error) {
        console.error('API Error:', error);
        this.showNotification('An error occurred. Please try again.', 'error');
    }

    // Loading state management
    setLoadingState(element, isLoading) {
        if (isLoading) {
            element.disabled = true;
            const originalText = element.innerHTML;
            element.setAttribute('data-original-text', originalText);
            element.innerHTML = '<span class="loading-spinner me-2"></span> Loading...';
        } else {
            element.disabled = false;
            const originalText = element.getAttribute('data-original-text');
            if (originalText) {
                element.innerHTML = originalText;
            }
        }
    }
}

// Initialize the main system
const healthSystem = new HealthAlertSystem();

// Utility functions for the global scope
window.formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

window.validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

window.validatePhone = (phone) => {
    const re = /^[0-9+]{10,15}$/;
    return re.test(phone);
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HealthAlertSystem;
}