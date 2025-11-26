// public/js/socket.js
class SocketManager {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.init();
    }

    init() {
        this.connect();
        this.setupGlobalEventListeners();
    }

    connect() {
        try {
            this.socket = io({
                timeout: 10000,
                reconnectionAttempts: this.maxReconnectAttempts,
                reconnectionDelay: 1000
            });

            this.setupSocketEventListeners();
            
        } catch (error) {
            console.error('❌ Socket connection failed:', error);
            this.scheduleReconnect();
        }
    }

    setupSocketEventListeners() {
        if (!this.socket) return;

        // Connection events
        this.socket.on('connect', () => {
            console.log('✅ Socket connected successfully');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.onConnect();
        });

        this.socket.on('disconnect', (reason) => {
            console.log('🔌 Socket disconnected:', reason);
            this.isConnected = false;
            this.onDisconnect(reason);
        });

        this.socket.on('connect_error', (error) => {
            console.error('❌ Socket connection error:', error);
            this.isConnected = false;
            this.onConnectError(error);
        });

        this.socket.on('reconnect_attempt', (attempt) => {
            console.log(`🔄 Reconnection attempt ${attempt}`);
            this.reconnectAttempts = attempt;
        });

        this.socket.on('reconnect_failed', () => {
            console.error('❌ Maximum reconnection attempts reached');
            this.onReconnectFailed();
        });

        // Application-specific events
        this.socket.on('notification', (data) => {
            this.handleNotification(data);
        });

        this.socket.on('alert_update', (data) => {
            this.handleAlertUpdate(data);
        });

        this.socket.on('report_update', (data) => {
            this.handleReportUpdate(data);
        });

        this.socket.on('user_activity', (data) => {
            this.handleUserActivity(data);
        });
    }

    setupGlobalEventListeners() {
        // Global event listeners for the application
        window.addEventListener('online', () => {
            console.log('🌐 Browser is online');
            if (!this.isConnected) {
                this.connect();
            }
        });

        window.addEventListener('offline', () => {
            console.log('🔴 Browser is offline');
        });

        // Page visibility change
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && !this.isConnected) {
                this.connect();
            }
        });
    }

    onConnect() {
        // Join appropriate room based on user role
        const userData = this.getUserData();
        if (userData && userData.id) {
            this.joinUserRoom(userData.id);
        }

        // Notify the application
        this.emitGlobalEvent('socket:connected');
        
        // Update connection status in UI
        this.updateConnectionStatus(true);
    }

    onDisconnect(reason) {
        this.updateConnectionStatus(false);
        this.emitGlobalEvent('socket:disconnected', { reason });
        
        if (reason === 'io server disconnect') {
            // Server intentionally disconnected, try to reconnect
            this.socket.connect();
        }
    }

    onConnectError(error) {
        this.emitGlobalEvent('socket:error', { error });
        this.scheduleReconnect();
    }

    onReconnectFailed() {
        this.emitGlobalEvent('socket:reconnect_failed');
        console.error('Please refresh the page to reconnect');
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            console.log(`🔄 Reconnecting in ${delay}ms`);
            
            setTimeout(() => {
                this.connect();
            }, delay);
        }
    }

    // User room management
    joinUserRoom(userId) {
        if (this.socket && this.isConnected) {
            this.socket.emit('join-user-room', userId);
            console.log(`🚪 Joined user room: user-${userId}`);
        }
    }

    leaveUserRoom(userId) {
        if (this.socket && this.isConnected) {
            this.socket.emit('leave-user-room', userId);
        }
    }

    // Event handlers for application-specific events
    handleNotification(data) {
        console.log('📢 Notification received:', data);
        
        // Emit global event for other components to listen to
        this.emitGlobalEvent('notification:received', data);
        
        // Update notification count
        this.updateNotificationCount();
        
        // Show toast notification if enabled
        if (this.shouldShowToast()) {
            this.showToastNotification(data);
        }
    }

    handleAlertUpdate(data) {
        console.log('🚨 Alert update received:', data);
        this.emitGlobalEvent('alert:updated', data);
    }

    handleReportUpdate(data) {
        console.log('📄 Report update received:', data);
        this.emitGlobalEvent('report:updated', data);
    }

    handleUserActivity(data) {
        console.log('👤 User activity:', data);
        this.emitGlobalEvent('user:activity', data);
    }

    // Utility methods
    emitGlobalEvent(eventName, data = {}) {
        const event = new CustomEvent(eventName, { detail: data });
        window.dispatchEvent(event);
    }

    getUserData() {
        // Try to get user data from various sources
        try {
            // From global variable
            if (window.currentUser) {
                return window.currentUser;
            }
            
            // From sessionStorage
            const userData = sessionStorage.getItem('userData');
            if (userData) {
                return JSON.parse(userData);
            }
            
            // From meta tag
            const metaUser = document.querySelector('meta[name="user-data"]');
            if (metaUser) {
                return JSON.parse(metaUser.getAttribute('content'));
            }
        } catch (error) {
            console.error('Error getting user data:', error);
        }
        
        return null;
    }

    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            statusElement.textContent = connected ? 'Connected' : 'Disconnected';
            statusElement.className = connected ? 'text-success' : 'text-danger';
        }
    }

    updateNotificationCount() {
        // This will be implemented by the notification system
        window.dispatchEvent(new CustomEvent('notifications:update'));
    }

    shouldShowToast() {
        // Check user preferences or page context
        return !document.hidden && 
               !window.location.pathname.includes('/login') &&
               !window.location.pathname.includes('/registration');
    }

    showToastNotification(data) {
        // Create and show toast notification
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-primary border-0';
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <strong>${data.title || 'Notification'}</strong><br>
                    ${data.message || 'New update'}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        const container = document.querySelector('.toast-container') || this.createToastContainer();
        container.appendChild(toast);

        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Remove toast after hide
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });

        // Handle notification updates
this.socket.on('notification-update', (data) => {
    if (data.userId === this.getUserId()) {
        // Refresh notifications if the update is for current user
        if (typeof loadNotifications === 'function') {
            loadNotifications();
        }
    }
});
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
        return container;
    }

    // Public methods for external use
    emit(event, data) {
        if (this.socket && this.isConnected) {
            this.socket.emit(event, data);
        } else {
            console.warn('Socket not connected, cannot emit event:', event);
        }
    }

    on(event, callback) {
        if (this.socket) {
            this.socket.on(event, callback);
        }
    }

    off(event, callback) {
        if (this.socket) {
            this.socket.off(event, callback);
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.isConnected = false;
        }
    }

    reconnect() {
        this.disconnect();
        this.connect();
    }

    getConnectionStatus() {
        return this.isConnected;
    }
}

// Global socket manager instance
let socketManager = null;

// Initialize socket manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        socketManager = new SocketManager();
        window.socketManager = socketManager; // Make it globally available
        
        // Global event listeners for socket events
        window.addEventListener('notification:received', (event) => {
            console.log('Global notification event:', event.detail);
        });
        
        window.addEventListener('socket:connected', () => {
            console.log('Socket connected globally');
        });
        
        window.addEventListener('socket:disconnected', (event) => {
            console.log('Socket disconnected:', event.detail.reason);
        });
        
    } catch (error) {
        console.error('Failed to initialize SocketManager:', error);
    }
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SocketManager;
}