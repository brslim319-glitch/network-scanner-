// Initialize Socket.IO with error handling
const socket = io({
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000
});

// Debug logging for Socket.IO events
socket.on('connect', () => {
    console.log('Connected to server');
    document.getElementById('statusIndicator').textContent = 'Connected';
    document.getElementById('statusIndicator').className = 'status-connected';
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    document.getElementById('statusIndicator').textContent = 'Disconnected';
    document.getElementById('statusIndicator').className = 'status-disconnected';
});

socket.on('connect_error', (error) => {
    console.error('Connection error:', error);
    document.getElementById('statusIndicator').textContent = 'Connection Error';
    document.getElementById('statusIndicator').className = 'status-error';
});

// Theme handling
const themeToggle = document.getElementById('theme-toggle');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
document.body.setAttribute('data-theme', prefersDark ? 'dark' : 'light');

themeToggle.addEventListener('click', () => {
    const currentTheme = document.body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    themeToggle.textContent = newTheme === 'dark' ? '☀️' : '🌙';
});

// Navigation
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const targetView = item.dataset.view;
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        views.forEach(view => {
            view.classList.toggle('active', view.id === `${targetView}View`);
        });
    });
});

// Capture controls
const startButton = document.getElementById('startCapture');
const stopButton = document.getElementById('stopCapture');
const saveButton = document.getElementById('saveCapture');
const filterInput = document.getElementById('filterInput');
const applyFilterButton = document.getElementById('applyFilter');
const saveProfileButton = document.getElementById('save-profile');
const statusIndicator = document.getElementById('statusIndicator');

let isCapturing = false;
let packetCount = 0;

async function updateCaptureStatus(started) {
    isCapturing = started;
    startButton.disabled = started;
    stopButton.disabled = !started;
    statusIndicator.textContent = started ? 'Capturing' : 'Stopped';
    statusIndicator.className = started ? 'status-capturing' : 'status-stopped';
}

startButton.addEventListener('click', async () => {
    try {
        console.log('Starting capture...'); // Debug log
        const response = await fetch('/api/start_capture', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        console.log('Start capture response:', data); // Debug log
        if (data.success) {
            await updateCaptureStatus(true);
            showNotification('Capture started successfully', 'success');
        } else {
            showNotification(data.error || 'Failed to start capture', 'error');
        }
    } catch (error) {
        console.error('Error starting capture:', error);
        showNotification('Error starting capture', 'error');
    }
});

stopButton.addEventListener('click', async () => {
    try {
        const response = await fetch('/api/stop_capture', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (data.success) {
            await updateCaptureStatus(false);
            showNotification('Capture stopped successfully', 'success');
        } else {
            showNotification(data.error || 'Failed to stop capture', 'error');
        }
    } catch (error) {
        console.error('Error stopping capture:', error);
        showNotification('Error stopping capture', 'error');
    }
});

saveButton.addEventListener('click', async () => {
    try {
        const response = await fetch('/api/save_capture', { method: 'POST' });
        const data = await response.json();
        if (data.status === 'success') {
            showNotification(`Capture saved as ${data.filename}`, 'success');
        } else {
            showNotification('Failed to save capture', 'error');
        }
    } catch (error) {
        console.error('Error saving capture:', error);
        showNotification('Error saving capture', 'error');
    }
});

applyFilterButton.addEventListener('click', async () => {
    const filter = filterInput.value;
    try {
        const response = await fetch('/api/set_filter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filter })
        });
        const data = await response.json();
        if (data.status === 'success') {
            showNotification('Filter applied successfully', 'success');
        } else {
            showNotification('Failed to apply filter', 'error');
        }
    } catch (error) {
        console.error('Error applying filter:', error);
        showNotification('Error applying filter', 'error');
    }
});

// Profile modal
const profileModal = document.getElementById('profile-modal');
const saveProfileConfirm = document.getElementById('save-profile-confirm');
const cancelProfile = document.getElementById('cancel-profile');

saveProfileButton.addEventListener('click', () => {
    profileModal.classList.remove('hidden');
});

saveProfileConfirm.addEventListener('click', async () => {
    const name = document.getElementById('profile-name').value;
    const filter = filterInput.value;
    
    if (!name) {
        showNotification('Please enter a profile name', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/save_profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, filter_string: filter })
        });
        const data = await response.json();
        if (data.status === 'success') {
            showNotification('Profile saved successfully', 'success');
            profileModal.classList.add('hidden');
        } else {
            showNotification('Failed to save profile', 'error');
        }
    } catch (error) {
        console.error('Error saving profile:', error);
        showNotification('Error saving profile', 'error');
    }
});

cancelProfile.addEventListener('click', () => {
    profileModal.classList.add('hidden');
});

// Packet handling
const packetTable = document.getElementById('packetTable').getElementsByTagName('tbody')[0];
const MAX_PACKETS = 1000;

socket.on('packet', function(data) {
    console.log('Received packet:', data); // Debug log
    packetCount++;
    document.getElementById('stats').textContent = packetCount;
    
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${new Date(data.timestamp).toLocaleTimeString()}</td>
        <td>${data.src || 'N/A'}</td>
        <td>${data.dst || 'N/A'}</td>
        <td>${data.proto || 'N/A'}</td>
        <td>${data.length || 'N/A'}</td>
        <td>${data.info || 'N/A'}</td>
    `;
    
    packetTable.insertBefore(row, packetTable.firstChild);
    
    // Remove old rows if we exceed MAX_PACKETS
    while (packetTable.children.length > MAX_PACKETS) {
        packetTable.removeChild(packetTable.lastChild);
    }
    
    // Update statistics
    updateStatistics(data);
});

// Statistics and charts
let packetRateData = {
    x: [],
    y: [],
    type: 'scatter',
    mode: 'lines',
    name: 'Packets/sec'
};

let protocolData = {
    labels: [],
    values: [],
    type: 'pie',
    name: 'Protocols'
};

function updateStatistics(data) {
    // Update packet rate
    const now = new Date();
    packetRateData.x.push(now);
    packetRateData.y.push(1);
    
    // Keep only last 60 seconds
    const cutoff = new Date(now - 60000);
    while (packetRateData.x[0] < cutoff) {
        packetRateData.x.shift();
        packetRateData.y.shift();
    }
    
    // Update protocol distribution
    if (data.proto) {
        const protoIndex = protocolData.labels.indexOf(data.proto);
        if (protoIndex === -1) {
            protocolData.labels.push(data.proto);
            protocolData.values.push(1);
        } else {
            protocolData.values[protoIndex]++;
        }
    }
    
    // Update charts
    Plotly.newPlot('packet-rate-chart', [packetRateData], {
        title: 'Packet Rate',
        xaxis: { title: 'Time' },
        yaxis: { title: 'Packets/sec' }
    });
    
    Plotly.newPlot('protocol-chart', [protocolData], {
        title: 'Protocol Distribution'
    });
}

// Alerts handling
const alertsList = document.getElementById('alerts-list');

socket.on('alert', function(data) {
    const alertElement = document.createElement('div');
    alertElement.className = 'alert-item';
    alertElement.innerHTML = `
        <h4>${data.type}</h4>
        <p>${data.description}</p>
        <small>Severity: ${data.severity}</small>
    `;
    
    alertsList.insertBefore(alertElement, alertsList.firstChild);
    showNotification(`New alert: ${data.type}`, 'warning');
});

// GeoIP Map
const map = L.map('geoip-map').setView([0, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

socket.on('ip_info', function(data) {
    if (data.location) {
        const { latitude, longitude, country, city } = data.location;
        L.marker([latitude, longitude])
            .bindPopup(`${city}, ${country}`)
            .addTo(map);
    }
});

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Logout
document.getElementById('logout-button').addEventListener('click', async () => {
    try {
        const response = await fetch('/logout');
        const data = await response.json();
        if (data.success) {
            window.location.href = '/login';
        } else {
            showNotification('Logout failed', 'error');
        }
    } catch (error) {
        console.error('Error logging out:', error);
        showNotification('Error during logout', 'error');
    }
});

// Initialize charts
Plotly.newPlot('packet-rate-chart', [packetRateData], {
    title: 'Packet Rate',
    xaxis: { title: 'Time' },
    yaxis: { title: 'Packets/sec' }
});

Plotly.newPlot('protocol-chart', [protocolData], {
    title: 'Protocol Distribution'
});
