// GlobalShodan - Main Application
class GlobalShodan {
    constructor() {
        this.apiBase = '/api';
        this.init();
    }

    init() {
        this.loadStats();
        this.loadRecentDevices();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Main search
        document.getElementById('searchButton')?.addEventListener('click', () => this.performSearch());
        document.getElementById('mainSearch')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSearch();
        });

        // Quick scan
        document.getElementById('scanIpButton')?.addEventListener('click', () => this.scanIp());
        document.getElementById('ipScanInput')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scanIp();
        });

        // Random scan
        document.getElementById('scanRandom')?.addEventListener('click', () => this.scanRandomIPs());
    }

    async performSearch() {
        const query = document.getElementById('mainSearch').value.trim();
        if (!query) return;

        const params = new URLSearchParams({
            q: query,
            country: document.getElementById('countryFilter').value,
            device_type: document.getElementById('deviceTypeFilter').value,
            risk: document.getElementById('riskFilter').value
        });

        window.location.href = `/search?${params.toString()}`;
    }

    async loadStats() {
        try {
            const response = await fetch(`${this.apiBase}/stats`);
            const stats = await response.json();
            
            document.getElementById('totalDevices').textContent = stats.total_devices.toLocaleString();
            document.getElementById('vulnerableDevices').textContent = stats.vulnerable_devices.toLocaleString();
            document.getElementById('countries').textContent = stats.countries;
            document.getElementById('deviceTypes').textContent = stats.device_types;
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async loadRecentDevices() {
        try {
            const response = await fetch(`${this.apiBase}/search?limit=6`);
            const data = await response.json();
            
            this.displayDevices(data.devices, 'recentDevices');
        } catch (error) {
            console.error('Error loading recent devices:', error);
            document.getElementById('recentDevices').innerHTML = 
                '<div class="loading">Error loading devices</div>';
        }
    }

    displayDevices(devices, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!devices || devices.length === 0) {
            container.innerHTML = '<div class="loading">No devices found</div>';
            return;
        }

        container.innerHTML = devices.map(device => `
            <div class="device-card">
                <div class="device-header">
                    <div class="device-ip">${device.ip}</div>
                    <div class="device-risk risk-${this.getRiskLevel(device.risk_score)}">
                        ${this.getRiskLevel(device.risk_score).toUpperCase()}
                    </div>
                </div>
                <div class="device-location">
                    ${device.country} • ${device.city} • ${device.device_type}
                </div>
                <div class="device-services">
                    ${device.services.slice(0, 5).map(service => `
                        <span class="service-tag">${service.port}/${service.service}</span>
                    `).join('')}
                </div>
                ${device.vulnerabilities && device.vulnerabilities.length > 0 ? `
                    <div class="vulnerabilities-list">
                        ${device.vulnerabilities.slice(0, 2).map(vuln => `
                            <div class="vulnerability-item">
                                <strong>${vuln.cve}</strong>: ${vuln.description}
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `).join('');
    }

    getRiskLevel(score) {
        if (score >= 8) return 'critical';
        if (score >= 6) return 'high';
        if (score >= 3) return 'medium';
        return 'low';
    }

    async scanIp() {
        const ipInput = document.getElementById('ipScanInput');
        const resultsDiv = document.getElementById('scanResults');
        const ip = ipInput.value.trim();
        
        if (!ip) {
            resultsDiv.innerHTML = '<div class="error">Please enter an IP address</div>';
            return;
        }

        resultsDiv.innerHTML = '<div class="loading">Scanning IP address...</div>';

        try {
            const response = await fetch(`${this.apiBase}/scan?ip=${encodeURIComponent(ip)}`);
            const result = await response.json();
            
            if (result.error) {
                resultsDiv.innerHTML = `<div class="error">Error: ${result.error}</div>`;
            } else {
                resultsDiv.innerHTML = `
                    <div class="device-card">
                        <div class="device-header">
                            <div class="device-ip">${result.ip}</div>
                            <div class="device-risk risk-${this.getRiskLevel(result.risk_score)}">
                                ${this.getRiskLevel(result.risk_score).toUpperCase()}
                            </div>
                        </div>
                        <div class="device-location">
                            ${result.country} • ${result.city} • ${result.device_type}
                        </div>
                        <div class="device-services">
                            ${result.services.map(service => `
                                <span class="service-tag">${service.port}/${service.service}</span>
                            `).join('')}
                        </div>
                        ${result.vulnerabilities && result.vulnerabilities.length > 0 ? `
                            <div class="vulnerabilities-list">
                                <strong>Vulnerabilities Found:</strong>
                                ${result.vulnerabilities.map(vuln => `
                                    <div class="vulnerability-item">
                                        <strong>${vuln.cve}</strong> (${vuln.risk}): ${vuln.description}
                                    </div>
                                `).join('')}
                            </div>
                        ` : '<p>No vulnerabilities detected</p>'}
                    </div>
                `;
            }
        } catch (error) {
            resultsDiv.innerHTML = `<div class="error">Scan failed: ${error.message}</div>`;
        }
    }

    async scanRandomIPs() {
        const button = document.getElementById('scanRandom');
        const originalText = button.textContent;
        
        button.textContent = 'Scanning...';
        button.disabled = true;

        try {
            const response = await fetch(`${this.apiBase}/random_scan`);
            const result = await response.json();
            
            alert(result.message);
            // Reload recent devices to show new scans
            this.loadRecentDevices();
        } catch (error) {
            alert('Scan failed: ' + error.message);
        } finally {
            button.textContent = originalText;
            button.disabled = false;
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.shodanApp = new GlobalShodan();
});
