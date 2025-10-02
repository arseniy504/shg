// Search Page Functionality
class SearchPage {
    constructor() {
        this.currentPage = 1;
        this.limit = 20;
        this.totalResults = 0;
        this.currentQuery = '';
        this.apiBase = '/api';
        this.init();
    }

    init() {
        this.parseUrlParams();
        this.setupEventListeners();
        if (this.currentQuery) {
            this.performSearch();
        }
    }

    parseUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        this.currentQuery = urlParams.get('q') || '';
        this.country = urlParams.get('country') || '';
        this.deviceType = urlParams.get('device_type') || '';
        this.riskLevel = urlParams.get('risk') || '';

        // Update form fields
        document.getElementById('searchInput').value = this.currentQuery;
        document.getElementById('countryFilter').value = this.country;
        document.getElementById('deviceTypeFilter').value = this.deviceType;
        document.getElementById('riskFilter').value = this.riskLevel;
    }

    setupEventListeners() {
        document.getElementById('searchButton').addEventListener('click', () => this.performSearch());
        document.getElementById('searchInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSearch();
        });

        // Filter changes
        ['countryFilter', 'deviceTypeFilter', 'riskFilter'].forEach(id => {
            document.getElementById(id).addEventListener('change', () => {
                if (this.currentQuery) {
                    this.performSearch();
                }
            });
        });
    }

    async performSearch(page = 1) {
        this.currentPage = page;
        this.currentQuery = document.getElementById('searchInput').value.trim();
        
        const country = document.getElementById('countryFilter').value;
        const deviceType = document.getElementById('deviceTypeFilter').value;
        const riskLevel = document.getElementById('riskFilter').value;

        this.showLoading();

        try {
            const params = new URLSearchParams({
                q: this.currentQuery,
                country: country,
                device_type: deviceType,
                risk: riskLevel,
                page: page,
                limit: this.limit
            });

            const response = await fetch(`${this.apiBase}/search?${params}`);
            const data = await response.json();

            this.displayResults(data);
            this.updatePagination(data.total_count);
            this.updateUrl(params);

        } catch (error) {
            this.displayError(error);
        } finally {
            this.hideLoading();
        }
    }

    displayResults(data) {
        const resultsContainer = document.getElementById('searchResults');
        const resultsCount = document.getElementById('resultsCount');

        resultsCount.textContent = `${data.total_count.toLocaleString()} devices found`;

        if (!data.devices || data.devices.length === 0) {
            resultsContainer.innerHTML = `
                <div class="loading">
                    <h3>No devices found</h3>
                    <p>Try adjusting your search terms or filters</p>
                </div>
            `;
            return;
        }

        resultsContainer.innerHTML = data.devices.map(device => `
            <div class="device-card">
                <div class="device-header">
                    <div class="device-ip">${device.ip}</div>
                    <div class="device-risk risk-${this.getRiskLevel(device.risk_score)}">
                        ${this.getRiskLevel(device.risk_score).toUpperCase()}
                    </div>
                </div>
                <div class="device-location">
                    ${device.country} • ${device.city} • ${device.isp} • ${device.device_type}
                </div>
                <div class="device-services">
                    ${device.services.slice(0, 8).map(service => `
                        <span class="service-tag">${service.port}/${service.service}</span>
                    `).join('')}
                </div>
                ${device.vulnerabilities && device.vulnerabilities.length > 0 ? `
                    <div class="vulnerabilities-list">
                        <strong>Vulnerabilities:</strong>
                        ${device.vulnerabilities.slice(0, 3).map(vuln => `
                            <div class="vulnerability-item">
                                <strong>${vuln.cve}</strong> (${vuln.risk}): ${vuln.description}
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
                <div class="device-meta">
                    <small>Last seen: ${new Date(device.last_seen).toLocaleDateString()}</small>
                </div>
            </div>
        `).join('');
    }

    getRiskLevel(score) {
        if (score >= 8) return 'critical';
        if (score >= 6) return 'high';
        if (score >= 3) return 'medium';
        return 'low';
    }

    updatePagination(totalResults) {
        this.totalResults = totalResults;
        const totalPages = Math.ceil(totalResults / this.limit);
        const pagination = document.getElementById('pagination');

        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }

        let html = '<div class="pagination-controls">';
        
        // Previous button
        if (this.currentPage > 1) {
            html += `<button onclick="searchPage.performSearch(${this.currentPage - 1})">Previous</button>`;
        }

        // Page numbers
        for (let i = 1; i <= totalPages && i <= 10; i++) {
            if (i === this.currentPage) {
                html += `<button class="active">${i}</button>`;
            } else {
                html += `<button onclick="searchPage.performSearch(${i})">${i}</button>`;
            }
        }

        // Next button
        if (this.currentPage < totalPages) {
            html += `<button onclick="searchPage.performSearch(${this.currentPage + 1})">Next</button>`;
        }

        html += '</div>';
        pagination.innerHTML = html;
    }

    updateUrl(params) {
        const newUrl = `${window.location.pathname}?${params.toString()}`;
        window.history.replaceState({}, '', newUrl);
    }

    showLoading() {
        document.getElementById('loading').classList.remove('hidden');
        document.getElementById('searchResults').classList.add('hidden');
    }

    hideLoading() {
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('searchResults').classList.remove('hidden');
    }

    displayError(error) {
        document.getElementById('searchResults').innerHTML = `
            <div class="loading">
                <h3>Search Error</h3>
                <p>${error.message || 'Failed to perform search'}</p>
            </div>
        `;
    }
}

// Initialize search page
document.addEventListener('DOMContentLoaded', () => {
    window.searchPage = new SearchPage();
});
