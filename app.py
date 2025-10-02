#!/usr/bin/env python3
"""
Real Shodan Clone - Complete Production Website
Author: Colin
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import asyncio
import aiohttp
import sqlite3
import json
import logging
import threading
from datetime import datetime
import nmap
import ipaddress
import random
import os
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RealShodanAPI:
    def __init__(self):
        self.db_path = 'database/real_devices.db'
        self.init_database()
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    def init_database(self):
        """Initialize the database with real device data"""
        os.makedirs('database', exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                ports TEXT,
                services TEXT,
                device_type TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                org TEXT,
                vulnerabilities TEXT,
                risk_score INTEGER,
                first_seen DATETIME,
                last_seen DATETIME,
                banner TEXT,
                os TEXT,
                latitude REAL,
                longitude REAL
            )
        ''')
        
        # Insert some real sample data
        self.insert_sample_data(cursor)
        
        conn.commit()
        conn.close()
        
    def insert_sample_data(self, cursor):
        """Insert realistic sample data"""
        sample_devices = [
            {
                'ip': '93.184.216.34',  # example.com
                'ports': '[80, 443]',
                'services': json.dumps([
                    {'port': 80, 'service': 'HTTP', 'banner': 'nginx/1.25.3'},
                    {'port': 443, 'service': 'HTTPS', 'banner': 'nginx/1.25.3'}
                ]),
                'device_type': 'web_server',
                'country': 'US',
                'city': 'New York',
                'isp': 'Cloudflare',
                'org': 'Example Organization',
                'vulnerabilities': '[]',
                'risk_score': 2,
                'banner': 'nginx/1.25.3',
                'os': 'Linux',
                'latitude': 40.7128,
                'longitude': -74.0060
            },
            {
                'ip': '8.8.8.8',  # Google DNS
                'ports': '[53, 443]',
                'services': json.dumps([
                    {'port': 53, 'service': 'DNS', 'banner': 'Google DNS'},
                    {'port': 443, 'service': 'HTTPS', 'banner': 'Google Frontend'}
                ]),
                'device_type': 'dns_server',
                'country': 'US',
                'city': 'Mountain View',
                'isp': 'Google',
                'org': 'Google LLC',
                'vulnerabilities': '[]',
                'risk_score': 1,
                'banner': 'Google DNS Server',
                'os': 'Linux',
                'latitude': 37.3861,
                'longitude': -122.0839
            },
            {
                'ip': '208.67.222.222',  # OpenDNS
                'ports': '[53, 443]',
                'services': json.dumps([
                    {'port': 53, 'service': 'DNS', 'banner': 'OpenDNS Server'},
                    {'port': 443, 'service': 'HTTPS', 'banner': 'OpenDNS Dashboard'}
                ]),
                'device_type': 'dns_server',
                'country': 'US',
                'city': 'San Francisco',
                'isp': 'Cisco',
                'org': 'OpenDNS',
                'vulnerabilities': '[]',
                'risk_score': 1,
                'banner': 'OpenDNS Server',
                'os': 'Linux',
                'latitude': 37.7749,
                'longitude': -122.4194
            }
        ]
        
        for device in sample_devices:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO devices 
                    (ip, ports, services, device_type, country, city, isp, org, vulnerabilities, risk_score, first_seen, last_seen, banner, os, latitude, longitude)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"), datetime("now"), ?, ?, ?, ?)
                ''', (
                    device['ip'], device['ports'], device['services'], device['device_type'],
                    device['country'], device['city'], device['isp'], device['org'],
                    device['vulnerabilities'], device['risk_score'], device['banner'],
                    device['os'], device['latitude'], device['longitude']
                ))
            except Exception as e:
                logging.error(f"Error inserting sample data: {e}")

    def search_devices(self, query="", device_type="", country="", risk_level="", page=1, limit=50):
        """Search devices in database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # Build WHERE conditions
            conditions = []
            params = []
            
            if query:
                conditions.append('''
                    (ip LIKE ? OR services LIKE ? OR device_type LIKE ? OR 
                     country LIKE ? OR city LIKE ? OR isp LIKE ? OR org LIKE ? OR banner LIKE ?)
                ''')
                search_term = f'%{query}%'
                params.extend([search_term] * 8)
                
            if device_type:
                conditions.append('device_type = ?')
                params.append(device_type)
                
            if country:
                conditions.append('country = ?')
                params.append(country)
                
            if risk_level:
                risk_ranges = {
                    'critical': (8, 10),
                    'high': (6, 7), 
                    'medium': (3, 5),
                    'low': (0, 2)
                }
                if risk_level in risk_ranges:
                    min_risk, max_risk = risk_ranges[risk_level]
                    conditions.append('risk_score BETWEEN ? AND ?')
                    params.extend([min_risk, max_risk])
            
            where_clause = ' AND '.join(conditions) if conditions else '1=1'
            
            # Get total count
            cursor.execute(f'SELECT COUNT(*) FROM devices WHERE {where_clause}', params)
            total_count = cursor.fetchone()[0]
            
            # Get paginated results
            offset = (page - 1) * limit
            cursor.execute(f'''
                SELECT * FROM devices 
                WHERE {where_clause}
                ORDER BY last_seen DESC 
                LIMIT ? OFFSET ?
            ''', params + [limit, offset])
            
            devices = []
            for row in cursor.fetchall():
                device = dict(row)
                # Parse JSON fields
                device['ports'] = json.loads(device['ports']) if device['ports'] else []
                device['services'] = json.loads(device['services']) if device['services'] else []
                device['vulnerabilities'] = json.loads(device['vulnerabilities']) if device['vulnerabilities'] else []
                devices.append(device)
            
            return {
                'devices': devices,
                'total_count': total_count,
                'page': page,
                'limit': limit
            }
            
        except Exception as e:
            logging.error(f"Search error: {e}")
            return {'devices': [], 'total_count': 0, 'page': page, 'limit': limit}
        finally:
            conn.close()

    def get_stats(self):
        """Get website statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT COUNT(*) FROM devices')
            total_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM devices WHERE risk_score > 5')
            vulnerable_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT country) FROM devices WHERE country != "Unknown"')
            countries = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT device_type) FROM devices')
            device_types = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                GROUP BY device_type 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_devices = {row[0]: row[1] for row in cursor.fetchall()}
            
            return {
                'total_devices': total_devices,
                'vulnerable_devices': vulnerable_devices,
                'countries': countries,
                'device_types': device_types,
                'top_devices': top_devices,
                'last_updated': datetime.now().isoformat()
            }
            
        finally:
            conn.close()

    async def scan_single_device(self, ip):
        """Scan a single device using nmap"""
        try:
            # Validate IP
            ipaddress.ip_address(ip)
            
            # Use nmap to scan
            nm = nmap.PortScanner()
            nm.scan(ip, '21,22,23,80,443,8080,8443,3389,53', arguments='-T4 -sV --host-timeout 30s')
            
            if ip in nm.all_hosts():
                return await self.process_scan_results(ip, nm[ip])
            else:
                return {'error': 'Host not found or not responding'}
                
        except Exception as e:
            return {'error': str(e)}

    async def process_scan_results(self, ip, nmap_data):
        """Process nmap scan results"""
        try:
            services = []
            open_ports = []
            
            for proto in nmap_data.all_protocols():
                for port, port_data in nmap_data[proto].items():
                    if port_data['state'] == 'open':
                        open_ports.append(port)
                        services.append({
                            'port': port,
                            'service': port_data.get('name', 'unknown'),
                            'banner': f"{port_data.get('product', '')} {port_data.get('version', '')}".strip(),
                            'protocol': proto
                        })
            
            if not services:
                return {'error': 'No open ports found'}
            
            device_type = self.determine_device_type(services)
            geo_info = await self.get_geolocation(ip)
            vulnerabilities = self.scan_vulnerabilities(services)
            
            device_data = {
                'ip': ip,
                'ports': open_ports,
                'services': services,
                'device_type': device_type,
                'country': geo_info.get('country', 'Unknown'),
                'city': geo_info.get('city', 'Unknown'),
                'isp': geo_info.get('isp', 'Unknown'),
                'org': geo_info.get('org', 'Unknown'),
                'vulnerabilities': vulnerabilities,
                'risk_score': self.calculate_risk_score(vulnerabilities),
                'banner': services[0]['banner'] if services else '',
                'os': nmap_data.get('osmatch', [{}])[0].get('name', 'Unknown') if nmap_data.get('osmatch') else 'Unknown',
                'last_seen': datetime.now().isoformat()
            }
            
            # Save to database
            self.save_device(device_data)
            
            return device_data
            
        except Exception as e:
            logging.error(f"Error processing scan results: {e}")
            return {'error': 'Failed to process scan results'}

    def determine_device_type(self, services):
        """Determine device type from services"""
        service_text = ' '.join([s['service'].lower() + ' ' + s['banner'].lower() for s in services])
        
        if any(x in service_text for x in ['http', 'apache', 'nginx', 'iis']):
            return 'web_server'
        elif any(x in service_text for x in ['ssh', 'telnet']):
            return 'network_device'
        elif any(x in service_text for x in ['ftp', 'sftp']):
            return 'file_server'
        elif any(x in service_text for x in ['mysql', 'postgresql', 'mongodb']):
            return 'database'
        elif any(x in service_text for x in ['dns', 'bind']):
            return 'dns_server'
        elif any(x in service_text for x in ['camera', 'streaming']):
            return 'camera'
        else:
            return 'unknown'

    async def get_geolocation(self, ip):
        """Get IP geolocation"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}') as response:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'lat': data.get('lat', 0),
                            'lon': data.get('lon', 0)
                        }
        except:
            pass
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

    def scan_vulnerabilities(self, services):
        """Scan for vulnerabilities"""
        vulnerabilities = []
        
        for service in services:
            banner = service['banner'].lower()
            port = service['port']
            
            # Check for common vulnerabilities
            if 'apache/2.4.49' in banner or 'apache/2.4.50' in banner:
                vulnerabilities.append({
                    'cve': 'CVE-2021-41773',
                    'description': 'Apache Path Traversal Vulnerability',
                    'risk': 'high',
                    'service': f'{service["service"]}:{port}'
                })
                
            if 'openssh 7.0' in banner and 'openssh 7.1' not in banner:
                vulnerabilities.append({
                    'cve': 'CVE-2016-0777',
                    'description': 'OpenSSH Information Disclosure',
                    'risk': 'medium',
                    'service': f'{service["service"]}:{port}'
                })
                
            if 'vsftpd 2.3.4' in banner:
                vulnerabilities.append({
                    'cve': 'CVE-2011-2523',
                    'description': 'vsftpd Backdoor Command Execution',
                    'risk': 'critical',
                    'service': f'{service["service"]}:{port}'
                })
        
        return vulnerabilities

    def calculate_risk_score(self, vulnerabilities):
        """Calculate risk score"""
        if not vulnerabilities:
            return 0
            
        risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        return min(sum(risk_weights.get(vuln['risk'], 1) for vuln in vulnerabilities), 10)

    def save_device(self, device_data):
        """Save device to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO devices 
                (ip, ports, services, device_type, country, city, isp, org, vulnerabilities, risk_score, last_seen, banner, os)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"), ?, ?)
            ''', (
                device_data['ip'],
                json.dumps(device_data.get('ports', [])),
                json.dumps(device_data.get('services', [])),
                device_data.get('device_type', 'unknown'),
                device_data.get('country', 'Unknown'),
                device_data.get('city', 'Unknown'),
                device_data.get('isp', 'Unknown'),
                device_data.get('org', 'Unknown'),
                json.dumps(device_data.get('vulnerabilities', [])),
                device_data.get('risk_score', 0),
                device_data.get('banner', ''),
                device_data.get('os', 'Unknown')
            ))
            
            conn.commit()
            logging.info(f"Saved device: {device_data['ip']}")
            
        except Exception as e:
            logging.error(f"Error saving device: {e}")
        finally:
            conn.close()

# Flask Application
app = Flask(__name__)
CORS(app)
shodan_api = RealShodanAPI()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search_page():
    return render_template('search.html')

@app.route('/map')
def map_page():
    return render_template('map.html')

@app.route('/api')
def api_page():
    return render_template('api.html')

@app.route('/stats')
def stats_page():
    return render_template('stats.html')

# API Routes
@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')
    device_type = request.args.get('device_type', '')
    country = request.args.get('country', '')
    risk_level = request.args.get('risk', '')
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    
    results = shodan_api.search_devices(query, device_type, country, risk_level, page, limit)
    return jsonify(results)

@app.route('/api/scan')
async def api_scan():
    ip = request.args.get('ip', '')
    if not ip:
        return jsonify({'error': 'IP address required'})
    
    result = await shodan_api.scan_single_device(ip)
    return jsonify(result)

@app.route('/api/stats')
def api_stats():
    stats = shodan_api.get_stats()
    return jsonify(stats)

@app.route('/api/devices/map')
def api_devices_map():
    """Get device data for map"""
    conn = sqlite3.connect(shodan_api.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT ip, country, city, device_type, risk_score, latitude, longitude 
        FROM devices 
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        LIMIT 1000
    ''')
    
    devices = []
    for row in cursor.fetchall():
        devices.append(dict(row))
    
    conn.close()
    return jsonify(devices)

@app.route('/api/random_scan')
async def api_random_scan():
    """Scan random public IPs to populate database"""
    def generate_random_ip():
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    # Generate 10 random IPs to scan
    ips = [generate_random_ip() for _ in range(10)]
    results = []
    
    for ip in ips:
        try:
            result = await shodan_api.scan_single_device(ip)
            if 'error' not in result:
                results.append(result)
        except:
            continue
    
    return jsonify({
        'message': f'Scanned {len(ips)} random IPs, found {len(results)} devices',
        'devices_found': len(results)
    })

if __name__ == '__main__':
    # Create templates directory
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    print("🌍 Real Shodan Clone Starting...")
    print("📊 Access at: http://localhost:5000")
    print("🔍 Features: Real device scanning, vulnerability detection, global search")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
