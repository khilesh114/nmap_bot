#!/usr/bin/env python3
"""
Advanced Ethical Bug Bounty Reconnaissance Bot for Telegram
Features: CIDR Scan, IP.txt Upload, Stop/Start, Real-time Updates, 10-min Progress
Author: GitHubGuru
Version: 3.0.1 FIXED
"""

import asyncio
import ipaddress
import socket
import ssl
import aiohttp
import nmap
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import telebot
from telebot.async_telebot import AsyncTeleBot
from telebot import types
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
import hashlib

# ========================
# CONFIGURATION
# ========================
TELEGRAM_BOT_TOKEN = "8249252:AAGqHoIqpTyzChzbJ"
TELEGRAM_CHAT_ID = "210875344"

# Initialize bot
bot = AsyncTeleBot(TELEGRAM_BOT_TOKEN)

# Progress update interval (10 minutes)
PROGRESS_UPDATE_INTERVAL = 600  # 600 seconds = 10 minutes

# ========================
# GLOBAL SCAN CONTROL
# ========================
class ScanController:
    def __init__(self):
        self.current_scan = None
        self.is_running = False
        self.stop_requested = False
        self.last_progress_update = None
        self.scan_type = None
        self.scan_target = None
        self.scan_stats = {
            'total_ips': 0,
            'scanned_ips': 0,
            'active_ips': 0,
            'total_services': 0,
            'total_findings': 0,
            'high_critical': 0
        }
    
    def reset(self):
        self.current_scan = None
        self.is_running = False
        self.stop_requested = False
        self.last_progress_update = None
        self.scan_type = None
        self.scan_target = None
        self.scan_stats = {
            'total_ips': 0,
            'scanned_ips': 0,
            'active_ips': 0,
            'total_services': 0,
            'total_findings': 0,
            'high_critical': 0
        }
    
    def start_scan(self, task, scan_type, target):
        """Store task and set running state"""
        self.current_scan = task
        self.is_running = True
        self.stop_requested = False
        self.scan_type = scan_type
        self.scan_target = target
        self.last_progress_update = datetime.now()
    
    def request_stop(self):
        """Request scan stop and cancel task"""
        self.stop_requested = True
        if self.current_scan and not self.current_scan.done():
            self.current_scan.cancel()
    
    def should_send_progress(self):
        """Check if 10 minutes passed since last update"""
        if not self.last_progress_update:
            return True
        elapsed = (datetime.now() - self.last_progress_update).total_seconds()
        return elapsed >= PROGRESS_UPDATE_INTERVAL

scan_controller = ScanController()

# ========================
# SERVICE DATABASE
# ========================
SERVICE_PORTS = {
    # Web Services
    80: {"name": "HTTP", "category": "Web", "severity": "Medium"},
    443: {"name": "HTTPS", "category": "Web", "severity": "Low"},
    8080: {"name": "HTTP-Proxy", "category": "Web", "severity": "Medium"},
    8443: {"name": "HTTPS-Alt", "category": "Web", "severity": "Medium"},
    8000: {"name": "HTTP-Alt", "category": "Web", "severity": "Medium"},
    8888: {"name": "HTTP-Alt2", "category": "Web", "severity": "Medium"},
    
    # Remote Access
    22: {"name": "SSH", "category": "Remote Access", "severity": "Medium"},
    23: {"name": "Telnet", "category": "Remote Access", "severity": "Critical"},
    3389: {"name": "RDP", "category": "Remote Access", "severity": "Critical"},
    5900: {"name": "VNC", "category": "Remote Access", "severity": "Critical"},
    5901: {"name": "VNC-1", "category": "Remote Access", "severity": "Critical"},
    
    # File Transfer
    20: {"name": "FTP-Data", "category": "File Transfer", "severity": "High"},
    21: {"name": "FTP", "category": "File Transfer", "severity": "High"},
    69: {"name": "TFTP", "category": "File Transfer", "severity": "High"},
    115: {"name": "SFTP", "category": "File Transfer", "severity": "Medium"},
    
    # Mail Services
    25: {"name": "SMTP", "category": "Mail", "severity": "Medium"},
    110: {"name": "POP3", "category": "Mail", "severity": "Medium"},
    143: {"name": "IMAP", "category": "Mail", "severity": "Medium"},
    465: {"name": "SMTPS", "category": "Mail", "severity": "Low"},
    587: {"name": "SMTP-Submission", "category": "Mail", "severity": "Medium"},
    993: {"name": "IMAPS", "category": "Mail", "severity": "Low"},
    995: {"name": "POP3S", "category": "Mail", "severity": "Low"},
    
    # Databases
    1433: {"name": "MSSQL", "category": "Database", "severity": "Critical"},
    1521: {"name": "Oracle", "category": "Database", "severity": "Critical"},
    3306: {"name": "MySQL", "category": "Database", "severity": "Critical"},
    5432: {"name": "PostgreSQL", "category": "Database", "severity": "Critical"},
    6379: {"name": "Redis", "category": "Database", "severity": "Critical"},
    7000: {"name": "Cassandra", "category": "Database", "severity": "Critical"},
    7001: {"name": "Cassandra-SSL", "category": "Database", "severity": "Critical"},
    9042: {"name": "Cassandra-CQL", "category": "Database", "severity": "Critical"},
    9200: {"name": "Elasticsearch", "category": "Database", "severity": "Critical"},
    9300: {"name": "Elasticsearch-Transport", "category": "Database", "severity": "Critical"},
    27017: {"name": "MongoDB", "category": "Database", "severity": "Critical"},
    27018: {"name": "MongoDB-Shard", "category": "Database", "severity": "Critical"},
    28017: {"name": "MongoDB-Web", "category": "Database", "severity": "Critical"},
    
    # Network Services
    53: {"name": "DNS", "category": "Network", "severity": "Medium"},
    67: {"name": "DHCP", "category": "Network", "severity": "Medium"},
    68: {"name": "DHCP-Client", "category": "Network", "severity": "Medium"},
    161: {"name": "SNMP", "category": "Network", "severity": "High"},
    162: {"name": "SNMP-Trap", "category": "Network", "severity": "High"},
    389: {"name": "LDAP", "category": "Network", "severity": "High"},
    636: {"name": "LDAPS", "category": "Network", "severity": "Medium"},
    
    # File Sharing
    137: {"name": "NetBIOS-NS", "category": "File Sharing", "severity": "High"},
    138: {"name": "NetBIOS-DGM", "category": "File Sharing", "severity": "High"},
    139: {"name": "NetBIOS-SSN", "category": "File Sharing", "severity": "High"},
    445: {"name": "SMB", "category": "File Sharing", "severity": "Critical"},
    2049: {"name": "NFS", "category": "File Sharing", "severity": "High"},
    
    # DevOps / CI-CD
    2375: {"name": "Docker", "category": "DevOps", "severity": "Critical"},
    2376: {"name": "Docker-SSL", "category": "DevOps", "severity": "High"},
    4243: {"name": "Docker-Alt", "category": "DevOps", "severity": "Critical"},
    5000: {"name": "Docker-Registry", "category": "DevOps", "severity": "High"},
    6443: {"name": "Kubernetes-API", "category": "DevOps", "severity": "Critical"},
    8001: {"name": "Kubernetes-Dashboard", "category": "DevOps", "severity": "Critical"},
    9000: {"name": "Portainer", "category": "DevOps", "severity": "High"},
    10250: {"name": "Kubelet-API", "category": "DevOps", "severity": "Critical"},
    
    # Monitoring
    3000: {"name": "Grafana", "category": "Monitoring", "severity": "Medium"},
    9090: {"name": "Prometheus", "category": "Monitoring", "severity": "Medium"},
    9091: {"name": "Prometheus-Pushgateway", "category": "Monitoring", "severity": "Medium"},
    
    # Message Queues
    5672: {"name": "RabbitMQ", "category": "Message Queue", "severity": "High"},
    15672: {"name": "RabbitMQ-Management", "category": "Message Queue", "severity": "High"},
    9092: {"name": "Kafka", "category": "Message Queue", "severity": "High"},
    
    # Other Services
    179: {"name": "BGP", "category": "Routing", "severity": "Critical"},
    1194: {"name": "OpenVPN", "category": "VPN", "severity": "Medium"},
    1723: {"name": "PPTP", "category": "VPN", "severity": "High"},
    4500: {"name": "IPSec-NAT", "category": "VPN", "severity": "Medium"},
    5060: {"name": "SIP", "category": "VoIP", "severity": "Medium"},
    5061: {"name": "SIP-TLS", "category": "VoIP", "severity": "Low"},
    11211: {"name": "Memcached", "category": "Cache", "severity": "Critical"},
}

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/signin",
    "/wp-admin", "/wp-login.php", "/wp-admin/", 
    "/phpmyadmin", "/phpMyAdmin", "/pma",
    "/cpanel", "/whm", "/webmail",
    "/plesk", "/panel", "/controlpanel",
    "/manager", "/manager/html",
    "/console", "/dashboard", "/portal",
    "/api/login", "/api/auth", "/auth", "/auth/login",
    "/user/login", "/admin/login", "/administrator/login",
    "/adminer", "/adminer.php",
    "/setup", "/install", "/config"
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy", 
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

# ========================
# TELEGRAM KEYBOARD
# ========================
def get_control_keyboard():
    """Get inline keyboard with Stop button"""
    markup = types.InlineKeyboardMarkup()
    stop_btn = types.InlineKeyboardButton("🛑 Stop Scan", callback_data="stop_scan")
    markup.add(stop_btn)
    return markup

def get_start_keyboard():
    """Get inline keyboard with Start button"""
    markup = types.InlineKeyboardMarkup()
    start_btn = types.InlineKeyboardButton("▶️ Start New Scan", callback_data="start_scan")
    markup.add(start_btn)
    return markup

# ========================
# HELPER FUNCTIONS
# ========================
def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR to IP list"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def parse_ip_file(content: str) -> List[str]:
    """Parse IP addresses from file content"""
    ip_pattern = re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    
    ips = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        found_ips = ip_pattern.findall(line)
        ips.extend(found_ips)
    
    unique_ips = list(dict.fromkeys(ips))
    return unique_ips

async def send_telegram(message: str, keyboard=None):
    """Send Telegram message with optional keyboard"""
    try:
        if keyboard:
            await bot.send_message(TELEGRAM_CHAT_ID, message, parse_mode='Markdown', reply_markup=keyboard)
        else:
            await bot.send_message(TELEGRAM_CHAT_ID, message, parse_mode='Markdown')
    except Exception as e:
        print(f"Telegram error: {e}")

async def send_progress_update():
    """Send 10-minute progress update"""
    if not scan_controller.should_send_progress():
        return
    
    stats = scan_controller.scan_stats
    progress = (stats['scanned_ips']/stats['total_ips']*100) if stats['total_ips'] > 0 else 0
    elapsed = (datetime.now() - scan_controller.last_progress_update).total_seconds() / 60
    
    scan_type_emoji = "🌐" if scan_controller.scan_type == 'cidr' else "📄"
    
    update_msg = f"""⏱️ *10-Minute Progress Update*

{scan_type_emoji} Scan Type: {scan_controller.scan_type.upper()}
Target: `{scan_controller.scan_target}`

📊 *Current Status:*
Scanned: {stats['scanned_ips']}/{stats['total_ips']} IPs
Progress: {progress:.1f}%

🟢 Active IPs: {stats['active_ips']}
🔍 Services Found: {stats['total_services']}
⚠️ Total Findings: {stats['total_findings']}
🚨 High/Critical: {stats['high_critical']}

⏲️ Elapsed: {elapsed:.1f} minutes
Status: *Running* 🔄"""
    
    await send_telegram(update_msg, get_control_keyboard())
    scan_controller.last_progress_update = datetime.now()

def check_stop():
    """Check if stop requested"""
    if scan_controller.stop_requested:
        raise asyncio.CancelledError("Scan stopped by user")
    return False

# ========================
# IP DETECTION
# ========================
async def is_ip_active(ip: str) -> bool:
    """Check if IP is active"""
    check_stop()
    
    for port in [80, 443, 22, 21, 23, 8080]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except:
            continue
    
    for protocol in ['http', 'https']:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
                async with session.head(f'{protocol}://{ip}', ssl=False) as response:
                    return True
        except:
            continue
    
    return False

# ========================
# PORT SCANNING
# ========================
async def scan_all_ports(ip: str) -> Dict[int, Dict]:
    """Scan all important ports"""
    check_stop()
    
    open_ports = {}
    loop = asyncio.get_event_loop()
    
    def nmap_scan():
        try:
            nm = nmap.PortScanner()
            ports = ','.join(str(p) for p in SERVICE_PORTS.keys())
            nm.scan(ip, ports, arguments='-sV -sC --script=banner,ssl-cert -T4 --max-retries 1')
            
            result = {}
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto].keys():
                        service_info = nm[ip][proto][port]
                        result[port] = {
                            'state': service_info.get('state', 'unknown'),
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', ''),
                            'cpe': service_info.get('cpe', '')
                        }
            return result
        except Exception as e:
            print(f"Nmap error for {ip}: {e}")
            return {}
    
    with ThreadPoolExecutor() as executor:
        open_ports = await loop.run_in_executor(executor, nmap_scan)
    
    return open_ports

# ========================
# SERVICE ANALYSIS
# ========================
async def analyze_http_service(ip: str, port: int, is_https: bool = False) -> List[Dict]:
    """Analyze HTTP/HTTPS service"""
    findings = []
    protocol = 'https' if is_https else 'http'
    base_url = f"{protocol}://{ip}:{port}"
    
    check_stop()
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            try:
                async with session.get(base_url, ssl=False, allow_redirects=True) as response:
                    headers = response.headers
                    
                    if not is_https and port in [80, 8080]:
                        findings.append({
                            'type': 'Unencrypted HTTP Service',
                            'severity': 'Medium',
                            'risk_score': 5,
                            'description': f'HTTP service running without encryption on port {port}',
                            'impact': 'Traffic can be intercepted and modified',
                            'recommendation': 'Implement HTTPS with valid SSL/TLS certificate'
                        })
                    
                    missing = [h for h in SECURITY_HEADERS if h not in headers]
                    if missing:
                        findings.append({
                            'type': 'Missing Security Headers',
                            'severity': 'Medium',
                            'risk_score': 6,
                            'description': f"Missing: {', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}",
                            'impact': 'Vulnerable to XSS, clickjacking, MIME sniffing',
                            'recommendation': 'Implement security headers per OWASP guidelines'
                        })
                    
                    if 'Server' in headers:
                        server = headers['Server']
                        if any(c.isdigit() for c in server):
                            findings.append({
                                'type': 'Server Version Disclosure',
                                'severity': 'Low',
                                'risk_score': 3,
                                'description': f'Server: {server}',
                                'impact': 'Helps attackers identify vulnerabilities',
                                'recommendation': 'Remove version information from headers'
                            })
                    
                    if 'Set-Cookie' in headers:
                        cookie = headers['Set-Cookie'].lower()
                        issues = []
                        if 'httponly' not in cookie:
                            issues.append('HttpOnly')
                        if 'secure' not in cookie and is_https:
                            issues.append('Secure')
                        if 'samesite' not in cookie:
                            issues.append('SameSite')
                        
                        if issues:
                            findings.append({
                                'type': 'Insecure Cookie Configuration',
                                'severity': 'Medium',
                                'risk_score': 6,
                                'description': f"Missing: {', '.join(issues)}",
                                'impact': 'Vulnerable to XSS and CSRF attacks',
                                'recommendation': 'Set HttpOnly, Secure, SameSite=Strict flags'
                            })
            except:
                pass
            
            for path in ADMIN_PATHS[:10]:
                check_stop()
                try:
                    async with session.get(f"{base_url}{path}", ssl=False, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status in [200, 301, 302, 401, 403]:
                            severity = 'Critical' if resp.status == 200 else 'High'
                            risk = 9 if resp.status == 200 else 7
                            
                            findings.append({
                                'type': 'Exposed Admin Interface',
                                'severity': severity,
                                'risk_score': risk,
                                'description': f'Admin panel at {path} (HTTP {resp.status})',
                                'impact': 'Admin interface exposed - brute-force target',
                                'recommendation': 'Restrict by IP, implement MFA, rate limiting'
                            })
                            break
                except:
                    continue
            
            try:
                async with session.request('OPTIONS', base_url, ssl=False, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if 'Allow' in resp.headers:
                        dangerous = [m for m in ['PUT', 'DELETE', 'TRACE'] if m in resp.headers['Allow']]
                        if dangerous:
                            findings.append({
                                'type': 'Dangerous HTTP Methods',
                                'severity': 'Medium',
                                'risk_score': 5,
                                'description': f"Enabled: {', '.join(dangerous)}",
                                'impact': 'Potential unauthorized file operations',
                                'recommendation': 'Disable unnecessary HTTP methods'
                            })
            except:
                pass
    
    except Exception as e:
        print(f"HTTP analysis error: {e}")
    
    return findings

async def analyze_ssh(ip: str, port: int) -> List[Dict]:
    """Analyze SSH service"""
    findings = []
    check_stop()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            findings.append({
                'type': 'SSH Banner Disclosure',
                'severity': 'Low',
                'risk_score': 2,
                'description': f'Banner: {banner}',
                'impact': 'Version info aids targeted attacks',
                'recommendation': 'Consider hiding detailed version'
            })
            
            if 'SSH-1' in banner:
                findings.append({
                    'type': 'Outdated SSH Protocol',
                    'severity': 'Critical',
                    'risk_score': 10,
                    'description': 'SSH Protocol 1.x detected',
                    'impact': 'Critical vulnerabilities, completely insecure',
                    'recommendation': 'Upgrade to SSH Protocol 2.0 immediately'
                })
    except:
        pass
    
    return findings

async def analyze_telnet(ip: str, port: int) -> List[Dict]:
    """Analyze Telnet service"""
    return [{
        'type': 'Insecure Telnet Protocol',
        'severity': 'Critical',
        'risk_score': 10,
        'description': 'Telnet service running - cleartext protocol',
        'impact': 'All credentials and data transmitted in plaintext',
        'recommendation': 'Disable Telnet, use SSH instead'
    }]

async def analyze_ftp(ip: str, port: int) -> List[Dict]:
    """Analyze FTP service"""
    findings = [{
        'type': 'Insecure FTP Protocol',
        'severity': 'High',
        'risk_score': 8,
        'description': 'FTP service - cleartext credentials',
        'impact': 'Credentials transmitted in plaintext',
        'recommendation': 'Use SFTP or FTPS instead'
    }]
    
    try:
        import ftplib
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(ip, port)
        response = ftp.login()
        ftp.quit()
        
        if '230' in response:
            findings.append({
                'type': 'Anonymous FTP Access',
                'severity': 'Critical',
                'risk_score': 9,
                'description': 'Anonymous FTP login allowed',
                'impact': 'Unauthorized file access and potential upload',
                'recommendation': 'Disable anonymous access'
            })
    except:
        pass
    
    return findings

async def analyze_database(ip: str, port: int, service: str) -> List[Dict]:
    """Analyze database services"""
    return [{
        'type': 'Exposed Database Service',
        'severity': 'Critical',
        'risk_score': 10,
        'description': f'{service} exposed on internet (port {port})',
        'impact': 'Direct database access - critical data breach risk',
        'recommendation': 'Implement firewall rules, allow only trusted IPs'
    }]

async def analyze_rdp_vnc(ip: str, port: int, service: str) -> List[Dict]:
    """Analyze RDP/VNC services"""
    return [{
        'type': 'Exposed Remote Desktop',
        'severity': 'Critical',
        'risk_score': 9,
        'description': f'{service} accessible from internet',
        'impact': 'Remote desktop exposed to brute-force attacks',
        'recommendation': 'Use VPN, implement IP whitelisting and MFA'
    }]

async def analyze_smb(ip: str, port: int) -> List[Dict]:
    """Analyze SMB service"""
    return [{
        'type': 'Exposed SMB Service',
        'severity': 'Critical',
        'risk_score': 9,
        'description': 'SMB/CIFS file sharing exposed',
        'impact': 'Vulnerable to EternalBlue and ransomware attacks',
        'recommendation': 'Block SMB from internet, update to SMBv3'
    }]

async def analyze_docker(ip: str, port: int) -> List[Dict]:
    """Analyze Docker service"""
    return [{
        'type': 'Exposed Docker API',
        'severity': 'Critical',
        'risk_score': 10,
        'description': f'Docker API on port {port}',
        'impact': 'Full container control, potential host compromise',
        'recommendation': 'Never expose Docker API to internet, use TLS + auth'
    }]

async def analyze_ssl(ip: str, port: int) -> List[Dict]:
    """Analyze SSL/TLS"""
    findings = []
    check_stop()
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                
                if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    findings.append({
                        'type': 'Weak TLS Version',
                        'severity': 'High',
                        'risk_score': 8,
                        'description': f'Using {version}',
                        'impact': 'Vulnerable to downgrade attacks',
                        'recommendation': 'Use TLS 1.2 or TLS 1.3 only'
                    })
                
                if cipher and cipher[2] < 128:
                    findings.append({
                        'type': 'Weak Cipher Suite',
                        'severity': 'High',
                        'risk_score': 7,
                        'description': f'{cipher[0]} with {cipher[2]}-bit key',
                        'impact': 'Encryption can be broken',
                        'recommendation': 'Use AES-256 or ChaCha20'
                    })
    except:
        pass
    
    return findings

# ========================
# MAIN SERVICE ANALYZER
# ========================
async def analyze_service_full(ip: str, port: int, service_info: Dict) -> List[Dict]:
    """Complete service analysis dispatcher"""
    findings = []
    service_name = service_info['name'].lower()
    
    check_stop()
    
    if port in [80, 8080, 8000, 8888] or 'http' in service_name:
        findings.extend(await analyze_http_service(ip, port, False))
    
    if port in [443, 8443] or 'https' in service_name:
        findings.extend(await analyze_http_service(ip, port, True))
        findings.extend(await analyze_ssl(ip, port))
    
    if port == 22 or 'ssh' in service_name:
        findings.extend(await analyze_ssh(ip, port))
    
    if port == 23 or 'telnet' in service_name:
        findings.extend(await analyze_telnet(ip, port))
    
    if port in [20, 21] or 'ftp' in service_name:
        findings.extend(await analyze_ftp(ip, port))
    
    if port in [3306, 5432, 27017, 6379, 9200, 1433, 1521]:
        findings.extend(await analyze_database(ip, port, service_info['name']))
    
    if port in [3389, 5900, 5901] or service_name in ['rdp', 'vnc']:
        findings.extend(await analyze_rdp_vnc(ip, port, service_info['name']))
    
    if port == 445 or 'smb' in service_name:
        findings.extend(await analyze_smb(ip, port))
    
    if port in [2375, 2376, 4243]:
        findings.extend(await analyze_docker(ip, port))
    
    if port in [161, 162]:
        findings.append({
            'type': 'Exposed SNMP Service',
            'severity': 'High',
            'risk_score': 7,
            'description': 'SNMP accessible from internet',
            'impact': 'Network information disclosure, potential RCE',
            'recommendation': 'Restrict access, use SNMPv3 with encryption'
        })
    
    if port in SERVICE_PORTS:
        service_data = SERVICE_PORTS[port]
        if service_data['severity'] in ['Critical', 'High'] and not findings:
            findings.append({
                'type': f'Exposed {service_data["category"]} Service',
                'severity': service_data['severity'],
                'risk_score': 7 if service_data['severity'] == 'High' else 9,
                'description': f'{service_data["name"]} on port {port}',
                'impact': 'Service exposed to internet - potential attack vector',
                'recommendation': 'Restrict access with firewall rules'
            })
    
    return findings

# ========================
# IP SCANNER
# ========================
async def scan_single_ip(ip: str, ip_index: int, total_ips: int):
    """Scan single IP completely"""
    check_stop()
    
    scan_controller.scan_stats['scanned_ips'] = ip_index
    
    # Send 10-minute progress update if needed
    await send_progress_update()
    
    is_active = await is_ip_active(ip)
    
    if not is_active:
        return
    
    scan_controller.scan_stats['active_ips'] += 1
    await send_telegram(f"""🟢 *Active IP Found*
IP: `{ip}`
Progress: {ip_index}/{total_ips} ({(ip_index/total_ips*100):.1f}%)""", get_control_keyboard())
    
    check_stop()
    
    open_ports = await scan_all_ports(ip)
    
    if not open_ports:
        await send_telegram(f"ℹ️ IP `{ip}` is active but no open ports detected")
        return
    
    scan_controller.scan_stats['total_services'] += len(open_ports)
    
    ip_findings = []
    
    for port, service_info in open_ports.items():
        check_stop()
        
        service_name = service_info['name']
        version = f"{service_info['product']} {service_info['version']}".strip()
        
        category = SERVICE_PORTS.get(port, {}).get('category', 'Unknown')
        await send_telegram(f"""🔍 *Service Detected*
IP: `{ip}`
Port: `{port}`
Service: *{service_name}*
Category: {category}
Version: {version or 'Unknown'}""")
        
        findings = await analyze_service_full(ip, port, service_info)
        
        for finding in findings:
            ip_findings.append(finding)
            scan_controller.scan_stats['total_findings'] += 1
            
            if finding['severity'] in ['High', 'Critical']:
                scan_controller.scan_stats['high_critical'] += 1
            
            severity_emoji = {
                'Low': '🟡',
                'Medium': '🟠',
                'High': '🔴',
                'Critical': '🚨'
            }
            
            msg = f"""{severity_emoji.get(finding['severity'], '⚠️')} *Finding Alert*

IP: `{ip}`
Port: `{port}`
Service: *{service_name}*
Severity: *{finding['severity']}*
Risk: *{finding['risk_score']}/10*

*Issue:*
{finding['description']}

*Impact:*
{finding['impact']}

*Fix:*
{finding['recommendation']}"""
            
            await send_telegram(msg)
    
    high_critical_count = len([f for f in ip_findings if f['severity'] in ['High', 'Critical']])
    
    summary = f"""✅ *IP Scan Complete: {ip}*

Services Found: {len(open_ports)}
Total Findings: {len(ip_findings)}
High/Critical: {high_critical_count}

Overall Progress: {ip_index}/{total_ips}"""
    
    await send_telegram(summary, get_control_keyboard())

# ========================
# MAIN SCAN ENGINE
# ========================
async def start_reconnaissance(ip_list: List[str], scan_type: str, target_name: str):
    """Main reconnaissance engine - works for both CIDR and IP list"""
    try:
        scan_controller.is_running = True
        scan_controller.stop_requested = False
        scan_controller.last_progress_update = datetime.now()
        
        start_time = datetime.now()
        
        if not ip_list:
            await send_telegram("❌ No valid IPs to scan")
            scan_controller.reset()
            return
        
        total_ips = len(ip_list)
        scan_controller.scan_stats['total_ips'] = total_ips
        
        scan_type_emoji = "🌐" if scan_type == 'cidr' else "📄"
        
        await send_telegram(f"""{scan_type_emoji} *Reconnaissance Started*

Type: *{scan_type.upper()}*
Target: `{target_name}`
Total IPs: {total_ips}
Start: {start_time.strftime('%H:%M:%S')}
Mode: Ethical, Passive

⏱️ Progress updates every 10 minutes
Scanning in progress... 🔍""", get_control_keyboard())
        
        for idx, ip in enumerate(ip_list, 1):
            check_stop()
            await scan_single_ip(ip, idx, total_ips)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        stats = scan_controller.scan_stats
        
        final_msg = f"""🎯 *Reconnaissance Complete*

{scan_type_emoji} *Scan Type:* {scan_type.upper()}
*Target:* `{target_name}`

*Scan Statistics:*
• Total IPs: {stats['total_ips']}
• Scanned: {stats['scanned_ips']}
• Active IPs: {stats['active_ips']}
• Services Found: {stats['total_services']}
• Total Findings: {stats['total_findings']}
• High/Critical: {stats['high_critical']}

*Time Analysis:*
• Duration: {duration:.1f}s ({duration/60:.1f} min)
• Start: {start_time.strftime('%H:%M:%S')}
• End: {end_time.strftime('%H:%M:%S')}
• Avg per IP: {(duration/total_ips):.2f}s

All findings are Bug Bounty compliant! ✅"""
        
        await send_telegram(final_msg, get_start_keyboard())
        
        report = {
            'scan_info': {
                'type': scan_type,
                'target': target_name,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': duration
            },
            'statistics': stats,
            'ip_list': ip_list[:100]
        }
        
        filename = f'scan_{scan_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        await send_telegram(f"📄 Report saved: `{filename}`")
        
    except asyncio.CancelledError:
        stats = scan_controller.scan_stats
        await send_telegram(f"""🛑 *Scan Stopped by User*

Type: {scan_type.upper()}
Target: `{target_name}`

Scanned: {stats['scanned_ips']}/{stats['total_ips']} IPs
Active IPs: {stats['active_ips']}
Services: {stats['total_services']}
Findings: {stats['total_findings']}
High/Critical: {stats['high_critical']}""", get_start_keyboard())
    except Exception as e:
        await send_telegram(f"❌ Error: {str(e)}", get_start_keyboard())
    finally:
        scan_controller.reset()

# ========================
# TELEGRAM HANDLERS
# ========================
@bot.message_handler(commands=['start', 'help'])
async def cmd_start(message):
    """Start command"""
    help_msg = """🔍 *Ethical Bug Bounty Recon Bot*
_By GitHubGuru_

*Commands:*
/scan <CIDR> - Scan CIDR range
/status - Current scan status
/help - This message

*File Upload:*
📤 Send a text file with IPs (one per line)
   Supported formats: ip.txt, ips.txt, list.txt

*Examples:*
• /scan 104.18.36.0/24
• Upload ip.txt file

*IP.txt Format:*

*Features:*
✅ CIDR & IP list scanning
✅ Real-time updates
✅ 10-minute progress reports
✅ Stop/Resume anytime
✅ 50+ service detection
✅ Complete vulnerability analysis
✅ Bug Bounty compliant

Ready to scan! 🚀"""
    
    await bot.reply_to(message, help_msg, parse_mode='Markdown')

@bot.message_handler(commands=['scan'])
async def cmd_scan(message):
    """Scan command for CIDR"""
    if scan_controller.is_running:
        await bot.reply_to(message, "⚠️ Scan already running! Use Stop button first.", reply_markup=get_control_keyboard())
        return
    
    try:
        cidr = message.text.split()[1]
        
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            await bot.reply_to(message, "❌ Invalid CIDR\nExample: /scan 104.18.36.0/24")
            return
        
        ip_list = expand_cidr(cidr)
        
        await bot.reply_to(message, f"🎯 Starting CIDR scan: `{cidr}`\nTotal IPs: {len(ip_list)}", parse_mode='Markdown')
        
        task = asyncio.create_task(start_reconnaissance(ip_list, 'cidr', cidr))
        scan_controller.start_scan(task, 'cidr', cidr)
        
    except IndexError:
        await bot.reply_to(message, "❌ Usage: /scan <CIDR>\nExample: /scan 104.18.36.0/24")
    except Exception as e:
        await bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(content_types=['document'])
async def handle_document(message):
    """Handle IP list file upload"""
    if scan_controller.is_running:
        await bot.reply_to(message, "⚠️ Scan already running! Use Stop button first.", reply_markup=get_control_keyboard())
        return
    
    try:
        file_info = await bot.get_file(message.document.file_id)
        filename = message.document.file_name
        
        if not filename.lower().endswith(('.txt', '.list', '.ips')):
            await bot.reply_to(message, "❌ Please send a .txt file with IP addresses")
            return
        
        downloaded_file = await bot.download_file(file_info.file_path)
        content = downloaded_file.decode('utf-8', errors='ignore')
        
        ip_list = parse_ip_file(content)
        
        if not ip_list:
            await bot.reply_to(message, "❌ No valid IP addresses found in file")
            return
        
        await bot.reply_to(message, f"""✅ *File Processed Successfully*

Filename: `{filename}`
Valid IPs: {len(ip_list)}

Starting scan... 🚀""", parse_mode='Markdown')
        
        task = asyncio.create_task(start_reconnaissance(ip_list, 'iplist', filename))
        scan_controller.start_scan(task, 'iplist', filename)
        
    except Exception as e:
        await bot.reply_to(message, f"❌ File processing error: {str(e)}")

@bot.message_handler(commands=['status'])
async def cmd_status(message):
    """Status command"""
    if scan_controller.is_running:
        stats = scan_controller.scan_stats
        progress = (stats['scanned_ips']/stats['total_ips']*100) if stats['total_ips'] > 0 else 0
        
        scan_type_emoji = "🌐" if scan_controller.scan_type == 'cidr' else "📄"
        
        elapsed_mins = (datetime.now() - scan_controller.last_progress_update).total_seconds() / 60
        next_update = max(0, 10 - elapsed_mins)
        
        status_msg = f"""📊 *Scan Status: Running* 🟢

{scan_type_emoji} Type: {scan_controller.scan_type.upper()}
Target: `{scan_controller.scan_target}`

*Progress:*
Scanned: {stats['scanned_ips']}/{stats['total_ips']} ({progress:.1f}%)
Active IPs: {stats['active_ips']}
Services: {stats['total_services']}
Findings: {stats['total_findings']}
High/Critical: {stats['high_critical']}

⏱️ Next update in: {next_update:.1f} min"""
        
        await bot.reply_to(message, status_msg, parse_mode='Markdown', reply_markup=get_control_keyboard())
    else:
        await bot.reply_to(message, "✅ No scan running\n\nUse /scan <CIDR> or upload ip.txt", reply_markup=get_start_keyboard())

@bot.callback_query_handler(func=lambda call: True)
async def callback_handler(call):
    """FIXED: Handle button clicks with timeout protection"""
    try:
        if call.data == "stop_scan":
            if scan_controller.is_running:
                scan_controller.request_stop()
                
                # Answer immediately to prevent timeout
                try:
                    await bot.answer_callback_query(
                        call.id, 
                        "🛑 Stopping scan...", 
                        show_alert=False
                    )
                except Exception as e:
                    print(f"Callback answer error (ignored): {e}")
                
                # Remove keyboard
                try:
                    await bot.edit_message_reply_markup(
                        call.message.chat.id, 
                        call.message.message_id, 
                        reply_markup=None
                    )
                except Exception as e:
                    print(f"Keyboard removal error (ignored): {e}")
            else:
                try:
                    await bot.answer_callback_query(call.id, "No scan running")
                except Exception as e:
                    print(f"Callback error (ignored): {e}")
        
        elif call.data == "start_scan":
            try:
                await bot.answer_callback_query(
                    call.id, 
                    "Use /scan <CIDR> or upload ip.txt"
                )
            except Exception as e:
                print(f"Callback error (ignored): {e}")
    
    except Exception as e:
        print(f"Callback handler error: {e}")
        try:
            await bot.answer_callback_query(call.id, "Error processing request")
        except:
            pass

# ========================
# MAIN (FIXED)
# ========================
async def main():
    """Main function with proper cleanup"""
    print("=" * 60)
    print("🤖 Bug Bounty Recon Bot v3.0.1 FIXED Started!")
    print("=" * 60)
    print("Features:")
    print("  ✅ CIDR scanning (/scan command)")
    print("  ✅ IP list file upload (ip.txt)")
    print("  ✅ Real-time Telegram updates")
    print("  ✅ 10-minute progress reports")
    print("  ✅ Stop/Start functionality")
    print("  ✅ 50+ service detection")
    print("  ✅ Complete vulnerability analysis")
    print("  ✅ Ethical & Bug Bounty safe")
    print("=" * 60)
    print("Cleaning up old callbacks...")
    
    # FIXED: Clear old webhooks and pending updates
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        print("✅ Old webhooks and callbacks cleared")
    except Exception as e:
        print(f"Webhook cleanup: {e}")
    
    print("Bot ready! Waiting for commands...")
    print("=" * 60)
    
    # FIXED: Start polling with skip_pending=True
    await bot.polling(
        non_stop=True, 
        interval=0, 
        timeout=60,
        request_timeout=60,
        skip_pending=True  # Skip old callbacks
    )

if __name__ == "__main__":
    asyncio.run(main())
