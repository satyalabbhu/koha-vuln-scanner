import streamlit as st
import subprocess
import os
import json
import datetime
import socket
import threading
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from urllib.parse import urlparse
import time
import re
import urllib3
from weasyprint import HTML
import base64
from io import BytesIO
import numpy as np

# LLM Analysis import
try:
    from llm_analysis import LibrarianReportGenerator
    LLM_ANALYSIS_AVAILABLE = True
except ImportError:
    LLM_ANALYSIS_AVAILABLE = False
    print("LLM Analysis module not available. Some features may be limited.")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
RESULTS_DIR = "results"
Path(RESULTS_DIR).mkdir(exist_ok=True)

# Enhanced tool configurations
TOOLS = {
    "nmap": {
        "name": "Nmap Port Scanner",
        "cmd": "nmap -sS -T4 -p 1-65535 {target}",
        "category": "Network",
        "fallback": True,
        "description": "Port scanning and service detection",
        "requires_web": False
    },
    "nikto": {
        "name": "Nikto Web Scanner", 
        "cmd": "nikto -h {web_url}",
        "category": "Web",
        "fallback": False,
        "description": "Web server vulnerability scanner",
        "requires_web": True
    },
    "sqlmap": {
        "name": "SQLMap",
        "cmd": "sqlmap -u {web_url} --batch --random-agent --level=1 --risk=1",
        "category": "Web",
        "fallback": True,
        "description": "SQL injection testing",
        "requires_web": True
    },
    "gobuster": {
        "name": "Gobuster",
        "cmd": "gobuster dir -u {web_url} -w /usr/share/wordlists/dirb/common.txt -t 20",
        "category": "Web",
        "fallback": True,
        "description": "Directory/file bruteforcing",
        "requires_web": True
    },
    "nuclei": {
        "name": "Nuclei",
        "cmd": "nuclei -u {web_url} -silent",
        "category": "Vulnerability",
        "fallback": False,
        "description": "Fast vulnerability scanner",
        "requires_web": True
    },
    "whatweb": {
        "name": "WhatWeb",
        "cmd": "whatweb {web_url}",
        "category": "Reconnaissance",
        "fallback": True,
        "description": "Technology fingerprinting",
        "requires_web": True
    },
    "wpscan": {
        "name": "WPScan",
        "cmd": "wpscan --url {web_url} --no-banner --random-user-agent",
        "category": "CMS",
        "fallback": False,
        "description": "WordPress security scanner",
        "requires_web": True
    },
    "masscan": {
        "name": "Masscan",
        "cmd": "masscan -p1-65535 {target} --rate=1000",
        "category": "Network",
        "fallback": True,
        "description": "High-speed port scanner",
        "requires_web": False
    }
}

# Streamlit configuration
st.set_page_config(
    page_title="⚡ KOHA CYBER THREAT SCANNER",
    page_icon="💀",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap');

/* Main Theme */
.stApp {
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
    color: #00ff00;
    font-family: 'Rajdhani', sans-serif;
}

/* Header styles */
.main-header {
    background: linear-gradient(135deg, #ff0040 0%, #8b0000 50%, #000000 100%);
    color: #ffffff;
    padding: 2rem;
    border-radius: 15px;
    text-align: center;
    margin-bottom: 2rem;
    border: 2px solid #ff0040;
    box-shadow: 0 0 30px #ff0040, inset 0 0 30px rgba(255, 0, 64, 0.1);
    position: relative;
    overflow: hidden;
}

.main-header::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(255, 0, 64, 0.05) 4px
    );
    animation: scan 3s linear infinite;
}

@keyframes scan {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(100%); }
}

.main-header h1 {
    font-family: 'Orbitron', monospace;
    font-weight: 900;
    font-size: 3rem;
    text-shadow: 0 0 20px #ff0040;
    z-index: 1;
    position: relative;
}

.main-header p {
    font-size: 1.2rem;
    color: #cccccc;
    z-index: 1;
    position: relative;
}

/* Tool Cards */
.tool-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #00ff00;
    margin: 0.5rem 0;
    margin-bottom: 12px;
    line-height: 1.4;
    border: 1px solid #00ff00;
    box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
    transition: all 0.3s ease;
}

.tool-card:hover {
    box-shadow: 0 0 25px rgba(0, 255, 0, 0.6);
    transform: translateY(-2px);
}

/* Vulnerability Cards */
.vulnerability {
    background: rgba(255, 255, 204, 0.1);
    border: 1px solid #ffeaa7;
    padding: 0.75rem;
    border-radius: 5px;
    margin: 0.5rem 0;
    backdrop-filter: blur(10px);
    transition: all 0.3s ease;
}

.vulnerability:hover {
    transform: translateX(5px);
}

.critical { 
    background: rgba(248, 215, 218, 0.2); 
    border-color: #ff0040; 
    box-shadow: 0 0 15px rgba(255, 0, 64, 0.5);
}

.high { 
    background: rgba(255, 243, 205, 0.2); 
    border-color: #ff6b35; 
    box-shadow: 0 0 15px rgba(255, 107, 53, 0.5);
}

.medium { 
    background: rgba(209, 236, 241, 0.2); 
    border-color: #17a2b8; 
    box-shadow: 0 0 15px rgba(23, 162, 184, 0.5);
}

.low { 
    background: rgba(212, 237, 218, 0.2); 
    border-color: #28a745; 
    box-shadow: 0 0 15px rgba(40, 167, 69, 0.5);
}

.info { 
    background: rgba(226, 227, 229, 0.2); 
    border-color: #6c757d; 
    box-shadow: 0 0 15px rgba(108, 117, 125, 0.5);
}

/* Category Colors */
.category-network { border-left-color: #28a745; }
.category-web { border-left-color: #007bff; }
.category-vulnerability { border-left-color: #dc3545; }
.category-reconnaissance { border-left-color: #6f42c1; }
.category-cms { border-left-color: #fd7e14; }

/* Target Info */
.target-info {
    background: linear-gradient(135deg, rgba(231, 243, 255, 0.1) 0%, rgba(23, 162, 184, 0.1) 100%);
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #007bff;
    margin: 1rem 0;
    border: 1px solid #007bff;
    box-shadow: 0 0 20px rgba(0, 123, 255, 0.4);
    backdrop-filter: blur(10px);
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #ff0040 0%, #8b0000 100%);
    color: white;
    border: 2px solid #ff0040;
    border-radius: 5px;
    font-family: 'Orbitron', monospace;
    font-weight: 700;
    text-transform: uppercase;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    box-shadow: 0 0 25px #ff0040;
    transform: translateY(-2px);
}

/* Metrics */
.metric-container {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid #00ff00;
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
    box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
}

/* Sidebar */
.css-1d391kg {
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
}

/* Text inputs */
.stTextInput > div > div > input {
    background: rgba(26, 26, 46, 0.8);
    color: #00ff00;
    border: 1px solid #00ff00;
    border-radius: 5px;
}

/* Select boxes */
.stSelectbox > div > div > select {
    background: rgba(26, 26, 46, 0.8);
    color: #00ff00;
    border: 1px solid #00ff00;
}

/* Checkboxes */
.stCheckbox > label {
    color: #00ff00;
    font-family: 'Rajdhani', sans-serif;
}

/* Progress bars */
.stProgress > div > div > div {
    background: #ff0040;
}

/* Expanders */
.streamlit-expanderHeader {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #00ff00;
    border: 1px solid #00ff00;
}

/* Code blocks */
.stCode {
    background: rgba(0, 0, 0, 0.8);
    border: 1px solid #00ff00;
    color: #00ff00;
}

/* Tables */
.dataframe {
    background: rgba(26, 26, 46, 0.9);
    color: #00ff00;
    border: 1px solid #00ff00;
}

/* Animation for scan status */
.scanning-indicator {
    display: inline-block;
    font-size: 1.5rem;
    animation: pulse 1s infinite;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

/* Terminal-like text */
.terminal-text {
    font-family: 'Courier New', monospace;
    background: rgba(0, 0, 0, 0.9);
    color: #00ff00;
    padding: 1rem;
    border-radius: 5px;
    border: 1px solid #00ff00;
    white-space: pre-wrap;
}

/* Glitch effect for critical vulnerabilities */
.glitch {
    position: relative;
    animation: glitch 2s infinite;
}

@keyframes glitch {
    0% { transform: translate(0); }
    20% { transform: translate(-2px, 2px); }
    40% { transform: translate(-2px, -2px); }
    60% { transform: translate(2px, 2px); }
    80% { transform: translate(2px, -2px); }
    100% { transform: translate(0); }
}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>💀 KOHA CYBER THREAT SCANNER</h1>
    <p>Advanced Penetration Testing & Vulnerability Assessment Platform</p>
    <p style="font-size: 0.9rem; margin-top: 1rem;">🚨 AUTHORIZED USE ONLY - LETHAL DIGITAL WEAPONS 🚨</p>
</div>
""", unsafe_allow_html=True)

# Functions
def validate_target(target):
    """Validate and analyze target to determine available services"""
    target_info = {
        'ip': target,
        'has_web': False,
        'open_ports': [],
        'protocols': [],
        'services': {}
    }
    
    # Basic port scan to determine available services
    common_ports = [21, 22, 23, 25, 53, 80, 135, 139, 389, 443, 445, 464, 593, 636, 993, 995, 3389, 5985, 8080, 8443]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            if result == 0:
                target_info['open_ports'].append(port)
                service = get_service_name(port)
                target_info['services'][port] = service
                
                # Check for web services
                if port in [80, 443, 8080, 8443]:
                    target_info['has_web'] = True
                    protocol = 'HTTPS' if port in [443, 8443] else 'HTTP'
                    if protocol not in target_info['protocols']:
                        target_info['protocols'].append(protocol)
            sock.close()
        except:
            continue
    
    return target_info

def get_appropriate_tools(target_info):
    """Return appropriate tools based on target analysis"""
    suitable_tools = []
    
    # Always include network scanning tools if we have any open ports
    if target_info['open_ports']:
        suitable_tools.extend(['nmap', 'masscan'])
    
    # Include web tools only if web services are detected
    if target_info['has_web']:
        suitable_tools.extend(['nikto', 'sqlmap', 'gobuster', 'whatweb', 'nuclei'])
        
        # Add WordPress scanner if HTTP is available
        if 'HTTP' in target_info['protocols']:
            suitable_tools.append('wpscan')
    
    return suitable_tools

def get_web_url(target, target_info):
    """Determine the appropriate web URL for the target"""
    if not target_info['has_web']:
        return None
    
    # Prefer HTTPS if available, otherwise HTTP
    if 443 in target_info['open_ports']:
        return f"https://{target}"
    elif 8443 in target_info['open_ports']:
        return f"https://{target}:8443"
    elif 80 in target_info['open_ports']:
        return f"http://{target}"
    elif 8080 in target_info['open_ports']:
        return f"http://{target}:8080"
    
    return f"http://{target}"  # Default fallback

def get_service_name(port):
    """Get common service name for port"""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 464: 'Kerberos', 
        593: 'RPC-HTTPS', 636: 'LDAPS', 647: 'DHCP-Failover',
        993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5985: 'WinRM',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    return services.get(port, 'Unknown')

def get_port_severity(port):
    """Determine severity based on port and service"""
    critical_ports = [21, 23, 135, 139, 445, 3389]  # Highly exploitable
    high_risk_ports = [22, 25, 80, 443, 993, 995, 5985]  # Standard but risky
    medium_risk_ports = [53, 389, 636, 464, 593, 647]  # Domain services
    
    if port in critical_ports:
        return 'critical'
    elif port in high_risk_ports:
        return 'high'
    elif port in medium_risk_ports:
        return 'medium'
    else:
        return 'low'

def check_tool_available(tool):
    """Robust check if a tool is available (handles non-zero exit codes)"""
    try:
        # Masscan specific logic
        if tool == "masscan":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            output = (result.stdout + result.stderr).lower()
            return any(keyword in output for keyword in ["masscan", "port scanner", "transmit rate", "--rate"])

        elif tool == "gobuster":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            output = (result.stdout + result.stderr).lower()
            return any(keyword in output for keyword in ["gobuster", "directory", "brute force", "usage"])

        elif tool == "nmap":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            return result.returncode == 0 or "nmap" in result.stdout.lower()

        elif tool == "nikto":
            result = subprocess.run([tool, "-Help"], capture_output=True, timeout=5, text=True)
            return "nikto" in (result.stdout + result.stderr).lower()

        elif tool == "sqlmap":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            return "sqlmap" in (result.stdout + result.stderr).lower()

        elif tool == "whatweb":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            return "whatweb" in (result.stdout + result.stderr).lower()

        elif tool == "nuclei":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            return "nuclei" in (result.stdout + result.stderr).lower()

        elif tool == "wpscan":
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            return "wpscan" in (result.stdout + result.stderr).lower()

        else:
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5, text=True)
            output = (result.stdout + result.stderr).lower()
            return any(x in output for x in ["usage", "help", tool])
    
    except Exception:
        try:
            which_result = subprocess.run(["which", tool], capture_output=True, timeout=3, text=True)
            return which_result.returncode == 0 and which_result.stdout.strip()
        except:
            return False


def basic_port_scan(target, ports=None):
    """Enhanced port scanner using Python sockets"""
    if ports is None:
        ports = list(range(1, 1001))  # Default to first 1000 ports
    
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def basic_web_scan(target, target_info=None):
    """Enhanced web technology detection"""
    results = []
    
    if target_info and not target_info['has_web']:
        return ["No web services available"]
    
    web_url = get_web_url(target, target_info) if target_info else f"http://{target}"
    
    try:
        response = requests.get(web_url, timeout=10, verify=False, 
                              headers={'User-Agent': 'Mozilla/5.0 (compatible; Security Scanner)'})
        
        # Check for common technologies
        content = response.text.lower()
        headers = response.headers
        
        results.append(f"HTTP Status: {response.status_code}")
        results.append(f"Content Length: {len(response.text)} bytes")
        
        # WordPress detection
        if 'wp-content' in content or 'wordpress' in content:
            results.append("⚠️ WordPress detected")
        
        # Server detection
        if 'Server' in headers:
            results.append(f"Server: {headers['Server']}")
        
        # Security headers check
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 'Strict-Transport-Security']
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            results.append(f"⚠️ Missing security headers: {', '.join(missing_headers)}")
            
        # Technology fingerprinting
        tech_indicators = {
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'php': 'PHP',
            'asp.net': 'ASP.NET',
            'tomcat': 'Apache Tomcat',
            'nginx': 'Nginx',
            'apache': 'Apache'
        }
        
        for indicator, tech in tech_indicators.items():
            if indicator in content or indicator in str(headers):
                results.append(f"✓ {tech} detected")
                
    except Exception as e:
        results.append(f"❌ Connection error: {str(e)}")
    
    return results

def basic_dir_scan(target, target_info=None):
    """Enhanced directory enumeration"""
    common_dirs = ['admin', 'wp-admin', 'login', 'dashboard', 'test', 'backup', 
                   'config', 'api', 'uploads', 'images', 'js', 'css', 'includes',
                   'administrator', 'phpmyadmin', 'wp-content', 'wp-includes']
    found_dirs = []
    
    web_url = get_web_url(target, target_info) if target_info else f"http://{target}"
    base_url = web_url.rstrip('/')
    
    for directory in common_dirs:
        try:
            url = f"{base_url}/{directory}"
            response = requests.get(url, timeout=5, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0 (compatible; Security Scanner)'})
            if response.status_code == 200:
                found_dirs.append(f"✓ /{directory} (200 - Accessible)")
            elif response.status_code == 403:
                found_dirs.append(f"⚠️ /{directory} (403 - Forbidden)")
            elif response.status_code == 401:
                found_dirs.append(f"🔒 /{directory} (401 - Unauthorized)")
        except:
            continue
            
    return found_dirs

def parse_vulnerabilities(tool_name, output):
    """Enhanced vulnerability parsing"""
    vulnerabilities = []
    
    if tool_name == "nmap":
        # Parse nmap output
        lines = output.split('\n')
        for line in lines:
            if 'open' in line and '/' in line and 'tcp' in line:
                port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if port_match:
                    port = int(port_match.group(1))
                    service = port_match.group(2)
                    severity = get_port_severity(port)
                    vulnerabilities.append({
                        'type': 'Open Port',
                        'severity': severity,
                        'description': f'Port {port} ({service}) is open',
                        'detail': line.strip(),
                        'tool': tool_name
                    })
    
    elif tool_name == "nikto":
        # Parse nikto output
        lines = output.split('\n')
        for line in lines:
            if line.startswith('+') and ('OSVDB' in line or 'vulnerable' in line.lower() or 'CGI' in line):
                severity = 'high' if any(word in line.lower() for word in ['vulnerable', 'exploit', 'injection']) else 'medium'
                vulnerabilities.append({
                    'type': 'Web Vulnerability',
                    'severity': severity,
                    'description': line.strip(),
                    'detail': line.strip(),
                    'tool': tool_name
                })
    
    elif tool_name == "sqlmap":
        # Parse sqlmap output
        if 'injectable' in output.lower() or 'vulnerable' in output.lower():
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'critical',
                'description': 'SQL injection vulnerability detected',
                'detail': 'Target appears to be vulnerable to SQL injection',
                'tool': tool_name
            })
        elif 'error' in output.lower() and 'mysql' in output.lower():
            vulnerabilities.append({
                'type': 'Database Error',
                'severity': 'medium',
                'description': 'Database error disclosure detected',
                'detail': 'Application may be leaking database information',
                'tool': tool_name
            })
    
    elif tool_name == "nuclei":
        # Parse nuclei output
        lines = output.split('\n')
        for line in lines:
            if '[' in line and ']' in line:
                severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line.lower())
                severity = severity_match.group(1) if severity_match else 'medium'
                vulnerabilities.append({
                    'type': 'Nuclei Finding',
                    'severity': severity,
                    'description': line.strip(),
                    'detail': line.strip(),
                    'tool': tool_name
                })
    
    elif tool_name == "whatweb":
        # Parse whatweb output for interesting findings
        if 'wordpress' in output.lower():
            vulnerabilities.append({
                'type': 'CMS Detection',
                'severity': 'info',
                'description': 'WordPress installation detected',
                'detail': 'WordPress CMS identified - check for version and vulnerabilities',
                'tool': tool_name
            })
    
    # Generic parsing for security-related keywords
    vuln_keywords = {
        'vulnerable': 'high',
        'security': 'medium',
        'exposed': 'high',
        'injection': 'critical',
        'xss': 'high',
        'csrf': 'medium',
        'disclosure': 'medium',
        'weak': 'medium',
        'default': 'medium'
    }
    
    for line in output.split('\n'):
        line_lower = line.lower()
        for keyword, severity in vuln_keywords.items():
            if keyword in line_lower and line.strip() and not any(v['detail'] == line.strip() for v in vulnerabilities):
                vulnerabilities.append({
                    'type': 'Potential Issue',
                    'severity': severity,
                    'description': f'Security-related finding: {keyword}',
                    'detail': line.strip(),
                    'tool': tool_name
                })
                break
    
    return vulnerabilities

def run_tool_scan(tool_name, target, target_info):
    """Enhanced tool scanning with proper target handling"""
    if tool_name not in TOOLS:
        return None, []
    
    tool_config = TOOLS[tool_name]
    vulnerabilities = []
    
    # Skip web tools if no web services are available
    if tool_config.get('requires_web', False) and not target_info['has_web']:
        return f"⚠️ Skipping {tool_name} - No web services detected on target", []
    
    try:
        tool_available = check_tool_available(tool_name)
        
        if tool_available:
            # Prepare command with appropriate URL/target
            if tool_config.get('requires_web', False):
                web_url = get_web_url(target, target_info)
                if not web_url:
                    return f"❌ Cannot determine web URL for {tool_name}", []
                # Format command with only the parameters it needs
                if '{web_url}' in tool_config['cmd'] and '{target}' in tool_config['cmd']:
                    cmd = tool_config['cmd'].format(target=target, web_url=web_url)
                elif '{web_url}' in tool_config['cmd']:
                    cmd = tool_config['cmd'].format(web_url=web_url)
                else:
                    cmd = tool_config['cmd'].format(target=target)
            else:
                cmd = tool_config['cmd'].format(target=target)
            
            # Run the tool
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            output = result.stdout + result.stderr
            vulnerabilities = parse_vulnerabilities(tool_name, output)
            
            # Add tool name to vulnerabilities
            for vuln in vulnerabilities:
                vuln['tool'] = tool_name
            
        elif tool_config.get('fallback'):
            # Use Python-based fallbacks
            if tool_name == "nmap" or tool_name == "masscan":
                open_ports = basic_port_scan(target, list(range(1, 1001)))
                services = []
                for port in open_ports:
                    service = get_service_name(port)
                    severity = get_port_severity(port)
                    services.append(f"{port}/{service} ({severity})")
                    vulnerabilities.append({
                        'type': 'Open Port',
                        'severity': severity,
                        'description': f'Port {port} ({service}) is open',
                        'detail': f'Open port: {port}/{service}',
                        'tool': tool_name
                    })
                
                output = f"✓ Basic port scan completed\nOpen ports found: {len(open_ports)}\n" + '\n'.join(services)
            
            elif tool_name == "whatweb" and target_info['has_web']:
                tech_results = basic_web_scan(target, target_info)
                output = f"✓ Basic web scan completed:\n" + '\n'.join(tech_results)
                
                # Add vulnerabilities for missing security headers
                for result in tech_results:
                    if "Missing security headers" in result:
                        vulnerabilities.append({
                            'type': 'Security Headers',
                            'severity': 'medium',
                            'description': result,
                            'detail': 'Missing security headers can expose application to attacks',
                            'tool': tool_name
                        })
                
            elif tool_name == "gobuster" and target_info['has_web']:
                found_dirs = basic_dir_scan(target, target_info)
                output = f"✓ Basic directory scan completed:\n" + '\n'.join(found_dirs)
                for directory in found_dirs:
                    if '200 - Accessible' in directory:
                        vulnerabilities.append({
                            'type': 'Directory Found',
                            'severity': 'low',
                            'description': f'Accessible directory: {directory}',
                            'detail': directory,
                            'tool': tool_name
                        })
                    elif '403 - Forbidden' in directory:
                        vulnerabilities.append({
                            'type': 'Directory Found',
                            'severity': 'info',
                            'description': f'Protected directory: {directory}',
                            'detail': directory,
                            'tool': tool_name
                        })
            
            elif tool_name == "sqlmap":
                if target_info['has_web']:
                    output = "⚠️ Basic SQL injection check not implemented in fallback mode\nPlease install sqlmap for full functionality"
                else:
                    output = "❌ SQL injection testing requires web services"
                
            else:
                output = f"⚠️ Tool {tool_name} not available and no fallback implemented"
        else:
            output = f"❌ Tool {tool_name} not available on system"
            
    except subprocess.TimeoutExpired:
        output = f"⏱️ {tool_name} scan timed out (5 minutes)"
    except Exception as e:
        output = f"❌ Error running {tool_name}: {str(e)}"
    
    return output, vulnerabilities

def save_results(tool_name, target, output, vulnerabilities):
    """Save scan results"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{tool_name}_{target.replace('.', '_')}_{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    data = {
        'tool': tool_name,
        'target': target,
        'timestamp': datetime.datetime.now().isoformat(),
        'output': output,
        'vulnerabilities': vulnerabilities,
        'vulnerability_count': len(vulnerabilities)
    }
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    return filepath

def create_vulnerability_charts(vulnerabilities):
    """Create interactive charts for vulnerability data"""
    if not vulnerabilities:
        return None, None, None
    
    # Prepare data for charts
    df = pd.DataFrame(vulnerabilities)
    
    # Severity distribution pie chart
    severity_counts = df['severity'].value_counts()
    colors = ['#ff0040', '#ff6b35', '#17a2b8', '#28a745', '#6c757d']
    
    pie_fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title="🎯 Vulnerability Distribution by Severity",
        color_discrete_sequence=colors
    )
    pie_fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#00ff00',
        title_font_color='#ff0040',
        title_font_size=18
    )
    
    # Tools vs vulnerabilities bar chart
    tool_counts = df['tool'].value_counts()
    bar_fig = px.bar(
        x=tool_counts.index,
        y=tool_counts.values,
        title="🔧 Vulnerabilities Found by Tool",
        labels={'x': 'Security Tools', 'y': 'Number of Issues'},
        color=tool_counts.values,
        color_continuous_scale='Reds'
    )
    bar_fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#00ff00',
        title_font_color='#ff0040',
        title_font_size=18
    )
    
    # Severity timeline if multiple scans
    if len(df) > 1:
        timeline_fig = px.scatter(
            df, 
            x=range(len(df)), 
            y='severity',
            color='severity',
            title="📈 Vulnerability Timeline",
            labels={'x': 'Discovery Order', 'y': 'Severity Level'},
            color_discrete_map={
                'critical': '#ff0040',
                'high': '#ff6b35', 
                'medium': '#17a2b8',
                'low': '#28a745',
                'info': '#6c757d'
            }
        )
        timeline_fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#00ff00',
            title_font_color='#ff0040',
            title_font_size=18
        )
    else:
        timeline_fig = None
    
    return pie_fig, bar_fig, timeline_fig

def generate_enhanced_report(scan_results, target_info, target_ip):
    """Generate comprehensive HTML and PDF reports with charts"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Collect all vulnerabilities
    all_vulnerabilities = []
    for tool_name, result_data in scan_results.items():
        all_vulnerabilities.extend(result_data.get('vulnerabilities', []))
    
    # Generate statistics
    total_vulnerabilities = len(all_vulnerabilities)
    severity_counts = {}
    tool_counts = {}
    
    for vuln in all_vulnerabilities:
        severity = vuln.get('severity', 'info')
        tool = vuln.get('tool', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        tool_counts[tool] = tool_counts.get(tool, 0) + 1
    
    # Risk score calculation
    risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
    risk_score = sum(risk_weights.get(sev, 1) * count for sev, count in severity_counts.items())
    max_possible_score = total_vulnerabilities * 10
    risk_percentage = (risk_score / max_possible_score * 100) if max_possible_score > 0 else 0
    
    # Determine risk level
    if risk_percentage >= 80:
        risk_level = "🚨 CRITICAL"
        risk_color = "#ff0040"
    elif risk_percentage >= 60:
        risk_level = "⚠️ HIGH"
        risk_color = "#ff6b35"
    elif risk_percentage >= 40:
        risk_level = "📢 MEDIUM"
        risk_color = "#17a2b8"
    elif risk_percentage >= 20:
        risk_level = "ℹ️ LOW"
        risk_color = "#28a745"
    else:
        risk_level = "✅ MINIMAL"
        risk_color = "#6c757d"
    
    # Create enhanced HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>KOHA Cyber Threat Assessment Report</title>
        <meta charset="UTF-8">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap');
            
            body {{
                font-family: 'Rajdhani', sans-serif;
                background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
                color: #00ff00;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}
            
            .header {{
                background: linear-gradient(135deg, #ff0040 0%, #8b0000 50%, #000000 100%);
                color: white;
                padding: 2rem;
                border-radius: 15px;
                text-align: center;
                margin-bottom: 2rem;
                border: 2px solid #ff0040;
                box-shadow: 0 0 30px #ff0040;
            }}
            
            .header h1 {{
                font-family: 'Orbitron', monospace;
                font-weight: 900;
                font-size: 2.5rem;
                text-shadow: 0 0 20px #ff0040;
                margin: 0;
            }}
            
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 2rem 0;
            }}
            
            .metric-card {{
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border: 1px solid #00ff00;
                border-radius: 10px;
                padding: 1.5rem;
                text-align: center;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            }}
            
            .metric-value {{
                font-size: 2.5rem;
                font-weight: 700;
                color: #ff0040;
                font-family: 'Orbitron', monospace;
            }}
            
            .metric-label {{
                font-size: 1rem;
                color: #00ff00;
                text-transform: uppercase;
            }}
            
            .risk-indicator {{
                background: linear-gradient(135deg, rgba(255, 0, 64, 0.1) 0%, rgba(139, 0, 0, 0.1) 100%);
                border: 2px solid {risk_color};
                border-radius: 10px;
                padding: 1rem;
                margin: 1rem 0;
                text-align: center;
            }}
            
            .risk-level {{
                font-size: 2rem;
                font-weight: 900;
                color: {risk_color};
                font-family: 'Orbitron', monospace;
            }}
            
            .section {{
                background: rgba(26, 26, 46, 0.9);
                border: 1px solid #00ff00;
                border-radius: 10px;
                padding: 1.5rem;
                margin: 1.5rem 0;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
            }}
            
            .section h2 {{
                color: #ff0040;
                font-family: 'Orbitron', monospace;
                border-bottom: 2px solid #ff0040;
                padding-bottom: 0.5rem;
            }}
            
            .vulnerability {{
                background: rgba(255, 255, 204, 0.1);
                border-left: 4px solid #ffeaa7;
                padding: 1rem;
                margin: 1rem 0;
                border-radius: 5px;
            }}
            
            .vulnerability.critical {{
                border-left-color: #ff0040;
                background: rgba(248, 215, 218, 0.2);
                box-shadow: 0 0 10px rgba(255, 0, 64, 0.3);
            }}
            
            .vulnerability.high {{
                border-left-color: #ff6b35;
                background: rgba(255, 243, 205, 0.2);
                box-shadow: 0 0 10px rgba(255, 107, 53, 0.3);
            }}
            
            .vulnerability.medium {{
                border-left-color: #17a2b8;
                background: rgba(209, 236, 241, 0.2);
            }}
            
            .vulnerability.low {{
                border-left-color: #28a745;
                background: rgba(212, 237, 218, 0.2);
            }}
            
            .tool-section {{
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border: 1px solid #00ff00;
                border-radius: 8px;
                padding: 1rem;
                margin: 1rem 0;
            }}
            
            .footer {{
                text-align: center;
                margin-top: 3rem;
                padding: 2rem;
                border-top: 2px solid #ff0040;
                color: #666;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 1rem 0;
            }}
            
            th, td {{
                border: 1px solid #00ff00;
                padding: 8px;
                text-align: left;
            }}
            
            th {{
                background: rgba(255, 0, 64, 0.2);
                color: #ff0040;
                font-weight: 700;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>💀 KOHA CYBER THREAT SCANNER</h1>
            <p>Advanced Penetration Testing & Vulnerability Assessment Report</p>
            <p><strong>Target:</strong> {target_ip} | <strong>Generated:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="risk-indicator">
            <div class="risk-level">{risk_level}</div>
            <div>Overall Risk Score: {risk_score}/{max_possible_score} ({risk_percentage:.1f}%)</div>
        </div>
        
        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-value">{total_vulnerabilities}</div>
                <div class="metric-label">Total Issues</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(scan_results)}</div>
                <div class="metric-label">Tools Used</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(target_info.get('open_ports', []))}</div>
                <div class="metric-label">Open Ports</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{'YES' if target_info.get('has_web', False) else 'NO'}</div>
                <div class="metric-label">Web Services</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Target Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Target IP/Domain</td><td>{target_ip}</td></tr>
                <tr><td>Open Ports</td><td>{', '.join(map(str, target_info.get('open_ports', [])))}</td></tr>
                <tr><td>Services</td><td>{', '.join([f"{port}/{service}" for port, service in target_info.get('services', {}).items()])}</td></tr>
                <tr><td>Web Services</td><td>{'Available' if target_info.get('has_web', False) else 'Not detected'}</td></tr>
                <tr><td>Protocols</td><td>{', '.join(target_info.get('protocols', []))}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Severity Breakdown</h2>
            <table>
                <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
    """
    
    # Add severity breakdown
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_counts.get(severity, 0)
        percentage = (count / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
        html_content += f"<tr><td>{severity.title()}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
    
    html_content += """
            </table>
        </div>
    """
    
    # Add detailed findings for each tool
    for tool_name, result_data in scan_results.items():
        tool_config = TOOLS.get(tool_name, {})
        vulnerabilities = result_data.get('vulnerabilities', [])
        
        html_content += f"""
        <div class="section">
            <h2>🔧 {tool_config.get('name', tool_name)} Results</h2>
            <p><strong>Category:</strong> {tool_config.get('category', 'Unknown')}</p>
            <p><strong>Description:</strong> {tool_config.get('description', 'No description available')}</p>
            <p><strong>Issues Found:</strong> {len(vulnerabilities)}</p>
        """
        
        if vulnerabilities:
            html_content += "<h3>🚨 Security Issues:</h3>"
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info')
                html_content += f"""
                <div class="vulnerability {severity}">
                    <strong>{vuln.get('type', 'Finding')} ({severity.upper()})</strong><br>
                    {vuln.get('description', 'No description')}<br>
                    <small><em>{vuln.get('detail', '')}</em></small>
                </div>
                """
        else:
            html_content += "<p>✅ No security issues detected by this tool.</p>"
        
        html_content += "</div>"
    
    # Add footer
    html_content += f"""
        <div class="footer">
            <p>🛡️ <strong>KOHA Cyber Threat Scanner</strong> - Advanced Security Assessment Platform</p>
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
            <p><strong>⚖️ LEGAL NOTICE:</strong> This scan was conducted on authorized systems only.</p>
        </div>
    </body>
    </html>
    """
    
    # Save HTML report
    html_filename = f"enhanced_report_{target_ip.replace('.', '_')}_{timestamp}.html"
    html_filepath = os.path.join(RESULTS_DIR, html_filename)
    with open(html_filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Generate PDF report
    pdf_filename = f"enhanced_report_{target_ip.replace('.', '_')}_{timestamp}.pdf"
    pdf_filepath = os.path.join(RESULTS_DIR, pdf_filename)
    try:
        HTML(html_filepath).write_pdf(pdf_filepath)
    except Exception as e:
        st.error(f"Failed to generate PDF: {str(e)}")
        pdf_filepath = None
    
    return html_filepath, pdf_filepath, {
        'total_vulnerabilities': total_vulnerabilities,
        'severity_counts': severity_counts,
        'tool_counts': tool_counts,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_percentage': risk_percentage
    }

# Initialize session state for better UX
if 'target_analyzed' not in st.session_state:
    st.session_state.target_analyzed = False
if 'target_info' not in st.session_state:
    st.session_state.target_info = None
if 'selected_tools' not in st.session_state:
    st.session_state.selected_tools = []
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}
if 'all_vulnerabilities' not in st.session_state:
    st.session_state.all_vulnerabilities = []

# Initialize tool selection states
for tool_name in TOOLS.keys():
    if f'tool_selected_{tool_name}' not in st.session_state:
        st.session_state[f'tool_selected_{tool_name}'] = False

# Main interface
col1, col2 = st.columns([2, 1])

# Sidebar content (col2) - Always visible
with col2:
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                padding: 1rem; border-radius: 10px; border: 1px solid #00ff00;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3); margin-bottom: 1rem;">
        <h3 style="color: #ff0040; font-family: 'Orbitron', monospace; text-align: center; margin: 0;">
            💀 COMMAND CENTER 💀
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Arsenal Status Summary (always visible)
    available_tools = 0
    total_tools = len(TOOLS)
    
    # Quick status check for summary
    for tool_name, config in TOOLS.items():
        tool_available = check_tool_available(tool_name)
        has_fallback = config.get('fallback', False)
        
        if tool_available:
            available_tools += 1
        elif has_fallback:
            available_tools += 0.5
    
    # Arsenal readiness calculation
    readiness_percentage = (available_tools / total_tools) * 100
    if readiness_percentage >= 80:
        readiness_status = "🟢 FULLY ARMED"
        readiness_color = "#00ff00"
    elif readiness_percentage >= 60:
        readiness_status = "🟡 COMBAT READY"
        readiness_color = "#ffff00"
    else:
        readiness_status = "🔴 LIMITED CAPACITY"
        readiness_color = "#ff0040"
    
    # Compact arsenal summary always visible
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border: 1px solid {readiness_color}; border-radius: 8px; padding: 0.75rem; margin: 0.5rem 0;">
        <div style="color: {readiness_color}; font-weight: bold; font-size: 0.9rem;">
            🛠️ ARSENAL STATUS
        </div>
        <div style="color: #cccccc; font-size: 0.8rem; margin: 0.25rem 0;">
            {readiness_status} | {readiness_percentage:.1f}% Ready
        </div>
        <div style="color: #888; font-size: 0.7rem;">
            {int(available_tools)}/{total_tools} tools operational
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Detailed arsenal status in collapsible expander
    with st.expander("🔧 **View Detailed Arsenal Status**", expanded=False):
        st.markdown("**Tool Arsenal Overview:**")
        
        # Enhanced tool status display
        for tool_name, config in TOOLS.items():
            tool_available = check_tool_available(tool_name)
            has_fallback = config.get('fallback', False)
            
            if tool_available:
                status = "🟢 OPERATIONAL"
                status_color = "#00ff00"
            elif has_fallback:
                status = "🟡 BACKUP MODE"
                status_color = "#ffff00"
            else:
                status = "🔴 OFFLINE"
                status_color = "#ff0040"
            
            category_colors = {
                'Network': '#28a745',
                'Web': '#007bff', 
                'Vulnerability': '#dc3545',
                'Reconnaissance': '#6f42c1',
                'CMS': '#fd7e14'
            }
            
            border_color = category_colors.get(config['category'], '#00ff00')
            
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                        padding: 1rem; border-radius: 8px; margin-bottom: 10px;
                        border-left: 4px solid {border_color}; border: 1px solid {border_color};
                        box-shadow: 0 0 15px rgba(0, 255, 0, 0.2); transition: all 0.3s ease;">
                <div style="color: {status_color}; font-weight: bold; font-family: 'Orbitron', monospace;">
                    {config['name']}
                </div>
                <div style="color: {status_color}; font-size: 0.8rem; margin: 5px 0;">
                    {status}
                </div>
                <div style="color: #cccccc; font-size: 0.8rem;">
                    {config['description']}
                </div>
                <div style="color: {border_color}; font-size: 0.7rem; margin-top: 5px;">
                    Category: {config['category']}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    # Scan History Summary (always visible)
    if os.path.exists(RESULTS_DIR):
        scan_files = sorted([f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')], 
                           key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), 
                           reverse=True)
        recent_scans_count = len(scan_files)
        latest_scan_time = None
        if scan_files:
            latest_file = os.path.join(RESULTS_DIR, scan_files[0])
            latest_scan_time = datetime.datetime.fromtimestamp(os.path.getmtime(latest_file))
        
        # Compact summary always visible
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    border: 1px solid #00ff00; border-radius: 8px; padding: 0.75rem; margin: 0.5rem 0;">
            <div style="color: #00ff00; font-weight: bold; font-size: 0.9rem;">
                📡 SCAN ACTIVITY
            </div>
            <div style="color: #cccccc; font-size: 0.8rem; margin: 0.25rem 0;">
                {recent_scans_count} total scans
            </div>
            {f'<div style="color: #888; font-size: 0.7rem;">Last: {latest_scan_time.strftime("%m/%d %H:%M")}</div>' if latest_scan_time else '<div style="color: #888; font-size: 0.7rem;">No scans yet</div>'}
        </div>
        """, unsafe_allow_html=True)
        
        # Detailed scan history in collapsible expander
        with st.expander("🔍 **View Detailed Scan History**", expanded=False):
            if scan_files:
                st.markdown("**Recent Scans (Last 10):**")
                for scan_file in scan_files[:10]:
                    file_path = os.path.join(RESULTS_DIR, scan_file)
                    file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    # Parse filename for info
                    parts = scan_file.replace('.json', '').split('_')
                    if len(parts) >= 2:
                        tool_name = parts[0]
                        target = '_'.join(parts[1:-2]).replace('_', '.')
                        
                        # Determine scan type icon
                        tool_icons = {
                            'nmap': '🔍', 'nikto': '🕷️', 'sqlmap': '💉', 'gobuster': '📁',
                            'nuclei': '⚡', 'whatweb': '🌐', 'wpscan': '📝', 'masscan': '⚡'
                        }
                        
                        tool_icon = tool_icons.get(tool_name, '🔧')
                        
                        col_scan, col_download = st.columns([4, 1])
                        with col_scan:
                            st.markdown(f"""
                            <div style="background: rgba(26, 26, 46, 0.5); padding: 0.5rem; margin: 0.25rem 0; 
                                        border-radius: 5px; border-left: 2px solid #00ff00; font-size: 0.75rem;">
                                <div style="color: #00ff00; font-weight: bold;">
                                    {tool_icon} {tool_name.upper()}
                                </div>
                                <div style="color: #cccccc;">Target: {target}</div>
                                <div style="color: #888; font-size: 0.7rem;">
                                    {file_time.strftime("%Y-%m-%d %H:%M")}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col_download:
                            try:
                                with open(file_path, 'r') as f:
                                    file_content = f.read()
                                    st.download_button(
                                        label="⬇️",
                                        data=file_content,
                                        file_name=scan_file,
                                        mime="application/json",
                                        key=f"download_{scan_file}",
                                        help=f"Download {scan_file}",
                                        use_container_width=True
                                    )
                            except:
                                pass
            else:
                st.markdown("""
                <div style="text-align: center; padding: 1.5rem; color: #666;">
                    <div style="font-size: 2rem;">👻</div>
                    <div>No scan history found</div>
                    <div style="font-size: 0.8rem;">Run your first scan to see results here</div>
                </div>
                """, unsafe_allow_html=True)
    
    # Intelligence Metrics Summary (always visible)
    if os.path.exists(RESULTS_DIR):
        total_scans = len([f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')])
        
        # Count vulnerabilities from recent scans
        total_vulns = 0
        critical_vulns = 0
        if scan_files:
            for scan_file in scan_files[:20]:  # Check last 20 scans
                try:
                    with open(os.path.join(RESULTS_DIR, scan_file), 'r') as f:
                        data = json.load(f)
                        vulns = data.get('vulnerabilities', [])
                        total_vulns += len(vulns)
                        critical_vulns += len([v for v in vulns if v.get('severity') == 'critical'])
                except:
                    continue
        
        # Compact metrics summary always visible
        security_score = max(0, 100 - (critical_vulns * 10))
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    border: 1px solid #17a2b8; border-radius: 8px; padding: 0.75rem; margin: 0.5rem 0;">
            <div style="color: #17a2b8; font-weight: bold; font-size: 0.9rem;">
                📊 INTELLIGENCE OVERVIEW
            </div>
            <div style="color: #cccccc; font-size: 0.8rem; margin: 0.25rem 0;">
                Security Score: {security_score}% | Scans: {total_scans} | Issues: {total_vulns}
            </div>
            {f'<div style="color: #ff0040; font-size: 0.7rem;">⚠️ {critical_vulns} critical vulnerabilities</div>' if critical_vulns > 0 else '<div style="color: #00ff00; font-size: 0.7rem;">✅ No critical issues found</div>'}
        </div>
        """, unsafe_allow_html=True)
        
        # Detailed metrics in collapsible expander
        with st.expander("📈 **View Detailed Intelligence Metrics**", expanded=False):
            st.markdown("**Security Intelligence Dashboard:**")
            
            # Enhanced metrics display
            metrics_data = [
                ("🎯", "Total Scans", total_scans, "#00ff00"),
                ("🚨", "Vulnerabilities", total_vulns, "#ff6b35"),
                ("💀", "Critical Issues", critical_vulns, "#ff0040"),
                ("🛡️", "Security Score", f"{security_score}%", "#17a2b8")
            ]
            
            for icon, label, value, color in metrics_data:
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                            border: 1px solid {color}; border-radius: 8px; padding: 1rem; margin: 0.5rem 0;
                            text-align: center; box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);">
                    <div style="color: {color}; font-size: 1.8rem; font-family: 'Orbitron', monospace;">
                        {icon} {value}
                    </div>
                    <div style="color: #cccccc; font-size: 0.8rem; text-transform: uppercase;">
                        {label}
                    </div>
                </div>
                """, unsafe_allow_html=True)

# Main content area (col1)
with col1:
    st.subheader("🎯 Target Configuration")
    
    target_ip = st.text_input("Target IP Address or Domain", placeholder="192.168.1.100 or example.com", key="target_ip")
    
    # Only analyze target when it changes or analyze button is clicked
    analyze_target = st.button("🔍 Analyze Target", type="secondary", use_container_width=True)
    
    if target_ip and (analyze_target or (st.session_state.get('last_target') != target_ip)):
        st.session_state.last_target = target_ip
        with st.spinner("Analyzing target..."):
            st.session_state.target_info = validate_target(target_ip)
            st.session_state.target_analyzed = True
            st.session_state.scan_completed = False  # Reset scan results when target changes
    
    # Display target analysis results if available
    if st.session_state.target_analyzed and st.session_state.target_info:
        target_info = st.session_state.target_info
        
        if target_info['open_ports']:
            st.markdown(f"""
            <div class="target-info">
                <h4>🔍 Target Analysis Results</h4>
                <p><strong>Target:</strong> {target_ip}</p>
                <p><strong>Open Ports:</strong> {len(target_info['open_ports'])}</p>
                <p><strong>Services:</strong> {', '.join([f"{port}/{service}" for port, service in target_info['services'].items()][:8])}</p>
                <p><strong>Web Services:</strong> {'✅ Available' if target_info['has_web'] else '❌ Not detected'}</p>
                {f"<p><strong>Protocols:</strong> {', '.join(target_info['protocols'])}</p>" if target_info['protocols'] else ""}
            </div>
            """, unsafe_allow_html=True)
            
            # Tool selection section - only show if target is analyzed
            st.subheader("🔧 Available Security Tools")
            
            # Get appropriate tools for this target
            suitable_tools = get_appropriate_tools(target_info)
            
            # Group tools by category
            categories = {}
            for tool_name, config in TOOLS.items():
                category = config['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append((tool_name, config))
            
            # Use form to prevent refreshing on each checkbox
            with st.form("tool_selection_form"):
                st.markdown("**Select tools for scanning (changes won't refresh the page):**")
                
                selected_tools = []
                
                # Display tools by category with checkboxes
                for category, tools in categories.items():
                    st.markdown(f"**{category} Tools**")
                    
                    for tool_name, config in tools:
                        # Check if tool is suitable for this target
                        is_suitable = tool_name in suitable_tools
                        tool_available = check_tool_available(tool_name)
                        has_fallback = config.get('fallback', False)
                        
                        if not is_suitable:
                            status_icon = "🚫"
                            status_text = " (not suitable for this target)"
                            disabled = True
                        elif tool_available:
                            status_icon = "✅"
                            status_text = ""
                            disabled = False
                        elif has_fallback:
                            status_icon = "⚠️"
                            status_text = " (fallback available)"
                            disabled = False
                        else:
                            status_icon = "❌"
                            status_text = " (not available)"
                            disabled = True
                        
                        # Use session state for checkbox value
                        tool_selected = st.checkbox(
                            f"{status_icon} {config['name']}{status_text}",
                            key=f"tool_{tool_name}",
                            help=config['description'],
                            disabled=disabled,
                            value=st.session_state.get(f'tool_selected_{tool_name}', False)
                        )
                        
                        if tool_selected and is_suitable and not disabled:
                            selected_tools.append(tool_name)
                
                # Scan mode selection
                st.markdown("---")
                st.subheader("⚙️ Scan Configuration")
                
                scan_mode = st.selectbox(
                    "Scan Mode",
                    ["Custom Selection", "Quick Scan (Recommended)", "Full Scan (All Suitable Tools)"],
                    help="Choose your scanning strategy"
                )
                
                # Submit button for tool selection
                tools_submitted = st.form_submit_button("✅ Confirm Tool Selection", use_container_width=True)
                
                if tools_submitted:
                    # Update session state with current selections
                    for tool_name in TOOLS.keys():
                        st.session_state[f'tool_selected_{tool_name}'] = st.session_state.get(f'tool_{tool_name}', False)
                    
                    if scan_mode == "Full Scan (All Suitable Tools)":
                        # Update all suitable tools to selected
                        for tool_name in TOOLS.keys():
                            st.session_state[f'tool_selected_{tool_name}'] = tool_name in suitable_tools
                        st.session_state.selected_tools = suitable_tools
                    elif scan_mode == "Quick Scan (Recommended)":
                        # Reset all selections first
                        for tool_name in TOOLS.keys():
                            st.session_state[f'tool_selected_{tool_name}'] = False
                        # Select quick scan tools
                        quick_tools = ["nmap"]
                        if target_info['has_web']:
                            quick_tools.extend(["whatweb", "gobuster"])
                        quick_tools_available = [tool for tool in quick_tools if tool in suitable_tools]
                        for tool_name in quick_tools_available:
                            st.session_state[f'tool_selected_{tool_name}'] = True
                        st.session_state.selected_tools = quick_tools_available
                    else:  # Custom Selection
                        st.session_state.selected_tools = selected_tools
                    
                    st.success(f"✅ Selected {len(st.session_state.selected_tools)} tools: {', '.join(st.session_state.selected_tools)}")
                    st.rerun()  # Refresh to update the UI with new selections
            
            # Show selected tools
            if st.session_state.selected_tools:
                st.markdown("**🎯 Selected Tools for Scanning:**")
                tool_cols = st.columns(min(len(st.session_state.selected_tools), 4))
                for i, tool_name in enumerate(st.session_state.selected_tools):
                    with tool_cols[i % 4]:
                        config = TOOLS[tool_name]
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                                    padding: 0.5rem; border-radius: 5px; border: 1px solid #00ff00;
                                    text-align: center; margin: 0.25rem 0;">
                            <div style="color: #00ff00; font-weight: bold; font-size: 0.8rem;">
                                {config['name']}
                            </div>
                            <div style="color: #cccccc; font-size: 0.7rem;">
                                {config['category']}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
            
            # Scan execution - separate from tool selection
            st.markdown("---")
            if st.session_state.selected_tools:
                scan_col1, scan_col2 = st.columns([3, 1])
                
                with scan_col1:
                    if st.button("🚀 START SECURITY SCAN", type="primary", use_container_width=True):
                        # Perform the actual scan
                        scan_results = {}
                        all_vulnerabilities = []
                        
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        st.info(f"🔍 Starting scan with {len(st.session_state.selected_tools)} tools...")
                        
                        for i, tool_name in enumerate(st.session_state.selected_tools):
                            config = TOOLS[tool_name]
                            status_text.text(f"Running {config['name']}... ({i+1}/{len(st.session_state.selected_tools)})")
                            
                            output, vulnerabilities = run_tool_scan(tool_name, target_ip, target_info)
                            scan_results[tool_name] = {
                                'output': output,
                                'vulnerabilities': vulnerabilities
                            }
                            all_vulnerabilities.extend(vulnerabilities)
                            
                            # Save results
                            if output:
                                save_results(tool_name, target_ip, output, vulnerabilities)
                            
                            progress_bar.progress((i + 1) / len(st.session_state.selected_tools))
                        
                        # Store results in session state
                        st.session_state.scan_results = scan_results
                        st.session_state.all_vulnerabilities = all_vulnerabilities
                        st.session_state.scan_completed = True
                        
                        status_text.text("✅ Scan completed!")
                        
                        # Display summary
                        total_issues = len(all_vulnerabilities)
                        if total_issues > 0:
                            st.success(f"🎯 Scan completed! Found {total_issues} potential security issues across {len(st.session_state.selected_tools)} tools.")
                        else:
                            st.info(f"✅ Scan completed! No major security issues detected across {len(st.session_state.selected_tools)} tools.")
                
                with scan_col2:
                    if st.button("🔄 New Target", use_container_width=True, help="Clear results and start fresh"):
                        # Reset session state
                        st.session_state.target_analyzed = False
                        st.session_state.target_info = None
                        st.session_state.selected_tools = []
                        st.session_state.scan_completed = False
                        st.session_state.scan_results = {}
                        st.session_state.all_vulnerabilities = []
                        
                        # Reset tool selection states
                        for tool_name in TOOLS.keys():
                            st.session_state[f'tool_selected_{tool_name}'] = False
                        
                        if 'last_target' in st.session_state:
                            del st.session_state.last_target
                        st.rerun()
            else:
                st.warning("⚠️ Please select at least one tool before starting the scan.")
        else:
            st.warning("⚠️ No open ports detected on target. Target may be down or filtered.")
                
    # Display scan results if available
    if st.session_state.scan_completed and st.session_state.scan_results:
        scan_results = st.session_state.scan_results
        all_vulnerabilities = st.session_state.all_vulnerabilities
        target_info = st.session_state.target_info
        total_issues = len(all_vulnerabilities)
        
        # Enhanced Vulnerability Analysis with Charts
        if all_vulnerabilities:
            severity_counts = {}
            for vuln in all_vulnerabilities:
                severity = vuln.get('severity', 'info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Display severity summary with enhanced visuals
            st.subheader("🎯 THREAT ASSESSMENT MATRIX")
            
            # Risk calculation
            risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            risk_score = sum(risk_weights.get(sev, 1) * count for sev, count in severity_counts.items())
            max_possible_score = total_issues * 10
            risk_percentage = (risk_score / max_possible_score * 100) if max_possible_score > 0 else 0
            
            # Risk level determination
            if risk_percentage >= 80:
                risk_level = "🚨 CRITICAL THREAT"
                risk_color = "#ff0040"
            elif risk_percentage >= 60:
                risk_level = "⚠️ HIGH RISK"
                risk_color = "#ff6b35"
            elif risk_percentage >= 40:
                risk_level = "📢 MEDIUM RISK"
                risk_color = "#17a2b8"
            elif risk_percentage >= 20:
                risk_level = "ℹ️ LOW RISK"
                risk_color = "#28a745"
            else:
                risk_level = "✅ MINIMAL RISK"
                risk_color = "#6c757d"
            
            # Display risk indicator
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, rgba(255, 0, 64, 0.1) 0%, rgba(139, 0, 0, 0.1) 100%);
                        border: 2px solid {risk_color}; border-radius: 10px; padding: 1rem; margin: 1rem 0;
                        text-align: center; color: {risk_color}; font-family: 'Orbitron', monospace;">
                <div style="font-size: 2rem; font-weight: 900;">{risk_level}</div>
                <div>Risk Score: {risk_score}/{max_possible_score} ({risk_percentage:.1f}%)</div>
            </div>
            """, unsafe_allow_html=True)
            
            # Metrics grid
            cols = st.columns(5)
            severity_icons = {
                'critical': '🚨',
                'high': '⚠️',
                'medium': '📋',
                'low': '💡',
                'info': 'ℹ️'
            }
            
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            for i, severity in enumerate(severity_order):
                count = severity_counts.get(severity, 0)
                with cols[i]:
                    st.metric(
                        label=f"{severity_icons.get(severity, '📋')} {severity.title()}",
                        value=count,
                        delta=None
                    )
            
            # Generate and display charts
            st.subheader("📊 VISUAL THREAT ANALYSIS")
            pie_fig, bar_fig, timeline_fig = create_vulnerability_charts(all_vulnerabilities)
            
            if pie_fig and bar_fig:
                chart_cols = st.columns(2)
                with chart_cols[0]:
                    st.plotly_chart(pie_fig, use_container_width=True)
                with chart_cols[1]:
                    st.plotly_chart(bar_fig, use_container_width=True)
                
                if timeline_fig:
                    st.plotly_chart(timeline_fig, use_container_width=True)
            
            # Generate enhanced reports
            st.subheader("📋 EXPORT REPORTS")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📄 Generate HTML Report", use_container_width=True):
                    with st.spinner("Generating HTML report..."):
                        html_path, pdf_path, stats = generate_enhanced_report(scan_results, target_info, target_ip)
                        st.success(f"✅ HTML report generated: {os.path.basename(html_path)}")
                        
                        with open(html_path, 'r', encoding='utf-8') as f:
                            st.download_button(
                                label="⬇️ Download HTML",
                                data=f.read(),
                                file_name=os.path.basename(html_path),
                                mime="text/html"
                            )
            
            with col2:
                if st.button("📊 Generate PDF Report", use_container_width=True):
                    with st.spinner("Generating PDF report..."):
                        try:
                            html_path, pdf_path, stats = generate_enhanced_report(scan_results, target_info, target_ip)
                            if pdf_path and os.path.exists(pdf_path):
                                st.success(f"✅ PDF report generated: {os.path.basename(pdf_path)}")
                                
                                with open(pdf_path, 'rb') as f:
                                    st.download_button(
                                        label="⬇️ Download PDF",
                                        data=f.read(),
                                        file_name=os.path.basename(pdf_path),
                                        mime="application/pdf"
                                    )
                            else:
                                st.error("❌ PDF generation failed")
                        except Exception as e:
                            st.error(f"❌ PDF generation error: {str(e)}")
            
            with col3:
                if st.button("📊 Generate JSON Data", use_container_width=True):
                    with st.spinner("Generating JSON export..."):
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        json_data = {
                            'scan_summary': {
                                'target': target_ip,
                                'timestamp': datetime.datetime.now().isoformat(),
                                'total_vulnerabilities': total_issues,
                                'risk_score': risk_score,
                                'risk_level': risk_level,
                                'risk_percentage': risk_percentage
                            },
                            'vulnerability_breakdown': severity_counts,
                            'scan_results': scan_results,
                            'target_info': target_info
                        }
                        
                        json_filename = f"comprehensive_scan_{target_ip.replace('.', '_')}_{timestamp}.json"
                        st.download_button(
                            label="⬇️ Download JSON",
                            data=json.dumps(json_data, indent=2),
                            file_name=json_filename,
                            mime="application/json"
                        )
            
            # AI-Powered Librarian Reports Section
            st.markdown("---")
            st.subheader("🤖 AI-POWERED SECURITY REPORTS")
            st.markdown("""
            **Transform technical security findings into different report formats!**
            
            Choose from multiple report styles to match your audience and communication needs.
            """)
            
            # Report type selector
            report_type = st.selectbox(
                "📊 Select Report Style:",
                ["📚 Librarian-Friendly Report", "🚀 Cyberpunk Forensic Analysis", "📋 Standard Technical Report"],
                help="Choose the report style that best fits your needs"
            )
            
            ai_col1, ai_col2 = st.columns([2, 1])
            
            with ai_col1:
                if report_type == "📚 Librarian-Friendly Report":
                    button_text = "📚 Generate Librarian Report"
                    spinner_text = "🤖 Analyzing vulnerabilities with AI..."
                elif report_type == "🚀 Cyberpunk Forensic Analysis":
                    button_text = "🚀 Generate Forensic Analysis"
                    spinner_text = "⚡ Running cybersec forensic protocols..."
                else:
                    button_text = "📋 Generate Technical Report"
                    spinner_text = "🔍 Processing technical analysis..."
                
                if st.button(button_text, use_container_width=True, type="primary"):
                    with st.spinner(spinner_text):
                        try:
                            if report_type == "📚 Librarian-Friendly Report":
                                # Import LLM analysis module
                                from llm_analysis import LibrarianReportGenerator
                                
                                # Prepare vulnerability data for LLM analysis
                                vulnerability_data = {
                                    'target': target_ip,
                                    'total_vulnerabilities': total_issues,
                                    'severity_counts': severity_counts,
                                    'scan_results': scan_results,
                                    'target_info': target_info,
                                    'risk_score': risk_score,
                                    'risk_level': risk_level
                                }
                                
                                # Initialize the LLM generator (will use template if no LLM available)
                                generator = LibrarianReportGenerator()
                                
                                # Generate the librarian report
                                librarian_report = generator.generate_librarian_report(vulnerability_data)
                                
                                # Save the report
                                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                                librarian_filename = f"librarian_report_{target_ip.replace('.', '_')}_{timestamp}.md"
                                
                                st.success("✅ Librarian-friendly report generated!")
                                
                                # Display a preview
                                with st.expander("📖 Report Preview", expanded=True):
                                    preview_text = librarian_report[:1500] + "..." if len(librarian_report) > 1500 else librarian_report
                                    st.markdown(preview_text)
                                
                                # Download button
                                st.download_button(
                                    label="⬇️ Download Librarian Report (.md)",
                                    data=librarian_report,
                                    file_name=librarian_filename,
                                    mime="text/markdown",
                                    use_container_width=True
                                )
                            
                            elif report_type == "🚀 Cyberpunk Forensic Analysis":
                                # Generate cyberpunk forensic report
                                from llm_analysis import LibrarianReportGenerator
                                
                                # Prepare vulnerability data for forensic analysis
                                vulnerability_data = {
                                    'target': target_ip,
                                    'total_vulnerabilities': total_issues,
                                    'severity_counts': severity_counts,
                                    'scan_results': scan_results,
                                    'target_info': target_info,
                                    'risk_score': risk_score,
                                    'risk_level': risk_level
                                }
                                
                                # Initialize the generator
                                generator = LibrarianReportGenerator()
                                
                                # Generate the cyberpunk forensic report
                                forensic_report = generator.generate_forensic_cyberpunk_report(vulnerability_data)
                                
                                # Save the report
                                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                                forensic_filename = f"cyberpunk_forensic_{target_ip.replace('.', '_')}_{timestamp}.md"
                                
                                st.success("⚡ Cyberpunk forensic analysis complete!")
                                
                                # Display a preview with syntax highlighting
                                with st.expander("🚀 Forensic Analysis Preview", expanded=True):
                                    st.markdown("```")
                                    preview_text = forensic_report[:2000] + "\n[... truncated for preview ...]" if len(forensic_report) > 2000 else forensic_report
                                    st.code(preview_text, language="text")
                                    st.markdown("```")
                                
                                # Download button
                                st.download_button(
                                    label="⬇️ Download Forensic Analysis (.md)",
                                    data=forensic_report,
                                    file_name=forensic_filename,
                                    mime="text/markdown",
                                    use_container_width=True
                                )
                            
                            else:
                                # Standard Technical Report (simple text report as placeholder)
                                report_content = f"Technical Report for {target_ip}\nGenerated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                                report_content += "Vulnerabilities Found:\n"
                                for vuln in all_vulnerabilities:
                                    report_content += f"- {vuln.get('type', 'Unknown Issue')} ({vuln.get('severity', 'Info')}): {vuln.get('description', 'No details')}\n"
                                
                                # Save and download the technical report
                                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                                tech_report_filename = f"technical_report_{target_ip.replace('.', '_')}_{timestamp}.txt"
                                with open(tech_report_filename, 'w') as f:
                                    f.write(report_content)
                                
                                st.success("✅ Technical report generated!")
                                st.download_button(
                                    label="⬇️ Download Technical Report (.txt)",
                                    data=report_content,
                                    file_name=tech_report_filename,
                                    mime="text/plain",
                                    use_container_width=True
                                )
                        
                        except ImportError:
                            st.error("❌ LLM analysis module not available. Please install required dependencies.")
                            st.info("Run: `pip install llama-cpp-python transformers torch` to enable AI features.")
                        except Exception as e:
                            st.error(f"❌ Error generating report: {str(e)}")
            
            with ai_col2:
                st.info("""
                **What you'll get:**
                - Simple, non-technical language
                - Clear priority levels
                - Actionable recommendations
                - Library-specific context
                - Risk explanations anyone can understand
                """)
                
                if st.button("⚙️ Configure LLM", use_container_width=True):
                    st.info("""
                    **LLM Configuration:**
                    1. Edit `llm_config.json` to set your model path
                    2. Supported models: LLaMA, Mistral, HuggingFace models
                    3. Template mode available if no LLM is configured
                    
                    **Model Path Examples:**
                    - `/path/to/llama-2-7b-chat.gguf`
                    - `microsoft/DialoGPT-medium`
                    """)
                    
                    # Create config file if it doesn't exist
                    try:
                        from llm_analysis import create_model_config_file
                        config_path = create_model_config_file()
                        st.success(f"Configuration file created: {config_path}")
                    except Exception as e:
                        st.warning(f"Could not create config file: {str(e)}")
            
            # Enhanced Detailed Results with Improved Navigation
            st.subheader("🔍 DETAILED THREAT ANALYSIS")
            
            # Quick Navigation and Summary
            st.markdown("### 📋 Scan Summary")
            
            # Create a navigation bar for quick jumps
            nav_cols = st.columns(len(st.session_state.selected_tools) + 1)
            
            with nav_cols[0]:
                st.markdown("**Quick Jump:**")
            
            for idx, tool_name in enumerate(st.session_state.selected_tools):
                if tool_name in scan_results:
                    config = TOOLS[tool_name]
                    vulnerabilities = scan_results[tool_name]['vulnerabilities']
                    with nav_cols[idx + 1]:
                        color = "#ff0040" if len(vulnerabilities) > 0 else "#00ff00"
                        if st.button(f"{config['name'][:6]}... ({len(vulnerabilities)})", 
                                   key=f"nav_{tool_name}", 
                                   help=f"Jump to {config['name']} results"):
                            # This creates an anchor point (visual feedback)
                            pass
                        
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                                    border: 2px solid {color}; border-radius: 10px; padding: 0.5rem;
                                    text-align: center; margin: 0.2rem 0; font-size: 0.8rem;">
                            <div style="color: {color}; font-size: 1.2rem; font-weight: bold;">
                                {len(vulnerabilities)}
                            </div>
                            <div style="color: #cccccc; font-size: 0.7rem;">
                                {config['name']}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
            
            # Improved collapsible results sections
            st.markdown("---")
            
            for tool_name in st.session_state.selected_tools:
                if tool_name in scan_results:
                    config = TOOLS[tool_name]
                    result_data = scan_results[tool_name]
                    vulnerabilities = result_data['vulnerabilities']
                    
                    # Smart expansion logic: auto-expand small results, collapse large ones
                    auto_expand = len(vulnerabilities) > 0 and len(vulnerabilities) <= 8
                    
                    # Create anchor for navigation
                    st.markdown(f'<div id="tool_{tool_name}"></div>', unsafe_allow_html=True)
                    
                    with st.expander(f"🔧 {config['name']} - {len(vulnerabilities)} Issues Found", expanded=auto_expand):
                        
                        # Compact tool info header
                        info_cols = st.columns([3, 1])
                        with info_cols[0]:
                            st.markdown(f"""
                            **🔧 {config['name']}** | Category: {config['category']}  
                            {config['description']}
                            """)
                        
                        with info_cols[1]:
                            issue_color = '#ff0040' if len(vulnerabilities) > 0 else '#00ff00'
                            st.markdown(f"""
                            <div style="text-align: center; padding: 0.5rem; 
                                        background: rgba(0,0,0,0.3); border-radius: 8px; 
                                        border: 2px solid {issue_color};">
                                <div style="color: {issue_color}; font-size: 1.5rem; font-weight: bold;">
                                    {len(vulnerabilities)}
                                </div>
                                <div style="color: #cccccc; font-size: 0.8rem;">Issues Found</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        # Handle vulnerability display with smart pagination
                        if vulnerabilities:
                            total_vulns = len(vulnerabilities)
                            
                            # For large result sets, show summary first
                            if total_vulns > 15:
                                st.warning(f"⚠️ Large result set detected ({total_vulns} issues). Using pagination for better performance.")
                                
                                # Show severity summary for large sets
                                severity_summary = {}
                                for v in vulnerabilities:
                                    sev = v.get('severity', 'info')
                                    severity_summary[sev] = severity_summary.get(sev, 0) + 1
                                
                                sum_cols = st.columns(len(severity_summary) if severity_summary else 1)
                                for idx, (sev, count) in enumerate(severity_summary.items()):
                                    if idx < len(sum_cols):
                                        with sum_cols[idx]:
                                            sev_color = {'critical': '#ff0040', 'high': '#ff6b35', 
                                                       'medium': '#17a2b8', 'low': '#28a745', 'info': '#6c757d'}.get(sev, '#6c757d')
                                            st.markdown(f"""
                                            <div style="text-align: center; padding: 0.3rem; background: rgba(0,0,0,0.2); 
                                                        border-radius: 5px; border: 1px solid {sev_color};">
                                                <div style="color: {sev_color}; font-weight: bold;">{count}</div>
                                                <div style="color: #ccc; font-size: 0.7rem;">{sev.title()}</div>
                                            </div>
                                            """, unsafe_allow_html=True)
                            
                            # Pagination for large lists
                            items_per_page = 12
                            if total_vulns > items_per_page:
                                total_pages = (total_vulns + items_per_page - 1) // items_per_page
                                
                                # Pagination controls
                                page_controls = st.columns([1, 3, 1])
                                with page_controls[1]:
                                    page = st.selectbox(
                                        f"📄 Page (showing {items_per_page} per page)",
                                        range(1, total_pages + 1),
                                        key=f"page_{tool_name}",
                                        format_func=lambda x: f"Page {x} of {total_pages}"
                                    )
                                
                                start_idx = (page - 1) * items_per_page
                                end_idx = min(start_idx + items_per_page, total_vulns)
                                current_vulns = vulnerabilities[start_idx:end_idx]
                                
                                st.info(f"📋 Showing vulnerabilities {start_idx + 1}-{end_idx} of {total_vulns}")
                            else:
                                current_vulns = vulnerabilities
                                start_idx = 0
                            
                            # Display vulnerabilities in a clean format
                            for i, vuln in enumerate(current_vulns):
                                display_idx = start_idx + i + 1
                                severity = vuln.get('severity', 'info')
                                severity_colors = {
                                    'critical': '#ff0040', 'high': '#ff6b35', 'medium': '#17a2b8', 
                                    'low': '#28a745', 'info': '#6c757d'
                                }
                                sev_color = severity_colors.get(severity, '#6c757d')
                                severity_icons = {
                                    'critical': '🔥', 'high': '⚠️', 'medium': '📋', 'low': '💡', 'info': 'ℹ️'
                                }
                                sev_icon = severity_icons.get(severity, '📋')
                                
                                # Compact vulnerability card
                                st.markdown(f"""
                                <div style="background: linear-gradient(135deg, rgba(26,26,46,0.8) 0%, rgba(22,33,62,0.8) 100%);
                                            border-left: 4px solid {sev_color}; border-radius: 8px; 
                                            padding: 0.8rem; margin: 0.5rem 0; 
                                            box-shadow: 0 2px 4px rgba(0,0,0,0.3);">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                                        <strong style="color: {sev_color};">
                                            {sev_icon} #{display_idx:02d} {vuln.get('type', 'Finding')}
                                        </strong>
                                        <span style="background: {sev_color}; color: white; padding: 2px 8px; 
                                                    border-radius: 12px; font-size: 0.7rem; font-weight: bold;">
                                            {severity.upper()}
                                        </span>
                                    </div>
                                    <div style="color: #e0e0e0; margin-bottom: 0.3rem;">
                                        <strong>Issue:</strong> {vuln.get('description', 'No description available')}
                                    </div>
                                    <div style="color: #b0b0b0; font-size: 0.9rem;">
                                        <strong>Details:</strong> 
                                        <code style="background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; 
                                                    color: #90EE90; font-size: 0.8rem;">
                                            {vuln.get('detail', 'No additional details')[:100]}{'...' if len(str(vuln.get('detail', ''))) > 100 else ''}
                                        </code>
                                    </div>
                                    <div style="text-align: right; margin-top: 0.3rem;">
                                        <small style="color: #888; font-style: italic;">via {tool_name}</small>
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                        else:
                            st.success("✅ No security issues detected by this tool.")
                        
                        # Raw output section (no nested expander)
                        st.markdown("---")
                        st.markdown("**📋 Raw Tool Output:**")
                        
                        # Show/hide toggle using session state
                        show_output_key = f"show_output_{tool_name}"
                        if show_output_key not in st.session_state:
                            st.session_state[show_output_key] = False
                        
                        # Toggle button for raw output
                        if st.button(f"{'🔽 Hide' if st.session_state[show_output_key] else '🔽 Show'} Raw Output", 
                                   key=f"toggle_{tool_name}_output"):
                            st.session_state[show_output_key] = not st.session_state[show_output_key]
                        
                        # Show output if toggled on
                        if st.session_state[show_output_key]:
                            output_text = result_data['output']
                            if len(output_text) > 5000:
                                st.warning(f"⚠️ Large output detected ({len(output_text)} characters). Showing first 5000 characters.")
                                st.code(output_text[:5000] + "\n\n[... OUTPUT TRUNCATED ...]", language='text')
                                
                                # Option to download full output
                                st.download_button(
                                    label="📥 Download Full Output",
                                    data=output_text,
                                    file_name=f"{tool_name}_full_output.txt",
                                    mime="text/plain",
                                    key=f"download_{tool_name}_output"
                                )
                            else:
                                st.code(output_text, language='text')
            
            # Add quick action buttons for easy access
            st.markdown("---")
            st.markdown("### ⚡ Quick Actions")
            action_cols = st.columns(4)
            
            with action_cols[0]:
                if st.button("📊 Jump to Charts", use_container_width=True):
                    st.markdown('<a href="#visual-threat-analysis">📊 Charts</a>', unsafe_allow_html=True)
            
            with action_cols[1]:
                if st.button("📄 Generate Reports", use_container_width=True):
                    st.markdown('<a href="#export-reports">📋 Reports</a>', unsafe_allow_html=True)
            
            with action_cols[2]:
                if st.button("🎯 New Scan", use_container_width=True):
                    st.session_state.target_analyzed = False
                    st.session_state.target_info = None
                    st.session_state.selected_tools = []
                    st.session_state.scan_completed = False
                    st.session_state.scan_results = {}
                    st.session_state.all_vulnerabilities = []
                    st.rerun()
            
            with action_cols[3]:
                # Download all results as JSON
                if st.button("💾 Download All Data", use_container_width=True):
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    all_data = {
                        'scan_summary': {
                            'target': target_ip,
                            'timestamp': datetime.datetime.now().isoformat(),
                            'total_vulnerabilities': len(all_vulnerabilities),
                            'tools_used': list(scan_results.keys())
                        },
                        'scan_results': scan_results,
                        'target_info': target_info
                    }
                    
                    st.download_button(
                        label="⬇️ Download Complete Scan Data",
                        data=json.dumps(all_data, indent=2),
                        file_name=f"complete_scan_{target_ip.replace('.', '_')}_{timestamp}.json",
                        mime="application/json",
                        use_container_width=True
                    )
            
            # Real-time threat intelligence (keeping inside col1 context)
            st.subheader("🌐 THREAT INTELLIGENCE")
            
            # Use simple layout instead of columns to avoid nesting
            st.markdown("### 📊 Security Metrics Overview")
            
            # Display metrics in a single row using HTML
            active_exploits = len([v for v in all_vulnerabilities if v.get('severity') in ['critical', 'high']])
            secure_services = len(target_info.get('open_ports', [])) - len([v for v in all_vulnerabilities if v.get('type') == 'Open Port'])
            security_score = 100 - risk_percentage
            
            st.markdown(f"""
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">
                <div class="metric-container">
                    <div style="color: #ff0040; font-size: 2rem; font-family: 'Orbitron', monospace;">
                        {active_exploits}</div>
                    <div>Active Exploits</div>
                </div>
                <div class="metric-container">
                    <div style="color: #00ff00; font-size: 2rem; font-family: 'Orbitron', monospace;">
                        {secure_services}</div>
                    <div>Secure Services</div>
                </div>
                <div class="metric-container">
                    <div style="color: #17a2b8; font-size: 2rem; font-family: 'Orbitron', monospace;">
                        {security_score:.1f}%</div>
                    <div>Security Score</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("✅ No vulnerabilities detected in the scan!")
    
    elif st.session_state.target_analyzed and not st.session_state.scan_completed:
        st.info("📋 Target analyzed. Please select tools and start the scan to see results.")

# Enhanced Compact Footer
st.markdown("---")

# Use CSS injection for animations
st.markdown("""
<style>
.footer-container {
    background: linear-gradient(135deg, #ff0040 0%, #8b0000 30%, #1a1a2e 100%);
    color: white;
    padding: 1rem;
    border-radius: 12px;
    margin: 1rem 0;
    border: 2px solid #ff0040;
    box-shadow: 0 0 20px rgba(255, 0, 64, 0.4);
    font-family: 'Rajdhani', sans-serif;
    position: relative;
    overflow: hidden;
}

.scanner-line {
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00ff00, transparent);
    animation: scan 3s linear infinite;
}

@keyframes scan {
    0% { left: -100%; }
    100% { left: 100%; }
}

.footer-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
}

.footer-left {
    flex: 1;
    min-width: 200px;
}

.footer-right {
    flex: 1;
    min-width: 150px;
    text-align: right;
}

.warning-text {
    font-size: 0.9rem;
    font-weight: 600;
    margin-bottom: 0.2rem;
}

.warning-highlight {
    color: #ffff00;
    text-shadow: 0 0 5px #ffff00;
}

.subtitle {
    font-size: 0.7rem;
    color: #cccccc;
    opacity: 0.9;
}

.version-text {
    font-size: 0.8rem;
    font-weight: 500;
    color: #00ff00;
    font-family: 'Orbitron', monospace;
    text-shadow: 0 0 5px #00ff00;
}

.division-text {
    font-size: 0.6rem;
    color: #ff6b35;
    margin-top: 0.1rem;
}
</style>
""", unsafe_allow_html=True)

# Create the footer using HTML with CSS classes
st.markdown("""
<div class="footer-container">
    <div class="scanner-line"></div>
    <div class="footer-content">
        <div class="footer-left">
            <div class="warning-text">
                🚨 <strong class="warning-highlight">AUTHORIZED USE ONLY</strong>
            </div>
            <div class="subtitle">
                Test own systems only • Follow responsible disclosure
            </div>
        </div>
        <div class="footer-right">
            <div class="version-text">
                KOHA v2.0 | 2025
            </div>
            <div class="division-text">
                Security Research Division
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Enhanced Help section
with st.expander("🔥 TACTICAL OPERATIONS MANUAL 🔥", expanded=False):
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                padding: 1.5rem; border-radius: 10px; border: 1px solid #00ff00;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);">
    """, unsafe_allow_html=True)
    
    st.markdown("""
    ## 🔧 ARSENAL SPECIFICATIONS
    
    ### 🌐 Network Warfare Tools
    - **🔍 Nmap**: Industry-standard port scanner and service detection - The reconnaissance king
    - **⚡ Masscan**: High-speed port scanner capable of scanning the entire Internet in under 5 minutes
    
    ### 🕷️ Web Application Assault Tools  
    - **🕷️ Nikto**: Web server vulnerability scanner with over 6700 potentially dangerous files/programs
    - **💉 SQLMap**: Automated SQL injection detection and exploitation tool - Database infiltration specialist
    - **📁 Gobuster**: Directory and file brute-forcing tool - Uncover hidden attack surfaces
    - **⚡ Nuclei**: Fast vulnerability scanner with 4000+ templates - Community-powered threat detection
    - **🌐 WhatWeb**: Web application fingerprinting - Technology stack reconnaissance
    
    ### 🎯 Specialized CMS Tools
    - **📝 WPScan**: WordPress-specific security scanner - Dominate the world's most popular CMS
    
    ## 🚨 THREAT CLASSIFICATION SYSTEM
    
    - **🚨 CRITICAL**: Immediate exploitation possible - System compromise imminent
    - **⚠️ HIGH**: Significant security risk - Rapid response required  
    - **📢 MEDIUM**: Moderate risk level - Investigate and remediate
    - **ℹ️ LOW**: Minor security concern - Monitor and assess
    - **📋 INFO**: Intelligence gathering - No immediate threat
    
    ## 📋 OPERATIONAL PROCEDURES
    
    ### 🎯 Phase 1: Target Acquisition
    1. **Target Analysis**: System automatically analyzes target to determine available services
    2. **Service Enumeration**: Identifies web services, open ports, and running protocols
    3. **Attack Surface Mapping**: Determines optimal tools for comprehensive assessment
    
    ### ⚔️ Phase 2: Assault Configuration
    - **🔥 QUICK STRIKE**: Essential tools for rapid assessment (Recommended for stealth operations)
    - **💥 FULL ASSAULT**: Deploy all suitable tools for maximum coverage (Total warfare mode)
    - **🎯 PRECISION STRIKE**: Manual tool selection for targeted operations
    
    ### 📊 Phase 3: Intelligence Analysis
    - **Real-time Threat Visualization**: Interactive charts and graphs showing vulnerability distribution
    - **Risk Assessment Matrix**: Automated risk scoring based on vulnerability severity
    - **Threat Intelligence**: Live analysis of discovered attack vectors
    
    ### 📋 Phase 4: Mission Reporting
    - **📄 HTML Intelligence Reports**: Comprehensive web-based reports with full styling
    - **📊 PDF Tactical Briefings**: Print-ready reports for offline analysis
    - **💾 JSON Data Exports**: Machine-readable format for integration with other tools
    
    ## 🌐 ADVANCED FEATURES
    
    ### 🔍 Smart Target Analysis
    - Automatic service detection and categorization
    - Intelligent tool recommendation based on discovered services
    - Real-time port scanning with socket-based fallbacks
    
    ### 📊 Visual Threat Intelligence
    - Interactive pie charts showing vulnerability distribution by severity
    - Bar charts displaying tool effectiveness and issue discovery rates  
    - Timeline analysis for vulnerability discovery patterns
    - Risk scoring algorithms with threat level classification
    
    ### 🎯 Enhanced Reporting Engine
    - Futuristic HTML reports with CSS3 animations and gradients
    - Professional PDF generation with charts and detailed analysis
    - Comprehensive JSON exports with full scan metadata
    - Real-time report generation with download capabilities
    
    ## ⚖️ RULES OF ENGAGEMENT
    
    **🚨 CRITICAL WARNING 🚨**
    
    This is a **LETHAL DIGITAL WEAPON SYSTEM**. Unauthorized use is strictly prohibited and may result in:
    - Criminal prosecution under computer fraud laws
    - Civil liability for damages
    - Academic/professional disciplinary action
    - Permanent legal consequences
    
    ### ✅ Authorized Usage Only
    - **✅ YOUR OWN SYSTEMS**: Full permission to scan and test
    - **✅ EXPLICIT WRITTEN CONSENT**: Documented authorization from system owner
    - **✅ PENETRATION TESTING CONTRACTS**: Professional security assessments
    - **✅ EDUCATIONAL LAB ENVIRONMENTS**: Designated training systems
    
    ### ❌ Prohibited Activities  
    - **❌ UNAUTHORIZED SCANNING**: Never scan systems without permission
    - **❌ MALICIOUS INTENT**: This tool is for security assessment only
    - **❌ DATA THEFT**: Do not extract or steal sensitive information
    - **❌ SERVICE DISRUPTION**: Avoid causing system downtime or damage
    
    ### 🛡️ Responsible Disclosure
    1. **Document findings professionally**
    2. **Report vulnerabilities to system owners first**
    3. **Allow reasonable time for remediation** 
    4. **Follow coordinated disclosure timelines**
    5. **Protect sensitive information during the process**
    
    ## 🔧 TECHNICAL SPECIFICATIONS
    
    ### 🖥️ System Requirements
    - **OS**: Linux/Unix recommended (Windows WSL supported)
    - **Python**: 3.8+ with virtual environment
    - **Memory**: 4GB RAM minimum, 8GB recommended
    - **Storage**: 2GB free space for reports and logs
    - **Network**: Unrestricted outbound connectivity
    
    ### 📦 Dependencies
    - **Streamlit**: Modern web interface framework
    - **Plotly**: Interactive charting and visualization
    - **Requests**: HTTP client for web reconnaissance  
    - **WeasyPrint**: PDF report generation engine
    - **Pandas**: Data analysis and manipulation
    - **NumPy**: Numerical computing support
    
    ### 🔌 External Tool Integration
    The scanner automatically detects and integrates with:
    - Security tools installed via package managers
    - Custom tool installations in system PATH
    - Fallback implementations for missing tools
    - Docker container support for isolated execution
    
    **Remember: With great power comes great responsibility. Use this arsenal wisely.**
    """)
    
    st.markdown("</div>", unsafe_allow_html=True)

# Export functionality with human-readable report
if st.button("📊 Generate Summary Report"):
    if os.path.exists(RESULTS_DIR):
        scan_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')]

        if scan_files:
            summary_data = {
                'report_generated': datetime.datetime.now().isoformat(),
                'total_scans': len(scan_files),
                'scans': [],
                'total_vulnerabilities': 0,
                'severity_summary': {}
            }

            for scan_file in scan_files[-10:]:
                try:
                    with open(os.path.join(RESULTS_DIR, scan_file), 'r') as f:
                        data = json.load(f)
                        summary_data['scans'].append({
                            'tool': data.get('tool'),
                            'target': data.get('target'),
                            'timestamp': data.get('timestamp'),
                            'vulnerability_count': data.get('vulnerability_count', 0),
                            'vulnerabilities': data.get('vulnerabilities', [])
                        })

                        for vuln in data.get('vulnerabilities', []):
                            severity = vuln.get('severity', 'info')
                            summary_data['severity_summary'][severity] = summary_data['severity_summary'].get(severity, 0) + 1
                            summary_data['total_vulnerabilities'] += 1
                except:
                    continue

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"security_summary_report_{timestamp}.json"
            html_filename = f"report_{timestamp}.html"
            pdf_filename = f"report_{timestamp}.pdf"

            # Create human-readable HTML report
            html_content = f"""
            <html><head><style>
            body {{ font-family: Arial; padding: 20px; }}
            h1 {{ background: #333; color: white; padding: 10px; }}
            h2 {{ color: #0056b3; }}
            .vuln {{ border: 1px solid #ccc; margin-bottom: 10px; padding: 10px; border-radius: 5px; }}
            .critical {{ background-color: #f8d7da; }}
            .high {{ background-color: #fff3cd; }}
            .medium {{ background-color: #d1ecf1; }}
            .low {{ background-color: #d4edda; }}
            .info {{ background-color: #f8f9fa; }}
            </style></head><body>
            <h1>Koha Security Summary Report</h1>
            <p><strong>Generated:</strong> {summary_data['report_generated']}</p>
            <h2>📊 Summary</h2>
            <p>Total Scans: {summary_data['total_scans']}<br>
               Total Vulnerabilities: {summary_data['total_vulnerabilities']}</p>
            <h3>Severity Breakdown:</h3><ul>
            {''.join(f'<li>{sev.title()}: {count}</li>' for sev, count in summary_data['severity_summary'].items())}
            </ul><hr>
            """

            for scan in summary_data['scans']:
                html_content += f"""
                <h2>Target: {scan['target']} ({scan['tool']})</h2>
                <p><strong>Vulnerabilities:</strong> {scan['vulnerability_count']}</p>
                <div>
                {''.join(f'<div class="vuln {vuln["severity"]}"><strong>{vuln["type"]}</strong><br>{vuln["description"]}<br><em>{vuln["detail"]}</em></div>' for vuln in scan['vulnerabilities']) if scan['vulnerabilities'] else '<p>No vulnerabilities found.</p>'}
                </div><hr>
                """

            html_content += "</body></html>"

            with open(html_filename, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Generate PDF
            HTML(html_filename).write_pdf(pdf_filename)

            # Show downloads
            st.download_button(
                label="📥 Download JSON Report",
                data=json.dumps(summary_data, indent=2),
                file_name=report_filename,
                mime="application/json"
            )

            with open(html_filename, "r", encoding="utf-8") as f:
                st.download_button("📄 Download HTML Report", data=f.read(), file_name=html_filename, mime="text/html")

            with open(pdf_filename, "rb") as f:
                st.download_button("🧾 Download PDF Report", data=f.read(), file_name=pdf_filename, mime="application/pdf")

            st.success(f"✅ Summary report generated with {summary_data['total_vulnerabilities']} vulnerabilities across {len(summary_data['scans'])} scans.")
        else:
            st.warning("⚠️ No scan data available to generate report.")
    else:
        st.warning("⚠️ No results directory found.")
