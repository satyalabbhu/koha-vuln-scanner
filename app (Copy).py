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
import requests
from urllib.parse import urlparse
import time
import re
import urllib3
from weasyprint import HTML

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
    page_title="🛡️ Koha Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.main-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 2rem;
    border-radius: 15px;
    text-align: center;
    margin-bottom: 2rem;
}
.tool-card {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #667eea;
    margin: 0.5rem 0;
    margin-bottom: 12px;
    line-height: 1.4;
}
.vulnerability {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    padding: 0.75rem;
    border-radius: 5px;
    margin: 0.5rem 0;
}
.critical { background: #f8d7da; border-color: #f1aeb5; }
.high { background: #fff3cd; border-color: #ffeaa7; }
.medium { background: #d1ecf1; border-color: #b6d4da; }
.low { background: #d4edda; border-color: #c3e6cb; }
.info { background: #e2e3e5; border-color: #d6d8db; }
.category-network { border-left-color: #28a745; }
.category-web { border-left-color: #007bff; }
.category-vulnerability { border-left-color: #dc3545; }
.category-reconnaissance { border-left-color: #6f42c1; }
.category-cms { border-left-color: #fd7e14; }
.target-info {
    background: #e7f3ff;
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #007bff;
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ Koha Security Scanner</h1>
    <p>Comprehensive Security Assessment Tool</p>
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
                cmd = tool_config['cmd'].format(target=target, web_url=web_url)
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

# Main interface
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("🎯 Target Configuration")
    
    target_ip = st.text_input("Target IP Address or Domain", placeholder="192.168.1.100 or example.com", key="target_ip")
    
    # Target analysis
    if target_ip:
        with st.spinner("Analyzing target..."):
            target_info = validate_target(target_ip)
        
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
        else:
            st.warning("⚠️ No open ports detected on target. Target may be down or filtered.")
        
        # Tool selection
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
        
        # Display tools by category
        selected_tools = []
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
                elif tool_available:
                    status_icon = "✅"
                    status_text = ""
                elif has_fallback:
                    status_icon = "⚠️"
                    status_text = " (fallback available)"
                else:
                    status_icon = "❌"
                    status_text = " (not available)"
                
                tool_selected = st.checkbox(
                    f"{status_icon} {config['name']}{status_text}",
                    key=f"tool_{tool_name}",
                    help=config['description'],
                    disabled=not is_suitable
                )
                
                if tool_selected and is_suitable:
                    selected_tools.append(tool_name)
        
        # Scan options
        st.subheader("⚙️ Scan Options")
        scan_mode = st.selectbox(
            "Scan Mode",
            ["Quick Scan (Recommended)", "Full Scan (All Suitable Tools)", "Custom Selection"]
        )
        
        if scan_mode == "Full Scan (All Suitable Tools)":
            selected_tools = suitable_tools
        elif scan_mode == "Quick Scan (Recommended)":
            quick_tools = ["nmap"]
            if target_info['has_web']:
                quick_tools.extend(["whatweb", "gobuster"])
            selected_tools = [tool for tool in quick_tools if tool in suitable_tools]
        
        # Scan execution
        if st.button("🚀 Start Security Scan", type="primary", use_container_width=True):
            if not target_info['open_ports']:
                st.error("❌ Cannot scan target - no open ports detected. Please verify the target is accessible.")
            elif not selected_tools:
                st.warning("⚠️ Please select at least one suitable tool to run.")
            else:
                scan_results = {}
                all_vulnerabilities = []
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                st.info(f"🔍 Starting scan with {len(selected_tools)} tools...")
                
                for i, tool_name in enumerate(selected_tools):
                    config = TOOLS[tool_name]
                    status_text.text(f"Running {config['name']}... ({i+1}/{len(selected_tools)})")
                    
                    output, vulnerabilities = run_tool_scan(tool_name, target_ip, target_info)
                    scan_results[tool_name] = {
                        'output': output,
                        'vulnerabilities': vulnerabilities
                    }
                    all_vulnerabilities.extend(vulnerabilities)
                    
                    # Save results
                    if output:
                        save_results(tool_name, target_ip, output, vulnerabilities)
                    
                    progress_bar.progress((i + 1) / len(selected_tools))
                
                status_text.text("✅ Scan completed!")
                
                # Display summary
                total_issues = len(all_vulnerabilities)
                if total_issues > 0:
                    st.success(f"🎯 Scan completed! Found {total_issues} potential security issues across {len(selected_tools)} tools.")
                else:
                    st.info(f"✅ Scan completed! No major security issues detected across {len(selected_tools)} tools.")
                
                # Vulnerability summary
                if all_vulnerabilities:
                    severity_counts = {}
                    for vuln in all_vulnerabilities:
                        severity = vuln.get('severity', 'info')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Display severity summary
                    st.subheader("📊 Risk Summary")
                    cols = st.columns(len(severity_counts) if severity_counts else 1)
                    severity_icons = {
                        'critical': '🚨',
                        'high': '⚠️',
                        'medium': '📢',
                        'low': 'ℹ️',
                        'info': '📋'
                    }
                    
                    severity_colors = {
                        'critical': '#dc3545',
                        'high': '#fd7e14',
                        'medium': '#ffc107',
                        'low': '#28a745',
                        'info': '#6c757d'
                    }
                    
                    for i, (severity, count) in enumerate(severity_counts.items()):
                        if i < len(cols):
                            with cols[i]:
                                st.metric(
                                    label=f"{severity_icons.get(severity, '📋')} {severity.title()}",
                                    value=count,
                                    delta=None
                                )
                
                # Detailed results
                st.subheader("🔍 Detailed Scan Results")
                
                for tool_name in selected_tools:
                    if tool_name in scan_results:
                        config = TOOLS[tool_name]
                        result_data = scan_results[tool_name]
                        
                        with st.expander(f"{config['name']} Results", expanded=True):
                            st.markdown(f"""
                            <div class="tool-card category-{config['category'].lower()}">
                                <h4>{config['name']}</h4>
                                <p><strong>Category:</strong> {config['category']}</p>
                                <p><strong>Description:</strong> {config['description']}</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Display vulnerabilities first
                            if result_data['vulnerabilities']:
                                st.markdown("**🚨 Security Issues Found:**")
                                for vuln in result_data['vulnerabilities']:
                                    severity = vuln.get('severity', 'info')
                                    severity_class = severity
                                    severity_icon = severity_icons.get(severity, '📋')
                                    
                                    st.markdown(f"""
                                    <div class="vulnerability {severity_class}">
                                        <strong>{severity_icon} {vuln.get('type', 'Finding')} ({severity.upper()})</strong><br>
                                        {vuln.get('description', 'No description')}<br>
                                        <small><em>{vuln.get('detail', '')}</em></small>
                                    </div>
                                    """, unsafe_allow_html=True)
                            
                            # Display tool output
                            st.markdown("**📋 Tool Output:**")
                            st.code(result_data['output'], language='text')

with col2:
    st.subheader("🛠️ Tools Status")
    
    # Display tool availability
    for tool_name, config in TOOLS.items():
        tool_available = check_tool_available(tool_name)
        has_fallback = config.get('fallback', False)
        
        if tool_available:
            status = "✅ Available"
            color = "green"
        elif has_fallback:
            status = "⚠️ Fallback"
            color = "orange"
        else:
            status = "❌ Missing"
            color = "red"
        
        st.markdown(f"""
        <div class="tool-card" style="margin-bottom: 10px;">
            <strong style="color: {color};">{config['name']}</strong><br>
            <small style="display: block; margin: 2px 0;">{status}</small><br>
            <small style="color: #666;">{config['description']}</small>
        </div>
        """, unsafe_allow_html=True)
    
    st.subheader("📁 Recent Scans")
    
    # Display recent scan files
    if os.path.exists(RESULTS_DIR):
        scan_files = sorted([f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')], 
                           key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), 
                           reverse=True)[:5]
        
        if scan_files:
            for scan_file in scan_files:
                file_path = os.path.join(RESULTS_DIR, scan_file)
                file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                
                # Parse filename for info
                parts = scan_file.replace('.json', '').split('_')
                if len(parts) >= 2:
                    tool_name = parts[0]
                    target = parts[1].replace('_', '.')
                    
                    st.markdown(f"""
                    <div style="background: #f8f9fa; padding: 0.5rem; margin: 0.25rem 0; border-radius: 5px; font-size: 0.8rem;">
                        <strong>{tool_name}</strong><br>
                        Target: {target}<br>
                        <small>{file_time.strftime("%Y-%m-%d %H:%M")}</small>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Download button
                    with open(file_path, 'r') as f:
                        st.download_button(
                            label="📥",
                            data=f.read(),
                            file_name=scan_file,
                            mime="application/json",
                            key=f"download_{scan_file}"
                        )
        else:
            st.info("No recent scans found")
    
    st.subheader("📊 Statistics")
    
    # Calculate some basic statistics
    if os.path.exists(RESULTS_DIR):
        total_scans = len([f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')])
        st.metric("Total Scans", total_scans)
        
        # Count vulnerabilities from recent scans
        total_vulns = 0
        if scan_files:
            for scan_file in scan_files[:10]:  # Check last 10 scans
                try:
                    with open(os.path.join(RESULTS_DIR, scan_file), 'r') as f:
                        data = json.load(f)
                        total_vulns += data.get('vulnerability_count', 0)
                except:
                    continue
        
        st.metric("Recent Vulnerabilities", total_vulns)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 1rem;">
    <small>🛡️ <strong>Koha Security Scanner</strong> - Comprehensive Security Assessment Tool<br>
    Always follow responsible disclosure practices and only scan systems you own or have permission to test.</small>
</div>
""", unsafe_allow_html=True)

# Help section
with st.expander("ℹ️ Help & Information"):
    st.markdown("""
    ## 🔧 Tool Descriptions
    
    **Network Tools:**
    - **Nmap**: Industry-standard port scanner and service detection
    - **Masscan**: High-speed port scanner for large networks
    
    **Web Tools:**
    - **Nikto**: Web server vulnerability scanner
    - **SQLMap**: Automated SQL injection detection and exploitation
    - **Gobuster**: Directory and file brute-forcing tool
    - **Nuclei**: Fast vulnerability scanner with extensive templates
    - **WhatWeb**: Web application fingerprinting
    
    **CMS Tools:**
    - **WPScan**: WordPress-specific security scanner
    
    ## 🚨 Security Levels
    
    - **🚨 Critical**: Immediate attention required - high risk of exploitation
    - **⚠️ High**: Should be addressed promptly - moderate risk
    - **📢 Medium**: Should be reviewed - low to moderate risk  
    - **ℹ️ Low**: Informational - minimal risk
    - **📋 Info**: General information - no direct security risk
    
    ## 📋 Usage Guidelines
    
    1. **Target Analysis**: The tool first analyzes your target to determine available services
    2. **Tool Selection**: Only suitable tools for your target will be enabled
    3. **Scan Modes**: 
       - Quick Scan: Essential tools for basic assessment
       - Full Scan: All suitable tools for comprehensive testing
       - Custom: Select specific tools manually
    4. **Results**: Review vulnerabilities by severity and save reports for documentation
    
    ## ⚖️ Legal Notice
    
    **Only use this tool on systems you own or have explicit permission to test.**
    Unauthorized scanning may violate local laws and terms of service.
    Always follow responsible disclosure practices.
    """)

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
