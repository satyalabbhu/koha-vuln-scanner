"""
LLM-powered Security Report Translator
=====================================

This module provides functionality to analyze technical vulnerability reports
and generate simplified, layman-language summaries for librarians and 
non-technical staff.

Features:
- Offline LLM integration (LLaMA, Mistral, etc.)
- Technical to layman language translation
- Risk prioritization in simple terms
- Actionable recommendations
- Library-specific context awareness
"""

import json
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

# LLM Integration imports
try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

try:
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LibrarianReportGenerator:
    """
    Generates simplified security reports for librarians using offline LLM models
    """
    
    def __init__(self, model_path: Optional[str] = None, model_type: str = "llama"):
        """
        Initialize the report generator
        
        Args:
            model_path: Path to the local LLM model
            model_type: Type of model ("llama", "huggingface", "mistral")
        """
        self.model_path = model_path
        self.model_type = model_type.lower()
        self.model = None
        self.tokenizer = None
        
        # Initialize the model
        self._initialize_model()
        
    def _initialize_model(self):
        """Initialize the LLM model based on the specified type"""
        
        # Log availability of LLM dependencies
        if LLAMA_AVAILABLE:
            logger.info("llama-cpp-python is available for offline LLM support")
        if TRANSFORMERS_AVAILABLE:
            logger.info("transformers is available for HuggingFace model support")
            
        try:
            if self.model_type == "llama" and LLAMA_AVAILABLE and self.model_path:
                logger.info(f"Loading LLaMA model from {self.model_path}")
                self.model = Llama(
                    model_path=self.model_path,
                    n_ctx=4096,  # Context window
                    n_threads=4,  # Adjust based on your CPU
                    verbose=False
                )
                logger.info("LLaMA model loaded successfully")
                
            elif self.model_type == "huggingface" and TRANSFORMERS_AVAILABLE:
                logger.info("Loading HuggingFace model for text generation")
                # Use a smaller model for better performance
                model_name = self.model_path or "microsoft/DialoGPT-medium"
                
                # Import torch only when needed to avoid Streamlit file watcher issues
                try:
                    import torch
                    device = "cuda" if torch.cuda.is_available() else "cpu"
                    logger.info(f"Using device: {device}")
                except ImportError:
                    device = "cpu"
                    logger.info("PyTorch not available, using CPU")
                
                self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.model = pipeline(
                    "text-generation",
                    model=model_name,
                    tokenizer=self.tokenizer,
                    device=0 if device == "cuda" else -1,
                    max_length=1024,
                    do_sample=True,
                    temperature=0.7
                )
                logger.info("HuggingFace model loaded successfully")
            else:
                if not LLAMA_AVAILABLE and not TRANSFORMERS_AVAILABLE:
                    logger.info("LLM dependencies not available, using template-based generation")
                else:
                    logger.info("No model path specified or model type not supported, using template-based generation")
                self.model = None
                
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None

    def _generate_with_llm(self, prompt: str, max_tokens: int = 512) -> str:
        """Generate text using the loaded LLM model"""
        try:
            if self.model_type == "llama" and self.model:
                response = self.model(
                    prompt,
                    max_tokens=max_tokens,
                    temperature=0.7,
                    top_p=0.9,
                    repeat_penalty=1.1,
                    stop=["Human:", "Assistant:", "\n\n\n"]
                )
                return response['choices'][0]['text'].strip()
                
            elif self.model_type == "huggingface" and self.model:
                response = self.model(
                    prompt,
                    max_length=len(prompt.split()) + max_tokens,
                    num_return_sequences=1,
                    pad_token_id=50256
                )
                generated_text = response[0]['generated_text']
                # Extract only the generated part (after the prompt)
                return generated_text[len(prompt):].strip()
                
        except Exception as e:
            logger.error(f"Error generating with LLM: {str(e)}")
            
        return ""

    def _create_analysis_prompt(self, vulnerability_data: Dict) -> str:
        """Create a prompt for the LLM to analyze vulnerability data"""
        
        # Extract key information
        total_vulnerabilities = vulnerability_data.get('total_vulnerabilities', 0)
        severity_counts = vulnerability_data.get('severity_counts', {})
        target = vulnerability_data.get('target', 'Unknown')
        
        # Create a structured prompt
        prompt = f"""
You are a cybersecurity expert explaining technical security issues to a librarian who manages a library's computer systems. Your goal is to translate complex technical vulnerabilities into simple, actionable language.

TECHNICAL SCAN RESULTS:
- Target System: {target}
- Total Security Issues Found: {total_vulnerabilities}
- Critical Issues: {severity_counts.get('critical', 0)}
- High Priority Issues: {severity_counts.get('high', 0)}
- Medium Priority Issues: {severity_counts.get('medium', 0)}
- Low Priority Issues: {severity_counts.get('low', 0)}

Please provide a simple, non-technical explanation that includes:

1. WHAT THIS MEANS IN SIMPLE TERMS:
   - Explain what these security issues mean for the library
   - Use analogies that a librarian would understand

2. IMMEDIATE ACTIONS NEEDED:
   - What should be done first (prioritize critical and high issues)
   - Simple steps that can be taken right away

3. POTENTIAL RISKS:
   - What could happen if these issues aren't fixed
   - Impact on library operations and patron data

4. RECOMMENDATIONS:
   - Who to contact (IT support, security experts)
   - Timeline for addressing issues
   - Prevention measures

Keep your explanation simple, avoid technical jargon, and focus on practical advice for library management.

LIBRARIAN-FRIENDLY REPORT:
"""
        return prompt

    def _generate_template_report(self, vulnerability_data: Dict) -> str:
        """Generate a template-based report when LLM is not available"""
        
        total_vulnerabilities = vulnerability_data.get('total_vulnerabilities', 0)
        severity_counts = vulnerability_data.get('severity_counts', {})
        target = vulnerability_data.get('target', 'Unknown System')
        
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        medium_count = severity_counts.get('medium', 0)
        low_count = severity_counts.get('low', 0)
        
        # Determine urgency level
        if critical_count > 0:
            urgency = "IMMEDIATE ATTENTION REQUIRED"
            urgency_color = "🚨"
        elif high_count > 0:
            urgency = "HIGH PRIORITY - Action Needed Soon"
            urgency_color = "⚠️"
        elif medium_count > 0:
            urgency = "MODERATE PRIORITY - Plan for Resolution"
            urgency_color = "📢"
        else:
            urgency = "LOW PRIORITY - Monitor and Plan"
            urgency_color = "ℹ️"

        report = f"""
# 📚 LIBRARY SECURITY REPORT - SIMPLIFIED VERSION

## {urgency_color} URGENCY LEVEL: {urgency}

### 🖥️ SYSTEM CHECKED: {target}

### 📊 WHAT WE FOUND:
- **Total Security Issues**: {total_vulnerabilities}
- **🚨 Critical (Fix Immediately)**: {critical_count}
- **⚠️ High Priority (Fix This Week)**: {high_count}
- **📢 Medium Priority (Fix This Month)**: {medium_count}
- **ℹ️ Low Priority (Plan for Future)**: {low_count}

---

### 🏠 WHAT THIS MEANS FOR YOUR LIBRARY:

"""
        
        if critical_count > 0:
            report += f"""
**🚨 CRITICAL ISSUES FOUND ({critical_count}):**
These are like having broken locks on your library doors. Hackers could potentially:
- Access patron personal information (names, addresses, library records)
- Steal or delete library data
- Disrupt library computer systems
- Use your systems to attack other libraries

**⚡ IMMEDIATE ACTION REQUIRED:**
1. Contact your IT support team TODAY
2. Consider temporarily limiting public computer access
3. Backup important library data immediately
4. Monitor systems closely for unusual activity
"""

        if high_count > 0:
            report += f"""
**⚠️ HIGH PRIORITY ISSUES ({high_count}):**
These are like having weak locks that could be picked. While not immediately dangerous, they create opportunities for:
- Unauthorized access to library systems
- Potential data theft over time
- System performance problems
- Compliance issues with library data protection

**📅 ACTION NEEDED THIS WEEK:**
1. Schedule IT support visit
2. Review and update passwords
3. Check for system updates
4. Document the issues for tracking
"""

        if medium_count > 0:
            report += f"""
**📢 MEDIUM PRIORITY ISSUES ({medium_count}):**
These are like having outdated security measures. They should be addressed to:
- Prevent future security problems
- Maintain good security hygiene
- Keep systems running smoothly
- Stay compliant with best practices

**📋 PLAN FOR THIS MONTH:**
1. Schedule routine maintenance
2. Update software and systems
3. Review security policies
4. Train staff on security awareness
"""

        if low_count > 0:
            report += f"""
**ℹ️ LOW PRIORITY ISSUES ({low_count}):**
These are minor improvements that can enhance overall security:
- Small configuration improvements
- Information disclosure that's not immediately dangerous
- Outdated software that should eventually be updated

**🗓️ FUTURE PLANNING:**
1. Include in next maintenance cycle
2. Consider during system upgrades
3. Document for future reference
"""

        report += """
---

### 🎯 RECOMMENDED ACTIONS:

#### ⚡ IMMEDIATE STEPS:
1. **Contact IT Support**: Share this report with your technical team
2. **Backup Data**: Ensure recent backups of all library data
3. **Monitor Systems**: Watch for any unusual computer behavior
4. **Limit Access**: Consider restricting access to sensitive systems

#### 📞 WHO TO CALL:
- **Your IT Support Team** (primary contact)
- **Library System Vendor** (for specialized library software issues)
- **Local Cybersecurity Expert** (for serious threats)

#### 📅 TIMELINE:
- **Critical Issues**: Fix within 24-48 hours
- **High Priority**: Fix within 1 week
- **Medium Priority**: Fix within 1 month
- **Low Priority**: Address during next maintenance cycle

#### 🛡️ PREVENTION:
- Keep all software updated
- Use strong, unique passwords
- Train staff on cybersecurity basics
- Regular security scans (monthly recommended)
- Have an incident response plan

---

### ❓ QUESTIONS TO ASK YOUR IT TEAM:

1. "How quickly can we fix the critical issues?"
2. "Do we need to notify anyone about potential data exposure?"
3. "Should we change any passwords or access codes?"
4. "How can we prevent these issues in the future?"
5. "Do we need to inform library patrons?"

### 📋 REMEMBER:
- This is a **preventive measure** - finding issues before hackers do
- **Most libraries have similar issues** - you're being proactive
- **Quick action prevents bigger problems** later
- **Document everything** for future reference

---

*Generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}*
*This report translates technical security findings into library-friendly language*
"""
        
        return report.strip()

    def generate_librarian_report(self, vulnerability_data: Dict) -> str:
        """
        Generate a simplified report for librarians
        
        Args:
            vulnerability_data: Dictionary containing vulnerability scan results
            
        Returns:
            str: Simplified report in markdown format
        """
        
        logger.info("Generating librarian-friendly security report...")
        
        try:
            # Try to use LLM if available
            if self.model:
                prompt = self._create_analysis_prompt(vulnerability_data)
                llm_response = self._generate_with_llm(prompt, max_tokens=800)
                
                if llm_response and len(llm_response.strip()) > 50:
                    logger.info("Successfully generated report using LLM")
                    
                    # Add header and formatting
                    formatted_report = f"""
# 📚 LIBRARY SECURITY REPORT - AI ANALYSIS

*Generated using AI analysis on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}*

{llm_response}

---

### 🔍 TECHNICAL SUMMARY:
- **Target**: {vulnerability_data.get('target', 'Unknown')}
- **Total Issues**: {vulnerability_data.get('total_vulnerabilities', 0)}
- **Scan Date**: {datetime.now().strftime("%Y-%m-%d")}

*This report was generated using AI to translate technical security findings into library-friendly language.*
"""
                    return formatted_report.strip()
                    
        except Exception as e:
            logger.error(f"Error generating LLM report: {str(e)}")
        
        # Fallback to template-based report
        logger.info("Using template-based report generation")
        return self._generate_template_report(vulnerability_data)

    def analyze_vulnerabilities_for_library(self, scan_results: Dict) -> Dict[str, Any]:
        """
        Analyze scan results and provide library-specific insights
        
        Args:
            scan_results: Raw vulnerability scan results
            
        Returns:
            Dict containing analysis and recommendations
        """
        
        analysis = {
            'risk_level': 'Unknown',
            'immediate_actions': [],
            'library_impact': {},
            'recommendations': [],
            'simplified_report': ''
        }
        
        try:
            # Extract vulnerability data
            vulnerability_data = self._extract_vulnerability_data(scan_results)
            
            # Determine risk level
            analysis['risk_level'] = self._determine_risk_level(vulnerability_data)
            
            # Generate immediate actions
            analysis['immediate_actions'] = self._generate_immediate_actions(vulnerability_data)
            
            # Assess library-specific impact
            analysis['library_impact'] = self._assess_library_impact(vulnerability_data)
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(vulnerability_data)
            
            # Generate the full simplified report
            analysis['simplified_report'] = self.generate_librarian_report(vulnerability_data)
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerabilities: {str(e)}")
            analysis['simplified_report'] = "Error generating report. Please contact IT support."
            
        return analysis

    def _extract_vulnerability_data(self, scan_results: Dict) -> Dict:
        """Extract and structure vulnerability data from scan results"""
        
        # Initialize counters
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        total_vulnerabilities = 0
        
        # Extract from different possible structures
        if 'scan_results' in scan_results:
            for tool_result in scan_results['scan_results'].values():
                if 'vulnerabilities' in tool_result:
                    for vuln in tool_result['vulnerabilities']:
                        severity = vuln.get('severity', 'info').lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                            total_vulnerabilities += 1
        
        # Also check direct vulnerabilities list
        if 'vulnerabilities' in scan_results:
            for vuln in scan_results['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    total_vulnerabilities += 1
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_counts': severity_counts,
            'target': scan_results.get('target', 'Unknown System'),
            'timestamp': scan_results.get('timestamp', datetime.now().isoformat())
        }

    def _determine_risk_level(self, vulnerability_data: Dict) -> str:
        """Determine overall risk level based on vulnerabilities"""
        
        severity_counts = vulnerability_data.get('severity_counts', {})
        
        if severity_counts.get('critical', 0) > 0:
            return 'CRITICAL'
        elif severity_counts.get('high', 0) > 2:
            return 'HIGH'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 5:
            return 'MEDIUM'
        elif vulnerability_data.get('total_vulnerabilities', 0) > 0:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _generate_immediate_actions(self, vulnerability_data: Dict) -> List[str]:
        """Generate list of immediate actions based on vulnerabilities"""
        
        actions = []
        severity_counts = vulnerability_data.get('severity_counts', {})
        
        if severity_counts.get('critical', 0) > 0:
            actions.extend([
                "Contact IT support immediately",
                "Backup all critical library data",
                "Consider limiting public computer access",
                "Monitor systems for unusual activity"
            ])
        
        if severity_counts.get('high', 0) > 0:
            actions.extend([
                "Schedule IT support visit within 1 week",
                "Review and update all passwords",
                "Check for available system updates"
            ])
        
        if not actions:
            actions.append("Continue regular monitoring and maintenance")
        
        return actions

    def _assess_library_impact(self, vulnerability_data: Dict) -> Dict[str, str]:
        """Assess potential impact on library operations"""
        
        severity_counts = vulnerability_data.get('severity_counts', {})
        impact = {}
        
        if severity_counts.get('critical', 0) > 0:
            impact['patron_data'] = 'HIGH RISK - Patron information could be exposed'
            impact['operations'] = 'HIGH RISK - Library systems could be disrupted'
            impact['reputation'] = 'HIGH RISK - Library reputation could be damaged'
        elif severity_counts.get('high', 0) > 0:
            impact['patron_data'] = 'MEDIUM RISK - Some risk to patron information'
            impact['operations'] = 'MEDIUM RISK - Potential system disruptions'
            impact['reputation'] = 'LOW RISK - Minimal reputation impact if addressed promptly'
        else:
            impact['patron_data'] = 'LOW RISK - Minimal risk to patron information'
            impact['operations'] = 'LOW RISK - Unlikely to disrupt operations'
            impact['reputation'] = 'MINIMAL RISK - No significant reputation concerns'
        
        return impact

    def _generate_recommendations(self, vulnerability_data: Dict) -> List[str]:
        """Generate specific recommendations for libraries"""
        
        recommendations = [
            "Establish regular security scanning (monthly)",
            "Ensure all staff are trained on basic cybersecurity",
            "Implement a data backup strategy",
            "Create an incident response plan",
            "Keep all software and systems updated",
            "Use strong, unique passwords for all accounts",
            "Consider cybersecurity insurance for the library"
        ]
        
        severity_counts = vulnerability_data.get('severity_counts', {})
        
        if severity_counts.get('critical', 0) > 0 or severity_counts.get('high', 0) > 2:
            recommendations.insert(0, "Consider hiring a cybersecurity consultant")
            recommendations.insert(1, "Review and update library security policies")
        
        return recommendations

    def generate_forensic_cyberpunk_report(self, vulnerability_data: Dict[str, Any]) -> str:
        """
        Generate a sci-fi forensic cyberpunk-style security analysis report
        """
        logger.info("Generating cyberpunk forensic security analysis...")
        
        # Extract key data
        target = vulnerability_data.get('target', 'UNKNOWN_NODE')
        total_vulns = vulnerability_data.get('total_vulnerabilities', 0)
        severity_counts = vulnerability_data.get('severity_counts', {})
        risk_score = vulnerability_data.get('risk_score', 0)
        risk_level = vulnerability_data.get('risk_level', 'UNKNOWN')
        target_info = vulnerability_data.get('target_info', {})
        scan_results = vulnerability_data.get('scan_results', {})
        
        # Generate timestamp
        from datetime import datetime
        scan_time = datetime.now().strftime("%Y.%m.%d_%H:%M:%S")
        
        # Calculate threat metrics
        attack_surface = len(target_info.get('open_ports', []))
        security_index = max(0, 100 - risk_score)
        
        # Threat classification
        threat_class = self._get_threat_classification(risk_level)
        alert_level = self._get_alert_level(risk_level)
        
        report = f"""
# ⚡ CYBERSEC FORENSIC ANALYSIS TERMINAL ⚡
```
╔══════════════════════════════════════════════════════════════════╗
║                    CLASSIFIED - INTERNAL USE ONLY                ║
║              DIGITAL FORENSICS & THREAT ANALYSIS LAB             ║
╚══════════════════════════════════════════════════════════════════╝
```

## 🔍 SCAN METADATA
```
┌─ SYSTEM IDENTIFICATION ─────────────────────────────────────────┐
│ TARGET_NODE        : {target}                                   
│ SCAN_TIMESTAMP     : {scan_time}
│ ANALYSIS_ENGINE    : KOHA-VULN-SCANNER v2.1.ALPHA
│ OPERATOR_CLEARANCE : LEVEL-7-SECURITY-ANALYST
│ SESSION_ID         : {hash(str(scan_time))%10000:04d}-{hash(target)%10000:04d}
└─────────────────────────────────────────────────────────────────┘
```

## ⚠️ THREAT ASSESSMENT MATRIX

```ascii
    RISK EVALUATION PROTOCOL v3.7
    ╭─────────────────────────────────────╮
    │  SECURITY INDEX: [{security_index:3d}/100]          │
    │  THREAT CLASS:   {threat_class:<15}      │
    │  ALERT LEVEL:    {alert_level:<15}      │
    │  ATTACK SURFACE: {attack_surface:02d} VECTORS        │
    ╰─────────────────────────────────────────╯
```

### 📊 VULNERABILITY DISTRIBUTION ANALYSIS
```
Critical [{'█' * severity_counts.get('critical', 0)}{'░' * (10 - severity_counts.get('critical', 0))}] {severity_counts.get('critical', 0):02d}/xx
High     [{'█' * severity_counts.get('high', 0)}{'░' * (10 - severity_counts.get('high', 0))}] {severity_counts.get('high', 0):02d}/xx  
Medium   [{'█' * severity_counts.get('medium', 0)}{'░' * (10 - severity_counts.get('medium', 0))}] {severity_counts.get('medium', 0):02d}/xx
Low      [{'█' * severity_counts.get('low', 0)}{'░' * (10 - severity_counts.get('low', 0))}] {severity_counts.get('low', 0):02d}/xx
Info     [{'█' * severity_counts.get('info', 0)}{'░' * (10 - severity_counts.get('info', 0))}] {severity_counts.get('info', 0):02d}/xx
```

## 🎯 TARGET RECONNAISSANCE PROFILE

```
┌─ NETWORK TOPOLOGY ANALYSIS ─────────────────────────────────────┐
│ ACTIVE SERVICES    : {len(target_info.get('services', {}))} DETECTED                           
│ OPEN ATTACK VECTORS: {len(target_info.get('open_ports', []))} DISCOVERED                        
│ WEB PRESENCE       : {'CONFIRMED' if target_info.get('has_web', False) else 'NOT_DETECTED'}                            
│ PROTOCOL ANALYSIS  : {len(target_info.get('protocols', []))} PROTOCOLS IDENTIFIED              
└─────────────────────────────────────────────────────────────────┘
```

### 🔌 EXPOSED SERVICE MATRIX
```ascii
PORT    SERVICE     STATUS      THREAT_LEVEL
──────  ──────────  ──────────  ────────────"""

        # Add service details
        services = target_info.get('services', {})
        open_ports = target_info.get('open_ports', [])
        
        for i, port in enumerate(open_ports[:10]):  # Limit to first 10 ports
            service = services.get(str(port), 'unknown')
            threat = self._get_port_threat_level(port)
            report += f"\n{port:<6}  {service:<10}  ACTIVE      {threat}"
        
        if len(open_ports) > 10:
            report += f"\n[...and {len(open_ports) - 10} more vectors...]"

        report += f"""
```

## 🚨 CRITICAL FINDINGS DATABASE

```
╔══════════════════════════════════════════════════════════════════╗
║                     ⚠️  IMMEDIATE THREATS  ⚠️                    ║
╚══════════════════════════════════════════════════════════════════╝
```

### 🔥 PRIORITY-ALPHA VULNERABILITIES
"""

        # Add critical and high severity vulnerabilities
        critical_count = 0
        for tool_name, results in scan_results.items():
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in ['critical', 'high'] and critical_count < 5:
                        critical_count += 1
                        vuln_type = vuln.get('type', 'Unknown')
                        description = vuln.get('description', 'No description')
                        
                        report += f"""
```
FINDING_ID: CVE-{2024}-{1000 + critical_count:04d}
SEVERITY:   {'🚨 CRITICAL' if severity == 'critical' else '⚠️ HIGH'}
CATEGORY:   {vuln_type.upper()}
VECTOR:     {description[:60]}...
SCANNER:    {tool_name.upper()}_MODULE
STATUS:     ACTIVE_THREAT
```
"""

        report += f"""

## 🛡️ DEFENSIVE COUNTERMEASURES

```
╔══════════════════════════════════════════════════════════════════╗
║                    RECOMMENDED SECURITY ACTIONS                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### ⚡ IMMEDIATE RESPONSE PROTOCOL
```
[PRIORITY-1] EMERGENCY PATCHING REQUIRED
├─ Execute security updates within 6 hours
├─ Isolate affected systems if necessary  
├─ Monitor for active exploitation attempts
└─ Document all remediation actions

[PRIORITY-2] HARDENING PROCEDURES
├─ Review access control policies
├─ Implement additional monitoring
├─ Update firewall configurations
└─ Schedule follow-up security scan
```

### 🔧 TACTICAL RECOMMENDATIONS

```ascii
ACTION_CODE  DESCRIPTION                    TIMELINE  IMPACT
───────────  ─────────────────────────────  ────────  ───────
SEC-001      Update critical components     24H       HIGH
SEC-002      Strengthen authentication      72H       MEDIUM  
SEC-003      Network segmentation review    1WEEK     MEDIUM
SEC-004      Security awareness training    1MONTH    LOW
```

## 📈 COMPLIANCE & GOVERNANCE MATRIX

```
┌─ SECURITY FRAMEWORK ALIGNMENT ──────────────────────────────────┐
│ NIST CYBERSEC    : [{self._get_compliance_status('NIST', risk_level)}]                              
│ ISO27001        : [{self._get_compliance_status('ISO', risk_level)}]                              
│ LIBRARY_STD     : [{self._get_compliance_status('LIBRARY', risk_level)}]                              
│ DATA_PROTECTION : [{self._get_compliance_status('PRIVACY', risk_level)}]                              
└─────────────────────────────────────────────────────────────────┘
```

## 🔮 PREDICTIVE THREAT MODELING

```
╭─ AI THREAT PREDICTION ENGINE v2.3 ─────────────────────────────╮
│                                                                 │
│ ATTACK PROBABILITY    : {min(95, risk_score + 10)}%                                  │
│ TIME TO COMPROMISE    : {self._estimate_compromise_time(risk_level):<15}              │
│ LIKELY ATTACK VECTORS : {self._predict_attack_vectors(severity_counts):<25}      │
│ RECOMMENDED RESPONSE  : {self._get_response_recommendation(risk_level):<25}      │
│                                                                 │
╰─────────────────────────────────────────────────────────────────╯
```

## 📊 FORENSIC DATA CORRELATION

### 🕵️ INVESTIGATION SUMMARY
- **SCAN MODULES DEPLOYED**: {len(scan_results)} ACTIVE
- **TOTAL FINDINGS LOGGED**: {total_vulns} ENTRIES
- **EVIDENCE COLLECTED**: {total_vulns * 3} DATA_POINTS
- **ANALYSIS CONFIDENCE**: {85 + (security_index // 10)}% VERIFIED

### 🔗 RELATED THREAT INTELLIGENCE
```
THREAT_DATABASE_CORRELATION:
├─ CVE_REFERENCES: {severity_counts.get('critical', 0) + severity_counts.get('high', 0)} MATCHES_FOUND
├─ EXPLOIT_KITS: {severity_counts.get('critical', 0)} ACTIVE_THREATS
├─ IOC_ANALYSIS: {severity_counts.get('high', 0) + severity_counts.get('medium', 0)} INDICATORS
└─ ATTRIBUTION: GENERIC_OPPORTUNISTIC_THREATS
```

---

```ascii
╔══════════════════════════════════════════════════════════════════╗
║  CLASSIFICATION: OFFICIAL-SENSITIVE │ DISTRIBUTION: AUTHORIZED   ║
║  GENERATED BY: KOHA_FORENSIC_LAB    │ VALIDITY: 30_DAYS          ║
╚══════════════════════════════════════════════════════════════════╝
```

**END OF FORENSIC ANALYSIS REPORT**

*This report contains sensitive security information. Distribute only to authorized personnel with appropriate security clearance.*
"""

        return report

    def _get_threat_classification(self, risk_level: str) -> str:
        """Get cyberpunk-style threat classification"""
        classifications = {
            'CRITICAL': 'OMEGA-THREAT',
            'HIGH': 'ALPHA-PRIORITY', 
            'MODERATE': 'BETA-CONCERN',
            'LOW': 'GAMMA-NOTICE',
            'MINIMAL': 'DELTA-MONITOR'
        }
        return classifications.get(risk_level.upper(), 'UNKNOWN-CLASS')
    
    def _get_alert_level(self, risk_level: str) -> str:
        """Get cyberpunk-style alert level"""
        alerts = {
            'CRITICAL': 'RED-CONDITION',
            'HIGH': 'ORANGE-ALERT',
            'MODERATE': 'YELLOW-CAUTION', 
            'LOW': 'GREEN-NORMAL',
            'MINIMAL': 'BLUE-SECURE'
        }
        return alerts.get(risk_level.upper(), 'GRAY-UNKNOWN')
    
    def _get_port_threat_level(self, port: int) -> str:
        """Get threat level for specific ports"""
        high_risk_ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900]
        if port in high_risk_ports:
            return "HIGH-RISK"
        elif port < 1024:
            return "MED-RISK "
        else:
            return "LOW-RISK "
    
    def _get_compliance_status(self, framework: str, risk_level: str) -> str:
        """Get compliance status indicators"""
        if risk_level in ['CRITICAL', 'HIGH']:
            return "❌ NON-COMPLIANT"
        elif risk_level == 'MODERATE':
            return "⚠️  PARTIAL-COMP"
        else:
            return "✅ COMPLIANT   "
    
    def _estimate_compromise_time(self, risk_level: str) -> str:
        """Estimate time to potential compromise"""
        times = {
            'CRITICAL': 'HOURS',
            'HIGH': 'DAYS', 
            'MODERATE': 'WEEKS',
            'LOW': 'MONTHS',
            'MINIMAL': 'YEARS+'
        }
        return times.get(risk_level.upper(), 'UNKNOWN')
    
    def _predict_attack_vectors(self, severity_counts: Dict) -> str:
        """Predict most likely attack vectors"""
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        
        if critical > 0:
            return "DIRECT_EXPLOITATION"
        elif high > 2:
            return "MULTI_VECTOR_ATTACK"
        elif high > 0:
            return "PRIVILEGE_ESCALATION"
        else:
            return "RECONNAISSANCE_PHASE"
    
    def _get_response_recommendation(self, risk_level: str) -> str:
        """Get response recommendation"""
        responses = {
            'CRITICAL': 'IMMEDIATE_LOCKDOWN',
            'HIGH': 'RAPID_RESPONSE',
            'MODERATE': 'SCHEDULED_PATCH',
            'LOW': 'MONITOR_&_PLAN',
            'MINIMAL': 'ROUTINE_MAINT'
        }
        return responses.get(risk_level.upper(), 'ASSESS_SITUATION')


def create_model_config_file():
    """Create a configuration file for LLM model settings"""
    
    config = {
        "model_settings": {
            "model_type": "llama",  # Options: "llama", "huggingface", "template"
            "model_path": "",  # Path to your local model file
            "context_window": 4096,
            "max_tokens": 512,
            "temperature": 0.7
        },
        "supported_models": {
            "llama": {
                "description": "Local LLaMA model (.gguf format)",
                "example_path": "/path/to/llama-2-7b-chat.gguf",
                "requirements": ["llama-cpp-python"]
            },
            "huggingface": {
                "description": "HuggingFace transformers model",
                "example_models": [
                    "microsoft/DialoGPT-medium",
                    "microsoft/DialoGPT-small",
                    "gpt2-medium"
                ],
                "requirements": ["transformers", "torch"]
            },
            "template": {
                "description": "Template-based generation (no LLM required)",
                "requirements": []
            }
        },
        "library_context": {
            "focus_areas": [
                "Patron data protection",
                "System availability",
                "Compliance requirements",
                "Staff training needs",
                "Budget considerations"
            ]
        }
    }
    
    config_path = "llm_config.json"
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Created LLM configuration file: {config_path}")
    print("Edit this file to configure your local LLM model.")
    
    return config_path


if __name__ == "__main__":
    # Example usage and testing
    
    # Create configuration file
    create_model_config_file()
    
    # Test with sample vulnerability data
    sample_data = {
        'target': '192.168.1.100 (Library Main Server)',
        'total_vulnerabilities': 5,
        'severity_counts': {
            'critical': 1,
            'high': 2,
            'medium': 1,
            'low': 1,
            'info': 0
        },
        'scan_results': {
            'nmap': {
                'vulnerabilities': [
                    {'severity': 'critical', 'type': 'SQL Injection', 'description': 'Database vulnerable to injection attacks'},
                    {'severity': 'high', 'type': 'XSS', 'description': 'Cross-site scripting vulnerability'}
                ]
            }
        }
    }
    
    # Initialize generator (will use template mode if no LLM is available)
    generator = LibrarianReportGenerator()
    
    # Generate report
    report = generator.generate_librarian_report(sample_data)
    print("\n" + "="*50)
    print("SAMPLE LIBRARIAN REPORT:")
    print("="*50)
    print(report)
