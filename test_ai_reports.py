#!/usr/bin/env python3
"""
Test script for AI-Powered Librarian Reports functionality
"""

import sys
import os
sys.path.append(os.getcwd())

from llm_analysis import LibrarianReportGenerator, create_model_config_file

def test_ai_librarian_reports():
    """Test the AI-powered librarian reports functionality"""
    print("🧪 Testing AI-Powered Librarian Reports")
    print("=" * 50)
    
    # Test 1: Configuration file creation
    print("\n1. Testing configuration file creation...")
    try:
        config_path = create_model_config_file()
        print(f"✅ Configuration file created: {config_path}")
        
        # Check if file exists and has content
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                content = f.read()
                print(f"✅ Config file size: {len(content)} characters")
        else:
            print("❌ Config file not found")
    except Exception as e:
        print(f"❌ Configuration creation failed: {e}")
    
    # Test 2: Generator initialization
    print("\n2. Testing generator initialization...")
    try:
        generator = LibrarianReportGenerator()
        print(f"✅ Generator initialized")
        print(f"   Model type: {generator.model_type}")
        print(f"   LLAMA available: {hasattr(generator, 'llama_model')}")
        print(f"   Transformers available: {hasattr(generator, 'tokenizer')}")
    except Exception as e:
        print(f"❌ Generator initialization failed: {e}")
        return
    
    # Test 3: Sample vulnerability data
    print("\n3. Testing report generation with sample data...")
    sample_data = {
        'target': '192.168.1.100',
        'total_vulnerabilities': 8,
        'severity_counts': {
            'critical': 1,
            'high': 2, 
            'medium': 3,
            'low': 2
        },
        'scan_results': {
            'nmap': {
                'vulnerabilities': [
                    {
                        'severity': 'high',
                        'type': 'Open Port',
                        'description': 'SSH service running on default port',
                        'detail': 'Port 22/tcp open ssh OpenSSH 7.4'
                    }
                ]
            },
            'nikto': {
                'vulnerabilities': [
                    {
                        'severity': 'medium',
                        'type': 'Web Vulnerability',
                        'description': 'Outdated web server version detected',
                        'detail': 'Apache/2.2.15 - potentially vulnerable'
                    }
                ]
            }
        },
        'target_info': {
            'has_web': True,
            'open_ports': [22, 80, 443, 3306],
            'services': {'22': 'ssh', '80': 'http', '443': 'https', '3306': 'mysql'}
        },
        'risk_score': 75,
        'risk_level': 'HIGH'
    }
    
    try:
        print("   Generating librarian report...")
        report = generator.generate_librarian_report(sample_data)
        print(f"✅ Report generated successfully")
        print(f"   Report length: {len(report)} characters")
        print(f"   Report lines: {len(report.splitlines())} lines")
        
        # Show preview
        print("\n📖 Report Preview (first 800 characters):")
        print("-" * 50)
        print(report[:800])
        if len(report) > 800:
            print("\n[... truncated ...]")
        print("-" * 50)
        
        # Save test report
        test_report_path = "test_librarian_report.md"
        with open(test_report_path, 'w') as f:
            f.write(report)
        print(f"✅ Test report saved to: {test_report_path}")
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 4: Different risk levels
    print("\n4. Testing different risk levels...")
    risk_scenarios = [
        {'risk_level': 'LOW', 'total_vulnerabilities': 2, 'severity_counts': {'low': 2}},
        {'risk_level': 'MODERATE', 'total_vulnerabilities': 5, 'severity_counts': {'medium': 3, 'low': 2}},
        {'risk_level': 'CRITICAL', 'total_vulnerabilities': 10, 'severity_counts': {'critical': 3, 'high': 4, 'medium': 3}}
    ]
    
    for scenario in risk_scenarios:
        try:
            test_data = sample_data.copy()
            test_data.update(scenario)
            mini_report = generator.generate_librarian_report(test_data)
            risk_level = scenario['risk_level']
            vuln_count = scenario['total_vulnerabilities']
            print(f"   ✅ {risk_level} risk scenario: {len(mini_report)} chars, {vuln_count} vulns")
        except Exception as e:
            print(f"   ❌ {scenario['risk_level']} scenario failed: {e}")
    
    print("\n🎉 AI-Powered Librarian Reports testing completed!")
    print("=" * 50)

if __name__ == "__main__":
    test_ai_librarian_reports()
