#!/usr/bin/env python3
"""
Test script to verify tool input compatibility fix
Tests that tools with {target} and {web_url} placeholders work correctly
"""

import sys
import os

# Add the project directory to the path
sys.path.insert(0, '/home/satya/koha-vuln-scanner')

# Test the tool configurations
def test_tool_configs():
    """Test that all tool configurations can be formatted correctly"""
    
    # Import after adding to path
    from app import TOOLS
    
    # Test target and web URL
    test_target = "192.168.1.100"
    test_web_url = "http://192.168.1.100"
    
    print("🔧 Testing Tool Command Formatting Compatibility")
    print("=" * 60)
    
    success_count = 0
    total_count = 0
    
    for tool_name, config in TOOLS.items():
        total_count += 1
        print(f"\n🔍 Testing {tool_name}: {config['name']}")
        print(f"   Command template: {config['cmd']}")
        print(f"   Requires web: {config.get('requires_web', False)}")
        
        try:
            # Test command formatting based on requirements
            if config.get('requires_web', False):
                # Web tool - should use web_url
                if '{web_url}' in config['cmd'] and '{target}' in config['cmd']:
                    cmd = config['cmd'].format(target=test_target, web_url=test_web_url)
                    print(f"   ✅ Formatted (both): {cmd}")
                elif '{web_url}' in config['cmd']:
                    cmd = config['cmd'].format(web_url=test_web_url)
                    print(f"   ✅ Formatted (web_url): {cmd}")
                else:
                    cmd = config['cmd'].format(target=test_target)
                    print(f"   ✅ Formatted (target): {cmd}")
            else:
                # Network tool - should use target
                cmd = config['cmd'].format(target=test_target)
                print(f"   ✅ Formatted: {cmd}")
            
            success_count += 1
            
        except KeyError as e:
            print(f"   ❌ Missing placeholder: {e}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {success_count}/{total_count} tools passed")
    
    if success_count == total_count:
        print("🎉 All tools are compatible!")
        return True
    else:
        print("⚠️ Some tools have compatibility issues")
        return False

def test_url_construction():
    """Test web URL construction logic"""
    print("\n🌐 Testing Web URL Construction")
    print("=" * 40)
    
    # Import after adding to path
    from app import get_web_url
    
    # Test scenarios
    test_cases = [
        {
            'name': 'HTTPS available (port 443)',
            'target': 'example.com',
            'target_info': {
                'has_web': True,
                'open_ports': [443, 80, 22]
            },
            'expected': 'https://example.com'
        },
        {
            'name': 'HTTP only (port 80)',
            'target': '192.168.1.100',
            'target_info': {
                'has_web': True,
                'open_ports': [80, 22]
            },
            'expected': 'http://192.168.1.100'
        },
        {
            'name': 'Custom HTTPS port (8443)',
            'target': 'test.local',
            'target_info': {
                'has_web': True,
                'open_ports': [8443, 22]
            },
            'expected': 'https://test.local:8443'
        },
        {
            'name': 'Custom HTTP port (8080)',
            'target': '10.0.0.1',
            'target_info': {
                'has_web': True,
                'open_ports': [8080, 22]
            },
            'expected': 'http://10.0.0.1:8080'
        },
        {
            'name': 'No web services',
            'target': '192.168.1.50',
            'target_info': {
                'has_web': False,
                'open_ports': [22]
            },
            'expected': None
        }
    ]
    
    passed = 0
    total = len(test_cases)
    
    for test_case in test_cases:
        result = get_web_url(test_case['target'], test_case['target_info'])
        if result == test_case['expected']:
            print(f"   ✅ {test_case['name']}: {result}")
            passed += 1
        else:
            print(f"   ❌ {test_case['name']}: got {result}, expected {test_case['expected']}")
    
    print(f"\n📊 URL Construction Results: {passed}/{total} tests passed")
    return passed == total

if __name__ == "__main__":
    print("🧪 Tool Input Compatibility Test Suite")
    print("Testing fix for tools requiring web addresses vs IP addresses")
    print()
    
    # Run tests
    config_test = test_tool_configs()
    url_test = test_url_construction()
    
    print("\n" + "=" * 60)
    if config_test and url_test:
        print("🎉 ALL TESTS PASSED! Tool compatibility issue has been resolved.")
        print("\n✅ Key improvements:")
        print("   • Tools now use appropriate input format (IP/domain vs full URL)")
        print("   • Smart command formatting based on tool requirements")
        print("   • Proper web URL construction with protocol detection")
        print("   • Support for custom ports (8080, 8443, etc.)")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED! Please review the issues above.")
        sys.exit(1)
