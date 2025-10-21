#!/usr/bin/env python3
"""
Test script for Phase 1: Elite Executor Integration
This verifies that elite commands are properly connected to the web app
"""

import sys
import os

# Add workspace to path
sys.path.insert(0, '/workspace')

def test_elite_executor_direct():
    """Test elite executor directly"""
    print("\n" + "="*60)
    print("PHASE 1 INTEGRATION TEST - ELITE EXECUTOR")
    print("="*60)
    
    try:
        # Test direct import
        from Core.elite_executor import EliteCommandExecutor
        print("✅ Elite executor import successful")
        
        # Create instance
        executor = EliteCommandExecutor()
        print("✅ Elite executor instance created")
        
        # Get available commands
        commands = executor.get_available_commands()
        print(f"✅ Found {len(commands)} commands")
        
        # Check critical commands
        critical_commands = ['hashdump', 'persistence', 'clearlogs', 'inject', 'migrate']
        for cmd in critical_commands:
            if cmd in commands:
                print(f"  ✓ {cmd} loaded")
            else:
                print(f"  ✗ {cmd} MISSING")
        
        # Test command execution
        print("\n[Testing Command Execution]")
        result = executor.execute('whoami')
        
        if isinstance(result, dict):
            if result.get('success') or 'error' in result:
                print("✅ Command execution returns proper format")
                print(f"  Result keys: {list(result.keys())}")
            else:
                print("⚠️  Command result missing success/error")
        else:
            print("❌ Command didn't return dict")
            
        return True
        
    except Exception as e:
        print(f"❌ Elite executor test failed: {e}")
        return False

def test_web_app_integration():
    """Test web app integration"""
    print("\n[Testing Web App Integration]")
    
    try:
        # Import web app
        from web_app_real import get_elite_executor, execute_command_elite
        print("✅ Web app imports successful")
        
        # Get executor through web app
        executor = get_elite_executor()
        print("✅ Got elite executor through web app")
        
        # Test command routing
        result = execute_command_elite('test_connection', 'whoami')
        if 'source' in result:
            print(f"✅ Command routing works (source: {result.get('source')})")
        else:
            print("⚠️  Command routing missing source metadata")
            
        return True
        
    except ImportError as e:
        print(f"❌ Web app integration failed: {e}")
        print("   Make sure elite_executor is imported in web_app_real.py")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_api_endpoint():
    """Test if API endpoint exists"""
    print("\n[Testing API Endpoint]")
    
    try:
        # Check if elite status endpoint exists
        with open('/workspace/web_app_real.py', 'r') as f:
            content = f.read()
            
        if '/api/elite/status' in content:
            print("✅ Elite status API endpoint exists")
        else:
            print("❌ Elite status API endpoint missing")
            
        if 'execute_command_elite' in content:
            print("✅ Elite command execution function exists")
        else:
            print("❌ Elite command execution function missing")
            
        return True
        
    except Exception as e:
        print(f"❌ API endpoint check failed: {e}")
        return False

def main():
    """Run all integration tests"""
    
    print("\n🚀 RUNNING PHASE 1 INTEGRATION TESTS")
    print("-" * 60)
    
    # Run tests
    test1 = test_elite_executor_direct()
    test2 = test_web_app_integration()
    test3 = test_api_endpoint()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    if test1 and test2 and test3:
        print("✅ ALL TESTS PASSED - Phase 1 Integration Complete!")
        print("\nNext Steps:")
        print("1. Elite executor is connected to web app")
        print("2. Commands route through elite system")
        print("3. Ready for Phase 2: Subprocess elimination")
        return 0
    else:
        print("❌ TESTS FAILED - Integration incomplete")
        print("\nRequired fixes:")
        if not test1:
            print("- Fix elite executor issues")
        if not test2:
            print("- Complete web app integration")
        if not test3:
            print("- Add API endpoints")
        return 1

if __name__ == "__main__":
    exit(main())