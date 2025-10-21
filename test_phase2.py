#!/usr/bin/env python3
"""
Test Phase 2: Subprocess Elimination Progress
"""

import os
import sys

def check_subprocess_usage():
    """Check how many elite commands still use subprocess"""
    
    print("\n" + "="*60)
    print("PHASE 2 PROGRESS: SUBPROCESS ELIMINATION")
    print("="*60)
    
    elite_dir = "/workspace/Core/elite_commands"
    
    total_files = 0
    using_subprocess = []
    clean_files = []
    
    for file in os.listdir(elite_dir):
        if file.startswith("elite_") and file.endswith(".py"):
            total_files += 1
            filepath = os.path.join(elite_dir, file)
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            if 'subprocess' in content:
                using_subprocess.append(file)
            else:
                clean_files.append(file)
    
    print(f"\nTotal elite commands: {total_files}")
    print(f"Using subprocess: {len(using_subprocess)} ({len(using_subprocess)*100//total_files}%)")
    print(f"Clean (no subprocess): {len(clean_files)} ({len(clean_files)*100//total_files}%)")
    
    # Check critical commands
    critical = ['elite_persistence.py', 'elite_clearlogs.py', 'elite_hashdump.py', 
                'elite_inject.py', 'elite_migrate.py']
    
    print("\n[Critical Commands Status]")
    for cmd in critical:
        if cmd in clean_files:
            print(f"  ✅ {cmd}: CLEAN (no subprocess)")
        elif cmd in using_subprocess:
            print(f"  ❌ {cmd}: Still uses subprocess")
        else:
            print(f"  ⚠️  {cmd}: Not found")
    
    # Test API wrapper
    print("\n[API Wrapper Test]")
    try:
        sys.path.insert(0, '/workspace/Core')
        from api_wrappers import get_native_api, list_processes_native, get_system_info_native
        
        print("✅ API wrapper imported successfully")
        
        # Test functions
        try:
            info = get_system_info_native()
            print(f"✅ System info works: {list(info.keys())[:3]}...")
        except Exception as e:
            print(f"⚠️  System info error: {e}")
        
        try:
            procs = list_processes_native()
            print(f"✅ Process list works: {len(procs)} processes found")
        except Exception as e:
            print(f"⚠️  Process list error: {e}")
            
    except ImportError as e:
        print(f"❌ API wrapper import failed: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("PHASE 2 STATUS")
    print("="*60)
    
    progress = (len(clean_files) / total_files) * 100
    
    if progress < 10:
        print(f"⚠️  JUST STARTED: {progress:.1f}% complete")
    elif progress < 50:
        print(f"🔄 IN PROGRESS: {progress:.1f}% complete")
    elif progress < 90:
        print(f"📈 GOOD PROGRESS: {progress:.1f}% complete")
    else:
        print(f"✅ NEARLY COMPLETE: {progress:.1f}% complete")
    
    print(f"\nRemaining work: {len(using_subprocess)} files still need refactoring")
    if using_subprocess:
        print("Next files to fix:")
        for f in using_subprocess[:5]:
            print(f"  - {f}")

if __name__ == "__main__":
    check_subprocess_usage()