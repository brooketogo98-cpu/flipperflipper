# Critical Safety and Rollback Procedures
## Preventing Catastrophic Implementation Failures

---

## MANDATORY CHECKPOINT SYSTEM

### Create Snapshots at These Points:

1. **BEFORE Phase 0** - Clean baseline
2. **AFTER Obfuscation Removal** - Critical checkpoint
3. **AFTER Python 3 Migration** - Before any functional changes
4. **AFTER Each 10 Commands** - Incremental safety
5. **BEFORE Integration Testing** - Pre-merge safety

### Git Checkpoint Commands:
```bash
# Create checkpoint branch
git checkout -b checkpoint_$(date +%Y%m%d_%H%M%S)
git add -A
git commit -m "Checkpoint: [Phase Name]"
git push origin checkpoint_$(date +%Y%m%d_%H%M%S)

# Return to main work
git checkout main
```

---

## ROLLBACK PROCEDURES

### If Implementation Breaks:

#### Level 1: File-Level Rollback
```bash
# Revert specific file
git checkout HEAD -- filepath

# Revert entire directory
git checkout HEAD -- Core/elite_commands/
```

#### Level 2: Commit Rollback
```bash
# Find last working commit
git log --oneline -20

# Reset to specific commit (keep changes)
git reset --soft [commit_hash]

# Reset to specific commit (discard changes)
git reset --hard [commit_hash]
```

#### Level 3: Emergency Recovery
```bash
# Complete reset to origin/main
git fetch origin
git reset --hard origin/main
```

---

## BREAKING CHANGE DETECTION

### Auto-Test After Each Phase:
```python
# tests/sanity_check.py
import sys
import importlib

def sanity_check():
    """Quick test that nothing is catastrophically broken"""
    
    critical_imports = [
        'web_app_real',
        'Application.st_main',
        'Core.elite_executor',
        'Core.elite_connection'
    ]
    
    for module_name in critical_imports:
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            print(f"❌ CRITICAL: Cannot import {module_name}: {e}")
            return False
    
    # Test basic Flask app starts
    try:
        from web_app_real import app
        with app.test_client() as client:
            response = client.get('/')
            if response.status_code not in [200, 302]:
                print(f"❌ Web app broken: {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Web app won't start: {e}")
        return False
    
    print("✅ Sanity check passed")
    return True

# Run after EVERY major change
if __name__ == "__main__":
    sys.exit(0 if sanity_check() else 1)
```

---

## IMPLEMENTATION ISOLATION

### Work in Isolated Branches:
```bash
# Functional team branch
git checkout -b functional_implementation

# Technical team branch  
git checkout -b technical_implementation

# Never work directly on main until tested
```

### Test Merge Before Real Merge:
```bash
# Create test merge branch
git checkout -b test_merge
git merge functional_implementation
git merge technical_implementation

# Run full test suite
python tests/integration_test.py

# If passes, then merge to main
git checkout main
git merge test_merge
```

---

## CRITICAL DO NOT BREAK LIST

### These Files/Functions MUST Always Work:

1. **web_app_real.py** - `app.run()` must start
2. **templates/dashboard.html** - Must render
3. **static/js/app_real.js** - WebSocket must connect
4. **Database connections** - Must not break existing data
5. **Configuration loading** - Must maintain compatibility

### Test These Continuously:
```python
# tests/critical_functions.py
def test_critical_functions():
    """Test functions that absolutely cannot break"""
    
    tests = {
        'flask_app_starts': test_flask_startup(),
        'websocket_connects': test_websocket(),
        'database_accessible': test_database(),
        'config_loads': test_configuration(),
        'dashboard_renders': test_dashboard_render()
    }
    
    for name, result in tests.items():
        if not result:
            print(f"❌ CRITICAL FAILURE: {name}")
            print("DO NOT CONTINUE - ROLLBACK IMMEDIATELY")
            return False
    
    return True
```

---

## PARALLEL WORK SAFETY

### Prevent Team Conflicts:

```python
# Core/implementation_lock.py
import os
import json
from datetime import datetime

class ImplementationLock:
    """Prevent both AIs from modifying same file"""
    
    def __init__(self):
        self.lock_file = '.implementation_locks.json'
        
    def acquire_lock(self, filepath, team):
        """Acquire exclusive lock on file"""
        locks = self._read_locks()
        
        if filepath in locks:
            owner = locks[filepath]['team']
            if owner != team:
                raise Exception(f"File locked by {owner} team")
        
        locks[filepath] = {
            'team': team,
            'timestamp': datetime.now().isoformat()
        }
        
        self._write_locks(locks)
        return True
    
    def release_lock(self, filepath, team):
        """Release lock on file"""
        locks = self._read_locks()
        
        if filepath in locks:
            if locks[filepath]['team'] == team:
                del locks[filepath]
                self._write_locks(locks)
```

This prevents both AIs from modifying the same file simultaneously.