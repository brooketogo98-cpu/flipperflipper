#!/bin/bash
# Quick fixes for critical issues

echo "╔═══════════════════════════════════════════════════════╗"
echo "║     STITCH RAT - CRITICAL SECURITY FIXES              ║"
echo "╚═══════════════════════════════════════════════════════╝"

# Fix 1: Untrack .env from git
echo ""
echo "[1/5] Removing .env from git tracking..."
git rm --cached .env 2>/dev/null || echo "  ⚠️  .env already untracked or doesn't exist"

# Fix 2: Update .gitignore
echo ""
echo "[2/5] Updating .gitignore..."
cat >> .gitignore << 'GITIGNORE_END'

# === SECURITY: Never commit these ===
.env
.env.local
.env.*.local

# === Compiled payloads ===
native_payloads/output/payload*
native_payloads/output/*.exe
native_payloads/output/*.bin
native_payloads/output/*.elf

# === Runtime directories ===
downloads/*
!downloads/.gitkeep
uploads/*
!uploads/.gitkeep

# === Backup/test directories ===
.backup_*/
.rollback/

# === Editor files ===
*.swp
*.swo
.DS_Store
GITIGNORE_END

echo "  ✅ .gitignore updated"

# Fix 3: Clean up tracked binaries
echo ""
echo "[3/5] Removing tracked binaries..."
git rm --cached native_payloads/output/payload* 2>/dev/null || echo "  ⚠️  No tracked binaries found"

# Fix 4: Clean up old backups (commented out for safety)
echo ""
echo "[4/5] Cleaning old backups..."
# Uncomment to actually delete:
# rm -rf .backup_* .rollback/
echo "  ⚠️  Skipped (uncomment lines in script to enable)"
echo "  To manually clean: rm -rf .backup_* .rollback/"

# Fix 5: Create placeholder files
echo ""
echo "[5/5] Creating placeholder files..."
mkdir -p downloads uploads
touch downloads/.gitkeep uploads/.gitkeep
echo "  ✅ Placeholders created"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                   NEXT STEPS                          ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "1. 🔐 Change your password in .env:"
echo "   Edit .env and set a NEW secure password"
echo ""
echo "2. 🔧 Fix hardcoded password:"
echo "   Edit web_app_real.py line 243"
echo "   Remove: password = 'SecureTestPassword123!'"
echo "   Add: sys.exit(1)  # Fail if no password"
echo ""
echo "3. 💾 Commit changes:"
echo "   git add .gitignore downloads/.gitkeep uploads/.gitkeep"
echo "   git commit -m 'security: Remove credentials and binaries from git'"
echo "   git push"
echo ""
echo "✅ Script complete!"
