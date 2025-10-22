# Prompt for Claude AI: Implement MFA for Login System

## Context

You are being asked to implement Multi-Factor Authentication (MFA) for a Flask-based web application. The user has provided you with comprehensive documentation that you MUST read and follow.

---

## Your Task

Implement TOTP-based Multi-Factor Authentication (MFA/2FA) that works with Microsoft Authenticator, Google Authenticator, and other standard authenticator apps.

---

## Important Instructions

1. **READ THESE DOCUMENTS FIRST** (in this exact order):
   - `/workspace/LOGIN_SYSTEM_SECURITY_ANALYSIS.md` - Understand current system and security flaws
   - `/workspace/MFA_IMPLEMENTATION_GUIDE_FOR_AI.md` - Complete step-by-step implementation guide

2. **FOLLOW THE GUIDE EXACTLY:**
   - The implementation guide assumes you know nothing
   - It provides every command, every line of code, every step
   - Do NOT deviate from the guide unless you have a specific technical reason
   - Do NOT skip steps

3. **FILES YOU WILL CREATE:**
   - `/workspace/mfa_manager.py` - Core MFA logic module
   - `/workspace/mfa_database.py` - Database operations for MFA
   - `/workspace/create_mfa_tables.py` - Database schema creation
   - `/workspace/templates/mfa_setup.html` - MFA setup page
   - `/workspace/templates/mfa_verify.html` - MFA verification page
   - `/workspace/templates/mfa_backup_codes.html` - Backup codes display
   - `/workspace/test_mfa.py` - Unit tests

4. **FILES YOU WILL MODIFY:**
   - `/workspace/web_app_real.py` - Update login route, add MFA routes
   - `/workspace/config.py` - Add MFA configuration (optional)

5. **DEPENDENCIES YOU WILL INSTALL:**
   ```bash
   pip3 install pyotp==2.9.0 qrcode==7.4.2 pillow==10.1.0 cryptography==41.0.7
   ```

6. **TESTING REQUIREMENTS:**
   - ALL unit tests must pass
   - Manual testing must verify:
     - QR code displays and scans correctly
     - TOTP verification works
     - Backup codes work for recovery
     - Session security is maintained
     - Encryption is working

7. **SECURITY REQUIREMENTS:**
   - TOTP secrets MUST be encrypted in database
   - Backup codes MUST be hashed (like passwords)
   - MFA sessions MUST timeout after 5 minutes
   - Users MUST NOT be able to bypass MFA
   - All MFA events MUST be logged

---

## Step-by-Step Workflow

### Phase 1: Preparation (DO THIS FIRST)
```
1. Read /workspace/LOGIN_SYSTEM_SECURITY_ANALYSIS.md completely
2. Read /workspace/MFA_IMPLEMENTATION_GUIDE_FOR_AI.md completely
3. Create backup of current system
4. Install required dependencies
5. Verify dependencies installed correctly
```

### Phase 2: Implementation (FOLLOW THE GUIDE)
```
1. Create mfa_manager.py (STEP 1 in guide)
2. Create database tables (STEP 2 in guide)
3. Create mfa_database.py (STEP 3 in guide)
4. Create HTML templates (STEP 4 in guide)
5. Update web_app_real.py (STEP 5 in guide)
6. Update config.py (STEP 6 in guide - optional)
```

### Phase 3: Testing (VERIFY EVERYTHING WORKS)
```
1. Run unit tests (STEP 7 in guide)
2. Start Flask application
3. Test MFA setup flow
4. Test MFA login flow
5. Test backup code recovery
6. Verify database encryption
7. Check audit logs
```

### Phase 4: Validation (FINAL CHECKLIST)
```
Go through the complete checklist in Section 7 of the guide.
Mark each item as completed.
Do NOT skip any checklist items.
```

---

## Expected User Experience

After your implementation, the login flow should work like this:

### First Login:
```
User: Enters username + password
System: ✅ Password correct
System: Redirects to /mfa/setup
System: Shows QR code and secret key
User: Scans QR code with Microsoft Authenticator
User: Enters 6-digit code from app
System: ✅ Code correct
System: Generates 10 backup codes
System: Shows backup codes (ONE TIME ONLY)
User: Downloads/prints backup codes
System: Redirects to dashboard
User: ✅ Logged in
```

### Subsequent Logins:
```
User: Enters username + password
System: ✅ Password correct
System: Redirects to /mfa/verify
System: Asks for 6-digit code
User: Opens Microsoft Authenticator app
User: Enters current 6-digit code
System: ✅ Code correct
System: Redirects to dashboard
User: ✅ Logged in
```

### If Phone Lost:
```
User: Enters username + password
System: ✅ Password correct
System: Redirects to /mfa/verify
User: Clicks "Lost your device?"
System: Asks for backup recovery code
User: Enters one backup code
System: ✅ Code valid
System: Removes used code from database
System: Redirects to dashboard
User: ✅ Logged in
System: Prompts to reset MFA
```

---

## Common Mistakes to Avoid

❌ **DON'T** store TOTP secrets as plaintext
✅ **DO** encrypt secrets using Fernet

❌ **DON'T** store backup codes as plaintext
✅ **DO** hash backup codes like passwords

❌ **DON'T** allow unlimited MFA verification attempts
✅ **DO** rate limit and log failed attempts

❌ **DON'T** allow users to skip MFA after password verification
✅ **DO** enforce MFA for every login

❌ **DON'T** forget to handle clock drift
✅ **DO** use valid_window=1 in TOTP verification

❌ **DON'T** reuse backup codes
✅ **DO** remove codes from database after use

❌ **DON'T** forget session timeouts
✅ **DO** expire MFA sessions after 5 minutes

❌ **DON'T** skip the backup of the current system
✅ **DO** create backup before making changes

---

## Code Quality Standards

Your code must:
- ✅ Follow PEP 8 style guidelines
- ✅ Include docstrings for all functions
- ✅ Handle all exceptions gracefully
- ✅ Log all important events
- ✅ Validate all user inputs
- ✅ Use secure random number generation (secrets module)
- ✅ Include helpful comments
- ✅ Be readable and maintainable

---

## Testing Checklist

Before you mark the task complete, verify:

### Unit Tests:
- [ ] All tests in test_mfa.py pass
- [ ] Secret generation works
- [ ] Encryption/decryption works
- [ ] Token verification works
- [ ] Backup codes work
- [ ] QR code generation works

### Integration Tests:
- [ ] Login redirects to MFA setup for new users
- [ ] QR code displays correctly
- [ ] Scanned QR code works with Microsoft Authenticator
- [ ] Manual secret entry works
- [ ] First TOTP verification succeeds
- [ ] Backup codes display and download
- [ ] Subsequent login redirects to MFA verify
- [ ] TOTP verification succeeds on login
- [ ] Invalid codes show error
- [ ] Backup code recovery works
- [ ] Used backup code cannot be reused
- [ ] MFA session expires after timeout
- [ ] Cannot access dashboard without MFA

### Security Tests:
- [ ] Secrets encrypted in database (not plaintext)
- [ ] Backup codes hashed in database (not plaintext)
- [ ] Encryption key file has restricted permissions
- [ ] MFA events logged in audit table
- [ ] Failed attempts logged
- [ ] Cannot bypass MFA by URL manipulation

### Database Tests:
- [ ] user_mfa table created
- [ ] mfa_audit_log table created
- [ ] Indexes created
- [ ] Data saves correctly
- [ ] Data retrieves correctly
- [ ] Updates work correctly
- [ ] Foreign key constraints work

---

## Success Criteria

Your implementation is complete when:

1. ✅ All files created as specified in the guide
2. ✅ All dependencies installed successfully
3. ✅ All unit tests pass
4. ✅ All integration tests pass
5. ✅ All security tests pass
6. ✅ All database tests pass
7. ✅ Documentation is accurate and complete
8. ✅ Code follows quality standards
9. ✅ User experience matches specification
10. ✅ No security vulnerabilities introduced

---

## Deliverables

When you complete this task, provide:

1. **Summary of Changes:**
   - List all files created
   - List all files modified
   - List all dependencies installed

2. **Test Results:**
   - Output from unit tests
   - Screenshots of manual testing (if possible)
   - Confirmation all tests pass

3. **Security Verification:**
   - Confirm secrets are encrypted
   - Confirm backup codes are hashed
   - Confirm audit logging works
   - Confirm no bypass vulnerabilities

4. **User Documentation:**
   - How to set up MFA (user perspective)
   - How to use backup codes
   - What to do if phone is lost

5. **Admin Documentation:**
   - How to reset user MFA
   - How to disable MFA for a user
   - How to view MFA audit logs

---

## If You Encounter Issues

### If dependencies won't install:
```bash
# Try upgrading pip first
pip3 install --upgrade pip

# Then install dependencies
pip3 install pyotp qrcode pillow cryptography
```

### If database errors occur:
```bash
# Delete and recreate database
rm -f /workspace/Application/stitch.db
python3 create_mfa_tables.py
```

### If secrets encryption fails:
```bash
# Check encryption key file
ls -la /workspace/Application/.mfa_encryption_key

# Regenerate if needed
rm -f /workspace/Application/.mfa_encryption_key
python3 -c "from mfa_manager import mfa_manager; print('Key regenerated')"
```

### If TOTP verification always fails:
```bash
# Check server time
date

# Compare with your phone time
# They should be within 30 seconds of each other
```

### If QR code won't display:
```bash
# Verify pillow installed
python3 -c "from PIL import Image; print('Pillow OK')"

# Reinstall if needed
pip3 install --force-reinstall pillow
```

---

## Questions to Ask Yourself

Before you start:
- [ ] Have I read both documentation files completely?
- [ ] Do I understand the current authentication flow?
- [ ] Do I understand what TOTP is?
- [ ] Do I have all required dependencies?

During implementation:
- [ ] Am I following the guide exactly?
- [ ] Am I encrypting secrets properly?
- [ ] Am I hashing backup codes?
- [ ] Am I logging all events?
- [ ] Am I handling errors gracefully?

After implementation:
- [ ] Did all unit tests pass?
- [ ] Did I test the entire user flow manually?
- [ ] Did I verify security measures are in place?
- [ ] Did I complete the final checklist?
- [ ] Is the code production-ready?

---

## Reference Information

### TOTP (Time-based One-Time Password):
- Algorithm: RFC 6238
- Code length: 6 digits
- Time step: 30 seconds
- Hash algorithm: SHA-1 (default)
- Compatible apps: Microsoft Authenticator, Google Authenticator, Authy, 1Password, etc.

### QR Code Format:
```
otpauth://totp/IssuerName:username?secret=SECRET&issuer=IssuerName
```

### Encryption:
- Algorithm: Fernet (AES-128 CBC with HMAC-SHA256)
- Library: cryptography.fernet
- Key generation: Fernet.generate_key()

### Backup Codes:
- Format: 8-character alphanumeric
- Character set: A-Z (excluding O, I, L), 2-9 (excluding 0, 1)
- Hashing: SHA-256
- Storage: JSON array of hashes

---

## Final Notes

This is a comprehensive implementation that significantly improves security. Take your time, follow the guide step by step, and don't skip testing.

The documentation provided is extremely detailed because implementing MFA correctly is critical for security. Every step matters.

If you successfully complete this implementation following the guide, the system will be protected against:
- ✅ Password theft
- ✅ Phishing attacks  
- ✅ Keyloggers
- ✅ Session hijacking (partially)
- ✅ Credential stuffing
- ✅ Brute force attacks (enhanced)

Good luck! Follow the guide, test thoroughly, and you'll succeed.

---

## Quick Reference: File Locations

```
/workspace/
├── mfa_manager.py                          [CREATE - Core MFA logic]
├── mfa_database.py                         [CREATE - Database operations]
├── create_mfa_tables.py                    [CREATE - Schema creation]
├── test_mfa.py                             [CREATE - Unit tests]
├── web_app_real.py                         [MODIFY - Add MFA routes]
├── config.py                               [MODIFY - Add MFA config]
├── templates/
│   ├── mfa_setup.html                      [CREATE - Setup page]
│   ├── mfa_verify.html                     [CREATE - Verification page]
│   └── mfa_backup_codes.html               [CREATE - Backup codes page]
├── Application/
│   ├── stitch.db                           [DATABASE - Will be updated]
│   ├── .mfa_encryption_key                 [AUTO-GENERATED - Fernet key]
│   └── .secret_key                         [EXISTING - Session key]
└── Documentation/
    ├── LOGIN_SYSTEM_SECURITY_ANALYSIS.md   [READ FIRST]
    └── MFA_IMPLEMENTATION_GUIDE_FOR_AI.md  [READ SECOND, FOLLOW EXACTLY]
```

---

*End of Claude AI Handoff Prompt*

**START HERE:** Read `/workspace/MFA_IMPLEMENTATION_GUIDE_FOR_AI.md` and begin with Phase 1.
